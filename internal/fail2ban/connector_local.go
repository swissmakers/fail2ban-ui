// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fail2ban

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// Connector for a local Fail2ban instance via fail2ban-client CLI.
type LocalConnector struct {
	server shared.Fail2banServer
}

// =========================================================================
//  Constructor
// =========================================================================

// Create a new LocalConnector for the given server config.
func NewLocalConnector(server shared.Fail2banServer) *LocalConnector {
	return &LocalConnector{server: server}
}

func (lc *LocalConnector) Server() shared.Fail2banServer {
	return lc.server
}

func (lc *LocalConnector) configPath() string {
	return NormalizeConfigPath(lc.server.ConfigPath)
}

func (lc *LocalConnector) GetJailSummary(ctx context.Context) (*JailSummary, error) {
	out, err := lc.runFail2banClient(ctx, "banned")
	if err != nil {
		socketPath := lc.server.SocketPath
		if strings.TrimSpace(socketPath) == "" {
			socketPath = "default socket"
		}
		return nil, fmt.Errorf("unable to retrieve jail information via socket %s. is your fail2ban service running? details: %w (output: %s)",
			socketPath, err, strings.TrimSpace(out))
	}
	infos, err := parseBannedJails(out)
	if err != nil {
		return nil, err
	}
	exists, managed, err := lc.CheckJailLocalIntegrity(ctx)
	if err != nil {
		debugf("Warning: could not check jail.local integrity on %s: %v", lc.server.Name, err)
	}
	return &JailSummary{Jails: infos, JailLocalExists: exists, JailLocalManaged: managed}, nil
}

func (lc *LocalConnector) GetBannedIPs(ctx context.Context, jail string) ([]string, error) {
	if err := ValidateJailName(jail); err != nil {
		return nil, err
	}
	out, err := lc.runFail2banClient(ctx, "get", jail, "banip")
	if err != nil {
		return nil, fmt.Errorf("fail2ban-client get %s banip failed: %w (output: %s)", jail, err, strings.TrimSpace(out))
	}
	return strings.Fields(out), nil
}

// Unban an IP from a given jail.
func (lc *LocalConnector) UnbanIP(ctx context.Context, jail, ip string) error {
	if err := validateBanTarget(jail, ip); err != nil {
		return err
	}
	args := []string{"set", jail, "unbanip", ip}
	if _, err := lc.runFail2banClient(ctx, args...); err != nil {
		return fmt.Errorf("error unbanning IP %s from jail %s: %w", ip, jail, err)
	}
	return nil
}

// Ban an IP in a given jail.
func (lc *LocalConnector) BanIP(ctx context.Context, jail, ip string) error {
	if err := validateBanTarget(jail, ip); err != nil {
		return err
	}
	args := []string{"set", jail, "banip", ip}
	if _, err := lc.runFail2banClient(ctx, args...); err != nil {
		return fmt.Errorf("error banning IP %s in jail %s: %w", ip, jail, err)
	}
	return nil
}

// Reload the Fail2ban service.
func (lc *LocalConnector) Reload(ctx context.Context) error {
	out, err := lc.runFail2banClient(ctx, "-c", lc.configPath(), "reload")
	if err != nil {
		if strings.Contains(err.Error(), "Found no accessible config files") {
			return fmt.Errorf("fail2ban reload error: %w - fail2ban-ui cannot see the complete fail2ban configuration: when sharing a socket with a fail2ban container, /etc/fail2ban inside the fail2ban-ui container must contain the full configuration tree (including fail2ban.conf and jail.conf), not only the custom jail/filter files", err)
		}
		return fmt.Errorf("fail2ban reload error: %w (output: %s)", err, strings.TrimSpace(out))
	}
	return checkReloadOutput(out)
}

func (lc *LocalConnector) ValidateConfiguration(ctx context.Context) error {
	return validateConfig(ctx, lc.runFail2banClient, lc.configPath())
}

// Restart or reload the local Fail2ban instance; returns "restart" or "reload".
func (lc *LocalConnector) Restart(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("systemctl"); err == nil {
		out, err := exec.CommandContext(ctx, "systemctl", "restart", "fail2ban").CombinedOutput()
		if err != nil {
			return "restart", fmt.Errorf("failed to restart fail2ban via systemd: %w - output: %s",
				err, strings.TrimSpace(string(out)))
		}
		if err := waitForFail2ban(ctx, lc.runFail2banClient, "fail2ban", restartReadyTimeout); err != nil {
			return "restart", fmt.Errorf("%w: fail2ban health check after systemd restart failed: %w", ErrRestartNotResponding, err)
		}
		return "restart", nil
	}
	if err := lc.Reload(ctx); err != nil {
		return "reload", fmt.Errorf("failed to reload fail2ban via fail2ban-client (systemctl not available): %w", err)
	}
	if err := waitForFail2ban(ctx, lc.runFail2banClient, "fail2ban", restartReadyTimeout); err != nil {
		return "reload", fmt.Errorf("%w: fail2ban health check after reload failed: %w", ErrRestartNotResponding, err)
	}
	return "reload", nil
}

// Local servers deliver callbacks in-process, so only fail2ban itself is checked.
func (lc *LocalConnector) ProbeHealth(ctx context.Context) ServerHealth {
	if err := pingFail2ban(ctx, lc.runFail2banClient, "fail2ban"); err != nil {
		return ServerHealth{Error: err.Error()}
	}
	return ServerHealth{Fail2banOK: true}
}

func (lc *LocalConnector) GetFilterConfig(ctx context.Context, jail string) (string, string, error) {
	return readFilterConfigWithFallback(jail, lc.configPath())
}

func (lc *LocalConnector) SetFilterConfig(ctx context.Context, jail, content string) error {
	return SetFilterConfigLocal(jail, content, lc.configPath())
}

// =========================================================================
//  CLI Helpers
// =========================================================================

func (lc *LocalConnector) runFail2banClient(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "fail2ban-client", fail2banArgs(lc.server.SocketPath, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	output, err := selectCommandOutput("fail2ban-client", stdout.String(), stderr.String(), runErr)
	if err == nil {
		if s := strings.TrimSpace(stderr.String()); s != "" {
			debugf("fail2ban-client stderr ignored [%s]: %s", lc.server.Name, truncateForLog(s, maxLoggedOutputBytes))
		}
	}
	return output, err
}

// =========================================================================
//  Delegated Operations
// =========================================================================

func (lc *LocalConnector) GetAllJails(ctx context.Context) ([]JailInfo, error) {
	return GetAllJails(lc.configPath())
}

func (lc *LocalConnector) UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error {
	return UpdateJailEnabledStates(updates, lc.configPath())
}

func (lc *LocalConnector) GetFilters(ctx context.Context) ([]string, error) {
	return DiscoverFiltersFromFiles(lc.configPath())
}

func (lc *LocalConnector) TestFilter(ctx context.Context, filterName string, logLines []string, filterContent string) (string, string, error) {
	return TestFilterLocal(ctx, filterName, logLines, filterContent, lc.configPath())
}

func (lc *LocalConnector) GetJailConfig(ctx context.Context, jail string) (string, string, error) {
	return GetJailConfig(jail, lc.configPath())
}

func (lc *LocalConnector) SetJailConfig(ctx context.Context, jail, content string) error {
	return SetJailConfig(jail, content, lc.configPath())
}

func (lc *LocalConnector) TestLogpathWithResolution(ctx context.Context, logpath string) (originalPath, resolvedPath string, files []string, err error) {
	return TestLogpathWithResolution(logpath, lc.configPath())
}

func (lc *LocalConnector) EnsureJailLocalStructure(ctx context.Context) error {
	root := lc.configPath()
	// Run migration once if enabled (experimental, off by default)
	if isJailAutoMigrationEnabled() {
		if _, done := migratedRoots.LoadOrStore(root, true); !done {
			debugf("JAIL_AUTOMIGRATION=true: running experimental jail.local -> jail.d/ migration for %s", root)
			if err := MigrateJailsFromJailLocal(root); err != nil {
				log.Printf("warning: jail.local migration for %s failed: %v", lc.server.Name, err)
			}
		}
	}
	return EnsureManagedJailLocal(root, []byte(mustProvider().BuildJailLocalContent()))
}

func (lc *LocalConnector) CreateJail(ctx context.Context, jailName, content string) error {
	return CreateJail(jailName, content, lc.configPath())
}

func (lc *LocalConnector) DeleteJail(ctx context.Context, jailName string) error {
	return DeleteJail(jailName, lc.configPath())
}

func (lc *LocalConnector) CreateFilter(ctx context.Context, filterName, content string) error {
	return CreateFilter(filterName, content, lc.configPath())
}

func (lc *LocalConnector) DeleteFilter(ctx context.Context, filterName string) error {
	return DeleteFilter(filterName, lc.configPath())
}

func (lc *LocalConnector) Close() error { return nil }

func (lc *LocalConnector) CheckJailLocalIntegrity(ctx context.Context) (bool, bool, error) {
	jailLocalPath := JailLocal(lc.configPath())
	content, err := os.ReadFile(jailLocalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("failed to read jail.local: %w", err)
	}
	hasUIAction := strings.Contains(string(content), managedJailLocalMarker)
	return true, hasUIAction, nil
}
