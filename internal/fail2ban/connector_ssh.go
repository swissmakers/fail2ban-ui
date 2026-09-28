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
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// =========================================================================
//  Types and Constants
// =========================================================================

// Talks like this to a remote Fail2ban instance over SSH
type SSHConnector struct {
	server          shared.Fail2banServer
	fail2banPath    string
	pathMutex       sync.RWMutex
	tunnelPort      int
	forwardPort     int
	closed          atomic.Bool
	reloadPending   atomic.Bool
	masterMu        sync.Mutex
	masterUp        atomic.Bool
	masterFailUntil time.Time
	sessionSem      chan struct{}
	actionRepairMu  sync.Mutex
	actionRepairAt  time.Time
	tunnelCheckMu   sync.Mutex
	healthMu        sync.RWMutex
	health          SSHHealthStatus
}

// How long to wait before retrying an action file repair on the same host
const actionRepairDebounce = 5 * time.Minute

// Report whether repair may be attempted now, and claims the slot if so.
func (sc *SSHConnector) beginActionRepair() bool {
	sc.actionRepairMu.Lock()
	defer sc.actionRepairMu.Unlock()
	if !sc.actionRepairAt.IsZero() && time.Since(sc.actionRepairAt) < actionRepairDebounce {
		return false
	}
	sc.actionRepairAt = time.Now()
	return true
}

// =========================================================================
//  Constructor
// =========================================================================

// Builds a validated SSHConnector without contacting the remote host.
func newBareSSHConnector(server shared.Fail2banServer) (*SSHConnector, error) {
	if server.Host == "" {
		return nil, fmt.Errorf("host is required for ssh connector")
	}
	if server.SSHUser == "" {
		return nil, fmt.Errorf("sshUser is required for ssh connector")
	}
	if err := shared.ValidateServerFields(server); err != nil {
		return nil, err
	}
	conn := &SSHConnector{
		server:     server,
		sessionSem: make(chan struct{}, sshMaxConcurrentSessions),
	}

	if server.ReverseTunnelEnabled {
		conn.tunnelPort = resolveTunnelPort(server)
		conn.forwardPort = uiServerPort()
		debugf("Reverse tunnel enabled for server %s, will use -R %d:localhost:%d", server.Name, conn.tunnelPort, conn.forwardPort)
	}
	return conn, nil
}

// Create a new SSHConnector for the given server config.
func NewSSHConnector(server shared.Fail2banServer) (Connector, error) {
	conn, err := newBareSSHConnector(server)
	if err != nil {
		return nil, err
	}

	if kh := conn.knownHostsPath(); kh != "" {
		if err := os.MkdirAll(filepath.Dir(kh), 0o700); err != nil {
			debugf("failed to create known_hosts directory for %s: %v", server.Name, err)
		}
	}

	// Use a timeout context to prevent hanging if SSH server isn't ready yet
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := conn.ensureAction(ctx); err != nil {
		log.Printf("warning: failed to ensure remote fail2ban action for %s during startup (server may not be ready): %v", server.Name, err)
	}
	return conn, nil
}

// =========================================================================
//  Connector Functions
// =========================================================================

func (sc *SSHConnector) Server() shared.Fail2banServer {
	return sc.server
}

// Collects jail status for every active remote jail.
func (sc *SSHConnector) GetJailInfos(ctx context.Context) ([]JailInfo, error) {
	summary, err := sc.GetJailSummary(ctx)
	if err != nil {
		return nil, err
	}
	return summary.Jails, nil
}

func (sc *SSHConnector) GetJailSummary(ctx context.Context) (*JailSummary, error) {
	root := sc.getFail2banPath(ctx)
	script, err := buildBannedSummaryScript(sc.server.SocketPath, JailLocal(root), CustomActionFile(root))
	if err != nil {
		return nil, err
	}
	out, err := sc.runRemoteCommand(ctx, []string{script})
	if err != nil {
		return nil, fmt.Errorf("failed to read jail status from %s: %w", sc.server.Name, err)
	}

	summary, err := splitBannedSummary(out)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sc.server.Name, err)
	}
	infos, err := parseBannedJails(summary.banned)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sc.server.Name, err)
	}
	desired, renderErr := sc.desiredActionConfig()
	drifted := sc.reloadPending.Load() || !summary.actionExists ||
		(renderErr == nil && strings.TrimSpace(summary.actionFile) != strings.TrimSpace(desired))
	return &JailSummary{
		Jails:             infos,
		JailLocalExists:   summary.jailLocalExists,
		JailLocalManaged:  summary.jailLocalExists && strings.Contains(summary.jailLocal, managedJailLocalMarker),
		ActionFileDrifted: drifted,
	}, nil
}

func (sc *SSHConnector) GetBannedIPs(ctx context.Context, jail string) ([]string, error) {
	if err := ValidateJailName(jail); err != nil {
		return nil, err
	}
	out, err := sc.runFail2banCommand(ctx, "get", jail, "banip")
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

func (sc *SSHConnector) UnbanIP(ctx context.Context, jail, ip string) error {
	if err := ValidateJailName(jail); err != nil {
		return err
	}
	if err := shared.ValidateIP(ip); err != nil {
		return err
	}
	_, err := sc.runFail2banCommand(ctx, "set", jail, "unbanip", ip)
	return err
}

func (sc *SSHConnector) BanIP(ctx context.Context, jail, ip string) error {
	if err := ValidateJailName(jail); err != nil {
		return err
	}
	if err := shared.ValidateIP(ip); err != nil {
		return err
	}
	_, err := sc.runFail2banCommand(ctx, "set", jail, "banip", ip)
	return err
}

func (sc *SSHConnector) Reload(ctx context.Context) error {
	// Same tree that ValidateConfiguration checked; the client, not the daemon, reads the files.
	out, err := sc.runFail2banCommand(ctx, "-c", sc.getFail2banPath(ctx), "reload")
	if err != nil {
		return err
	}
	if err := checkReloadOutput(out); err != nil {
		return err
	}
	sc.reloadPending.Store(false)
	return nil
}

func (sc *SSHConnector) ValidateConfiguration(ctx context.Context) error {
	out, err := sc.runFail2banCommand(ctx, "-c", sc.getFail2banPath(ctx), "-t")
	if err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}
	return checkReloadOutput(out)
}

func (sc *SSHConnector) Restart(ctx context.Context) error {
	_, err := sc.RestartWithMode(ctx)
	return err
}

func (sc *SSHConnector) RestartWithMode(ctx context.Context) (string, error) {
	// Try systemd restart on the remote host first.
	out, err := sc.runRemoteCommand(ctx, []string{"sudo", "-n", "systemctl", "restart", "fail2ban"})
	if err == nil {
		if err := sc.checkFail2banHealthyRemote(ctx); err != nil {
			return "restart", fmt.Errorf("remote fail2ban health check after systemd restart failed: %w", err)
		}
		return "restart", nil
	}
	// If systemd is not available or if there is an interactive authentication required, we will fall back to fail2ban-client.
	if sc.isSystemctlUnavailable(out, err) {
		if reloadErr := sc.Reload(ctx); reloadErr != nil {
			return "reload", fmt.Errorf("failed to reload fail2ban via fail2ban-client on remote: %w", reloadErr)
		}
		if err := sc.checkFail2banHealthyRemote(ctx); err != nil {
			return "reload", fmt.Errorf("remote fail2ban health check after reload failed: %w", err)
		}
		return "reload", nil
	}

	// systemctl exists but restart failed for some other reason, we will return the error.
	return "restart", fmt.Errorf("failed to restart fail2ban via systemd on remote: %w (output: %s)", err, out)
}

func (sc *SSHConnector) desiredActionConfig() (string, error) {
	p := mustProvider()
	return p.BuildFail2banActionConfig(sc.actionCallbackURL(), sc.server.ID, p.CallbackSecret())
}

func (sc *SSHConnector) ensureAction(ctx context.Context) error {
	sc.reloadPending.Store(true)
	actionPath := CustomActionFile(sc.getFail2banPath(ctx))
	desired, err := sc.desiredActionConfig()
	if err != nil {
		return fmt.Errorf("refusing to write the action file on %s: %w", sc.server.Name, err)
	}
	script, err := buildEnsureActionScript(actionPath, desired)
	if err != nil {
		return fmt.Errorf("refusing to write the action file on %s: %w", sc.server.Name, err)
	}
	out, err := sc.runRemoteCommand(ctx, []string{script})
	if err != nil {
		return fmt.Errorf("failed to ensure the action file %s on %s: %w", actionPath, sc.server.Name, err)
	}
	if marker := extractMarkerValue(out, missingToolsMarker); marker != "" {
		log.Printf("warning: managed host %s (%s) is missing required tool(s): %s - ban callbacks will arrive empty until installed",
			sc.server.Name, sc.server.ID, marker)
	}
	if marker := extractMarkerValue(out, permWarningMarker); marker != "" {
		log.Printf("warning: the action file %s on %s (%s) stays readable by every user on that host, so the callback secret is exposed - restrict it or let the UI own the file",
			marker, sc.server.Name, sc.server.ID)
	}
	debugf("Successfully ensured action file %s on server %s", actionPath, sc.server.Name)
	return nil
}

// Returns the value after marker on the first matching line, or "".
func extractMarkerValue(output, marker string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, marker); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// =========================================================================
//  SSH Helpers
// =========================================================================

func buildBannedSummaryScript(socketPath, jailLocalPath, actionPath string) (string, error) {
	quotedJailLocal, err := quoteRemotePath(jailLocalPath)
	if err != nil {
		return "", err
	}
	quotedAction, err := quoteRemotePath(actionPath)
	if err != nil {
		return "", err
	}
	sockArg := ""
	if socketPath != "" {
		quotedSock, err := quoteRemotePath(socketPath)
		if err != nil {
			return "", err
		}
		sockArg = "-s " + quotedSock + " "
	}
	return fmt.Sprintf(`sudo fail2ban-client %sbanned
echo %s
if [ -f %s ]; then echo %s; cat %s; else echo %s; fi
if [ -f %s ]; then echo %s; cat %s; else echo %s; fi
echo %s
`, sockArg,
		bannedSectionEnd,
		quotedJailLocal, batchJailLocalBegin, quotedJailLocal, batchJailLocalMissing,
		quotedAction, batchActionBegin, quotedAction, batchActionMissing,
		batchEnd), nil
}

type bannedSummary struct {
	banned          string
	jailLocal       string
	jailLocalExists bool
	actionFile      string
	actionExists    bool
}

func splitBannedSummary(out string) (bannedSummary, error) {
	var res bannedSummary
	var bannedBuf, jailLocalBuf, actionBuf strings.Builder
	const (
		inBanned = iota
		betweenSections
		inJailLocal
		inAction
	)
	mode := inBanned
	complete := false

	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == bannedSectionEnd:
			mode = betweenSections
		case trimmed == batchJailLocalBegin:
			res.jailLocalExists = true
			mode = inJailLocal
		case trimmed == batchJailLocalMissing:
			res.jailLocalExists = false
			mode = betweenSections
		case trimmed == batchActionBegin:
			res.actionExists = true
			mode = inAction
		case trimmed == batchActionMissing:
			res.actionExists = false
			mode = betweenSections
		case trimmed == batchEnd:
			complete = true
			mode = betweenSections
		case mode == inBanned:
			bannedBuf.WriteString(line)
			bannedBuf.WriteString("\n")
		case mode == inJailLocal:
			jailLocalBuf.WriteString(line)
			jailLocalBuf.WriteString("\n")
		case mode == inAction:
			actionBuf.WriteString(line)
			actionBuf.WriteString("\n")
		}
	}
	if !complete {
		return bannedSummary{}, fmt.Errorf("truncated summary output from the remote host")
	}
	res.banned = strings.TrimSpace(bannedBuf.String())
	res.jailLocal = jailLocalBuf.String()
	res.actionFile = actionBuf.String()
	return res, nil
}

func (sc *SSHConnector) runFail2banCommand(ctx context.Context, args ...string) (string, error) {
	words := append([]string{"sudo", "fail2ban-client"}, fail2banArgs(sc.server.SocketPath, args...)...)
	for i, w := range words {
		words[i] = shellQuote(w)
	}
	return sc.runRemoteCommand(ctx, []string{strings.Join(words, " ")})
}

// Detects "no systemd" situations on the remote host or if an interactive authentication is required.
func (sc *SSHConnector) isSystemctlUnavailable(output string, err error) bool {
	if carried, ok := CommandOutput(err); ok {
		output = carried
	}
	msg := strings.ToLower(output + " " + err.Error())
	return strings.Contains(msg, "command not found") ||
		strings.Contains(msg, "system has not been booted with systemd") ||
		strings.Contains(msg, "failed to connect to bus") ||
		strings.Contains(msg, "interactive authentication required") ||
		strings.Contains(msg, "sudo: a terminal is required") ||
		strings.Contains(msg, "sudo: a password is required") ||
		strings.Contains(msg, "sudo: a password is needed") ||
		strings.Contains(msg, "sorry, you must have a tty")
}

func (sc *SSHConnector) checkFail2banHealthyRemote(ctx context.Context) error {
	out, err := sc.runFail2banCommand(ctx, "ping")
	return checkPingOutput(out, err, "remote fail2ban")
}
