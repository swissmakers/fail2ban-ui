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
	"encoding/base64"
	"fmt"
	"log"
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
	server       shared.Fail2banServer
	fail2banPath string
	pathMutex    sync.RWMutex
	tunnelPort   int
	forwardPort  int
	tunnelWasUp  bool
	closed       atomic.Bool
	masterMu     sync.Mutex
	masterUp     atomic.Bool
	sessionSem   chan struct{}
}

const sshEnsureActionScript = `python3 - <<'PY'
import base64
import os
import pathlib
import shutil
import sys

try:
    action_dir = pathlib.Path("/etc/fail2ban/action.d")
    action_dir.mkdir(parents=True, exist_ok=True)
    action_cfg = base64.b64decode("__PAYLOAD__").decode("utf-8")
    action_file = action_dir / "ui-custom-action.conf"
    action_file.write_text(action_cfg)
    os.chmod(action_file, 0o600)
    missing = [t for t in ("jq", "curl") if shutil.which(t) is None]
    if missing:
        sys.stdout.write("F2BUI_MISSING_TOOLS:" + ",".join(missing) + "\n")
except Exception as e:
    sys.stderr.write(f"Error: {e}\n")
    sys.exit(1)
PY`

// =========================================================================
//  Constructor
// =========================================================================

// Create a new SSHConnector for the given server config.
func NewSSHConnector(server shared.Fail2banServer) (Connector, error) {
	if server.Host == "" {
		return nil, fmt.Errorf("host is required for ssh connector")
	}
	if server.SSHUser == "" {
		return nil, fmt.Errorf("sshUser is required for ssh connector")
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

	// Use a timeout context to prevent hanging if SSH server isn't ready yet
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := conn.ensureAction(ctx); err != nil {
		debugf("warning: failed to ensure remote fail2ban action for %s during startup (server may not be ready): %v", server.Name, err)
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

// GetJailSummary fetches every jail's banned IPs plus the jail.local integrity state in a single remote command
func (sc *SSHConnector) GetJailSummary(ctx context.Context) (*JailSummary, error) {
	script, err := buildBannedSummaryScript(sc.server.SocketPath, JailLocal(sc.getFail2banPath(ctx)))
	if err != nil {
		return nil, err
	}
	out, err := sc.runRemoteCommand(ctx, []string{script})
	if err != nil {
		return nil, fmt.Errorf("failed to read jail status from %s: %w", sc.server.Name, err)
	}

	bannedOut, jailLocal, exists, err := splitBannedSummary(out)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sc.server.Name, err)
	}
	infos, err := parseBannedJails(bannedOut)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (fail2ban 0.11 or newer is required)", sc.server.Name, err)
	}
	return &JailSummary{
		Jails:            infos,
		JailLocalExists:  exists,
		JailLocalManaged: exists && strings.Contains(jailLocal, managedJailLocalMarker),
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
	if err := ValidateIP(ip); err != nil {
		return err
	}
	_, err := sc.runFail2banCommand(ctx, "set", jail, "unbanip", ip)
	return err
}

func (sc *SSHConnector) BanIP(ctx context.Context, jail, ip string) error {
	if err := ValidateJailName(jail); err != nil {
		return err
	}
	if err := ValidateIP(ip); err != nil {
		return err
	}
	_, err := sc.runFail2banCommand(ctx, "set", jail, "banip", ip)
	return err
}

func (sc *SSHConnector) Reload(ctx context.Context) error {
	out, err := sc.runFail2banCommand(ctx, "reload")
	if err != nil {
		return err
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
		reloadOut, reloadErr := sc.runFail2banCommand(ctx, "reload")
		if reloadErr != nil {
			return "reload", fmt.Errorf("failed to reload fail2ban via fail2ban-client on remote: %w (output: %s)",
				reloadErr, strings.TrimSpace(reloadOut))
		}
		if err := sc.checkFail2banHealthyRemote(ctx); err != nil {
			return "reload", fmt.Errorf("remote fail2ban health check after reload failed: %w", err)
		}
		return "reload", nil
	}

	// systemctl exists but restart failed for some other reason, we will return the error.
	return "restart", fmt.Errorf("failed to restart fail2ban via systemd on remote: %w (output: %s)", err, out)
}

func (sc *SSHConnector) ensureAction(ctx context.Context) error {
	p := mustProvider()
	actionConfig := p.BuildFail2banActionConfig(sc.actionCallbackURL(), sc.server.ID, p.CallbackSecret())
	payload := base64.StdEncoding.EncodeToString([]byte(actionConfig))
	script := strings.ReplaceAll(sshEnsureActionScript, "__PAYLOAD__", payload)
	scriptB64 := base64.StdEncoding.EncodeToString([]byte(script))
	args := sc.buildSSHArgs([]string{"sh", "-s"})

	// The remote shell reads the base64 payload from stdin and pipes it through base64 -d | bash.
	scriptContent := fmt.Sprintf("cat <<'ENDBASE64' | base64 -d | bash\n%s\nENDBASE64\n", scriptB64)

	debugf("SSH ensureAction command [%s]: ssh %s (with here-doc via stdin)", sc.server.Name, strings.Join(args, " "))

	sc.ensureMasterLazy(ctx)
	if err := sc.acquireSession(ctx); err != nil {
		return err
	}
	defer sc.releaseSession()

	stdout, stderr, execErr := sc.execSSH(ctx, args, strings.NewReader(scriptContent))
	if execErr != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	output, err := selectCommandOutput(stdout, stderr, execErr)
	if err != nil {
		debugf("Failed to ensure action file for server %s: %v", sc.server.Name, err)
		return fmt.Errorf("failed to ensure action file on remote server %s: %w", sc.server.Name, err)
	}
	if marker := extractMissingToolsWarning(output); marker != "" {
		log.Printf("warning: managed host %s (%s) is missing required tool(s): %s - ban callbacks will arrive empty until installed",
			sc.server.Name, sc.server.ID, marker)
	}
	if output != "" {
		debugf("Successfully ensured action file for server %s (output: %s)", sc.server.Name, output)
	} else {
		debugf("Successfully ensured action file for server %s (no output)", sc.server.Name)
	}
	return nil
}

func extractMissingToolsWarning(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "F2BUI_MISSING_TOOLS:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// =========================================================================
//  SSH Helpers
// =========================================================================

func buildBannedSummaryScript(socketPath, jailLocalPath string) (string, error) {
	quotedJailLocal, err := quoteRemotePath(jailLocalPath)
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
echo %s
`, sockArg,
		bannedSectionEnd,
		quotedJailLocal, batchJailLocalBegin, quotedJailLocal, batchJailLocalMissing,
		batchEnd), nil
}

func splitBannedSummary(out string) (banned, jailLocal string, jailLocalExists bool, err error) {
	var bannedBuf, jailLocalBuf strings.Builder
	const (
		inBanned = iota
		betweenSections
		inJailLocal
	)
	mode := inBanned
	complete := false

	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == bannedSectionEnd:
			mode = betweenSections
		case trimmed == batchJailLocalBegin:
			jailLocalExists = true
			mode = inJailLocal
		case trimmed == batchJailLocalMissing:
			jailLocalExists = false
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
		}
	}
	if !complete {
		return "", "", false, fmt.Errorf("truncated summary output from the remote host")
	}
	return strings.TrimSpace(bannedBuf.String()), jailLocalBuf.String(), jailLocalExists, nil
}

func (sc *SSHConnector) runFail2banCommand(ctx context.Context, args ...string) (string, error) {
	cmdArgs := append([]string{"sudo", "fail2ban-client"}, fail2banArgs(sc.server.SocketPath, args...)...)
	return sc.runRemoteCommand(ctx, cmdArgs)
}

// Detects "no systemd" situations on the remote host or if an interactive authentication is required.
func (sc *SSHConnector) isSystemctlUnavailable(output string, err error) bool {
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
