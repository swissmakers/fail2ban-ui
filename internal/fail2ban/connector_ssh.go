package fail2ban

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

const sshEnsureActionScript = `python3 - <<'PY'
import base64
import pathlib

action_dir = pathlib.Path("/etc/fail2ban/action.d")
action_dir.mkdir(parents=True, exist_ok=True)
action_cfg = base64.b64decode("__PAYLOAD__").decode("utf-8")
(action_dir / "ui-custom-action.conf").write_text(action_cfg)

jail_file = pathlib.Path("/etc/fail2ban/jail.local")
if not jail_file.exists():
    jail_file.write_text("[DEFAULT]\n")

lines = jail_file.read_text().splitlines()
already = any("Custom Fail2Ban action applied by fail2ban-ui" in line for line in lines)
if not already:
    new_lines = []
    inserted = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("action") and "ui-custom-action" not in stripped and not inserted:
            if not stripped.startswith("#"):
                new_lines.append("# " + line)
            else:
                new_lines.append(line)
            new_lines.append("# Custom Fail2Ban action applied by fail2ban-ui")
            new_lines.append("action = %(action_mwlg)s")
            inserted = True
            continue
        new_lines.append(line)
    if not inserted:
        insert_at = None
        for idx, value in enumerate(new_lines):
            if value.strip().startswith("[DEFAULT]"):
                insert_at = idx + 1
                break
        if insert_at is None:
            new_lines.append("[DEFAULT]")
            insert_at = len(new_lines)
        new_lines.insert(insert_at, "# Custom Fail2Ban action applied by fail2ban-ui")
        new_lines.insert(insert_at + 1, "action = %(action_mwlg)s")
    jail_file.write_text("\n".join(new_lines) + "\n")
PY`

// SSHConnector connects to a remote Fail2ban instance over SSH.
type SSHConnector struct {
	server config.Fail2banServer
}

// NewSSHConnector creates a new SSH connector.
func NewSSHConnector(server config.Fail2banServer) (Connector, error) {
	if server.Host == "" {
		return nil, fmt.Errorf("host is required for ssh connector")
	}
	if server.SSHUser == "" {
		return nil, fmt.Errorf("sshUser is required for ssh connector")
	}
	conn := &SSHConnector{server: server}
	if err := conn.ensureAction(context.Background()); err != nil {
		fmt.Printf("warning: failed to ensure remote fail2ban action for %s: %v\n", server.Name, err)
	}
	return conn, nil
}

func (sc *SSHConnector) ID() string {
	return sc.server.ID
}

func (sc *SSHConnector) Server() config.Fail2banServer {
	return sc.server
}

func (sc *SSHConnector) GetJailInfos(ctx context.Context) ([]JailInfo, error) {
	jails, err := sc.getJails(ctx)
	if err != nil {
		return nil, err
	}

	// Use parallel execution for better performance
	type jailResult struct {
		jail JailInfo
		err  error
	}
	results := make(chan jailResult, len(jails))
	var wg sync.WaitGroup

	for _, jail := range jails {
		wg.Add(1)
		go func(j string) {
			defer wg.Done()
			ips, err := sc.GetBannedIPs(ctx, j)
			if err != nil {
				results <- jailResult{err: err}
				return
			}
			results <- jailResult{
				jail: JailInfo{
					JailName:      j,
					TotalBanned:   len(ips),
					NewInLastHour: 0,
					BannedIPs:     ips,
					Enabled:       true,
				},
			}
		}(jail)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var infos []JailInfo
	for result := range results {
		if result.err != nil {
			continue
		}
		infos = append(infos, result.jail)
	}

	sort.SliceStable(infos, func(i, j int) bool {
		return infos[i].JailName < infos[j].JailName
	})
	return infos, nil
}

func (sc *SSHConnector) GetBannedIPs(ctx context.Context, jail string) ([]string, error) {
	out, err := sc.runFail2banCommand(ctx, "status", jail)
	if err != nil {
		return nil, err
	}
	var bannedIPs []string
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "IP list:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				ips := strings.Fields(strings.TrimSpace(parts[1]))
				bannedIPs = append(bannedIPs, ips...)
			}
			break
		}
	}
	return bannedIPs, nil
}

func (sc *SSHConnector) UnbanIP(ctx context.Context, jail, ip string) error {
	_, err := sc.runFail2banCommand(ctx, "set", jail, "unbanip", ip)
	return err
}

func (sc *SSHConnector) Reload(ctx context.Context) error {
	_, err := sc.runFail2banCommand(ctx, "reload")
	return err
}

func (sc *SSHConnector) Restart(ctx context.Context) error {
	_, err := sc.runRemoteCommand(ctx, []string{"sudo", "systemctl", "restart", "fail2ban"})
	return err
}

func (sc *SSHConnector) GetFilterConfig(ctx context.Context, jail string) (string, error) {
	path := fmt.Sprintf("/etc/fail2ban/filter.d/%s.conf", jail)
	out, err := sc.runRemoteCommand(ctx, []string{"sudo", "cat", path})
	if err != nil {
		return "", fmt.Errorf("failed to read remote filter config: %w", err)
	}
	return out, nil
}

func (sc *SSHConnector) SetFilterConfig(ctx context.Context, jail, content string) error {
	path := fmt.Sprintf("/etc/fail2ban/filter.d/%s.conf", jail)
	cmd := fmt.Sprintf("cat <<'EOF' | sudo tee %s >/dev/null\n%s\nEOF", path, content)
	_, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", cmd})
	return err
}

func (sc *SSHConnector) FetchBanEvents(ctx context.Context, limit int) ([]BanEvent, error) {
	// Not available over SSH without copying logs; return empty slice.
	return []BanEvent{}, nil
}

func (sc *SSHConnector) ensureAction(ctx context.Context) error {
	callbackURL := config.GetCallbackURL()
	actionConfig := config.BuildFail2banActionConfig(callbackURL)
	payload := base64.StdEncoding.EncodeToString([]byte(actionConfig))
	script := strings.ReplaceAll(sshEnsureActionScript, "__PAYLOAD__", payload)
	// Base64 encode the entire script to avoid shell escaping issues
	scriptB64 := base64.StdEncoding.EncodeToString([]byte(script))
	cmd := fmt.Sprintf("echo %s | base64 -d | sudo bash", scriptB64)
	_, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", cmd})
	return err
}

func (sc *SSHConnector) getJails(ctx context.Context) ([]string, error) {
	out, err := sc.runFail2banCommand(ctx, "status")
	if err != nil {
		return nil, err
	}
	var jails []string
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Jail list:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				raw := strings.TrimSpace(parts[1])
				jails = strings.Split(raw, ",")
				for i := range jails {
					jails[i] = strings.TrimSpace(jails[i])
				}
			}
		}
	}
	return jails, nil
}

func (sc *SSHConnector) runFail2banCommand(ctx context.Context, args ...string) (string, error) {
	fail2banArgs := sc.buildFail2banArgs(args...)
	cmdArgs := append([]string{"sudo", "fail2ban-client"}, fail2banArgs...)
	return sc.runRemoteCommand(ctx, cmdArgs)
}

func (sc *SSHConnector) buildFail2banArgs(args ...string) []string {
	if sc.server.SocketPath == "" {
		return args
	}
	base := []string{"-s", sc.server.SocketPath}
	return append(base, args...)
}

func (sc *SSHConnector) runRemoteCommand(ctx context.Context, command []string) (string, error) {
	args := sc.buildSSHArgs(command)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	settingSnapshot := config.GetSettings()
	if settingSnapshot.Debug {
		config.DebugLog("SSH command [%s]: ssh %s", sc.server.Name, strings.Join(args, " "))
	}
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		if settingSnapshot.Debug {
			config.DebugLog("SSH command error [%s]: %v | output: %s", sc.server.Name, err, output)
		}
		return output, fmt.Errorf("ssh command failed: %w (output: %s)", err, output)
	}
	if settingSnapshot.Debug {
		config.DebugLog("SSH command output [%s]: %s", sc.server.Name, output)
	}
	return output, nil
}

func (sc *SSHConnector) buildSSHArgs(command []string) []string {
	args := []string{"-o", "BatchMode=yes"}
	if sc.server.SSHKeyPath != "" {
		args = append(args, "-i", sc.server.SSHKeyPath)
	}
	if sc.server.Port > 0 {
		args = append(args, "-p", strconv.Itoa(sc.server.Port))
	}
	target := sc.server.Host
	if sc.server.SSHUser != "" {
		target = fmt.Sprintf("%s@%s", sc.server.SSHUser, target)
	}
	args = append(args, target)
	args = append(args, command...)
	return args
}

// GetAllJails implements Connector.
func (sc *SSHConnector) GetAllJails(ctx context.Context) ([]JailInfo, error) {
	// Read jail.local and jail.d files remotely
	var allJails []JailInfo

	// Parse jail.local
	jailLocalContent, err := sc.runRemoteCommand(ctx, []string{"sudo", "cat", "/etc/fail2ban/jail.local"})
	if err == nil {
		jails := parseJailConfigContent(jailLocalContent)
		allJails = append(allJails, jails...)
	}

	// Parse jail.d directory
	jailDCmd := "sudo find /etc/fail2ban/jail.d -maxdepth 1 -name '*.conf' -type f"
	jailDList, err := sc.runRemoteCommand(ctx, []string{"sh", "-c", jailDCmd})
	if err == nil && jailDList != "" {
		for _, file := range strings.Split(jailDList, "\n") {
			file = strings.TrimSpace(file)
			if file == "" {
				continue
			}
			content, err := sc.runRemoteCommand(ctx, []string{"sudo", "cat", file})
			if err == nil {
				jails := parseJailConfigContent(content)
				allJails = append(allJails, jails...)
			}
		}
	}

	return allJails, nil
}

// UpdateJailEnabledStates implements Connector.
func (sc *SSHConnector) UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error {
	// Read current jail.local
	content, err := sc.runRemoteCommand(ctx, []string{"sudo", "cat", "/etc/fail2ban/jail.local"})
	if err != nil {
		return fmt.Errorf("failed to read jail.local: %w", err)
	}

	// Update enabled states
	lines := strings.Split(content, "\n")
	var outputLines []string
	var currentJail string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			currentJail = strings.Trim(trimmed, "[]")
			outputLines = append(outputLines, line)
		} else if strings.HasPrefix(trimmed, "enabled") {
			if val, ok := updates[currentJail]; ok {
				outputLines = append(outputLines, fmt.Sprintf("enabled = %t", val))
				delete(updates, currentJail)
			} else {
				outputLines = append(outputLines, line)
			}
		} else {
			outputLines = append(outputLines, line)
		}
	}

	// Write back
	newContent := strings.Join(outputLines, "\n")
	cmd := fmt.Sprintf("cat <<'EOF' | sudo tee /etc/fail2ban/jail.local >/dev/null\n%s\nEOF", newContent)
	_, err = sc.runRemoteCommand(ctx, []string{"bash", "-lc", cmd})
	return err
}

// GetFilters implements Connector.
func (sc *SSHConnector) GetFilters(ctx context.Context) ([]string, error) {
	// Use find with sudo - execute sudo separately to avoid shell issues
	// First try with sudo, if that fails, the error will be clear
	list, err := sc.runRemoteCommand(ctx, []string{"sudo", "find", "/etc/fail2ban/filter.d", "-maxdepth", "1", "-type", "f"})
	if err != nil {
		return nil, fmt.Errorf("failed to list filters: %w", err)
	}
	// Filter for .conf files and extract names in Go
	var filters []string
	seen := make(map[string]bool) // Avoid duplicates
	for _, line := range strings.Split(list, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Only process .conf files - be strict about the extension
		if !strings.HasSuffix(line, ".conf") {
			continue
		}
		// Exclude backup files and other non-filter files
		if strings.HasSuffix(line, ".conf.bak") ||
			strings.HasSuffix(line, ".conf~") ||
			strings.HasSuffix(line, ".conf.old") ||
			strings.HasSuffix(line, ".conf.rpmnew") ||
			strings.HasSuffix(line, ".conf.rpmsave") ||
			strings.Contains(line, "README") {
			continue
		}
		parts := strings.Split(line, "/")
		if len(parts) > 0 {
			filename := parts[len(parts)-1]
			// Double-check it ends with .conf
			if !strings.HasSuffix(filename, ".conf") {
				continue
			}
			name := strings.TrimSuffix(filename, ".conf")
			if name != "" && !seen[name] {
				seen[name] = true
				filters = append(filters, name)
			}
		}
	}
	return filters, nil
}

// TestFilter implements Connector.
func (sc *SSHConnector) TestFilter(ctx context.Context, filterName string, logLines []string) ([]string, error) {
	if len(logLines) == 0 {
		return []string{}, nil
	}

	// Sanitize filter name to prevent path traversal
	filterName = strings.TrimSpace(filterName)
	if filterName == "" {
		return nil, fmt.Errorf("filter name cannot be empty")
	}
	// Remove any path components
	filterName = strings.ReplaceAll(filterName, "/", "")
	filterName = strings.ReplaceAll(filterName, "..", "")

	// Use fail2ban-regex with filter name directly - it handles everything
	// Format: fail2ban-regex "log line" /etc/fail2ban/filter.d/filter-name.conf
	filterPath := fmt.Sprintf("/etc/fail2ban/filter.d/%s.conf", filterName)

	var matches []string
	for _, logLine := range logLines {
		logLine = strings.TrimSpace(logLine)
		if logLine == "" {
			continue
		}
		// Use fail2ban-regex: log line as string, filter file path
		// Escape the log line for shell safety
		escapedLine := strconv.Quote(logLine)
		cmd := fmt.Sprintf("sudo fail2ban-regex %s %s", escapedLine, strconv.Quote(filterPath))
		out, err := sc.runRemoteCommand(ctx, []string{"sh", "-c", cmd})
		// fail2ban-regex returns success (exit 0) if the line matches
		// Look for "Lines: 1 lines, 0 ignored, 1 matched" or similar success indicators
		if err == nil {
			// Check if output indicates a match
			output := strings.ToLower(out)
			if strings.Contains(output, "matched") ||
				strings.Contains(output, "success") ||
				strings.Contains(output, "1 matched") {
				matches = append(matches, logLine)
			}
		}
	}
	return matches, nil
}

// parseJailConfigContent parses jail configuration content and returns JailInfo slice.
func parseJailConfigContent(content string) []JailInfo {
	var jails []JailInfo
	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentJail string
	enabled := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if currentJail != "" && currentJail != "DEFAULT" {
				jails = append(jails, JailInfo{
					JailName: currentJail,
					Enabled:  enabled,
				})
			}
			currentJail = strings.Trim(line, "[]")
			enabled = true
		} else if strings.HasPrefix(strings.ToLower(line), "enabled") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				value := strings.TrimSpace(parts[1])
				enabled = strings.EqualFold(value, "true")
			}
		}
	}
	if currentJail != "" && currentJail != "DEFAULT" {
		jails = append(jails, JailInfo{
			JailName: currentJail,
			Enabled:  enabled,
		})
	}
	return jails
}
