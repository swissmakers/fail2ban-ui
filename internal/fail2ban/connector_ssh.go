package fail2ban

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	// Validate filter name
	jail = strings.TrimSpace(jail)
	if jail == "" {
		return "", fmt.Errorf("filter name cannot be empty")
	}

	// Try .local first, then fallback to .conf
	localPath := fmt.Sprintf("/etc/fail2ban/filter.d/%s.local", jail)
	confPath := fmt.Sprintf("/etc/fail2ban/filter.d/%s.conf", jail)

	out, err := sc.runRemoteCommand(ctx, []string{"cat", localPath})
	if err == nil {
		return out, nil
	}

	// Fallback to .conf
	out, err = sc.runRemoteCommand(ctx, []string{"cat", confPath})
	if err != nil {
		return "", fmt.Errorf("failed to read remote filter config (tried .local and .conf): %w", err)
	}
	return out, nil
}

func (sc *SSHConnector) SetFilterConfig(ctx context.Context, jail, content string) error {
	// Validate filter name
	jail = strings.TrimSpace(jail)
	if jail == "" {
		return fmt.Errorf("filter name cannot be empty")
	}

	// Ensure .local file exists (copy from .conf if needed)
	localPath := fmt.Sprintf("/etc/fail2ban/filter.d/%s.local", jail)
	confPath := fmt.Sprintf("/etc/fail2ban/filter.d/%s.conf", jail)

	// Check if .local exists, if not, copy from .conf
	checkScript := fmt.Sprintf(`
		if [ ! -f "%s" ]; then
			if [ -f "%s" ]; then
				cp "%s" "%s"
			else
				echo "Error: filter .conf file does not exist: %s" >&2
				exit 1
			fi
		fi
	`, localPath, confPath, confPath, localPath, confPath)

	_, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", checkScript})
	if err != nil {
		return fmt.Errorf("failed to ensure filter .local file: %w", err)
	}

	// Write to .local file
	cmd := fmt.Sprintf("cat <<'EOF' | tee %s >/dev/null\n%s\nEOF", localPath, content)
	_, err = sc.runRemoteCommand(ctx, []string{"bash", "-lc", cmd})
	return err
}

func (sc *SSHConnector) FetchBanEvents(ctx context.Context, limit int) ([]BanEvent, error) {
	// Not available over SSH without copying logs; return empty slice.
	return []BanEvent{}, nil
}

func (sc *SSHConnector) ensureAction(ctx context.Context) error {
	callbackURL := config.GetCallbackURL()
	actionConfig := config.BuildFail2banActionConfig(callbackURL, sc.server.ID)
	payload := base64.StdEncoding.EncodeToString([]byte(actionConfig))
	script := strings.ReplaceAll(sshEnsureActionScript, "__PAYLOAD__", payload)
	// Base64 encode the entire script to avoid shell escaping issues
	scriptB64 := base64.StdEncoding.EncodeToString([]byte(script))

	// Use sh -s to read commands from stdin, then pass the base64 string via stdin
	// This is the most reliable way to pass data via SSH
	args := sc.buildSSHArgs([]string{"sh", "-s"})
	cmd := exec.CommandContext(ctx, "ssh", args...)

	// Create a script that reads the base64 string from stdin and pipes it through base64 -d | bash
	// We use a here-document to pass the base64 string
	scriptContent := fmt.Sprintf("cat <<'ENDBASE64' | base64 -d | bash\n%s\nENDBASE64\n", scriptB64)
	cmd.Stdin = strings.NewReader(scriptContent)

	settingSnapshot := config.GetSettings()
	if settingSnapshot.Debug {
		config.DebugLog("SSH ensureAction command [%s]: ssh %s (with here-doc via stdin)", sc.server.Name, strings.Join(args, " "))
	}

	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		config.DebugLog("Failed to ensure action file for server %s: %v (output: %s)", sc.server.Name, err, output)
		return fmt.Errorf("failed to ensure action file on remote server %s: %w (remote output: %s)", sc.server.Name, err, output)
	}
	if output != "" {
		config.DebugLog("Successfully ensured action file for server %s (output: %s)", sc.server.Name, output)
	} else {
		config.DebugLog("Successfully ensured action file for server %s (no output)", sc.server.Name)
	}
	return nil
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
	// In containerized environments, disable strict host key checking
	if _, container := os.LookupEnv("CONTAINER"); container {
		args = append(args,
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "LogLevel=ERROR",
		)
	}
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
	// Read jail.local (DEFAULT only) and jail.d files remotely
	var allJails []JailInfo

	// Parse jail.local (only DEFAULT section, skip other jails)
	jailLocalContent, err := sc.runRemoteCommand(ctx, []string{"cat", "/etc/fail2ban/jail.local"})
	if err == nil {
		// Filter to only include DEFAULT section jails (though DEFAULT itself isn't returned as a jail)
		jails := parseJailConfigContent(jailLocalContent)
		// Filter out DEFAULT section - we only want actual jails
		for _, jail := range jails {
			if jail.JailName != "DEFAULT" {
				allJails = append(allJails, jail)
			}
		}
	}

	// Parse jail.d directory - prefer .local over .conf files
	// First get .local files
	jailDLocalCmd := "find /etc/fail2ban/jail.d -maxdepth 1 -name '*.local' -type f 2>/dev/null"
	jailDLocalList, err := sc.runRemoteCommand(ctx, []string{"sh", "-c", jailDLocalCmd})
	processedJails := make(map[string]bool)
	if err == nil && jailDLocalList != "" {
		for _, file := range strings.Split(jailDLocalList, "\n") {
			file = strings.TrimSpace(file)
			if file == "" {
				continue
			}
			// Skip files that start with . (like .local) - these are invalid
			baseName := filepath.Base(file)
			if strings.HasPrefix(baseName, ".") {
				config.DebugLog("Skipping invalid jail file: %s", file)
				continue
			}
			content, err := sc.runRemoteCommand(ctx, []string{"cat", file})
			if err == nil {
				jails := parseJailConfigContent(content)
				for _, jail := range jails {
					// Skip jails with empty names
					if jail.JailName != "" {
						allJails = append(allJails, jail)
						processedJails[jail.JailName] = true
					}
				}
			}
		}
	}
	// Then get .conf files that don't have corresponding .local files
	jailDConfCmd := "find /etc/fail2ban/jail.d -maxdepth 1 -name '*.conf' -type f 2>/dev/null"
	jailDConfList, err := sc.runRemoteCommand(ctx, []string{"sh", "-c", jailDConfCmd})
	if err == nil && jailDConfList != "" {
		for _, file := range strings.Split(jailDConfList, "\n") {
			file = strings.TrimSpace(file)
			if file == "" {
				continue
			}
			// Extract jail name from filename
			baseName := strings.TrimSuffix(filepath.Base(file), ".conf")
			// Skip files that start with . (like .conf) - these are invalid
			if baseName == "" || strings.HasPrefix(filepath.Base(file), ".") {
				config.DebugLog("Skipping invalid jail file: %s", file)
				continue
			}
			// Only process if we haven't already processed this jail from a .local file
			if !processedJails[baseName] {
				content, err := sc.runRemoteCommand(ctx, []string{"cat", file})
				if err == nil {
					jails := parseJailConfigContent(content)
					allJails = append(allJails, jails...)
				}
			}
		}
	}

	return allJails, nil
}

// UpdateJailEnabledStates implements Connector.
func (sc *SSHConnector) UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error {
	// Ensure jail.d directory exists
	_, err := sc.runRemoteCommand(ctx, []string{"mkdir", "-p", "/etc/fail2ban/jail.d"})
	if err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}

	// Update each jail in its own .local file
	for jailName, enabled := range updates {
		// Validate jail name - skip empty or invalid names
		jailName = strings.TrimSpace(jailName)
		if jailName == "" {
			config.DebugLog("Skipping empty jail name in updates map")
			continue
		}

		localPath := fmt.Sprintf("/etc/fail2ban/jail.d/%s.local", jailName)
		confPath := fmt.Sprintf("/etc/fail2ban/jail.d/%s.conf", jailName)

		// Ensure .local file exists (copy from .conf if needed)
		ensureScript := fmt.Sprintf(`
			if [ ! -f "%s" ]; then
				if [ -f "%s" ]; then
					cp "%s" "%s"
				else
					echo "[%s]" > "%s"
				fi
			fi
		`, localPath, confPath, confPath, localPath, jailName, localPath)

		if _, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", ensureScript}); err != nil {
			return fmt.Errorf("failed to ensure .local file for jail %s: %w", jailName, err)
		}

		// Read existing .local file
		content, err := sc.runRemoteCommand(ctx, []string{"cat", localPath})
		if err != nil {
			return fmt.Errorf("failed to read jail .local file %s: %w", localPath, err)
		}

		// Update enabled state in existing file
		lines := strings.Split(content, "\n")
		var outputLines []string
		var foundEnabled bool
		var currentJail string

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				currentJail = strings.Trim(trimmed, "[]")
				outputLines = append(outputLines, line)
			} else if strings.HasPrefix(strings.ToLower(trimmed), "enabled") {
				if currentJail == jailName {
					outputLines = append(outputLines, fmt.Sprintf("enabled = %t", enabled))
					foundEnabled = true
				} else {
					outputLines = append(outputLines, line)
				}
			} else {
				outputLines = append(outputLines, line)
			}
		}

		// If enabled line not found, add it after the jail section header
		if !foundEnabled {
			var newLines []string
			for i, line := range outputLines {
				newLines = append(newLines, line)
				if strings.TrimSpace(line) == fmt.Sprintf("[%s]", jailName) {
					newLines = append(newLines, fmt.Sprintf("enabled = %t", enabled))
					if i+1 < len(outputLines) {
						newLines = append(newLines, outputLines[i+1:]...)
					}
					break
				}
			}
			if len(newLines) > len(outputLines) {
				outputLines = newLines
			} else {
				outputLines = append(outputLines, fmt.Sprintf("enabled = %t", enabled))
			}
		}

		// Write updated content to .local file
		newContent := strings.Join(outputLines, "\n")
		cmd := fmt.Sprintf("cat <<'EOF' | tee %s >/dev/null\n%s\nEOF", localPath, newContent)
		if _, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", cmd}); err != nil {
			return fmt.Errorf("failed to write jail .local file %s: %w", localPath, err)
		}
	}
	return nil
}

// GetFilters implements Connector.
func (sc *SSHConnector) GetFilters(ctx context.Context) ([]string, error) {
	// Use find to list filter files
	list, err := sc.runRemoteCommand(ctx, []string{"find", "/etc/fail2ban/filter.d", "-maxdepth", "1", "-type", "f"})
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
	sort.Strings(filters)
	return filters, nil
}

// TestFilter implements Connector.
func (sc *SSHConnector) TestFilter(ctx context.Context, filterName string, logLines []string) (string, string, error) {
	cleaned := normalizeLogLines(logLines)
	if len(cleaned) == 0 {
		return "No log lines provided.\n", "", nil
	}

	// Sanitize filter name to prevent path traversal
	filterName = strings.TrimSpace(filterName)
	if filterName == "" {
		return "", "", fmt.Errorf("filter name cannot be empty")
	}
	// Remove any path components
	filterName = strings.ReplaceAll(filterName, "/", "")
	filterName = strings.ReplaceAll(filterName, "..", "")

	// Try .local first, then fallback to .conf
	localPath := fmt.Sprintf("/etc/fail2ban/filter.d/%s.local", filterName)
	confPath := fmt.Sprintf("/etc/fail2ban/filter.d/%s.conf", filterName)

	const heredocMarker = "F2B_FILTER_TEST_LOG"
	logContent := strings.Join(cleaned, "\n")

	script := fmt.Sprintf(`
set -e
LOCAL_PATH=%[1]q
CONF_PATH=%[2]q
FILTER_PATH=""
if [ -f "$LOCAL_PATH" ]; then
  FILTER_PATH="$LOCAL_PATH"
elif [ -f "$CONF_PATH" ]; then
  FILTER_PATH="$CONF_PATH"
else
  echo "Filter not found: checked both $LOCAL_PATH and $CONF_PATH" >&2
  exit 1
fi
echo "FILTER_PATH:$FILTER_PATH"
TMPFILE=$(mktemp /tmp/fail2ban-test-XXXXXX.log)
trap 'rm -f "$TMPFILE"' EXIT
cat <<'%[3]s' > "$TMPFILE"
%[4]s
%[3]s
fail2ban-regex "$TMPFILE" "$FILTER_PATH" || true
`, localPath, confPath, heredocMarker, logContent)

	out, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", script})
	if err != nil {
		return "", "", err
	}

	// Extract filter path from output (it's on the first line with FILTER_PATH: prefix)
	lines := strings.Split(out, "\n")
	var filterPath string
	var outputLines []string
	foundPathMarker := false

	for _, line := range lines {
		if strings.HasPrefix(line, "FILTER_PATH:") {
			filterPath = strings.TrimPrefix(line, "FILTER_PATH:")
			filterPath = strings.TrimSpace(filterPath)
			foundPathMarker = true
			// Skip this line from the output
			continue
		}
		outputLines = append(outputLines, line)
	}

	// If we didn't find FILTER_PATH marker, try to determine it
	if !foundPathMarker || filterPath == "" {
		// Check which file exists remotely
		localOut, localErr := sc.runRemoteCommand(ctx, []string{"test", "-f", localPath, "&&", "echo", localPath, "||", "echo", ""})
		if localErr == nil && strings.TrimSpace(localOut) != "" {
			filterPath = strings.TrimSpace(localOut)
		} else {
			filterPath = confPath
		}
	}

	output := strings.Join(outputLines, "\n")
	return output, filterPath, nil
}

// GetJailConfig implements Connector.
func (sc *SSHConnector) GetJailConfig(ctx context.Context, jail string) (string, error) {
	// Validate jail name
	jail = strings.TrimSpace(jail)
	if jail == "" {
		return "", fmt.Errorf("jail name cannot be empty")
	}

	// Try .local first, then fallback to .conf
	localPath := fmt.Sprintf("/etc/fail2ban/jail.d/%s.local", jail)
	confPath := fmt.Sprintf("/etc/fail2ban/jail.d/%s.conf", jail)

	out, err := sc.runRemoteCommand(ctx, []string{"cat", localPath})
	if err == nil {
		return out, nil
	}

	// Fallback to .conf
	out, err = sc.runRemoteCommand(ctx, []string{"cat", confPath})
	if err != nil {
		// If neither exists, return empty jail section
		return fmt.Sprintf("[%s]\n", jail), nil
	}
	return out, nil
}

// SetJailConfig implements Connector.
func (sc *SSHConnector) SetJailConfig(ctx context.Context, jail, content string) error {
	// Validate jail name
	jail = strings.TrimSpace(jail)
	if jail == "" {
		return fmt.Errorf("jail name cannot be empty")
	}

	localPath := fmt.Sprintf("/etc/fail2ban/jail.d/%s.local", jail)
	confPath := fmt.Sprintf("/etc/fail2ban/jail.d/%s.conf", jail)

	// Ensure jail.d directory exists
	_, err := sc.runRemoteCommand(ctx, []string{"mkdir", "-p", "/etc/fail2ban/jail.d"})
	if err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}

	// Ensure .local file exists (copy from .conf if needed)
	ensureScript := fmt.Sprintf(`
		if [ ! -f "%s" ]; then
			if [ -f "%s" ]; then
				cp "%s" "%s"
			else
				echo "[%s]" > "%s"
			fi
		fi
	`, localPath, confPath, confPath, localPath, jail, localPath)

	if _, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", ensureScript}); err != nil {
		return fmt.Errorf("failed to ensure .local file for jail %s: %w", jail, err)
	}

	// Write to .local file
	cmd := fmt.Sprintf("cat <<'EOF' | tee %s >/dev/null\n%s\nEOF", localPath, content)
	_, err = sc.runRemoteCommand(ctx, []string{"bash", "-lc", cmd})
	return err
}

// TestLogpath implements Connector.
func (sc *SSHConnector) TestLogpath(ctx context.Context, logpath string) ([]string, error) {
	if logpath == "" {
		return []string{}, nil
	}

	logpath = strings.TrimSpace(logpath)
	hasWildcard := strings.ContainsAny(logpath, "*?[")

	var script string
	if hasWildcard {
		// Use find with glob pattern
		script = fmt.Sprintf(`
set -e
LOGPATH=%q
# Use find for glob patterns
find $(dirname "$LOGPATH") -maxdepth 1 -path "$LOGPATH" -type f 2>/dev/null | sort
`, logpath)
	} else {
		// Check if it's a directory or file
		script = fmt.Sprintf(`
set -e
LOGPATH=%q
if [ -d "$LOGPATH" ]; then
  find "$LOGPATH" -maxdepth 1 -type f 2>/dev/null | sort
elif [ -f "$LOGPATH" ]; then
  echo "$LOGPATH"
fi
`, logpath)
	}

	out, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", script})
	if err != nil {
		return []string{}, nil // Return empty on error
	}

	var matches []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			matches = append(matches, line)
		}
	}
	return matches, nil
}

// TestLogpathWithResolution implements Connector.
// Resolves variables on remote system, then tests the resolved path.
func (sc *SSHConnector) TestLogpathWithResolution(ctx context.Context, logpath string) (originalPath, resolvedPath string, files []string, err error) {
	originalPath = strings.TrimSpace(logpath)
	if originalPath == "" {
		return originalPath, "", []string{}, nil
	}

	// Create Python script to resolve variables on remote system
	resolveScript := fmt.Sprintf(`python3 - <<'PYEOF'
import os
import re
import glob
from pathlib import Path

def extract_variables(s):
    """Extract all variable names from a string."""
    pattern = r'%%\(([^)]+)\)s'
    return re.findall(pattern, s)

def find_variable_definition(var_name, fail2ban_path="/etc/fail2ban"):
    """Search for variable definition in all .conf files."""
    var_name_lower = var_name.lower()
    
    for conf_file in Path(fail2ban_path).rglob("*.conf"):
        try:
            with open(conf_file, 'r') as f:
                current_var = None
                current_value = []
                in_multiline = False
                
                for line in f:
                    original_line = line
                    line = line.strip()
                    
                    if not in_multiline:
                        if '=' in line and not line.startswith('#'):
                            parts = line.split('=', 1)
                            key = parts[0].strip()
                            value = parts[1].strip()
                            
                            if key.lower() == var_name_lower:
                                current_var = key
                                current_value = [value]
                                in_multiline = True
                                continue
                    else:
                        # Check if continuation or new variable/section
                        if line.startswith('[') or (not line.startswith(' ') and '=' in line and not line.startswith('\t')):
                            # End of multi-line
                            return ' '.join(current_value)
                        else:
                            # Continuation
                            current_value.append(line)
                
                if in_multiline and current_var:
                    return ' '.join(current_value)
        except:
            continue
    
    return None

def resolve_variable_recursive(var_name, visited=None):
    """Resolve variable recursively."""
    if visited is None:
        visited = set()
    
    if var_name in visited:
        raise ValueError(f"Circular reference detected for variable '{var_name}'")
    
    visited.add(var_name)
    
    try:
        value = find_variable_definition(var_name)
        if value is None:
            raise ValueError(f"Variable '{var_name}' not found")
        
        # Check for nested variables
        nested_vars = extract_variables(value)
        if not nested_vars:
            return value
        
        # Resolve nested variables
        resolved = value
        for nested_var in nested_vars:
            nested_value = resolve_variable_recursive(nested_var, visited.copy())
            pattern = f'%%({re.escape(nested_var)})s'
            resolved = re.sub(pattern, nested_value, resolved)
        
        return resolved
    finally:
        visited.discard(var_name)

def resolve_logpath(logpath):
    """Resolve all variables in logpath."""
    variables = extract_variables(logpath)
    if not variables:
        return logpath
    
    resolved = logpath
    for var_name in variables:
        var_value = resolve_variable_recursive(var_name)
        pattern = f'%%({re.escape(var_name)})s'
        resolved = re.sub(pattern, var_value, resolved)
    
    return resolved

# Main
logpath = %q
try:
    resolved = resolve_logpath(logpath)
    print(f"RESOLVED:{resolved}")
except Exception as e:
    print(f"ERROR:{str(e)}")
    exit(1)
PYEOF
`, originalPath)

	// Run resolution script
	resolveOut, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", resolveScript})
	if err != nil {
		return originalPath, "", nil, fmt.Errorf("failed to resolve variables: %w", err)
	}

	resolveOut = strings.TrimSpace(resolveOut)
	if strings.HasPrefix(resolveOut, "ERROR:") {
		return originalPath, "", nil, errors.New(strings.TrimPrefix(resolveOut, "ERROR:"))
	}
	if strings.HasPrefix(resolveOut, "RESOLVED:") {
		resolvedPath = strings.TrimPrefix(resolveOut, "RESOLVED:")
	} else {
		// Fallback: use original if resolution failed
		resolvedPath = originalPath
	}

	// Test the resolved path
	files, err = sc.TestLogpath(ctx, resolvedPath)
	if err != nil {
		return originalPath, resolvedPath, nil, fmt.Errorf("failed to test logpath: %w", err)
	}

	return originalPath, resolvedPath, files, nil
}

// UpdateDefaultSettings implements Connector.
func (sc *SSHConnector) UpdateDefaultSettings(ctx context.Context, settings config.AppSettings) error {
	jailLocalPath := "/etc/fail2ban/jail.local"

	// Read existing file if it exists
	existingContent, err := sc.runRemoteCommand(ctx, []string{"cat", jailLocalPath})
	if err != nil {
		// File doesn't exist, create new one
		existingContent = ""
	}

	// Remove commented lines (lines starting with #) using sed
	if existingContent != "" {
		// Use sed to remove lines starting with # (but preserve empty lines)
		removeCommentsCmd := fmt.Sprintf("sed '/^[[:space:]]*#/d' %s", jailLocalPath)
		uncommentedContent, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", removeCommentsCmd})
		if err == nil {
			existingContent = uncommentedContent
		}
	}

	// Convert IgnoreIPs array to space-separated string
	ignoreIPStr := strings.Join(settings.IgnoreIPs, " ")
	if ignoreIPStr == "" {
		ignoreIPStr = "127.0.0.1/8 ::1"
	}
	// Set default banaction values if not set
	banactionVal := settings.Banaction
	if banactionVal == "" {
		banactionVal = "iptables-multiport"
	}
	banactionAllportsVal := settings.BanactionAllports
	if banactionAllportsVal == "" {
		banactionAllportsVal = "iptables-allports"
	}
	// Define the keys we want to update
	keysToUpdate := map[string]string{
		"bantime.increment":  fmt.Sprintf("bantime.increment = %t", settings.BantimeIncrement),
		"ignoreip":           fmt.Sprintf("ignoreip = %s", ignoreIPStr),
		"bantime":            fmt.Sprintf("bantime = %s", settings.Bantime),
		"findtime":           fmt.Sprintf("findtime = %s", settings.Findtime),
		"maxretry":           fmt.Sprintf("maxretry = %d", settings.Maxretry),
		"destemail":          fmt.Sprintf("destemail = %s", settings.Destemail),
		"banaction":          fmt.Sprintf("banaction = %s", banactionVal),
		"banaction_allports": fmt.Sprintf("banaction_allports = %s", banactionAllportsVal),
	}

	// Parse existing content and update only specific keys in DEFAULT section
	if existingContent == "" {
		// File doesn't exist, create new one with DEFAULT section
		defaultLines := []string{"[DEFAULT]"}
		for _, key := range []string{"bantime.increment", "ignoreip", "bantime", "findtime", "maxretry", "destemail", "banaction", "banaction_allports"} {
			defaultLines = append(defaultLines, keysToUpdate[key])
		}
		defaultLines = append(defaultLines, "")
		newContent := strings.Join(defaultLines, "\n")
		cmd := fmt.Sprintf("cat <<'EOF' | tee %s >/dev/null\n%s\nEOF", jailLocalPath, newContent)
		_, err = sc.runRemoteCommand(ctx, []string{"bash", "-lc", cmd})
		return err
	}

	// Use Python script to update only specific keys in DEFAULT section
	// Preserves banner, action_mwlg, and action override sections
	// Escape values for shell/Python
	escapeForShell := func(s string) string {
		// Escape single quotes for shell
		return strings.ReplaceAll(s, "'", "'\"'\"'")
	}

	updateScript := fmt.Sprintf(`python3 <<'PY'
import re

jail_file = '%s'
ignore_ip_str = '%s'
banaction_val = '%s'
banaction_allports_val = '%s'
bantime_increment_val = %t
keys_to_update = {
    'bantime.increment': 'bantime.increment = ' + str(bantime_increment_val),
    'ignoreip': 'ignoreip = ' + ignore_ip_str,
    'bantime': 'bantime = %s',
    'findtime': 'findtime = %s',
    'maxretry': 'maxretry = %d',
    'destemail': 'destemail = %s',
    'banaction': 'banaction = ' + banaction_val,
    'banaction_allports': 'banaction_allports = ' + banaction_allports_val
}

try:
    with open(jail_file, 'r') as f:
        lines = f.readlines()
except FileNotFoundError:
    lines = []

output_lines = []
in_default = False
default_section_found = False
keys_updated = set()

for line in lines:
    stripped = line.strip()
    
    # Preserve banner lines, action_mwlg lines, and action override lines
    is_banner = 'Fail2Ban-UI' in line or 'fail2ban-ui' in line
    is_action_mwlg = 'action_mwlg' in stripped
    is_action_override = 'action = %%(action_mwlg)s' in stripped
    
    if stripped.startswith('[') and stripped.endswith(']'):
        section_name = stripped.strip('[]')
        if section_name == "DEFAULT":
            in_default = True
            default_section_found = True
            output_lines.append(line)
        else:
            in_default = False
            output_lines.append(line)
    elif in_default:
        # Check if this line is a key we need to update
        key_updated = False
        for key, new_value in keys_to_update.items():
            pattern = r'^\s*' + re.escape(key) + r'\s*='
            if re.match(pattern, stripped):
                output_lines.append(new_value + '\n')
                keys_updated.add(key)
                key_updated = True
                break
        if not key_updated:
            # Keep the line as-is (might be action_mwlg or other DEFAULT settings)
            output_lines.append(line)
    else:
        # Keep lines outside DEFAULT section (preserves banner, action_mwlg, action override)
        output_lines.append(line)

# If DEFAULT section wasn't found, create it at the beginning
if not default_section_found:
    default_lines = ["[DEFAULT]\n"]
    for key in ["bantime.increment", "ignoreip", "bantime", "findtime", "maxretry", "destemail"]:
        default_lines.append(keys_to_update[key] + "\n")
    default_lines.append("\n")
    output_lines = default_lines + output_lines
else:
    # Add any missing keys to the DEFAULT section
    for key in ["bantime.increment", "ignoreip", "bantime", "findtime", "maxretry", "destemail"]:
        if key not in keys_updated:
            # Find the DEFAULT section and insert after it
            for i, line in enumerate(output_lines):
                if line.strip() == "[DEFAULT]":
                    output_lines.insert(i + 1, keys_to_update[key] + "\n")
                    break

with open(jail_file, 'w') as f:
    f.writelines(output_lines)
PY`, escapeForShell(jailLocalPath), escapeForShell(ignoreIPStr), escapeForShell(banactionVal), escapeForShell(banactionAllportsVal), settings.BantimeIncrement, escapeForShell(settings.Bantime), escapeForShell(settings.Findtime), settings.Maxretry, escapeForShell(settings.Destemail))

	_, err = sc.runRemoteCommand(ctx, []string{"bash", "-lc", updateScript})
	return err
}

// EnsureJailLocalStructure implements Connector.
func (sc *SSHConnector) EnsureJailLocalStructure(ctx context.Context) error {
	jailLocalPath := "/etc/fail2ban/jail.local"
	settings := config.GetSettings()

	// Convert IgnoreIPs array to space-separated string
	ignoreIPStr := strings.Join(settings.IgnoreIPs, " ")
	if ignoreIPStr == "" {
		ignoreIPStr = "127.0.0.1/8 ::1"
	}
	// Set default banaction values if not set
	banactionVal := settings.Banaction
	if banactionVal == "" {
		banactionVal = "iptables-multiport"
	}
	banactionAllportsVal := settings.BanactionAllports
	if banactionAllportsVal == "" {
		banactionAllportsVal = "iptables-allports"
	}
	// Escape values for shell/Python
	escapeForShell := func(s string) string {
		return strings.ReplaceAll(s, "'", "'\"'\"'")
	}

	// Build the structure using Python script
	ensureScript := fmt.Sprintf(`python3 <<'PY'
import os
import re

jail_file = '%s'
ignore_ip_str = '%s'
banaction_val = '%s'
banaction_allports_val = '%s'
banner_content = """%s"""
settings = {
    'bantime_increment': %t,
    'ignoreip': ignore_ip_str,
    'bantime': '%s',
    'findtime': '%s',
    'maxretry': %d,
    'destemail': '%s',
    'banaction': banaction_val,
    'banaction_allports': banaction_allports_val
}

# Check if file already has our full banner (indicating it's already properly structured)
has_full_banner = False
has_action_mwlg = False
has_action_override = False

try:
    with open(jail_file, 'r') as f:
        content = f.read()
        # Check for the complete banner pattern with hash line separators
        has_full_banner = '################################################################################' in content and 'Fail2Ban-UI Managed Configuration' in content and 'DO NOT EDIT THIS FILE MANUALLY' in content
        has_action_mwlg = 'action_mwlg' in content and 'ui-custom-action' in content
        has_action_override = 'action = %%(action_mwlg)s' in content
except FileNotFoundError:
    pass

# If already properly structured, just update DEFAULT section
if has_full_banner and has_action_mwlg and has_action_override:
    try:
        with open(jail_file, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []
    
    # Always add the full banner at the start
    output_lines = []
    output_lines.extend(banner_content.splitlines())
    output_lines.append('')
    
    # Skip everything before [DEFAULT] section (old banner, comments, empty lines)
    found_section = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            # Found a section - stop skipping and process this line
            found_section = True
        if not found_section:
            # Skip lines before any section (old banner, comments, empty lines)
            continue
        
        # Process lines after we found a section
        if stripped.startswith('[') and stripped.endswith(']'):
            section_name = stripped.strip('[]')
            if section_name == "DEFAULT":
                in_default = True
                output_lines.append(line)
            else:
                in_default = False
                output_lines.append(line)
        elif in_default:
            key_updated = False
            for key, new_value in [
                ('bantime.increment', 'bantime.increment = ' + str(settings['bantime_increment'])),
                ('ignoreip', 'ignoreip = ' + settings['ignoreip']),
                ('bantime', 'bantime = ' + settings['bantime']),
                ('findtime', 'findtime = ' + settings['findtime']),
                ('maxretry', 'maxretry = ' + str(settings['maxretry'])),
                ('destemail', 'destemail = ' + settings['destemail']),
                ('banaction', 'banaction = ' + settings['banaction']),
                ('banaction_allports', 'banaction_allports = ' + settings['banaction_allports']),
            ]:
                pattern = r'^\s*' + re.escape(key) + r'\s*='
                if re.match(pattern, stripped):
                    output_lines.append(new_value + '\n')
                    keys_updated.add(key)
                    key_updated = True
                    break
            if not key_updated:
                output_lines.append(line)
        else:
            output_lines.append(line)
    
    # Add missing keys
    if in_default:
        for key, new_value in [
            ('bantime.increment', 'bantime.increment = ' + str(settings['bantime_increment'])),
            ('ignoreip', 'ignoreip = ' + settings['ignoreip']),
            ('bantime', 'bantime = ' + settings['bantime']),
            ('findtime', 'findtime = ' + settings['findtime']),
            ('maxretry', 'maxretry = ' + str(settings['maxretry'])),
            ('destemail', 'destemail = ' + settings['destemail']),
            ('banaction', 'banaction = ' + settings['banaction']),
            ('banaction_allports', 'banaction_allports = ' + settings['banaction_allports']),
        ]:
            if key not in keys_updated:
                for i, output_line in enumerate(output_lines):
                    if output_line.strip() == "[DEFAULT]":
                        output_lines.insert(i + 1, new_value + '\n')
                        break
    
    with open(jail_file, 'w') as f:
        f.writelines(output_lines)
else:
    # Create new structure
    banner = banner_content
    
    default_section = """[DEFAULT]
bantime.increment = """ + str(settings['bantime_increment']) + """
ignoreip = """ + settings['ignoreip'] + """
bantime = """ + settings['bantime'] + """
findtime = """ + settings['findtime'] + """
maxretry = """ + str(settings['maxretry']) + """
destemail = """ + settings['destemail'] + """
banaction = """ + settings['banaction'] + """
banaction_allports = """ + settings['banaction_allports'] + """

"""
    
    action_mwlg_config = """# Custom Fail2Ban action using geo-filter for email alerts
action_mwlg = %%(action_)s
             ui-custom-action[sender="%%(sender)s", dest="%%(destemail)s", logpath="%%(logpath)s", chain="%%(chain)s"]

"""
    
    action_override = """# Custom Fail2Ban action applied by fail2ban-ui
action = %%(action_mwlg)s
"""
    
    new_content = banner + default_section + action_mwlg_config + action_override
    
    with open(jail_file, 'w') as f:
        f.write(new_content)
PY`, escapeForShell(jailLocalPath), escapeForShell(ignoreIPStr), escapeForShell(banactionVal), escapeForShell(banactionAllportsVal), escapeForShell(config.JailLocalBanner()), settings.BantimeIncrement,
		escapeForShell(settings.Bantime), escapeForShell(settings.Findtime), settings.Maxretry, escapeForShell(settings.Destemail))

	// IMPORTANT: Run migration FIRST before ensuring structure
	// This is because ensureJailLocalStructure may overwrite jail.local,
	// which would destroy any jail sections that need to be migrated
	if err := sc.MigrateJailsFromJailLocalRemote(ctx); err != nil {
		config.DebugLog("Warning: No migration done (may be normal if no jails to migrate): %v", err)
		// Don't fail - continue with ensuring structure
	}

	// Then ensure the basic structure
	_, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", ensureScript})
	return err
}

// MigrateJailsFromJailLocalRemote migrates non-commented jail sections from jail.local to jail.d/*.local files on remote system.
func (sc *SSHConnector) MigrateJailsFromJailLocalRemote(ctx context.Context) error {
	jailLocalPath := "/etc/fail2ban/jail.local"
	jailDPath := "/etc/fail2ban/jail.d"

	// Check if jail.local exists
	checkScript := fmt.Sprintf("test -f %s && echo 'exists' || echo 'notfound'", jailLocalPath)
	out, err := sc.runRemoteCommand(ctx, []string{"sh", "-c", checkScript})
	if err != nil || strings.TrimSpace(out) != "exists" {
		return nil // Nothing to migrate
	}

	// Read jail.local content
	content, err := sc.runRemoteCommand(ctx, []string{"cat", jailLocalPath})
	if err != nil {
		return fmt.Errorf("failed to read jail.local: %w", err)
	}

	// Parse content locally to extract non-commented sections
	sections, defaultContent, err := parseJailSectionsUncommented(content)
	if err != nil {
		return fmt.Errorf("failed to parse jail.local: %w", err)
	}

	// If no non-commented, non-DEFAULT jails found, nothing to migrate
	if len(sections) == 0 {
		config.DebugLog("No jails to migrate from jail.local on remote system")
		return nil
	}

	// Create backup
	backupPath := jailLocalPath + ".backup." + fmt.Sprintf("%d", time.Now().Unix())
	backupScript := fmt.Sprintf("cp %s %s", jailLocalPath, backupPath)
	if _, err := sc.runRemoteCommand(ctx, []string{"sh", "-c", backupScript}); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	config.DebugLog("Created backup of jail.local at %s on remote system", backupPath)

	// Ensure jail.d directory exists
	ensureDirScript := fmt.Sprintf("mkdir -p %s", jailDPath)
	if _, err := sc.runRemoteCommand(ctx, []string{"sh", "-c", ensureDirScript}); err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}

	// Write each jail to its own .local file
	migratedCount := 0
	for jailName, jailContent := range sections {
		if jailName == "" {
			continue
		}

		jailFilePath := fmt.Sprintf("%s/%s.local", jailDPath, jailName)

		// Check if .local file already exists
		checkFileScript := fmt.Sprintf("test -f %s && echo 'exists' || echo 'notfound'", jailFilePath)
		fileOut, err := sc.runRemoteCommand(ctx, []string{"sh", "-c", checkFileScript})
		if err == nil && strings.TrimSpace(fileOut) == "exists" {
			config.DebugLog("Skipping migration for jail %s: .local file already exists", jailName)
			continue
		}

		// Write jail content to .local file using heredoc
		// Escape single quotes in content for shell
		escapedContent := strings.ReplaceAll(jailContent, "'", "'\"'\"'")
		writeScript := fmt.Sprintf(`cat > %s <<'JAILEOF'
%s
JAILEOF
`, jailFilePath, escapedContent)
		if _, err := sc.runRemoteCommand(ctx, []string{"bash", "-c", writeScript}); err != nil {
			return fmt.Errorf("failed to write jail file %s: %w", jailFilePath, err)
		}
		config.DebugLog("Migrated jail %s to %s on remote system", jailName, jailFilePath)
		migratedCount++
	}

	// Only rewrite jail.local if we migrated something
	if migratedCount > 0 {
		// Rewrite jail.local with only DEFAULT section
		// Escape single quotes in defaultContent for shell
		escapedDefault := strings.ReplaceAll(defaultContent, "'", "'\"'\"'")
		writeLocalScript := fmt.Sprintf(`cat > %s <<'LOCALEOF'
%s
LOCALEOF
`, jailLocalPath, escapedDefault)
		if _, err := sc.runRemoteCommand(ctx, []string{"bash", "-c", writeLocalScript}); err != nil {
			return fmt.Errorf("failed to rewrite jail.local: %w", err)
		}
		config.DebugLog("Migration completed on remote system: moved %d jails to jail.d/", migratedCount)
	}

	return nil
}

// parseJailConfigContent parses jail configuration content and returns JailInfo slice.
func parseJailConfigContent(content string) []JailInfo {
	var jails []JailInfo
	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentJail string
	enabled := true

	// Sections that should be ignored (not jails)
	ignoredSections := map[string]bool{
		"DEFAULT":  true,
		"INCLUDES": true,
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if currentJail != "" && !ignoredSections[currentJail] {
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
	if currentJail != "" && !ignoredSections[currentJail] {
		jails = append(jails, JailInfo{
			JailName: currentJail,
			Enabled:  enabled,
		})
	}
	return jails
}
