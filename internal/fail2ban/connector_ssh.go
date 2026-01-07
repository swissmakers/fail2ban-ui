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
import sys

try:
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
except Exception as e:
    sys.stderr.write(f"Error: {e}\n")
    sys.exit(1)
PY`

// SSHConnector connects to a remote Fail2ban instance over SSH.
type SSHConnector struct {
	server       config.Fail2banServer
	fail2banPath string // Cache the fail2ban path
	pathCached   bool   // Track if path is cached
	pathMutex    sync.RWMutex
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

	// Use a timeout context to prevent hanging if SSH server isn't ready yet
	// The action file can be ensured later when actually needed
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := conn.ensureAction(ctx); err != nil {
		// Log warning but don't fail connector creation - action can be ensured later
		config.DebugLog("warning: failed to ensure remote fail2ban action for %s during startup (server may not be ready): %v", server.Name, err)
		// Don't return error - allow connector to be created even if action setup fails
		// The action will be ensured later when UpdateActionFiles is called
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
			// Use SplitN to only split on the first colon, preserving IPv6 addresses
			parts := strings.SplitN(line, ":", 2)
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

func (sc *SSHConnector) BanIP(ctx context.Context, jail, ip string) error {
	_, err := sc.runFail2banCommand(ctx, "set", jail, "banip", ip)
	return err
}

func (sc *SSHConnector) Reload(ctx context.Context) error {
	_, err := sc.runFail2banCommand(ctx, "reload")
	return err
}

// RestartWithMode restarts (or reloads) the remote Fail2ban instance over SSH
// and returns a mode string describing what happened:
//   - "restart": systemd service was restarted and health check passed
//   - "reload":  configuration was reloaded via fail2ban-client and pong check passed
func (sc *SSHConnector) Restart(ctx context.Context) error {
	_, err := sc.RestartWithMode(ctx)
	return err
}

// RestartWithMode implements the detailed restart logic for SSH connectors.
func (sc *SSHConnector) RestartWithMode(ctx context.Context) (string, error) {
	// First, we try systemd restart on the remote host
	out, err := sc.runRemoteCommand(ctx, []string{"systemctl", "restart", "fail2ban"})
	if err == nil {
		if err := sc.checkFail2banHealthyRemote(ctx); err != nil {
			return "restart", fmt.Errorf("remote fail2ban health check after systemd restart failed: %w", err)
		}
		return "restart", nil
	}

	// Then, if systemd is not available, we fall back to fail2ban-client.
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

	// systemctl exists but restart failed for some other reason, we surface it.
	return "restart", fmt.Errorf("failed to restart fail2ban via systemd on remote: %w (output: %s)", err, out)
}

func (sc *SSHConnector) GetFilterConfig(ctx context.Context, filterName string) (string, string, error) {
	// Validate filter name
	filterName = strings.TrimSpace(filterName)
	if filterName == "" {
		return "", "", fmt.Errorf("filter name cannot be empty")
	}

	fail2banPath := sc.getFail2banPath(ctx)
	// Try .local first, then fallback to .conf
	localPath := filepath.Join(fail2banPath, "filter.d", filterName+".local")
	confPath := filepath.Join(fail2banPath, "filter.d", filterName+".conf")

	content, err := sc.readRemoteFile(ctx, localPath)
	if err == nil {
		return content, localPath, nil
	}

	// Fallback to .conf
	content, err = sc.readRemoteFile(ctx, confPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read remote filter config (tried .local and .conf): %w", err)
	}
	return content, confPath, nil
}

func (sc *SSHConnector) SetFilterConfig(ctx context.Context, filterName, content string) error {
	// Validate filter name
	filterName = strings.TrimSpace(filterName)
	if filterName == "" {
		return fmt.Errorf("filter name cannot be empty")
	}

	fail2banPath := sc.getFail2banPath(ctx)
	filterDPath := filepath.Join(fail2banPath, "filter.d")

	// Ensure directory exists
	_, err := sc.runRemoteCommand(ctx, []string{"mkdir", "-p", filterDPath})
	if err != nil {
		return fmt.Errorf("failed to create filter.d directory: %w", err)
	}

	// Ensure .local file exists (copy from .conf if needed)
	if err := sc.ensureRemoteLocalFile(ctx, filterDPath, filterName); err != nil {
		return fmt.Errorf("failed to ensure filter .local file: %w", err)
	}

	// Write to .local file
	localPath := filepath.Join(filterDPath, filterName+".local")
	if err := sc.writeRemoteFile(ctx, localPath, content); err != nil {
		return fmt.Errorf("failed to write filter config: %w", err)
	}

	return nil
}

func (sc *SSHConnector) FetchBanEvents(ctx context.Context, limit int) ([]BanEvent, error) {
	// Not available over SSH without copying logs; return empty slice.
	return []BanEvent{}, nil
}

func (sc *SSHConnector) ensureAction(ctx context.Context) error {
	callbackURL := config.GetCallbackURL()
	settings := config.GetSettings()
	actionConfig := config.BuildFail2banActionConfig(callbackURL, sc.server.ID, settings.CallbackSecret)
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
			// Use SplitN to only split on the first colon
			parts := strings.SplitN(line, ":", 2)
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

// isSystemctlUnavailable tries to detect “no systemd” situations on the remote host.
func (sc *SSHConnector) isSystemctlUnavailable(output string, err error) bool {
	msg := strings.ToLower(output + " " + err.Error())
	return strings.Contains(msg, "command not found") ||
		strings.Contains(msg, "system has not been booted with systemd") ||
		strings.Contains(msg, "failed to connect to bus")
}

// checkFail2banHealthyRemote runs `sudo fail2ban-client ping` on the remote host
// and expects a successful pong reply.
func (sc *SSHConnector) checkFail2banHealthyRemote(ctx context.Context) error {
	out, err := sc.runFail2banCommand(ctx, "ping")
	trimmed := strings.TrimSpace(out)
	if err != nil {
		return fmt.Errorf("remote fail2ban ping error: %w (output: %s)", err, trimmed)
	}
	// Typical output is e.g. "Server replied: pong" – accept anything that
	// contains "pong" case-insensitively.
	if !strings.Contains(strings.ToLower(trimmed), "pong") {
		return fmt.Errorf("unexpected remote fail2ban ping output: %s", trimmed)
	}
	return nil
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
	// Add connection timeout to prevent hanging
	args = append(args,
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=5",
		"-o", "ServerAliveCountMax=2",
	)
	// In containerized environments, disable strict host key checking
	if _, container := os.LookupEnv("CONTAINER"); container {
		args = append(args,
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "LogLevel=ERROR",
		)
	}
	// Enable SSH connection multiplexing for faster connections
	// Use a control socket based on server ID for connection reuse
	controlPath := fmt.Sprintf("/tmp/ssh_control_%s_%s", sc.server.ID, strings.ReplaceAll(sc.server.Host, ".", "_"))
	args = append(args,
		"-o", "ControlMaster=auto",
		"-o", fmt.Sprintf("ControlPath=%s", controlPath),
		"-o", "ControlPersist=300", // Keep connection alive for 5 minutes
	)
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

// listRemoteFiles lists files in a remote directory matching a pattern.
// Uses find command which works reliably with FACL permissions.
func (sc *SSHConnector) listRemoteFiles(ctx context.Context, directory, pattern string) ([]string, error) {
	// Use find command with absolute path - it will handle non-existent directories gracefully
	// Find files ending with pattern, exclude hidden files, and ensure they're regular files
	// Redirect stderr to /dev/null to suppress "No such file or directory" errors
	// Pass the entire command as a single string to SSH (SSH executes through a shell by default)
	cmd := fmt.Sprintf(`find "%s" -maxdepth 1 -type f -name "*%s" ! -name ".*" 2>/dev/null | sort`, directory, pattern)

	out, err := sc.runRemoteCommand(ctx, []string{cmd})
	if err != nil {
		// If find fails (e.g., directory doesn't exist or permission denied), return empty list (not an error)
		config.DebugLog("Find command failed for %s on server %s: %v, returning empty list", directory, sc.server.Name, err)
		return []string{}, nil
	}

	// If find succeeds but directory doesn't exist, it will return empty output
	// This is fine - we'll just return an empty list

	var files []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// Skip empty lines, current directory marker, and relative paths
		if line == "" || line == "." || strings.HasPrefix(line, "./") {
			continue
		}
		// Only process files that match our pattern (end with .local or .conf)
		// and are actually in the target directory
		if strings.HasSuffix(line, pattern) {
			// If it's already an absolute path starting with our directory, use it directly
			if strings.HasPrefix(line, directory) {
				files = append(files, line)
			} else if !strings.HasPrefix(line, "/") {
				// Relative path, join with directory
				fullPath := filepath.Join(directory, line)
				files = append(files, fullPath)
			}
			// Skip any other absolute paths that don't start with our directory
		}
	}

	return files, nil
}

// readRemoteFile reads the content of a remote file via SSH.
func (sc *SSHConnector) readRemoteFile(ctx context.Context, filePath string) (string, error) {
	content, err := sc.runRemoteCommand(ctx, []string{"cat", filePath})
	if err != nil {
		return "", fmt.Errorf("failed to read remote file %s: %w", filePath, err)
	}
	return content, nil
}

// writeRemoteFile writes content to a remote file via SSH using a heredoc.
func (sc *SSHConnector) writeRemoteFile(ctx context.Context, filePath, content string) error {
	// Escape single quotes for safe use in a single-quoted heredoc
	escaped := strings.ReplaceAll(content, "'", "'\"'\"'")

	// Use heredoc to write file content
	script := fmt.Sprintf(`cat > %s <<'REMOTEEOF'
%s
REMOTEEOF
`, filePath, escaped)

	_, err := sc.runRemoteCommand(ctx, []string{script})
	if err != nil {
		return fmt.Errorf("failed to write remote file %s: %w", filePath, err)
	}
	return nil
}

// ensureRemoteLocalFile ensures that a .local file exists on the remote system.
// If .local doesn't exist, it copies from .conf if available, or creates an empty file.
func (sc *SSHConnector) ensureRemoteLocalFile(ctx context.Context, basePath, name string) error {
	localPath := fmt.Sprintf("%s/%s.local", basePath, name)
	confPath := fmt.Sprintf("%s/%s.conf", basePath, name)

	// Check if .local exists, if not, copy from .conf or create empty file
	script := fmt.Sprintf(`
		if [ ! -f "%s" ]; then
			if [ -f "%s" ]; then
				cp "%s" "%s"
			else
				# Create empty .local file if neither exists
				touch "%s"
			fi
		fi
	`, localPath, confPath, confPath, localPath, localPath)

	_, err := sc.runRemoteCommand(ctx, []string{script})
	if err != nil {
		return fmt.Errorf("failed to ensure remote .local file %s: %w", localPath, err)
	}
	return nil
}

// getFail2banPath detects the fail2ban configuration path on the remote system.
// Returns /config/fail2ban for linuxserver images, or /etc/fail2ban for standard installations.
// Uses caching to avoid repeated SSH calls.
func (sc *SSHConnector) getFail2banPath(ctx context.Context) string {
	// Try to read from cache first
	sc.pathMutex.RLock()
	if sc.pathCached {
		path := sc.fail2banPath
		sc.pathMutex.RUnlock()
		return path
	}
	sc.pathMutex.RUnlock()

	// Acquire write lock to update cache
	sc.pathMutex.Lock()
	defer sc.pathMutex.Unlock()

	// Double-check after acquiring write lock (another goroutine might have cached it)
	if sc.pathCached {
		return sc.fail2banPath
	}

	// Actually fetch the path
	checkCmd := `test -d "/config/fail2ban" && echo "/config/fail2ban" || (test -d "/etc/fail2ban" && echo "/etc/fail2ban" || echo "/etc/fail2ban")`
	out, err := sc.runRemoteCommand(ctx, []string{checkCmd})
	if err == nil {
		path := strings.TrimSpace(out)
		if path != "" {
			sc.fail2banPath = path
			sc.pathCached = true
			return path
		}
	}
	// Default to /etc/fail2ban
	sc.fail2banPath = "/etc/fail2ban"
	sc.pathCached = true
	return sc.fail2banPath
}

// GetAllJails implements Connector.
// Discovers all jails from filesystem (mirrors local connector behavior).
// Optimized to read all files in a single SSH command instead of individual reads.
func (sc *SSHConnector) GetAllJails(ctx context.Context) ([]JailInfo, error) {
	fail2banPath := sc.getFail2banPath(ctx)
	jailDPath := filepath.Join(fail2banPath, "jail.d")

	var allJails []JailInfo
	processedFiles := make(map[string]bool) // Track base names to avoid duplicates
	processedJails := make(map[string]bool) // Track jail names to avoid duplicates

	// Use a Python script to read all files in a single SSH command
	// This is much more efficient than reading each file individually
	readAllScript := fmt.Sprintf(`python3 << 'PYEOF'
import os
import sys
import json

jail_d_path = %q
files_data = {}

# Read all .local files first
local_files = []
if os.path.isdir(jail_d_path):
    for filename in os.listdir(jail_d_path):
        if filename.endswith('.local') and not filename.startswith('.'):
            local_files.append(os.path.join(jail_d_path, filename))

# Process .local files
for filepath in sorted(local_files):
    try:
        filename = os.path.basename(filepath)
        basename = filename[:-6]  # Remove .local
        if basename and basename not in files_data:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            files_data[basename] = {'path': filepath, 'content': content, 'type': 'local'}
    except Exception as e:
        sys.stderr.write(f"Error reading {filepath}: {e}\n")

# Read all .conf files that don't have corresponding .local files
conf_files = []
if os.path.isdir(jail_d_path):
    for filename in os.listdir(jail_d_path):
        if filename.endswith('.conf') and not filename.startswith('.'):
            basename = filename[:-5]  # Remove .conf
            if basename not in files_data:
                conf_files.append(os.path.join(jail_d_path, filename))

# Process .conf files
for filepath in sorted(conf_files):
    try:
        filename = os.path.basename(filepath)
        basename = filename[:-5]  # Remove .conf
        if basename:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            files_data[basename] = {'path': filepath, 'content': content, 'type': 'conf'}
    except Exception as e:
        sys.stderr.write(f"Error reading {filepath}: {e}\n")

# Output files with a delimiter: FILE_START:path:type\ncontent\nFILE_END\n
for basename, data in sorted(files_data.items()):
    print(f"FILE_START:{data['path']}:{data['type']}")
    print(data['content'], end='')
    print("FILE_END")
PYEOF`, jailDPath)

	output, err := sc.runRemoteCommand(ctx, []string{readAllScript})
	if err != nil {
		// Fallback to individual file reads if the script fails
		config.DebugLog("Failed to read all jail files at once on server %s, falling back to individual reads: %v", sc.server.Name, err)
		return sc.getAllJailsFallback(ctx, jailDPath)
	}

	// Parse the output: files are separated by FILE_START:path:type\ncontent\nFILE_END\n
	var currentFile string
	var currentContent strings.Builder
	var currentType string
	inFile := false

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "FILE_START:") {
			// Save previous file if any
			if inFile && currentFile != "" {
				content := currentContent.String()
				jails := parseJailConfigContent(content)
				for _, jail := range jails {
					if jail.JailName != "" && jail.JailName != "DEFAULT" && !processedJails[jail.JailName] {
						allJails = append(allJails, jail)
						processedJails[jail.JailName] = true
					}
				}
			}
			// Parse new file header: FILE_START:path:type
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 {
				currentFile = parts[1]
				currentType = parts[2]
				currentContent.Reset()
				inFile = true
				filename := filepath.Base(currentFile)
				var baseName string
				if currentType == "local" {
					baseName = strings.TrimSuffix(filename, ".local")
				} else {
					baseName = strings.TrimSuffix(filename, ".conf")
				}
				if baseName != "" {
					processedFiles[baseName] = true
				}
			}
		} else if line == "FILE_END" {
			// End of file, process it
			if inFile && currentFile != "" {
				content := currentContent.String()
				jails := parseJailConfigContent(content)
				for _, jail := range jails {
					if jail.JailName != "" && jail.JailName != "DEFAULT" && !processedJails[jail.JailName] {
						allJails = append(allJails, jail)
						processedJails[jail.JailName] = true
					}
				}
			}
			inFile = false
			currentFile = ""
			currentContent.Reset()
		} else if inFile {
			// Content line
			if currentContent.Len() > 0 {
				currentContent.WriteString("\n")
			}
			currentContent.WriteString(line)
		}
	}

	// Handle last file if output doesn't end with FILE_END
	if inFile && currentFile != "" {
		content := currentContent.String()
		jails := parseJailConfigContent(content)
		for _, jail := range jails {
			if jail.JailName != "" && jail.JailName != "DEFAULT" && !processedJails[jail.JailName] {
				allJails = append(allJails, jail)
				processedJails[jail.JailName] = true
			}
		}
	}

	return allJails, nil
}

// getAllJailsFallback is the fallback method that reads files individually.
// Used when the optimized batch read fails.
func (sc *SSHConnector) getAllJailsFallback(ctx context.Context, jailDPath string) ([]JailInfo, error) {
	var allJails []JailInfo
	processedFiles := make(map[string]bool)
	processedJails := make(map[string]bool)

	// List all .local files first
	localFiles, err := sc.listRemoteFiles(ctx, jailDPath, ".local")
	if err != nil {
		config.DebugLog("Failed to list .local files in jail.d on server %s: %v", sc.server.Name, err)
	} else {
		for _, filePath := range localFiles {
			filename := filepath.Base(filePath)
			baseName := strings.TrimSuffix(filename, ".local")
			if baseName == "" || processedFiles[baseName] {
				continue
			}
			processedFiles[baseName] = true

			content, err := sc.readRemoteFile(ctx, filePath)
			if err != nil {
				config.DebugLog("Failed to read jail file %s on server %s: %v", filePath, sc.server.Name, err)
				continue
			}

			jails := parseJailConfigContent(content)
			for _, jail := range jails {
				if jail.JailName != "" && jail.JailName != "DEFAULT" && !processedJails[jail.JailName] {
					allJails = append(allJails, jail)
					processedJails[jail.JailName] = true
				}
			}
		}
	}

	// List all .conf files that don't have corresponding .local files
	confFiles, err := sc.listRemoteFiles(ctx, jailDPath, ".conf")
	if err != nil {
		config.DebugLog("Failed to list .conf files in jail.d on server %s: %v", sc.server.Name, err)
	} else {
		for _, filePath := range confFiles {
			filename := filepath.Base(filePath)
			baseName := strings.TrimSuffix(filename, ".conf")
			if baseName == "" || processedFiles[baseName] {
				continue
			}
			processedFiles[baseName] = true

			content, err := sc.readRemoteFile(ctx, filePath)
			if err != nil {
				config.DebugLog("Failed to read jail file %s on server %s: %v", filePath, sc.server.Name, err)
				continue
			}

			jails := parseJailConfigContent(content)
			for _, jail := range jails {
				if jail.JailName != "" && jail.JailName != "DEFAULT" && !processedJails[jail.JailName] {
					allJails = append(allJails, jail)
					processedJails[jail.JailName] = true
				}
			}
		}
	}

	return allJails, nil
}

// UpdateJailEnabledStates implements Connector.
func (sc *SSHConnector) UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error {
	fail2banPath := sc.getFail2banPath(ctx)
	jailDPath := filepath.Join(fail2banPath, "jail.d")

	// Update each jail in its own .local file
	for jailName, enabled := range updates {
		// Validate jail name - skip empty or invalid names
		jailName = strings.TrimSpace(jailName)
		if jailName == "" {
			config.DebugLog("Skipping empty jail name in updates map")
			continue
		}

		localPath := filepath.Join(jailDPath, jailName+".local")
		confPath := filepath.Join(jailDPath, jailName+".conf")

		// Combined script: ensure .local file exists AND read it in one SSH call
		// This reduces SSH round-trips from 2 to 1 per jail
		combinedScript := fmt.Sprintf(`
			if [ ! -f "%s" ]; then
				if [ -f "%s" ]; then
					cp "%s" "%s"
				else
					echo "[%s]" > "%s"
				fi
			fi
			cat "%s"
		`, localPath, confPath, confPath, localPath, jailName, localPath, localPath)

		content, err := sc.runRemoteCommand(ctx, []string{combinedScript})
		if err != nil {
			return fmt.Errorf("failed to ensure and read .local file for jail %s: %w", jailName, err)
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
		if _, err := sc.runRemoteCommand(ctx, []string{cmd}); err != nil {
			return fmt.Errorf("failed to write jail .local file %s: %w", localPath, err)
		}
	}
	return nil
}

// GetFilters implements Connector.
// Discovers all filters from filesystem (mirrors local connector behavior).
func (sc *SSHConnector) GetFilters(ctx context.Context) ([]string, error) {
	fail2banPath := sc.getFail2banPath(ctx)
	filterDPath := filepath.Join(fail2banPath, "filter.d")

	filterMap := make(map[string]bool)      // Track unique filter names
	processedFiles := make(map[string]bool) // Track base names to avoid duplicates

	// Helper function to check if file should be excluded
	shouldExclude := func(filename string) bool {
		if strings.HasSuffix(filename, ".bak") ||
			strings.HasSuffix(filename, "~") ||
			strings.HasSuffix(filename, ".old") ||
			strings.HasSuffix(filename, ".rpmnew") ||
			strings.HasSuffix(filename, ".rpmsave") ||
			strings.Contains(filename, "README") {
			return true
		}
		return false
	}

	// First pass: collect all .local files (these take precedence)
	localFiles, err := sc.listRemoteFiles(ctx, filterDPath, ".local")
	if err != nil {
		config.DebugLog("Failed to list .local filters on server %s: %v", sc.server.Name, err)
	} else {
		for _, filePath := range localFiles {
			filename := filepath.Base(filePath)
			if shouldExclude(filename) {
				continue
			}
			baseName := strings.TrimSuffix(filename, ".local")
			if baseName == "" || processedFiles[baseName] {
				continue
			}
			processedFiles[baseName] = true
			filterMap[baseName] = true
		}
	}

	// Second pass: collect .conf files that don't have corresponding .local files
	confFiles, err := sc.listRemoteFiles(ctx, filterDPath, ".conf")
	if err != nil {
		config.DebugLog("Failed to list .conf filters on server %s: %v", sc.server.Name, err)
	} else {
		for _, filePath := range confFiles {
			filename := filepath.Base(filePath)
			if shouldExclude(filename) {
				continue
			}
			baseName := strings.TrimSuffix(filename, ".conf")
			if baseName == "" || processedFiles[baseName] {
				continue
			}
			processedFiles[baseName] = true
			filterMap[baseName] = true
		}
	}

	// Convert map to sorted slice
	var filters []string
	for name := range filterMap {
		filters = append(filters, name)
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

	// Get the fail2ban path dynamically
	fail2banPath := sc.getFail2banPath(ctx)
	// Try .local first, then fallback to .conf
	localPath := filepath.Join(fail2banPath, "filter.d", filterName+".local")
	confPath := filepath.Join(fail2banPath, "filter.d", filterName+".conf")

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

	out, err := sc.runRemoteCommand(ctx, []string{script})
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
func (sc *SSHConnector) GetJailConfig(ctx context.Context, jail string) (string, string, error) {
	// Validate jail name
	jail = strings.TrimSpace(jail)
	if jail == "" {
		return "", "", fmt.Errorf("jail name cannot be empty")
	}

	fail2banPath := sc.getFail2banPath(ctx)
	// Try .local first, then fallback to .conf
	localPath := filepath.Join(fail2banPath, "jail.d", jail+".local")
	confPath := filepath.Join(fail2banPath, "jail.d", jail+".conf")

	content, err := sc.readRemoteFile(ctx, localPath)
	if err == nil {
		return content, localPath, nil
	}

	// Fallback to .conf
	content, err = sc.readRemoteFile(ctx, confPath)
	if err != nil {
		// If neither exists, return empty jail section with .local path (will be created on save)
		return fmt.Sprintf("[%s]\n", jail), localPath, nil
	}
	return content, confPath, nil
}

// SetJailConfig implements Connector.
func (sc *SSHConnector) SetJailConfig(ctx context.Context, jail, content string) error {
	// Validate jail name
	jail = strings.TrimSpace(jail)
	if jail == "" {
		return fmt.Errorf("jail name cannot be empty")
	}

	fail2banPath := sc.getFail2banPath(ctx)
	jailDPath := filepath.Join(fail2banPath, "jail.d")

	// Ensure jail.d directory exists
	_, err := sc.runRemoteCommand(ctx, []string{"mkdir", "-p", jailDPath})
	if err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}

	// Ensure .local file exists (copy from .conf if needed)
	if err := sc.ensureRemoteLocalFile(ctx, jailDPath, jail); err != nil {
		return fmt.Errorf("failed to ensure .local file for jail %s: %w", jail, err)
	}

	// Write to .local file
	localPath := filepath.Join(jailDPath, jail+".local")
	if err := sc.writeRemoteFile(ctx, localPath, content); err != nil {
		return fmt.Errorf("failed to write jail config: %w", err)
	}

	return nil
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

	out, err := sc.runRemoteCommand(ctx, []string{script})
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
	resolveOut, err := sc.runRemoteCommand(ctx, []string{resolveScript})
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
		uncommentedContent, err := sc.runRemoteCommand(ctx, []string{removeCommentsCmd})
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
		"enabled":            fmt.Sprintf("enabled = %t", settings.DefaultJailEnable),
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
		for _, key := range []string{"enabled", "bantime.increment", "ignoreip", "bantime", "findtime", "maxretry", "destemail", "banaction", "banaction_allports"} {
			defaultLines = append(defaultLines, keysToUpdate[key])
		}
		defaultLines = append(defaultLines, "")
		newContent := strings.Join(defaultLines, "\n")
		cmd := fmt.Sprintf("cat <<'EOF' | tee %s >/dev/null\n%s\nEOF", jailLocalPath, newContent)
		_, err = sc.runRemoteCommand(ctx, []string{cmd})
		return err
	}

	// Use Python script to update only specific keys in DEFAULT section
	// Preserves banner, action_mwlg, and action override sections
	// Escape values for shell/Python
	escapeForShell := func(s string) string {
		// Escape single quotes for shell
		return strings.ReplaceAll(s, "'", "'\"'\"'")
	}

	// Convert boolean values to Python boolean literals
	defaultJailEnablePython := "False"
	if settings.DefaultJailEnable {
		defaultJailEnablePython = "True"
	}
	bantimeIncrementPython := "False"
	if settings.BantimeIncrement {
		bantimeIncrementPython = "True"
	}

	updateScript := fmt.Sprintf(`python3 <<'PY'
import re

jail_file = '%s'
ignore_ip_str = '%s'
banaction_val = '%s'
banaction_allports_val = '%s'
default_jail_enable_val = %s
bantime_increment_val = %s
bantime_val = '%s'
findtime_val = '%s'
maxretry_val = %d
destemail_val = '%s'
keys_to_update = {
    'enabled': 'enabled = ' + str(default_jail_enable_val).lower(),
    'bantime.increment': 'bantime.increment = ' + str(bantime_increment_val).lower(),
    'ignoreip': 'ignoreip = ' + ignore_ip_str,
    'bantime': 'bantime = ' + bantime_val,
    'findtime': 'findtime = ' + findtime_val,
    'maxretry': 'maxretry = ' + str(maxretry_val),
    'destemail': 'destemail = ' + destemail_val,
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
    for key in ["enabled", "bantime.increment", "ignoreip", "bantime", "findtime", "maxretry", "destemail"]:
        default_lines.append(keys_to_update[key] + "\n")
    default_lines.append("\n")
    output_lines = default_lines + output_lines
else:
    # Add any missing keys to the DEFAULT section
    for key in ["enabled", "bantime.increment", "ignoreip", "bantime", "findtime", "maxretry", "destemail"]:
        if key not in keys_updated:
            # Find the DEFAULT section and insert after it
            for i, line in enumerate(output_lines):
                if line.strip() == "[DEFAULT]":
                    output_lines.insert(i + 1, keys_to_update[key] + "\n")
                    break

with open(jail_file, 'w') as f:
    f.writelines(output_lines)
PY`, escapeForShell(jailLocalPath), escapeForShell(ignoreIPStr), escapeForShell(banactionVal), escapeForShell(banactionAllportsVal), defaultJailEnablePython, bantimeIncrementPython, escapeForShell(settings.Bantime), escapeForShell(settings.Findtime), settings.Maxretry, escapeForShell(settings.Destemail))

	_, err = sc.runRemoteCommand(ctx, []string{updateScript})
	return err
}

// EnsureJailLocalStructure implements Connector.
// For SSH connectors we:
//  1. Migrate any legacy jails out of jail.local into jail.d/*.local
//  2. Rebuild /etc/fail2ban/jail.local with a clean, managed structure
//     (banner, [DEFAULT] section based on current settings, and action_mwlg/action override).
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

	// Build the new jail.local content in Go (mirrors local ensureJailLocalStructure)
	banner := config.JailLocalBanner()

	defaultSection := fmt.Sprintf(`[DEFAULT]
enabled = %t
bantime.increment = %t
ignoreip = %s
bantime = %s
findtime = %s
maxretry = %d
destemail = %s
banaction = %s
banaction_allports = %s

`,
		settings.DefaultJailEnable,
		settings.BantimeIncrement,
		ignoreIPStr,
		settings.Bantime,
		settings.Findtime,
		settings.Maxretry,
		settings.Destemail,
		banactionVal,
		banactionAllportsVal,
	)

	actionMwlgConfig := `# Custom Fail2Ban action using geo-filter for email alerts
action_mwlg = %(action_)s
             ui-custom-action[sender="%(sender)s", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]

`

	actionOverride := `# Custom Fail2Ban action applied by fail2ban-ui
action = %(action_mwlg)s
`

	content := banner + defaultSection + actionMwlgConfig + actionOverride

	// Escape single quotes for safe use in a single-quoted heredoc
	escaped := strings.ReplaceAll(content, "'", "'\"'\"'")

	// IMPORTANT: Run migration FIRST before ensuring structure.
	// This is because EnsureJailLocalStructure may overwrite jail.local,
	// which would destroy any jail sections that need to be migrated.
	// If migration fails for any reason, we SHOULD NOT overwrite jail.local,
	// otherwise legacy jails would be lost.
	if err := sc.MigrateJailsFromJailLocalRemote(ctx); err != nil {
		return fmt.Errorf("failed to migrate legacy jails from jail.local on remote server %s: %w", sc.server.Name, err)
	}

	// Write the rebuilt content via heredoc over SSH
	writeScript := fmt.Sprintf(`cat > %s <<'JAILLOCAL'
%s
JAILLOCAL
`, jailLocalPath, escaped)

	_, err := sc.runRemoteCommand(ctx, []string{writeScript})
	return err
}

// MigrateJailsFromJailLocalRemote migrates non-commented jail sections from jail.local to jail.d/*.local files on remote system.
func (sc *SSHConnector) MigrateJailsFromJailLocalRemote(ctx context.Context) error {
	jailLocalPath := "/etc/fail2ban/jail.local"
	jailDPath := "/etc/fail2ban/jail.d"

	// Check if jail.local exists
	checkScript := fmt.Sprintf("test -f %s && echo 'exists' || echo 'notfound'", jailLocalPath)
	out, err := sc.runRemoteCommand(ctx, []string{checkScript})
	if err != nil || strings.TrimSpace(out) != "exists" {
		config.DebugLog("No jails to migrate from jail.local on server %s (file does not exist)", sc.server.Name)
		return nil // Nothing to migrate
	}

	// Read jail.local content
	content, err := sc.runRemoteCommand(ctx, []string{"cat", jailLocalPath})
	if err != nil {
		return fmt.Errorf("failed to read jail.local on server %s: %w", sc.server.Name, err)
	}

	// Parse content locally to extract non-commented sections
	sections, defaultContent, err := parseJailSectionsUncommented(content)
	if err != nil {
		return fmt.Errorf("failed to parse jail.local on server %s: %w", sc.server.Name, err)
	}

	// If no non-commented, non-DEFAULT jails found, nothing to migrate
	if len(sections) == 0 {
		config.DebugLog("No jails to migrate from jail.local on remote system")
		return nil
	}

	// Create backup
	backupPath := jailLocalPath + ".backup." + fmt.Sprintf("%d", time.Now().Unix())
	backupScript := fmt.Sprintf("cp %s %s", jailLocalPath, backupPath)
	if _, err := sc.runRemoteCommand(ctx, []string{backupScript}); err != nil {
		return fmt.Errorf("failed to create backup on server %s: %w", sc.server.Name, err)
	}
	config.DebugLog("Created backup of jail.local at %s on server %s", backupPath, sc.server.Name)

	// Ensure jail.d directory exists
	ensureDirScript := fmt.Sprintf("mkdir -p %s", jailDPath)
	if _, err := sc.runRemoteCommand(ctx, []string{ensureDirScript}); err != nil {
		return fmt.Errorf("failed to create jail.d directory on server %s: %w", sc.server.Name, err)
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
		fileOut, err := sc.runRemoteCommand(ctx, []string{checkFileScript})
		if err == nil && strings.TrimSpace(fileOut) == "exists" {
			config.DebugLog("Skipping migration for jail %s on server %s: .local file already exists", jailName, sc.server.Name)
			continue
		}

		// Write jail content to .local file using heredoc
		// Escape single quotes in content for shell
		escapedContent := strings.ReplaceAll(jailContent, "'", "'\"'\"'")
		writeScript := fmt.Sprintf(`cat > %s <<'JAILEOF'
%s
JAILEOF
'`, jailFilePath, escapedContent)
		if _, err := sc.runRemoteCommand(ctx, []string{writeScript}); err != nil {
			return fmt.Errorf("failed to write jail file %s: %w", jailFilePath, err)
		}
		config.DebugLog("Migrated jail %s to %s on server %s", jailName, jailFilePath, sc.server.Name)
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
'`, jailLocalPath, escapedDefault)
		if _, err := sc.runRemoteCommand(ctx, []string{writeLocalScript}); err != nil {
			return fmt.Errorf("failed to rewrite jail.local: %w", err)
		}
		config.DebugLog("Migration completed on server %s: moved %d jails to jail.d/", sc.server.Name, migratedCount)
	}

	return nil
}

// CreateJail implements Connector.
func (sc *SSHConnector) CreateJail(ctx context.Context, jailName, content string) error {
	// Validate jail name
	if err := ValidateJailName(jailName); err != nil {
		return err
	}

	fail2banPath := sc.getFail2banPath(ctx)
	jailDPath := filepath.Join(fail2banPath, "jail.d")

	// Ensure jail.d directory exists
	_, err := sc.runRemoteCommand(ctx, []string{"mkdir", "-p", jailDPath})
	if err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}

	// Validate content starts with correct section header
	trimmed := strings.TrimSpace(content)
	expectedSection := fmt.Sprintf("[%s]", jailName)
	if !strings.HasPrefix(trimmed, expectedSection) {
		// Prepend the section header if missing
		content = expectedSection + "\n" + content
	}

	// Write the file
	localPath := filepath.Join(jailDPath, jailName+".local")
	if err := sc.writeRemoteFile(ctx, localPath, content); err != nil {
		return fmt.Errorf("failed to create jail file: %w", err)
	}

	return nil
}

// DeleteJail implements Connector.
func (sc *SSHConnector) DeleteJail(ctx context.Context, jailName string) error {
	// Validate jail name
	if err := ValidateJailName(jailName); err != nil {
		return err
	}

	fail2banPath := sc.getFail2banPath(ctx)
	localPath := filepath.Join(fail2banPath, "jail.d", jailName+".local")
	confPath := filepath.Join(fail2banPath, "jail.d", jailName+".conf")

	// Delete both .local and .conf files if they exist (rm -f doesn't error if file doesn't exist)
	// Use a single command to delete both files
	_, err := sc.runRemoteCommand(ctx, []string{"rm", "-f", localPath, confPath})
	if err != nil {
		return fmt.Errorf("failed to delete jail files %s or %s: %w", localPath, confPath, err)
	}

	return nil
}

// CreateFilter implements Connector.
func (sc *SSHConnector) CreateFilter(ctx context.Context, filterName, content string) error {
	// Validate filter name
	if err := ValidateFilterName(filterName); err != nil {
		return err
	}

	fail2banPath := sc.getFail2banPath(ctx)
	filterDPath := filepath.Join(fail2banPath, "filter.d")

	// Ensure filter.d directory exists
	_, err := sc.runRemoteCommand(ctx, []string{"mkdir", "-p", filterDPath})
	if err != nil {
		return fmt.Errorf("failed to create filter.d directory: %w", err)
	}

	// Write the file
	localPath := filepath.Join(filterDPath, filterName+".local")
	if err := sc.writeRemoteFile(ctx, localPath, content); err != nil {
		return fmt.Errorf("failed to create filter file: %w", err)
	}

	return nil
}

// DeleteFilter implements Connector.
func (sc *SSHConnector) DeleteFilter(ctx context.Context, filterName string) error {
	// Validate filter name
	if err := ValidateFilterName(filterName); err != nil {
		return err
	}

	fail2banPath := sc.getFail2banPath(ctx)
	localPath := filepath.Join(fail2banPath, "filter.d", filterName+".local")
	confPath := filepath.Join(fail2banPath, "filter.d", filterName+".conf")

	// Delete both .local and .conf files if they exist (rm -f doesn't error if file doesn't exist)
	// Use a single command to delete both files
	_, err := sc.runRemoteCommand(ctx, []string{"rm", "-f", localPath, confPath})
	if err != nil {
		return fmt.Errorf("failed to delete filter files %s or %s: %w", localPath, confPath, err)
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
