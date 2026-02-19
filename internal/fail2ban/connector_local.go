package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// Connector for a local Fail2ban instance via fail2ban-client CLI.
type LocalConnector struct {
	server config.Fail2banServer
}

// =========================================================================
//  Constructor
// =========================================================================

// Create a new LocalConnector for the given server config.
func NewLocalConnector(server config.Fail2banServer) *LocalConnector {
	return &LocalConnector{server: server}
}

func (lc *LocalConnector) ID() string {
	return lc.server.ID
}

func (lc *LocalConnector) Server() config.Fail2banServer {
	return lc.server
}

// Collects jail status for every active local jail.
func (lc *LocalConnector) GetJailInfos(ctx context.Context) ([]JailInfo, error) {
	jails, err := lc.getJails(ctx)
	if err != nil {
		return nil, err
	}
	return collectJailInfos(ctx, jails, lc.GetBannedIPs)
}

// Get banned IPs for a given jail.
func (lc *LocalConnector) GetBannedIPs(ctx context.Context, jail string) ([]string, error) {
	args := []string{"status", jail}
	out, err := lc.runFail2banClient(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("fail2ban-client status %s failed: %w", jail, err)
	}
	var bannedIPs []string
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "IP list:") {
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

// Unban an IP from a given jail.
func (lc *LocalConnector) UnbanIP(ctx context.Context, jail, ip string) error {
	args := []string{"set", jail, "unbanip", ip}
	if _, err := lc.runFail2banClient(ctx, args...); err != nil {
		return fmt.Errorf("error unbanning IP %s from jail %s: %w", ip, jail, err)
	}
	return nil
}

// Ban an IP in a given jail.
func (lc *LocalConnector) BanIP(ctx context.Context, jail, ip string) error {
	args := []string{"set", jail, "banip", ip}
	if _, err := lc.runFail2banClient(ctx, args...); err != nil {
		return fmt.Errorf("error banning IP %s in jail %s: %w", ip, jail, err)
	}
	return nil
}

// Reload the Fail2ban service.
func (lc *LocalConnector) Reload(ctx context.Context) error {
	out, err := lc.runFail2banClient(ctx, "reload")
	if err != nil {
		return fmt.Errorf("fail2ban reload error: %w (output: %s)", err, strings.TrimSpace(out))
	}
	// Check if fail2ban-client returns "OK"
	outputTrimmed := strings.TrimSpace(out)
	if outputTrimmed != "OK" && outputTrimmed != "" {
		config.DebugLog("fail2ban reload output: %s", out)
		if strings.Contains(out, "Errors in jail") || strings.Contains(out, "Unable to read the filter") {
			return fmt.Errorf("fail2ban reload completed but with errors (output: %s)", strings.TrimSpace(out))
		}
	}
	return nil
}

// Restart or reload the local Fail2ban instance; returns "restart" or "reload".
func (lc *LocalConnector) RestartWithMode(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("systemctl"); err == nil {
		cmd := "systemctl restart fail2ban"
		out, err := executeShellCommand(ctx, cmd)
		if err != nil {
			return "restart", fmt.Errorf("failed to restart fail2ban via systemd: %w - output: %s",
				err, strings.TrimSpace(out))
		}
		if err := lc.checkFail2banHealthy(ctx); err != nil {
			return "restart", fmt.Errorf("fail2ban health check after systemd restart failed: %w", err)
		}
		return "restart", nil
	}
	if err := lc.Reload(ctx); err != nil {
		return "reload", fmt.Errorf("failed to reload fail2ban via fail2ban-client (systemctl not available): %w", err)
	}
	if err := lc.checkFail2banHealthy(ctx); err != nil {
		return "reload", fmt.Errorf("fail2ban health check after reload failed: %w", err)
	}
	return "reload", nil
}

func (lc *LocalConnector) Restart(ctx context.Context) error {
	_, err := lc.RestartWithMode(ctx)
	return err
}

func (lc *LocalConnector) GetFilterConfig(ctx context.Context, jail string) (string, string, error) {
	return GetFilterConfigLocal(jail)
}

func (lc *LocalConnector) SetFilterConfig(ctx context.Context, jail, content string) error {
	return SetFilterConfigLocal(jail, content)
}

// Get all jails.
func (lc *LocalConnector) getJails(ctx context.Context) ([]string, error) {
	out, err := lc.runFail2banClient(ctx, "status")
	if err != nil {
		return nil, fmt.Errorf("error: unable to retrieve jail information. is your fail2ban service running? details: %w", err)
	}
	var jails []string
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Jail list:") {
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

// =========================================================================
//  CLI Helpers
// =========================================================================

func (lc *LocalConnector) runFail2banClient(ctx context.Context, args ...string) (string, error) {
	cmdArgs := lc.buildFail2banArgs(args...)
	cmd := exec.CommandContext(ctx, "fail2ban-client", cmdArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (lc *LocalConnector) buildFail2banArgs(args ...string) []string {
	if lc.server.SocketPath == "" {
		return args
	}
	base := []string{"-s", lc.server.SocketPath}
	return append(base, args...)
}

func (lc *LocalConnector) checkFail2banHealthy(ctx context.Context) error {
	out, err := lc.runFail2banClient(ctx, "ping")
	trimmed := strings.TrimSpace(out)
	if err != nil {
		return fmt.Errorf("fail2ban ping error: %w (output: %s)", err, trimmed)
	}
	if !strings.Contains(strings.ToLower(trimmed), "pong") {
		return fmt.Errorf("unexpected fail2ban ping output: %s", trimmed)
	}
	return nil
}

// =========================================================================
//  Delegated Operations
// =========================================================================

func (lc *LocalConnector) GetAllJails(ctx context.Context) ([]JailInfo, error) {
	return GetAllJails()
}

func (lc *LocalConnector) UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error {
	return UpdateJailEnabledStates(updates)
}

func (lc *LocalConnector) GetFilters(ctx context.Context) ([]string, error) {
	return GetFiltersLocal()
}

func (lc *LocalConnector) TestFilter(ctx context.Context, filterName string, logLines []string, filterContent string) (string, string, error) {
	return TestFilterLocal(filterName, logLines, filterContent)
}

func (lc *LocalConnector) GetJailConfig(ctx context.Context, jail string) (string, string, error) {
	return GetJailConfig(jail)
}

func (lc *LocalConnector) SetJailConfig(ctx context.Context, jail, content string) error {
	return SetJailConfig(jail, content)
}

func (lc *LocalConnector) TestLogpath(ctx context.Context, logpath string) ([]string, error) {
	return TestLogpath(logpath)
}

func (lc *LocalConnector) TestLogpathWithResolution(ctx context.Context, logpath string) (originalPath, resolvedPath string, files []string, err error) {
	return TestLogpathWithResolution(logpath)
}

func (lc *LocalConnector) UpdateDefaultSettings(ctx context.Context, settings config.AppSettings) error {
	return UpdateDefaultSettingsLocal(settings)
}

func (lc *LocalConnector) EnsureJailLocalStructure(ctx context.Context) error {
	return config.EnsureJailLocalStructure()
}

func (lc *LocalConnector) CreateJail(ctx context.Context, jailName, content string) error {
	return CreateJail(jailName, content)
}

func (lc *LocalConnector) DeleteJail(ctx context.Context, jailName string) error {
	return DeleteJail(jailName)
}

func (lc *LocalConnector) CreateFilter(ctx context.Context, filterName, content string) error {
	return CreateFilter(filterName, content)
}

func (lc *LocalConnector) DeleteFilter(ctx context.Context, filterName string) error {
	return DeleteFilter(filterName)
}

func (lc *LocalConnector) CheckJailLocalIntegrity(ctx context.Context) (bool, bool, error) {
	const jailLocalPath = "/etc/fail2ban/jail.local"
	content, err := os.ReadFile(jailLocalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("failed to read jail.local: %w", err)
	}
	hasUIAction := strings.Contains(string(content), "ui-custom-action")
	return true, hasUIAction, nil
}

// =========================================================================
//  Shell Execution
// =========================================================================

func executeShellCommand(ctx context.Context, command string) (string, error) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", errors.New("no command provided")
	}
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
