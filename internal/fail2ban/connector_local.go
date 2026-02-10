package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// LocalConnector interacts with a local fail2ban instance via fail2ban-client CLI.
type LocalConnector struct {
	server config.Fail2banServer
}

// NewLocalConnector creates a new LocalConnector instance.
func NewLocalConnector(server config.Fail2banServer) *LocalConnector {
	return &LocalConnector{server: server}
}

// ID implements Connector.
func (lc *LocalConnector) ID() string {
	return lc.server.ID
}

// Server implements Connector.
func (lc *LocalConnector) Server() config.Fail2banServer {
	return lc.server
}

// GetJailInfos implements Connector.
func (lc *LocalConnector) GetJailInfos(ctx context.Context) ([]JailInfo, error) {
	jails, err := lc.getJails(ctx)
	if err != nil {
		return nil, err
	}

	logPath := lc.server.LogPath
	if logPath == "" {
		logPath = "/var/log/fail2ban.log"
	}

	banHistory, err := ParseBanLog(logPath)
	if err != nil {
		banHistory = make(map[string][]BanEvent)
	}

	oneHourAgo := time.Now().Add(-1 * time.Hour)

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
			bannedIPs, err := lc.GetBannedIPs(ctx, j)
			if err != nil {
				results <- jailResult{err: err}
				return
			}
			newInLastHour := 0
			if events, ok := banHistory[j]; ok {
				for _, e := range events {
					if e.Time.After(oneHourAgo) {
						newInLastHour++
					}
				}
			}
			results <- jailResult{
				jail: JailInfo{
					JailName:      j,
					TotalBanned:   len(bannedIPs),
					NewInLastHour: newInLastHour,
					BannedIPs:     bannedIPs,
					Enabled:       true,
				},
			}
		}(jail)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var finalResults []JailInfo
	for result := range results {
		if result.err != nil {
			continue
		}
		finalResults = append(finalResults, result.jail)
	}

	sort.SliceStable(finalResults, func(i, j int) bool {
		return finalResults[i].JailName < finalResults[j].JailName
	})
	return finalResults, nil
}

// GetBannedIPs implements Connector.
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

// UnbanIP implements Connector.
func (lc *LocalConnector) UnbanIP(ctx context.Context, jail, ip string) error {
	args := []string{"set", jail, "unbanip", ip}
	if _, err := lc.runFail2banClient(ctx, args...); err != nil {
		return fmt.Errorf("error unbanning IP %s from jail %s: %w", ip, jail, err)
	}
	return nil
}

// BanIP implements Connector.
func (lc *LocalConnector) BanIP(ctx context.Context, jail, ip string) error {
	args := []string{"set", jail, "banip", ip}
	if _, err := lc.runFail2banClient(ctx, args...); err != nil {
		return fmt.Errorf("error banning IP %s in jail %s: %w", ip, jail, err)
	}
	return nil
}

// Reload implements Connector.
func (lc *LocalConnector) Reload(ctx context.Context) error {
	out, err := lc.runFail2banClient(ctx, "reload")
	if err != nil {
		// Include the output in the error message for better debugging
		return fmt.Errorf("fail2ban reload error: %w (output: %s)", err, strings.TrimSpace(out))
	}

	// Check if output indicates success (fail2ban-client returns "OK" on success)
	outputTrimmed := strings.TrimSpace(out)
	if outputTrimmed != "OK" && outputTrimmed != "" {
		config.DebugLog("fail2ban reload output: %s", out)

		// Check for jail errors in output even when command succeeds
		// Look for patterns like "Errors in jail 'jailname'. Skipping..."
		if strings.Contains(out, "Errors in jail") || strings.Contains(out, "Unable to read the filter") {
			// Return an error that includes the output so handler can parse it
			return fmt.Errorf("fail2ban reload completed but with errors (output: %s)", strings.TrimSpace(out))
		}
	}
	return nil
}

// RestartWithMode restarts (or reloads) the local Fail2ban instance and returns
// a mode string describing what happened:
//   - "restart": systemd service was restarted and health check passed
//   - "reload":  configuration was reloaded via fail2ban-client and pong check passed
func (lc *LocalConnector) RestartWithMode(ctx context.Context) (string, error) {
	// 1) Try systemd restart if systemctl is available.
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

	// 2) Fallback: no systemctl in PATH (container image without systemd, or
	//    non-systemd environment). Use fail2ban-client reload + ping.
	if err := lc.Reload(ctx); err != nil {
		return "reload", fmt.Errorf("failed to reload fail2ban via fail2ban-client (systemctl not available): %w", err)
	}
	if err := lc.checkFail2banHealthy(ctx); err != nil {
		return "reload", fmt.Errorf("fail2ban health check after reload failed: %w", err)
	}
	return "reload", nil
}

// Restart implements Connector.
func (lc *LocalConnector) Restart(ctx context.Context) error {
	_, err := lc.RestartWithMode(ctx)
	return err
}

// GetFilterConfig implements Connector.
func (lc *LocalConnector) GetFilterConfig(ctx context.Context, jail string) (string, string, error) {
	return GetFilterConfigLocal(jail)
}

// SetFilterConfig implements Connector.
func (lc *LocalConnector) SetFilterConfig(ctx context.Context, jail, content string) error {
	return SetFilterConfigLocal(jail, content)
}

// FetchBanEvents implements Connector.
func (lc *LocalConnector) FetchBanEvents(ctx context.Context, limit int) ([]BanEvent, error) {
	logPath := lc.server.LogPath
	if logPath == "" {
		logPath = "/var/log/fail2ban.log"
	}
	eventsByJail, err := ParseBanLog(logPath)
	if err != nil {
		return nil, err
	}
	var all []BanEvent
	for _, evs := range eventsByJail {
		all = append(all, evs...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		return all[i].Time.After(all[j].Time)
	})
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

func (lc *LocalConnector) getJails(ctx context.Context) ([]string, error) {
	out, err := lc.runFail2banClient(ctx, "status")
	if err != nil {
		return nil, fmt.Errorf("error: unable to retrieve jail information. is your fail2ban service running? details: %w", err)
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

// checkFail2banHealthy runs a quick `fail2ban-client ping` via the existing
// runFail2banClient helper and expects a successful pong reply.
func (lc *LocalConnector) checkFail2banHealthy(ctx context.Context) error {
	out, err := lc.runFail2banClient(ctx, "ping")
	trimmed := strings.TrimSpace(out)
	if err != nil {
		return fmt.Errorf("fail2ban ping error: %w (output: %s)", err, trimmed)
	}
	// Typical output is e.g. "Server replied: pong" – accept anything that
	// contains "pong" case-insensitively.
	if !strings.Contains(strings.ToLower(trimmed), "pong") {
		return fmt.Errorf("unexpected fail2ban ping output: %s", trimmed)
	}
	return nil
}

// GetAllJails implements Connector.
func (lc *LocalConnector) GetAllJails(ctx context.Context) ([]JailInfo, error) {
	return GetAllJails()
}

// UpdateJailEnabledStates implements Connector.
func (lc *LocalConnector) UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error {
	return UpdateJailEnabledStates(updates)
}

// GetFilters implements Connector.
func (lc *LocalConnector) GetFilters(ctx context.Context) ([]string, error) {
	return GetFiltersLocal()
}

// TestFilter implements Connector.
func (lc *LocalConnector) TestFilter(ctx context.Context, filterName string, logLines []string, filterContent string) (string, string, error) {
	return TestFilterLocal(filterName, logLines, filterContent)
}

// GetJailConfig implements Connector.
func (lc *LocalConnector) GetJailConfig(ctx context.Context, jail string) (string, string, error) {
	return GetJailConfig(jail)
}

// SetJailConfig implements Connector.
func (lc *LocalConnector) SetJailConfig(ctx context.Context, jail, content string) error {
	return SetJailConfig(jail, content)
}

// TestLogpath implements Connector.
func (lc *LocalConnector) TestLogpath(ctx context.Context, logpath string) ([]string, error) {
	return TestLogpath(logpath)
}

// TestLogpathWithResolution implements Connector.
func (lc *LocalConnector) TestLogpathWithResolution(ctx context.Context, logpath string) (originalPath, resolvedPath string, files []string, err error) {
	return TestLogpathWithResolution(logpath)
}

// UpdateDefaultSettings implements Connector.
func (lc *LocalConnector) UpdateDefaultSettings(ctx context.Context, settings config.AppSettings) error {
	return UpdateDefaultSettingsLocal(settings)
}

// EnsureJailLocalStructure implements Connector.
func (lc *LocalConnector) EnsureJailLocalStructure(ctx context.Context) error {
	return config.EnsureJailLocalStructure()
}

// CreateJail implements Connector.
func (lc *LocalConnector) CreateJail(ctx context.Context, jailName, content string) error {
	return CreateJail(jailName, content)
}

// DeleteJail implements Connector.
func (lc *LocalConnector) DeleteJail(ctx context.Context, jailName string) error {
	return DeleteJail(jailName)
}

// CreateFilter implements Connector.
func (lc *LocalConnector) CreateFilter(ctx context.Context, filterName, content string) error {
	return CreateFilter(filterName, content)
}

// DeleteFilter implements Connector.
func (lc *LocalConnector) DeleteFilter(ctx context.Context, filterName string) error {
	return DeleteFilter(filterName)
}

// CheckJailLocalIntegrity implements Connector.
func (lc *LocalConnector) CheckJailLocalIntegrity(ctx context.Context) (bool, bool, error) {
	const jailLocalPath = "/etc/fail2ban/jail.local"
	content, err := os.ReadFile(jailLocalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, nil // file does not exist; OK, will be created
		}
		return false, false, fmt.Errorf("failed to read jail.local: %w", err)
	}
	hasUIAction := strings.Contains(string(content), "ui-custom-action")
	return true, hasUIAction, nil
}

func executeShellCommand(ctx context.Context, command string) (string, error) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", errors.New("no command provided")
	}
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
