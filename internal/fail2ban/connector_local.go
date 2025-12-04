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

// UnbanIP implements Connector.
func (lc *LocalConnector) UnbanIP(ctx context.Context, jail, ip string) error {
	args := []string{"set", jail, "unbanip", ip}
	if _, err := lc.runFail2banClient(ctx, args...); err != nil {
		return fmt.Errorf("error unbanning IP %s from jail %s: %w", ip, jail, err)
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
	if strings.TrimSpace(out) != "OK" && strings.TrimSpace(out) != "" {
		config.DebugLog("fail2ban reload output: %s", out)
	}
	return nil
}

// Restart implements Connector.
func (lc *LocalConnector) Restart(ctx context.Context) error {
	if _, container := os.LookupEnv("CONTAINER"); container {
		return fmt.Errorf("restart not supported inside container; please restart fail2ban on the host")
	}
	cmd := "systemctl restart fail2ban"
	out, err := executeShellCommand(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to restart fail2ban: %w - output: %s", err, out)
	}
	return nil
}

// GetFilterConfig implements Connector.
func (lc *LocalConnector) GetFilterConfig(ctx context.Context, jail string) (string, error) {
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
func (lc *LocalConnector) TestFilter(ctx context.Context, filterName string, logLines []string) (string, error) {
	return TestFilterLocal(filterName, logLines)
}

// GetJailConfig implements Connector.
func (lc *LocalConnector) GetJailConfig(ctx context.Context, jail string) (string, error) {
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

// UpdateDefaultSettings implements Connector.
func (lc *LocalConnector) UpdateDefaultSettings(ctx context.Context, settings config.AppSettings) error {
	return UpdateDefaultSettingsLocal(settings)
}

// EnsureJailLocalStructure implements Connector.
func (lc *LocalConnector) EnsureJailLocalStructure(ctx context.Context) error {
	return config.EnsureJailLocalStructure()
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
