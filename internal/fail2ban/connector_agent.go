package fail2ban

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// AgentConnector connects to a remote fail2ban-agent via HTTP API.
type AgentConnector struct {
	server config.Fail2banServer
	base   *url.URL
	client *http.Client
}

// NewAgentConnector constructs a new AgentConnector.
func NewAgentConnector(server config.Fail2banServer) (Connector, error) {
	if server.AgentURL == "" {
		return nil, fmt.Errorf("agentUrl is required for agent connector")
	}
	if server.AgentSecret == "" {
		return nil, fmt.Errorf("agentSecret is required for agent connector")
	}
	parsed, err := url.Parse(server.AgentURL)
	if err != nil {
		return nil, fmt.Errorf("invalid agentUrl: %w", err)
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	conn := &AgentConnector{
		server: server,
		base:   parsed,
		client: client,
	}
	if err := conn.ensureAction(context.Background()); err != nil {
		fmt.Printf("warning: failed to ensure agent action for %s: %v\n", server.Name, err)
	}
	return conn, nil
}

func (ac *AgentConnector) ID() string {
	return ac.server.ID
}

func (ac *AgentConnector) Server() config.Fail2banServer {
	return ac.server
}

func (ac *AgentConnector) ensureAction(ctx context.Context) error {
	settings := config.GetSettings()
	payload := map[string]any{
		"name":        "ui-custom-action",
		"config":      config.BuildFail2banActionConfig(config.GetCallbackURL(), ac.server.ID, settings.CallbackSecret),
		"callbackUrl": config.GetCallbackURL(),
		"setDefault":  true,
	}
	return ac.put(ctx, "/v1/actions/ui-custom", payload, nil)
}

func (ac *AgentConnector) GetJailInfos(ctx context.Context) ([]JailInfo, error) {
	var resp struct {
		Jails []JailInfo `json:"jails"`
	}
	if err := ac.get(ctx, "/v1/jails", &resp); err != nil {
		return nil, err
	}
	return resp.Jails, nil
}

func (ac *AgentConnector) GetBannedIPs(ctx context.Context, jail string) ([]string, error) {
	var resp struct {
		Jail        string   `json:"jail"`
		BannedIPs   []string `json:"bannedIPs"`
		TotalBanned int      `json:"totalBanned"`
	}
	if err := ac.get(ctx, fmt.Sprintf("/v1/jails/%s", url.PathEscape(jail)), &resp); err != nil {
		return nil, err
	}
	if len(resp.BannedIPs) > 0 {
		return resp.BannedIPs, nil
	}
	return []string{}, nil
}

func (ac *AgentConnector) UnbanIP(ctx context.Context, jail, ip string) error {
	payload := map[string]string{"ip": ip}
	return ac.post(ctx, fmt.Sprintf("/v1/jails/%s/unban", url.PathEscape(jail)), payload, nil)
}

func (ac *AgentConnector) BanIP(ctx context.Context, jail, ip string) error {
	payload := map[string]string{"ip": ip}
	return ac.post(ctx, fmt.Sprintf("/v1/jails/%s/ban", url.PathEscape(jail)), payload, nil)
}

func (ac *AgentConnector) Reload(ctx context.Context) error {
	return ac.post(ctx, "/v1/actions/reload", nil, nil)
}

func (ac *AgentConnector) Restart(ctx context.Context) error {
	return ac.post(ctx, "/v1/actions/restart", nil, nil)
}

// RestartWithMode restarts the remote agent-managed Fail2ban service and
// always reports mode "restart". Any error is propagated to the caller.
func (ac *AgentConnector) RestartWithMode(ctx context.Context) (string, error) {
	if err := ac.Restart(ctx); err != nil {
		return "restart", err
	}
	return "restart", nil
}

func (ac *AgentConnector) GetFilterConfig(ctx context.Context, jail string) (string, string, error) {
	var resp struct {
		Config   string `json:"config"`
		FilePath string `json:"filePath"`
	}
	if err := ac.get(ctx, fmt.Sprintf("/v1/filters/%s", url.PathEscape(jail)), &resp); err != nil {
		return "", "", err
	}
	// If agent doesn't return filePath, construct it (agent should handle .local priority)
	filePath := resp.FilePath
	if filePath == "" {
		// Default to .local path (agent should handle .local priority on its side)
		filePath = fmt.Sprintf("/etc/fail2ban/filter.d/%s.local", jail)
	}
	return resp.Config, filePath, nil
}

func (ac *AgentConnector) SetFilterConfig(ctx context.Context, jail, content string) error {
	payload := map[string]string{"config": content}
	return ac.put(ctx, fmt.Sprintf("/v1/filters/%s", url.PathEscape(jail)), payload, nil)
}

func (ac *AgentConnector) FetchBanEvents(ctx context.Context, limit int) ([]BanEvent, error) {
	query := url.Values{}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	var resp struct {
		Events []struct {
			IP        string `json:"ip"`
			Jail      string `json:"jail"`
			Hostname  string `json:"hostname"`
			Failures  string `json:"failures"`
			Whois     string `json:"whois"`
			Logs      string `json:"logs"`
			Timestamp string `json:"timestamp"`
		} `json:"events"`
	}
	endpoint := "/v1/events"
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	if err := ac.get(ctx, endpoint, &resp); err != nil {
		return nil, err
	}
	result := make([]BanEvent, 0, len(resp.Events))
	for _, evt := range resp.Events {
		ts, err := time.Parse(time.RFC3339, evt.Timestamp)
		if err != nil {
			ts = time.Now()
		}
		result = append(result, BanEvent{
			Time:    ts,
			Jail:    evt.Jail,
			IP:      evt.IP,
			LogLine: fmt.Sprintf("%s %s", evt.Hostname, evt.Failures),
		})
	}
	return result, nil
}

func (ac *AgentConnector) get(ctx context.Context, endpoint string, out any) error {
	req, err := ac.newRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	return ac.do(req, out)
}

func (ac *AgentConnector) post(ctx context.Context, endpoint string, payload any, out any) error {
	req, err := ac.newRequest(ctx, http.MethodPost, endpoint, payload)
	if err != nil {
		return err
	}
	return ac.do(req, out)
}

func (ac *AgentConnector) put(ctx context.Context, endpoint string, payload any, out any) error {
	req, err := ac.newRequest(ctx, http.MethodPut, endpoint, payload)
	if err != nil {
		return err
	}
	return ac.do(req, out)
}

func (ac *AgentConnector) delete(ctx context.Context, endpoint string, out any) error {
	req, err := ac.newRequest(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	return ac.do(req, out)
}

func (ac *AgentConnector) newRequest(ctx context.Context, method, endpoint string, payload any) (*http.Request, error) {
	u := *ac.base
	u.Path = path.Join(ac.base.Path, strings.TrimPrefix(endpoint, "/"))

	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-F2B-Token", ac.server.AgentSecret)
	return req, nil
}

func (ac *AgentConnector) do(req *http.Request, out any) error {
	settingsSnapshot := config.GetSettings()
	if settingsSnapshot.Debug {
		config.DebugLog("Agent request [%s]: %s %s", ac.server.Name, req.Method, req.URL.String())
	}

	resp, err := ac.client.Do(req)
	if err != nil {
		if settingsSnapshot.Debug {
			config.DebugLog("Agent request error [%s]: %v", ac.server.Name, err)
		}
		return fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(string(data))

	if settingsSnapshot.Debug {
		config.DebugLog("Agent response [%s]: %s | %s", ac.server.Name, resp.Status, trimmed)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("agent request failed: %s (%s)", resp.Status, trimmed)
	}

	if out == nil {
		return nil
	}

	if len(trimmed) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// GetAllJails implements Connector.
func (ac *AgentConnector) GetAllJails(ctx context.Context) ([]JailInfo, error) {
	var resp struct {
		Jails []JailInfo `json:"jails"`
	}
	if err := ac.get(ctx, "/v1/jails/all", &resp); err != nil {
		return nil, err
	}
	return resp.Jails, nil
}

// UpdateJailEnabledStates implements Connector.
func (ac *AgentConnector) UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error {
	return ac.post(ctx, "/v1/jails/update-enabled", updates, nil)
}

// GetFilters implements Connector.
func (ac *AgentConnector) GetFilters(ctx context.Context) ([]string, error) {
	var resp struct {
		Filters []string `json:"filters"`
	}
	if err := ac.get(ctx, "/v1/filters", &resp); err != nil {
		return nil, err
	}
	return resp.Filters, nil
}

// TestFilter implements Connector.
func (ac *AgentConnector) TestFilter(ctx context.Context, filterName string, logLines []string, filterContent string) (string, string, error) {
	payload := map[string]any{
		"filterName": filterName,
		"logLines":   logLines,
	}
	if filterContent != "" {
		payload["filterContent"] = filterContent
	}
	var resp struct {
		Output     string `json:"output"`
		FilterPath string `json:"filterPath"`
	}
	if err := ac.post(ctx, "/v1/filters/test", payload, &resp); err != nil {
		return "", "", err
	}
	// If agent doesn't return filterPath, construct it (agent should handle .local priority)
	filterPath := resp.FilterPath
	if filterPath == "" {
		// Default to .conf path (agent should handle .local priority on its side)
		filterPath = fmt.Sprintf("/etc/fail2ban/filter.d/%s.conf", filterName)
	}
	return resp.Output, filterPath, nil
}

// GetJailConfig implements Connector.
func (ac *AgentConnector) GetJailConfig(ctx context.Context, jail string) (string, string, error) {
	var resp struct {
		Config   string `json:"config"`
		FilePath string `json:"filePath"`
	}
	if err := ac.get(ctx, fmt.Sprintf("/v1/jails/%s/config", url.PathEscape(jail)), &resp); err != nil {
		return "", "", err
	}
	// If agent doesn't return filePath, construct it (agent should handle .local priority)
	filePath := resp.FilePath
	if filePath == "" {
		// Default to .local path (agent should handle .local priority on its side)
		filePath = fmt.Sprintf("/etc/fail2ban/jail.d/%s.local", jail)
	}
	return resp.Config, filePath, nil
}

// SetJailConfig implements Connector.
func (ac *AgentConnector) SetJailConfig(ctx context.Context, jail, content string) error {
	payload := map[string]string{"config": content}
	return ac.put(ctx, fmt.Sprintf("/v1/jails/%s/config", url.PathEscape(jail)), payload, nil)
}

// TestLogpath implements Connector.
func (ac *AgentConnector) TestLogpath(ctx context.Context, logpath string) ([]string, error) {
	payload := map[string]string{"logpath": logpath}
	var resp struct {
		Files []string `json:"files"`
	}
	if err := ac.post(ctx, "/v1/jails/test-logpath", payload, &resp); err != nil {
		return []string{}, nil // Return empty on error
	}
	return resp.Files, nil
}

// TestLogpathWithResolution implements Connector.
// Agent server should handle variable resolution.
func (ac *AgentConnector) TestLogpathWithResolution(ctx context.Context, logpath string) (originalPath, resolvedPath string, files []string, err error) {
	originalPath = strings.TrimSpace(logpath)
	if originalPath == "" {
		return originalPath, "", []string{}, nil
	}

	payload := map[string]string{"logpath": originalPath}
	var resp struct {
		OriginalLogpath string   `json:"original_logpath"`
		ResolvedLogpath string   `json:"resolved_logpath"`
		Files           []string `json:"files"`
		Error           string   `json:"error,omitempty"`
	}

	// Try new endpoint first, fallback to old endpoint
	if err := ac.post(ctx, "/v1/jails/test-logpath-with-resolution", payload, &resp); err != nil {
		// Fallback: use old endpoint and assume no resolution
		files, err2 := ac.TestLogpath(ctx, originalPath)
		if err2 != nil {
			return originalPath, "", nil, fmt.Errorf("failed to test logpath: %w", err2)
		}
		return originalPath, originalPath, files, nil
	}

	if resp.Error != "" {
		return originalPath, "", nil, fmt.Errorf("agent error: %s", resp.Error)
	}

	if resp.ResolvedLogpath == "" {
		resp.ResolvedLogpath = resp.OriginalLogpath
	}
	if resp.OriginalLogpath == "" {
		resp.OriginalLogpath = originalPath
	}

	return resp.OriginalLogpath, resp.ResolvedLogpath, resp.Files, nil
}

// UpdateDefaultSettings implements Connector.
func (ac *AgentConnector) UpdateDefaultSettings(ctx context.Context, settings config.AppSettings) error {
	// Convert IgnoreIPs array to space-separated string
	ignoreIPStr := strings.Join(settings.IgnoreIPs, " ")
	if ignoreIPStr == "" {
		ignoreIPStr = "127.0.0.1/8 ::1"
	}
	// Set default banaction values if not set
	banaction := settings.Banaction
	if banaction == "" {
		banaction = "nftables-multiport"
	}
	banactionAllports := settings.BanactionAllports
	if banactionAllports == "" {
		banactionAllports = "nftables-allports"
	}
	chain := settings.Chain
	if chain == "" {
		chain = "INPUT"
	}
	payload := map[string]interface{}{
		"bantimeIncrement":  settings.BantimeIncrement,
		"defaultJailEnable": settings.DefaultJailEnable,
		"ignoreip":          ignoreIPStr,
		"bantime":           settings.Bantime,
		"findtime":          settings.Findtime,
		"maxretry":          settings.Maxretry,
		"banaction":         banaction,
		"banactionAllports": banactionAllports,
		"chain":             chain,
		"bantimeRndtime":    settings.BantimeRndtime,
	}
	return ac.put(ctx, "/v1/jails/default-settings", payload, nil)
}

// EnsureJailLocalStructure implements Connector.
func (ac *AgentConnector) EnsureJailLocalStructure(ctx context.Context) error {
	// Call agent API endpoint to ensure jail.local structure
	// If the endpoint doesn't exist, we'll need to implement it on the agent side
	// For now, we'll try calling it and handle the error gracefully
	return ac.post(ctx, "/v1/jails/ensure-structure", nil, nil)
}

// CreateJail implements Connector.
func (ac *AgentConnector) CreateJail(ctx context.Context, jailName, content string) error {
	payload := map[string]interface{}{
		"name":    jailName,
		"content": content,
	}
	return ac.post(ctx, "/v1/jails", payload, nil)
}

// DeleteJail implements Connector.
func (ac *AgentConnector) DeleteJail(ctx context.Context, jailName string) error {
	return ac.delete(ctx, fmt.Sprintf("/v1/jails/%s", jailName), nil)
}

// CreateFilter implements Connector.
func (ac *AgentConnector) CreateFilter(ctx context.Context, filterName, content string) error {
	payload := map[string]interface{}{
		"name":    filterName,
		"content": content,
	}
	return ac.post(ctx, "/v1/filters", payload, nil)
}

// DeleteFilter implements Connector.
func (ac *AgentConnector) DeleteFilter(ctx context.Context, filterName string) error {
	return ac.delete(ctx, fmt.Sprintf("/v1/filters/%s", filterName), nil)
}
