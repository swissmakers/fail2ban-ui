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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/httpx"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

const (
	// Budget for ordinary agent calls; reload, restart and validation get agentServiceTimeout.
	agentRequestTimeout = 15 * time.Second
	agentServiceTimeout = 60 * time.Second
	agentDeregisterWait = 5 * time.Second
)

// =========================================================================
//  Types
// =========================================================================

// Connector for a remote Fail2ban-Agent via HTTP API.
type AgentConnector struct {
	server            shared.Fail2banServer
	base              *url.URL
	client            *http.Client
	driftMu           sync.Mutex
	drifted           bool
	capabilityMu      sync.Mutex
	operationCapable  bool
	capabilityChecked time.Time
}

type AgentConfigErrorKind string

const (
	AgentConfigErrorMissingURL    AgentConfigErrorKind = "missing_url"
	AgentConfigErrorMissingSecret AgentConfigErrorKind = "missing_secret"
	AgentConfigErrorInvalidURL    AgentConfigErrorKind = "invalid_url"
)

type AgentConfigError struct {
	Kind AgentConfigErrorKind
	Err  error
}

func (e *AgentConfigError) Error() string {
	switch e.Kind {
	case AgentConfigErrorMissingURL:
		return "agentUrl is required for agent connector"
	case AgentConfigErrorMissingSecret:
		return "agentSecret is required for agent connector"
	case AgentConfigErrorInvalidURL:
		if e.Err != nil {
			return fmt.Sprintf("invalid agentUrl: %v", e.Err)
		}
		return "invalid agentUrl"
	default:
		if e.Err != nil {
			return e.Err.Error()
		}
		return "agent configuration error"
	}
}

func (e *AgentConfigError) Unwrap() error {
	return e.Err
}

type AgentHTTPError struct {
	StatusCode int
	Status     string
	Body       string
	Code       string
}

// Reports whether err is an agent HTTP error with one of the given status codes.
func agentStatusIs(err error, codes ...int) bool {
	var httpErr *AgentHTTPError
	if !errors.As(err, &httpErr) {
		return false
	}
	return slices.Contains(codes, httpErr.StatusCode)
}

// Older agents answer unknown endpoints with 404, or 405 when the path exists for another method.
func agentUnsupported(err error) bool {
	return agentStatusIs(err, http.StatusNotFound, http.StatusMethodNotAllowed)
}

func (e *AgentHTTPError) Error() string {
	if strings.TrimSpace(e.Code) != "" {
		return fmt.Sprintf("agent request failed: %s [%s] (%s)", e.Status, e.Code, e.Body)
	}
	return fmt.Sprintf("agent request failed: %s (%s)", e.Status, e.Body)
}

type AgentTransportError struct {
	Err error
}

func (e *AgentTransportError) Error() string {
	return fmt.Sprintf("agent request failed: %v", e.Err)
}

func (e *AgentTransportError) Unwrap() error {
	return e.Err
}

func AgentErrorMessageKey(err error) string {
	if err == nil {
		return ""
	}

	var cfgErr *AgentConfigError
	if errors.As(err, &cfgErr) {
		switch cfgErr.Kind {
		case AgentConfigErrorMissingURL, AgentConfigErrorMissingSecret:
			return "servers.errors.agent_missing_config"
		case AgentConfigErrorInvalidURL:
			return "servers.errors.agent_invalid_url"
		}
	}

	var transportErr *AgentTransportError
	if errors.As(err, &transportErr) {
		return "servers.errors.agent_unreachable"
	}

	var httpErr *AgentHTTPError
	if errors.As(err, &httpErr) {
		if httpErr.StatusCode == http.StatusUnauthorized {
			return "servers.errors.agent_wrong_secret"
		}
		return "servers.errors.agent_request_failed"
	}

	return ""
}

// =========================================================================
//  Constructor
// =========================================================================

// Create a new AgentConnector for the given server config.
func NewAgentConnector(server shared.Fail2banServer) (Connector, error) {
	if server.AgentURL == "" {
		return nil, &AgentConfigError{Kind: AgentConfigErrorMissingURL}
	}
	if server.AgentSecret == "" {
		return nil, &AgentConfigError{Kind: AgentConfigErrorMissingSecret}
	}
	parsed, err := NormalizeAgentURL(server.AgentURL)
	if err != nil {
		return nil, &AgentConfigError{Kind: AgentConfigErrorInvalidURL, Err: err}
	}
	return &AgentConnector{
		server: server,
		base:   parsed,
		client: httpx.Client(agentServiceTimeout, false),
	}, nil
}

// Trims input and validates the agent URL. A bare host without scheme gets http and the agent's native port 9700 as default
// URLs with an explicit http/https scheme are kept exactly as entered. -> no port means the scheme's implied default (80/443), so agents
// behind reverse proxies on standard ports work.
func NormalizeAgentURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty URL")
	}
	hadScheme := strings.Contains(raw, "://")
	if !hadScheme {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("missing host")
	}
	if !hadScheme && u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "9700")
	}
	return u, nil
}

// =========================================================================
//  Connector Functions
// =========================================================================

func (ac *AgentConnector) Server() shared.Fail2banServer {
	return ac.server
}

func (ac *AgentConnector) ensureCallbackConfig(ctx context.Context) error {
	p := mustProvider()
	// Same rules as the SSH/local action files, so no host receives a value the others would refuse.
	if err := shared.ValidateCallbackURL(p.CallbackURL()); err != nil {
		return err
	}
	if err := shared.ValidateCallbackSecret(p.CallbackSecret()); err != nil {
		return err
	}
	if err := shared.ValidateServerID(ac.server.ID); err != nil {
		return err
	}
	payload := map[string]any{
		"serverId":         ac.server.ID,
		"callbackUrl":      p.CallbackURL(),
		"callbackSecret":   p.CallbackSecret(),
		"callbackHostname": strings.TrimSpace(ac.server.Hostname),
	}
	if err := ac.put(ctx, "/v1/callback/config", payload, nil); err != nil {
		return err
	}
	ac.setDrifted(false)
	return nil
}

// Tells the agent to stop posting callbacks for this server entry; older agents lack the endpoint.
func (ac *AgentConnector) deregister() {
	ctx, cancel := context.WithTimeout(context.Background(), agentDeregisterWait)
	defer cancel()
	err := ac.call(ctx, http.MethodDelete, "/v1/callback/config?serverId="+url.QueryEscape(ac.server.ID), agentDeregisterWait, nil, nil)
	if err != nil && !agentUnsupported(err) {
		log.Printf("warning: failed to deregister callbacks on agent %s: %v", ac.server.Name, err)
	}
}

func (ac *AgentConnector) setDrifted(v bool) {
	ac.driftMu.Lock()
	ac.drifted = v
	ac.driftMu.Unlock()
}

func (ac *AgentConnector) actionDrifted() bool {
	ac.driftMu.Lock()
	defer ac.driftMu.Unlock()
	return ac.drifted
}

func (ac *AgentConnector) GetJailSummary(ctx context.Context) (*JailSummary, error) {
	var resp struct {
		Jails []JailInfo `json:"jails"`
	}
	if err := ac.get(ctx, "/v1/jails", &resp); err != nil {
		return nil, err
	}
	exists, managed, err := ac.CheckJailLocalIntegrity(ctx)
	if err != nil {
		debugf("Warning: could not check jail.local integrity on %s: %v", ac.server.Name, err)
	}
	return &JailSummary{Jails: resp.Jails, JailLocalExists: exists, JailLocalManaged: managed, ActionFileDrifted: ac.actionDrifted()}, nil
}

func (ac *AgentConnector) GetBannedIPs(ctx context.Context, jail string) ([]string, error) {
	if err := ValidateJailName(jail); err != nil {
		return nil, err
	}
	var resp struct {
		Jail        string   `json:"jail"`
		BannedIPs   []string `json:"bannedIPs"`
		TotalBanned int      `json:"totalBanned"`
	}
	if err := ac.get(ctx, "/v1/jails/"+url.PathEscape(jail), &resp); err != nil {
		return nil, err
	}
	if len(resp.BannedIPs) > 0 {
		return resp.BannedIPs, nil
	}
	return []string{}, nil
}

func (ac *AgentConnector) UnbanIP(ctx context.Context, jail, ip string) error {
	if err := validateBanTarget(jail, ip); err != nil {
		return err
	}
	payload := map[string]string{"ip": ip}
	payload["jail"] = jail
	_, err := ac.serviceOperation(ctx, "unban", payload)
	return err
}

func (ac *AgentConnector) BanIP(ctx context.Context, jail, ip string) error {
	if err := validateBanTarget(jail, ip); err != nil {
		return err
	}
	payload := map[string]string{"ip": ip}
	payload["jail"] = jail
	_, err := ac.serviceOperation(ctx, "ban", payload)
	return err
}

func (ac *AgentConnector) Reload(ctx context.Context) error {
	resp, err := ac.serviceOperation(ctx, "reload")
	if err != nil {
		return err
	}
	return checkReloadOutput(resp.Output)
}

// Returns the agent-reported mode; agents before 0.2 do not report one.
func (ac *AgentConnector) Restart(ctx context.Context) (string, error) {
	resp, err := ac.serviceOperation(ctx, "restart")
	if resp.Mode == "" {
		resp.Mode = "restart"
	}
	return resp.Mode, err
}

func (ac *AgentConnector) ValidateConfiguration(ctx context.Context) error {
	resp, err := ac.serviceOperation(ctx, "validate")
	if err != nil {
		return err
	}
	return checkReloadOutput(resp.Output)
}

type operationPhaseKey struct{}

func WithOperationPhase(ctx context.Context, phase string) context.Context {
	return context.WithValue(ctx, operationPhaseKey{}, phase)
}

func AgentOperationID(ctx context.Context, kind string) string {
	id := OperationID(ctx)
	if id == "" {
		return ""
	}
	phase, _ := ctx.Value(operationPhaseKey{}).(string)
	sum := sha256.Sum256([]byte(id + "\x00" + phase + "\x00" + kind))
	return hex.EncodeToString(sum[:])
}

type AgentOperation struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Jail      string `json:"jail,omitempty"`
	IP        string `json:"ip,omitempty"`
	State     string `json:"state"`
	Output    string `json:"output,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Error     string `json:"error,omitempty"`
	Code      string `json:"code,omitempty"`
	Quiescent bool   `json:"quiescent"`
}

func (ac *AgentConnector) RequireOperationSupport(ctx context.Context) error {
	ac.capabilityMu.Lock()
	defer ac.capabilityMu.Unlock()
	if time.Since(ac.capabilityChecked) < time.Minute {
		if ac.operationCapable {
			return nil
		}
		return fmt.Errorf("agent upgrade required: durable service operations and configuration validation are not supported")
	}
	var caps struct {
		Version int      `json:"version"`
		Kinds   []string `json:"kinds"`
	}
	err := ac.get(ctx, "/v1/operations/capabilities", &caps)
	if err != nil && !agentUnsupported(err) {
		return err
	}
	ac.operationCapable = err == nil && caps.Version >= 1 && slices.Contains(caps.Kinds, "reload") && slices.Contains(caps.Kinds, "restart") && slices.Contains(caps.Kinds, "validate") && slices.Contains(caps.Kinds, "ban") && slices.Contains(caps.Kinds, "unban")
	ac.capabilityChecked = time.Now()
	if !ac.operationCapable {
		return fmt.Errorf("agent upgrade required: durable service operations and configuration validation are not supported")
	}
	return nil
}

func (ac *AgentConnector) ReconcileOperation(ctx context.Context, kind string) (AgentOperation, error) {
	id := AgentOperationID(ctx, kind)
	if id == "" {
		return AgentOperation{}, fmt.Errorf("operation ID is required for reconciliation")
	}
	return ac.reconcileOperationID(ctx, id, kind)
}

func (ac *AgentConnector) reconcileOperationID(ctx context.Context, id, kind string) (AgentOperation, error) {
	op, err := ac.getOperation(ctx, id, kind)
	if !agentStatusIs(err, http.StatusNotFound) {
		return op, err
	}
	err = ac.post(ctx, "/v1/operations/"+url.PathEscape(id)+"/reconcile", map[string]string{"kind": kind}, &op)
	if err == nil && (op.ID != id || op.Kind != kind || op.State == "") {
		err = fmt.Errorf("agent returned an invalid reconciliation record")
	}
	return op, err
}

func (ac *AgentConnector) BackupConfiguration(ctx context.Context, id string) error {
	if err := ac.RequireOperationSupport(ctx); err != nil {
		return err
	}
	return ac.post(ctx, "/v1/config/snapshots", map[string]string{"id": id}, nil)
}
func (ac *AgentConnector) RestoreConfiguration(ctx context.Context, id string) error {
	return ac.post(ctx, "/v1/config/snapshots/"+url.PathEscape(id)+"/restore", nil, nil)
}
func (ac *AgentConnector) DeleteConfigurationBackup(ctx context.Context, id string) error {
	return ac.delete(ctx, "/v1/config/snapshots/"+url.PathEscape(id), nil)
}

func (ac *AgentConnector) getOperation(ctx context.Context, id, kind string) (AgentOperation, error) {
	var op AgentOperation
	err := ac.get(ctx, "/v1/operations/"+url.PathEscape(id), &op)
	if err == nil && (op.ID != id || op.Kind != kind || op.State == "") {
		err = fmt.Errorf("agent returned an invalid operation record")
	}
	return op, err
}

func (ac *AgentConnector) serviceOperation(ctx context.Context, kind string, target ...map[string]string) (AgentOperation, error) {
	if err := ac.RequireOperationSupport(ctx); err != nil {
		return AgentOperation{}, err
	}
	id := AgentOperationID(ctx, kind)
	if id == "" {
		id = "standalone-" + rand.Text()
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Minute)
	defer cancel()
	var op AgentOperation
	payload := map[string]string{"id": id, "kind": kind}
	if len(target) > 0 {
		payload["jail"], payload["ip"] = target[0]["jail"], target[0]["ip"]
	}
	err := ac.post(ctx, "/v1/operations", payload, &op)
	if err != nil {
		var httpErr *AgentHTTPError
		if errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusBadRequest || httpErr.StatusCode == http.StatusUnauthorized || httpErr.StatusCode == http.StatusForbidden || httpErr.StatusCode == http.StatusConflict) {
			return op, err
		}
		var getErr error
		op, getErr = ac.reconcileOperationID(ctx, id, kind)
		if getErr != nil {
			return op, fmt.Errorf("%w: agent operation %s (%s): %v", ErrOperationOutcomeUnknown, id, kind, err)
		}
	}
	for {
		if op.ID != id || op.Kind != kind {
			return op, fmt.Errorf("%w: invalid agent operation response for %s", ErrOperationOutcomeUnknown, id)
		}
		switch op.State {
		case "succeeded":
			return op, nil
		case "failed":
			if op.Code == "config_invalid" {
				return op, fmt.Errorf("configuration validation failed: %s", firstNonEmpty(op.Output, op.Error, "invalid configuration"))
			}
			return op, fmt.Errorf("agent %s failed: %s", kind, firstNonEmpty(op.Error, op.Output, op.Code, "no error detail"))
		case "unknown":
			return op, fmt.Errorf("%w: agent operation %s: %s", ErrOperationOutcomeUnknown, id, op.Error)
		case "queued", "running":
		default:
			return op, fmt.Errorf("%w: agent operation %s has invalid state %q", ErrOperationOutcomeUnknown, id, op.State)
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return op, fmt.Errorf("%w: agent operation %s continues independently: %v", ErrOperationOutcomeUnknown, id, ctx.Err())
		case <-timer.C:
		}
		op, err = ac.getOperation(ctx, id, kind)
		if err != nil {
			return op, fmt.Errorf("%w: cannot read agent operation %s: %v", ErrOperationOutcomeUnknown, id, err)
		}
	}
}

// Checks agent readiness and whether its callback registration still matches this server entry.
func (ac *AgentConnector) ProbeHealth(ctx context.Context) ServerHealth {
	var detail agentHealthDetail
	err := ac.get(ctx, "/v1/health", &detail)
	if agentUnsupported(err) {
		return ac.probeLegacyReadiness(ctx)
	}
	if err != nil {
		return ServerHealth{Error: err.Error(), TransportOK: agentTransportReachable(err)}
	}
	p := mustProvider()
	fingerprint := agentCallbackFingerprint(ac.server.AgentSecret, ac.server.ID, p.CallbackURL(), p.CallbackSecret())
	h, drifted := healthFromDetail(detail, ac.server.ID, fingerprint)
	ac.setDrifted(drifted)
	return h
}

func (ac *AgentConnector) probeLegacyReadiness(ctx context.Context) ServerHealth {
	ctx, cancel := context.WithTimeout(ctx, agentRequestTimeout)
	defer cancel()
	req, err := ac.newRequest(ctx, http.MethodGet, "/readyz", nil)
	if err != nil {
		return ServerHealth{Error: err.Error()}
	}
	resp, err := ac.client.Do(req)
	if err != nil {
		return ServerHealth{Error: (&AgentTransportError{Err: err}).Error()}
	}
	defer resp.Body.Close()
	body, err := httpx.ReadLimited(resp.Body)
	if err != nil {
		return ServerHealth{Error: err.Error()}
	}
	return healthFromLegacyReadyz(resp.StatusCode, body)
}

type agentHealthDetail struct {
	Ready      bool            `json:"ready"`
	Busy       bool            `json:"busy"`
	Checks     map[string]bool `json:"checks"`
	Supervisor struct {
		LastError string `json:"lastError"`
	} `json:"supervisor"`
	Callback struct {
		Configured  bool   `json:"configured"`
		ServerID    string `json:"serverId"`
		Fingerprint string `json:"fingerprint"`
		LastError   string `json:"lastError"`
	} `json:"callback"`
}

// Maps agent health detail to ServerHealth; drifted means the UI should push its callback config again.
func healthFromDetail(d agentHealthDetail, serverID, fingerprint string) (ServerHealth, bool) {
	reachable := true
	h := ServerHealth{Fail2banOK: d.Ready, TransportOK: &reachable, Busy: d.Busy}
	if d.Busy {
		h.Error = "service operation is active; daemon status is temporarily unavailable"
		return h, false
	}
	if !d.Ready {
		var failed []string
		for name, ok := range d.Checks {
			if !ok {
				failed = append(failed, name)
			}
		}
		slices.Sort(failed)
		h.Error = firstNonEmpty(d.Supervisor.LastError, "agent is not ready")
		if len(failed) > 0 {
			h.Error += " (failed checks: " + strings.Join(failed, ", ") + ")"
		}
		return h, false
	}
	callbackOK := false
	h.CallbackOK = &callbackOK
	switch {
	case !d.Callback.Configured || d.Callback.ServerID == "":
		h.Error = "agent has no callback configuration"
		return h, true
	case d.Callback.ServerID != serverID:
		h.Error = fmt.Sprintf("agent callbacks are registered to server entry %q", d.Callback.ServerID)
		return h, false
	case d.Callback.Fingerprint != fingerprint:
		h.Error = "agent callback configuration is outdated"
		return h, true
	case d.Callback.LastError != "":
		h.Error = "callback delivery failed: " + d.Callback.LastError
		return h, false
	}
	callbackOK = true
	return h, false
}

func agentTransportReachable(err error) *bool {
	var httpErr *AgentHTTPError
	if errors.As(err, &httpErr) {
		reachable := true
		return &reachable
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	var transportErr *AgentTransportError
	if errors.As(err, &transportErr) {
		reachable := false
		return &reachable
	}
	return nil
}

// Agents before 0.2 only expose /readyz; it reports fail2ban state but nothing about callbacks.
func healthFromLegacyReadyz(status int, body []byte) ServerHealth {
	var payload struct {
		Ready bool `json:"ready"`
		State struct {
			LastError string `json:"lastError"`
		} `json:"state"`
	}
	_ = json.Unmarshal(body, &payload)
	if status == http.StatusOK && payload.Ready {
		return ServerHealth{Fail2banOK: true}
	}
	return ServerHealth{Error: firstNonEmpty(payload.State.LastError, fmt.Sprintf("agent is not ready (HTTP %d)", status))}
}

// Identifies a callback registration without revealing the secret; the agent computes the same value.
func agentCallbackFingerprint(agentSecret, serverID, callbackURL, callbackSecret string) string {
	mac := hmac.New(sha256.New, []byte(agentSecret))
	mac.Write([]byte(serverID + "\n" + strings.TrimRight(callbackURL, "/") + "\n" + callbackSecret))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// =========================================================================
//  Filter Operations
// =========================================================================

func (ac *AgentConnector) GetFilterConfig(ctx context.Context, filter string) (string, string, error) {
	if err := ValidateFilterName(filter); err != nil {
		return "", "", err
	}
	var resp struct {
		Config   string `json:"config"`
		FilePath string `json:"filePath"`
	}
	if err := ac.get(ctx, "/v1/filters/"+url.PathEscape(filter), &resp); err != nil {
		return "", "", err
	}
	return resp.Config, firstNonEmpty(resp.FilePath, agentDefaultPath("filter.d", filter)), nil
}

func (ac *AgentConnector) SetFilterConfig(ctx context.Context, filter, content string) error {
	if err := ValidateFilterName(filter); err != nil {
		return err
	}
	if err := ac.RequireOperationSupport(ctx); err != nil {
		return err
	}
	payload := map[string]string{"config": content}
	return ac.put(ctx, "/v1/filters/"+url.PathEscape(filter), payload, nil)
}

// Path shown when an older agent does not report one.
func agentDefaultPath(dir, name string) string {
	return "/etc/fail2ban/" + dir + "/" + name + ".local"
}

// =========================================================================
//  HTTP Helpers
// =========================================================================

func (ac *AgentConnector) call(ctx context.Context, method, endpoint string, timeout time.Duration, payload, out any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := ac.newRequest(ctx, method, endpoint, payload)
	if err != nil {
		return err
	}
	return ac.do(req, out)
}

func (ac *AgentConnector) get(ctx context.Context, endpoint string, out any) error {
	return ac.call(ctx, http.MethodGet, endpoint, agentRequestTimeout, nil, out)
}

func (ac *AgentConnector) post(ctx context.Context, endpoint string, payload any, out any) error {
	return ac.call(ctx, http.MethodPost, endpoint, agentRequestTimeout, payload, out)
}

func (ac *AgentConnector) put(ctx context.Context, endpoint string, payload any, out any) error {
	return ac.call(ctx, http.MethodPut, endpoint, agentRequestTimeout, payload, out)
}

func (ac *AgentConnector) delete(ctx context.Context, endpoint string, out any) error {
	return ac.call(ctx, http.MethodDelete, endpoint, agentRequestTimeout, nil, out)
}

// Endpoints arrive already path-escaped; JoinPath keeps that escaping and the base path prefix.
func (ac *AgentConnector) newRequest(ctx context.Context, method, endpoint string, payload any) (*http.Request, error) {
	rel, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	u := ac.base.JoinPath(rel.EscapedPath())
	u.RawQuery = rel.RawQuery

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
	debugf("Agent request [%s]: %s %s", ac.server.Name, req.Method, req.URL.String())

	resp, err := ac.client.Do(req)
	if err != nil {
		debugf("Agent request error [%s]: %v", ac.server.Name, err)
		return &AgentTransportError{Err: err}
	}
	defer resp.Body.Close()

	data, err := httpx.ReadLimited(resp.Body)
	if err != nil {
		return err
	}
	trimmed := strings.TrimSpace(string(data))

	preview := trimmed
	if len(preview) > 512 {
		preview = preview[:512] + "..."
	}
	debugf("Agent response [%s]: %s | %s", ac.server.Name, resp.Status, preview)

	// Redirects are not followed, so a 3xx from a proxy must not count as success.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var payload struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal([]byte(trimmed), &payload)
		return &AgentHTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       trimmed,
			Code:       strings.TrimSpace(payload.Code),
		}
	}

	if out == nil {
		return nil
	}

	if len(trimmed) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// =========================================================================
//  Jail Operations
// =========================================================================

func (ac *AgentConnector) GetAllJails(ctx context.Context) ([]JailInfo, error) {
	var resp struct {
		Jails []JailInfo `json:"jails"`
	}
	if err := ac.get(ctx, "/v1/jails/all", &resp); err != nil {
		return nil, err
	}
	return resp.Jails, nil
}

func (ac *AgentConnector) UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error {
	for jail := range updates {
		if err := ValidateJailName(jail); err != nil {
			return err
		}
	}
	if err := ac.RequireOperationSupport(ctx); err != nil {
		return err
	}
	return ac.post(ctx, "/v1/jails/update-enabled", updates, nil)
}

func (ac *AgentConnector) GetFilters(ctx context.Context) ([]string, error) {
	var resp struct {
		Filters []string `json:"filters"`
	}
	if err := ac.get(ctx, "/v1/filters", &resp); err != nil {
		return nil, err
	}
	return resp.Filters, nil
}

func (ac *AgentConnector) TestFilter(ctx context.Context, filterName string, logLines []string, filterContent string) (string, string, error) {
	if err := ValidateFilterName(filterName); err != nil {
		return "", "", err
	}
	cleaned := normalizeLogLines(logLines)
	if len(cleaned) == 0 {
		return "No log lines provided.\n", "", nil
	}
	payload := map[string]any{
		"filterName": filterName,
		"logLines":   cleaned,
	}
	if filterContent != "" {
		payload["filterContent"] = filterContent
	}
	var resp struct {
		Output     string `json:"output"`
		FilterPath string `json:"filterPath"`
	}
	if err := ac.post(ctx, "/v1/filters/test", payload, &resp); err != nil {
		var httpErr *AgentHTTPError
		if errors.As(err, &httpErr) {
			var fail struct {
				Error      string `json:"error"`
				Output     string `json:"output"`
				FilterPath string `json:"filterPath"`
			}
			if json.Unmarshal([]byte(httpErr.Body), &fail) == nil {
				filterPath := firstNonEmpty(fail.FilterPath, agentDefaultPath("filter.d", filterName))
				if strings.TrimSpace(fail.Error) != "" || strings.TrimSpace(fail.Output) != "" || strings.TrimSpace(fail.FilterPath) != "" {
					errMsg := fail.Error
					if strings.TrimSpace(errMsg) == "" {
						errMsg = httpErr.Error()
					}
					return fail.Output, filterPath, fmt.Errorf("%s", errMsg)
				}
			}
		}
		return "", "", err
	}
	return resp.Output, firstNonEmpty(resp.FilterPath, agentDefaultPath("filter.d", filterName)), nil
}

func (ac *AgentConnector) GetJailConfig(ctx context.Context, jail string) (string, string, error) {
	if err := ValidateJailName(jail); err != nil {
		return "", "", err
	}
	var resp struct {
		Config   string `json:"config"`
		FilePath string `json:"filePath"`
	}
	if err := ac.get(ctx, "/v1/jails/"+url.PathEscape(jail)+"/config", &resp); err != nil {
		return "", "", err
	}
	return resp.Config, firstNonEmpty(resp.FilePath, agentDefaultPath("jail.d", jail)), nil
}

func (ac *AgentConnector) SetJailConfig(ctx context.Context, jail, content string) error {
	if err := ValidateJailName(jail); err != nil {
		return err
	}
	if err := ac.RequireOperationSupport(ctx); err != nil {
		return err
	}
	payload := map[string]string{"config": content}
	return ac.put(ctx, "/v1/jails/"+url.PathEscape(jail)+"/config", payload, nil)
}

// =========================================================================
//  Logpath Operations
// =========================================================================

func (ac *AgentConnector) testLogpathLegacy(ctx context.Context, logpath string) ([]string, error) {
	payload := map[string]string{"logpath": logpath}
	var resp struct {
		Files []string `json:"files"`
	}
	if err := ac.post(ctx, "/v1/jails/test-logpath", payload, &resp); err != nil {
		return nil, agentLogpathHTTPError(err)
	}
	return resp.Files, nil
}

// Turns a coded agent logpath rejection into agentLogpathError; other errors pass through.
func agentLogpathHTTPError(err error) error {
	var httpErr *AgentHTTPError
	if !errors.As(err, &httpErr) || httpErr.Code == "" {
		return err
	}
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal([]byte(httpErr.Body), &body)
	return agentLogpathError(httpErr.Code, firstNonEmpty(body.Error, httpErr.Status))
}

// Maps an agent logpath error code so handlers can tell an unreadable directory from a bad path.
func agentLogpathError(code, message string) error {
	if code == "logpath_inaccessible" {
		return fmt.Errorf("%w: %s", ErrLogpathInaccessible, message)
	}
	return fmt.Errorf("agent error: %s", message)
}

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
		Code            string   `json:"code,omitempty"`
	}

	// Try new endpoint first, fallback to old endpoint
	if err := ac.post(ctx, "/v1/jails/test-logpath-with-resolution", payload, &resp); err != nil {
		if !agentUnsupported(err) {
			return originalPath, "", nil, fmt.Errorf("failed to test logpath: %w", agentLogpathHTTPError(err))
		}
		// Fallback; use old endpoint if the agent lacks the new endpoint and assume no resolution
		// Agents without variable resolution only glob the literal path.
		files, err2 := ac.testLogpathLegacy(ctx, originalPath)
		if err2 != nil {
			return originalPath, "", nil, fmt.Errorf("failed to test logpath: %w", err2)
		}
		return originalPath, originalPath, files, nil
	}

	if resp.Error != "" {
		return originalPath, "", nil, agentLogpathError(resp.Code, resp.Error)
	}

	if resp.ResolvedLogpath == "" {
		resp.ResolvedLogpath = resp.OriginalLogpath
	}
	if resp.OriginalLogpath == "" {
		resp.OriginalLogpath = originalPath
	}

	return resp.OriginalLogpath, resp.ResolvedLogpath, resp.Files, nil
}

// =========================================================================
//  Settings and Structure
// =========================================================================

func (ac *AgentConnector) CheckJailLocalIntegrity(ctx context.Context) (bool, bool, error) {
	var result struct {
		Exists      bool `json:"exists"`
		HasUIAction bool `json:"hasUIAction"`
		Managed     bool `json:"managed"`
	}
	if err := ac.get(ctx, "/v1/jails/check-integrity", &result); err != nil {
		// If the agent does not implement this endpoint, assume OK.
		// Unknown on agents without the endpoint: report managed so nothing tries to recreate it.
		if agentStatusIs(err, http.StatusNotFound) {
			return true, true, nil
		}
		return false, false, fmt.Errorf("failed to check jail.local integrity on %s: %w", ac.server.Name, err)
	}
	return result.Exists, result.Managed || result.HasUIAction, nil
}

func (ac *AgentConnector) EnsureJailLocalStructure(ctx context.Context) error {
	if err := ac.RequireOperationSupport(ctx); err != nil {
		return err
	}
	content := mustProvider().BuildJailLocalContent()
	payload := map[string]any{}
	if strings.TrimSpace(content) != "" {
		payload["content"] = content
	}
	var resp struct {
		Skipped bool   `json:"skipped"`
		Reason  string `json:"reason"`
	}
	if err := ac.post(ctx, "/v1/jails/ensure-structure", payload, &resp); err != nil {
		return err
	}
	// If jail.local exists but is not managed by Fail2ban-UI, it belongs to the user; the agent does not overwrite it and reports it as skipped.
	if resp.Skipped {
		debugf("jail.local on agent server %s left untouched: %s", ac.server.Name, resp.Reason)
	}
	return nil
}

// =========================================================================
//  Filter and Jail Management
// =========================================================================

func (ac *AgentConnector) CreateJail(ctx context.Context, jailName, content string) error {
	if err := ValidateJailName(jailName); err != nil {
		return err
	}
	if err := ac.RequireOperationSupport(ctx); err != nil {
		return err
	}
	payload := map[string]interface{}{
		"name":    jailName,
		"content": content,
	}
	return ac.post(ctx, "/v1/jails", payload, nil)
}

func (ac *AgentConnector) DeleteJail(ctx context.Context, jailName string) error {
	if err := ValidateJailName(jailName); err != nil {
		return err
	}
	if err := ac.RequireOperationSupport(ctx); err != nil {
		return err
	}
	return ac.delete(ctx, "/v1/jails/"+url.PathEscape(jailName), nil)
}

func (ac *AgentConnector) CreateFilter(ctx context.Context, filterName, content string) error {
	if err := ValidateFilterName(filterName); err != nil {
		return err
	}
	if err := ac.RequireOperationSupport(ctx); err != nil {
		return err
	}
	payload := map[string]interface{}{
		"name":    filterName,
		"content": content,
	}
	return ac.post(ctx, "/v1/filters", payload, nil)
}

func (ac *AgentConnector) DeleteFilter(ctx context.Context, filterName string) error {
	if err := ValidateFilterName(filterName); err != nil {
		return err
	}
	if err := ac.RequireOperationSupport(ctx); err != nil {
		return err
	}
	return ac.delete(ctx, "/v1/filters/"+url.PathEscape(filterName), nil)
}

func (ac *AgentConnector) Close() error {
	ac.client.CloseIdleConnections()
	return nil
}
