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

package integrations

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/httpx"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// =========================================================================
//  Types
// =========================================================================

// Integration for the official Netgate Nexus API built into pfSense Plus
// 25.07+ (GUI and API served on port 8443, or 8080 over HTTP). Unlike the
// community pfSense REST API package, Nexus has no static API tokens: clients
// authenticate with a pfSense user account against POST /login and receive a
// short-lived JWT bearer token.
type pfSenseNexusIntegration struct{}

// nexusLoginResponse is the payload returned by POST /login.
type nexusLoginResponse struct {
	Token string `json:"token"`
}

// nexusTarget mirrors the FWTarget schema: one entry of an alias.
type nexusTarget struct {
	Name       string `json:"name"`
	Descr      string `json:"descr,omitempty"`
	UpdateFreq string `json:"updatefreq,omitempty"`
}

// nexusAlias mirrors the FWAlias schema returned by GET /aliases.
// Note: detail is a single string in Nexus (unlike the pfSense REST API
// package, where it is a list parallel to the address list).
type nexusAlias struct {
	Name      string        `json:"name"`
	Type      string        `json:"type,omitempty"`
	Descr     string        `json:"descr,omitempty"`
	Address   string        `json:"address,omitempty"`
	Targets   []nexusTarget `json:"targets,omitempty"`
	Detail    string        `json:"detail,omitempty"`
	Truncated bool          `json:"truncated,omitempty"`
}

// nexusAliasesResponse is the payload of GET /aliases.
type nexusAliasesResponse struct {
	Aliases       []nexusAlias `json:"aliases"`
	SystemAliases []nexusAlias `json:"system_aliases"`
}

// nexusTokenCache caches the JWT for a short window so bursts of block
// events (several IPs crossing the threshold at once) do not log in again
// for every single call. The TTL is derived from the token itself whenever
// it can be parsed; it never outlives the server-issued expiry.
type nexusTokenCache struct {
	mu      sync.Mutex
	token   string
	expires time.Time
}

var nexusTokens = &nexusTokenCache{}

// Safety net when the JWT expiry cannot be parsed: strictly less than the
// default 5-minute "JWT Session Expiry" configured on the firewall.
const nexusFallbackTokenTTL = 4 * time.Minute

// =========================================================================
//  Interface Implementation
// =========================================================================

func init() {
	Register(&pfSenseNexusIntegration{})
}

func (p *pfSenseNexusIntegration) ID() string {
	return "pfsense-nexus"
}

// Nexus rejects alias names containing anything but alpha-numeric characters
// and underscores ("name must only contain alpha-numeric and underscore
// characters") — stricter than the pfSense REST API package, so the Nexus
// integration validates this early with a clear error instead of failing on
// the firewall mid-block.
var nexusSafeAlias = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func (p *pfSenseNexusIntegration) Validate(cfg config.AdvancedActionsConfig) error {
	if err := ValidateOutboundURL(cfg.PfSenseNexus.BaseURL, "pfSense Nexus base URL"); err != nil {
		return err
	}
	if cfg.PfSenseNexus.Username == "" {
		return fmt.Errorf("pfSense Nexus username is required")
	}
	if cfg.PfSenseNexus.Password == "" {
		return fmt.Errorf("pfSense Nexus password is required")
	}
	if err := ValidateIdentifier(cfg.PfSenseNexus.Alias, "pfSense Nexus alias"); err != nil {
		return err
	}
	if !nexusSafeAlias.MatchString(cfg.PfSenseNexus.Alias) {
		return fmt.Errorf("pfSense Nexus alias %q is invalid: the Netgate Nexus API only accepts alpha-numeric characters and underscores in alias names", cfg.PfSenseNexus.Alias)
	}
	return nil
}

// =========================================================================
//  Block/Unblock
// =========================================================================

func (p *pfSenseNexusIntegration) BlockIP(req Request) error {
	if err := p.Validate(req.Config); err != nil {
		return err
	}
	if err := shared.ValidateIP(req.IP); err != nil {
		return fmt.Errorf("pfsense-nexus block: %w", err)
	}
	return p.modifyAliasIP(req, req.IP, "Fail2ban-UI permanent block", true)
}

func (p *pfSenseNexusIntegration) UnblockIP(req Request) error {
	if err := p.Validate(req.Config); err != nil {
		return err
	}
	if err := shared.ValidateIP(req.IP); err != nil {
		return fmt.Errorf("pfsense-nexus unblock: %w", err)
	}
	return p.modifyAliasIP(req, req.IP, "", false)
}

// =========================================================================
//  Netgate Nexus API
// =========================================================================

func (p *pfSenseNexusIntegration) modifyAliasIP(req Request, ip, description string, add bool) error {
	cfg := req.Config.PfSenseNexus
	if err := ValidateOutboundURL(cfg.BaseURL, "pfSense Nexus base URL"); err != nil {
		return err
	}
	baseURL := strings.TrimSuffix(cfg.BaseURL, "/")

	httpClient := httpx.Client(10*time.Second, cfg.SkipTLSVerify)

	alias, err := p.getAliasByName(httpClient, baseURL, cfg, req.Logger)
	if err != nil {
		// If the alias doesn't exist, create it automatically.
		if strings.Contains(err.Error(), "not found") {
			if req.Logger != nil {
				req.Logger("Alias %s not found, creating it automatically", cfg.Alias)
			}
			created, createErr := p.createAlias(httpClient, baseURL, cfg, req.Logger)
			if createErr != nil {
				return fmt.Errorf("failed to create alias %s: %w", cfg.Alias, createErr)
			}
			alias = created
		} else {
			return fmt.Errorf("failed to get alias %s: %w", cfg.Alias, err)
		}
	}

	if alias.Truncated {
		return fmt.Errorf("alias %s reports truncated values (maxvalues limit); refusing to modify it to avoid data loss. Increase 'maxvalues' or clean up the alias first", cfg.Alias)
	}

	if add {
		for _, tgt := range alias.Targets {
			if tgt.Name == ip {
				if req.Logger != nil {
					req.Logger("IP %s already exists in alias %s", ip, cfg.Alias)
				}
				return nil
			}
		}
		alias.Targets = append(alias.Targets, nexusTarget{Name: ip, Descr: description})
	} else {
		found := false
		targets := make([]nexusTarget, 0, len(alias.Targets))
		for _, tgt := range alias.Targets {
			if tgt.Name == ip {
				found = true
				continue
			}
			targets = append(targets, tgt)
		}
		if !found {
			if req.Logger != nil {
				req.Logger("IP %s not found in alias %s", ip, cfg.Alias)
			}
			return nil
		}
		alias.Targets = targets
	}

	if err := p.updateAlias(httpClient, baseURL, cfg, alias, req.Logger); err != nil {
		return fmt.Errorf("failed to update alias %s: %w", cfg.Alias, err)
	}

	if err := p.applyFirewallChanges(httpClient, baseURL, cfg, req.Logger); err != nil {
		if req.Logger != nil {
			req.Logger("Warning: failed to apply firewall changes: %v", err)
		}
	}

	if req.Logger != nil {
		action := "added to"
		if !add {
			action = "removed from"
		}
		req.Logger("IP %s successfully %s alias %s", ip, action, cfg.Alias)
	}

	return nil
}

// nexusCreds holds one request-scoped credential bundle.
type nexusCreds struct {
	baseURL  string
	username string
	password string
}

// doAuthed performs an authenticated request against the Nexus API, logging
// in first if needed. On a 401 response the cached token is dropped, a fresh
// login is performed once and the request is retried.
func (p *pfSenseNexusIntegration) doAuthed(client *http.Client, creds nexusCreds, method, path string, body []byte, logger func(string, ...interface{})) ([]byte, error) {
	send := func(token string) (*http.Response, []byte, error) {
		httpReq, err := http.NewRequest(method, creds.baseURL+path, bytes.NewReader(body))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create Nexus request: %w", err)
		}
		httpReq.Header.Set("Accept", "application/json")
		if body != nil {
			httpReq.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			httpReq.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(httpReq)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		bodyBytes, readErr := httpx.ReadLimited(resp.Body)
		if readErr != nil {
			return resp, nil, fmt.Errorf("failed to read Nexus response: %w", readErr)
		}
		return resp, bodyBytes, nil
	}

	token := nexusTokens.get()
	var err error
	if token == "" {
		// No cached token (first call of this operation or expired): log in
		// proactively instead of sending a request that is doomed to 401.
		if token, err = p.login(client, creds, logger); err != nil {
			return nil, err
		}
	}
	resp, bodyBytes, err := send(token)
	if err != nil {
		if netErr, ok := err.(interface {
			Timeout() bool
			Error() string
		}); ok && netErr.Timeout() {
			return nil, fmt.Errorf("Nexus API request %s %s timed out: %w", method, path, err)
		}
		return nil, fmt.Errorf("Nexus API request %s %s failed: %w", method, path, err)
	}

	// Missing, expired or revoked token: re-login once and retry.
	if resp.StatusCode == http.StatusUnauthorized {
		if logger != nil {
			logger("Nexus API returned 401 for %s %s, performing fresh login", method, path)
		}
		nexusTokens.invalidate()
		if token, err = p.login(client, creds, logger); err != nil {
			return nil, err
		}
		resp, bodyBytes, err = send(token)
		if err != nil {
			if netErr, ok := err.(interface {
				Timeout() bool
				Error() string
			}); ok && netErr.Timeout() {
				return nil, fmt.Errorf("Nexus API request %s %s timed out after re-login: %w", method, path, err)
			}
			return nil, fmt.Errorf("Nexus API request %s %s failed after re-login: %w", method, path, err)
		}
	}

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Nexus API %s %s failed: status %s, response: %s", method, path, resp.Status, strings.TrimSpace(string(bodyBytes)))
	}
	return bodyBytes, nil
}

// login authenticates against POST /login with base64-encoded credentials
// (the encoding Nexus expects) and caches the returned JWT.
func (p *pfSenseNexusIntegration) login(client *http.Client, creds nexusCreds, logger func(string, ...interface{})) (string, error) {
	payload, err := json.Marshal(map[string]string{
		"username": base64.StdEncoding.EncodeToString([]byte(creds.username)),
		"password": base64.StdEncoding.EncodeToString([]byte(creds.password)),
	})
	if err != nil {
		return "", fmt.Errorf("failed to encode Nexus login payload: %w", err)
	}

	if logger != nil {
		logger("Calling Nexus API POST %s/login", creds.baseURL)
	}

	httpReq, err := http.NewRequest(http.MethodPost, creds.baseURL+"/login", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create Nexus login request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		if netErr, ok := err.(interface {
			Timeout() bool
			Error() string
		}); ok && netErr.Timeout() {
			return "", fmt.Errorf("Nexus login request to %s/login timed out: %w", creds.baseURL, err)
		}
		return "", fmt.Errorf("Nexus login request to %s/login failed: %w (check base URL, network connectivity and credentials)", creds.baseURL, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := httpx.ReadLimited(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("Nexus login failed: status %s, response: %s (check pfSense Nexus username/password and that the user belongs to a group with modify capability)", resp.Status, strings.TrimSpace(string(bodyBytes)))
	}

	var loginResp nexusLoginResponse
	if err := json.Unmarshal(bodyBytes, &loginResp); err != nil || loginResp.Token == "" {
		return "", fmt.Errorf("failed to decode Nexus login response: %w", err)
	}

	nexusTokens.set(loginResp.Token)
	if logger != nil {
		logger("Nexus login succeeded")
	}
	return loginResp.Token, nil
}

// getAliasByName lists all aliases (system aliases excluded) and returns the
// one matching the configured name, case-insensitive.
func (p *pfSenseNexusIntegration) getAliasByName(client *http.Client, baseURL string, cfg config.PfSenseNexusIntegrationSettings, logger func(string, ...interface{})) (*nexusAlias, error) {
	creds := nexusCreds{baseURL: baseURL, username: cfg.Username, password: cfg.Password}

	// maxvalues defaults to 5 entries per alias server-side; request a high
	// limit so large aliases (typical fail2ban block lists) are not silently
	// truncated.
	body, err := p.doAuthed(client, creds, http.MethodGet, "/aliases?maxvalues=100000", nil, logger)
	if err != nil {
		return nil, err
	}

	var listResp nexusAliasesResponse
	if err := json.Unmarshal(body, &listResp); err != nil {
		return nil, fmt.Errorf("failed to decode Nexus aliases response: %w", err)
	}

	for i := range listResp.Aliases {
		if strings.EqualFold(listResp.Aliases[i].Name, cfg.Alias) {
			return &listResp.Aliases[i], nil
		}
	}

	return nil, fmt.Errorf("alias %s not found", cfg.Alias)
}

// createAlias creates the managed alias as a host alias via PUT /aliases
// (Nexus deliberately has no POST /aliases collection endpoint).
func (p *pfSenseNexusIntegration) createAlias(client *http.Client, baseURL string, cfg config.PfSenseNexusIntegrationSettings, logger func(string, ...interface{})) (*nexusAlias, error) {
	creds := nexusCreds{baseURL: baseURL, username: cfg.Username, password: cfg.Password}

	payload, err := json.Marshal(nexusAlias{
		Name:    cfg.Alias,
		Type:    "host",
		Descr:   "Fail2ban-UI alias",
		Targets: []nexusTarget{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode Nexus alias creation payload: %w", err)
	}

	if _, err := p.doAuthed(client, creds, http.MethodPut, "/aliases", payload, logger); err != nil {
		return nil, err
	}

	if logger != nil {
		logger("Nexus API PUT /aliases succeeded: alias %s created", cfg.Alias)
	}
	return &nexusAlias{Name: cfg.Alias, Type: "host", Descr: "Fail2ban-UI alias"}, nil
}

// updateAlias persists the new target list via POST /aliases/{name}
// ({id} path parameter is the alias name in Nexus).
func (p *pfSenseNexusIntegration) updateAlias(client *http.Client, baseURL string, cfg config.PfSenseNexusIntegrationSettings, alias *nexusAlias, logger func(string, ...interface{})) error {
	creds := nexusCreds{baseURL: baseURL, username: cfg.Username, password: cfg.Password}

	if alias.Targets == nil {
		alias.Targets = []nexusTarget{}
	}

	payload, err := json.Marshal(nexusAlias{
		Name:    alias.Name,
		Type:    alias.Type,
		Descr:   alias.Descr,
		Targets: alias.Targets,
	})
	if err != nil {
		return fmt.Errorf("failed to encode Nexus alias update payload: %w", err)
	}

	path := "/aliases/" + url.PathEscape(alias.Name)
	if _, err := p.doAuthed(client, creds, http.MethodPost, path, payload, logger); err != nil {
		return err
	}

	if logger != nil {
		logger("Nexus API POST %s succeeded", path)
	}
	return nil
}

// applyFirewallChanges triggers a filter reload so the alias table is
// rebuilt and running rules pick up the new values.
func (p *pfSenseNexusIntegration) applyFirewallChanges(client *http.Client, baseURL string, cfg config.PfSenseNexusIntegrationSettings, logger func(string, ...interface{})) error {
	creds := nexusCreds{baseURL: baseURL, username: cfg.Username, password: cfg.Password}

	body, err := p.doAuthed(client, creds, http.MethodPost, "/system/filterreload/reload", []byte("{}"), logger)
	if err != nil {
		return err
	}

	if logger != nil {
		logger("Nexus API filter reload triggered: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

// =========================================================================
//  Token cache
// =========================================================================

func (c *nexusTokenCache) get() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" || time.Now().After(c.expires) {
		return ""
	}
	return c.token
}

func (c *nexusTokenCache) set(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
	c.expires = time.Now().Add(nexusTokenTTL(token))
}

func (c *nexusTokenCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = ""
	c.expires = time.Time{}
}

// nexusTokenTTL derives the cache lifetime from the JWT exp claim; falls
// back to a conservative constant when the payload cannot be parsed.
func nexusTokenTTL(token string) time.Duration {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nexusFallbackTokenTTL
	}
	// JWT payloads use unpadded base64url encoding.
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some implementations pad; retry with standard padding handling.
		if padded, padErr := base64.URLEncoding.DecodeString(parts[1]); padErr == nil {
			raw = padded
		} else {
			return nexusFallbackTokenTTL
		}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Exp <= 0 {
		return nexusFallbackTokenTTL
	}
	ttl := time.Until(time.Unix(claims.Exp, 0))
	if ttl <= 0 {
		return 0
	}
	// Refresh slightly early to avoid using a token that expires mid-flight.
	if ttl > 15*time.Second {
		ttl -= 15 * time.Second
	}
	return ttl
}
