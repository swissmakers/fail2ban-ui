package integrations

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

type pfSenseIntegration struct{}

// FirewallAliasResponse represents the response structure from pfSense API
type FirewallAliasResponse struct {
	Data FirewallAlias `json:"data"`
}

// FirewallAlias represents a firewall alias in pfSense
type FirewallAlias struct {
	ID      int      `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Descr   string   `json:"descr"`
	Address []string `json:"address"`
	Detail  []string `json:"detail"`
}

func init() {
	Register(&pfSenseIntegration{})
}

func (p *pfSenseIntegration) ID() string {
	return "pfsense"
}

func (p *pfSenseIntegration) DisplayName() string {
	return "pfSense"
}

func (p *pfSenseIntegration) Validate(cfg config.AdvancedActionsConfig) error {
	if cfg.PfSense.BaseURL == "" {
		return fmt.Errorf("pfSense base URL is required")
	}
	if cfg.PfSense.APIToken == "" {
		return fmt.Errorf("pfSense API key is required")
	}
	if cfg.PfSense.Alias == "" {
		return fmt.Errorf("pfSense alias is required")
	}
	return nil
}

func (p *pfSenseIntegration) BlockIP(req Request) error {
	if err := p.Validate(req.Config); err != nil {
		return err
	}
	return p.modifyAliasIP(req, req.IP, "Fail2ban-UI permanent block", true)
}

func (p *pfSenseIntegration) UnblockIP(req Request) error {
	if err := p.Validate(req.Config); err != nil {
		return err
	}
	return p.modifyAliasIP(req, req.IP, "", false)
}

// modifyAliasIP implements the GET-modify-PATCH pattern for pfSense alias management
func (p *pfSenseIntegration) modifyAliasIP(req Request, ip, description string, add bool) error {
	cfg := req.Config.PfSense
	baseURL := strings.TrimSuffix(cfg.BaseURL, "/")

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	if cfg.SkipTLSVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 - user controlled
		}
	}

	// GET the alias by name
	alias, err := p.getAliasByName(httpClient, baseURL, cfg.APIToken, cfg.Alias, req.Logger)
	if err != nil {
		return fmt.Errorf("failed to get alias %s: %w", cfg.Alias, err)
	}

	// Modify the address array
	if add {
		// Check if IP already exists
		ipExists := false
		for _, addr := range alias.Address {
			if addr == ip {
				ipExists = true
				break
			}
		}
		if !ipExists {
			alias.Address = append(alias.Address, ip)
			if description != "" {
				// Add description to detail array, matching the address array length
				alias.Detail = append(alias.Detail, description)
			}
		} else {
			if req.Logger != nil {
				req.Logger("IP %s already exists in alias %s", ip, cfg.Alias)
			}
			return nil // IP already blocked, consider it success
		}
	} else {
		// Remove IP from address array
		found := false
		newAddress := make([]string, 0, len(alias.Address))
		newDetail := make([]string, 0, len(alias.Detail))
		for i, addr := range alias.Address {
			if addr != ip {
				newAddress = append(newAddress, addr)
				// Keep corresponding detail if it exists
				if i < len(alias.Detail) {
					newDetail = append(newDetail, alias.Detail[i])
				}
			} else {
				found = true
			}
		}
		if !found {
			if req.Logger != nil {
				req.Logger("IP %s not found in alias %s", ip, cfg.Alias)
			}
			return nil // IP not in alias, consider it success
		}
		alias.Address = newAddress
		alias.Detail = newDetail
	}

	// PATCH the alias with updated configuration
	if err := p.updateAlias(httpClient, baseURL, cfg.APIToken, alias, req.Logger); err != nil {
		return fmt.Errorf("failed to update alias %s: %w", cfg.Alias, err)
	}

	// Apply firewall changes
	if err := p.applyFirewallChanges(httpClient, baseURL, cfg.APIToken, req.Logger); err != nil {
		// Log warning but don't fail - the alias was updated successfully
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

// getAliasByName retrieves a firewall alias by name using GET /api/v2/firewall/alias
func (p *pfSenseIntegration) getAliasByName(client *http.Client, baseURL, apiToken, aliasName string, logger func(string, ...interface{})) (*FirewallAlias, error) {
	apiURL := baseURL + "/api/v2/firewall/alias"

	// Add query parameter for alias name
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}
	q := u.Query()
	q.Set("name", aliasName)
	u.RawQuery = q.Encode()
	apiURL = u.String()

	if logger != nil {
		logger("Calling pfSense API GET %s", apiURL)
	}

	httpReq, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create pfSense GET request: %w", err)
	}
	httpReq.Header.Set("x-api-key", apiToken)

	resp, err := client.Do(httpReq)
	if err != nil {
		if netErr, ok := err.(interface {
			Timeout() bool
			Error() string
		}); ok && netErr.Timeout() {
			return nil, fmt.Errorf("pfSense API request to %s timed out: %w", apiURL, err)
		}
		return nil, fmt.Errorf("pfSense API request to %s failed: %w", apiURL, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := strings.TrimSpace(string(bodyBytes))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pfSense API GET failed: status %s, response: %s", resp.Status, bodyStr)
	}

	var aliasResp FirewallAliasResponse
	if err := json.Unmarshal(bodyBytes, &aliasResp); err != nil {
		return nil, fmt.Errorf("failed to decode pfSense alias response: %w", err)
	}

	return &aliasResp.Data, nil
}

// updateAlias updates a firewall alias using PATCH /api/v2/firewall/alias/{id}
func (p *pfSenseIntegration) updateAlias(client *http.Client, baseURL, apiToken string, alias *FirewallAlias, logger func(string, ...interface{})) error {
	apiURL := fmt.Sprintf("%s/api/v2/firewall/alias/%d", baseURL, alias.ID)

	// Prepare PATCH payload - only include fields that can be updated
	patchPayload := map[string]interface{}{
		"name":    alias.Name,
		"type":    alias.Type,
		"descr":   alias.Descr,
		"address": alias.Address,
	}
	if len(alias.Detail) > 0 {
		patchPayload["detail"] = alias.Detail
	}

	data, err := json.Marshal(patchPayload)
	if err != nil {
		return fmt.Errorf("failed to encode pfSense PATCH payload: %w", err)
	}

	if logger != nil {
		logger("Calling pfSense API PATCH %s payload=%s", apiURL, string(data))
	}

	httpReq, err := http.NewRequest(http.MethodPatch, apiURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create pfSense PATCH request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", apiToken)

	resp, err := client.Do(httpReq)
	if err != nil {
		if netErr, ok := err.(interface {
			Timeout() bool
			Error() string
		}); ok && netErr.Timeout() {
			return fmt.Errorf("pfSense API request to %s timed out: %w", apiURL, err)
		}
		return fmt.Errorf("pfSense API request to %s failed: %w", apiURL, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := strings.TrimSpace(string(bodyBytes))

	if resp.StatusCode >= 300 {
		return fmt.Errorf("pfSense API PATCH failed: status %s, response: %s", resp.Status, bodyStr)
	}

	if logger != nil {
		logger("pfSense API PATCH succeeded: %s", bodyStr)
	}

	return nil
}

// applyFirewallChanges applies firewall changes using POST /api/v2/firewall/apply
func (p *pfSenseIntegration) applyFirewallChanges(client *http.Client, baseURL, apiToken string, logger func(string, ...interface{})) error {
	apiURL := baseURL + "/api/v2/firewall/apply"

	if logger != nil {
		logger("Calling pfSense API POST %s to apply firewall changes", apiURL)
	}

	httpReq, err := http.NewRequest(http.MethodPost, apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create pfSense apply request: %w", err)
	}
	httpReq.Header.Set("x-api-key", apiToken)

	resp, err := client.Do(httpReq)
	if err != nil {
		if netErr, ok := err.(interface {
			Timeout() bool
			Error() string
		}); ok && netErr.Timeout() {
			return fmt.Errorf("pfSense API request to %s timed out: %w", apiURL, err)
		}
		return fmt.Errorf("pfSense API request to %s failed: %w", apiURL, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := strings.TrimSpace(string(bodyBytes))

	if resp.StatusCode >= 300 {
		return fmt.Errorf("pfSense API apply failed: status %s, response: %s", resp.Status, bodyStr)
	}

	if logger != nil {
		logger("pfSense API apply succeeded: %s", bodyStr)
	}

	return nil
}
