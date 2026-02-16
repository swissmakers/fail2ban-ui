package integrations

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

type opnsenseIntegration struct{}

func init() {
	Register(&opnsenseIntegration{})
}

// =========================================================================
//  Interface Implementation
// =========================================================================

func (o *opnsenseIntegration) ID() string {
	return "opnsense"
}

func (o *opnsenseIntegration) DisplayName() string {
	return "OPNsense"
}

func (o *opnsenseIntegration) Validate(cfg config.AdvancedActionsConfig) error {
	if cfg.OPNsense.BaseURL == "" {
		return fmt.Errorf("OPNsense base URL is required")
	}
	if cfg.OPNsense.APIKey == "" || cfg.OPNsense.APISecret == "" {
		return fmt.Errorf("OPNsense API key and secret are required")
	}
	if cfg.OPNsense.Alias == "" {
		return fmt.Errorf("OPNsense alias is required")
	}
	return nil
}

// =========================================================================
//  Block/Unblock
// =========================================================================

func (o *opnsenseIntegration) BlockIP(req Request) error {
	if err := o.Validate(req.Config); err != nil {
		return err
	}
	return o.callAPI(req, "add", req.IP)
}

func (o *opnsenseIntegration) UnblockIP(req Request) error {
	if err := o.Validate(req.Config); err != nil {
		return err
	}
	return o.callAPI(req, "delete", req.IP)
}

// =========================================================================
//  OPNsense API
// =========================================================================

func (o *opnsenseIntegration) callAPI(req Request, action, ip string) error {
	cfg := req.Config.OPNsense
	apiURL := strings.TrimSuffix(cfg.BaseURL, "/") + fmt.Sprintf("/api/firewall/alias_util/%s/%s", action, cfg.Alias)
	payload := map[string]string{
		"address": ip,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode OPNsense payload: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	if cfg.SkipTLSVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 - user controlled
		}
	}

	reqLogger := "OPNsense"
	if req.Logger != nil {
		req.Logger("Calling OPNsense API %s action=%s payload=%s", apiURL, action, string(data))
	}

	httpReq, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create OPNsense request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	auth := base64.StdEncoding.EncodeToString([]byte(cfg.APIKey + ":" + cfg.APISecret))
	httpReq.Header.Set("Authorization", "Basic "+auth)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		// Provide more specific error messages for connection issues
		if netErr, ok := err.(interface {
			Timeout() bool
			Error() string
		}); ok && netErr.Timeout() {
			return fmt.Errorf("OPNsense API request to %s timed out: %w", apiURL, err)
		}
		return fmt.Errorf("OPNsense API request to %s failed: %w (check base URL, network connectivity, and API credentials)", apiURL, err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := strings.TrimSpace(string(bodyBytes))

	if resp.StatusCode >= 300 {
		if bodyStr != "" {
			return fmt.Errorf("OPNsense API request failed: status %s, response: %s", resp.Status, bodyStr)
		}
		return fmt.Errorf("OPNsense API request failed: status %s (check API credentials and alias name)", resp.Status)
	}

	if req.Logger != nil {
		req.Logger("%s API call succeeded", reqLogger)
		if bodyStr != "" {
			req.Logger("%s API response: %s", reqLogger, bodyStr)
		}
	}
	return nil
}
