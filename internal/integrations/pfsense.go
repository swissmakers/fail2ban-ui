package integrations

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

type pfSenseIntegration struct{}

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
	if cfg.PfSense.APIToken == "" || cfg.PfSense.APISecret == "" {
		return fmt.Errorf("pfSense API token and secret are required")
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
	payload := map[string]any{
		"alias": req.Config.PfSense.Alias,
		"ip":    req.IP,
		"descr": "Fail2ban-UI permanent block",
	}
	return p.callAPI(req, "add", payload)
}

func (p *pfSenseIntegration) UnblockIP(req Request) error {
	if err := p.Validate(req.Config); err != nil {
		return err
	}
	payload := map[string]any{
		"alias": req.Config.PfSense.Alias,
		"ip":    req.IP,
	}
	return p.callAPI(req, "delete", payload)
}

func (p *pfSenseIntegration) callAPI(req Request, action string, payload map[string]any) error {
	cfg := req.Config.PfSense
	payload["action"] = action

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode pfSense payload: %w", err)
	}

	apiURL := strings.TrimSuffix(cfg.BaseURL, "/") + "/api/v2/firewall/alias/ip"

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	if cfg.SkipTLSVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 - user controlled
		}
	}

	reqLogger := "pfSense"
	if req.Logger != nil {
		req.Logger("Calling pfSense API %s action=%s payload=%s", apiURL, action, string(data))
	}

	httpReq, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create pfSense request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-API-Key", cfg.APIToken)
	httpReq.Header.Set("X-API-Secret", cfg.APISecret)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("pfSense request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("pfSense request failed: status %s", resp.Status)
	}

	if req.Logger != nil {
		req.Logger("%s API call succeeded", reqLogger)
	}
	return nil
}
