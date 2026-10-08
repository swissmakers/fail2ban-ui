// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Normalization and validation of settings submitted through the UI.
// Primitive validators (host, path, port, IP) live in internal/shared;
// everything here operates on config.* structs and web-layer policy.

package web

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/integrations"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

var fail2banDurationPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?( ?[0-9]*[smhdwy][a-z]*)*$`)
var fail2banNumberPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
var headerValueSanitizer = strings.NewReplacer("\r", "", "\n", "", "\x00", "")
var headerNameRe = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")

func sanitizeHeaderValue(s string) string {
	return headerValueSanitizer.Replace(s)
}

func normalizeWebhookMethod(method string) (string, bool) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "POST"
	}
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
		return method, true
	default:
		return method, false
	}
}

func validateFail2banDurationField(name, value string) error {
	if value == "" {
		return nil
	}
	if !fail2banDurationPattern.MatchString(value) {
		return fmt.Errorf("%s has an invalid time format: %q (examples: 3600, 48h, 5w)", name, value)
	}
	return nil
}

func normalizeAndValidateSettingsRequest(req *config.AppSettings) error {
	req.CallbackURL = strings.TrimRight(strings.TrimSpace(req.CallbackURL), "/")
	if req.CallbackURL != "" {
		if err := shared.ValidateCallbackURL(req.CallbackURL); err != nil {
			return err
		}
	}
	req.CallbackSecret = strings.TrimSpace(req.CallbackSecret)
	if err := shared.ValidateCallbackSecret(req.CallbackSecret); err != nil {
		return err
	}
	req.Bantime = strings.ToLower(strings.TrimSpace(req.Bantime))
	req.Findtime = strings.ToLower(strings.TrimSpace(req.Findtime))
	req.BantimeRndtime = strings.ToLower(strings.TrimSpace(req.BantimeRndtime))
	req.BantimeMaxtime = strings.ToLower(strings.TrimSpace(req.BantimeMaxtime))
	req.BantimeFactor = strings.TrimSpace(req.BantimeFactor)
	bantimeMagnitude := strings.TrimPrefix(req.Bantime, "-")
	if req.Bantime != "" && bantimeMagnitude == "" {
		return fmt.Errorf("bantime has an invalid time format: %q (examples: 3600, 48h, -1)", req.Bantime)
	}
	if err := validateFail2banDurationField("bantime", bantimeMagnitude); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"findtime":        req.Findtime,
		"bantime.rndtime": req.BantimeRndtime,
		"bantime.maxtime": req.BantimeMaxtime,
	} {
		if err := validateFail2banDurationField(name, value); err != nil {
			return err
		}
	}
	if req.BantimeFactor != "" && !fail2banNumberPattern.MatchString(req.BantimeFactor) {
		return fmt.Errorf("bantime.factor must be a number, got %q", req.BantimeFactor)
	}

	if err := normalizeJailDefaults(req); err != nil {
		return err
	}

	req.AlertProvider = strings.ToLower(strings.TrimSpace(req.AlertProvider))
	if req.AlertProvider == "" {
		req.AlertProvider = "email"
	}
	switch req.AlertProvider {
	case "email", "webhook", "elasticsearch":
	default:
		return errors.New("alert provider must be email, webhook or elasticsearch")
	}

	req.ThreatIntel.Provider = strings.ToLower(strings.TrimSpace(req.ThreatIntel.Provider))
	switch req.ThreatIntel.Provider {
	case "", "none":
		req.ThreatIntel.Provider = "none"
	case "alienvault":
		if strings.TrimSpace(req.ThreatIntel.AlienVaultAPIKey) == "" {
			return errors.New("AlienVault API key is required")
		}
	case "abuseipdb":
		if strings.TrimSpace(req.ThreatIntel.AbuseIPDBAPIKey) == "" {
			return errors.New("AbuseIPDB API key is required")
		}
	default:
		return errors.New("threat intelligence provider must be none, alienvault or abuseipdb")
	}

	req.Webhook.URL = strings.TrimSpace(req.Webhook.URL)
	req.Elasticsearch.URL = strings.TrimSpace(req.Elasticsearch.URL)
	req.Elasticsearch.APIKey = strings.TrimSpace(req.Elasticsearch.APIKey)
	req.Elasticsearch.Username = strings.TrimSpace(req.Elasticsearch.Username)
	req.Elasticsearch.Password = strings.TrimSpace(req.Elasticsearch.Password)
	req.Elasticsearch.Index = config.ElasticsearchDataStream(req.Elasticsearch.Index)

	method, ok := normalizeWebhookMethod(req.Webhook.Method)
	if !ok {
		return fmt.Errorf("webhook method must be one of GET, POST, PUT, PATCH, DELETE")
	}
	req.Webhook.Method = method
	if len(req.Webhook.Headers) > 0 {
		cleaned := make(map[string]string, len(req.Webhook.Headers))
		for k, v := range req.Webhook.Headers {
			key := strings.TrimSpace(k)
			if key == "" {
				continue
			}
			if !headerNameRe.MatchString(key) {
				return fmt.Errorf("invalid webhook header name %q", key)
			}
			cleaned[key] = sanitizeHeaderValue(v)
		}
		req.Webhook.Headers = cleaned
	}

	if req.AlertProvider == "webhook" && req.Webhook.URL == "" {
		return errors.New("webhook URL is required when alert provider is webhook")
	}
	if req.Webhook.URL != "" {
		if err := integrations.ValidateOutboundURL(req.Webhook.URL, "webhook URL"); err != nil {
			return err
		}
	}
	if req.AlertProvider == "elasticsearch" {
		if req.Elasticsearch.URL == "" {
			return errors.New("elasticsearch URL is required when alert provider is elasticsearch")
		}
		if req.Elasticsearch.APIKey == "" && (req.Elasticsearch.Username == "" || req.Elasticsearch.Password == "") {
			return errors.New("elasticsearch authentication requires API key or username/password")
		}
	}
	if req.Elasticsearch.URL != "" {
		if err := integrations.ValidateOutboundURL(req.Elasticsearch.URL, "elasticsearch URL"); err != nil {
			return err
		}
	}
	if err := integrations.ValidateElasticsearchDataStream(req.Elasticsearch.Index); err != nil {
		return err
	}

	return validateAdvancedActionsSettings(&req.AdvancedActions)
}

// Trims and validates the values written into every server's jail.local [DEFAULT] section
func normalizeJailDefaults(req *config.AppSettings) error {
	ignore := make([]string, 0, len(req.IgnoreIPs))
	for _, entry := range req.IgnoreIPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if err := shared.ValidateIgnoreIPEntry(entry); err != nil {
			return withKey(err, "settings.errors.invalid_ignoreip")
		}
		ignore = append(ignore, entry)
	}
	req.IgnoreIPs = ignore
	req.Banaction = strings.TrimSpace(req.Banaction)
	req.BanactionAllports = strings.TrimSpace(req.BanactionAllports)
	for _, name := range []string{req.Banaction, req.BanactionAllports} {
		if name == "" {
			continue
		}
		if err := shared.ValidateBanactionName(name); err != nil {
			return withKey(err, "settings.errors.invalid_banaction")
		}
	}
	req.Chain = strings.TrimSpace(req.Chain)
	if req.Chain != "" {
		if err := shared.ValidateChainName(req.Chain); err != nil {
			return withKey(err, "settings.errors.invalid_chain")
		}
	}
	return nil
}

func validateAdvancedActionsSettings(cfg *config.AdvancedActionsConfig) error {
	cfg.PfSense.BaseURL = strings.TrimSpace(cfg.PfSense.BaseURL)
	cfg.PfSense.Alias = strings.TrimSpace(cfg.PfSense.Alias)
	cfg.OPNsense.BaseURL = strings.TrimSpace(cfg.OPNsense.BaseURL)
	cfg.OPNsense.Alias = strings.TrimSpace(cfg.OPNsense.Alias)
	cfg.UniFi.BaseURL = strings.TrimSpace(cfg.UniFi.BaseURL)
	cfg.UniFi.SiteName = strings.TrimSpace(cfg.UniFi.SiteName)
	cfg.UniFi.TrafficListName = strings.TrimSpace(cfg.UniFi.TrafficListName)
	cfg.Mikrotik.Host = strings.TrimSpace(cfg.Mikrotik.Host)
	cfg.Mikrotik.AddressList = strings.TrimSpace(cfg.Mikrotik.AddressList)
	cfg.Mikrotik.SSHKeyPath = strings.TrimSpace(cfg.Mikrotik.SSHKeyPath)
	if cfg.Mikrotik.SSHKeyPath != "" {
		cfg.Mikrotik.SSHKeyPath = filepath.Clean(cfg.Mikrotik.SSHKeyPath)
	}

	if cfg.PfSense.BaseURL != "" {
		if err := integrations.ValidateOutboundURL(cfg.PfSense.BaseURL, "pfSense base URL"); err != nil {
			return err
		}
	}
	if cfg.PfSense.Alias != "" {
		if err := integrations.ValidateIdentifier(cfg.PfSense.Alias, "pfSense alias"); err != nil {
			return err
		}
	}
	if cfg.OPNsense.BaseURL != "" {
		if err := integrations.ValidateOutboundURL(cfg.OPNsense.BaseURL, "OPNsense base URL"); err != nil {
			return err
		}
	}
	if cfg.OPNsense.Alias != "" {
		if err := integrations.ValidateIdentifier(cfg.OPNsense.Alias, "OPNsense alias"); err != nil {
			return err
		}
	}
	if cfg.UniFi.BaseURL != "" {
		if err := integrations.ValidateOutboundURL(cfg.UniFi.BaseURL, "UniFi base URL"); err != nil {
			return err
		}
	}
	if cfg.UniFi.SiteName != "" {
		if err := integrations.ValidateIdentifier(cfg.UniFi.SiteName, "UniFi site name"); err != nil {
			return err
		}
	}
	if cfg.UniFi.TrafficListName != "" {
		if err := integrations.ValidateIdentifier(cfg.UniFi.TrafficListName, "UniFi traffic matching list name"); err != nil {
			return err
		}
	}
	if cfg.Mikrotik.Host != "" {
		if err := shared.ValidateHost(cfg.Mikrotik.Host); err != nil {
			return fmt.Errorf("mikrotik host: %w", err)
		}
	}
	if cfg.Mikrotik.AddressList != "" {
		if err := integrations.ValidateIdentifier(cfg.Mikrotik.AddressList, "mikrotik address list"); err != nil {
			return err
		}
	}
	if err := shared.ValidateAbsolutePath(cfg.Mikrotik.SSHKeyPath, "mikrotik sshKeyPath"); err != nil {
		return err
	}
	if err := shared.ValidatePort(cfg.Mikrotik.Port); err != nil {
		return fmt.Errorf("mikrotik port: %w", err)
	}
	return nil
}
