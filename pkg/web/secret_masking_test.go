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

package web

import (
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

func TestMaskAppSettingsSecrets(t *testing.T) {
	s := config.AppSettings{CallbackSecret: "topsecret"}
	s.SMTP.Password = "pw"
	s.Webhook.Headers = map[string]string{"Authorization": "Bearer xyz"}
	s.Servers = []config.Fail2banServer{{ID: "a", Type: "agent", AgentSecret: "agent-tok"}}

	masked := maskAppSettingsSecrets(s)

	if masked.CallbackSecret != secretMaskSentinel {
		t.Errorf("callback secret not masked: %q", masked.CallbackSecret)
	}
	if masked.SMTP.Password != secretMaskSentinel {
		t.Errorf("smtp password not masked: %q", masked.SMTP.Password)
	}
	if masked.Webhook.Headers["Authorization"] != secretMaskSentinel {
		t.Errorf("webhook header not masked: %q", masked.Webhook.Headers["Authorization"])
	}
	if masked.Servers[0].AgentSecret != secretMaskSentinel {
		t.Errorf("embedded server agent secret not masked: %q", masked.Servers[0].AgentSecret)
	}
	// Masking must not mutate the original (value fields or the embedded slice).
	if s.CallbackSecret != "topsecret" {
		t.Errorf("original mutated: %q", s.CallbackSecret)
	}
	if s.Servers[0].AgentSecret != "agent-tok" {
		t.Errorf("original server slice mutated (aliasing): %q", s.Servers[0].AgentSecret)
	}
}

func TestRestoreMaskedServerSecrets(t *testing.T) {
	stored := config.AppSettings{
		Servers: []config.Fail2banServer{{ID: "a", AgentSecret: "stored-tok"}},
	}
	req := config.AppSettings{
		Servers: []config.Fail2banServer{{ID: "a", AgentSecret: secretMaskSentinel}},
	}
	restoreMaskedSecrets(&req, stored)
	if req.Servers[0].AgentSecret != "stored-tok" {
		t.Errorf("unchanged server secret should be restored, got %q", req.Servers[0].AgentSecret)
	}
}

func TestMaskEmptySecretStaysEmpty(t *testing.T) {
	masked := maskAppSettingsSecrets(config.AppSettings{})
	if masked.CallbackSecret != "" {
		t.Errorf("empty secret should stay empty, got %q", masked.CallbackSecret)
	}
}

func TestRestoreMaskedSecrets(t *testing.T) {
	stored := config.AppSettings{CallbackSecret: "stored-secret"}
	stored.SMTP.Password = "stored-pw"
	stored.Webhook.Headers = map[string]string{"Authorization": "Bearer stored"}

	// Client leaves callback secret unchanged (sentinel) but rotates SMTP password.
	req := config.AppSettings{CallbackSecret: secretMaskSentinel}
	req.SMTP.Password = "new-pw"
	req.Webhook.Headers = map[string]string{"Authorization": secretMaskSentinel}

	restoreMaskedSecrets(&req, stored)

	if req.CallbackSecret != "stored-secret" {
		t.Errorf("unchanged secret should be restored, got %q", req.CallbackSecret)
	}
	if req.SMTP.Password != "new-pw" {
		t.Errorf("changed secret should be kept, got %q", req.SMTP.Password)
	}
	if req.Webhook.Headers["Authorization"] != "Bearer stored" {
		t.Errorf("unchanged header should be restored, got %q", req.Webhook.Headers["Authorization"])
	}
}

func settingsWithAllSecrets() (config.AppSettings, map[string]func(*config.AppSettings) *string) {
	var s config.AppSettings
	fields := map[string]func(*config.AppSettings) *string{
		"CallbackSecret":         func(s *config.AppSettings) *string { return &s.CallbackSecret },
		"SMTP.Password":          func(s *config.AppSettings) *string { return &s.SMTP.Password },
		"ThreatIntel.AlienVault": func(s *config.AppSettings) *string { return &s.ThreatIntel.AlienVaultAPIKey },
		"ThreatIntel.AbuseIPDB":  func(s *config.AppSettings) *string { return &s.ThreatIntel.AbuseIPDBAPIKey },
		"Elasticsearch.APIKey":   func(s *config.AppSettings) *string { return &s.Elasticsearch.APIKey },
		"Elasticsearch.Password": func(s *config.AppSettings) *string { return &s.Elasticsearch.Password },
		"Mikrotik.Password":      func(s *config.AppSettings) *string { return &s.AdvancedActions.Mikrotik.Password },
		"PfSense.APIToken":       func(s *config.AppSettings) *string { return &s.AdvancedActions.PfSense.APIToken },
		"PfSense.APISecret":      func(s *config.AppSettings) *string { return &s.AdvancedActions.PfSense.APISecret },
		"OPNsense.APIKey":        func(s *config.AppSettings) *string { return &s.AdvancedActions.OPNsense.APIKey },
		"OPNsense.APISecret":     func(s *config.AppSettings) *string { return &s.AdvancedActions.OPNsense.APISecret },
	}
	for name, get := range fields {
		*get(&s) = "secret-" + name
	}
	return s, fields
}

func TestMaskAndRestoreCoverAllSecretFields(t *testing.T) {
	stored, fields := settingsWithAllSecrets()

	masked := maskAppSettingsSecrets(stored)
	for name, get := range fields {
		if got := *get(&masked); got != secretMaskSentinel {
			t.Errorf("%s not masked: %q", name, got)
		}
	}

	req := masked
	restoreMaskedSecrets(&req, stored)
	for name, get := range fields {
		want := *get(&stored)
		if got := *get(&req); got != want {
			t.Errorf("%s not restored: got %q, want %q", name, got, want)
		}
	}
}

func TestMaskServer(t *testing.T) {
	server := config.Fail2banServer{ID: "a", Type: "agent", AgentSecret: "agent-tok"}
	masked := maskServer(server)
	if masked.AgentSecret != secretMaskSentinel {
		t.Errorf("agent secret not masked: %q", masked.AgentSecret)
	}
	if server.AgentSecret != "agent-tok" {
		t.Errorf("original mutated: %q", server.AgentSecret)
	}
	if empty := maskServer(config.Fail2banServer{ID: "b"}); empty.AgentSecret != "" {
		t.Errorf("empty secret should stay empty, got %q", empty.AgentSecret)
	}
}
