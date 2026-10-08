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

package web

import (
	"slices"
	"strings"
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

func TestNormalizeSettingsWebhookMethod(t *testing.T) {
	for _, method := range []string{"", "   ", "post", " Put "} {
		req := config.AppSettings{Webhook: config.WebhookSettings{Method: method}}
		if err := normalizeAndValidateSettingsRequest(&req); err != nil {
			t.Errorf("method %q should be accepted: %v", method, err)
			continue
		}
		switch req.Webhook.Method {
		case "GET", "POST", "PUT", "PATCH", "DELETE":
		default:
			t.Errorf("method %q normalized to unexpected %q", method, req.Webhook.Method)
		}
	}

	req := config.AppSettings{Webhook: config.WebhookSettings{Method: "TRACE"}}
	if err := normalizeAndValidateSettingsRequest(&req); err == nil {
		t.Error("disallowed method TRACE must be rejected")
	}
}

func TestNormalizeSettingsWebhookHeaders(t *testing.T) {
	req := config.AppSettings{Webhook: config.WebhookSettings{
		Headers: map[string]string{"X-Token": "abc\r\nInjected: 1\x00"},
	}}
	if err := normalizeAndValidateSettingsRequest(&req); err != nil {
		t.Fatalf("valid header should be accepted: %v", err)
	}
	if got := req.Webhook.Headers["X-Token"]; got != "abcInjected: 1" {
		t.Errorf("header value not sanitized, got %q", got)
	}

	for _, name := range []string{"Foo:Bar", "X Bad", "Ä-Umlaut"} {
		req := config.AppSettings{Webhook: config.WebhookSettings{
			Headers: map[string]string{name: "v"},
		}}
		if err := normalizeAndValidateSettingsRequest(&req); err == nil {
			t.Errorf("header name %q must be rejected", name)
		}
	}
}

func TestNormalizeJailDefaults(t *testing.T) {
	tests := []struct {
		name    string
		req     config.AppSettings
		wantKey string
		wantIPs []string
	}{
		{name: "valid and trimmed", req: config.AppSettings{IgnoreIPs: []string{" 127.0.0.1/8 ", "", "::1"}, Banaction: " nftables[type=multiport] ", Chain: "INPUT"}, wantIPs: []string{"127.0.0.1/8", "::1"}},
		{name: "ignoreip newline", req: config.AppSettings{IgnoreIPs: []string{"1.2.3.4\nbantime = -1"}}, wantKey: "settings.errors.invalid_ignoreip"},
		{name: "banaction newline", req: config.AppSettings{Banaction: "x\naction = evil"}, wantKey: "settings.errors.invalid_banaction"},
		{name: "allports invalid", req: config.AppSettings{BanactionAllports: "a b"}, wantKey: "settings.errors.invalid_banaction"},
		{name: "chain invalid", req: config.AppSettings{Chain: "IN\rPUT"}, wantKey: "settings.errors.invalid_chain"},
		{name: "empty defaults allowed", req: config.AppSettings{}, wantIPs: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.req
			err := normalizeJailDefaults(&req)
			if tt.wantKey != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if got := buildErrorResponse(err, "")["messageKey"]; got != tt.wantKey {
					t.Fatalf("messageKey = %v, want %s", got, tt.wantKey)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(req.IgnoreIPs, tt.wantIPs) {
				t.Fatalf("IgnoreIPs = %q, want %q", req.IgnoreIPs, tt.wantIPs)
			}
		})
	}
}

func TestNormalizeSettingsElasticsearchDataStream(t *testing.T) {
	for in, want := range map[string]string{"": config.DefaultElasticsearchDataStream, "fail2ban-events": config.DefaultElasticsearchDataStream, " logs-x-prod ": "logs-x-prod"} {
		req := config.AppSettings{Elasticsearch: config.ElasticsearchSettings{Index: in}}
		if err := normalizeAndValidateSettingsRequest(&req); err != nil {
			t.Errorf("index %q should be accepted: %v", in, err)
		} else if req.Elasticsearch.Index != want {
			t.Errorf("index %q normalized to %q, want %q", in, req.Elasticsearch.Index, want)
		}
	}
	req := config.AppSettings{Elasticsearch: config.ElasticsearchSettings{Index: "logs-*"}}
	if err := normalizeAndValidateSettingsRequest(&req); err == nil {
		t.Error("a pattern must be rejected as data stream name")
	}
}

func TestNormalizeSettingsUniFi(t *testing.T) {
	for _, baseURL := range []string{"http://192.168.1.1", "https://unifi.lan:8443", "https://[fd00::1]/controller"} {
		t.Run(baseURL, func(t *testing.T) {
			want := config.UniFiIntegrationSettings{
				BaseURL: baseURL, SiteName: "main-site", TrafficListName: "fail2ban_blocked",
				APIKey: "test-api-key", SkipTLSVerify: true,
			}
			input := want
			input.BaseURL = " " + baseURL + " "
			input.SiteName = " main-site "
			input.TrafficListName = " fail2ban_blocked "
			req := config.AppSettings{AdvancedActions: config.AdvancedActionsConfig{
				Integration: "unifi", Enabled: true, UniFi: input,
			}}
			if err := normalizeAndValidateSettingsRequest(&req); err != nil {
				t.Fatalf("valid LAN configuration should be accepted: %v", err)
			}
			if got := req.AdvancedActions.UniFi; got != want {
				t.Errorf("normalized UniFi settings = %+v, want %+v", got, want)
			}
		})
	}
}

func TestNormalizeSettingsUniFiRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name  string
		input config.UniFiIntegrationSettings
		field string
	}{
		{"unsupported scheme", config.UniFiIntegrationSettings{BaseURL: "file:///etc/passwd"}, "UniFi base URL"},
		{"missing host", config.UniFiIntegrationSettings{BaseURL: "https://"}, "UniFi base URL"},
		{"URL control characters", config.UniFiIntegrationSettings{BaseURL: "https://unifi.lan/\r\ninjected"}, "UniFi base URL"},
		{"site path traversal", config.UniFiIntegrationSettings{SiteName: "../default"}, "UniFi site name"},
		{"site control characters", config.UniFiIntegrationSettings{SiteName: "main\nsite"}, "UniFi site name"},
		{"list path traversal", config.UniFiIntegrationSettings{TrafficListName: "../blocked"}, "UniFi traffic matching list name"},
		{"list command characters", config.UniFiIntegrationSettings{TrafficListName: "blocked;command"}, "UniFi traffic matching list name"},
		{"list too long", config.UniFiIntegrationSettings{TrafficListName: strings.Repeat("a", 129)}, "UniFi traffic matching list name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate stored fields even when another integration is selected.
			req := config.AppSettings{AdvancedActions: config.AdvancedActionsConfig{
				Integration: "pfsense", UniFi: tt.input,
			}}
			err := normalizeAndValidateSettingsRequest(&req)
			if err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("expected validation error for %s, got %v", tt.field, err)
			}
		})
	}
}

func TestNormalizeSettingsUniFiAllowsIncompleteSettings(t *testing.T) {
	for _, input := range []config.UniFiIntegrationSettings{
		{},
		{BaseURL: " ", SiteName: " ", TrafficListName: " "},
		{BaseURL: "https://unifi.lan"},
		{SiteName: "default", TrafficListName: "blocked"},
	} {
		for _, enabled := range []bool{false, true} {
			req := config.AppSettings{AdvancedActions: config.AdvancedActionsConfig{
				Integration: "unifi", Enabled: enabled, UniFi: input,
			}}
			if err := normalizeAndValidateSettingsRequest(&req); err != nil {
				t.Errorf("incomplete configuration %+v (enabled=%v) should remain saveable: %v", input, enabled, err)
			}
		}
	}
}
