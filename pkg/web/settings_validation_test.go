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
