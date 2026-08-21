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
