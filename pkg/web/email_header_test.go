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
	"html"
	"mime"
	"strings"
	"testing"
)

func TestSanitizeHeaderValueStripsCRLFAndNUL(t *testing.T) {
	t.Parallel()
	in := "sshd\r\nBcc: attacker@evil.com\x00"
	got := sanitizeHeaderValue(in)
	if strings.ContainsAny(got, "\r\n\x00") {
		t.Fatalf("sanitizeHeaderValue left CR/LF/NUL in %q", got)
	}
	if got != "sshdBcc: attacker@evil.com" {
		t.Fatalf("sanitizeHeaderValue = %q", got)
	}
}

func TestSubjectEncodingNeutralizesInjection(t *testing.T) {
	t.Parallel()
	subject := "[Fail2Ban] sshd: banned 1.2.3.4\r\nBcc: attacker@evil.com"
	encoded := mime.QEncoding.Encode("UTF-8", subject)
	if strings.ContainsAny(encoded, "\r\n") {
		t.Fatalf("encoded subject still contains CR/LF: %q", encoded)
	}

	plain := "[Fail2Ban] sshd: banned 1.2.3.4 from host"
	if got := mime.QEncoding.Encode("UTF-8", plain); got != plain {
		t.Fatalf("plain subject was altered: got %q want %q", got, plain)
	}
}

func TestEmailTemplatesEscapeUntrustedContent(t *testing.T) {
	t.Parallel()
	// WHOIS, log lines and event metadata can come from remote servers or callbacks.
	payload := `</pre><a href="https://attacker.example/">Open this link</a><script>alert(1)</script>`
	details := []emailDetail{{Label: payload, Value: payload}}
	for _, style := range []string{"classic", "modern", "lotr"} {
		t.Run(style, func(t *testing.T) {
			modern := style != "classic"
			whois := formatWhoisForEmail(payload, "en", modern)
			logs := formatLogsForEmail("", payload, "en", modern)
			var body string
			switch style {
			case "classic":
				body = buildClassicEmailBody(payload, payload, details, whois, logs, payload, payload, payload, "support@example.com")
			case "modern":
				body = buildModernEmailBody(payload, payload, details, whois, logs, payload, payload, payload)
			case "lotr":
				body = buildLOTREmailBody(payload, payload, payload, details, whois, logs, payload, payload, payload)
			}
			if strings.Contains(body, payload) {
				t.Fatal("untrusted email content was rendered as HTML")
			}
			if !strings.Contains(whois, html.EscapeString(payload)) || !strings.Contains(logs, html.EscapeString(payload)) {
				t.Fatal("WHOIS and log text must be preserved as escaped text")
			}
			if !strings.Contains(body, whois) || !strings.Contains(body, logs) || !strings.Contains(body, html.EscapeString(payload)) {
				t.Fatal("escaped content must remain visible in the email")
			}
		})
	}
}
