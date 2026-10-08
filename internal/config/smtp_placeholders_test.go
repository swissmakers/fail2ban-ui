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

package config

import (
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

func TestScrubLegacySMTPPlaceholders(t *testing.T) {
	legacy := SMTPSettings{Host: "smtp.office365.com", Username: "noreply@swissmakers.ch", Password: "password", From: "noreply@swissmakers.ch", Port: 587}
	tests := []struct {
		name string
		in   AppSettings
		want AppSettings
	}{
		{
			name: "legacy defaults cleared",
			in:   AppSettings{Destemail: "alerts@example.com", SMTP: legacy},
			want: AppSettings{SMTP: SMTPSettings{Port: 587}},
		},
		{
			name: "real credentials kept",
			in:   AppSettings{Destemail: "ops@corp.example", SMTP: SMTPSettings{Host: "smtp.office365.com", Username: "noreply@swissmakers.ch", Password: "s3cret-real", From: "noreply@swissmakers.ch"}},
			want: AppSettings{Destemail: "ops@corp.example", SMTP: SMTPSettings{Host: "smtp.office365.com", Username: "noreply@swissmakers.ch", Password: "s3cret-real", From: "noreply@swissmakers.ch"}},
		},
		{
			name: "custom host kept with placeholder credentials",
			in:   AppSettings{SMTP: SMTPSettings{Host: "mail.corp.example", Username: "noreply@swissmakers.ch", Password: "password", From: "alerts@corp.example"}},
			want: AppSettings{SMTP: SMTPSettings{Host: "mail.corp.example", From: "alerts@corp.example"}},
		},
		{
			name: "placeholder destination only",
			in:   AppSettings{Destemail: "Alerts@Example.com"},
			want: AppSettings{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in
			scrubLegacySMTPPlaceholders(&got)
			if got.Destemail != tt.want.Destemail || got.SMTP != tt.want.SMTP {
				t.Fatalf("got %+v / %+v, want %+v / %+v", got.Destemail, got.SMTP, tt.want.Destemail, tt.want.SMTP)
			}
		})
	}
}

func TestSanitizeJailDefaults(t *testing.T) {
	s := AppSettings{
		IgnoreIPs:         []string{"127.0.0.1/8", "1.2.3.4\nbantime = -1", "example.com"},
		Banaction:         "nftables\naction = x",
		BanactionAllports: "nftables[type=allports]",
		Chain:             "IN PUT",
	}
	warnings := sanitizeJailDefaults(&s)
	if len(warnings) != 3 {
		t.Fatalf("warnings = %q, want 3", warnings)
	}
	if len(s.IgnoreIPs) != 2 || s.IgnoreIPs[0] != "127.0.0.1/8" || s.IgnoreIPs[1] != "example.com" {
		t.Fatalf("IgnoreIPs = %q", s.IgnoreIPs)
	}
	if s.Banaction != "" || s.BanactionAllports != "nftables[type=allports]" || s.Chain != "" {
		t.Fatalf("banaction=%q allports=%q chain=%q", s.Banaction, s.BanactionAllports, s.Chain)
	}
}

func TestGenerateCallbackSecret(t *testing.T) {
	a, b := generateCallbackSecret(), generateCallbackSecret()
	if len(a) != 42 || a == b {
		t.Fatalf("secrets %q / %q: want 42 characters and distinct values", a, b)
	}
	if err := shared.ValidateCallbackSecret(a); err != nil {
		t.Fatalf("generated secret rejected: %v", err)
	}
}
