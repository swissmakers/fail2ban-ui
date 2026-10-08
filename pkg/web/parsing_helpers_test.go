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
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
)

func TestExtractCountryFromWhois(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"country field", "inetnum: 1.2.3.0\ncountry: CH\n", "CH"},
		{"lowercase is uppercased", "country: ch\n", "CH"},
		{"country code field", "Country Code: DE\n", "DE"},
		{"leading whitespace", "   country:   AT   \n", "AT"},
		{"three-letter value ignored", "country: CHE\n", ""},
		{"empty value ignored", "country:\n", ""},
		{"no country", "inetnum: 1.2.3.0\nnetname: EXAMPLE\n", ""},
		{"empty input", "", ""},
		{"first match wins", "country: CH\ncountry: DE\n", "CH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractCountryFromWhois(tc.in); got != tc.want {
				t.Fatalf("extractCountryFromWhois(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Drives threat-intel backoff: wrong values hammer or stall the upstream.
func TestParseRetryAfter(t *testing.T) {
	fallback := 30 * time.Second

	t.Run("integer seconds", func(t *testing.T) {
		if got := parseRetryAfter("120", fallback); got != 120*time.Second {
			t.Fatalf("got %v, want 120s", got)
		}
	})
	t.Run("zero is clamped to one second", func(t *testing.T) {
		if got := parseRetryAfter("0", fallback); got != time.Second {
			t.Fatalf("got %v, want 1s", got)
		}
	})
	t.Run("negative is clamped to one second", func(t *testing.T) {
		if got := parseRetryAfter("-5", fallback); got != time.Second {
			t.Fatalf("got %v, want 1s", got)
		}
	})
	t.Run("whitespace is trimmed", func(t *testing.T) {
		if got := parseRetryAfter("  45  ", fallback); got != 45*time.Second {
			t.Fatalf("got %v, want 45s", got)
		}
	})
	t.Run("empty falls back", func(t *testing.T) {
		if got := parseRetryAfter("", fallback); got != fallback {
			t.Fatalf("got %v, want the fallback", got)
		}
	})
	t.Run("garbage falls back", func(t *testing.T) {
		if got := parseRetryAfter("soon", fallback); got != fallback {
			t.Fatalf("got %v, want the fallback", got)
		}
	})
	t.Run("http date in the future", func(t *testing.T) {
		at := time.Now().UTC().Add(90 * time.Second)
		got := parseRetryAfter(at.Format(http.TimeFormat), fallback)
		if got < 80*time.Second || got > 95*time.Second {
			t.Fatalf("got %v, want roughly 90s", got)
		}
	})
	t.Run("http date in the past is clamped", func(t *testing.T) {
		at := time.Now().UTC().Add(-time.Hour)
		if got := parseRetryAfter(at.Format(http.TimeFormat), fallback); got != time.Second {
			t.Fatalf("got %v, want 1s", got)
		}
	})
}

// jail without a logpath must still be accepted
func TestJailConfigsWithoutLogpathYieldNoPaths(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
	}{
		{"UI override written when disabling a stock jail", "[sshd]\nenabled = false\n"},
		{"journal-backed jail", "[sshd]\nbackend = systemd\njournalmatch = _SYSTEMD_UNIT=sshd.service\nenabled = true\n"},
		{"seeded empty section", "[sshd]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.TrimSpace(fail2ban.ExtractLogpathFromJailConfig(tc.cfg))
			if got := strings.Fields(raw); len(got) != 0 {
				t.Fatalf("expected no logpaths for %q, got %#v", tc.cfg, got)
			}
		})
	}
}

// jail that does declare a logpath must still be validated
func TestJailConfigWithLogpathStillYieldsPaths(t *testing.T) {
	raw := strings.TrimSpace(fail2ban.ExtractLogpathFromJailConfig("[sshd]\nenabled = true\nlogpath = /var/log/auth.log\n"))
	got := strings.Fields(raw)
	if len(got) != 1 || got[0] != "/var/log/auth.log" {
		t.Fatalf("got %#v, want [/var/log/auth.log]", got)
	}
}
