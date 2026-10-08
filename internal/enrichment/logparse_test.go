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

package enrichment

import (
	"reflect"
	"testing"

	"github.com/elastic/go-grok"
)

// A pattern that stops compiling is skipped silently, so pin compilation here.
func TestAllPatternsCompile(t *testing.T) {
	groups := map[string][]PatternDef{
		"HTTPPatterns":     HTTPPatterns,
		"SSHPatterns":      SSHPatterns,
		"MailPatterns":     MailPatterns,
		"FallbackPatterns": FallbackPatterns,
	}
	for groupName, defs := range groups {
		if len(defs) == 0 {
			t.Fatalf("%s is empty", groupName)
		}
		for _, d := range defs {
			t.Run(groupName+"/"+d.Name, func(t *testing.T) {
				g := grok.New()
				if err := g.AddPatterns(SubPatterns); err != nil {
					t.Fatalf("custom sub-patterns do not load: %v", err)
				}
				if err := g.Compile(d.Pattern, true); err != nil {
					t.Fatalf("pattern %q does not compile: %v", d.Name, err)
				}
			})
		}
	}
}

// The UI groups on Name/Category/Action.
func TestPatternDefinitionsAreComplete(t *testing.T) {
	seen := map[string]string{}
	for groupName, defs := range map[string][]PatternDef{
		"HTTPPatterns":     HTTPPatterns,
		"SSHPatterns":      SSHPatterns,
		"MailPatterns":     MailPatterns,
		"FallbackPatterns": FallbackPatterns,
	} {
		for _, d := range defs {
			// Process may be empty: the syslog prefix captures process.name itself.
			if d.Name == "" || d.Category == "" || d.Action == "" {
				t.Errorf("%s: pattern %+v has an empty Name/Category/Action", groupName, d)
			}
			if prev, dup := seen[d.Name]; dup {
				t.Errorf("duplicate pattern name %q in %s and %s", d.Name, prev, groupName)
			}
			seen[d.Name] = groupName
		}
	}
}

func TestSplitAndClean(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"only whitespace", "  \n\t\n  ", nil},
		{"single line", "one line", []string{"one line"}},
		{"blank lines dropped", "a\n\n\nb\n", []string{"a", "b"}},
		{"entries trimmed", "  a  \n\t b\t\n", []string{"a", "b"}},
		{"carriage returns handled", "a\r\nb\r\n", []string{"a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := splitAndClean(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitAndClean(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseLogLinesSSH(t *testing.T) {
	const line = "Feb 23 14:37:29 myhost sshd[12345]: Failed password for root from 203.0.113.77 port 54321 ssh2"

	got := ParseLogLines(line, "sshd")
	if got == nil {
		t.Fatal("ParseLogLines returned nil for a standard sshd failed-password line")
	}

	want := map[string]interface{}{
		"source.address":   "203.0.113.77",
		"source.user.name": "root",
		"process.name":     "sshd",
		"event.action":     "failed_password",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("field %q = %v (%T), want %v", k, got[k], got[k], v)
		}
	}
	if got["source.port"] != 54321 {
		t.Errorf("source.port = %v (%T), want int 54321", got["source.port"], got["source.port"])
	}
	if _, present := got["log.original"]; present {
		t.Errorf("log.original must not be promoted to the top level, got %v", got["log.original"])
	}
}

func TestParseLogLinesInvalidUser(t *testing.T) {
	const line = "Feb 23 14:37:29 myhost sshd[12345]: Invalid user admin from 203.0.113.77 port 54321"

	got := ParseLogLines(line, "sshd")
	if got == nil {
		t.Fatal("ParseLogLines returned nil for a standard sshd invalid-user line")
	}
	if got["source.address"] != "203.0.113.77" {
		t.Errorf("source.address = %v, want 203.0.113.77", got["source.address"])
	}
	if got["source.user.name"] != "admin" {
		t.Errorf("source.user.name = %v, want admin", got["source.user.name"])
	}
}

func TestParseLogLinesHTTP(t *testing.T) {
	const line = `203.0.113.77 - - [23/Feb/2026:14:37:29 +0100] "GET /.git/config HTTP/1.1" 301 248 "-" "Mozilla/5.0"`

	got := ParseLogLines(line, "apache-scanner")
	if got == nil {
		t.Fatal("ParseLogLines returned nil for a combined-format access log line")
	}
	if got["source.address"] != "203.0.113.77" {
		t.Errorf("source.address = %v, want 203.0.113.77", got["source.address"])
	}
	if got["http.request.method"] != "GET" {
		t.Errorf("http.request.method = %v, want GET", got["http.request.method"])
	}
	if got["url.original"] != "/.git/config" {
		t.Errorf("url.original = %v, want /.git/config", got["url.original"])
	}
	if got["http.response.status_code"] != 301 {
		t.Errorf("status_code = %v (%T), want int 301", got["http.response.status_code"], got["http.response.status_code"])
	}
}

func TestParseLogLinesVhost(t *testing.T) {
	tests := []struct {
		name, line, server string
	}{
		{"vhost with port", `code.example.com:443 203.0.113.7 - - [30/Sep/2026:12:00:01 +0200] "GET /wp-login.php HTTP/1.1" 301 230 "-" "curl/8.0"`, "code.example.com"},
		{"vhost without port", `code.example.com 203.0.113.7 - - [30/Sep/2026:12:00:01 +0200] "GET /wp-login.php HTTP/1.1" 301 230 "-" "curl/8.0"`, "code.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseLogLines(tt.line, "apache-badbots")
			if got["server.address"] != tt.server || got["source.address"] != "203.0.113.7" {
				t.Errorf("server.address = %v, source.address = %v", got["server.address"], got["source.address"])
			}
		})
	}
}

func TestParseLogLinesEdgeCases(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		if got := ParseLogLines("", "sshd"); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})
	t.Run("whitespace only", func(t *testing.T) {
		if got := ParseLogLines("   \n\t\n", "sshd"); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})
	t.Run("unmatched garbage", func(t *testing.T) {
		if got := ParseLogLines("this is not any known log format", "sshd"); got != nil {
			t.Fatalf("want nil for unparseable input, got %#v", got)
		}
	})
	t.Run("parsed_logs keeps the original line of every match", func(t *testing.T) {
		first := "Feb 23 14:37:29 myhost sshd[12345]: Failed password for root from 203.0.113.77 port 54321 ssh2"
		second := "Feb 23 14:37:30 myhost sshd[12346]: Invalid user admin from 203.0.113.78 port 54322"

		got := ParseLogLines(first+"\n"+second, "sshd")
		if got == nil {
			t.Fatal("want both lines parsed, got nil")
		}
		entries, ok := got["fail2ban.parsed_logs"].([]map[string]interface{})
		if !ok {
			t.Fatalf("fail2ban.parsed_logs = %#v, want a slice of entries", got["fail2ban.parsed_logs"])
		}
		if len(entries) != 2 {
			t.Fatalf("got %d parsed entries, want 2", len(entries))
		}
		originals := []string{}
		for _, e := range entries {
			orig, ok := e["log.original"].(string)
			if !ok || orig == "" {
				t.Fatalf("entry %#v is missing log.original", e)
			}
			originals = append(originals, orig)
		}
		if originals[0] != first || originals[1] != second {
			t.Fatalf("log.original values = %#v, want the two input lines in order", originals)
		}
	})

	t.Run("richest line wins across several", func(t *testing.T) {
		logs := "this is noise\n" +
			"Feb 23 14:37:29 myhost sshd[12345]: Failed password for root from 203.0.113.77 port 54321 ssh2"
		got := ParseLogLines(logs, "sshd")
		if got == nil {
			t.Fatal("want the parseable line to win, got nil")
		}
		if got["source.address"] != "203.0.113.77" {
			t.Fatalf("source.address = %v, want the parsed line's value", got["source.address"])
		}
	})
}

func TestParseWhois(t *testing.T) {
	t.Run("RIPE style", func(t *testing.T) {
		const blob = `inetnum:        203.0.113.0 - 203.0.113.255
netname:        EXAMPLE-NET
country:        CH
origin:         AS200373
abuse-c:        AR12345
% Abuse contact for '203.0.113.0 - 203.0.113.255' is 'abuse@example.ch'
`
		got := ParseWhois(blob)
		if got == nil {
			t.Fatal("ParseWhois returned nil for a RIPE style record")
		}
		if got["whois.asn"] != "200373" {
			t.Errorf("whois.asn = %v, want the AS prefix stripped (200373)", got["whois.asn"])
		}
		if got["whois.abuse_email"] != "abuse@example.ch" {
			t.Errorf("whois.abuse_email = %v, want abuse@example.ch", got["whois.abuse_email"])
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if got := ParseWhois(""); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})
	t.Run("whitespace only", func(t *testing.T) {
		if got := ParseWhois("   \n  \n"); got != nil {
			t.Fatalf("want nil, got %#v", got)
		}
	})
	t.Run("no recognised keys", func(t *testing.T) {
		if got := ParseWhois("something: else\nanother: value\n"); got != nil {
			t.Fatalf("want nil when nothing maps, got %#v", got)
		}
	})
}
