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

package fail2ban

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A jail defined in two jail.d files, the UI's own <name>.local (disabled) and a custom file (enabled) that fail2ban
// reads later (lexical last-wins).
func setupDuplicateJailDir(t *testing.T) string {
	t.Helper()
	configPath := t.TempDir()
	jailD := filepath.Join(configPath, "jail.d")
	if err := os.MkdirAll(jailD, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(jailD, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("recidive.local", "[recidive]\nenabled = false\n")
	write("swissmakers-recidive.local", "[recidive]\nenabled  = true\nfilter   = recidive\nlogpath  = /var/log/fail2ban.log\n")
	write("apache-auth.local", "[apache-auth]\nenabled = true\n")
	return configPath
}

func TestDiscoverJailsFromFilesLastWins(t *testing.T) {
	configPath := setupDuplicateJailDir(t)

	jails, err := DiscoverJailsFromFiles(configPath)
	if err != nil {
		t.Fatalf("DiscoverJailsFromFiles: %v", err)
	}
	byName := map[string]bool{}
	for _, j := range jails {
		byName[j.JailName] = j.Enabled
	}
	// swissmakers-recidive.local is read after recidive.local by fail2ban, so
	// the effective state is enabled -> the UI must report the same.
	if enabled, ok := byName["recidive"]; !ok || !enabled {
		t.Fatalf("recidive enabled = %v (found=%v), want true (last-wins)", enabled, ok)
	}
	if enabled, ok := byName["apache-auth"]; !ok || !enabled {
		t.Fatalf("apache-auth enabled = %v (found=%v), want true", enabled, ok)
	}
}

func TestUpdateJailEnabledStatesWritesAllDefiningFiles(t *testing.T) {
	configPath := setupDuplicateJailDir(t)
	jailD := filepath.Join(configPath, "jail.d")

	if err := UpdateJailEnabledStates(map[string]bool{"recidive": false}, configPath); err != nil {
		t.Fatalf("UpdateJailEnabledStates: %v", err)
	}

	for _, file := range []string{"recidive.local", "swissmakers-recidive.local"} {
		content, err := os.ReadFile(filepath.Join(jailD, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if !strings.Contains(string(content), "enabled = false") {
			t.Fatalf("%s does not contain 'enabled = false':\n%s", file, content)
		}
		if strings.Contains(string(content), "enabled  = true") {
			t.Fatalf("%s still contains the old enabled = true line:\n%s", file, content)
		}
	}
	// Other settings in the custom file must survive the rewrite.
	content, _ := os.ReadFile(filepath.Join(jailD, "swissmakers-recidive.local"))
	if !strings.Contains(string(content), "logpath  = /var/log/fail2ban.log") {
		t.Fatalf("swissmakers-recidive.local lost unrelated settings:\n%s", content)
	}

	// The UI list must reflect the now truly disabled jail.
	jails, err := DiscoverJailsFromFiles(configPath)
	if err != nil {
		t.Fatalf("DiscoverJailsFromFiles: %v", err)
	}
	for _, j := range jails {
		if j.JailName == "recidive" && j.Enabled {
			t.Fatal("recidive still reported enabled after disabling")
		}
	}
}

func TestUpdateJailEnabledStatesCreatesFileWhenUndefined(t *testing.T) {
	configPath := setupDuplicateJailDir(t)
	jailD := filepath.Join(configPath, "jail.d")

	if err := UpdateJailEnabledStates(map[string]bool{"sshd": true}, configPath); err != nil {
		t.Fatalf("UpdateJailEnabledStates: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(jailD, "sshd.local"))
	if err != nil {
		t.Fatalf("sshd.local not created: %v", err)
	}
	if !strings.Contains(string(content), "[sshd]") || !strings.Contains(string(content), "enabled = true") {
		t.Fatalf("sshd.local content unexpected:\n%s", content)
	}
}

func TestContainsJailSection(t *testing.T) {
	content := "# comment\n[swissmakers-apache-scanner]\nenabled = true\n"
	if !containsJailSection(content, "swissmakers-apache-scanner") {
		t.Fatal("expected section to be found")
	}
	if containsJailSection(content, "other-jail") {
		t.Fatal("did not expect section for other jail")
	}
	garbled := "mux_client_request_session: session request failed\nControlSocket /tmp/x already exists\n"
	if containsJailSection(garbled, "swissmakers-apache-scanner") {
		t.Fatal("garbled content must not contain the jail section")
	}
	if !containsJailSection("  [j1]  \n", "j1") {
		t.Fatal("expected trimmed section header to match")
	}
}

func TestSanitizeLogpath(t *testing.T) {
	valid := []string{
		"/var/log/auth.log",
		"/var/log/httpd/*access_log",
		"/var/log/app/[abc].log",
		"",
	}
	for _, p := range valid {
		if _, err := sanitizeLogpath(p); err != nil {
			t.Errorf("sanitizeLogpath(%q) should pass: %v", p, err)
		}
	}
	invalid := []string{
		"relative/log",
		"/var/log/../../etc/passwd",
		"/var/log/x\x00y",
		"/var/log/x;rm",
		"/var/log/$(id)",
		"/var/log/`id`",
		"/var/log/x'y",
	}
	for _, p := range invalid {
		if _, err := sanitizeLogpath(p); err == nil {
			t.Errorf("sanitizeLogpath(%q) should fail", p)
		}
	}
}

func TestFilterNameForJail(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain filter", "[sshd]\nenabled = true\nfilter = sshd\n", "sshd"},
		{"filter with parameters", "filter = apache-auth[mode=aggressive]\n", "apache-auth"},
		{"spaces around value", "filter    =    nginx-limit-req   \n", "nginx-limit-req"},
		{"uppercase key", "FILTER = sshd\n", "sshd"},
		{"commented filter is ignored", "#filter = evil\nfilter = sshd\n", "sshd"},
		{"only a commented filter falls back to jail", "# filter = sshd\n", "myjail"},
		{"no filter key falls back to jail", "[sshd]\nenabled = true\n", "myjail"},
		{"empty input falls back to jail", "", "myjail"},
		{"first filter wins", "filter = one\nfilter = two\n", "one"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FilterNameForJail("myjail", tc.in); got != tc.want {
				t.Fatalf("FilterNameForJail(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Paths come back newline-separated; the jail handlers split them with strings.Fields.
func TestExtractLogpathFromJailConfig(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"single path", "logpath = /var/log/auth.log\n", "/var/log/auth.log"},
		{
			"several paths on one line",
			"logpath = /var/log/a.log /var/log/b.log\n",
			"/var/log/a.log\n/var/log/b.log",
		},
		{
			"continuation lines are collected",
			"logpath = /var/log/a.log\n          /var/log/b.log\n          /var/log/c.log\nmaxretry = 3\n",
			"/var/log/a.log\n/var/log/b.log\n/var/log/c.log",
		},
		{
			"continuation stops at a comment",
			"logpath = /var/log/a.log\n          /var/log/b.log\n# /var/log/ignored.log\n",
			"/var/log/a.log\n/var/log/b.log",
		},
		{
			"continuation stops at the next key",
			"logpath = /var/log/a.log\n          /var/log/b.log\nenabled = true\n",
			"/var/log/a.log\n/var/log/b.log",
		},
		{"commented logpath is ignored", "# logpath = /var/log/evil.log\n", ""},
		{"no logpath key", "[sshd]\nenabled = true\n", ""},
		{"empty input", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractLogpathFromJailConfig(tc.in); got != tc.want {
				t.Fatalf("ExtractLogpathFromJailConfig(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeJailSection(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "empty", content: "  \n", want: "[sshd]\n"},
		{name: "no header prepends", content: "enabled = true\n", want: "[sshd]\nenabled = true\n"},
		{name: "correct header unchanged", content: "[sshd]\nenabled = true\n", want: "[sshd]\nenabled = true\n"},
		{name: "adds trailing newline", content: "[sshd]\nenabled = true", want: "[sshd]\nenabled = true\n"},
		{name: "single wrong header renamed", content: "# note\n[other]\nport = ssh\n", want: "# note\n[sshd]\nport = ssh\n"},
		{name: "duplicate correct header dropped", content: "[sshd]\na = 1\n[sshd]\nb = 2\n", want: "[sshd]\na = 1\nb = 2\n"},
		{name: "other sections kept verbatim", content: "[sshd]\na = 1\n[extra]\nb = 2\n", want: "[sshd]\na = 1\n[extra]\nb = 2\n"},
		{
			name:    "two wrong headers keep content",
			content: "[one]\na = 1\n[two]\nb = 2\n",
			want:    "[sshd]\na = 1\n[two]\nb = 2\n",
		},
		{name: "default not renamed", content: "[DEFAULT]\nbantime = 1h\n", want: "[sshd]\n[DEFAULT]\nbantime = 1h\n"},
		{name: "default kept before wrong jail header", content: "[DEFAULT]\nx = 1\n[old]\ny = 2\n", want: "[DEFAULT]\nx = 1\n[sshd]\ny = 2\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeJailSection("sshd", tt.content); got != tt.want {
				t.Fatalf("NormalizeJailSection =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}
