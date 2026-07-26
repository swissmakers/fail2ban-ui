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

// Characterization tests for the filter [INCLUDES] resolution. The output of
// resolveFilterIncludes is fed straight into fail2ban-regex, so ordering and
// variable shadowing are load-bearing: these pin the behaviour so the shared
// implementation used by the local and SSH connectors cannot drift.

func writeFilterFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
}

func indexOfOrFail(t *testing.T, haystack, needle, label string) int {
	t.Helper()
	idx := strings.Index(haystack, needle)
	if idx < 0 {
		t.Fatalf("%s (%q) missing from output:\n%s", label, needle, haystack)
	}
	return idx
}

func TestResolveFilterIncludes(t *testing.T) {
	t.Run("before content precedes main content", func(t *testing.T) {
		dir := t.TempDir()
		writeFilterFile(t, dir, "common.conf", "[INCLUDES]\n[Definition]\n__prefix_line = COMMON_PREFIX\n")
		main := "[INCLUDES]\nbefore = common.conf\n\n[Definition]\nfailregex = MAIN_REGEX\n"

		out, err := resolveFilterIncludes(main, dir, "sshd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		before := indexOfOrFail(t, out, "COMMON_PREFIX", "included content")
		mainIdx := indexOfOrFail(t, out, "MAIN_REGEX", "main content")
		if before > mainIdx {
			t.Fatalf("before-include must precede main content, got:\n%s", out)
		}
	})

	t.Run("after content follows main content", func(t *testing.T) {
		dir := t.TempDir()
		writeFilterFile(t, dir, "tail.conf", "[Definition]\nignoreregex = TAIL_IGNORE\n")
		main := "[INCLUDES]\nafter = tail.conf\n\n[Definition]\nfailregex = MAIN_REGEX\n"

		out, err := resolveFilterIncludes(main, dir, "sshd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mainIdx := indexOfOrFail(t, out, "MAIN_REGEX", "main content")
		after := indexOfOrFail(t, out, "TAIL_IGNORE", "after-include content")
		if after < mainIdx {
			t.Fatalf("after-include must follow main content, got:\n%s", out)
		}
	})

	t.Run("before and after both applied in order", func(t *testing.T) {
		dir := t.TempDir()
		writeFilterFile(t, dir, "head.conf", "HEAD_MARKER\n")
		writeFilterFile(t, dir, "tail.conf", "TAIL_MARKER\n")
		main := "[INCLUDES]\nbefore = head.conf\nafter = tail.conf\n\n[Definition]\nfailregex = MAIN_REGEX\n"

		out, err := resolveFilterIncludes(main, dir, "sshd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		h := indexOfOrFail(t, out, "HEAD_MARKER", "before content")
		m := indexOfOrFail(t, out, "MAIN_REGEX", "main content")
		tl := indexOfOrFail(t, out, "TAIL_MARKER", "after content")
		if !(h < m && m < tl) {
			t.Fatalf("expected before < main < after ordering, got h=%d m=%d t=%d:\n%s", h, m, tl, out)
		}
	})

	t.Run("prefers .local over .conf", func(t *testing.T) {
		dir := t.TempDir()
		writeFilterFile(t, dir, "common.conf", "FROM_CONF\n")
		writeFilterFile(t, dir, "common.local", "FROM_LOCAL\n")
		main := "[INCLUDES]\nbefore = common.conf\n\n[Definition]\nfailregex = MAIN_REGEX\n"

		out, err := resolveFilterIncludes(main, dir, "sshd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "FROM_LOCAL") || strings.Contains(out, "FROM_CONF") {
			t.Fatalf(".local must win over .conf, got:\n%s", out)
		}
	})

	t.Run("self-inclusion in before is skipped", func(t *testing.T) {
		dir := t.TempDir()
		writeFilterFile(t, dir, "sshd.conf", "SELF_CONTENT\n")
		main := "[INCLUDES]\nbefore = sshd.conf\n\n[Definition]\nfailregex = MAIN_REGEX\n"

		out, err := resolveFilterIncludes(main, dir, "sshd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(out, "SELF_CONTENT") {
			t.Fatalf("self-inclusion in before must be skipped, got:\n%s", out)
		}
	})

	t.Run("self-inclusion in after is allowed (fail2ban .local pattern)", func(t *testing.T) {
		dir := t.TempDir()
		writeFilterFile(t, dir, "sshd.local", "SELF_AFTER_CONTENT\n")
		main := "[INCLUDES]\nafter = sshd.local\n\n[Definition]\nfailregex = MAIN_REGEX\n"

		out, err := resolveFilterIncludes(main, dir, "sshd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "SELF_AFTER_CONTENT") {
			t.Fatalf("self-inclusion in after must be kept, got:\n%s", out)
		}
	})

	t.Run("missing include is skipped without error", func(t *testing.T) {
		dir := t.TempDir()
		main := "[INCLUDES]\nbefore = does-not-exist.conf\n\n[Definition]\nfailregex = MAIN_REGEX\n"

		out, err := resolveFilterIncludes(main, dir, "sshd")
		if err != nil {
			t.Fatalf("missing include must not error, got: %v", err)
		}
		if !strings.Contains(out, "MAIN_REGEX") {
			t.Fatalf("main content must survive a missing include, got:\n%s", out)
		}
	})

	t.Run("include name escaping the filter dir is skipped", func(t *testing.T) {
		dir := t.TempDir()
		outside := filepath.Join(filepath.Dir(dir), "escaped.conf")
		if err := os.WriteFile(outside, []byte("ESCAPED_CONTENT\n"), 0o600); err != nil {
			t.Fatalf("setup failed: %v", err)
		}
		defer func() { _ = os.Remove(outside) }()

		main := "[INCLUDES]\nbefore = ../escaped.conf\n\n[Definition]\nfailregex = MAIN_REGEX\n"
		out, err := resolveFilterIncludes(main, dir, "sshd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(out, "ESCAPED_CONTENT") {
			t.Fatalf("include name must not escape the filter directory, got:\n%s", out)
		}
	})

	t.Run("main [DEFAULT] variables shadow the included ones", func(t *testing.T) {
		dir := t.TempDir()
		writeFilterFile(t, dir, "common.conf", "[DEFAULT]\n__prefix_line = INCLUDED_VALUE\nkeepme = KEEP_VALUE\n")
		main := "[INCLUDES]\nbefore = common.conf\n\n[DEFAULT]\n__prefix_line = MAIN_VALUE\n\n[Definition]\nfailregex = MAIN_REGEX\n"

		out, err := resolveFilterIncludes(main, dir, "sshd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(out, "INCLUDED_VALUE") {
			t.Fatalf("shadowed variable must be removed from the include, got:\n%s", out)
		}
		if !strings.Contains(out, "MAIN_VALUE") {
			t.Fatalf("main definition must survive, got:\n%s", out)
		}
		if !strings.Contains(out, "KEEP_VALUE") {
			t.Fatalf("non-shadowed included variable must survive, got:\n%s", out)
		}
	})

	t.Run("include without trailing newline still separates from main", func(t *testing.T) {
		dir := t.TempDir()
		writeFilterFile(t, dir, "common.conf", "NO_TRAILING_NEWLINE")
		main := "[INCLUDES]\nbefore = common.conf\n\n[Definition]\nfailregex = MAIN_REGEX\n"

		out, err := resolveFilterIncludes(main, dir, "sshd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "NO_TRAILING_NEWLINE\n") {
			t.Fatalf("a newline must be inserted after an include lacking one, got:\n%q", out)
		}
	})

	t.Run("[INCLUDES] directives are stripped from the emitted content", func(t *testing.T) {
		dir := t.TempDir()
		writeFilterFile(t, dir, "common.conf", "COMMON\n")
		main := "[INCLUDES]\nbefore = common.conf\n\n[Definition]\nfailregex = MAIN_REGEX\n"

		out, err := resolveFilterIncludes(main, dir, "sshd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(out, "[INCLUDES]") || strings.Contains(out, "before = common.conf") {
			t.Fatalf("[INCLUDES] section must not be emitted, got:\n%s", out)
		}
	})
}

func TestDedupeConfigBaseNames(t *testing.T) {
	t.Run("local shadows conf and result is sorted", func(t *testing.T) {
		got := dedupeConfigBaseNames(
			[]string{"/f/sshd.local", "/f/zzz.local"},
			[]string{"/f/sshd.conf", "/f/apache.conf"},
		)
		want := []string{"apache", "sshd", "zzz"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	})

	t.Run("documentation and backup files are excluded", func(t *testing.T) {
		got := dedupeConfigBaseNames(nil, []string{
			"/f/README.conf", "/f/sshd.conf", "/f/old.conf.bak", "/f/x.conf.rpmnew",
		})
		if len(got) != 1 || got[0] != "sshd" {
			t.Fatalf("expected only sshd, got %v", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if got := dedupeConfigBaseNames(nil, nil); len(got) != 0 {
			t.Fatalf("expected empty, got %v", got)
		}
	})
}

func TestExtractVariablesFromContent(t *testing.T) {
	vars := extractVariablesFromContent("[DEFAULT]\nfoo = 1\n# comment = 2\nbar=3\n\n[Definition]\nbaz = 4\n")
	if !vars["foo"] || !vars["bar"] {
		t.Fatalf("expected foo and bar from [DEFAULT], got %v", vars)
	}
	if vars["baz"] {
		t.Fatalf("variables outside [DEFAULT] must be ignored, got %v", vars)
	}
	if vars["# comment"] || vars["comment"] {
		t.Fatalf("comments must be ignored, got %v", vars)
	}
}

func TestRemoveDuplicateVariables(t *testing.T) {
	t.Run("removes only shadowed [DEFAULT] entries", func(t *testing.T) {
		included := "[DEFAULT]\ndrop = 1\nkeep = 2\n\n[Definition]\ndrop = 3\n"
		out := removeDuplicateVariables(included, map[string]bool{"drop": true})
		if strings.Contains(out, "drop = 1") {
			t.Fatalf("shadowed [DEFAULT] entry must be removed, got:\n%s", out)
		}
		if !strings.Contains(out, "keep = 2") {
			t.Fatalf("unshadowed entry must survive, got:\n%s", out)
		}
		if !strings.Contains(out, "drop = 3") {
			t.Fatalf("entries outside [DEFAULT] must survive, got:\n%s", out)
		}
	})

	t.Run("no shadowing leaves content intact apart from newline normalization", func(t *testing.T) {
		included := "[DEFAULT]\na = 1\n"
		out := removeDuplicateVariables(included, map[string]bool{})
		if !strings.Contains(out, "a = 1") || !strings.Contains(out, "[DEFAULT]") {
			t.Fatalf("content must be preserved, got:\n%s", out)
		}
	})
}

func TestParseJailConfigContent(t *testing.T) {
	t.Run("sections parsed with enabled state", func(t *testing.T) {
		jails := parseJailConfigContent("[sshd]\nenabled = true\n\n[nginx]\nenabled = false\n")
		if len(jails) != 2 {
			t.Fatalf("expected 2 jails, got %+v", jails)
		}
		if jails[0].JailName != "sshd" || !jails[0].Enabled {
			t.Fatalf("sshd should be enabled, got %+v", jails[0])
		}
		if jails[1].JailName != "nginx" || jails[1].Enabled {
			t.Fatalf("nginx should be disabled, got %+v", jails[1])
		}
	})

	t.Run("DEFAULT and INCLUDES are not jails", func(t *testing.T) {
		jails := parseJailConfigContent("[DEFAULT]\nenabled = true\n[INCLUDES]\nbefore = x\n[real]\nenabled = true\n")
		if len(jails) != 1 || jails[0].JailName != "real" {
			t.Fatalf("expected only the real jail, got %+v", jails)
		}
	})

	t.Run("missing enabled key defaults to enabled", func(t *testing.T) {
		jails := parseJailConfigContent("[sshd]\nport = ssh\n")
		if len(jails) != 1 || !jails[0].Enabled {
			t.Fatalf("jail without an enabled key defaults to true, got %+v", jails)
		}
	})

	t.Run("empty content yields no jails", func(t *testing.T) {
		if jails := parseJailConfigContent(""); len(jails) != 0 {
			t.Fatalf("expected no jails, got %+v", jails)
		}
	})
}

func TestJailAccumulator(t *testing.T) {
	t.Run("local overrides conf", func(t *testing.T) {
		acc := newJailAccumulator()
		acc.add("[sshd]\nenabled = false\n", "conf")
		acc.add("[sshd]\nenabled = true\n", "local")
		if len(acc.jails) != 1 {
			t.Fatalf("expected a single merged jail, got %+v", acc.jails)
		}
		if !acc.jails[0].Enabled {
			t.Fatalf(".local must win over .conf, got %+v", acc.jails[0])
		}
	})

	t.Run("conf does not override local", func(t *testing.T) {
		acc := newJailAccumulator()
		acc.add("[sshd]\nenabled = true\n", "local")
		acc.add("[sshd]\nenabled = false\n", "conf")
		if !acc.jails[0].Enabled {
			t.Fatalf(".conf must not override .local, got %+v", acc.jails[0])
		}
	})

	t.Run("same type re-definition wins", func(t *testing.T) {
		acc := newJailAccumulator()
		acc.add("[sshd]\nenabled = true\n", "local")
		acc.add("[sshd]\nenabled = false\n", "local")
		if acc.jails[0].Enabled {
			t.Fatalf("later same-type definition must win, got %+v", acc.jails[0])
		}
	})

	t.Run("insertion order preserved and DEFAULT skipped", func(t *testing.T) {
		acc := newJailAccumulator()
		acc.add("[DEFAULT]\nenabled = true\n[b]\nenabled = true\n[a]\nenabled = true\n", "conf")
		if len(acc.jails) != 2 || acc.jails[0].JailName != "b" || acc.jails[1].JailName != "a" {
			t.Fatalf("expected [b a] in insertion order, got %+v", acc.jails)
		}
	})
}
