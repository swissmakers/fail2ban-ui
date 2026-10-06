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

package fail2ban

import (
	"path/filepath"
	"testing"
)

func TestNormalizeConfigPath(t *testing.T) {
	t.Parallel()
	if got := NormalizeConfigPath(""); got != DefaultConfigRoot {
		t.Fatalf("empty: got %q want %q", got, DefaultConfigRoot)
	}
	if got := NormalizeConfigPath("  "); got != DefaultConfigRoot {
		t.Fatalf("whitespace: got %q want %q", got, DefaultConfigRoot)
	}
	if got := NormalizeConfigPath("/opt/fail2ban"); got != "/opt/fail2ban" {
		t.Fatalf("clean path: got %q", got)
	}
	if got := NormalizeConfigPath("/etc/fail2ban/../fail2ban/"); got != "/etc/fail2ban" {
		t.Fatalf("clean: got %q", got)
	}
	for _, bad := range []string{
		"relative/dir",
		"/etc/fail2\x00ban",
		"/etc/f'oo",
		"/etc/f;oo",
		"/etc/f$oo",
		"/etc/fail2ban\nX",
	} {
		if got := NormalizeConfigPath(bad); got != DefaultConfigRoot {
			t.Fatalf("unsafe %q: got %q, want fallback %q", bad, got, DefaultConfigRoot)
		}
	}
}

func TestPathLayout(t *testing.T) {
	t.Parallel()
	root := "/tmp/f2b-test"
	wantJail := filepath.Join(root, "jail.d")
	if got := JailDir(root); got != wantJail {
		t.Fatalf("JailDir: got %q want %q", got, wantJail)
	}
	wantFilter := filepath.Join(root, "filter.d")
	if got := FilterDir(root); got != wantFilter {
		t.Fatalf("FilterDir: got %q want %q", got, wantFilter)
	}
	wantLocal := filepath.Join(root, "jail.local")
	if got := JailLocal(root); got != wantLocal {
		t.Fatalf("JailLocal: got %q want %q", got, wantLocal)
	}
	wantActionDir := filepath.Join(root, "action.d")
	if got := ActionDir(root); got != wantActionDir {
		t.Fatalf("ActionDir: got %q want %q", got, wantActionDir)
	}
	wantAction := filepath.Join(wantActionDir, "ui-custom-action.conf")
	if got := CustomActionFile(root); got != wantAction {
		t.Fatalf("CustomActionFile: got %q want %q", got, wantAction)
	}
}

func TestSafeConfigName(t *testing.T) {
	t.Parallel()
	valid := []string{"sshd", "nginx-limit-req", "my_jail", "Jail123"}
	for _, name := range valid {
		if got, err := safeConfigName(name); err != nil || got != name {
			t.Fatalf("safeConfigName(%q): got %q err %v, want %q nil", name, got, err, name)
		}
	}

	invalid := []string{
		"", "   ",
		"../etc/passwd",
		"foo/bar",
		"foo..bar",
		"foo.local",
		"a b",
		"foo\x00bar",
		"jail$(whoami)",
	}
	for _, name := range invalid {
		if _, err := safeConfigName(name); err == nil {
			t.Fatalf("safeConfigName(%q): expected error, got nil", name)
		}
	}
}

func TestResolveWithinDir(t *testing.T) {
	t.Parallel()
	dir := "/etc/fail2ban/jail.d"

	got, err := resolveWithinDir(dir, "sshd", ".local")
	if err != nil {
		t.Fatalf("resolveWithinDir valid: unexpected error %v", err)
	}
	want := filepath.Join(dir, "sshd.local")
	if got != want {
		t.Fatalf("resolveWithinDir: got %q want %q", got, want)
	}

	// Traversal and injection attempts must be rejected by the name allowlist.
	for _, name := range []string{"../../etc/passwd", "..", "foo/bar", "a/../../b"} {
		if _, err := resolveWithinDir(dir, name, ".local"); err == nil {
			t.Fatalf("resolveWithinDir(%q): expected error, got nil", name)
		}
	}
}

// Guards user-supplied names against path traversal.
func TestValidateFilterAndJailName(t *testing.T) {
	t.Parallel()

	valid := []string{"sshd", "nginx-limit-req", "my_jail", "Jail123", "a"}
	dangerous := []string{
		"",
		"   ",
		"..",
		"../etc",
		"../../etc/passwd",
		"/etc/passwd",
		"sshd/../../root",
		"sshd.conf",
		"sshd space",
		"sshd;rm -rf /",
		"sshd$(whoami)",
		"sshd|cat",
		"-leading-dash",
		"sshd\nmore",
		"sshd\x00",
	}

	for _, name := range valid {
		t.Run("filter/valid/"+name, func(t *testing.T) {
			if err := ValidateFilterName(name); err != nil {
				t.Fatalf("ValidateFilterName(%q) = %v, want nil", name, err)
			}
		})
		t.Run("jail/valid/"+name, func(t *testing.T) {
			if err := ValidateJailName(name); err != nil {
				t.Fatalf("ValidateJailName(%q) = %v, want nil", name, err)
			}
		})
	}

	for _, name := range dangerous {
		t.Run("filter/rejected/"+name, func(t *testing.T) {
			if err := ValidateFilterName(name); err == nil {
				t.Fatalf("ValidateFilterName(%q) = nil, want an error", name)
			}
		})
		t.Run("jail/rejected/"+name, func(t *testing.T) {
			if err := ValidateJailName(name); err == nil {
				t.Fatalf("ValidateJailName(%q) = nil, want an error", name)
			}
		})
	}
}

func TestResolveWithinDirRejectsEscape(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"..", "../evil", "/abs", "a/b"} {
		if _, err := resolveWithinDir("/etc/fail2ban/jail.d", name, ".local"); err == nil {
			t.Fatalf("resolveWithinDir(%q) = nil error, want rejection", name)
		}
	}
}
