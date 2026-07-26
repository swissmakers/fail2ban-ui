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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveLogpathVariablesAtPath_customRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	localPath := filepath.Join(root, "vars.local")
	content := "my_custom_log = /tmp/from-custom-root.log\n"
	if err := os.WriteFile(localPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveLogpathVariables("%(my_custom_log)s", root)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/from-custom-root.log" {
		t.Fatalf("resolved logpath: got %q", got)
	}
}

func writeConfigFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", name, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestResolveLogpathVariables(t *testing.T) {
	t.Run("no variables passes through unchanged", func(t *testing.T) {
		got, err := ResolveLogpathVariables("/var/log/auth.log", t.TempDir())
		if err != nil || got != "/var/log/auth.log" {
			t.Fatalf("got %q, err %v", got, err)
		}
	})

	t.Run("empty logpath", func(t *testing.T) {
		got, err := ResolveLogpathVariables("", t.TempDir())
		if err != nil || got != "" {
			t.Fatalf("got %q, err %v", got, err)
		}
	})

	t.Run(".local shadows .conf", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "paths.conf", "logdir = /from-conf\n")
		writeConfigFile(t, root, "paths.local", "logdir = /from-local\n")

		got, err := ResolveLogpathVariables("%(logdir)s/app.log", root)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "/from-local/app.log" {
			t.Fatalf(".local must win over .conf, got %q", got)
		}
	})

	t.Run("falls back to .conf when no .local defines it", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "paths.conf", "logdir = /from-conf\n")

		got, err := ResolveLogpathVariables("%(logdir)s/app.log", root)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "/from-conf/app.log" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("searches subdirectories", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "jail.d/custom.local", "deepvar = /deep/path\n")

		got, err := ResolveLogpathVariables("%(deepvar)s/x.log", root)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "/deep/path/x.log" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("nested variable references resolve", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "paths.local", "base = /var/log\nappdir = %(base)s/app\n")

		got, err := ResolveLogpathVariables("%(appdir)s/access.log", root)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "/var/log/app/access.log" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("multiple variables in one logpath", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "paths.local", "d1 = /a\nd2 = /b\n")

		got, err := ResolveLogpathVariables("%(d1)s/x %(d2)s/y", root)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "/a/x /b/y" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("multiline continuation is joined", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "paths.local", "multi = /one/a.log\n         /two/b.log\n\nother = x\n")

		got, err := ResolveLogpathVariables("%(multi)s", root)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(got, "/one/a.log") || !strings.Contains(got, "/two/b.log") {
			t.Fatalf("both continuation lines must be present, got %q", got)
		}
	})

	t.Run("undefined variable is an error", func(t *testing.T) {
		if _, err := ResolveLogpathVariables("%(nope)s/x.log", t.TempDir()); err == nil {
			t.Fatal("expected an error for an undefined variable")
		}
	})

	t.Run("circular reference is an error, not a hang", func(t *testing.T) {
		root := t.TempDir()
		writeConfigFile(t, root, "loop.local", "a = %(b)s\nb = %(a)s\n")

		if _, err := ResolveLogpathVariables("%(a)s", root); err == nil {
			t.Fatal("expected an error for a circular reference")
		}
	})

	t.Run("missing config root is an error", func(t *testing.T) {
		if _, err := ResolveLogpathVariables("%(x)s", filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
			t.Fatal("expected an error when the config root is absent")
		}
	})
}

func TestSnapshotVariableSourceMatchesFilesystem(t *testing.T) {
	files := []struct{ name, content string }{
		{"paths.conf", "logdir = /from-conf\nbase = /var/log\n"},
		{"paths.local", "logdir = /from-local\n"},
		{"jail.d/deep.local", "deepvar = %(base)s/deep\n"},
		{"multi.local", "multi = /one/a.log\n         /two/b.log\n\nother = x\n"},
	}

	root := t.TempDir()
	var snapshot []remoteFile
	for _, f := range files {
		writeConfigFile(t, root, f.name, f.content)
		snapshot = append(snapshot, remoteFile{path: filepath.Join(root, f.name), content: f.content})
	}

	cases := []string{
		"%(logdir)s/app.log",
		"%(base)s/x.log",
		"%(deepvar)s/y.log",
		"%(multi)s",
		"/no/variables.log",
	}
	for _, logpath := range cases {
		fsGot, fsErr := resolveLogpathVariablesFrom(logpath, fsVariableSource{root: root})
		snapGot, snapErr := resolveLogpathVariablesFrom(logpath, snapshotVariableSource{files: snapshot})
		if (fsErr == nil) != (snapErr == nil) {
			t.Fatalf("%s: error mismatch fs=%v snapshot=%v", logpath, fsErr, snapErr)
		}
		if fsGot != snapGot {
			t.Fatalf("%s: fs source gave %q, snapshot gave %q", logpath, fsGot, snapGot)
		}
	}

	got, err := resolveLogpathVariablesFrom("%(logdir)s/app.log", snapshotVariableSource{files: snapshot})
	if err != nil || got != "/from-local/app.log" {
		t.Fatalf(".local must shadow .conf in the snapshot source, got %q (err %v)", got, err)
	}
}

func TestSnapshotVariableSourceUndefinedVariable(t *testing.T) {
	src := snapshotVariableSource{files: []remoteFile{{path: "/etc/fail2ban/x.conf", content: "a = 1\n"}}}
	if _, err := src.findVariable("missing"); err == nil {
		t.Fatal("expected an error for an undefined variable")
	}
}

func TestExtractVariablesFromString(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"/var/log/auth.log", nil},
		{"%(a)s", []string{"a"}},
		{"%(a)s/%(b)s", []string{"a", "b"}},
		{"prefix-%(with_underscore)s-suffix", []string{"with_underscore"}},
	}
	for _, tc := range cases {
		got := extractVariablesFromString(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("extractVariablesFromString(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("extractVariablesFromString(%q) = %v, want %v", tc.in, got, tc.want)
			}
		}
	}
}
