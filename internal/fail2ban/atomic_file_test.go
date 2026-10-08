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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicConfigPreservesBackupOnRetry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		remote  bool
		minimal bool
	}{
		{name: "local"},
		{name: "SSH script", remote: true},
		{name: "SSH without cmp", remote: true, minimal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.remote {
				// Backup-content checks do not need to flush every filesystem on the test host.
				withFakeBinary(t, "sync", "exit 0\n")
			}
			if tc.minimal {
				bin := t.TempDir()
				for _, tool := range []string{"sh", "cat", "chmod", "mktemp", "mv", "readlink", "rm", "stat", "sync"} {
					path, err := exec.LookPath(tool)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(path, filepath.Join(bin, tool)); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("PATH", bin)
			}
			path := filepath.Join(t.TempDir(), "jail.local")
			old := "[sshd]\nenabled = false\n"
			if err := os.WriteFile(path, []byte(old), 0640); err != nil {
				t.Fatal(err)
			}
			// independent of the test runner's umask
			if err := os.Chmod(path, 0640); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if tc.remote {
					script, err := buildRemoteWriteScript(path, "[sshd]\nenabled = true\n")
					if err != nil {
						t.Fatal(err)
					}
					if output, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
						t.Fatalf("write: %v %s", err, output)
					}
				} else if err := writeConfigAtomic(path, []byte("[sshd]\nenabled = true\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != "[sshd]\nenabled = true\n" {
				t.Fatalf("target not replaced: %q %v", got, err)
			}
			backup, err := os.ReadFile(path + ".f2bui.bak")
			if err != nil || string(backup) != old {
				t.Fatalf("previous configuration lost: %s %v", backup, err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0640 {
				t.Fatal("existing permissions were not preserved")
			}
			info, err = os.Stat(path + ".f2bui.bak")
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("backup must be private")
			}
		})
	}
}

func TestFailedStagingLeavesRemoteConfigUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jail.local")
	if err := os.WriteFile(path, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	script, err := buildRemoteWriteScript(path, "replacement\n")
	if err != nil {
		t.Fatal(err)
	}
	withFakeBinary(t, "cat", "echo partial; exit 1\n")
	if err := exec.Command("sh", "-c", script).Run(); err == nil {
		t.Fatal("staging failure was ignored")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original\n" {
		t.Fatalf("original was truncated: %s %v", data, err)
	}
}

func TestRemoteWriteDetectsTrailingNewlineChanges(t *testing.T) {
	withFakeBinary(t, "sync", "exit 0\n")
	path := filepath.Join(t.TempDir(), "jail.local")
	old := "# Keep this dot.\n"
	content := old + "\n"
	if err := os.WriteFile(path, []byte(old), 0644); err != nil {
		t.Fatal(err)
	}
	script, err := buildRemoteWriteScript(path, content)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if output, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
			t.Fatalf("write: %v %s", err, output)
		}
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != content {
		t.Fatalf("newline change was lost: %q %v", got, err)
	}
	if got, err := os.ReadFile(path + backupSuffix); err != nil || string(got) != old {
		t.Fatalf("previous configuration lost: %q %v", got, err)
	}
}

func TestRemoteWriteReadFailurePreservesConfigAndBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jail.local")
	old, backup := "original\n", "previous backup\n"
	for name, content := range map[string]string{path: old, path + backupSuffix: backup} {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	realCat, err := exec.LookPath("cat")
	if err != nil {
		t.Fatal(err)
	}
	withFakeBinary(t, "cat", "if [ \"$#\" -gt 0 ] && [ \"$1\" = "+shellQuote(path)+" ]; then printf partial; exit 1; fi\nexec "+shellQuote(realCat)+" \"$@\"\n")
	script, err := buildRemoteWriteScript(path, "replacement\n")
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("sh", "-c", script).CombinedOutput(); err == nil {
		t.Fatalf("read failure was ignored: %s", output)
	}
	for name, want := range map[string]string{path: old, path + backupSuffix: backup} {
		if got, err := os.ReadFile(name); err != nil || string(got) != want {
			t.Fatalf("file changed after read failure: %s: %q %v", name, got, err)
		}
	}
	if files, err := filepath.Glob(path + ".f2bui.*"); err != nil || len(files) != 1 || files[0] != path+backupSuffix {
		t.Fatalf("staged files were not cleaned up: %v %v", files, err)
	}
}

// A dangling symlink must be followed and its target created, leaving the link intact.
func TestWriteConfigAtomicCreatesDanglingSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "managed", "jail.local")
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "jail.local")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeConfigAtomic(link, []byte("new\n"), 0644); err != nil {
		t.Fatalf("write through dangling symlink: %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "new\n" {
		t.Fatalf("symlink target not written: %q %v", got, err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}
}

// BusyBox chmod has no --reference; under set -e the whole write would silently abort there.
func TestRemoteWriteScriptAvoidsGNUOnlyTools(t *testing.T) {
	script, err := buildRemoteWriteScript("/etc/fail2ban/jail.local", "x\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, gnuOnly := range []string{"--reference", "chmod --", "readlink -e", "cp --"} {
		if strings.Contains(script, gnuOnly) {
			t.Errorf("remote write script uses GNU-only %q", gnuOnly)
		}
	}
}
