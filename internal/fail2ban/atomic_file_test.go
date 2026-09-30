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
	for _, remote := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "SSH script"}[remote], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "jail.local")
			old := "[sshd]\nenabled = false\n"
			if err := os.WriteFile(path, []byte(old), 0640); err != nil {
				t.Fatal(err)
			}
			// WriteFile's mode is subject to the runner's umask.
			if err := os.Chmod(path, 0640); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if remote {
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
