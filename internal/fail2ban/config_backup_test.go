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
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// Run the exact SSH payload against a temporary directory. No SSH daemon,
// Fail2Ban process, or production configuration participates in these tests.
func configurationBackupHarness(t *testing.T, transport, root string) func(string, string) error {
	t.Helper()
	if transport == "local" {
		c := NewLocalConnector(shared.Fail2banServer{ConfigPath: root})
		return func(id, mode string) error {
			switch mode {
			case "backup":
				return c.BackupConfiguration(context.Background(), id)
			case "restore":
				return c.RestoreConfiguration(context.Background(), id)
			default:
				return c.DeleteConfigurationBackup(context.Background(), id)
			}
		}
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is needed to test the remote backup payload")
	}
	return func(id, mode string) error {
		cmd := exec.Command(python, "-c", remoteConfigBackupScript, root, id, mode)
		return cmd.Run()
	}
}

func TestConfigurationBackupRestoresExactFilesAndModes(t *testing.T) {
	for _, transport := range []string{"local", "ssh"} {
		t.Run(transport, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"jail.d", "filter.d", "action.d"} {
				if err := os.Mkdir(filepath.Join(root, dir), 0755); err != nil {
					t.Fatal(err)
				}
			}
			original := map[string]string{"jail.local": "[DEFAULT]\nenabled = false\n", "jail.d/ssh.local": "[ssh]\nenabled = true\n", "filter.d/ssh.conf": "[Definition]\nfailregex = before\n", "action.d/ui-custom-action.conf": "[Definition]\nactionban = before\n"}
			for name, content := range original {
				path := filepath.Join(root, name)
				if err := os.WriteFile(path, []byte(content), 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			}
			run := configurationBackupHarness(t, transport, root)
			if err := run("op1", "backup"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "jail.local"), []byte("invalid change"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(root, "jail.local"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, "filter.d/ssh.conf")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "jail.d/new.local"), []byte("new file"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "jail.d/operator-notes.txt"), []byte("leave alone"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := run("op1", "backup"); err != nil {
				t.Fatal(err)
			} // Retrying must not replace the original.
			for i := 0; i < 2; i++ {
				if err := run("op1", "restore"); err != nil {
					t.Fatal(err)
				}
			}
			for name, want := range original {
				got, err := os.ReadFile(filepath.Join(root, name))
				if err != nil || string(got) != want {
					t.Fatalf("%s = %q, %v", name, got, err)
				}
				info, err := os.Stat(filepath.Join(root, name))
				if err != nil || info.Mode().Perm() != 0640 {
					t.Fatalf("%s permissions were not restored: %v %v", name, info, err)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "jail.d/new.local")); !os.IsNotExist(err) {
				t.Fatal("new config survived rollback")
			}
			if raw, err := os.ReadFile(filepath.Join(root, "jail.d/operator-notes.txt")); err != nil || string(raw) != "leave alone" {
				t.Fatal("unrelated file changed")
			}
			if err := run("op1", "delete"); err != nil {
				t.Fatal(err)
			}
			if err := run("op1", "restore"); err == nil {
				t.Fatal("deleted backup still exists")
			}
		})
	}
}

func TestConfigurationBackupRejectsUnsafePathsAndCorruption(t *testing.T) {
	for _, transport := range []string{"local", "ssh"} {
		t.Run(transport, func(t *testing.T) {
			root := t.TempDir()
			run := configurationBackupHarness(t, transport, root)
			for _, id := range []string{"../outside", "", "bad/id"} {
				if err := run(id, "backup"); err == nil {
					t.Fatalf("accepted invalid id %q", id)
				}
			}
			if err := run("op1", "backup"); err != nil {
				t.Fatal(err)
			}
			path, err := backupFilePath(root, "op1")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("broken JSON"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := run("op1", "backup"); err == nil {
				t.Fatal("accepted corrupt immutable backup")
			}
			if err := os.WriteFile(filepath.Join(root, "jail.local"), []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			bad := configBackup{Files: map[string]configBackupFile{"jail.local": {Data: []byte("must not write"), Mode: 0600, UID: os.Getuid(), GID: os.Getgid()}, "../escape.conf": {Data: []byte("escape"), Mode: 0600, UID: os.Getuid(), GID: os.Getgid()}}}
			raw, _ := json.Marshal(bad)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := run("op1", "restore"); err == nil {
				t.Fatal("accepted unsafe snapshot path")
			}
			if raw, err := os.ReadFile(filepath.Join(root, "jail.local")); err != nil || string(raw) != "unchanged" {
				t.Fatal("restore changed a file before validating all backup entries")
			}
		})
	}
}

func TestConfigurationBackupRejectsSymlinkFilesAndDirectories(t *testing.T) {
	for _, transport := range []string{"local", "ssh"} {
		for _, link := range []string{"jail.local", "jail.d", ".fail2ban-ui-operations"} {
			t.Run(transport+"/"+link, func(t *testing.T) {
				root := t.TempDir()
				outside := t.TempDir()
				if link == "jail.local" {
					outside = filepath.Join(outside, "target")
					if err := os.WriteFile(outside, []byte("untouched"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(outside, filepath.Join(root, link)); err != nil {
					t.Fatal(err)
				}
				if err := configurationBackupHarness(t, transport, root)("op1", "backup"); err == nil {
					t.Fatal("snapshot followed symlink")
				}
			})
		}
	}
}

func TestSSHConfigurationRollbackWithoutChownPermissionSkipsUnchangedFiles(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "filter.d"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{"jail.local": "original jail\n", "filter.d/unchanged.conf": "root-owned original\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(raw), 0640); err != nil {
			t.Fatal(err)
		}
	}
	run := configurationBackupHarness(t, "ssh", root)
	if err := run("op1", "backup"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "jail.local"), []byte("invalid jail\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "jail.local"), 0600); err != nil {
		t.Fatal(err)
	}
	// Emulate an unprivileged SSH account..
	prefix := `import os
original_replace=os.replace
def restricted_replace(src,dst):
 if dst.endswith('/filter.d/unchanged.conf'): raise PermissionError('unchanged root-owned file must not be rewritten')
 return original_replace(src,dst)
def denied_chown(fd,uid,gid): raise PermissionError('SSH account cannot restore root ownership')
os.replace=restricted_replace
os.fchown=denied_chown
`
	if out, err := exec.Command(python, "-c", prefix+remoteConfigBackupScript, root, "op1", "restore").CombinedOutput(); err != nil {
		t.Fatalf("unprivileged rollback failed: %v %s", err, out)
	}
	if raw, err := os.ReadFile(filepath.Join(root, "jail.local")); err != nil || string(raw) != "original jail\n" {
		t.Fatalf("config not recovered: %q %v", raw, err)
	}
	if info, err := os.Stat(filepath.Join(root, "jail.local")); err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("config mode not recovered: %v %v", info, err)
	}
}
