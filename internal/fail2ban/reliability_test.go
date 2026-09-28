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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func regressionConnector(t *testing.T) *SSHConnector {
	sc := testSSHConnector()
	sc.server.SSHKeyPath = filepath.Join(t.TempDir(), "key")
	sc.fail2banPath = t.TempDir()
	return sc
}
func TestRegressionFilterLogsRemainData(t *testing.T) {
	sc := regressionConnector(t)
	marker := filepath.Join(t.TempDir(), "executed")
	received := filepath.Join(t.TempDir(), "received")
	t.Setenv("REVIEW_RECEIVED", received)
	withFakeBinary(t, "fail2ban-regex", "cat \"$1\" > \"$REVIEW_RECEIVED\"\n")
	withFakeSSH(t, `case "$*" in *"-O check"*) exit 0 ;; esac
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift; shift
exec sh -c "$*"
`)
	_, _, err := sc.TestFilter(context.Background(), "sshd", []string{"F2B_FILTER_TEST_LOG", "printf injected > '" + marker + "'", "exit 0"}, "[Definition]\nfailregex = ^<HOST>$\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("pasted log lines executed a shell command")
	}
	// A TestFilter that did nothing would also pass the check above; require the lines arrived as data.
	got, err := os.ReadFile(received)
	if err != nil || !strings.Contains(string(got), "printf injected > '"+marker+"'") {
		t.Fatalf("log lines did not reach fail2ban-regex verbatim: %q %v", got, err)
	}
}
func TestRegressionUnreadableJailLocalMustNotBeOverwritten(t *testing.T) {
	sc := regressionConnector(t)
	record := filepath.Join(t.TempDir(), "writes")
	t.Setenv("REVIEW_WRITES", record)
	withFakeSSH(t, `case "$*" in
 *"-O check"*) exit 0 ;;
 *"target="*) echo attempted >> "$REVIEW_WRITES"; exit 0 ;;
 *"cat "*) echo "cat: jail.local: Permission denied" >&2; exit 1 ;;
 esac
 exit 0
`)
	err := sc.EnsureJailLocalStructure(context.Background())
	if _, statErr := os.Stat(record); statErr == nil {
		t.Fatalf("write attempted after ownership check failed; returned error = %v", err)
	}
	if err == nil {
		t.Fatal("an unreadable jail.local must be reported, not treated as success")
	}
}
func TestRegressionSSHReadFailureMustNotBecomeEmptyJail(t *testing.T) {
	sc := regressionConnector(t)
	withFakeSSH(t, `case "$*" in *"-O check"*) exit 0 ;; esac
echo "ssh: connection reset by peer" >&2
exit 255
`)
	content, _, err := sc.GetJailConfig(context.Background(), "sshd")
	if err == nil {
		t.Fatalf("transport failure reported as successful config read: %q", content)
	}
}
func TestRegressionChangingSSHIdentityClosesOldMaster(t *testing.T) {
	sc := regressionConnector(t)
	sc.server.Type = "ssh"
	replacement := sc.server
	replacement.SSHUser = "replacement-user"
	if !sshTunnelConfigChanged(sc, replacement) {
		t.Fatal("changing SSH user without reverse tunnel retains the old control master")
	}
	next := &SSHConnector{server: replacement}
	if sc.controlPath() == next.controlPath() {
		t.Fatal("different SSH users share the same control path")
	}
}
func TestRegressionTunnelCallbackPreservesBasePath(t *testing.T) {
	t.Setenv("BASE_PATH", "/dev")
	sc := regressionConnector(t)
	sc.tunnelPort = 9443
	if !strings.HasSuffix(sc.actionCallbackURL(), "/dev") {
		t.Fatalf("tunnel callback URL loses BASE_PATH: %s", sc.actionCallbackURL())
	}
}
func TestRegressionJailOverridesMergeWithConf(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "service.conf"), []byte("[sshd]\nenabled = true\n[other]\nenabled = true\n"), 0600)
	os.WriteFile(filepath.Join(dir, "service.local"), []byte("[sshd]\nmaxretry = 9\n"), 0600)
	script, err := buildJailDirDumpScript(dir)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	acc := newJailAccumulator()
	for _, file := range parseRemoteFileDump(string(out)) {
		acc.add(file.content, jailFileType(file.path))
	}
	if len(acc.jails) != 2 {
		t.Fatalf("jails hidden by partial .local override: %+v", acc.jails)
	}
	if !acc.jails[0].Enabled {
		t.Fatal("partial override falsely disables jail")
	}
}
func TestRegressionTunnelMustFailWhenForwardCannotBind(t *testing.T) {
	sc := regressionConnector(t)
	sc.tunnelPort = 9443
	sc.forwardPort = 8080
	args := append([]string{"-G", "-F", "/dev/null"}, sc.buildMasterSSHArgs([]string{"true"})...)
	out, err := exec.Command("ssh", args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "exitonforwardfailure yes") {
		t.Fatal("effective OpenSSH configuration permits success when reverse forwarding fails")
	}
}

func TestRegressionFailedReloadRemainsPending(t *testing.T) {
	sc := regressionConnector(t)
	sc.server.ID = "review"
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})
	os.MkdirAll(filepath.Join(sc.fail2banPath, "action.d"), 0700)
	os.WriteFile(CustomActionFile(sc.fail2banPath), []byte("old action\n"), 0600)
	os.WriteFile(JailLocal(sc.fail2banPath), []byte("[DEFAULT]\naction=ui-custom-action\n"), 0600)
	withFakeBinary(t, "sudo", "exec \"$@\"\n")
	// Dispatch on the command word: validation and reload both lead with -c <root>.
	withFakeBinary(t, "fail2ban-client", `for a in "$@"; do last="$a"; done
case "$last" in
 -t) exit 0 ;;
 banned) echo "[{'sshd': []}]"; exit 0 ;;
 reload) echo 'simulated reload failure' >&2; exit 1 ;;
esac
exit 1
`)
	withFakeSSH(t, `case "$*" in *"-O check"*) exit 0 ;; esac
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift; shift
exec sh -c "$*"
`)
	manager := &Manager{connectors: map[string]Connector{"review": sc}}
	before, err := sc.GetJailSummary(context.Background())
	if err != nil || !before.ActionFileDrifted {
		t.Fatalf("invalid setup: %v %+v", err, before)
	}
	manager.RepairActionFile(context.Background(), "review")
	after, err := sc.GetJailSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !after.ActionFileDrifted || !manager.ConfigSyncStatus("review").Pending {
		t.Fatal("failed reload must remain pending")
	}
	withFakeBinary(t, "fail2ban-client", "echo OK\n")
	manager.RetryPendingConfig(context.Background())
	if manager.ConfigSyncStatus("review").Pending {
		t.Fatal("background retry did not clear the pending reload")
	}
	if sc.reloadPending.Load() {
		t.Fatal("connector still reports pending reload after recovery")
	}
}
