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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

func withFakeBinary(t *testing.T, name, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" + body
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("failed to write fake %s: %v", name, err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func withFakeSSH(t *testing.T, body string) {
	t.Helper()
	withFakeBinary(t, "ssh", body)
}

func testSSHConnector() *SSHConnector {
	return &SSHConnector{
		server:     shared.Fail2banServer{Name: "test", Host: "10.0.0.1", SSHUser: "f2b"},
		sessionSem: make(chan struct{}, sshMaxConcurrentSessions),
	}
}

func TestExecSSHStreamsStaySeparate(t *testing.T) {
	withFakeSSH(t, `echo "real output"
echo "mux noise" >&2
exit 0
`)
	sc := testSSHConnector()
	stdout, stderr, err := sc.execSSH(context.Background(), []string{"whatever"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(stdout) != "real output" {
		t.Fatalf("stdout = %q, want just the real output", stdout)
	}
	if !strings.Contains(stderr, "mux noise") {
		t.Fatalf("stderr = %q, want the noise kept on stderr", stderr)
	}
	if strings.Contains(stdout, "mux noise") {
		t.Fatalf("stderr must never leak into stdout, got %q", stdout)
	}
}

func TestExecSSHPropagatesExitStatus(t *testing.T) {
	withFakeSSH(t, `echo "partial"
echo "failure detail" >&2
exit 3
`)
	sc := testSSHConnector()
	stdout, stderr, err := sc.execSSH(context.Background(), []string{"whatever"}, nil)
	if err == nil {
		t.Fatal("expected a non-zero exit to produce an error")
	}
	if !strings.Contains(stdout, "partial") || !strings.Contains(stderr, "failure detail") {
		t.Fatalf("captured output must survive a failure: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestExecSSHTransportErrorDetection(t *testing.T) {
	t.Run("ssh dying silently with 255 is a transport error", func(t *testing.T) {
		withFakeSSH(t, "exit 255\n")
		sc := testSSHConnector()
		_, stderr, err := sc.execSSH(context.Background(), []string{"whatever"}, nil)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !isSSHTransportError(err, stderr) {
			t.Fatalf("exit 255 with no stderr must be a transport error, got %v", err)
		}
	})

	t.Run("ssh connection failure is a transport error", func(t *testing.T) {
		withFakeSSH(t, `echo "ssh: connect to host 10.0.0.1 port 22: Connection refused" >&2
exit 255
`)
		sc := testSSHConnector()
		_, stderr, err := sc.execSSH(context.Background(), []string{"whatever"}, nil)
		if !isSSHTransportError(err, stderr) {
			t.Fatalf("a refused connection must be a transport error, got stderr=%q err=%v", stderr, err)
		}
	})

	t.Run("remote fail2ban error exiting 255 is NOT a transport error", func(t *testing.T) {
		withFakeSSH(t, `echo "Sorry but the jail 'nosuchjail' does not exist" >&2
exit 255
`)
		sc := testSSHConnector()
		_, stderr, err := sc.execSSH(context.Background(), []string{"whatever"}, nil)
		if err == nil {
			t.Fatal("expected an error")
		}
		if isSSHTransportError(err, stderr) {
			t.Fatalf("a remote command failure must not trigger a master re-dial: stderr=%q", stderr)
		}
	})
}

func TestExecSSHNonTransportExitIsNotRetried(t *testing.T) {
	withFakeSSH(t, "exit 1\n")
	sc := testSSHConnector()
	_, stderr, err := sc.execSSH(context.Background(), []string{"whatever"}, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if isSSHTransportError(err, stderr) {
		t.Fatalf("exit 1 is a remote command failure, not a transport error: %v", err)
	}
}

func TestExecSSHCancellationDoesNotHang(t *testing.T) {
	// Emits output, then sleeps far longer than the test is willing to wait
	withFakeSSH(t, `echo "before sleep"
sleep 30
`)
	sc := testSSHConnector()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	var stdout string
	var err error
	go func() {
		stdout, _, err = sc.execSSH(ctx, []string{"whatever"}, nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("execSSH did not return after context cancellation")
	}
	if err == nil {
		t.Fatal("expected a cancellation error")
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("expected the context error, got %v", err)
	}
	if !strings.Contains(stdout, "before sleep") {
		t.Fatalf("output captured before cancellation must be returned, got %q", stdout)
	}
}

func TestExecSSHStdinIsDelivered(t *testing.T) {
	withFakeSSH(t, "cat\n")
	sc := testSSHConnector()
	stdout, _, err := sc.execSSH(context.Background(), []string{"sh", "-s"}, strings.NewReader("piped payload\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "piped payload") {
		t.Fatalf("stdin must reach the remote command, got %q", stdout)
	}
}

func TestEnsureActionUsesProbedConfigRoot(t *testing.T) {
	log := filepath.Join(t.TempDir(), "invocations")
	t.Setenv("F2BUI_TEST_SSH_LOG", log)
	withFakeSSH(t, `case "$*" in
  *"-O check"*) exit 0 ;;
  *"test -d"*)  echo "/config/fail2ban"; exit 0 ;;
esac
printf '%s\n' "$*" >> "$F2BUI_TEST_SSH_LOG"
exit 0
`)
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})

	sc := testSSHConnector()
	if err := sc.ensureAction(context.Background()); err != nil {
		t.Fatalf("ensureAction failed: %v", err)
	}

	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("fake ssh recorded nothing: %v", err)
	}
	recorded := string(raw)
	if !strings.Contains(recorded, "/config/fail2ban/action.d/ui-custom-action.conf") {
		t.Fatalf("action file must follow the probed root, got:\n%s", recorded)
	}
	if strings.Contains(recorded, "/etc/fail2ban/action.d") {
		t.Fatalf("action file must not go to the hardcoded default root, got:\n%s", recorded)
	}
	if strings.Contains(recorded, "sudo") {
		t.Fatalf("the action write must run as the service account, got:\n%s", recorded)
	}
	if !strings.Contains(recorded, "http://127.0.0.1:8080/api/ban") {
		t.Fatalf("the current callback URL must be written into the file, got:\n%s", recorded)
	}
}

func TestGetJailSummaryReportsActionDrift(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})

	summaryOutput := func(actionContent string) string {
		return strings.Join([]string{
			"[{'sshd': ['1.2.3.4']}]",
			bannedSectionEnd,
			batchJailLocalBegin,
			"[DEFAULT]",
			"action = ui-custom-action",
			batchActionBegin,
			actionContent,
			batchEnd,
			"",
		}, "\n")
	}

	t.Run("matching action file is not drifted", func(t *testing.T) {
		sc := testSSHConnector()
		sc.fail2banPath = DefaultConfigRoot
		desired, err := sc.desiredActionConfig()
		if err != nil {
			t.Fatal(err)
		}
		want := strings.TrimSuffix(desired, "\n")
		withFakeSSH(t, "cat >/dev/null 2>&1\ncat <<'OUT'\n"+summaryOutput(want)+"OUT\nexit 0\n")

		got, err := sc.GetJailSummary(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ActionFileDrifted {
			t.Fatal("an up-to-date action file must not be reported as drifted")
		}
	})

	t.Run("stale callback URL is drifted", func(t *testing.T) {
		sc := testSSHConnector()
		sc.fail2banPath = DefaultConfigRoot
		desired, err := sc.desiredActionConfig()
		if err != nil {
			t.Fatal(err)
		}
		stale := strings.ReplaceAll(strings.TrimSuffix(desired, "\n"),
			"http://127.0.0.1:8080", "http://old.example.com")
		withFakeSSH(t, "cat >/dev/null 2>&1\ncat <<'OUT'\n"+summaryOutput(stale)+"OUT\nexit 0\n")

		got, err := sc.GetJailSummary(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.ActionFileDrifted {
			t.Fatal("an action file with an outdated callback URL must be reported as drifted")
		}
	})
}

// socket path with spaces must reach sudo as one argument, not as extra fail2ban-client options.
func TestRunFail2banCommandQuotesEveryWord(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "cmd")
	t.Setenv("F2BUI_TEST_SSH_LOG", logFile)
	withFakeSSH(t, `case "$*" in *"-O check"*) exit 0 ;; esac
for a in "$@"; do last="$a"; done
printf '%s' "$last" > "$F2BUI_TEST_SSH_LOG"
echo pong
`)
	sc := testSSHConnector()
	sc.server.SocketPath = "/run/f2b.sock -c /tmp/evil"
	if _, err := sc.runFail2banCommand(context.Background(), "ping"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	remote, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	// Replay exactly what the remote shell receives and see how it splits.
	out, err := exec.Command("sh", "-c", `eval "set -- $1"; printf '%s\n' "$@"`, "_", string(remote)).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	want := []string{"sudo", "fail2ban-client", "-s", "/run/f2b.sock -c /tmp/evil", "ping"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("remote shell split the command into %q, want %q", got, want)
	}
}

func TestGetFail2banPathOnlyTrustsKnownRoots(t *testing.T) {
	cases := []struct{ name, out, want string }{
		{"container root", "/config/fail2ban", "/config/fail2ban"},
		{"default root", "/etc/fail2ban", "/etc/fail2ban"},
		{"login banner before the answer", "Welcome to host\n/config/fail2ban", "/config/fail2ban"},
		{"unexpected output", "/tmp/x;id", DefaultConfigRoot},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFakeSSH(t, "case \"$*\" in *\"-O check\"*) exit 0 ;; esac\nprintf '"+tc.out+"\\n'\n")
			sc := testSSHConnector()
			if got := sc.getFail2banPath(context.Background()); got != tc.want {
				t.Fatalf("getFail2banPath() = %q, want %q", got, tc.want)
			}
		})
	}
	t.Run("unexpected output is not cached", func(t *testing.T) {
		withFakeSSH(t, "case \"$*\" in *\"-O check\"*) exit 0 ;; esac\nprintf 'garbage\\n'\n")
		sc := testSSHConnector()
		sc.getFail2banPath(context.Background())
		if sc.fail2banPath != "" {
			t.Fatalf("cached untrusted probe output %q", sc.fail2banPath)
		}
	})
}

func TestDeleteFilterRemovesBackupsOverSSH(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "cmd")
	t.Setenv("F2BUI_TEST_SSH_LOG", logFile)
	withFakeSSH(t, `case "$*" in
  *"-O check"*) exit 0 ;;
  *"test -d"*)  echo "/config/fail2ban"; exit 0 ;;
esac
for a in "$@"; do last="$a"; done
printf '%s' "$last" > "$F2BUI_TEST_SSH_LOG"
exit 0
`)
	sc := testSSHConnector()
	if err := sc.DeleteFilter(context.Background(), "apache-auth"); err != nil {
		t.Fatalf("DeleteFilter: %v", err)
	}
	remote, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", `eval "set -- $1"; printf '%s\n' "$@"`, "_", string(remote)).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	dir := "/config/fail2ban/filter.d/"
	want := []string{"rm", "-f", dir + "apache-auth.local", dir + "apache-auth.conf", dir + "apache-auth.local.f2bui.bak", dir + "apache-auth.conf.f2bui.bak"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("remote delete ran %q, want %q", got, want)
	}
}
