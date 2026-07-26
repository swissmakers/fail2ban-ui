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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// The following tests run against a fake ssh rather than a real host
func withFakeSSH(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" + body
	path := filepath.Join(dir, "ssh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("failed to write fake ssh: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
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
