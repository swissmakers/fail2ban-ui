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
	"errors"
	"strings"
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

func TestResolveTunnelPort(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})

	cases := []struct {
		name string
		srv  shared.Fail2banServer
		want int
	}{
		{"explicit port", shared.Fail2banServer{Name: "s", TunnelPort: 9443}, 9443},
		{"zero falls back to UI port", shared.Fail2banServer{Name: "s"}, 8080},
		{"privileged port falls back to UI port", shared.Fail2banServer{Name: "s", TunnelPort: 80}, 8080},
		{"out of range falls back to UI port", shared.Fail2banServer{Name: "s", TunnelPort: 70000}, 8080},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveTunnelPort(tc.srv); got != tc.want {
				t.Fatalf("resolveTunnelPort(%+v) = %d, want %d", tc.srv.TunnelPort, got, tc.want)
			}
		})
	}
}

func TestResolveTunnelPortNoopProviderFallback(t *testing.T) {
	SetProvider(noopProvider{})
	defer SetProvider(noopProvider{})

	if got := resolveTunnelPort(shared.Fail2banServer{Name: "s"}); got != 8080 {
		t.Fatalf("resolveTunnelPort with noop provider = %d, want 8080", got)
	}
}

func TestActionCallbackURL(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})

	tunneled := &SSHConnector{server: shared.Fail2banServer{Name: "s"}, tunnelPort: 9443}
	if got := tunneled.actionCallbackURL(); got != "http://localhost:9443" {
		t.Fatalf("tunneled actionCallbackURL = %q, want http://localhost:9443", got)
	}

	direct := &SSHConnector{server: shared.Fail2banServer{Name: "s"}}
	if got := direct.actionCallbackURL(); got != "http://127.0.0.1:8080" {
		t.Fatalf("direct actionCallbackURL = %q, want provider callback URL", got)
	}
}

func TestBuildSSHArgsReverseTunnelForwardTarget(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})

	findR := func(args []string) string {
		for i, a := range args {
			if a == "-R" && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}

	custom := &SSHConnector{
		server:      shared.Fail2banServer{Host: "10.0.0.1", SSHUser: "f2b"},
		tunnelPort:  18080,
		forwardPort: 8080,
	}
	if got := findR(custom.buildMasterSSHArgs([]string{"true"})); got != "18080:localhost:8080" {
		t.Fatalf("master -R arg = %q, want 18080:localhost:8080", got)
	}

	deflt := &SSHConnector{
		server:      shared.Fail2banServer{Host: "10.0.0.1", SSHUser: "f2b"},
		tunnelPort:  8080,
		forwardPort: 8080,
	}
	if got := findR(deflt.buildMasterSSHArgs([]string{"true"})); got != "8080:localhost:8080" {
		t.Fatalf("master -R arg = %q, want 8080:localhost:8080", got)
	}

	noTunnel := &SSHConnector{server: shared.Fail2banServer{Host: "10.0.0.1", SSHUser: "f2b"}}
	if got := findR(noTunnel.buildMasterSSHArgs([]string{"true"})); got != "" {
		t.Fatalf("unexpected -R arg %q for connector without tunnel", got)
	}
}

func TestBuildSSHArgsMasterSessionSplit(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})

	hasOpt := func(args []string, opt string) bool {
		for i, a := range args {
			if a == "-o" && i+1 < len(args) && args[i+1] == opt {
				return true
			}
		}
		return false
	}
	countR := func(args []string) int {
		n := 0
		for _, a := range args {
			if a == "-R" {
				n++
			}
		}
		return n
	}

	tunneled := &SSHConnector{
		server:      shared.Fail2banServer{Host: "10.0.0.1", SSHUser: "f2b"},
		tunnelPort:  9443,
		forwardPort: 8080,
	}

	session := tunneled.buildSSHArgs([]string{"true"})
	if countR(session) != 0 {
		t.Fatalf("tunnel session args must not carry -R, got: %v", session)
	}
	if !hasOpt(session, "ControlMaster=no") {
		t.Fatalf("tunnel session args must use ControlMaster=no, got: %v", session)
	}

	master := tunneled.buildMasterSSHArgs([]string{"true"})
	if countR(master) != 1 {
		t.Fatalf("master args must carry exactly one -R, got: %v", master)
	}
	if !hasOpt(master, "ControlMaster=auto") || !hasOpt(master, "ControlPersist=0") {
		t.Fatalf("master args must use ControlMaster=auto + ControlPersist=0, got: %v", master)
	}

	plain := &SSHConnector{server: shared.Fail2banServer{Host: "10.0.0.1", SSHUser: "f2b"}}
	plainArgs := plain.buildSSHArgs([]string{"true"})
	if !hasOpt(plainArgs, "ControlMaster=auto") || !hasOpt(plainArgs, "ControlPersist=300") {
		t.Fatalf("non-tunnel session args changed unexpectedly: %v", plainArgs)
	}
	if countR(plainArgs) != 0 {
		t.Fatalf("non-tunnel args must not carry -R, got: %v", plainArgs)
	}
}

const sshMuxNoise = "mux_client_request_session: session request failed: Session open refused by peer\r\n" +
	"ControlSocket /tmp/ssh_control_srv-04e7c5bf2beffe52_172_16_10_13 already exists, disabling multiplexing\n"

func TestSelectCommandOutput(t *testing.T) {
	jailFile := "[swissmakers-apache-scanner]\nenabled = true\n"

	t.Run("success returns stdout only, stderr noise dropped", func(t *testing.T) {
		out, err := selectCommandOutput("ssh", jailFile, sshMuxNoise, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(out, "mux_client_request_session") || strings.Contains(out, "ControlSocket") {
			t.Fatalf("stderr noise leaked into output: %q", out)
		}
		if out != strings.TrimSpace(jailFile) {
			t.Fatalf("output = %q, want trimmed stdout", out)
		}
	})

	t.Run("failure folds both streams into the error", func(t *testing.T) {
		out, err := selectCommandOutput("ssh", "partial", "sudo: a password is required", errors.New("exit status 1"))
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "sudo: a password is required") || !strings.Contains(err.Error(), "partial") {
			t.Fatalf("error should contain both streams, got: %v", err)
		}
		if !strings.Contains(out, "sudo: a password is required") {
			t.Fatalf("returned output should keep error-path matching working, got: %q", out)
		}
	})
}

func TestBuildRemoteWriteScript(t *testing.T) {
	t.Run("single quotes are preserved verbatim", func(t *testing.T) {
		content := `ignoreregex = [^"]*(?:Let's Encrypt|Uptime)[^"]*` + "\n"
		script, err := buildRemoteWriteScript("/etc/fail2ban/filter.d/test.local", content)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(script, "Let's Encrypt") {
			t.Fatalf("content was altered: %q", script)
		}
		if strings.Contains(script, `'"'"'`) {
			t.Fatalf("content must not be shell-escaped inside a quoted heredoc: %q", script)
		}
	})

	t.Run("delimiter collision is rejected", func(t *testing.T) {
		if _, err := buildRemoteWriteScript("/tmp/f", "a\n"+remoteWriteDelimiter+"\nb\n"); err == nil {
			t.Fatal("expected error for content containing the heredoc delimiter")
		}
	})

	t.Run("unsafe path is rejected", func(t *testing.T) {
		if _, err := buildRemoteWriteScript("/tmp/f'oo", "x\n"); err == nil {
			t.Fatal("expected error for path containing a single quote")
		}
	})

	t.Run("exactly one trailing newline", func(t *testing.T) {
		script, err := buildRemoteWriteScript("/tmp/f", "line1\nline2\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "cat > '/tmp/f' <<'" + remoteWriteDelimiter + "'\nline1\nline2\n" + remoteWriteDelimiter + "\n"
		if script != want {
			t.Fatalf("script = %q, want %q", script, want)
		}
	})
}

func TestParseLogpathProbe(t *testing.T) {
	t.Run("NOACCESS marker -> inaccessible sentinel", func(t *testing.T) {
		_, err := parseLogpathProbe(logpathMarkerNoAccess + "\n")
		if !errors.Is(err, ErrLogpathInaccessible) {
			t.Fatalf("want ErrLogpathInaccessible, got %v", err)
		}
	})
	t.Run("NODIR marker -> empty, no error", func(t *testing.T) {
		files, err := parseLogpathProbe(logpathMarkerNoDir + "\n")
		if err != nil || len(files) != 0 {
			t.Fatalf("want empty/no-error, got files=%v err=%v", files, err)
		}
	})
	t.Run("file list parsed", func(t *testing.T) {
		files, err := parseLogpathProbe("/var/log/httpd/access_log\n/var/log/httpd/ssl_access_log\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(files) != 2 || files[0] != "/var/log/httpd/access_log" {
			t.Fatalf("unexpected files: %v", files)
		}
	})
	t.Run("empty output -> no files, no error", func(t *testing.T) {
		files, err := parseLogpathProbe("\n  \n")
		if err != nil || len(files) != 0 {
			t.Fatalf("want empty/no-error, got files=%v err=%v", files, err)
		}
	})
}

func TestParseRemoteFileDump(t *testing.T) {
	t.Run("two files with trailing newlines", func(t *testing.T) {
		out := batchFileBegin + "/etc/fail2ban/jail.d/a.local\n[a]\nenabled = true\n" + batchFileEnd + "\n" +
			batchFileBegin + "/etc/fail2ban/jail.d/b.local\n[b]\nenabled = false\n" + batchFileEnd + "\n"
		files := parseRemoteFileDump(out)
		if len(files) != 2 {
			t.Fatalf("want 2 files, got %+v", files)
		}
		if files[0].path != "/etc/fail2ban/jail.d/a.local" || files[0].content != "[a]\nenabled = true" {
			t.Fatalf("file 0 wrong: %+v", files[0])
		}
		if files[1].content != "[b]\nenabled = false" {
			t.Fatalf("file 1 wrong: %+v", files[1])
		}
	})

	t.Run("file without trailing newline glues the end marker", func(t *testing.T) {
		out := batchFileBegin + "/etc/fail2ban/jail.d/x.local\n[x]\nenabled = true" + batchFileEnd + "\n"
		files := parseRemoteFileDump(out)
		if len(files) != 1 || files[0].content != "[x]\nenabled = true" {
			t.Fatalf("glued end marker not recovered: %+v", files)
		}
	})

	t.Run("empty output", func(t *testing.T) {
		if files := parseRemoteFileDump(""); len(files) != 0 {
			t.Fatalf("want no files, got %+v", files)
		}
	})
}

func TestBuildJailDirDumpScript(t *testing.T) {
	t.Run("emits framed local files then conf files without a local sibling", func(t *testing.T) {
		script, err := buildJailDirDumpScript("/etc/fail2ban/jail.d")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(script, "'/etc/fail2ban/jail.d'/*.local") {
			t.Fatalf("missing quoted .local glob: %s", script)
		}
		if !strings.Contains(script, `[ ! -f "${f%.conf}.local" ]`) {
			t.Fatalf(".conf files must be skipped when a .local sibling exists: %s", script)
		}
		if !strings.Contains(script, batchFileBegin) || !strings.Contains(script, batchFileEnd) {
			t.Fatalf("missing framing markers: %s", script)
		}
		if strings.Contains(script, "python") {
			t.Fatalf("script must not depend on python: %s", script)
		}
		if strings.Contains(script, "2>&1") {
			t.Fatalf("stderr must never be merged into stdout: %s", script)
		}
	})

	t.Run("unsafe directory is rejected", func(t *testing.T) {
		if _, err := buildJailDirDumpScript("/etc/fail2'ban/jail.d"); err == nil {
			t.Fatal("expected an error for a path containing a single quote")
		}
	})
}

// Remote commands and their output can be enormous (generated scripts, whole
// config trees). Every log line is also broadcast to the browser console
// panel, so these must stay bounded.
func TestSummarizeRemoteCommand(t *testing.T) {
	t.Run("single-line command is kept verbatim", func(t *testing.T) {
		got := summarizeRemoteCommand([]string{"sudo", "fail2ban-client", "status"})
		if got != "sudo fail2ban-client status" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("multi-line script collapses to first line plus size", func(t *testing.T) {
		script := "echo 'F2BUI_JAIL_BEGIN:sshd'\nsudo fail2ban-client status 'sshd'\necho done\n"
		got := summarizeRemoteCommand([]string{script})
		if !strings.HasPrefix(got, "echo 'F2BUI_JAIL_BEGIN:sshd'") {
			t.Fatalf("first line must be kept, got %q", got)
		}
		if strings.Contains(got, "fail2ban-client status") {
			t.Fatalf("script body must not be logged, got %q", got)
		}
		if !strings.Contains(got, "3 lines") {
			t.Fatalf("expected a line count, got %q", got)
		}
		if strings.Contains(got, "\n") {
			t.Fatalf("summary must be a single line, got %q", got)
		}
	})

	t.Run("huge single-line command is truncated", func(t *testing.T) {
		got := summarizeRemoteCommand([]string{strings.Repeat("x", 10000)})
		if len(got) > maxLoggedOutputBytes+64 {
			t.Fatalf("summary too long: %d bytes", len(got))
		}
		if !strings.Contains(got, "truncated") {
			t.Fatalf("expected a truncation marker, got %q", got[:80])
		}
	})
}

func TestSummarizeSSHInvocation(t *testing.T) {
	command := []string{"echo one\necho two\n"}
	args := []string{"-o", "ControlMaster=no", "-R", "3082:localhost:3082", "user@host"}
	args = append(args, command...)

	got := summarizeSSHInvocation(args, command)
	// The ssh options are what matters when diagnosing connection problems.
	if !strings.Contains(got, "ControlMaster=no") || !strings.Contains(got, "-R 3082:localhost:3082") {
		t.Fatalf("ssh options must be preserved, got %q", got)
	}
	if strings.Contains(got, "echo two") {
		t.Fatalf("script body must not be logged, got %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("log line must be single-line, got %q", got)
	}
}

func TestTruncateForLog(t *testing.T) {
	if got := truncateForLog("short", 100); got != "short" {
		t.Fatalf("under-limit input must pass through, got %q", got)
	}
	got := truncateForLog(strings.Repeat("a", 500), 100)
	if !strings.HasPrefix(got, strings.Repeat("a", 100)) {
		t.Fatalf("head must be preserved, got %q", got)
	}
	if !strings.Contains(got, "500 bytes total") {
		t.Fatalf("expected the original size in the marker, got %q", got)
	}
}

func TestSelectCommandOutputCapsErrorPayload(t *testing.T) {
	huge := strings.Repeat("secret-config-line\n", 5000)
	out, err := selectCommandOutput("ssh", huge, "", errors.New("exit status 1"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(err.Error()) > maxLoggedOutputBytes+256 {
		t.Fatalf("error message must be capped, got %d bytes", len(err.Error()))
	}
	// Callers pattern-match on the returned output, so it stays complete.
	if len(out) < len(huge)-1 {
		t.Fatalf("returned output must not be truncated, got %d of %d bytes", len(out), len(huge))
	}
}

func TestSplitFilterTestOutput(t *testing.T) {
	t.Run("marker extracted and stripped from output", func(t *testing.T) {
		out, path := splitFilterTestOutput("Running tests\n" + filterPathMarker + "/etc/fail2ban/filter.d/sshd.conf\nLines: 1 matched\n")
		if path != "/etc/fail2ban/filter.d/sshd.conf" {
			t.Fatalf("filter path = %q", path)
		}
		if strings.Contains(out, filterPathMarker) {
			t.Fatalf("marker must not remain in output: %q", out)
		}
		if !strings.Contains(out, "Lines: 1 matched") {
			t.Fatalf("regex output must be preserved: %q", out)
		}
	})

	t.Run("missing marker yields empty path", func(t *testing.T) {
		out, path := splitFilterTestOutput("some failure\n")
		if path != "" {
			t.Fatalf("expected empty path, got %q", path)
		}
		if !strings.Contains(out, "some failure") {
			t.Fatalf("output must be preserved: %q", out)
		}
	})
}

func TestBuildConfigTreeDumpScript(t *testing.T) {
	script, err := buildConfigTreeDumpScript("/etc/fail2ban")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"'/etc/fail2ban'", "-name '*.conf'", "-name '*.local'", batchFileBegin, batchFileEnd} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q: %s", want, script)
		}
	}
	if strings.Contains(script, "python") {
		t.Fatalf("config tree dump must not depend on python: %s", script)
	}
	if strings.Contains(script, "2>&1") {
		t.Fatalf("stderr must never be merged into stdout: %s", script)
	}
	if _, err := buildConfigTreeDumpScript("/etc/fail2'ban"); err == nil {
		t.Fatal("expected an error for a path containing a single quote")
	}
}

func TestJailFileType(t *testing.T) {
	if got := jailFileType("/etc/fail2ban/jail.d/sshd.local"); got != "local" {
		t.Fatalf("jailFileType(.local) = %q, want local", got)
	}
	if got := jailFileType("/etc/fail2ban/jail.d/sshd.conf"); got != "conf" {
		t.Fatalf("jailFileType(.conf) = %q, want conf", got)
	}
}

// End-to-end of the GetAllJails parse path against output shaped exactly like
// the remote shell produces it, including a file with no trailing newline.
func TestJailDirDumpParsesIntoAccumulator(t *testing.T) {
	out := batchFileBegin + "/etc/fail2ban/jail.d/noeol.local\n[noeol]\nenabled = true" + batchFileEnd + "\n" +
		batchFileBegin + "/etc/fail2ban/jail.d/sshd.local\n[sshd]\nenabled = true\n" + batchFileEnd + "\n" +
		batchFileBegin + "/etc/fail2ban/jail.d/nginx.conf\n[nginx]\nenabled = false\n" + batchFileEnd + "\n"

	acc := newJailAccumulator()
	for _, f := range parseRemoteFileDump(out) {
		acc.add(f.content, jailFileType(f.path))
	}

	byName := map[string]bool{}
	for _, j := range acc.jails {
		byName[j.JailName] = j.Enabled
	}
	if len(acc.jails) != 3 {
		t.Fatalf("expected 3 jails, got %+v", acc.jails)
	}
	if !byName["noeol"] {
		t.Fatalf("jail from a file without a trailing newline must parse as enabled: %+v", acc.jails)
	}
	if !byName["sshd"] || byName["nginx"] {
		t.Fatalf("unexpected enabled states: %+v", acc.jails)
	}
}

func TestSSHTunnelConfigChanged(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})

	base := shared.Fail2banServer{
		Type: "ssh", Host: "10.0.0.1", Port: 22, SSHUser: "f2b", SSHKeyPath: "/config/.ssh/id",
		ReverseTunnelEnabled: true, TunnelPort: 9443,
	}
	tunneled := &SSHConnector{server: base, tunnelPort: 9443}

	cases := []struct {
		name   string
		old    *SSHConnector
		mutate func(shared.Fail2banServer) shared.Fail2banServer
		want   bool
	}{
		{"unchanged", tunneled, func(s shared.Fail2banServer) shared.Fail2banServer { return s }, false},
		{"no old tunnel, tunnel newly enabled", &SSHConnector{server: base}, func(s shared.Fail2banServer) shared.Fail2banServer { return s }, true},
		{"no old tunnel, tunnel stays off", &SSHConnector{server: base}, func(s shared.Fail2banServer) shared.Fail2banServer { s.ReverseTunnelEnabled = false; return s }, false},
		{"tunnel disabled", tunneled, func(s shared.Fail2banServer) shared.Fail2banServer { s.ReverseTunnelEnabled = false; return s }, true},
		{"type changed", tunneled, func(s shared.Fail2banServer) shared.Fail2banServer { s.Type = "agent"; return s }, true},
		{"port changed", tunneled, func(s shared.Fail2banServer) shared.Fail2banServer { s.TunnelPort = 9444; return s }, true},
		{"host changed", tunneled, func(s shared.Fail2banServer) shared.Fail2banServer { s.Host = "10.0.0.2"; return s }, true},
		{"ssh user changed", tunneled, func(s shared.Fail2banServer) shared.Fail2banServer { s.SSHUser = "other"; return s }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sshTunnelConfigChanged(tc.old, tc.mutate(base)); got != tc.want {
				t.Fatalf("sshTunnelConfigChanged = %v, want %v", got, tc.want)
			}
		})
	}
}
