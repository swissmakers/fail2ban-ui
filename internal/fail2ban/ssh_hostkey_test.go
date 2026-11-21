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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

const changedKeyBanner = `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:31qptbbgMC2I2FWQsTsaKadlJA0UUgZFHYOr+83qzlA.
Please contact your system administrator.
Add correct host key in /config/.ssh/known_hosts to get rid of this message.
Offending ED25519 key in /config/.ssh/known_hosts:1
Host key for [127.0.0.1]:2222 has changed and you have requested strict checking.
Host key verification failed.`

func hostKeyTestConnector() *SSHConnector {
	return &SSHConnector{server: shared.Fail2banServer{
		ID: "srv-1", Name: "mySSH", Host: "127.0.0.1", Port: 2222, SSHUser: "f2b",
	}}
}

func TestParseHostKeyError(t *testing.T) {
	sc := hostKeyTestConnector()

	t.Run("full banner", func(t *testing.T) {
		hk := sc.parseHostKeyError(changedKeyBanner, nil)
		if hk == nil {
			t.Fatal("banner must be classified as host-key error")
		}
		if hk.Fingerprint != "SHA256:31qptbbgMC2I2FWQsTsaKadlJA0UUgZFHYOr+83qzlA" {
			t.Errorf("fingerprint = %q", hk.Fingerprint)
		}
		if hk.Host != "127.0.0.1" || hk.ServerID != "srv-1" {
			t.Errorf("server identity not carried: %+v", hk)
		}
	})

	t.Run("bare verification failure", func(t *testing.T) {
		hk := sc.parseHostKeyError("Host key verification failed.", nil)
		if hk == nil {
			t.Fatal("bare failure must still be classified")
		}
		if hk.Fingerprint != "" {
			t.Errorf("no fingerprint expected, got %q", hk.Fingerprint)
		}
	})

	t.Run("unrelated errors are not classified", func(t *testing.T) {
		for _, s := range []string{"Permission denied (publickey).", "Connection refused", ""} {
			if hk := sc.parseHostKeyError(s, nil); hk != nil {
				t.Errorf("stderr %q must not be a host-key error", s)
			}
		}
	})
}

func TestHostKeyIssueRegistry(t *testing.T) {
	t.Cleanup(func() { pruneHostKeyIssues(map[string]struct{}{}) })

	if HostKeyIssue("reg-1") != nil {
		t.Fatal("registry must start empty for reg-1")
	}
	RecordHostKeyIssue(&SSHHostKeyError{ServerID: "reg-1", Fingerprint: "SHA256:aaa"})
	RecordHostKeyIssue(&SSHHostKeyError{ServerID: "reg-2", Fingerprint: "SHA256:bbb"})
	if got := HostKeyIssue("reg-1"); got == nil || got.Fingerprint != "SHA256:aaa" {
		t.Fatalf("recorded issue not returned: %+v", got)
	}

	// Overwrite with a newer fingerprint
	RecordHostKeyIssue(&SSHHostKeyError{ServerID: "reg-1", Fingerprint: "SHA256:ccc"})
	if got := HostKeyIssue("reg-1"); got.Fingerprint != "SHA256:ccc" {
		t.Fatalf("newer issue must overwrite, got %+v", got)
	}

	// Returned value is a copy
	HostKeyIssue("reg-1").Fingerprint = "mutated"
	if HostKeyIssue("reg-1").Fingerprint != "SHA256:ccc" {
		t.Fatal("HostKeyIssue must return a copy")
	}

	ClearHostKeyIssue("reg-1")
	if HostKeyIssue("reg-1") != nil {
		t.Fatal("cleared issue must be gone")
	}

	pruneHostKeyIssues(map[string]struct{}{})
	if HostKeyIssue("reg-2") != nil {
		t.Fatal("pruned issue must be gone")
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"SHA256:abc":    "SHA256:abc",
		"abc":           "SHA256:abc",
		"  SHA256:abc ": "SHA256:abc",
	}
	for in, want := range cases {
		if got := NormalizeFingerprint(in); got != want {
			t.Errorf("NormalizeFingerprint(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKnownHostsPattern(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"example.com", 0, "example.com"},
		{"example.com", 22, "example.com"},
		{"127.0.0.1", 2222, "[127.0.0.1]:2222"},
		{"2001:db8::1", 2222, "[2001:db8::1]:2222"},
	}
	for _, c := range cases {
		if got := knownHostsPattern(c.host, c.port); got != c.want {
			t.Errorf("knownHostsPattern(%q, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

func generateHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Starts an SSH server on 127.0.0.1 that presents the given host keys and returns its port.
func startHostKeyServer(t *testing.T, keys ...ssh.Signer) int {
	t.Helper()
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	for _, k := range keys {
		cfg.AddHostKey(k)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _, _, _ = ssh.NewServerConn(c, cfg)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestScanApprovedHostKey(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := ssh.NewSignerFromKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	ecSigner, err := ssh.NewSignerFromKey(ecPriv)
	if err != nil {
		t.Fatal(err)
	}
	edFP := ssh.FingerprintSHA256(edSigner.PublicKey())
	ecFP := ssh.FingerprintSHA256(ecSigner.PublicKey())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	both := startHostKeyServer(t, edSigner, ecSigner)
	// OpenSSH reports the ED25519 key while Go alone would negotiate ECDSA.
	for _, approved := range []string{edFP, ecFP} {
		key, presented, err := scanApprovedHostKey(ctx, "127.0.0.1", both, approved)
		if err != nil {
			t.Fatalf("approved %s: %v", approved, err)
		}
		if key == nil || ssh.FingerprintSHA256(key) != approved || presented != approved {
			t.Errorf("approved %s: got key %v, presented %s", approved, key, presented)
		}
	}

	key, presented, err := scanApprovedHostKey(ctx, "127.0.0.1", both, "SHA256:unknown")
	if err != nil || key != nil {
		t.Fatalf("unknown fingerprint must be a mismatch, got key %v, err %v", key, err)
	}
	if presented != edFP {
		t.Errorf("presented = %s, want the ED25519 key %s", presented, edFP)
	}

	ecdsaOnly := startHostKeyServer(t, ecSigner)
	key, _, err = scanApprovedHostKey(ctx, "127.0.0.1", ecdsaOnly, ecFP)
	if err != nil || key == nil {
		t.Fatalf("a server without an ED25519 key must still match its ECDSA key, got key %v, err %v", key, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if _, _, err := scanApprovedHostKey(ctx, "127.0.0.1", closed, edFP); err == nil {
		t.Error("an unreachable server must return an error")
	}
}

func TestKnownHostsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	key := generateHostKey(t)
	pattern := knownHostsPattern("127.0.0.1", 2222)

	if err := appendKnownHostEntry(khPath, pattern, key); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatal(err)
	}
	_, hosts, parsed, _, _, err := ssh.ParseKnownHosts(data)
	if err != nil {
		t.Fatalf("written entry must parse: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != pattern {
		t.Errorf("hosts = %v, want [%s]", hosts, pattern)
	}
	if ssh.FingerprintSHA256(parsed) != ssh.FingerprintSHA256(key) {
		t.Error("fingerprint mismatch after round trip")
	}

	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}
	if err := removeKnownHostEntries(context.Background(), khPath, pattern); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(khPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "127.0.0.1") {
		t.Errorf("entry must be removed, file still contains: %q", string(data))
	}
	if _, err := os.Stat(khPath + ".old"); !os.IsNotExist(err) {
		t.Error(".old backup must be deleted")
	}

	// Removing from a missing file is not an error.
	if err := removeKnownHostEntries(context.Background(), filepath.Join(dir, "missing"), pattern); err != nil {
		t.Errorf("missing file must not error: %v", err)
	}
}
