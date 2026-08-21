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

package shared

import "testing"

func TestValidateHost(t *testing.T) {
	valid := []string{"10.0.0.1", "fail2ban.example.com", "srv-01", "2001:db8::1", "host_name"}
	for _, h := range valid {
		if err := ValidateHost(h); err != nil {
			t.Errorf("ValidateHost(%q) should pass: %v", h, err)
		}
	}
	invalid := []string{"", " 10.0.0.1", "10.0.0.1 ", "-oProxyCommand=touch /tmp/pwn", "-host", "a/b", "a b", "host;rm", "a$b", "a|b"}
	for _, h := range invalid {
		if err := ValidateHost(h); err == nil {
			t.Errorf("ValidateHost(%q) should fail", h)
		}
	}
}

func TestValidateSSHUser(t *testing.T) {
	for _, u := range []string{"root", "sa_fail2ban", "user-1", "_svc"} {
		if err := ValidateSSHUser(u); err != nil {
			t.Errorf("ValidateSSHUser(%q) should pass: %v", u, err)
		}
	}
	for _, u := range []string{"", " root", "root ", "-u", "user@host", "u ser", "u;x"} {
		if err := ValidateSSHUser(u); err == nil {
			t.Errorf("ValidateSSHUser(%q) should fail", u)
		}
	}
}

func TestValidateAbsolutePath(t *testing.T) {
	for _, p := range []string{"", "/etc/fail2ban", "/config/.ssh/id_rsa", "/var/run/fail2ban/fail2ban.sock"} {
		if err := ValidateAbsolutePath(p, "path"); err != nil {
			t.Errorf("ValidateAbsolutePath(%q) should pass: %v", p, err)
		}
	}
	invalid := []string{
		"relative/path",
		"/etc/../etc/passwd",
		"/etc/fail2ban\nX",
		"/etc/fail2ban\x00",
		"/etc/f'oo",
		"/etc/f;oo",
		"/etc/f$oo",
	}
	for _, p := range invalid {
		if err := ValidateAbsolutePath(p, "path"); err == nil {
			t.Errorf("ValidateAbsolutePath(%q) should fail", p)
		}
	}
}

func TestValidatePort(t *testing.T) {
	for _, p := range []int{0, 1, 22, 65535} {
		if err := ValidatePort(p); err != nil {
			t.Errorf("ValidatePort(%d) should pass: %v", p, err)
		}
	}
	for _, p := range []int{-1, 65536, 100000} {
		if err := ValidatePort(p); err == nil {
			t.Errorf("ValidatePort(%d) should fail", p)
		}
	}
}

func TestValidateServerFields(t *testing.T) {
	t.Run("valid ssh server", func(t *testing.T) {
		err := ValidateServerFields(Fail2banServer{
			Type: "ssh", Host: "10.0.0.1", SSHUser: "f2b",
			SSHKeyPath: "/config/.ssh/id_rsa", Port: 22,
		})
		if err != nil {
			t.Fatalf("valid server rejected: %v", err)
		}
	})

	t.Run("ssh host option injection rejected", func(t *testing.T) {
		err := ValidateServerFields(Fail2banServer{
			Type: "ssh", Host: "-oProxyCommand=touch /tmp/pwn", SSHUser: "f2b",
		})
		if err == nil {
			t.Fatal("option-injection host must be rejected")
		}
	})

	t.Run("local config path traversal rejected", func(t *testing.T) {
		err := ValidateServerFields(Fail2banServer{
			Type: "local", ConfigPath: "/etc/../root",
		})
		if err == nil {
			t.Fatal("non-clean config path must be rejected")
		}
	})

	t.Run("valid local server", func(t *testing.T) {
		if err := ValidateServerFields(Fail2banServer{Type: "local", ConfigPath: "/etc/fail2ban"}); err != nil {
			t.Fatalf("valid local server rejected: %v", err)
		}
	})

	t.Run("unnormalized type rejected", func(t *testing.T) {
		if err := ValidateServerFields(Fail2banServer{Type: "SSH", Host: "10.0.0.1", SSHUser: "f2b"}); err == nil {
			t.Fatal("unnormalized type must be rejected; normalization happens before validation")
		}
	})
}
