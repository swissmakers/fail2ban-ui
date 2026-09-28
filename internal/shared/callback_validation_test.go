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

package shared

import "testing"

func TestValidateCallbackURL(t *testing.T) {
	valid := []string{
		"http://127.0.0.1:8080",
		"http://10.88.0.1:3080/dev",
		"https://fail2ban.swissmakers.corp",
		"https://fail2ban.example.com/my-f2b/sub_path",
		"http://fail2ban_ui:8080",
		"http://[::1]:8080/f2b",
		"HTTPS://Example.COM",
	}
	for _, u := range valid {
		t.Run("valid/"+u, func(t *testing.T) {
			if err := ValidateCallbackURL(u); err != nil {
				t.Fatalf("ValidateCallbackURL(%q) = %v, want nil", u, err)
			}
		})
	}

	invalid := []string{
		"",
		"http://h/x;touch /tmp/pwned;#",
		"http://h/$(id)",
		"http://h/`id`",
		"http://h/x'y",
		"http://h/x\"y",
		"http://h/a b",
		"http://h/x|y",
		"http://h/x&y",
		"http://h/%2e",
		"http://h/<ip>",
		"http://user:pass@h",
		"http://h/?q=1",
		"http://h/#frag",
		"http://h:0",
		"http://h:99999",
		"ftp://h",
		"javascript:alert(1)",
		"http://h/\nactionban = id",
	}
	for _, u := range invalid {
		t.Run("invalid/"+u, func(t *testing.T) {
			if err := ValidateCallbackURL(u); err == nil {
				t.Fatalf("ValidateCallbackURL(%q) = nil, want an error", u)
			}
		})
	}
}

func TestValidateCallbackSecret(t *testing.T) {
	for _, s := range []string{"", "same-as-ui-callback-secret", "Ab3_-~+/=.:@!#*,^&;|", "x"} {
		if err := ValidateCallbackSecret(s); err != nil {
			t.Errorf("ValidateCallbackSecret(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{"a'b", `a"b`, `a\b`, "a`b", "a$b", "a%b", "a<b", "a>b", "a b", "a\nb", "a\tb", "sécret"} {
		if err := ValidateCallbackSecret(s); err == nil {
			t.Errorf("ValidateCallbackSecret(%q) = nil, want an error", s)
		}
	}
}

func TestValidateServerID(t *testing.T) {
	for _, id := range []string{"local", "srv-3e62731129eaa4e3", "srv-1726000000000000000", "prod.web_01"} {
		if err := ValidateServerID(id); err != nil {
			t.Errorf("ValidateServerID(%q) = %v, want nil", id, err)
		}
	}
	for _, id := range []string{"", "x';touch /tmp/p;'", "-leading", ".hidden", "a b", "a/b", "a$b", "a\nb"} {
		if err := ValidateServerID(id); err == nil {
			t.Errorf("ValidateServerID(%q) = nil, want an error", id)
		}
	}
}

func TestValidateServerFieldsRejectsBadID(t *testing.T) {
	srv := Fail2banServer{ID: "x';id;'", Type: "local"}
	if err := ValidateServerFields(srv); err == nil {
		t.Fatal("a server id that breaks out of shell quoting must be rejected")
	}
}
