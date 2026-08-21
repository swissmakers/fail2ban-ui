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

package integrations

import "testing"

func TestValidateOutboundURL(t *testing.T) {
	t.Parallel()

	valid := []string{
		"http://192.168.1.1",
		"https://firewall.local",
		"http://10.0.0.5:8443/api",
		"https://example.com/path?q=1",
	}
	for _, raw := range valid {
		if err := ValidateOutboundURL(raw, "test URL"); err != nil {
			t.Fatalf("ValidateOutboundURL(%q): unexpected error %v", raw, err)
		}
	}

	invalid := []string{
		"",
		"   ",
		"ftp://example.com",
		"file:///etc/passwd",
		"gopher://example.com",
		"javascript:alert(1)",
		"http://",
		"://example.com",
		"http://exa\r\nmple.com",
	}
	for _, raw := range invalid {
		if err := ValidateOutboundURL(raw, "test URL"); err == nil {
			t.Fatalf("ValidateOutboundURL(%q): expected error, got nil", raw)
		}
	}
}

func TestValidateIdentifierRejectsTraversal(t *testing.T) {
	for _, ok := range []string{"fail2ban-permanent", "alias_1", "a.b.c", "list-42"} {
		if err := ValidateIdentifier(ok, "id"); err != nil {
			t.Errorf("ValidateIdentifier(%q) should pass: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "..", ".", "a..b", "../../etc", "a/b", "a b", "a;b"} {
		if err := ValidateIdentifier(bad, "id"); err == nil {
			t.Errorf("ValidateIdentifier(%q) should fail", bad)
		}
	}
}

func TestValidateElasticsearchIndex(t *testing.T) {
	for _, ok := range []string{"fail2ban-events", "logs.app", "abc_123"} {
		if err := ValidateElasticsearchIndex(ok); err != nil {
			t.Errorf("ValidateElasticsearchIndex(%q) should pass: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "x/_search", "../..", "UPPER", "-leading", "a..b", "a?b", "a#b"} {
		if err := ValidateElasticsearchIndex(bad); err == nil {
			t.Errorf("ValidateElasticsearchIndex(%q) should fail", bad)
		}
	}
}
