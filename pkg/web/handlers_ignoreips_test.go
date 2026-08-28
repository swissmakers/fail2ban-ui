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

package web

import (
	"reflect"
	"testing"
)

func TestIsValidIgnoreEntry(t *testing.T) {
	valid := []string{
		"192.0.2.10",
		"2001:db8::1",
		"192.0.2.0/24",
		"2001:db8::/32",
		"host.example",
		"f2b-host-1.internal",
	}
	for _, value := range valid {
		if !isValidIgnoreEntry(value) {
			t.Errorf("isValidIgnoreEntry(%q) = false, want true", value)
		}
	}

	invalid := []string{
		"",
		"host with spaces",
		"-invalid.example",
		"invalid-.example",
		"host/example",
	}
	for _, value := range invalid {
		if isValidIgnoreEntry(value) {
			t.Errorf("isValidIgnoreEntry(%q) = true, want false", value)
		}
	}
}

func TestSubtractIgnoreIPsIsCaseInsensitive(t *testing.T) {
	got := subtractIgnoreIPs(
		[]string{"127.0.0.1", "HOST.EXAMPLE", "203.0.113.10"},
		[]string{"host.example", "127.0.0.1"},
	)
	want := []string{"203.0.113.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("subtractIgnoreIPs() = %#v, want %#v", got, want)
	}
}

func TestPaginateIgnoreIPs(t *testing.T) {
	ips := []string{"one", "two", "three"}
	got, total, hasMore := paginateIgnoreIPs(ips, 1, 1)
	if want := []string{"two"}; !reflect.DeepEqual(got, want) || total != 3 || !hasMore {
		t.Fatalf("paginateIgnoreIPs() = (%#v, %d, %t), want (%#v, 3, true)", got, total, hasMore, want)
	}

	got, total, hasMore = paginateIgnoreIPs(ips, 99, 10)
	if len(got) != 0 || total != 3 || hasMore {
		t.Fatalf("out-of-range pagination = (%#v, %d, %t), want (empty, 3, false)", got, total, hasMore)
	}
}

func TestAllowedIPFeatureEnabled(t *testing.T) {
	t.Setenv("ALLOWED_IP_ENABLED", "")
	if !allowedIPFeatureEnabled() {
		t.Fatal("the feature should be enabled by default")
	}

	t.Setenv("ALLOWED_IP_ENABLED", "true")
	if !allowedIPFeatureEnabled() {
		t.Fatal("ALLOWED_IP_ENABLED=true should enable the feature")
	}

	t.Setenv("ALLOWED_IP_ENABLED", "false")
	if allowedIPFeatureEnabled() {
		t.Fatal("ALLOWED_IP_ENABLED=false should disable the feature")
	}
}
