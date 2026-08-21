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

import (
	"net"
	"testing"
)

func TestIsReservedIP(t *testing.T) {
	reserved := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.5", "172.16.0.1",
		"169.254.1.1", "224.0.0.1", "0.0.0.0",
		"::1", "fe80::1", "::", "fc00::1",
	}
	for _, s := range reserved {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test IP %q did not parse", s)
		}
		if !IsReservedIP(ip) {
			t.Errorf("IsReservedIP(%s) should be true", s)
		}
	}
	public := []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"}
	for _, s := range public {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test IP %q did not parse", s)
		}
		if IsReservedIP(ip) {
			t.Errorf("IsReservedIP(%s) should be false", s)
		}
	}
}
