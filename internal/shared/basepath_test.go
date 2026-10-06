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

func TestNormalizeBasePath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"/", ""},
		{"/myf2b", "/myf2b"},
		{"/myf2b/", "/myf2b"},
		{"myf2b", "/myf2b"},
		{"  /app/sub/  ", "/app/sub"},
		{"//evil.com", ""},
		{"///evil.com", ""},
		{"https://evil.com", ""},
		{"http://evil.com", ""},
		{"/path\r\nSet-Cookie: x=y", ""},
		{"\\\\evil.com", ""},
		{"/\\evil.com", ""},
		{"/a:b", ""},
	}
	for _, tt := range tests {
		if got := NormalizeBasePath(tt.in); got != tt.want {
			t.Errorf("NormalizeBasePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
