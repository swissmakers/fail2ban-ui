// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2025 Swissmakers GmbH (https://swissmakers.ch)
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

package auth

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func TestRequestIsSecure(t *testing.T) {
	plain := httptest.NewRequest("GET", "http://ui/", nil)
	proxied := httptest.NewRequest("GET", "http://ui/", nil)
	proxied.Header.Set("X-Forwarded-Proto", "https")
	direct := httptest.NewRequest("GET", "https://ui/", nil)
	direct.TLS = &tls.ConnectionState{}
	spoofedCase := httptest.NewRequest("GET", "http://ui/", nil)
	spoofedCase.Header.Set("X-Forwarded-Proto", "http")

	for name, tt := range map[string]struct {
		secure bool
		got    bool
	}{
		"plain":         {false, RequestIsSecure(plain)},
		"proxied https": {true, RequestIsSecure(proxied)},
		"direct tls":    {true, RequestIsSecure(direct)},
		"proxied http":  {false, RequestIsSecure(spoofedCase)},
		"nil request":   {false, RequestIsSecure(nil)},
	} {
		if tt.got != tt.secure {
			t.Errorf("%s: RequestIsSecure = %v, want %v", name, tt.got, tt.secure)
		}
	}
}
