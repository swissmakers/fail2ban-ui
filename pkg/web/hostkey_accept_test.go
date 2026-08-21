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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func performAcceptHostKey(t *testing.T, serverID, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/api/servers/"+serverID+"/hostkey/accept", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	if serverID != "" {
		c.Params = gin.Params{{Key: "id", Value: serverID}}
	}
	AcceptHostKeyHandler(c)
	return w
}

func TestAcceptHostKeyHandlerValidation(t *testing.T) {
	t.Run("missing id", func(t *testing.T) {
		if w := performAcceptHostKey(t, "", `{}`); w.Code != http.StatusBadRequest {
			t.Errorf("missing id: status %d, want 400", w.Code)
		}
	})

	t.Run("unknown server", func(t *testing.T) {
		if w := performAcceptHostKey(t, "no-such-server", `{"fingerprint":"SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`); w.Code != http.StatusNotFound {
			t.Errorf("unknown server: status %d, want 404", w.Code)
		}
	})
}

func TestSSHFingerprintPattern(t *testing.T) {
	valid := []string{
		"SHA256:31qptbbgMC2I2FWQsTsaKadlJA0UUgZFHYOr+83qzlA",
	}
	for _, fp := range valid {
		if !sshFingerprintRe.MatchString(fp) {
			t.Errorf("%q should be a valid fingerprint", fp)
		}
	}
	invalid := []string{
		"",
		"SHA256:",
		"SHA256:short",
		"MD5:aa:bb:cc",
		"SHA256:31qptbbgMC2I2FWQsTsaKadlJA0UUgZFHYOr+83qzlA\nX-Injected: 1",
		"SHA256:31qptbbgMC2I2FWQsTsaKadlJA0UUgZFHYOr+83qzl!",
	}
	for _, fp := range invalid {
		if sshFingerprintRe.MatchString(fp) {
			t.Errorf("%q should be rejected", fp)
		}
	}
}
