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

package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"golang.org/x/oauth2"
)

// The verifier stays in an HttpOnly cookie; the provider only ever sees its S256 hash.
func TestRedirectToOIDCProviderSendsPKCEChallenge(t *testing.T) {
	gin.SetMode(gin.TestMode)
	client := &auth.OIDCClient{
		Config: &config.OIDCConfig{},
		OAuth2Config: &oauth2.Config{
			ClientID: "fail2ban-ui",
			Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/auth", TokenURL: "https://idp.example/token"},
		},
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/auth/login?action=redirect", nil)

	redirectToOIDCProvider(c, client)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	var verifier *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "oidc_pkce" {
			verifier = ck
		}
	}
	if verifier == nil || verifier.Value == "" || !verifier.HttpOnly {
		t.Fatalf("missing HttpOnly oidc_pkce cookie: %+v", verifier)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != oauth2.S256ChallengeFromVerifier(verifier.Value) {
		t.Fatalf("redirect lacks the S256 challenge for the cookie's verifier: %s", loc)
	}
}
