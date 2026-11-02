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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/config"
	"golang.org/x/oauth2"
)

func TestPKCEChallengeAndVerifier(t *testing.T) {
	var gotVerifier string
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		gotVerifier = form.Get("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer"}`))
	}))
	defer tokenSrv.Close()

	c := &OIDCClient{
		Config: &config.OIDCConfig{},
		OAuth2Config: &oauth2.Config{
			ClientID: "fail2ban-ui",
			Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/auth", TokenURL: tokenSrv.URL},
		},
	}
	verifier := oauth2.GenerateVerifier()

	u, err := url.Parse(c.GetAuthURL("st", verifier))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != oauth2.S256ChallengeFromVerifier(verifier) {
		t.Fatalf("auth URL lacks the S256 challenge: %s", u)
	}
	if q.Get("code_verifier") != "" {
		t.Fatalf("auth URL leaks the verifier: %s", u)
	}

	if _, err := c.ExchangeCode(context.Background(), "code", verifier); err != nil {
		t.Fatal(err)
	}
	if gotVerifier != verifier {
		t.Fatalf("token request code_verifier = %q, want %q", gotVerifier, verifier)
	}
}
