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
	"github.com/swissmakers/fail2ban-ui/internal/shared"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExternalPath(t *testing.T) {
	shared.SetBasePath("/myf2b")
	defer shared.SetBasePath("")

	if got := ExternalPath("/"); got != "/myf2b/" {
		t.Errorf("ExternalPath('/') = %q", got)
	}
	if got := ExternalPath("/auth/login"); got != "/myf2b/auth/login" {
		t.Errorf("ExternalPath('/auth/login') = %q", got)
	}

	shared.SetBasePath("")
	if got := ExternalPath("/api/version"); got != "/api/version" {
		t.Errorf("root ExternalPath = %q", got)
	}
}

func TestStripBasePathHandler(t *testing.T) {
	shared.SetBasePath("/dev")
	defer shared.SetBasePath("")

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Path", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	handler := StripBasePathHandler(backend)

	t.Run("strips prefixed paths before routing", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/dev/static/app.css", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
		}
		if got := rr.Header().Get("X-Seen-Path"); got != "/static/app.css" {
			t.Fatalf("seen path = %q, want %q", got, "/static/app.css")
		}
	})

	t.Run("maps exact base path to root", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/dev", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
		}
		if got := rr.Header().Get("X-Seen-Path"); got != "/" {
			t.Fatalf("seen path = %q, want %q", got, "/")
		}
	})

	t.Run("redirects site root to base path root", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusTemporaryRedirect)
		}
		if got := rr.Header().Get("Location"); got != "/dev/" {
			t.Fatalf("location = %q, want %q", got, "/dev/")
		}
	})

	t.Run("serves the liveness probe without the base path", func(t *testing.T) {
		for _, path := range []string{"/healthz", "/dev/healthz"} {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
			if rr.Code != http.StatusNoContent || rr.Header().Get("X-Seen-Path") != "/healthz" {
				t.Fatalf("%s: status=%d seen=%q", path, rr.Code, rr.Header().Get("X-Seen-Path"))
			}
		}
	})

	t.Run("rejects unprefixed paths when base path is set", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})
}
