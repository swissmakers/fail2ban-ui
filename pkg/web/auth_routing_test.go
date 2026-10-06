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
	"testing"

	"github.com/gin-gonic/gin"
)

// A route that becomes public by accident is an auth bypass.
func TestIsPublicRoute(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"login", "/auth/login", true},
		{"callback", "/auth/callback", true},
		{"logout", "/auth/logout", true},
		{"status", "/auth/status", true},
		{"ban callback", "/api/ban", true},
		{"unban callback", "/api/unban", true},
		{"agent healthcheck", "/api/healthcheck/callback", true},
		{"static asset", "/static/js/core.js", true},
		{"locale file", "/locales/en.json", true},

		{"settings is protected", "/api/settings", false},
		{"servers is protected", "/api/servers", false},
		{"jails is protected", "/api/jails", false},
		{"root is protected", "/", false},
		{"summary is protected", "/api/summary", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPublicRoute(tc.path); got != tc.want {
				t.Fatalf("isPublicRoute(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// A protected route must not inherit public access from a shared prefix.
func TestIsPublicRoutePrefixDoesNotLeak(t *testing.T) {
	leaky := []string{
		"/api/bannedips",
		"/api/bans",
		"/api/unbanall",
		"/auth/login-as-admin",
		"/api/healthcheck/callbacks-admin",
	}
	for _, path := range leaky {
		t.Run(path, func(t *testing.T) {
			if isPublicRoute(path) {
				t.Fatalf("isPublicRoute(%q) = true: a protected route became public through prefix matching", path)
			}
		})
	}
}

func TestIsAPIRequest(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		accept string
		want   bool
	}{
		{"json accept header", "/dashboard", "application/json", true},
		{"api path", "/api/settings", "text/html", true},
		{"api path and json", "/api/settings", "application/json", true},
		{"browser page", "/dashboard", "text/html", false},
		{"no accept header", "/dashboard", "", false},
		{"json among several accepts", "/dashboard", "text/html, application/json;q=0.9", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			c := &gin.Context{Request: req}
			if got := isAPIRequest(c); got != tc.want {
				t.Fatalf("isAPIRequest(path=%q, accept=%q) = %v, want %v", tc.path, tc.accept, got, tc.want)
			}
		})
	}
}

// checkWSOrigin is the only guard against cross-origin WebSocket hijacking.
func TestCheckWSOrigin(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		origin string
		want   bool
	}{
		{"no origin header is allowed (non-browser client)", "ui.example.com", "", true},
		{"same host", "ui.example.com", "http://ui.example.com", true},
		{"same host with matching port", "ui.example.com:3080", "http://ui.example.com:3080", true},
		{"http implied port 80", "ui.example.com:80", "http://ui.example.com", true},
		{"https implied port 443", "ui.example.com:443", "https://ui.example.com", true},
		{"case insensitive host", "UI.example.com", "http://ui.EXAMPLE.com", true},

		{"different host is rejected", "ui.example.com", "http://evil.example.com", false},
		{"different port is rejected", "ui.example.com:3080", "http://ui.example.com:9999", false},
		{"implied port mismatch is rejected", "ui.example.com:3080", "https://ui.example.com", false},
		{"subdomain is rejected", "ui.example.com", "http://evil.ui.example.com", false},
		{"malformed origin is rejected", "ui.example.com", "http://[::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ws", nil)
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if got := checkWSOrigin(req); got != tc.want {
				t.Fatalf("checkWSOrigin(host=%q, origin=%q) = %v, want %v", tc.host, tc.origin, got, tc.want)
			}
		})
	}
}
