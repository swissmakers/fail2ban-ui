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

import "testing"

func TestIsPublicRouteExactAPIMatching(t *testing.T) {
	// Session-less fail2ban notification / healthcheck callbacks.
	for _, p := range []string{
		"/api/ban",
		"/api/unban",
		"/api/healthcheck/callback",
	} {
		if !isPublicRoute(p) {
			t.Errorf("isPublicRoute(%q) = false, want true (exact public API)", p)
		}
	}

	// Authenticated API endpoints must NOT be treated as public. In particular,
	// /api/banned must not be shadowed by the /api/ban prefix, otherwise the
	// dashboard's "Currently banned IPs" table gets a 401.
	for _, p := range []string{
		"/api/banned",
		"/api/ban/foo",
		"/api/banned?sort=ip",
		"/api/summary",
		"/api/jails/sshd/banned",
		"/api/settings",
	} {
		if isPublicRoute(p) {
			t.Errorf("isPublicRoute(%q) = true, want false (should require a session)", p)
		}
	}
}
