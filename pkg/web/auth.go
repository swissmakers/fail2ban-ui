// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2025 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
)

// If OIDC is enabled, this validates the session and redirects to login if not authenticated
// If OIDC is disabled, it allows all requests
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !auth.IsEnabled() {
			c.Next()
			return
		}
		path := c.Request.URL.Path
		if isPublicRoute(path) {
			c.Next()
			return
		}
		session, err := auth.GetSession(c.Request)
		if err != nil {
			if isAPIRequest(c) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
				c.Abort()
				return
			}
			c.Redirect(http.StatusFound, "/auth/login")
			c.Abort()
			return
		}
		c.Set("session", session)
		c.Set("userID", session.UserID)
		c.Set("userEmail", session.Email)
		c.Set("userName", session.Name)
		c.Set("username", session.Username)

		c.Next()
	}
}

// Checks if path is a public route (that does not require authentication)
func isPublicRoute(path string) bool {
	publicRoutes := []string{
		"/auth/login",
		"/auth/callback",
		"/auth/logout",
		"/auth/status",
		"/api/ban",
		"/api/unban",
		"/api/ws",
		"/static/",
		"/locales/",
	}
	for _, route := range publicRoutes {
		if strings.HasPrefix(path, route) {
			return true
		}
	}
	return false
}

// Checks if the request is an API request
func isAPIRequest(c *gin.Context) bool {
	accept := c.GetHeader("Accept")
	return strings.Contains(accept, "application/json") || strings.HasPrefix(c.Request.URL.Path, "/api/")
}
