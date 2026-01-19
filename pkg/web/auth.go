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

// AuthMiddleware protects routes requiring authentication
// If OIDC is enabled, validates session and redirects to login if not authenticated
// If OIDC is disabled, allows all requests
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if OIDC is enabled
		if !auth.IsEnabled() {
			// OIDC not enabled, allow request
			c.Next()
			return
		}

		// Check if this is a public route
		path := c.Request.URL.Path
		if isPublicRoute(path) {
			c.Next()
			return
		}

		// Validate session
		session, err := auth.GetSession(c.Request)
		if err != nil {
			// No valid session, redirect to login
			if isAPIRequest(c) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
				c.Abort()
				return
			}
			// For HTML requests, redirect to login
			c.Redirect(http.StatusFound, "/auth/login")
			c.Abort()
			return
		}

		// Store session in context for handlers to access
		c.Set("session", session)
		c.Set("userID", session.UserID)
		c.Set("userEmail", session.Email)
		c.Set("userName", session.Name)
		c.Set("username", session.Username)

		c.Next()
	}
}

// isPublicRoute checks if the path is a public route that doesn't require authentication
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

// isAPIRequest checks if the request is an API request (JSON expected)
func isAPIRequest(c *gin.Context) bool {
	accept := c.GetHeader("Accept")
	return strings.Contains(accept, "application/json") || strings.HasPrefix(c.Request.URL.Path, "/api/")
}
