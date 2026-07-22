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

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
)

const (
	PermissionRead  = "read"
	PermissionBan   = "ban"
	PermissionAdmin = "admin"
)

func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !auth.IsEnabled() || !auth.AuthorizationEnabled() {
			c.Next()
			return
		}

		sessionValue, exists := c.Get("session")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		session, ok := sessionValue.(*auth.Session)
		if !ok || session == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		if !auth.SessionHasPermission(session, permission) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func userHasAdminAccess(c *gin.Context) bool {
	if !auth.IsEnabled() || !auth.AuthorizationEnabled() {
		return true
	}
	sessionValue, exists := c.Get("session")
	if !exists {
		return false
	}
	session, ok := sessionValue.(*auth.Session)
	return ok && auth.SessionHasPermission(session, PermissionAdmin)
}
