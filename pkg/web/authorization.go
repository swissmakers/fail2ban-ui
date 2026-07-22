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
