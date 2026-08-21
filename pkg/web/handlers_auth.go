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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// =========================================================================
//  Auth Handlers
// =========================================================================

func redirectToOIDCProvider(c *gin.Context, oidcClient *auth.OIDCClient) {
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state parameter"})
		return
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)
	isSecure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"

	// Stores the state in a session cookie for validation
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		Path:     CookiePath(),
		MaxAge:   600,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})
	config.DebugLog("Set state cookie: %s (Secure: %v)", state, isSecure)

	c.Redirect(http.StatusFound, oidcClient.GetAuthURL(state))
}

func LoginHandler(c *gin.Context) {
	oidcClient := auth.GetOIDCClient()
	if oidcClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OIDC authentication is not configured"})
		return
	}
	oidcConfig := auth.GetConfig()
	skipLoginPage := oidcConfig != nil && oidcConfig.SkipLoginPage

	if skipLoginPage || c.Query("action") == "redirect" {
		redirectToOIDCProvider(c, oidcClient)
		return
	}
	renderIndexPage(c)
}

// Handles the OIDC callback, exchanging the code for a session.
func CallbackHandler(c *gin.Context) {
	oidcClient := auth.GetOIDCClient()
	if oidcClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OIDC authentication is not configured"})
		return
	}
	stateCookie, err := c.Cookie("oidc_state")
	if err != nil {
		config.DebugLog("Failed to get state cookie: %v", err)
		config.DebugLog("Request cookies: %v", c.Request.Cookies())
		config.DebugLog("Request URL: %s", c.Request.URL.String())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing state parameter", "details": err.Error()})
		return
	}
	isSecure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "oidc_state",
		Value:    "",
		Path:     CookiePath(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})
	returnedState := c.Query("state")
	if returnedState != stateCookie {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}
	code := c.Query("code")
	if code == "" {
		errorDesc := c.Query("error_description")
		if errorDesc != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "OIDC authentication failed: " + errorDesc})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing authorization code"})
		}
		return
	}
	token, err := oidcClient.ExchangeCode(c.Request.Context(), code)
	if err != nil {
		config.DebugLog("Failed to exchange code for token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange authorization code"})
		return
	}
	userInfo, err := oidcClient.VerifyToken(c.Request.Context(), token)
	if err != nil {
		config.DebugLog("Failed to verify token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify authentication token"})
		return
	}
	if err := auth.CreateSession(c.Writer, c.Request, userInfo, oidcClient.Config.SessionMaxAge); err != nil {
		config.DebugLog("Failed to create session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}
	config.DebugLog("User authenticated: %s (%s)", userInfo.Username, userInfo.Email)
	// Redirect to main page
	c.Redirect(http.StatusFound, ExternalPath("/"))
}

// Clears the session and redirects to the OIDC provider logout.
func LogoutHandler(c *gin.Context) {
	oidcClient := auth.GetOIDCClient()
	auth.DeleteSession(c.Writer, c.Request)
	// If a provider logout URL is configured, redirects there
	// Otherwise, auto-constructs the logout URL for standard OIDC providers
	if oidcClient != nil {
		logoutURL := oidcClient.Config.LogoutURL
		if logoutURL == "" && oidcClient.Config.IssuerURL != "" {
			issuerURL := oidcClient.Config.IssuerURL
			redirectURI := oidcClient.Config.RedirectURL
			if strings.Contains(redirectURI, "/auth/callback") {
				redirectURI = strings.TrimSuffix(redirectURI, "/auth/callback")
			}
			redirectURI = redirectURI + "/auth/login"
			redirectURIEncoded := url.QueryEscape(redirectURI)
			clientIDEncoded := url.QueryEscape(oidcClient.Config.ClientID)

			switch oidcClient.Config.Provider {
			case "keycloak":
				// Keycloak requires client_id when using post_logout_redirect_uri
				// Format: {issuer}/protocol/openid-connect/logout?post_logout_redirect_uri={redirect}&client_id={client_id}
				logoutURL = fmt.Sprintf("%s/protocol/openid-connect/logout?post_logout_redirect_uri=%s&client_id=%s", issuerURL, redirectURIEncoded, clientIDEncoded)
			case "pocketid":
				// Pocket-ID uses a different logout endpoint (https://pocket-id.io/docs/oidc/#end-session)
				// Format: {issuer}/api/oidc/end-session?redirect_uri={redirect}
				logoutURL = fmt.Sprintf("%s/api/oidc/end-session?redirect_uri=%s", issuerURL, redirectURIEncoded)
			case "authentik":
				// OIDC format for Authentik (https://docs.goauthentik.io/docs/providers/oidc/#logout)
				// Format: {issuer}/protocol/openid-connect/logout?redirect_uri={redirect}
				logoutURL = fmt.Sprintf("%s/protocol/openid-connect/logout?redirect_uri=%s", issuerURL, redirectURIEncoded)
			default:
				logoutURL = fmt.Sprintf("%s/protocol/openid-connect/logout?redirect_uri=%s", issuerURL, redirectURIEncoded)
			}
		}
		if logoutURL != "" {
			config.DebugLog("Redirecting to provider logout: %s", logoutURL)
			c.Redirect(http.StatusFound, logoutURL)
			return
		}
	}
	c.Redirect(http.StatusFound, ExternalPath("/auth/login"))
}

// Returns the current authentication status as JSON.
func AuthStatusHandler(c *gin.Context) {
	if !auth.IsEnabled() {
		c.JSON(http.StatusOK, gin.H{
			"enabled":       false,
			"authenticated": false,
		})
		return
	}

	oidcConfig := auth.GetConfig()
	skipLoginPage := false
	if oidcConfig != nil {
		skipLoginPage = oidcConfig.SkipLoginPage
	}

	session, err := auth.GetSession(c.Request)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled":       true,
			"authenticated": false,
			"skipLoginPage": skipLoginPage,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled":              true,
		"authenticated":        true,
		"skipLoginPage":        skipLoginPage,
		"authorizationEnabled": auth.AuthorizationEnabled(),
		"user": gin.H{
			"id":          session.UserID,
			"email":       session.Email,
			"name":        session.Name,
			"username":    session.Username,
			"roles":       session.Roles,
			"accessLevel": session.AccessLevel,
		},
	})
}

// Returns the authenticated user's profile information.
func UserInfoHandler(c *gin.Context) {
	if !auth.IsEnabled() {
		c.JSON(http.StatusOK, gin.H{"authenticated": false})
		return
	}

	session, err := auth.GetSession(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated":        true,
		"authorizationEnabled": auth.AuthorizationEnabled(),
		"user": gin.H{
			"id":          session.UserID,
			"email":       session.Email,
			"name":        session.Name,
			"username":    session.Username,
			"roles":       session.Roles,
			"accessLevel": session.AccessLevel,
		},
	})
}
