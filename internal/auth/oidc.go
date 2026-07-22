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

package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
	"golang.org/x/oauth2"
)

// =========================================================================
//  Types
// =========================================================================

type OIDCClient struct {
	Provider     *oidc.Provider
	Verifier     *oidc.IDTokenVerifier
	OAuth2Config *oauth2.Config
	Config       *config.OIDCConfig
}

type UserInfo struct {
	ID          string
	Email       string
	Name        string
	Username    string
	Roles       []string
	AccessLevel string
}

var (
	oidcClient *OIDCClient
)

const (
	AccessLevelAdmin   = "admin"
	AccessLevelSupport = "support"
)

func AuthorizationEnabled() bool {
	cfg := GetConfig()
	return cfg != nil && cfg.AuthorizationEnabled
}

func roleSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	return set
}

func hasAnyRole(userRoles []string, allowedRoles []string) bool {
	allowed := roleSet(allowedRoles)
	if len(allowed) == 0 {
		return false
	}
	for _, role := range userRoles {
		if _, ok := allowed[role]; ok {
			return true
		}
	}
	return false
}

func accessLevelForRoles(cfg *config.OIDCConfig, roles []string) string {
	if cfg == nil || !cfg.AuthorizationEnabled {
		return AccessLevelAdmin
	}
	if hasAnyRole(roles, cfg.AdminRoles) {
		return AccessLevelAdmin
	}
	if hasAnyRole(roles, cfg.SupportRoles) {
		return AccessLevelSupport
	}
	return ""
}

func SessionHasPermission(session *Session, permission string) bool {
	if session == nil {
		return false
	}
	if session.AccessLevel == AccessLevelAdmin {
		return true
	}
	if session.AccessLevel == AccessLevelSupport {
		switch permission {
		case "read", "ban":
			return true
		}
	}
	return false
}

// =========================================================================
//  Initialization
// =========================================================================

func contextWithSkipVerify(ctx context.Context, skipVerify bool) context.Context {
	if !skipVerify {
		return ctx
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	return oidc.ClientContext(ctx, client)
}

func InitializeOIDC(cfg *config.OIDCConfig) (*OIDCClient, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	// Retry OIDC provider discovery with exponential backoff (e.g. because of Keycloak starting up)
	maxRetries := 10
	retryDelay := 2 * time.Second
	var provider *oidc.Provider
	var err error

	for attempt := 0; attempt < maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ctx = contextWithSkipVerify(ctx, cfg.SkipVerify)

		provider, err = oidc.NewProvider(ctx, cfg.IssuerURL)
		cancel()

		if err == nil {
			break
		}
		config.DebugLog("OIDC provider discovery attempt %d/%d failed: %v, retrying in %v...", attempt+1, maxRetries, err, retryDelay)

		if attempt < maxRetries-1 {
			time.Sleep(retryDelay)
			// Increases the delay for each retry (exponential backoff)
			retryDelay = time.Duration(float64(retryDelay) * 1.5)
			if retryDelay > 10*time.Second {
				retryDelay = 10 * time.Second
			}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider after %d attempts: %w", maxRetries, err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	oidcClient = &OIDCClient{
		Provider:     provider,
		Verifier:     verifier,
		OAuth2Config: oauth2Config,
		Config:       cfg,
	}

	config.DebugLog("OIDC authentication initialized with provider: %s, issuer: %s", cfg.Provider, cfg.IssuerURL)

	return oidcClient, nil
}

// =========================================================================
//  Public Accessors
// =========================================================================

func GetOIDCClient() *OIDCClient {
	return oidcClient
}

func IsEnabled() bool {
	return oidcClient != nil && oidcClient.Config != nil && oidcClient.Config.Enabled
}

func GetConfig() *config.OIDCConfig {
	if oidcClient == nil {
		return nil
	}
	return oidcClient.Config
}

// =========================================================================
//  OAuth2 Flow
// =========================================================================

// Returns the OAuth2 authorization URL for the given state.
func (c *OIDCClient) GetAuthURL(state string) string {
	return c.OAuth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func claimByPath(claims map[string]interface{}, path string) interface{} {
	if path == "" {
		return nil
	}
	var current interface{} = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = m[part]
	}
	return current
}

func stringSliceFromClaim(value interface{}) []string {
	switch v := value.(type) {
	case string:
		return shared.SplitCommaList(v)
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

// Exchanges the authorization code for tokens.
func (c *OIDCClient) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	if c.OAuth2Config == nil {
		return nil, fmt.Errorf("OIDC client not properly initialized")
	}

	ctx = contextWithSkipVerify(ctx, c.Config.SkipVerify)
	token, err := c.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	return token, nil
}

// Verifies the ID token and extracts user information.
func (c *OIDCClient) VerifyToken(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	ctx = contextWithSkipVerify(ctx, c.Config.SkipVerify)
	idToken, err := c.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims struct {
		Subject           string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		GivenName         string `json:"given_name"`
		FamilyName        string `json:"family_name"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	allClaims := map[string]interface{}{}
	if err := idToken.Claims(&allClaims); err != nil {
		return nil, fmt.Errorf("failed to extract role claims: %w", err)
	}
	roles := stringSliceFromClaim(claimByPath(allClaims, c.Config.RoleClaim))

	userInfo := &UserInfo{
		ID:          claims.Subject,
		Email:       claims.Email,
		Name:        claims.Name,
		Roles:       roles,
		AccessLevel: accessLevelForRoles(c.Config, roles),
	}

	switch c.Config.UsernameClaim {
	case "email":
		userInfo.Username = claims.Email
	case "preferred_username":
		userInfo.Username = claims.PreferredUsername
		if userInfo.Username == "" {
			userInfo.Username = claims.Email
		}
	default:
		var claimValue interface{}
		if err := idToken.Claims(&map[string]interface{}{
			c.Config.UsernameClaim: &claimValue,
		}); err == nil {
			if str, ok := claimValue.(string); ok {
				userInfo.Username = str
			}
		}
		if userInfo.Username == "" {
			userInfo.Username = claims.PreferredUsername
			if userInfo.Username == "" {
				userInfo.Username = claims.Email
			}
		}
	}

	if userInfo.Name == "" {
		if claims.GivenName != "" || claims.FamilyName != "" {
			userInfo.Name = fmt.Sprintf("%s %s", claims.GivenName, claims.FamilyName)
			userInfo.Name = strings.TrimSpace(userInfo.Name)
		}
		if userInfo.Name == "" {
			userInfo.Name = userInfo.Username
		}
	}
	return userInfo, nil
}
