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
	"golang.org/x/oauth2"
)

// OIDCClient holds the OIDC provider, verifier, and OAuth2 configuration
type OIDCClient struct {
	Provider     *oidc.Provider
	Verifier     *oidc.IDTokenVerifier
	OAuth2Config *oauth2.Config
	Config       *config.OIDCConfig
}

// UserInfo represents the authenticated user information
type UserInfo struct {
	ID       string
	Email    string
	Name     string
	Username string
}

var (
	oidcClient *OIDCClient
)

// contextWithSkipVerify returns a context with an HTTP client that skips TLS verification if enabled
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

// InitializeOIDC sets up the OIDC client from configuration
func InitializeOIDC(cfg *config.OIDCConfig) (*OIDCClient, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	// Retry OIDC provider discovery with exponential backoff
	// This handles cases where the provider isn't ready yet (e.g., Keycloak starting up)
	maxRetries := 10
	retryDelay := 2 * time.Second
	var provider *oidc.Provider
	var err error

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Create context with timeout for each attempt
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		ctx = contextWithSkipVerify(ctx, cfg.SkipVerify)

		// Try to discover OIDC provider
		provider, err = oidc.NewProvider(ctx, cfg.IssuerURL)
		cancel()

		if err == nil {
			// Success - provider discovered
			break
		}

		// Log retry attempt (but don't fail yet)
		config.DebugLog("OIDC provider discovery attempt %d/%d failed: %v, retrying in %v...", attempt+1, maxRetries, err, retryDelay)

		if attempt < maxRetries-1 {
			time.Sleep(retryDelay)
			// Exponential backoff: increase delay for each retry
			retryDelay = time.Duration(float64(retryDelay) * 1.5)
			if retryDelay > 10*time.Second {
				retryDelay = 10 * time.Second
			}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider after %d attempts: %w", maxRetries, err)
	}

	// Create OAuth2 configuration
	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	// Create ID token verifier
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

// GetOIDCClient returns the initialized OIDC client
func GetOIDCClient() *OIDCClient {
	return oidcClient
}

// IsEnabled returns whether OIDC is enabled
func IsEnabled() bool {
	return oidcClient != nil && oidcClient.Config != nil && oidcClient.Config.Enabled
}

// GetConfig returns the OIDC configuration
func GetConfig() *config.OIDCConfig {
	if oidcClient == nil {
		return nil
	}
	return oidcClient.Config
}

// GetAuthURL generates the authorization URL for OIDC login
func (c *OIDCClient) GetAuthURL(state string) string {
	return c.OAuth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeCode exchanges the authorization code for tokens
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

// VerifyToken verifies the ID token and extracts user information
func (c *OIDCClient) VerifyToken(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	ctx = contextWithSkipVerify(ctx, c.Config.SkipVerify)
	// Verify the ID token
	idToken, err := c.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims
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

	userInfo := &UserInfo{
		ID:    claims.Subject,
		Email: claims.Email,
		Name:  claims.Name,
	}

	// Determine username based on configured claim
	switch c.Config.UsernameClaim {
	case "email":
		userInfo.Username = claims.Email
	case "preferred_username":
		userInfo.Username = claims.PreferredUsername
		if userInfo.Username == "" {
			userInfo.Username = claims.Email // Fallback to email
		}
	default:
		// Try to get the claim value dynamically
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

	// Fallback name construction
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
