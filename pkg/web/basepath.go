// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the PolyForm Shield License 1.0.0.
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://polyformproject.org/licenses/shield/1.0.0/
//
//     or in the LICENSE file in this repository.
//
// Required Notice: Copyright Swissmakers GmbH (https://swissmakers.ch)

package web

import (
	"net/http"
	"os"
	"strings"
	"sync"
)

var (
	basePathMu   sync.RWMutex
	httpBasePath string
)

// Normalizes a BASE_PATH value for use as an URL path prefix.
// Empty, "/", or whitespace yields "" (serve at site root).
func NormalizeBasePath(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "/" {
		return ""
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	return strings.TrimSuffix(s, "/")
}

// Reads BASE_PATH and applies NormalizeBasePath.
func SetBasePathFromEnv() {
	SetBasePath(os.Getenv("BASE_PATH"))
}

// Sets the external URL prefix (normalized). Pass "" for root.
func SetBasePath(p string) {
	basePathMu.Lock()
	defer basePathMu.Unlock()
	httpBasePath = NormalizeBasePath(p)
}

// Returns the normalized prefix without trailing slash, or "" for root.
func BasePath() string {
	basePathMu.RLock()
	defer basePathMu.RUnlock()
	return httpBasePath
}

// Returns the Path attribute for session and OIDC cookies.
func CookiePath() string {
	if b := BasePath(); b != "" {
		return b
	}
	return "/"
}

// Maps an internal route (e.g. "/auth/login") to the browser URL including BasePath.
func ExternalPath(internal string) string {
	base := BasePath()
	internal = strings.TrimSpace(internal)
	if internal == "" {
		internal = "/"
	}
	if !strings.HasPrefix(internal, "/") {
		internal = "/" + internal
	}
	if base == "" {
		return internal
	}
	if internal == "/" {
		return base + "/"
	}
	return base + internal
}

// Wraps an HTTP handler and strips BasePath before route matching.
// resolve against existing /static/* routes.
func StripBasePathHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := BasePath()
		if base == "" {
			next.ServeHTTP(w, r)
			return
		}

		p := r.URL.Path
		switch {
		case p == "/":
			http.Redirect(w, r, base+"/", http.StatusTemporaryRedirect)
			return
		case p == base:
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			next.ServeHTTP(w, r2)
			return
		case strings.HasPrefix(p, base+"/"):
			r2 := r.Clone(r.Context())
			r2.URL.Path = strings.TrimPrefix(p, base)
			if r2.URL.Path == "" {
				r2.URL.Path = "/"
			}
			next.ServeHTTP(w, r2)
			return
		default:
			http.NotFound(w, r)
			return
		}
	})
}
