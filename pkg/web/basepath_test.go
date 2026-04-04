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
	"net/http/httptest"
	"testing"
)

func TestNormalizeBasePath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"/", ""},
		{"/myf2b", "/myf2b"},
		{"/myf2b/", "/myf2b"},
		{"myf2b", "/myf2b"},
		{"  /app/sub/  ", "/app/sub"},
	}
	for _, tt := range tests {
		if got := NormalizeBasePath(tt.in); got != tt.want {
			t.Errorf("NormalizeBasePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExternalPath(t *testing.T) {
	SetBasePath("/myf2b")
	defer SetBasePath("")

	if got := ExternalPath("/"); got != "/myf2b/" {
		t.Errorf("ExternalPath('/') = %q", got)
	}
	if got := ExternalPath("/auth/login"); got != "/myf2b/auth/login" {
		t.Errorf("ExternalPath('/auth/login') = %q", got)
	}

	SetBasePath("")
	if got := ExternalPath("/api/version"); got != "/api/version" {
		t.Errorf("root ExternalPath = %q", got)
	}
}

func TestStripBasePathHandler(t *testing.T) {
	SetBasePath("/dev")
	defer SetBasePath("")

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Path", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	handler := StripBasePathHandler(backend)

	t.Run("strips prefixed paths before routing", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/dev/static/app.css", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
		}
		if got := rr.Header().Get("X-Seen-Path"); got != "/static/app.css" {
			t.Fatalf("seen path = %q, want %q", got, "/static/app.css")
		}
	})

	t.Run("maps exact base path to root", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/dev", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
		}
		if got := rr.Header().Get("X-Seen-Path"); got != "/" {
			t.Fatalf("seen path = %q, want %q", got, "/")
		}
	})

	t.Run("redirects site root to base path root", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusTemporaryRedirect)
		}
		if got := rr.Header().Get("Location"); got != "/dev/" {
			t.Fatalf("location = %q, want %q", got, "/dev/")
		}
	})

	t.Run("rejects unprefixed paths when base path is set", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})
}
