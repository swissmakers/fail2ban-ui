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

package integrations

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// resetNexusTokenCache isolates tests from the process-wide token cache.
func resetNexusTokenCache(t *testing.T) {
	t.Helper()
	nexusTokens.invalidate()
	t.Cleanup(nexusTokens.invalidate)
}

// nexusTestConfig returns a valid Nexus integration config pointing at the mock server.
func nexusTestConfig(serverURL string) config.AdvancedActionsConfig {
	return config.AdvancedActionsConfig{
		PfSenseNexus: config.PfSenseNexusIntegrationSettings{
			BaseURL:  serverURL,
			Username: "svc-fail2ban",
			Password: "secret-password",
			Alias:    "banned",
		},
	}
}

func TestPfSenseNexusValidate(t *testing.T) {
	integration := &pfSenseNexusIntegration{}

	valid := config.AdvancedActionsConfig{
		PfSenseNexus: config.PfSenseNexusIntegrationSettings{
			BaseURL:  "https://firewall.local:8443",
			Username: "svc-fail2ban",
			Password: "secret-password",
			Alias:    "banned",
		},
	}
	if err := integration.Validate(valid); err != nil {
		t.Fatalf("expected valid config to pass: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*config.AdvancedActionsConfig)
	}{
		{"empty base URL", func(c *config.AdvancedActionsConfig) { c.PfSenseNexus.BaseURL = "" }},
		{"bad scheme", func(c *config.AdvancedActionsConfig) { c.PfSenseNexus.BaseURL = "ftp://firewall.local:8443" }},
		{"empty username", func(c *config.AdvancedActionsConfig) { c.PfSenseNexus.Username = "" }},
		{"empty password", func(c *config.AdvancedActionsConfig) { c.PfSenseNexus.Password = "" }},
		{"empty alias", func(c *config.AdvancedActionsConfig) { c.PfSenseNexus.Alias = "" }},
		{"alias traversal", func(c *config.AdvancedActionsConfig) { c.PfSenseNexus.Alias = "../etc" }},
		{"alias hyphen (Nexus rejects)", func(c *config.AdvancedActionsConfig) { c.PfSenseNexus.Alias = "fail2ban-banned" }},
		{"alias dot (Nexus rejects)", func(c *config.AdvancedActionsConfig) { c.PfSenseNexus.Alias = "fail2ban.banned" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			if err := integration.Validate(cfg); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestPfSenseNexusRegistryEntry(t *testing.T) {
	if _, ok := Get("pfsense-nexus"); !ok {
		t.Fatalf("integration pfsense-nexus must be registered")
	}
}

func TestPfSenseNexusBlockIPCreatesAliasAndAddsTarget(t *testing.T) {
	resetNexusTokenCache(t)

	var logins int
	const expectedToken = "test-token-1"
	const stateAfterBlock = "1.2.3.4"

	mux := http.NewServeMux()

	// Login: verify base64-encoded credentials, hand out a JWT.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("login decode: %v", err)
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		wantUser := base64.StdEncoding.EncodeToString([]byte("svc-fail2ban"))
		wantPass := base64.StdEncoding.EncodeToString([]byte("secret-password"))
		if payload["username"] != wantUser || payload["password"] != wantPass {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		logins++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":%q}`, expectedToken)
	})

	// GET /aliases (list) and PUT /aliases (create): the collection endpoint.
	mux.HandleFunc("/aliases", func(w http.ResponseWriter, r *http.Request) {
		if err := requireBearer(w, r, expectedToken); err != nil {
			return
		}
		switch r.Method {
		case http.MethodGet:
			if got := r.URL.Query().Get("maxvalues"); got != "100000" {
				t.Errorf("maxvalues=%q, want 100000 (default 5 would truncate large aliases)", got)
			}
			aliases := []nexusAlias{}
			if state := currentAliasState(); state != "" {
				aliases = append(aliases, nexusAlias{
					Name: "banned", Type: "host",
					Targets: []nexusTarget{{Name: state}},
				})
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(nexusAliasesResponse{Aliases: aliases})
		case http.MethodPut:
			var alias nexusAlias
			if err := json.NewDecoder(r.Body).Decode(&alias); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			if alias.Name != "banned" || alias.Type != "host" {
				t.Errorf("create payload name=%q type=%q, want banned/host", alias.Name, alias.Type)
			}
			fmt.Fprint(w, `{"status":"ok"}`)
		default:
			t.Errorf("collection endpoint got method %s, want GET/PUT only", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// POST /aliases/{name}: record the submitted target list as state.
	mux.HandleFunc("/aliases/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("update got method %s, want POST", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := requireBearer(w, r, expectedToken); err != nil {
			return
		}
		if name := strings.TrimPrefix(r.URL.Path, "/aliases/"); name != "banned" {
			http.Error(w, "unknown alias", http.StatusBadRequest)
			return
		}
		var alias nexusAlias
		if err := json.NewDecoder(r.Body).Decode(&alias); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if alias.Name != "banned" {
			t.Errorf("update payload name=%q, want banned", alias.Name)
		}
		recordedAliasState.Store(flattenTargets(alias.Targets))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	// Filter reload must be triggered after the alias update.
	mux.HandleFunc("/system/filterreload/reload", func(w http.ResponseWriter, r *http.Request) {
		if err := requireBearer(w, r, expectedToken); err != nil {
			return
		}
		filterReloads.Add(1)
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	var logs []string
	req := Request{
		IP:     "1.2.3.4",
		Config: nexusTestConfig(server.URL),
		Logger: func(format string, args ...interface{}) {
			logs = append(logs, fmt.Sprintf(format, args...))
		},
	}

	integration := &pfSenseNexusIntegration{}
	if err := integration.BlockIP(req); err != nil {
		t.Fatalf("BlockIP failed: %v", err)
	}
	if got := currentAliasState(); got != stateAfterBlock {
		t.Fatalf("alias state after block = %q, want %q", got, stateAfterBlock)
	}
	if logins != 1 {
		t.Errorf("logins = %d, want 1", logins)
	}
	if filterReloads.Load() != 1 {
		t.Errorf("filter reloads = %d, want 1", filterReloads.Load())
	}
}

func TestPfSenseNexusBlockIPReusesCachedToken(t *testing.T) {
	resetNexusTokenCache(t)

	var logins int
	var requests atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		logins++
		fmt.Fprint(w, `{"token":"cached-token"}`)
	})
	mux.HandleFunc("/aliases", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			requests.Add(1)
		case http.MethodPut:
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
		fmt.Fprint(w, `{"aliases": [], "system_aliases": []}`)
	})
	mux.HandleFunc("/aliases/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/system/filterreload/reload", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	integration := &pfSenseNexusIntegration{}
	for _, ip := range []string{"1.2.3.4", "5.6.7.8"} {
		req := Request{IP: ip, Config: nexusTestConfig(server.URL)}
		if err := integration.BlockIP(req); err != nil {
			t.Fatalf("BlockIP(%s) failed: %v", ip, err)
		}
	}
	if logins != 1 {
		t.Errorf("logins = %d, want 1 (token must be reused within the burst)", logins)
	}
	if requests.Load() != 2 {
		t.Errorf("alias list requests = %d, want 2", requests.Load())
	}
}

func TestPfSenseNexusReloginAfter401(t *testing.T) {
	resetNexusTokenCache(t)

	var logins atomic.Int32
	const freshToken = "fresh-token"

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		logins.Add(1)
		fmt.Fprint(w, fmt.Sprintf(`{"token":%q}`, freshToken))
	})
	mux.HandleFunc("/aliases", func(w http.ResponseWriter, r *http.Request) {
		// The stale token seeded below must trigger exactly one re-login.
		if err := requireBearer(w, r, freshToken); err != nil {
			return
		}
		fmt.Fprint(w, `{"aliases": [], "system_aliases": []}`)
	})
	mux.HandleFunc("/aliases/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/system/filterreload/reload", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Seed the cache with an expired/stale token.
	nexusTokens.set("stale-token")
	nexusTokens.expires = time.Now().Add(-time.Minute)

	integration := &pfSenseNexusIntegration{}
	req := Request{IP: "1.2.3.4", Config: nexusTestConfig(server.URL)}
	if err := integration.BlockIP(req); err != nil {
		t.Fatalf("BlockIP failed: %v", err)
	}
	if logins.Load() != 1 {
		t.Errorf("logins = %d, want 1 re-login after 401", logins.Load())
	}
}

func TestPfSenseNexusUnblockIPRemovesTargetAndSkipsReloadWhenAbsent(t *testing.T) {
	resetNexusTokenCache(t)

	var reloads int
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"token":"t"}`)
	})
	mux.HandleFunc("/aliases", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(nexusAliasesResponse{Aliases: []nexusAlias{{
			Name:    "banned",
			Type:    "host",
			Targets: []nexusTarget{{Name: "1.2.3.4"}, {Name: "5.6.7.8"}},
		}}})
	})
	mux.HandleFunc("/aliases/", func(w http.ResponseWriter, r *http.Request) {
		var alias nexusAlias
		json.NewDecoder(r.Body).Decode(&alias)
		recordedAliasState.Store(flattenTargets(alias.Targets))
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/system/filterreload/reload", func(w http.ResponseWriter, r *http.Request) {
		reloads++
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	integration := &pfSenseNexusIntegration{}

	// Removing an existing IP updates the alias and triggers a reload.
	req := Request{IP: "1.2.3.4", Config: nexusTestConfig(server.URL)}
	if err := integration.UnblockIP(req); err != nil {
		t.Fatalf("UnblockIP failed: %v", err)
	}
	if got := currentAliasState(); got != "5.6.7.8" {
		t.Fatalf("alias state after unblock = %q, want 5.6.7.8", got)
	}
	if reloads != 1 {
		t.Errorf("filter reloads = %d, want 1", reloads)
	}

	// Removing an absent IP must be a no-op (no update, no reload).
	before := reloads
	req = Request{IP: "9.9.9.9", Config: nexusTestConfig(server.URL)}
	if err := integration.UnblockIP(req); err != nil {
		t.Fatalf("UnblockIP(absent) failed: %v", err)
	}
	if reloads != before {
		t.Errorf("filter reloads changed on no-op unblock: %d -> %d", before, reloads)
	}
}

func TestPfSenseNexusRefusesTruncatedAlias(t *testing.T) {
	resetNexusTokenCache(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"token":"t"}`)
	})
	mux.HandleFunc("/aliases", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(nexusAliasesResponse{Aliases: []nexusAlias{{
			Name:      "banned",
			Type:      "host",
			Targets:   []nexusTarget{{Name: "1.2.3.4"}},
			Truncated: true,
		}}})
	})
	mux.HandleFunc("/aliases/", func(w http.ResponseWriter, r *http.Request) {
		t.Error("alias must not be updated when truncated")
	})
	mux.HandleFunc("/system/filterreload/reload", func(w http.ResponseWriter, r *http.Request) {
		t.Error("filter reload must not run when alias update is refused")
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	integration := &pfSenseNexusIntegration{}
	req := Request{IP: "2.3.4.5", Config: nexusTestConfig(server.URL)}
	err := integration.BlockIP(req)
	if err == nil {
		t.Fatal("expected BlockIP to refuse a truncated alias")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("error should mention truncation, got: %v", err)
	}
}

func TestPfSenseNexusInvalidIPRejected(t *testing.T) {
	resetNexusTokenCache(t)

	integration := &pfSenseNexusIntegration{}
	req := Request{IP: "not-an-ip", Config: config.AdvancedActionsConfig{
		PfSenseNexus: config.PfSenseNexusIntegrationSettings{
			BaseURL: "https://firewall.local:8443", Username: "u", Password: "p", Alias: "banned",
		},
	}}
	if err := integration.BlockIP(req); err == nil || !strings.Contains(err.Error(), "invalid IP") {
		t.Fatalf("expected invalid IP error, got: %v", err)
	}
}

// =========================================================================
//  Helpers
// =========================================================================

var recordedAliasState atomic.Value // string: space-joined target names
var filterReloads atomic.Int32

func flattenTargets(targets []nexusTarget) string {
	names := make([]string, 0, len(targets))
	for _, tgt := range targets {
		names = append(names, tgt.Name)
	}
	return strings.Join(names, " ")
}

func currentAliasState() string {
	if v, ok := recordedAliasState.Load().(string); ok {
		return v
	}
	return ""
}

// requireBearer enforces auth and returns an error (after writing the 401) when missing/wrong.
func requireBearer(w http.ResponseWriter, r *http.Request, want string) error {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got != want {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
		return fmt.Errorf("unauthorized")
	}
	return nil
}
