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

package fail2ban

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

type testProvider struct{}

func (testProvider) DebugLog(format string, v ...interface{}) {}
func (testProvider) CallbackURL() string                      { return "http://127.0.0.1:8080" }
func (testProvider) CallbackSecret() string                   { return "test-secret" }
func (testProvider) BuildFail2banActionConfig(callbackURL, serverID, secret string) string {
	return ""
}
func (testProvider) BuildJailLocalContent() string {
	return "[DEFAULT]\nenabled = true\naction_mwlg = %(action_)s\n             ui-custom-action[logpath=\"%(logpath)s\", chain=\"%(chain)s\"]\naction = %(action_mwlg)s\n"
}

func TestNormalizeAgentURL(t *testing.T) {
	u, err := NormalizeAgentURL("127.0.0.1")
	if err != nil {
		t.Fatalf("normalize error: %v", err)
	}
	if got := u.String(); got != "http://127.0.0.1:9700" {
		t.Fatalf("got %q", got)
	}

	u, err = NormalizeAgentURL("https://agent.example.local")
	if err != nil {
		t.Fatalf("normalize https error: %v", err)
	}
	if got := u.String(); got != "https://agent.example.local:9700" {
		t.Fatalf("got %q", got)
	}
}

func TestAgentConnectorHeadersAndPathEscape(t *testing.T) {
	var capturedPath, capturedToken string
	var callbackConfig map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedToken = r.Header.Get("X-F2B-Token")
		switch {
		case r.URL.Path == "/v1/callback/config":
			_ = json.NewDecoder(r.Body).Decode(&callbackConfig)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		case strings.HasPrefix(r.URL.Path, "/v1/filters/"):
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	server := shared.Fail2banServer{
		ID:          "s1",
		Name:        "agent",
		Type:        "agent",
		AgentURL:    srv.URL,
		AgentSecret: "secret123",
	}
	c, err := NewAgentConnector(server)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	ac := c.(*AgentConnector)

	if capturedToken != "secret123" {
		t.Fatalf("ensureCallbackConfig token mismatch: %q", capturedToken)
	}
	if callbackConfig["serverId"] != "s1" {
		t.Fatalf("callback config serverId mismatch: %#v", callbackConfig)
	}
	if _, ok := callbackConfig["callbackUrl"]; !ok {
		t.Fatalf("callback config missing callbackUrl: %#v", callbackConfig)
	}

	if err := ac.DeleteFilter(context.Background(), "apache/auth"); err != nil {
		t.Fatalf("DeleteFilter: %v", err)
	}
	if capturedPath != "/v1/filters/apache%2Fauth" {
		t.Fatalf("path escape mismatch: %q", capturedPath)
	}
}

func TestAgentConnectorGetJailsParsesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/callback/config" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if r.URL.Path == "/v1/jails" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jails": []map[string]any{
					{"jailName": "sshd", "totalBanned": 1, "newInLastHour": 0, "bannedIPs": []string{"1.1.1.1"}, "enabled": true},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	server := shared.Fail2banServer{
		ID:          "s1",
		Name:        "agent",
		Type:        "agent",
		AgentURL:    srv.URL,
		AgentSecret: "secret123",
	}
	c, err := NewAgentConnector(server)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	jails, err := c.GetJailInfos(context.Background())
	if err != nil {
		t.Fatalf("GetJailInfos: %v", err)
	}
	if len(jails) != 1 || jails[0].JailName != "sshd" {
		t.Fatalf("unexpected response: %+v", jails)
	}
}

func TestAgentConnectorGetAllJailsLargeResponse(t *testing.T) {
	var jailObjs []map[string]any
	for i := 0; i < 200; i++ {
		jailObjs = append(jailObjs, map[string]any{
			"jailName":      fmt.Sprintf("jail-%d", i),
			"totalBanned":   0,
			"newInLastHour": 0,
			"bannedIPs":     []string{},
			"enabled":       false,
		})
	}
	payload, err := json.Marshal(map[string]any{"jails": jailObjs})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) <= 4096 {
		t.Fatalf("payload too small for regression test: %d bytes", len(payload))
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/callback/config" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if r.URL.Path == "/v1/jails/all" {
			_, _ = w.Write(payload)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	server := shared.Fail2banServer{
		ID:          "s1",
		Name:        "agent",
		Type:        "agent",
		AgentURL:    srv.URL,
		AgentSecret: "secret123",
	}
	c, err := NewAgentConnector(server)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	jails, err := c.GetAllJails(context.Background())
	if err != nil {
		t.Fatalf("GetAllJails: %v", err)
	}
	if len(jails) != len(jailObjs) {
		t.Fatalf("got %d jails, want %d", len(jails), len(jailObjs))
	}
}

func TestAgentConnectorEnsureStructurePassesManagedContent(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})

	var ensurePayload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/callback/config":
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/v1/jails/check-integrity":
			_, _ = w.Write([]byte(`{"exists":false,"hasUIAction":false}`))
		case "/v1/jails/ensure-structure":
			_ = json.NewDecoder(r.Body).Decode(&ensurePayload)
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	server := shared.Fail2banServer{
		ID:          "s1",
		Name:        "agent",
		Type:        "agent",
		AgentURL:    srv.URL,
		AgentSecret: "secret123",
	}
	c, err := NewAgentConnector(server)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	if err := c.EnsureJailLocalStructure(context.Background()); err != nil {
		t.Fatalf("EnsureJailLocalStructure: %v", err)
	}
	raw, ok := ensurePayload["content"]
	if !ok {
		t.Fatalf("missing content payload: %#v", ensurePayload)
	}
	content, _ := raw.(string)
	if !strings.Contains(content, "action_mwlg") || !strings.Contains(content, "ui-custom-action") {
		t.Fatalf("expected full managed content payload, got: %s", content)
	}
}

func TestAgentConnectorTestLogpathPropagatesAgentError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/callback/config" {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		if r.URL.Path == "/v1/jails/test-logpath" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"boom"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	server := shared.Fail2banServer{
		ID:          "s1",
		Name:        "agent",
		Type:        "agent",
		AgentURL:    srv.URL,
		AgentSecret: "secret123",
	}
	c, err := NewAgentConnector(server)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	ac := c.(*AgentConnector)

	_, err = ac.TestLogpath(context.Background(), "/var/log/auth.log")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected HTTP status in error, got: %v", err)
	}
}

func TestAgentConnectorTestFilterParsesErrorPayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/callback/config" {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		if r.URL.Path == "/v1/filters/test" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"regex failed","output":"fail2ban-regex output","filterPath":"/tmp/filter.conf"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	server := shared.Fail2banServer{
		ID:          "s1",
		Name:        "agent",
		Type:        "agent",
		AgentURL:    srv.URL,
		AgentSecret: "secret123",
	}
	c, err := NewAgentConnector(server)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	ac := c.(*AgentConnector)

	output, filterPath, err := ac.TestFilter(context.Background(), "sshd", []string{"foo"}, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "regex failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if output != "fail2ban-regex output" {
		t.Fatalf("unexpected output: %q", output)
	}
	if filterPath != "/tmp/filter.conf" {
		t.Fatalf("unexpected filter path: %q", filterPath)
	}
}

func TestNewAgentConnectorReturnsTypedConfigErrors(t *testing.T) {
	tests := []struct {
		name   string
		server shared.Fail2banServer
		kind   AgentConfigErrorKind
	}{
		{
			name: "missing url",
			server: shared.Fail2banServer{
				Type:        "agent",
				AgentSecret: "secret",
			},
			kind: AgentConfigErrorMissingURL,
		},
		{
			name: "missing secret",
			server: shared.Fail2banServer{
				Type:     "agent",
				AgentURL: "http://127.0.0.1:9700",
			},
			kind: AgentConfigErrorMissingSecret,
		},
		{
			name: "invalid url",
			server: shared.Fail2banServer{
				Type:        "agent",
				AgentURL:    "://bad",
				AgentSecret: "secret",
			},
			kind: AgentConfigErrorInvalidURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAgentConnector(tt.server)
			if err == nil {
				t.Fatal("expected error")
			}
			var cfgErr *AgentConfigError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("expected AgentConfigError, got %T: %v", err, err)
			}
			if cfgErr.Kind != tt.kind {
				t.Fatalf("kind=%s want %s", cfgErr.Kind, tt.kind)
			}
		})
	}
}

func TestAgentConnectorUnauthorizedIncludesStructuredCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/callback/config" {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		if r.URL.Path == "/v1/jails" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized","code":"auth_invalid_token"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	server := shared.Fail2banServer{
		ID:          "s1",
		Name:        "agent",
		Type:        "agent",
		AgentURL:    srv.URL,
		AgentSecret: "wrong-secret",
	}
	c, err := NewAgentConnector(server)
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	_, err = c.GetJailInfos(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}

	var httpErr *AgentHTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected AgentHTTPError, got %T: %v", err, err)
	}
	if httpErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d", httpErr.StatusCode, http.StatusUnauthorized)
	}
	if httpErr.Code != "auth_invalid_token" {
		t.Fatalf("code=%q", httpErr.Code)
	}
	if got := AgentErrorMessageKey(err); got != "servers.errors.agent_wrong_secret" {
		t.Fatalf("message key=%q", got)
	}
}
