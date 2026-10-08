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
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

type testProvider struct{}

func (testProvider) DebugLog(format string, v ...interface{}) {}
func (testProvider) CallbackURL() string                      { return "http://127.0.0.1:8080" }
func (testProvider) CallbackSecret() string                   { return "test-secret" }
func (testProvider) ServerPort() int                          { return 8080 }
func (testProvider) BuildFail2banActionConfig(callbackURL, serverID, secret string) (string, error) {
	return fmt.Sprintf("[Definition]\nactionban = curl -X POST %s/api/ban -H 'X-Callback-Secret: %s' --data 'serverId=%s'\n",
		callbackURL, secret, serverID), nil
}
func (testProvider) BuildJailLocalContent() string {
	return "[DEFAULT]\nenabled = true\naction_mwlg = %(action_)s\n             ui-custom-action[logpath=\"%(logpath)s\", chain=\"%(chain)s\"]\naction = %(action_mwlg)s\n"
}

func TestNormalizeAgentURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"127.0.0.1", "http://127.0.0.1:9700"},
		{"agent.example.local:1234", "http://agent.example.local:1234"},
		{"https://agent.example.local", "https://agent.example.local"},
		{"https://agent.example.local/", "https://agent.example.local/"},
		{"https://agent.example.local:443/", "https://agent.example.local:443/"},
		{"http://agent.example.local", "http://agent.example.local"},
		{"https://agent.example.local:9700", "https://agent.example.local:9700"},
	}
	for _, tc := range cases {
		u, err := NormalizeAgentURL(tc.in)
		if err != nil {
			t.Fatalf("NormalizeAgentURL(%q): %v", tc.in, err)
		}
		if got := u.String(); got != tc.want {
			t.Fatalf("NormalizeAgentURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	for _, invalid := range []string{"", "ftp://agent.example.local", "http://"} {
		if _, err := NormalizeAgentURL(invalid); err == nil {
			t.Fatalf("NormalizeAgentURL(%q) expected error", invalid)
		}
	}
}

func TestAgentConnectorCallbackConfigWithoutConstructorNetwork(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})
	var requests int
	var capturedToken string
	var callbackConfig map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		capturedToken = r.Header.Get("X-F2B-Token")
		if r.URL.Path == "/v1/callback/config" {
			_ = json.NewDecoder(r.Body).Decode(&callbackConfig)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c, err := NewAgentConnector(shared.Fail2banServer{ID: "s1", Name: "agent", Type: "agent", AgentURL: srv.URL, AgentSecret: "secret123"})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	if requests != 0 {
		t.Fatalf("constructor sent %d requests, want none", requests)
	}
	ac := c.(*AgentConnector)
	if err := ac.ensureCallbackConfig(context.Background()); err != nil {
		t.Fatalf("ensureCallbackConfig: %v", err)
	}
	if capturedToken != "secret123" || callbackConfig["serverId"] != "s1" || callbackConfig["callbackUrl"] == nil {
		t.Fatalf("token=%q config=%#v", capturedToken, callbackConfig)
	}
	if err := ac.DeleteFilter(context.Background(), "apache/auth"); err == nil {
		t.Fatal("DeleteFilter must reject a name with a slash")
	}
	if requests != 1 {
		t.Fatalf("invalid name reached the agent (%d requests)", requests)
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
	summary, err := c.GetJailSummary(context.Background())
	if err != nil {
		t.Fatalf("GetJailSummary: %v", err)
	}
	if len(summary.Jails) != 1 || summary.Jails[0].JailName != "sshd" {
		t.Fatalf("unexpected response: %+v", summary.Jails)
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
		case "/v1/operations/capabilities":
			_, _ = w.Write([]byte(agentOperationCapabilities))
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

	_, err = ac.testLogpathLegacy(context.Background(), "/var/log/auth.log")
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
	_, err = c.GetJailSummary(context.Background())
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

func newTestAgent(t *testing.T, handler http.HandlerFunc) *AgentConnector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := NewAgentConnector(shared.Fail2banServer{ID: "s1", Name: "agent", Type: "agent", AgentURL: srv.URL, AgentSecret: "secret123"})
	if err != nil {
		t.Fatalf("new connector: %v", err)
	}
	return c.(*AgentConnector)
}

func TestAgentNewRequestURL(t *testing.T) {
	tests := []struct {
		base, endpoint, want string
	}{
		{"http://agent:9700", "/v1/jails", "http://agent:9700/v1/jails"},
		{"https://proxy.example/agent/", "/v1/jails/sshd/config", "https://proxy.example/agent/v1/jails/sshd/config"},
		{"http://agent:9700", "/v1/filters/" + url.PathEscape("a b"), "http://agent:9700/v1/filters/a%20b"},
		{"http://agent:9700", "/v1/callback/config?serverId=s%201", "http://agent:9700/v1/callback/config?serverId=s%201"},
	}
	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			base, err := url.Parse(tt.base)
			if err != nil {
				t.Fatal(err)
			}
			ac := &AgentConnector{base: base}
			req, err := ac.newRequest(context.Background(), http.MethodGet, tt.endpoint, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := req.URL.String(); got != tt.want {
				t.Fatalf("URL = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAgentDoRejectsRedirect(t *testing.T) {
	ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	})
	err := ac.BanIP(context.Background(), "sshd", "192.0.2.1")
	if !agentStatusIs(err, http.StatusFound) {
		t.Fatalf("redirect reported as %v, want an HTTP 302 error", err)
	}
}

func TestAgentRestartParsesMode(t *testing.T) {
	for mode, want := range map[string]string{"reload": "reload", "": "restart"} {
		ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/operations/capabilities" {
				_, _ = w.Write([]byte(agentOperationCapabilities))
				return
			}
			var op AgentOperation
			if r.Method != http.MethodPost || r.URL.Path != "/v1/operations" {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			_ = json.NewDecoder(r.Body).Decode(&op)
			op.State, op.Mode, op.Quiescent = "succeeded", mode, true
			_ = json.NewEncoder(w).Encode(op)
		})
		if mode, err := ac.Restart(context.Background()); err != nil || mode != want {
			t.Fatalf("mode=%q err=%v, want %q", mode, err, want)
		}
	}
}

const agentOperationCapabilities = `{"version":1,"kinds":["reload","restart","validate","ban","unban"],"configurationSnapshots":true}`

func TestAgentOperationLostSubmitResponseRecoversWithoutResubmit(t *testing.T) {
	var submitted AgentOperation
	var posts atomic.Int32
	ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/operations/capabilities":
			_, _ = w.Write([]byte(agentOperationCapabilities))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/operations":
			posts.Add(1)
			_ = json.NewDecoder(r.Body).Decode(&submitted)
			submitted.State, submitted.Quiescent = "succeeded", true
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
		case r.Method == http.MethodGet && r.URL.Path == "/v1/operations/"+submitted.ID:
			_ = json.NewEncoder(w).Encode(submitted)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	})
	ctx := context.WithValue(context.Background(), operationLeaseKey{}, &operationLease{id: "parent-id"})
	ctx = WithOperationPhase(ctx, "primary-reload")
	if err := ac.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 1 || submitted.ID != AgentOperationID(ctx, "reload") {
		t.Fatalf("duplicate or unstable submit: %d %+v", posts.Load(), submitted)
	}
}

func TestAgentOperationCancellationAndPhaseIdentity(t *testing.T) {
	ctx := context.WithValue(context.Background(), operationLeaseKey{}, &operationLease{id: "parent-id"})
	primary := WithOperationPhase(ctx, "primary-reload")
	rollback := WithOperationPhase(ctx, "rollback-reload")
	if AgentOperationID(primary, "reload") == AgentOperationID(rollback, "reload") || AgentOperationID(primary, "reload") != AgentOperationID(WithOperationPhase(ctx, "primary-reload"), "reload") {
		t.Fatal("phase identities are not stable and distinct")
	}
	ctx, cancel := context.WithCancel(primary)
	defer cancel()
	var posts atomic.Int32
	ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/operations/capabilities" {
			_, _ = w.Write([]byte(agentOperationCapabilities))
			return
		}
		posts.Add(1)
		var op AgentOperation
		_ = json.NewDecoder(r.Body).Decode(&op)
		op.State = "running"
		_ = json.NewEncoder(w).Encode(op)
		time.AfterFunc(10*time.Millisecond, cancel)
	})
	if err := ac.Reload(ctx); !errors.Is(err, ErrOperationOutcomeUnknown) {
		t.Fatalf("cancellation was reported as definitive failure: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("canceled operation retried: %d", posts.Load())
	}
}

func TestOldAgentRefusesConfigChangesBeforeWriting(t *testing.T) {
	var mutations atomic.Int32
	ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutations.Add(1)
		}
		w.WriteHeader(http.StatusNotFound)
	})
	for _, change := range []func() error{
		func() error { return ac.UpdateJailEnabledStates(context.Background(), map[string]bool{"ssh": true}) },
		func() error { return ac.SetJailConfig(context.Background(), "ssh", "[ssh]\n") },
		func() error { return ac.SetFilterConfig(context.Background(), "ssh", "[Definition]\n") },
		func() error { return ac.Reload(context.Background()) },
		func() error { return ac.ValidateConfiguration(context.Background()) },
	} {
		if err := change(); err == nil || !strings.Contains(err.Error(), "upgrade required") {
			t.Fatalf("unsupported agent admitted change: %v", err)
		}
	}
	if mutations.Load() != 0 {
		t.Fatalf("old agent received %d mutations", mutations.Load())
	}
}

func TestAgentReconcileUnknownRemainsUnknownWhenQuiescent(t *testing.T) {
	ctx := context.WithValue(context.Background(), operationLeaseKey{}, &operationLease{id: "parent-id"})
	ctx = WithOperationPhase(ctx, "primary-reload")
	ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/operations/"+AgentOperationID(ctx, "reload") {
			t.Errorf("reconciliation mutated or looked up wrong operation: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(AgentOperation{ID: AgentOperationID(ctx, "reload"), Kind: "reload", State: "unknown", Quiescent: true})
	})
	op, err := ac.ReconcileOperation(ctx, "reload")
	if err != nil || op.State != "unknown" || !op.Quiescent {
		t.Fatalf("unknown outcome was hidden: %+v %v", op, err)
	}
}

func TestAgentReconcileMissingIDSealsDelayedSubmission(t *testing.T) {
	ctx := context.WithValue(context.Background(), operationLeaseKey{}, &operationLease{id: "missing-parent"})
	ctx = WithOperationPhase(ctx, "primary-reload")
	var sealed atomic.Int32
	ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		id := AgentOperationID(ctx, "reload")
		if r.Method == http.MethodGet && r.URL.Path == "/v1/operations/"+id {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/v1/operations/"+id+"/reconcile" {
			sealed.Add(1)
			_ = json.NewEncoder(w).Encode(AgentOperation{ID: id, Kind: "reload", State: "unknown", Code: "not_dispatched"})
			return
		}
		t.Errorf("recovery sent unexpected command: %s %s", r.Method, r.URL.Path)
	})
	op, err := ac.ReconcileOperation(ctx, "reload")
	if err != nil || op.Code != "not_dispatched" || sealed.Load() != 1 {
		t.Fatalf("missing ID not sealed: %+v %v", op, err)
	}
}

func TestAgentBanAndUnbanUseDurableProtocol(t *testing.T) {
	for _, kind := range []string{"ban", "unban"} {
		t.Run(kind, func(t *testing.T) {
			ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/operations/capabilities" {
					_, _ = w.Write([]byte(agentOperationCapabilities))
					return
				}
				if r.Method != http.MethodPost || r.URL.Path != "/v1/operations" {
					t.Errorf("legacy mutation called: %s %s", r.Method, r.URL.Path)
				}
				var op AgentOperation
				_ = json.NewDecoder(r.Body).Decode(&op)
				if op.Kind != kind || op.Jail != "sshd" || op.IP != "192.0.2.1" {
					t.Errorf("wrong ban target: %+v", op)
				}
				op.State, op.Quiescent = "succeeded", true
				_ = json.NewEncoder(w).Encode(op)
			})
			var err error
			if kind == "ban" {
				err = ac.BanIP(context.Background(), "sshd", "192.0.2.1")
			} else {
				err = ac.UnbanIP(context.Background(), "sshd", "192.0.2.1")
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAgentValidateConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{name: "ok", status: 200, body: `{"ok":true,"output":"OK: configuration test is successful"}`},
		{name: "invalid", status: 422, body: `{"ok":false,"code":"config_invalid","error":"invalid","output":"ERROR No section: 'sshd'"}`, wantErr: "No section: 'sshd'"},
		{name: "old agent", status: 404, body: `404 page not found`, wantErr: "agent upgrade required"},
		{name: "agent failure", status: 500, body: `{"ok":false,"error":"boom"}`, wantErr: "500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/operations/capabilities" {
					if tt.status == 404 || tt.status == 500 {
						w.WriteHeader(tt.status)
						_, _ = w.Write([]byte(tt.body))
						return
					}
					_, _ = w.Write([]byte(agentOperationCapabilities))
					return
				}
				if r.URL.Path != "/v1/operations" || r.Method != http.MethodPost {
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				}
				var op AgentOperation
				_ = json.NewDecoder(r.Body).Decode(&op)
				_ = json.Unmarshal([]byte(tt.body), &op)
				op.State, op.Quiescent = "succeeded", true
				if tt.status == 422 {
					op.State = "failed"
				}
				_ = json.NewEncoder(w).Encode(op)
			})
			err := ac.ValidateConfiguration(context.Background())
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestAgentLogpathFallsBackOnlyOnMissingEndpoint(t *testing.T) {
	for status, wantLegacy := range map[int]bool{http.StatusInternalServerError: false, http.StatusNotFound: true} {
		legacy := false
		ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/jails/test-logpath-with-resolution":
				w.WriteHeader(status)
			case "/v1/jails/test-logpath":
				legacy = true
				_, _ = w.Write([]byte(`{"files":["/var/log/auth.log"]}`))
			}
		})
		_, _, files, err := ac.TestLogpathWithResolution(context.Background(), "/var/log/auth.log")
		if legacy != wantLegacy {
			t.Fatalf("status %d: legacy endpoint called=%v, want %v", status, legacy, wantLegacy)
		}
		if wantLegacy && (err != nil || len(files) != 1) {
			t.Fatalf("legacy fallback: files=%v err=%v", files, err)
		}
		if !wantLegacy && err == nil {
			t.Fatal("agent failure was hidden by the fallback")
		}
	}
}

func TestAgentLogpathCodedRejection(t *testing.T) {
	ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"original_logpath":"/var/log/secure","files":[],"error":"permission denied","code":"logpath_inaccessible"}`))
	})
	_, _, _, err := ac.TestLogpathWithResolution(context.Background(), "/var/log/secure")
	if !errors.Is(err, ErrLogpathInaccessible) {
		t.Fatalf("coded 422 not mapped to ErrLogpathInaccessible: %v", err)
	}
}

func TestAgentLogpathError(t *testing.T) {
	if err := agentLogpathError("logpath_inaccessible", "permission denied"); !errors.Is(err, ErrLogpathInaccessible) {
		t.Fatalf("inaccessible not mapped: %v", err)
	}
	if err := agentLogpathError("logpath_invalid", "relative path"); errors.Is(err, ErrLogpathInaccessible) || !strings.Contains(err.Error(), "relative path") {
		t.Fatalf("invalid mapped wrong: %v", err)
	}
}

func TestAgentDeregister(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusMethodNotAllowed} {
		var method, serverID string
		ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) {
			method, serverID = r.Method, r.URL.Query().Get("serverId")
			w.WriteHeader(status)
		})
		ac.deregister()
		if method != http.MethodDelete || serverID != "s1" {
			t.Fatalf("status %d: got %s serverId=%q", status, method, serverID)
		}
	}
}

func TestReleaseConnectorDeregistersOnlyDepartedAgents(t *testing.T) {
	deleted := make(chan string, 4)
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted <- r.URL.Query().Get("serverId")
		}
	}
	old := newTestAgent(t, handler)
	sameURL := &AgentConnector{server: old.server, base: old.base}
	releaseConnector(old, sameURL)
	select {
	case id := <-deleted:
		t.Fatalf("agent with unchanged URL was deregistered (%s)", id)
	case <-time.After(200 * time.Millisecond):
	}
	releaseConnector(old, nil)
	select {
	case id := <-deleted:
		if id != "s1" {
			t.Fatalf("deregistered %q", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("removed agent was not deregistered")
	}
}

func TestHealthFromDetail(t *testing.T) {
	const fp = "0123456789abcdef0123456789abcdef"
	ready := func(mod func(*agentHealthDetail)) agentHealthDetail {
		d := agentHealthDetail{Ready: true}
		d.Callback.Configured, d.Callback.ServerID, d.Callback.Fingerprint = true, "s1", fp
		if mod != nil {
			mod(&d)
		}
		return d
	}
	tests := []struct {
		name        string
		detail      agentHealthDetail
		want        HealthState
		wantDrifted bool
	}{
		{name: "healthy", detail: ready(nil), want: HealthOK},
		{name: "busy", detail: ready(func(d *agentHealthDetail) { d.Busy = true }), want: HealthBusy},
		{name: "not ready", detail: agentHealthDetail{Checks: map[string]bool{"fail2banPing": false, "configWritable": true}}, want: HealthDown},
		{name: "no callback config", detail: ready(func(d *agentHealthDetail) { d.Callback.Configured = false }), want: HealthDegraded, wantDrifted: true},
		{name: "stale fingerprint", detail: ready(func(d *agentHealthDetail) { d.Callback.Fingerprint = "other" }), want: HealthDegraded, wantDrifted: true},
		{name: "other server entry", detail: ready(func(d *agentHealthDetail) { d.Callback.ServerID = "s2" }), want: HealthDegraded},
		{name: "delivery failing", detail: ready(func(d *agentHealthDetail) { d.Callback.LastError = "connection refused" }), want: HealthDegraded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, drifted := healthFromDetail(tt.detail, "s1", fp)
			if got := deriveHealthState(h); got != tt.want || drifted != tt.wantDrifted {
				t.Fatalf("state=%s drifted=%v (%+v), want %s drifted=%v", got, drifted, h, tt.want, tt.wantDrifted)
			}
			if tt.want != HealthOK && h.Error == "" {
				t.Fatal("unhealthy result without a reason")
			}
		})
	}
}

func TestHealthFromLegacyReadyz(t *testing.T) {
	if h := healthFromLegacyReadyz(200, []byte(`{"ready":true,"state":{"healthy":true}}`)); !h.Fail2banOK || h.CallbackOK != nil {
		t.Fatalf("ready legacy agent: %+v", h)
	}
	h := healthFromLegacyReadyz(503, []byte(`{"ready":false,"state":{"lastError":"ping failed"}}`))
	if h.Fail2banOK || h.Error != "ping failed" {
		t.Fatalf("unready legacy agent: %+v", h)
	}
}

func TestCheckIntegrityOnOldAgentAssumesManaged(t *testing.T) {
	ac := newTestAgent(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	exists, managed, err := ac.CheckJailLocalIntegrity(context.Background())
	if err != nil || !exists || !managed {
		t.Fatalf("exists=%v managed=%v err=%v, want true/true/nil", exists, managed, err)
	}
}

// Shared vector with the agent's CallbackFingerprint; both sides must agree byte for byte.
func TestAgentCallbackFingerprint(t *testing.T) {
	const want = "9563176e6c67afcc7e2efa9843f91808"
	if got := agentCallbackFingerprint("agent-token-0123456789", "srv-1", "https://ui.example.com/", "cb-secret-123"); got != want {
		t.Fatalf("fingerprint = %s, want %s", got, want)
	}
	if agentCallbackFingerprint("other-token-0123456789", "srv-1", "https://ui.example.com", "cb-secret-123") == want {
		t.Fatal("fingerprint must depend on the agent token")
	}
}
