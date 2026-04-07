package fail2ban

import (
	"context"
	"encoding/json"
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

func TestAgentConnectorEnsureStructureStripsUICustomAction(t *testing.T) {
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
	if strings.Contains(content, "ui-custom-action") || strings.Contains(content, "action_mwlg") {
		t.Fatalf("content still contains UI action block: %s", content)
	}
}
