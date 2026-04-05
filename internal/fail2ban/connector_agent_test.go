package fail2ban

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

func TestNormalizeAgentURL(t *testing.T) {
	u, err := normalizeAgentURL("127.0.0.1")
	if err != nil {
		t.Fatalf("normalize error: %v", err)
	}
	if got := u.String(); got != "http://127.0.0.1:9443" {
		t.Fatalf("got %q", got)
	}

	u, err = normalizeAgentURL("https://agent.example.local")
	if err != nil {
		t.Fatalf("normalize https error: %v", err)
	}
	if got := u.String(); got != "https://agent.example.local:9443" {
		t.Fatalf("got %q", got)
	}
}

func TestAgentConnectorHeadersAndPathEscape(t *testing.T) {
	var capturedPath, capturedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedToken = r.Header.Get("X-F2B-Token")
		switch {
		case r.URL.Path == "/v1/actions/ui-custom":
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
		t.Fatalf("ensureAction token mismatch: %q", capturedToken)
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
		if r.URL.Path == "/v1/actions/ui-custom" {
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
