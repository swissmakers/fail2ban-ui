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
	"encoding/json"
	"strings"
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/operations"
)

func TestOperationWebSocketRedactsDiagnosticsForNonAdmins(t *testing.T) {
	hub := NewHub()
	admin := &Client{canReadConsole: true, send: make(chan []byte, 1)}
	reader := &Client{canReadConsole: false, send: make(chan []byte, 1)}
	hub.clients[admin] = true
	hub.clients[reader] = true
	op := operations.Operation{
		ID: "operation-test", ServerID: "server-a", Kind: "jail.config", State: "failed", Phase: "validating",
		Message: "Operation failed", Error: "private remote diagnostic /etc/private-config",
		Result:   json.RawMessage(`{"error":"private remote diagnostic","configurationRestored":true}`),
		Payload:  json.RawMessage(`{"configuration":"private-config-payload"}`),
		Recovery: json.RawMessage(`{"backup":"private-recovery-data"}`),
	}
	message, err := json.Marshal(map[string]any{"type": "operation", "data": exposeOperation(op)})
	if err != nil {
		t.Fatal(err)
	}
	hub.deliver(message)
	adminMessage := <-admin.send
	readerMessage := <-reader.send
	if !strings.Contains(string(adminMessage), "private remote diagnostic") {
		t.Fatal("administrator lost the diagnostic required to fix the failed task")
	}
	for _, secret := range []string{"private remote diagnostic", "/etc/private-config", "private-config-payload", "private-recovery-data"} {
		if strings.Contains(string(readerMessage), secret) {
			t.Fatalf("reader received protected operation detail %q: %s", secret, readerMessage)
		}
	}
	var event struct {
		Type string          `json:"type"`
		Data publicOperation `json:"data"`
	}
	if err := json.Unmarshal(readerMessage, &event); err != nil {
		t.Fatal(err)
	}
	if event.Data.ID != op.ID || event.Data.State != "failed" || event.Data.Phase != "validating" {
		t.Fatalf("reader lost useful progress metadata: %+v", event.Data)
	}
	if len(event.Data.Result) != 0 || !strings.Contains(event.Data.Error, "administrator") {
		t.Fatalf("expected redacted failure: %+v", event.Data)
	}
}

func TestRedactedSuccessfulOperationStillCompletesSupportUI(t *testing.T) {
	op := exposeOperation(operations.Operation{
		ID: "ban", ServerID: "a", Kind: "jail.ban", State: "succeeded",
		Result: json.RawMessage(`{"message":"done","private":"diagnostic"}`),
	})
	public := redactOperation(op, false)
	var result map[string]any
	if err := json.Unmarshal(public.Result, &result); err != nil {
		t.Fatal(err)
	}
	if public.State != "succeeded" || result["message"] == "" || result["private"] != nil {
		t.Fatalf("safe successful result is unusable: %+v", public)
	}
}
