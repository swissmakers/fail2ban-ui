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
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
)

func TestBusyServerEditsAreRejectedBeforeSettingsArePersisted(t *testing.T) {
	server, err := config.UpsertServer(config.Fail2banServer{ID: "busy-server-preflight", Name: "original", Type: "local", Enabled: false, EnabledSet: true, SocketPath: "/tmp/f2bui-preflight.sock", ConfigPath: "/config/fail2ban"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = config.DeleteServer(server.ID) })
	_, release, err := fail2ban.GetManager().BeginOperation(context.Background(), server.ID, "busy-config-op", "jail.manage")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	changed := server
	changed.Name = "must-not-persist"
	body, _ := json.Marshal(changed)
	c, w := newTestContext(http.MethodPost, "/api/servers", string(body))
	UpsertServerHandler(c)
	if w.Code != http.StatusConflict {
		t.Fatalf("upsert status=%d body=%s", w.Code, w.Body.String())
	}
	stored, found := config.GetServerByID(server.ID)
	if !found || stored.Name != server.Name {
		t.Fatal("blocked upsert changed persisted settings")
	}
	c, w = newTestContext(http.MethodDelete, "/api/servers/"+server.ID, "")
	c.Params = gin.Params{{Key: "id", Value: server.ID}}
	DeleteServerHandler(c)
	if w.Code != http.StatusConflict {
		t.Fatalf("delete status=%d body=%s", w.Code, w.Body.String())
	}
	if _, found := config.GetServerByID(server.ID); !found {
		t.Fatal("blocked deletion removed persisted server")
	}
}
