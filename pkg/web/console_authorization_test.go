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
	"testing"
)

func TestConsoleMessagesOnlyReachAdmins(t *testing.T) {
	hub := NewHub()
	admin := &Client{send: make(chan []byte, 2), canReadConsole: true}
	reader := &Client{send: make(chan []byte, 2)}
	hub.clients[admin], hub.clients[reader] = true, true
	hub.deliver([]byte(`{"type":"console_log","message":"private"}`))
	if len(admin.send) != 1 || len(reader.send) != 0 {
		t.Fatal("console message did not respect permissions")
	}
	hub.deliver([]byte(`{"type":"ban_event","data":{}}`))
	if len(admin.send) != 2 || len(reader.send) != 1 {
		t.Fatal("event readers must still receive ban events")
	}
}
