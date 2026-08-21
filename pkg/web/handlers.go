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
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
)

// =========================================================================
//  Types and Variables
// =========================================================================

var wsHub *Hub

// SetWebSocketHub sets the global WebSocket hub instance
func SetWebSocketHub(hub *Hub) {
	wsHub = hub
}

// =========================================================================
//  Request Helpers
// =========================================================================

// Resolves the Fail2ban connector for the current request.
// Uses the "serverId" query param, "X-F2B-Server" header, or the default server.
func resolveConnector(c *gin.Context) (fail2ban.Connector, error) {
	serverID := c.Query("serverId")
	if serverID == "" {
		serverID = c.GetHeader("X-F2B-Server")
	}
	manager := fail2ban.GetManager()
	if serverID != "" {
		return manager.Connector(serverID)
	}
	return manager.DefaultConnector()
}

// Resolves a server by ID, hostname, or falls back to default.
func resolveServerForNotification(serverID, hostname string) (config.Fail2banServer, error) {
	if serverID != "" {
		if srv, ok := config.GetServerByID(serverID); ok {
			if !srv.Enabled {
				return config.Fail2banServer{}, fmt.Errorf("server %s is disabled", serverID)
			}
			return srv, nil
		}
		return config.Fail2banServer{}, fmt.Errorf("serverId %s not found", serverID)
	}
	if hostname != "" {
		if srv, ok := config.GetServerByHostname(hostname); ok {
			if !srv.Enabled {
				return config.Fail2banServer{}, fmt.Errorf("server for hostname %s is disabled", hostname)
			}
			return srv, nil
		}
	}
	srv := config.GetDefaultServer()
	if srv.ID == "" {
		return config.Fail2banServer{}, fmt.Errorf("no default fail2ban server configured")
	}
	if !srv.Enabled {
		return config.Fail2banServer{}, fmt.Errorf("default fail2ban server is disabled")
	}
	return srv, nil
}

func buildErrorResponse(err error, fallbackKey string) gin.H {
	resp := gin.H{"error": err.Error()}
	if key := fail2ban.AgentErrorMessageKey(err); key != "" {
		resp["messageKey"] = key
		return resp
	}
	if key := fail2ban.SSHErrorMessageKey(err); key != "" {
		resp["messageKey"] = key
		var hk *fail2ban.SSHHostKeyError
		if errors.As(err, &hk) && hk.Fingerprint != "" {
			resp["hostKeyFingerprint"] = hk.Fingerprint
		}
		return resp
	}
	if fallbackKey != "" {
		resp["messageKey"] = fallbackKey
	}
	return resp
}
