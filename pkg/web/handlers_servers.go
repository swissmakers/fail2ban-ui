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
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
)

// =========================================================================
//  Fail2ban Servers Management
// =========================================================================

// Returns all configured Fail2ban servers.
func ListServersHandler(c *gin.Context) {
	servers := config.ListServers()
	masked := maskServerSecrets(servers)
	if !userHasAdminAccess(c) {
		masked = stripServerConnectionDetails(masked)
	} else {
		for i := range masked {
			if hk := fail2ban.HostKeyIssue(masked[i].ID); hk != nil {
				masked[i].HostKeyError = hk.Error()
				masked[i].HostKeyFingerprint = hk.Fingerprint
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"servers": masked})
}

// Creates or updates a Fail2ban server configuration.
func UpsertServerHandler(c *gin.Context) {
	var req config.Fail2banServer
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
		return
	}

	if existing, ok := config.GetServerByID(req.ID); ok {
		req.AgentSecret = restoreSecret(req.AgentSecret, existing.AgentSecret)
	}

	switch strings.ToLower(req.Type) {
	case "", "local":
		req.Type = "local"
	case "ssh":
		if req.Host == "" || req.SSHUser == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ssh servers require host and sshUser"})
			return
		}
	case "agent":
		if req.AgentURL == "" || req.AgentSecret == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":      "agent servers require agentUrl and agentSecret",
				"messageKey": "servers.errors.agent_missing_config",
			})
			return
		}
		u, err := fail2ban.NormalizeAgentURL(req.AgentURL)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":      "invalid agentUrl: " + err.Error(),
				"messageKey": "servers.errors.agent_invalid_url",
			})
			return
		}
		req.AgentURL = u.String()
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported server type"})
		return
	}

	// Field-level validation happens in config.UpsertServer after normalization.

	// Check if server exists and was previously disabled
	oldServer, wasEnabled := config.GetServerByID(req.ID)
	wasDisabled := !wasEnabled || !oldServer.Enabled

	server, err := config.UpsertServer(req)
	if err != nil {
		resp := gin.H{"error": err.Error()}
		if errors.Is(err, config.ErrInvalidTunnelPort) {
			resp["messageKey"] = "servers.errors.invalid_tunnel_port"
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	// Check if server was just enabled (transition from disabled to enabled)
	justEnabled := wasDisabled && server.Enabled
	tunnelChanged := wasEnabled && oldServer.Enabled && server.Enabled &&
		(oldServer.ReverseTunnelEnabled != server.ReverseTunnelEnabled || oldServer.TunnelPort != server.TunnelPort)

	if err := config.ReloadFail2banManager(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if (justEnabled || tunnelChanged) && (server.Type == "ssh" || server.Type == "agent") {
		if err := fail2ban.GetManager().UpdateActionFileForServer(c.Request.Context(), server.ID); err != nil {
			config.DebugLog("Warning: failed to update action file for server %s: %v", server.Name, err)
		}
		if tunnelChanged {
			if conn, err := fail2ban.GetManager().Connector(server.ID); err == nil {
				if err := conn.Reload(c.Request.Context()); err != nil {
					config.DebugLog("Warning: failed to reload fail2ban on server %s after tunnel change: %v", server.Name, err)
				}
			}
		}
	}

	// Ensures the jail.local structure is properly initialized for newly enabled/added servers
	var actionFileWarning string
	var jailLocalWarning bool
	var restartWarning string
	if justEnabled && server.Type == "local" {
		if err := config.EnsureLocalFail2banAction(server); err != nil {
			config.DebugLog("Warning: failed to prepare local action artifacts for server %s: %v", server.Name, err)
			actionFileWarning = err.Error()
		}
	}
	if justEnabled || !wasEnabled {
		conn, err := fail2ban.GetManager().Connector(server.ID)
		if err == nil {
			// EnsureJailLocalStructure respects user-owned files:
			//   - file missing --> creates it
			//   - file is ours --> updates it
			//   - file is user's own --> leave it alone
			if !(server.Type == "local" && actionFileWarning != "") {
				if err := conn.EnsureJailLocalStructure(c.Request.Context()); err != nil {
					config.DebugLog("Warning: failed to ensure jail.local structure for server %s: %v", server.Name, err)
				} else {
					config.DebugLog("Successfully ensured jail.local structure for server %s", server.Name)
				}
			}

			// Checks the integrity AFTER ensuring structure so fresh servers don't trigger a false-positive warning.
			if exists, hasUI, chkErr := conn.CheckJailLocalIntegrity(c.Request.Context()); chkErr == nil && exists && !hasUI {
				jailLocalWarning = true
				log.Printf("WARNING: Server %s: jail.local is not managed by Fail2ban-UI. Please migrate your jail.local manually (see documentation).", server.Name)
			}

			// Tries to restart Fail2ban and performs a basic health check after the server was enabled
			if justEnabled {
				if err := conn.Restart(c.Request.Context()); err != nil {
					// Local connectors can report a transient "Could not find server" during initial startup.
					// Recheck briefly before surfacing a warning toast.
					if server.Type == "local" && waitForConnectorReady(c.Request.Context(), conn, 4, 750*time.Millisecond) {
						config.DebugLog("Local connector %s became healthy after transient restart/reload error: %v", server.Name, err)
					} else {
						msg := fmt.Sprintf("failed to restart fail2ban for server %s: %v", server.Name, err)
						config.DebugLog("Warning: %s", msg)
						restartWarning = msg
					}
				} else {
					if _, err := conn.GetJailInfos(c.Request.Context()); err != nil {
						config.DebugLog("Warning: fail2ban appears unhealthy on server %s after restart: %v", server.Name, err)
					} else {
						config.DebugLog("Fail2ban service appears healthy on server %s after restart", server.Name)
					}
				}
			}
		}
	}

	resp := gin.H{"server": maskServer(server)}
	if jailLocalWarning {
		resp["jailLocalWarning"] = true
	}
	if actionFileWarning != "" {
		resp["actionFileWarning"] = actionFileWarning
	}
	if restartWarning != "" {
		resp["restartWarning"] = restartWarning
	}
	// ReloadFail2banManager above already probed the host, so a host-key
	// problem is known here; let the UI warn right after save.
	if hk := fail2ban.HostKeyIssue(server.ID); hk != nil {
		resp["hostKeyError"] = hk.Error()
		if hk.Fingerprint != "" {
			resp["hostKeyFingerprint"] = hk.Fingerprint
		}
	}
	c.JSON(http.StatusOK, resp)
}

// Removes a server configuration by ID.
func DeleteServerHandler(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id parameter"})
		return
	}
	if err := config.DeleteServer(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := config.ReloadFail2banManager(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "server deleted"})
}

// Marks a server as the default.
func SetDefaultServerHandler(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id parameter"})
		return
	}
	server, err := config.SetDefaultServer(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := config.ReloadFail2banManager(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"server": maskServer(server)})
}

// Returns available SSH private keys from the host or container.
func ListSSHKeysHandler(c *gin.Context) {
	var dir string
	if _, container := os.LookupEnv("CONTAINER"); container {
		// In container, we look for SSH keys in the /config/.ssh directory
		dir = "/config/.ssh"
	} else {
		// On host, we look for SSH keys in the user's home directory
		home, err := os.UserHomeDir()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		dir = filepath.Join(home, ".ssh")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, gin.H{"keys": []string{}, "messageKey": "servers.form.no_keys"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var keys []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if (strings.HasPrefix(name, "id_") && !strings.HasSuffix(name, ".pub")) ||
			strings.HasSuffix(name, ".pem") ||
			(strings.HasSuffix(name, ".key") && !strings.HasSuffix(name, ".pub")) {
			keyPath := filepath.Join(dir, name)
			keys = append(keys, keyPath)
		}
	}
	if len(keys) == 0 {
		c.JSON(http.StatusOK, gin.H{"keys": []string{}, "messageKey": "servers.form.no_keys"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

// Verifies connectivity to a configured Fail2ban server by ID.
func TestServerHandler(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id parameter"})
		return
	}
	server, ok := config.GetServerByID(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "server not found"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	conn, err := fail2ban.GetManager().Connector(server.ID)
	if err != nil {
		conn, err = fail2ban.NewConnector(server)
		if err != nil {
			c.JSON(http.StatusBadRequest, buildErrorResponse(err, "servers.actions.test_failure"))
			return
		}
		defer func() {
			if err := conn.Close(); err != nil {
				config.DebugLog("Warning: failed to close test connector for server %s: %v", server.Name, err)
			}
		}()
	}

	if _, err := conn.GetJailInfos(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "servers.actions.test_failure"))
		return
	}

	// Checks the jail.local integrity: if it exists but is not managed by Fail2ban-UI, we warn the user.
	// If the file was removed (e.g. after finished migration or just deleted), we initialize a fresh managed file.
	resp := gin.H{"messageKey": "servers.actions.test_success"}
	if exists, hasUI, err := conn.CheckJailLocalIntegrity(ctx); err == nil {
		if exists && !hasUI {
			resp["jailLocalWarning"] = true
		} else if !exists {
			if err := conn.EnsureJailLocalStructure(ctx); err != nil {
				config.DebugLog("Warning: failed to initialize jail.local on test request: %v", err)
			} else {
				config.DebugLog("Initialized fresh jail.local for server %s (file was missing)", conn.Server().Name)
			}
		}
	}
	c.JSON(http.StatusOK, resp)
}

func waitForConnectorReady(ctx context.Context, conn fail2ban.Connector, attempts int, delay time.Duration) bool {
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if _, err := conn.GetJailInfos(ctx); err == nil {
			return true
		}
		if i == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(delay):
		}
	}
	return false
}

// =========================================================================
//  SSH Host Key Accept
// =========================================================================

var sshFingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// Replaces the pinned SSH host key of a server with the fingerprint the admin
// reviewed and approved in the UI.
func AcceptHostKeyHandler(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id parameter"})
		return
	}
	server, ok := config.GetServerByID(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "server not found"})
		return
	}
	if server.Type != "ssh" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host key management only applies to ssh servers"})
		return
	}

	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
		return
	}
	fingerprint := fail2ban.NormalizeFingerprint(req.Fingerprint)
	if !sshFingerprintRe.MatchString(fingerprint) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "fingerprint must be a SHA256 host key fingerprint"})
		return
	}

	// An accept is only valid against a recorded, displayed issue - no blind
	// re-pinning of servers that have no pending host-key change.
	issue := fail2ban.HostKeyIssue(id)
	if issue == nil {
		c.JSON(http.StatusConflict, gin.H{
			"error":      "no pending host key change for this server",
			"messageKey": "servers.errors.no_pending_host_key",
		})
		return
	}
	if issue.Fingerprint != "" && issue.Fingerprint != fingerprint {
		c.JSON(http.StatusConflict, gin.H{
			"error":      "displayed fingerprint is outdated; reload the server list",
			"messageKey": "servers.errors.host_key_mismatch",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	accepted, err := fail2ban.AcceptHostKey(ctx, server, fingerprint)
	if err != nil {
		status := http.StatusInternalServerError
		var mismatch *fail2ban.HostKeyMismatchError
		if errors.As(err, &mismatch) {
			status = http.StatusConflict
			c.JSON(status, gin.H{
				"error":              mismatch.Error(),
				"messageKey":         "servers.errors.host_key_mismatch",
				"hostKeyFingerprint": mismatch.Presented,
			})
			return
		}
		c.JSON(status, buildErrorResponse(err, "servers.actions.accept_hostkey_failed"))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"messageKey":  "servers.actions.accept_hostkey_success",
		"fingerprint": accepted,
	})
}
