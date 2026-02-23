// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/oschwald/maxminddb-golang"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/integrations"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
	"github.com/swissmakers/fail2ban-ui/internal/version"
)

// =========================================================================
//  Types and Variables
// =========================================================================

var wsHub *Hub

// SetWebSocketHub sets the global WebSocket hub instance
func SetWebSocketHub(hub *Hub) {
	wsHub = hub
}

type SummaryResponse struct {
	Jails            []fail2ban.JailInfo `json:"jails"`
	JailLocalWarning bool                `json:"jailLocalWarning,omitempty"`
}
type emailDetail struct {
	Label string
	Value string
}

type githubReleaseResponse struct {
	TagName string `json:"tag_name"`
}

var (
	httpQuotedStatusPattern = regexp.MustCompile(`"[^"]*"\s+(\d{3})\b`)
	httpPlainStatusPattern  = regexp.MustCompile(`\s(\d{3})\s+(?:\d+|-)`)
	suspiciousLogIndicators = []string{
		"select ",
		"union ",
		"/etc/passwd",
		"/xmlrpc.php",
		"/wp-admin",
		"/cgi-bin",
		"cmd=",
		"wget",
		"curl ",
		"nslookup",
		"content-length: 0",
		"${",
	}
	localeCache     = make(map[string]map[string]string)
	localeCacheLock sync.RWMutex
)

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

// =========================================================================
//  Dashboard
// =========================================================================

// Returns a JSON summary of all jails for the selected server.
func SummaryHandler(c *gin.Context) {
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	jailInfos, err := conn.GetJailInfos(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp := SummaryResponse{
		Jails: jailInfos,
	}

	// Checks the jail.local integrity on every summary request to warn the user if not managed by Fail2ban-UI.
	if exists, hasUI, chkErr := conn.CheckJailLocalIntegrity(c.Request.Context()); chkErr == nil {
		if exists && !hasUI {
			resp.JailLocalWarning = true
		} else if !exists {
			// File was removed (user finished migration) – initialize a fresh managed file
			if err := conn.EnsureJailLocalStructure(c.Request.Context()); err != nil {
				config.DebugLog("Warning: failed to initialize jail.local on summary request: %v", err)
			} else {
				config.DebugLog("Initialized fresh jail.local for server %s (file was missing)", conn.Server().Name)
			}
		}
	}

	c.JSON(http.StatusOK, resp)
}

// =========================================================================
//  Ban / Unban Actions
// =========================================================================

// Bans a given IP in a specific jail.
func BanIPHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("BanIPHandler called (handlers.go)")
	jail := c.Param("jail")
	ip := c.Param("ip")

	if err := integrations.ValidateIP(ip); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := conn.BanIP(c.Request.Context(), jail, ip); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fmt.Println(ip + " in jail " + jail + " banned successfully.")
	c.JSON(http.StatusOK, gin.H{
		"message": "IP banned successfully",
	})
}

// Unbans a given IP from a specific jail.
func UnbanIPHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("UnbanIPHandler called (handlers.go)")
	jail := c.Param("jail")
	ip := c.Param("ip")

	if err := integrations.ValidateIP(ip); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := conn.UnbanIP(c.Request.Context(), jail, ip); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fmt.Println(ip + " from jail " + jail + " unbanned successfully.")
	c.JSON(http.StatusOK, gin.H{
		"message": "IP unbanned successfully",
	})
}

// Processes incoming ban callbacks from Fail2Ban action scripts.
func BanNotificationHandler(c *gin.Context) {
	settings := config.GetSettings()
	providedSecret := c.GetHeader("X-Callback-Secret")
	expectedSecret := settings.CallbackSecret

	if expectedSecret == "" {
		log.Printf("⚠️ Callback secret not configured, rejecting request from %s", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Callback secret not configured"})
		return
	}

	if providedSecret == "" {
		log.Printf("⚠️ Missing X-Callback-Secret header in request from %s", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing X-Callback-Secret header"})
		return
	}

	if subtle.ConstantTimeCompare([]byte(providedSecret), []byte(expectedSecret)) != 1 {
		log.Printf("⚠️ Invalid callback secret in request from %s", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid callback secret"})
		return
	}

	var request struct {
		ServerID string `json:"serverId"`
		IP       string `json:"ip" binding:"required"`
		Jail     string `json:"jail" binding:"required"`
		Hostname string `json:"hostname"`
		Failures string `json:"failures"`
		Whois    string `json:"whois"`
		Logs     string `json:"logs"`
	}

	// Logs the raw JSON body of the request
	body, _ := io.ReadAll(c.Request.Body)
	log.Printf("----------------------------------------------------")
	log.Printf("Request Content-Length: %d", c.Request.ContentLength)
	log.Printf("Request Headers: %v", c.Request.Header)
	log.Printf("Request Headers: %v", c.Request.Body)

	log.Printf("----------------------------------------------------")

	config.DebugLog("📩 Incoming Ban Notification: %s\n", string(body))

	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	log.Printf("Request Content-Length: %d", c.Request.ContentLength)
	log.Printf("Request Headers: %v", c.Request.Header)
	log.Printf("Request Headers: %v", c.Request.Body)

	if err := c.ShouldBindJSON(&request); err != nil {
		var verr validator.ValidationErrors
		if errors.As(err, &verr) {
			for _, fe := range verr {
				log.Printf("❌ Validation error: Field '%s' violated rule '%s'", fe.Field(), fe.ActualTag())
			}
		} else {
			log.Printf("❌ JSON parsing error -> Action will not be recorded! Details: %v", err)
		}
		log.Printf("Raw JSON: %s", string(body))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// Logs the parsed request
	log.Printf("✅ Parsed ban request - IP: %s, Jail: %s, Hostname: %s, Failures: %s",
		request.IP, request.Jail, request.Hostname, request.Failures)

	if err := integrations.ValidateIP(request.IP); err != nil {
		log.Printf("⚠️ Invalid IP in ban notification: %s", request.IP)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP: " + err.Error()})
		return
	}

	server, err := resolveServerForNotification(request.ServerID, request.Hostname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := HandleBanNotification(c.Request.Context(), server, request.IP, request.Jail, request.Hostname, request.Failures, request.Whois, request.Logs); err != nil {
		log.Printf("❌ Failed to process ban notification: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process ban notification: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Ban notification processed successfully"})
}

// Processes incoming unban callbacks from Fail2Ban action scripts.
func UnbanNotificationHandler(c *gin.Context) {
	settings := config.GetSettings()
	providedSecret := c.GetHeader("X-Callback-Secret")
	expectedSecret := settings.CallbackSecret

	if expectedSecret == "" {
		log.Printf("⚠️ Callback secret not configured, rejecting request from %s", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Callback secret not configured"})
		return
	}

	if providedSecret == "" {
		log.Printf("⚠️ Missing X-Callback-Secret header in request from %s", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing X-Callback-Secret header"})
		return
	}

	if subtle.ConstantTimeCompare([]byte(providedSecret), []byte(expectedSecret)) != 1 {
		log.Printf("⚠️ Invalid callback secret in request from %s", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid callback secret"})
		return
	}

	var request struct {
		ServerID string `json:"serverId"`
		IP       string `json:"ip" binding:"required"`
		Jail     string `json:"jail" binding:"required"`
		Hostname string `json:"hostname"`
	}

	body, _ := io.ReadAll(c.Request.Body)
	config.DebugLog("📩 Incoming unban notification: %s\n", string(body))

	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	if err := c.ShouldBindJSON(&request); err != nil {
		var verr validator.ValidationErrors
		if errors.As(err, &verr) {
			for _, fe := range verr {
				log.Printf("❌ Validation error: Field '%s' violated rule '%s'", fe.Field(), fe.ActualTag())
			}
		} else {
			log.Printf("❌ JSON parsing error -> Action will not be recorded! Details: %v", err)
		}
		log.Printf("Raw JSON: %s", string(body))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	log.Printf("✅ Parsed unban request - IP: %s, Jail: %s, Hostname: %s",
		request.IP, request.Jail, request.Hostname)

	if err := integrations.ValidateIP(request.IP); err != nil {
		log.Printf("⚠️ Invalid IP in unban notification: %s", request.IP)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP: " + err.Error()})
		return
	}

	server, err := resolveServerForNotification(request.ServerID, request.Hostname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := HandleUnbanNotification(c.Request.Context(), server, request.IP, request.Jail, request.Hostname, "", ""); err != nil {
		log.Printf("❌ Failed to process unban notification: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process unban notification: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Unban notification processed successfully"})
}

// =========================================================================
//  Ban Events Records
// =========================================================================

// Returns paginated, filterable ban/unban events.
func ListBanEventsHandler(c *gin.Context) {
	serverID := c.Query("serverId")
	limit := storage.MaxBanEventsLimit
	if limitStr := c.DefaultQuery("limit", strconv.Itoa(storage.MaxBanEventsLimit)); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			if parsed <= storage.MaxBanEventsLimit {
				limit = parsed
			}
		}
	}
	offset := 0
	if offsetStr := c.DefaultQuery("offset", "0"); offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			if parsed <= storage.MaxBanEventsOffset {
				offset = parsed
			}
		}
	}

	var since time.Time
	if sinceStr := c.Query("since"); sinceStr != "" {
		if parsed, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = parsed
		}
	}
	search := strings.TrimSpace(c.Query("search"))
	country := strings.TrimSpace(c.Query("country"))

	ctx := c.Request.Context()
	events, err := storage.ListBanEventsFiltered(ctx, serverID, limit, offset, since, search, country)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp := gin.H{"events": events, "hasMore": len(events) == limit}
	if offset == 0 {
		total, errCount := storage.CountBanEventsFiltered(ctx, serverID, since, search, country)
		if errCount == nil {
			resp["total"] = total
		}
	}
	c.JSON(http.StatusOK, resp)
}

// Returns aggregated ban event counts per server.
func BanStatisticsHandler(c *gin.Context) {
	var since time.Time
	if sinceStr := c.Query("since"); sinceStr != "" {
		if parsed, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = parsed
		}
	}

	stats, err := storage.CountBanEventsByServer(c.Request.Context(), since)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"counts": stats})
}

// Returns aggregate stats for countries and recurring IPs for ban events.
func BanInsightsHandler(c *gin.Context) {
	var since time.Time
	if sinceStr := c.Query("since"); sinceStr != "" {
		if parsed, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = parsed
		}
	}
	serverID := c.Query("serverId")

	minCount := 3
	if minCountStr := c.DefaultQuery("minCount", "3"); minCountStr != "" {
		if parsed, err := strconv.Atoi(minCountStr); err == nil && parsed > 0 {
			minCount = parsed
		}
	}

	limit := 50
	if limitStr := c.DefaultQuery("limit", "50"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	ctx := c.Request.Context()

	countriesMap, err := storage.CountBanEventsByCountry(ctx, since, serverID)
	if err != nil {
		settings := config.GetSettings()
		errorMsg := err.Error()
		if settings.Debug {
			config.DebugLog("BanInsightsHandler: CountBanEventsByCountry error: %v", err)
			errorMsg = fmt.Sprintf("CountBanEventsByCountry failed: %v", err)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": errorMsg})
		return
	}

	recurring, err := storage.ListRecurringIPStats(ctx, since, minCount, limit, serverID)
	if err != nil {
		settings := config.GetSettings()
		errorMsg := err.Error()
		if settings.Debug {
			config.DebugLog("BanInsightsHandler: ListRecurringIPStats error: %v", err)
			errorMsg = fmt.Sprintf("ListRecurringIPStats failed: %v", err)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": errorMsg})
		return
	}

	totalOverall, err := storage.CountBanEvents(ctx, time.Time{}, serverID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().UTC()

	totalToday, err := storage.CountBanEvents(ctx, now.Add(-24*time.Hour), serverID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	totalWeek, err := storage.CountBanEvents(ctx, now.Add(-7*24*time.Hour), serverID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type countryStat struct {
		Country string `json:"country"`
		Count   int64  `json:"count"`
	}

	countries := make([]countryStat, 0, len(countriesMap))
	for country, count := range countriesMap {
		countries = append(countries, countryStat{
			Country: country,
			Count:   count,
		})
	}

	sort.Slice(countries, func(i, j int) bool {
		if countries[i].Count == countries[j].Count {
			return countries[i].Country < countries[j].Country
		}
		return countries[i].Count > countries[j].Count
	})

	c.JSON(http.StatusOK, gin.H{
		"countries": countries,
		"recurring": recurring,
		"totals": gin.H{
			"overall": totalOverall,
			"today":   totalToday,
			"week":    totalWeek,
		},
	})
}

// Deletes all stored ban event records.
func ClearBanEventsHandler(c *gin.Context) {
	deleted, err := storage.ClearBanEvents(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted})
}

// =========================================================================
//  Fail2ban Servers Management
// =========================================================================

// Returns all configured Fail2ban servers.
func ListServersHandler(c *gin.Context) {
	servers := config.ListServers()
	c.JSON(http.StatusOK, gin.H{"servers": servers})
}

// Creates or updates a Fail2ban server configuration.
func UpsertServerHandler(c *gin.Context) {
	var req config.Fail2banServer
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
		return
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "agent servers require agentUrl and agentSecret"})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported server type"})
		return
	}

	// Check if server exists and was previously disabled
	oldServer, wasEnabled := config.GetServerByID(req.ID)
	wasDisabled := !wasEnabled || !oldServer.Enabled

	server, err := config.UpsertServer(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if server was just enabled (transition from disabled to enabled)
	justEnabled := wasDisabled && server.Enabled

	if err := fail2ban.GetManager().ReloadFromSettings(config.GetSettings()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if justEnabled && (server.Type == "ssh" || server.Type == "agent") {
		if err := fail2ban.GetManager().UpdateActionFileForServer(c.Request.Context(), server.ID); err != nil {
			config.DebugLog("Warning: failed to update action file for server %s: %v", server.Name, err)
		}
	}

	// Ensures the jail.local structure is properly initialized for newly enabled/added servers
	var jailLocalWarning bool
	if justEnabled || !wasEnabled {
		conn, err := fail2ban.GetManager().Connector(server.ID)
		if err == nil {
			// EnsureJailLocalStructure respects user-owned files:
			//   - file missing --> creates it
			//   - file is ours --> updates it
			//   - file is user's own --> leave it alone
			if err := conn.EnsureJailLocalStructure(c.Request.Context()); err != nil {
				config.DebugLog("Warning: failed to ensure jail.local structure for server %s: %v", server.Name, err)
			} else {
				config.DebugLog("Successfully ensured jail.local structure for server %s", server.Name)
			}

			// Checks the integrity AFTER ensuring structure so fresh servers don't trigger a false-positive warning.
			if exists, hasUI, chkErr := conn.CheckJailLocalIntegrity(c.Request.Context()); chkErr == nil && exists && !hasUI {
				jailLocalWarning = true
				log.Printf("⚠️ Server %s: jail.local is not managed by Fail2ban-UI. Please migrate your jail.local manually (see documentation).", server.Name)
			}

			// Tries to restart Fail2ban and performs a basic health check after the server was enabled
			if justEnabled {
				if err := conn.Restart(c.Request.Context()); err != nil {
					msg := fmt.Sprintf("failed to restart fail2ban for server %s: %v", server.Name, err)
					config.DebugLog("Warning: %s", msg)
					c.JSON(http.StatusInternalServerError, gin.H{
						"error":  msg,
						"server": server,
					})
					return
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

	resp := gin.H{"server": server}
	if jailLocalWarning {
		resp["jailLocalWarning"] = true
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
	if err := fail2ban.GetManager().ReloadFromSettings(config.GetSettings()); err != nil {
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
	if err := fail2ban.GetManager().ReloadFromSettings(config.GetSettings()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"server": server})
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

	var (
		conn fail2ban.Connector
		err  error
	)

	switch server.Type {
	case "local":
		conn = fail2ban.NewLocalConnector(server)
	case "ssh":
		conn, err = fail2ban.NewSSHConnector(server)
	case "agent":
		conn, err = fail2ban.NewAgentConnector(server)
	default:
		err = fmt.Errorf("unsupported server type %s", server.Type)
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "messageKey": "servers.actions.test_failure"})
		return
	}

	if _, err := conn.GetJailInfos(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "messageKey": "servers.actions.test_failure"})
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

// =========================================================================
//  Notification Processing (Internal)
// =========================================================================

// Records a ban event, broadcasts it via WebSocket,
// evaluates advanced actions, and sends an email alert if enabled.
func HandleBanNotification(ctx context.Context, server config.Fail2banServer, ip, jail, hostname, failures, whois, logs string) error {
	// Loads the settings to get alert countries and GeoIP provider from the database
	settings := config.GetSettings()
	var whoisData string
	var err error
	if whois == "" {
		log.Printf("Performing whois lookup for IP %s", ip)
		whoisData, err = lookupWhois(ip)
		if err != nil {
			log.Printf("⚠️ Whois lookup failed for IP %s: %v", ip, err)
			whoisData = ""
		}
	} else {
		log.Printf("Using provided whois data for IP %s", ip)
		whoisData = whois
	}

	// Filters the logs for the email alert to show relevant lines
	filteredLogs := filterRelevantLogs(logs, ip, settings.MaxLogLines)

	// Looks up the country for the given IP using the configured GeoIP provider
	country, err := lookupCountry(ip, settings.GeoIPProvider, settings.GeoIPDatabasePath)
	if err != nil {
		log.Printf("⚠️ GeoIP lookup failed for IP %s: %v", ip, err)
		if whoisData != "" {
			country = extractCountryFromWhois(whoisData)
			if country != "" {
				log.Printf("Extracted country %s from whois data for IP %s", country, ip)
			}
		}
		if country == "" {
			country = ""
		}
	}

	event := storage.BanEventRecord{
		ServerID:   server.ID,
		ServerName: server.Name,
		Jail:       jail,
		IP:         ip,
		Country:    country,
		Hostname:   hostname,
		Failures:   failures,
		Whois:      whoisData,
		Logs:       filteredLogs,
		EventType:  "ban",
		OccurredAt: time.Now().UTC(),
	}
	if err := storage.RecordBanEvent(ctx, event); err != nil {
		log.Printf("⚠️ Failed to record ban event: %v", err)
	}

	// Broadcasts the ban event to WebSocket clients
	if wsHub != nil {
		wsHub.BroadcastBanEvent(event)
	}

	evaluateAdvancedActions(ctx, settings, server, ip)

	displayCountry := country
	if displayCountry == "" {
		displayCountry = "UNKNOWN"
	}

	if !shouldAlertForCountry(country, settings.AlertCountries) {
		log.Printf("❌ IP %s belongs to %s, which is NOT in alert countries (%v). No alert sent.", ip, displayCountry, settings.AlertCountries)
		return nil
	}

	if !settings.EmailAlertsForBans {
		log.Printf("❌ Alerts for bans are disabled. No alert sent for IP %s", ip)
		return nil
	}

	if err := dispatchAlert("ban", ip, jail, hostname, failures, whoisData, filteredLogs, country, settings); err != nil {
		log.Printf("❌ Failed to send ban alert: %v", err)
	}
	return nil
}

// Records an unban event, broadcasts it via WebSocket, and sends an email alert if enabled.
func HandleUnbanNotification(ctx context.Context, server config.Fail2banServer, ip, jail, hostname, whois, country string) error {
	// Loads the settings to get alert countries and GeoIP provider from the database
	settings := config.GetSettings()
	var whoisData string
	var err error
	if whois == "" {
		log.Printf("Performing whois lookup for IP %s", ip)
		whoisData, err = lookupWhois(ip)
		if err != nil {
			log.Printf("⚠️ Whois lookup failed for IP %s: %v", ip, err)
			whoisData = ""
		}
	} else {
		log.Printf("Using provided whois data for IP %s", ip)
		whoisData = whois
	}
	if country == "" {
		country, err = lookupCountry(ip, settings.GeoIPProvider, settings.GeoIPDatabasePath)
		if err != nil {
			log.Printf("⚠️ GeoIP lookup failed for IP %s: %v", ip, err)
			if whoisData != "" {
				country = extractCountryFromWhois(whoisData)
				if country != "" {
					log.Printf("Extracted country %s from whois data for IP %s", country, ip)
				}
			}
			if country == "" {
				country = ""
			}
		}
	}

	event := storage.BanEventRecord{
		ServerID:   server.ID,
		ServerName: server.Name,
		Jail:       jail,
		IP:         ip,
		Country:    country,
		Hostname:   hostname,
		Failures:   "",
		Whois:      whoisData,
		Logs:       "",
		EventType:  "unban",
		OccurredAt: time.Now().UTC(),
	}
	if err := storage.RecordBanEvent(ctx, event); err != nil {
		log.Printf("⚠️ Failed to record unban event: %v", err)
	}

	// Broadcasts the unban event to WebSocket clients
	if wsHub != nil {
		wsHub.BroadcastUnbanEvent(event)
	}

	if !settings.EmailAlertsForUnbans {
		log.Printf("🔕 Alerts for unbans are disabled. No alert sent for IP %s", ip)
		return nil
	}

	displayCountry := country
	if displayCountry == "" {
		displayCountry = "UNKNOWN"
	}

	if !shouldAlertForCountry(country, settings.AlertCountries) {
		log.Printf("🔕 IP %s belongs to %s, which is NOT in alert countries (%v). No alert sent.", ip, displayCountry, settings.AlertCountries)
		return nil
	}

	if err := dispatchAlert("unban", ip, jail, hostname, "", whoisData, "", country, settings); err != nil {
		log.Printf("❌ Failed to send unban alert: %v", err)
	}
	return nil
}

// =========================================================================
//  Alert Dispatch
// =========================================================================

// Routes an alert to the configured provider (email, webhook, or elasticsearch).
func dispatchAlert(alertType, ip, jail, hostname, failures, whois, logs, country string, settings config.AppSettings) error {
	switch settings.AlertProvider {
	case "webhook":
		return sendWebhookAlert(alertType, ip, jail, hostname, failures, whois, logs, country, settings)
	case "elasticsearch":
		return sendElasticsearchAlert(alertType, ip, jail, hostname, failures, whois, logs, country, settings)
	default:
		if alertType == "ban" {
			return sendBanAlert(ip, jail, hostname, failures, whois, logs, country, settings)
		}
		return sendUnbanAlert(ip, jail, hostname, whois, country, settings)
	}
}

// Sends a JSON payload to the configured webhook URL.
func sendWebhookAlert(alertType, ip, jail, hostname, failures, whois, logs, country string, settings config.AppSettings) error {
	cfg := settings.Webhook
	if cfg.URL == "" {
		return fmt.Errorf("webhook URL is not configured")
	}

	payload := map[string]interface{}{
		"event":     alertType,
		"ip":        ip,
		"jail":      jail,
		"hostname":  hostname,
		"country":   country,
		"failures":  failures,
		"whois":     whois,
		"logs":      logs,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	method := strings.ToUpper(cfg.Method)
	if method == "" {
		method = "POST"
	}

	req, err := http.NewRequest(method, cfg.URL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	if cfg.SkipTLSVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Webhook alert sent: %s %s -> %d", method, cfg.URL, resp.StatusCode)
	return nil
}

// Sends a document to the configured Elasticsearch index.
func sendElasticsearchAlert(alertType, ip, jail, hostname, failures, whois, logs, country string, settings config.AppSettings) error {
	cfg := settings.Elasticsearch
	if cfg.URL == "" {
		return fmt.Errorf("elasticsearch URL is not configured")
	}

	index := cfg.Index
	if index == "" {
		index = "fail2ban-events"
	}
	dateSuffix := time.Now().UTC().Format("2006.01.02")
	indexName := index + "-" + dateSuffix

	doc := map[string]interface{}{
		"@timestamp":                  time.Now().UTC().Format(time.RFC3339),
		"event.kind":                  "alert",
		"event.type":                  alertType,
		"source.ip":                   ip,
		"source.geo.country_iso_code": country,
		"observer.hostname":           hostname,
		"fail2ban.jail":               jail,
		"fail2ban.failures":           failures,
		"fail2ban.whois":              whois,
		"fail2ban.logs":               logs,
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal elasticsearch document: %w", err)
	}

	esURL := strings.TrimSuffix(cfg.URL, "/")
	reqURL := fmt.Sprintf("%s/%s/_doc", esURL, indexName)

	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create elasticsearch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+cfg.APIKey)
	} else if cfg.Username != "" {
		req.SetBasicAuth(cfg.Username, cfg.Password)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	if cfg.SkipTLSVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("elasticsearch request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("elasticsearch returned status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Elasticsearch alert indexed: %s -> %d", reqURL, resp.StatusCode)
	return nil
}

// Sends a test payload to the configured webhook URL.
func TestWebhookHandler(c *gin.Context) {
	settings := config.GetSettings()
	if settings.Webhook.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "webhook URL is not configured"})
		return
	}

	err := sendWebhookAlert("test", "203.0.113.1", "test-jail", "fail2ban-ui", "0", "", "This is a test webhook from Fail2ban-UI.", "XX", settings)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Test webhook sent successfully"})
}

// Sends a test document to the configured Elasticsearch instance.
func TestElasticsearchHandler(c *gin.Context) {
	settings := config.GetSettings()
	if settings.Elasticsearch.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "elasticsearch URL is not configured"})
		return
	}

	err := sendElasticsearchAlert("test", "203.0.113.1", "test-jail", "fail2ban-ui", "0", "", "This is a test document from Fail2ban-UI.", "XX", settings)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Test document indexed successfully"})
}

// =========================================================================
//  GeoIP and Helpers
// =========================================================================

// Resolves the ISO country code for an IP using the configured GeoIP provider.
func lookupCountry(ip, provider, dbPath string) (string, error) {
	switch provider {
	case "builtin":
		return lookupCountryBuiltin(ip)
	case "maxmind", "":
		if dbPath == "" {
			dbPath = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
		}
		return lookupCountryMaxMind(ip, dbPath)
	default:
		// Unknown GeoIP provider, falls back to MaxMind
		log.Printf("Unknown GeoIP provider '%s', falling back to MaxMind", provider)
		if dbPath == "" {
			dbPath = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
		}
		return lookupCountryMaxMind(ip, dbPath)
	}
}

// Looks up the country ISO code using MaxMind GeoLite2 database.
func lookupCountryMaxMind(ip, dbPath string) (string, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return "", fmt.Errorf("failed to open GeoIP database at %s: %w", dbPath, err)
	}
	defer db.Close()

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}

	if err := db.Lookup(parsedIP, &record); err != nil {
		return "", fmt.Errorf("GeoIP lookup error: %w", err)
	}

	return record.Country.ISOCode, nil
}

// Looks up the country ISO code using ip-api.com free API.
func lookupCountryBuiltin(ip string) (string, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	// Uses ip-api.com free API (no account needed, rate limited to 45 requests/minute)
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=countryCode", ip)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query ip-api.com: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ip-api.com returned status %d", resp.StatusCode)
	}

	var result struct {
		CountryCode string `json:"countryCode"`
		Status      string `json:"status"`
		Message     string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if result.Status == "fail" {
		return "", fmt.Errorf("ip-api.com error: %s", result.Message)
	}

	return result.CountryCode, nil
}

// Filters relevant logs for the email alert to show relevant lines.
func filterRelevantLogs(logs, ip string, maxLines int) string {
	if logs == "" {
		return ""
	}
	if maxLines <= 0 {
		maxLines = 50
	}
	lines := strings.Split(logs, "\n")
	if len(lines) <= maxLines {
		return logs
	}
	// Priority patterns to identify relevant log lines
	priorityPatterns := []string{
		"denied", "deny", "forbidden", "unauthorized", "failed", "failure",
		"error", "403", "404", "401", "500", "502", "503",
		"invalid", "rejected", "blocked", "ban",
	}
	type scoredLine struct {
		line  string
		score int
		index int
	}
	scored := make([]scoredLine, len(lines))
	for i, line := range lines {
		lineLower := strings.ToLower(line)
		score := 0

		if strings.Contains(line, ip) {
			score += 10
		}
		for _, pattern := range priorityPatterns {
			if strings.Contains(lineLower, pattern) {
				score += 5
			}
		}
		score += (len(lines) - i) / 10
		scored[i] = scoredLine{
			line:  line,
			score: score,
			index: i,
		}
	}
	for i := 0; i < len(scored)-1; i++ {
		for j := i + 1; j < len(scored); j++ {
			if scored[i].score < scored[j].score {
				scored[i], scored[j] = scored[j], scored[i]
			}
		}
	}
	selected := scored[:maxLines]
	for i := 0; i < len(selected)-1; i++ {
		for j := i + 1; j < len(selected); j++ {
			if selected[i].index > selected[j].index {
				selected[i], selected[j] = selected[j], selected[i]
			}
		}
	}
	result := make([]string, len(selected))
	for i, s := range selected {
		result[i] = s.line
	}
	filtered := []string{}
	lastLine := ""
	for _, line := range result {
		if line != lastLine {
			filtered = append(filtered, line)
			lastLine = line
		}
	}
	return strings.Join(filtered, "\n")
}

// Checks if an IP's country is in the allowed alert list.
func shouldAlertForCountry(country string, alertCountries []string) bool {
	if len(alertCountries) == 0 || strings.Contains(strings.Join(alertCountries, ","), "ALL") {
		return true
	}
	for _, c := range alertCountries {
		if strings.EqualFold(country, c) {
			return true
		}
	}
	return false
}

// =========================================================================
//  Page Rendering
// =========================================================================

// Renders the main SPA page with template variables.
func renderIndexPage(c *gin.Context) {
	disableExternalIP := os.Getenv("DISABLE_EXTERNAL_IP_LOOKUP") == "true" || os.Getenv("DISABLE_EXTERNAL_IP_LOOKUP") == "1"

	// Checks if OIDC is enabled and skip login page setting
	oidcEnabled := auth.IsEnabled()
	skipLoginPage := false
	if oidcEnabled {
		oidcConfig := auth.GetConfig()
		if oidcConfig != nil {
			skipLoginPage = oidcConfig.SkipLoginPage
		}
	}

	// Checks is a user wants to disable the github versioning check
	updateCheckEnabled := os.Getenv("UPDATE_CHECK") != "false"

	c.HTML(http.StatusOK, "index.html", gin.H{
		"timestamp":          time.Now().Format(time.RFC1123),
		"version":            time.Now().Unix(),
		"appVersion":         version.Version,
		"updateCheckEnabled": updateCheckEnabled,
		"disableExternalIP":  disableExternalIP,
		"oidcEnabled":        oidcEnabled,
		"skipLoginPage":      skipLoginPage,
	})
}

// =========================================================================
//  Version
// =========================================================================

// Returns the app version and checks GitHub for updates.
func GetVersionHandler(c *gin.Context) {
	updateCheckEnabled := os.Getenv("UPDATE_CHECK") != "false"
	out := gin.H{
		"version":              version.Version,
		"update_check_enabled": updateCheckEnabled,
	}
	if !updateCheckEnabled {
		c.JSON(http.StatusOK, out)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/swissmakers/fail2ban-ui/releases/latest", nil)
	if err != nil {
		c.JSON(http.StatusOK, out)
		return
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.JSON(http.StatusOK, out)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusOK, out)
		return
	}
	var gh githubReleaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&gh); err != nil {
		c.JSON(http.StatusOK, out)
		return
	}
	latest := strings.TrimPrefix(strings.TrimSpace(gh.TagName), "v")
	out["latest_version"] = latest
	out["update_available"] = versionLess(version.Version, latest)
	c.JSON(http.StatusOK, out)
}

// Checks if a version is less than another version.
func versionLess(a, b string) bool {
	parse := func(s string) []int {
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		parts := strings.Split(s, ".")
		out := make([]int, 0, len(parts))
		for _, p := range parts {
			n, _ := strconv.Atoi(p)
			out = append(out, n)
		}
		return out
	}
	pa, pb := parse(a), parse(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		va, vb := 0, 0
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va < vb {
			return true
		}
		if va > vb {
			return false
		}
	}
	return false
}

// =========================================================================
//  Jail Config
// =========================================================================

// Returns the filter and jail config for a given jail.
func GetJailFilterConfigHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("GetJailFilterConfigHandler called (handlers.go)")
	jail := c.Param("jail")
	config.DebugLog("Jail name: %s", jail)

	conn, err := resolveConnector(c)
	if err != nil {
		config.DebugLog("Failed to resolve connector: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	config.DebugLog("Connector resolved: %s", conn.Server().Name)

	var filterCfg string
	var filterFilePath string
	var jailCfg string
	var jailFilePath string
	var filterErr error

	// Always load jail config first to determine which filter to load
	config.DebugLog("Loading jail config for jail: %s", jail)
	var jailErr error
	jailCfg, jailFilePath, jailErr = conn.GetJailConfig(c.Request.Context(), jail)
	if jailErr != nil {
		config.DebugLog("Failed to load jail config: %v", jailErr)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load jail config: " + jailErr.Error()})
		return
	}
	config.DebugLog("Jail config loaded, length: %d, file: %s", len(jailCfg), jailFilePath)

	// Extracts the filter name from the jail config, or uses the jail name as fallback
	filterName := fail2ban.ExtractFilterFromJailConfig(jailCfg)
	if filterName == "" {
		// No filter directive found, uses the jail name as filter name
		filterName = jail
		config.DebugLog("No filter directive found in jail config, using jail name as filter name: %s", filterName)
	} else {
		config.DebugLog("Found filter directive in jail config: %s", filterName)
	}

	// Loads the filter config using the filter name determined from the jail config
	config.DebugLog("Loading filter config for filter: %s", filterName)
	filterCfg, filterFilePath, filterErr = conn.GetFilterConfig(c.Request.Context(), filterName)
	if filterErr != nil {
		config.DebugLog("Failed to load filter config for %s: %v", filterName, filterErr)
		config.DebugLog("Continuing without filter config (filter may not exist yet)")
		filterCfg = ""
		filterFilePath = ""
	} else {
		config.DebugLog("Filter config loaded, length: %d, file: %s", len(filterCfg), filterFilePath)
	}

	c.JSON(http.StatusOK, gin.H{
		"jail":           jail,
		"filter":         filterCfg,
		"filterFilePath": filterFilePath,
		"jailConfig":     jailCfg,
		"jailFilePath":   jailFilePath,
	})
}

// Saves updated filter/jail config and reloads Fail2ban.
func SetJailFilterConfigHandler(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			config.DebugLog("PANIC in SetJailFilterConfigHandler: %v", r)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Internal server error: %v", r)})
		}
	}()
	config.DebugLog("----------------------------")
	config.DebugLog("SetJailFilterConfigHandler called (handlers.go)")
	jail := c.Param("jail")
	config.DebugLog("Jail name: %s", jail)

	conn, err := resolveConnector(c)
	if err != nil {
		config.DebugLog("Failed to resolve connector: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	config.DebugLog("Connector resolved: %s (type: %s)", conn.Server().Name, conn.Server().Type)

	var req struct {
		Filter string `json:"filter"`
		Jail   string `json:"jail"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		config.DebugLog("Failed to parse JSON body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body: " + err.Error()})
		return
	}
	config.DebugLog("Request parsed - Filter length: %d, Jail length: %d", len(req.Filter), len(req.Jail))
	if len(req.Filter) > 0 {
		config.DebugLog("Filter preview (first 100 chars): %s", req.Filter[:min(100, len(req.Filter))])
	}
	if len(req.Jail) > 0 {
		config.DebugLog("Jail preview (first 100 chars): %s", req.Jail[:min(100, len(req.Jail))])
	}

	if req.Filter != "" {
		originalJailCfg, _, err := conn.GetJailConfig(c.Request.Context(), jail)
		if err != nil {
			config.DebugLog("Failed to load original jail config to determine filter name: %v", err)
			originalJailCfg = req.Jail
		}

		// Extracts the original filter name (the one that was loaded when the modal opened)
		originalFilterName := fail2ban.ExtractFilterFromJailConfig(originalJailCfg)
		if originalFilterName == "" {
			// No filter directive found in original config, uses the jail name as filter name
			originalFilterName = jail
			config.DebugLog("No filter directive found in original jail config, using jail name as filter name: %s", originalFilterName)
		} else {
			config.DebugLog("Found original filter directive in jail config: %s", originalFilterName)
		}

		// Extracts the new filter name from the updated jail config
		newFilterName := fail2ban.ExtractFilterFromJailConfig(req.Jail)
		if newFilterName == "" {
			newFilterName = jail
		}

		// If the filter name changed, saves to the original filter name
		// This prevents overwriting a different filter with the old filter's content
		if originalFilterName != newFilterName {
			config.DebugLog("Filter name changed from %s to %s, saving filter to original name: %s", originalFilterName, newFilterName, originalFilterName)
		} else {
			config.DebugLog("Filter name unchanged: %s", originalFilterName)
		}

		config.DebugLog("Saving filter config for filter: %s", originalFilterName)
		if err := conn.SetFilterConfig(c.Request.Context(), originalFilterName, req.Filter); err != nil {
			config.DebugLog("Failed to save filter config: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save filter config: " + err.Error()})
			return
		}
		config.DebugLog("Filter config saved successfully to filter: %s", originalFilterName)
	} else {
		config.DebugLog("No filter config provided, skipping")
	}

	if req.Jail != "" {
		config.DebugLog("Saving jail config for jail: %s", jail)
		if err := conn.SetJailConfig(c.Request.Context(), jail, req.Jail); err != nil {
			config.DebugLog("Failed to save jail config: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save jail config: " + err.Error()})
			return
		}
		config.DebugLog("Jail config saved successfully")
	} else {
		config.DebugLog("No jail config provided, skipping")
	}

	// Reloads Fail2ban
	config.DebugLog("Reloading fail2ban")
	if err := conn.Reload(c.Request.Context()); err != nil {
		log.Printf("⚠️ Config saved but fail2ban reload failed: %v", err)
		// If reload fails, we automatically disable the jail so Fail2ban won't crash on next restart (invalid filter/jail config)
		disableUpdate := map[string]bool{jail: false}
		if disableErr := conn.UpdateJailEnabledStates(c.Request.Context(), disableUpdate); disableErr != nil {
			log.Printf("⚠️ Failed to auto-disable jail %s after reload failure: %v", jail, disableErr)
			c.JSON(http.StatusOK, gin.H{
				"message": "Config saved successfully, but fail2ban reload failed",
				"warning": err.Error(),
			})
			return
		}
		if reloadErr2 := conn.Reload(c.Request.Context()); reloadErr2 != nil {
			log.Printf("⚠️ Failed to reload fail2ban after auto-disabling jail %s: %v", jail, reloadErr2)
		}
		c.JSON(http.StatusOK, gin.H{
			"message":          "Config saved successfully, but fail2ban reload failed",
			"warning":          err.Error(),
			"jailAutoDisabled": true,
			"jailName":         jail,
		})
		return
	}
	config.DebugLog("Fail2ban reloaded successfully")
	c.JSON(http.StatusOK, gin.H{"message": "Filter and jail config updated and fail2ban reloaded"})
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Validates that a jail's log path resolves to real files.
func TestLogpathHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("TestLogpathHandler called (handlers.go)")
	jail := c.Param("jail")
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var originalLogpath string

	// Checks if a logpath is provided in the request body
	var reqBody struct {
		Logpath string `json:"logpath"`
	}
	if err := c.ShouldBindJSON(&reqBody); err == nil && reqBody.Logpath != "" {
		// Uses the logpath from the request body (from textarea)
		originalLogpath = strings.TrimSpace(reqBody.Logpath)
		config.DebugLog("Using logpath from request body: %s", originalLogpath)
	} else {
		// Falls back to reading from the saved jail config
		jailCfg, _, err := conn.GetJailConfig(c.Request.Context(), jail)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load jail config: " + err.Error()})
			return
		}

		// Extracts the logpath from the jail config
		originalLogpath = fail2ban.ExtractLogpathFromJailConfig(jailCfg)
		if originalLogpath == "" {
			c.JSON(http.StatusOK, gin.H{
				"original_logpath": "",
				"resolved_logpath": "",
				"files":            []string{},
				"message":          "No logpath configured for this jail",
			})
			return
		}
		config.DebugLog("Using logpath from saved jail config: %s", originalLogpath)
	}

	if originalLogpath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No logpath provided"})
		return
	}

	// Gets the server type to determine the test strategy
	server := conn.Server()
	isLocalServer := server.Type == "local"

	// Splits the logpath by newlines and spaces (Fail2ban supports multiple logpaths separated by spaces or newlines)
	// First splits by newlines, then splits each line by spaces
	var logpaths []string
	for _, line := range strings.Split(originalLogpath, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		paths := strings.Fields(line)
		logpaths = append(logpaths, paths...)
	}

	var allResults []map[string]interface{}

	for _, logpathLine := range logpaths {
		logpathLine = strings.TrimSpace(logpathLine)
		if logpathLine == "" {
			continue
		}
		if isLocalServer {
			resolvedPath, err := fail2ban.ResolveLogpathVariables(logpathLine)
			if err != nil {
				allResults = append(allResults, map[string]interface{}{
					"logpath":       logpathLine,
					"resolved_path": "",
					"found":         false,
					"files":         []string{},
					"error":         err.Error(),
				})
				continue
			}
			if resolvedPath == "" {
				resolvedPath = logpathLine
			}

			files, localErr := fail2ban.TestLogpath(resolvedPath)

			allResults = append(allResults, map[string]interface{}{
				"logpath":       logpathLine,
				"resolved_path": resolvedPath,
				"found":         len(files) > 0,
				"files":         files,
				"error": func() string {
					if localErr != nil {
						return localErr.Error()
					}
					return ""
				}(),
			})
		} else {
			_, resolvedPath, filesOnRemote, err := conn.TestLogpathWithResolution(c.Request.Context(), logpathLine)
			if err != nil {
				allResults = append(allResults, map[string]interface{}{
					"logpath":       logpathLine,
					"resolved_path": resolvedPath,
					"found":         false,
					"files":         []string{},
					"error":         err.Error(),
				})
				continue
			}
			allResults = append(allResults, map[string]interface{}{
				"logpath":       logpathLine,
				"resolved_path": resolvedPath,
				"found":         len(filesOnRemote) > 0,
				"files":         filesOnRemote,
				"error":         "",
			})
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"original_logpath": originalLogpath,
		"is_local_server":  isLocalServer,
		"results":          allResults,
	})
}

// =========================================================================
//  Jail Management
// =========================================================================

// Returns all jails (enabled and disabled) for the manage-jails modal.
func ManageJailsHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("ManageJailsHandler called (handlers.go)")
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	jails, err := conn.GetAllJails(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load jails: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"jails": jails})
}

// =========================================================================
//  Advanced Actions
// =========================================================================

// Returns the permanent block log entries.
func ListPermanentBlocksHandler(c *gin.Context) {
	limit := 100
	if limitStr := c.DefaultQuery("limit", "100"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	records, err := storage.ListPermanentBlocks(c.Request.Context(), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"blocks": records})
}

// Deletes all permanent block records.
func ClearPermanentBlocksHandler(c *gin.Context) {
	deleted, err := storage.ClearPermanentBlocks(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted})
}

// Allows manual block/unblock against the configured integration.
func AdvancedActionsTestHandler(c *gin.Context) {
	var req struct {
		Action string `json:"action"`
		IP     string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}
	if err := integrations.ValidateIP(req.IP); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	action := strings.ToLower(req.Action)
	if action == "" {
		action = "block"
	}
	if action != "block" && action != "unblock" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be block or unblock"})
		return
	}

	settings := config.GetSettings()

	if settings.AdvancedActions.Integration == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no integration configured. Please configure an integration (MikroTik, pfSense, or OPNsense) in Advanced Actions settings first"})
		return
	}

	integration, ok := integrations.Get(settings.AdvancedActions.Integration)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("integration %s not found or not registered", settings.AdvancedActions.Integration)})
		return
	}

	if err := integration.Validate(settings.AdvancedActions); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("integration configuration is invalid: %v", err)})
		return
	}

	server := config.Fail2banServer{}

	// Checks if the IP is already blocked before attempting the action (for block action only)
	skipLoggingIfAlreadyBlocked := false
	if action == "block" && settings.AdvancedActions.Integration != "" {
		active, checkErr := storage.IsPermanentBlockActive(c.Request.Context(), req.IP, settings.AdvancedActions.Integration)
		if checkErr == nil && active {
			skipLoggingIfAlreadyBlocked = true
		}
	}

	err := runAdvancedIntegrationAction(
		c.Request.Context(),
		action,
		req.IP,
		settings,
		server,
		map[string]any{"manual": true},
		skipLoggingIfAlreadyBlocked,
	)
	if err != nil {
		if skipLoggingIfAlreadyBlocked {
			errMsg := strings.ToLower(err.Error())
			if strings.Contains(errMsg, "already have such entry") ||
				strings.Contains(errMsg, "already exists") ||
				strings.Contains(errMsg, "duplicate") {
				// IP is already blocked, returns info message with original error
				c.JSON(http.StatusOK, gin.H{"message": err.Error(), "info": true})
				return
			}
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Action %s completed for %s", action, req.IP)})
}

// Returns a sorted slice of jail names from the map.
func getJailNames(jails map[string]bool) []string {
	names := make([]string, 0, len(jails))
	for name := range jails {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Extracts problematic jail names from Fail2ban reload output.
func parseJailErrorsFromReloadOutput(output string) []string {
	var problematicJails []string
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.Contains(line, "Errors in jail") && strings.Contains(line, "Skipping") {
			re := regexp.MustCompile(`Errors in jail '([^']+)'`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				problematicJails = append(problematicJails, matches[1])
			}
		}
		// Also checks for filter errors that might indicate jail problems
		_ = strings.Contains(line, "Unable to read the filter")
	}

	seen := make(map[string]bool)
	uniqueJails := []string{}
	for _, jail := range problematicJails {
		if !seen[jail] {
			seen[jail] = true
			uniqueJails = append(uniqueJails, jail)
		}
	}

	return uniqueJails
}

// Enables/disables jails and reloads Fail2ban.
func UpdateJailManagementHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("UpdateJailManagementHandler called (handlers.go)")
	conn, err := resolveConnector(c)
	if err != nil {
		config.DebugLog("Error resolving connector: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var updates map[string]bool
	if err := c.ShouldBindJSON(&updates); err != nil {
		config.DebugLog("Error parsing JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON: " + err.Error()})
		return
	}
	config.DebugLog("Received jail updates: %+v", updates)
	if len(updates) == 0 {
		config.DebugLog("Warning: No jail updates provided")
		c.JSON(http.StatusBadRequest, gin.H{"error": "No jail updates provided"})
		return
	}

	// Tracks which jails were enabled (for error recovery)
	enabledJails := make(map[string]bool)
	for jailName, enabled := range updates {
		if enabled {
			enabledJails[jailName] = true
		}
	}

	if err := conn.UpdateJailEnabledStates(c.Request.Context(), updates); err != nil {
		config.DebugLog("Error updating jail enabled states: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update jail settings: " + err.Error()})
		return
	}
	config.DebugLog("Successfully updated jail enabled states")

	// Reloads fail2ban to apply the changes
	reloadErr := conn.Reload(c.Request.Context())

	// Checks for errors in reload output
	var problematicJails []string
	var detailedErrorOutput string
	if reloadErr != nil {
		errMsg := reloadErr.Error()
		config.DebugLog("Error: failed to reload fail2ban after updating jail settings: %v", reloadErr)

		// Extracts the output from the error message
		if strings.Contains(errMsg, "(output:") {
			outputStart := strings.Index(errMsg, "(output:") + 8
			outputEnd := strings.LastIndex(errMsg, ")")
			if outputEnd > outputStart {
				detailedErrorOutput = errMsg[outputStart:outputEnd]
				problematicJails = parseJailErrorsFromReloadOutput(detailedErrorOutput)
			}
		} else if strings.Contains(errMsg, "output:") {
			outputStart := strings.Index(errMsg, "output:") + 7
			if outputStart < len(errMsg) {
				detailedErrorOutput = strings.TrimSpace(errMsg[outputStart:])
				problematicJails = parseJailErrorsFromReloadOutput(detailedErrorOutput)
			}
		}

		// If problematic jails are found, disables them // TODO: @matthias we need to further enhance this
		if len(problematicJails) > 0 {
			config.DebugLog("Found %d problematic jail(s) in reload output: %v", len(problematicJails), problematicJails)

			disableUpdate := make(map[string]bool)
			for _, jailName := range problematicJails {
				disableUpdate[jailName] = false
			}

			for jailName := range enabledJails {
				if contains(problematicJails, jailName) {
					disableUpdate[jailName] = false
				}
			}

			if len(disableUpdate) > 0 {
				if disableErr := conn.UpdateJailEnabledStates(c.Request.Context(), disableUpdate); disableErr != nil {
					config.DebugLog("Error disabling problematic jails: %v", disableErr)
				} else {
					// Reload again after disabling
					if reloadErr2 := conn.Reload(c.Request.Context()); reloadErr2 != nil {
						config.DebugLog("Error: failed to reload fail2ban after disabling problematic jails: %v", reloadErr2)
					}
				}
			}

			for _, jailName := range problematicJails {
				enabledJails[jailName] = true
			}
		}

		if detailedErrorOutput != "" {
			errMsg = strings.TrimSpace(detailedErrorOutput)
		}

		if len(enabledJails) > 0 {
			config.DebugLog("Reload failed after enabling %d jail(s), auto-disabling all enabled jails: %v", len(enabledJails), enabledJails)

			disableUpdate := make(map[string]bool)
			for jailName := range enabledJails {
				disableUpdate[jailName] = false
			}

			if disableErr := conn.UpdateJailEnabledStates(c.Request.Context(), disableUpdate); disableErr != nil {
				config.DebugLog("Error disabling jails after reload failure: %v", disableErr)
				c.JSON(http.StatusOK, gin.H{
					"error":        fmt.Sprintf("Failed to reload fail2ban: %s. Additionally, failed to auto-disable enabled jails: %v", errMsg, disableErr),
					"autoDisabled": false,
					"enabledJails": getJailNames(enabledJails),
				})
				return
			}

			// Reloads again after disabling
			if reloadErr = conn.Reload(c.Request.Context()); reloadErr != nil {
				config.DebugLog("Error: failed to reload fail2ban after disabling jails: %v", reloadErr)
				c.JSON(http.StatusOK, gin.H{
					"error":        fmt.Sprintf("Failed to reload fail2ban after disabling jails: %v", reloadErr),
					"autoDisabled": true,
					"enabledJails": getJailNames(enabledJails),
				})
				return
			}

			config.DebugLog("Successfully disabled %d jail(s) and reloaded fail2ban", len(enabledJails))
			jailNamesList := getJailNames(enabledJails)
			if len(jailNamesList) == 1 {
				c.JSON(http.StatusOK, gin.H{
					"error":        fmt.Sprintf("Jail '%s' was enabled but caused a reload error: %s. It has been automatically disabled.", jailNamesList[0], errMsg),
					"autoDisabled": true,
					"enabledJails": jailNamesList,
					"message":      fmt.Sprintf("Jail '%s' was automatically disabled due to configuration error", jailNamesList[0]),
				})
			} else {
				c.JSON(http.StatusOK, gin.H{
					"error":        fmt.Sprintf("Jails %v were enabled but caused a reload error: %s. They have been automatically disabled.", jailNamesList, errMsg),
					"autoDisabled": true,
					"enabledJails": jailNamesList,
					"message":      fmt.Sprintf("%d jail(s) were automatically disabled due to configuration error", len(jailNamesList)),
				})
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"error": fmt.Sprintf("Failed to reload fail2ban: %s", errMsg),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Jail settings updated and fail2ban reloaded successfully"})
}

// Creates a new jail with the given name and optional config.
func CreateJailHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("CreateJailHandler called (handlers.go)")

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var req struct {
		JailName string `json:"jailName" binding:"required"`
		Content  string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON: " + err.Error()})
		return
	}

	if err := fail2ban.ValidateJailName(req.JailName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Content == "" {
		req.Content = fmt.Sprintf("[%s]\nenabled = false\n", req.JailName)
	}

	if err := conn.CreateJail(c.Request.Context(), req.JailName, req.Content); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create jail: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Jail '%s' created successfully", req.JailName)})
}

// Removes a jail and its config file.
func DeleteJailHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("DeleteJailHandler called (handlers.go)")

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	jailName := c.Param("jail")
	if jailName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Jail name is required"})
		return
	}

	if err := fail2ban.ValidateJailName(jailName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := conn.DeleteJail(c.Request.Context(), jailName); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete jail: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Jail '%s' deleted successfully", jailName)})
}

// =========================================================================
//  App Settings
// =========================================================================

// Returns the current AppSettings as JSON.
func GetSettingsHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("GetSettingsHandler called (handlers.go)")
	s := config.GetSettings()

	envPort, envPortSet := config.GetPortFromEnv()
	response := make(map[string]interface{})
	responseBytes, _ := json.Marshal(s)
	json.Unmarshal(responseBytes, &response)
	response["portFromEnv"] = envPort
	response["portEnvSet"] = envPortSet

	if envPortSet {
		response["port"] = envPort
	}

	envCallbackURL, envCallbackURLSet := config.GetCallbackURLFromEnv()
	response["callbackUrlEnvSet"] = envCallbackURLSet
	response["callbackUrlFromEnv"] = envCallbackURL
	if envCallbackURLSet {
		response["callbackUrl"] = envCallbackURL
	}

	c.JSON(http.StatusOK, response)
}

// Saves new settings, pushes defaults to servers, and reloads.
func UpdateSettingsHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("UpdateSettingsHandler called (handlers.go)")
	var req config.AppSettings
	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Println("JSON binding error:", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid JSON",
			"details": err.Error(),
		})
		return
	}
	config.DebugLog("JSON binding successful, updating settings (handlers.go)")

	// Ignores port changes from request if the PORT environment variable is set
	envPort, envPortSet := config.GetPortFromEnv()
	if envPortSet {
		req.Port = envPort
	}

	// Ignores callback URL changes from request if the CALLBACK_URL environment variable is set
	envCallbackURL, envCallbackURLSet := config.GetCallbackURLFromEnv()
	if envCallbackURLSet {
		req.CallbackURL = envCallbackURL
	}

	oldSettings := config.GetSettings()
	newSettings, err := config.UpdateSettings(req)
	if err != nil {
		fmt.Println("Error updating settings:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	config.DebugLog("Settings updated successfully (handlers.go)")

	// Checks if the callback URL changed; if so, updates the action files for all active remote servers
	callbackURLChanged := oldSettings.CallbackURL != newSettings.CallbackURL

	if err := fail2ban.GetManager().ReloadFromSettings(config.GetSettings()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reload fail2ban connectors: " + err.Error()})
		return
	}

	if callbackURLChanged {
		config.DebugLog("Callback URL changed, updating action files and reloading fail2ban on all servers")

		// Updates the action files for remote servers (SSH and Agent)
		if err := fail2ban.GetManager().UpdateActionFiles(c.Request.Context()); err != nil {
			config.DebugLog("Warning: failed to update some remote action files: %v", err)
		}

		// Reloads all remote servers after updating the action files
		connectors := fail2ban.GetManager().Connectors()
		for _, conn := range connectors {
			server := conn.Server()
			// Only reloads remote servers (SSH and Agent), local will be handled separately
			if (server.Type == "ssh" || server.Type == "agent") && server.Enabled {
				config.DebugLog("Reloading fail2ban on %s after callback URL change", server.Name)
				if err := conn.Reload(c.Request.Context()); err != nil {
					config.DebugLog("Warning: failed to reload fail2ban on %s after updating action file: %v", server.Name, err)
				} else {
					config.DebugLog("Successfully reloaded fail2ban on %s", server.Name)
				}
			}
		}

		// Also updates the local action file if the callback URL changed
		settings := config.GetSettings()
		for _, server := range settings.Servers {
			if server.Type == "local" && server.Enabled {
				if err := config.EnsureLocalFail2banAction(server); err != nil {
					config.DebugLog("Warning: failed to update local action file: %v", err)
				} else {
					// Reloads local fail2ban after updating the action file
					if conn, err := fail2ban.GetManager().Connector(server.ID); err == nil {
						config.DebugLog("Reloading local fail2ban after callback URL change")
						if reloadErr := conn.Reload(c.Request.Context()); reloadErr != nil {
							config.DebugLog("Warning: failed to reload local fail2ban after updating action file: %v", reloadErr)
						} else {
							config.DebugLog("Successfully reloaded local fail2ban")
						}
					}
				}
			}
		}
	}

	ignoreIPsChanged := !equalStringSlices(oldSettings.IgnoreIPs, newSettings.IgnoreIPs)
	defaultSettingsChanged := oldSettings.BantimeIncrement != newSettings.BantimeIncrement ||
		oldSettings.DefaultJailEnable != newSettings.DefaultJailEnable ||
		ignoreIPsChanged ||
		oldSettings.Bantime != newSettings.Bantime ||
		oldSettings.BantimeRndtime != newSettings.BantimeRndtime ||
		oldSettings.Findtime != newSettings.Findtime ||
		oldSettings.Maxretry != newSettings.Maxretry ||
		oldSettings.Banaction != newSettings.Banaction ||
		oldSettings.BanactionAllports != newSettings.BanactionAllports ||
		oldSettings.Chain != newSettings.Chain

	if defaultSettingsChanged {
		config.DebugLog("Fail2Ban DEFAULT settings changed, pushing to all enabled servers")
		connectors := fail2ban.GetManager().Connectors()
		var errors []string
		for _, conn := range connectors {
			server := conn.Server()
			config.DebugLog("Updating DEFAULT settings on server: %s (type: %s)", server.Name, server.Type)
			if err := conn.UpdateDefaultSettings(c.Request.Context(), newSettings); err != nil {
				errorMsg := fmt.Sprintf("Failed to update DEFAULT settings on %s: %v", server.Name, err)
				log.Printf("⚠️ %s", errorMsg)
				errors = append(errors, errorMsg)
			} else {
				config.DebugLog("Successfully updated DEFAULT settings on %s", server.Name)
				if err := conn.Reload(c.Request.Context()); err != nil {
					config.DebugLog("Warning: failed to reload fail2ban on %s after updating DEFAULT settings: %v", server.Name, err)
					errors = append(errors, fmt.Sprintf("Settings updated on %s, but reload failed: %v", server.Name, err))
				} else {
					config.DebugLog("Successfully reloaded fail2ban on %s", server.Name)
				}
			}
		}
		if len(errors) > 0 {
			config.DebugLog("Some servers failed to update DEFAULT settings: %v", errors)
			c.JSON(http.StatusOK, gin.H{
				"message":       "Settings updated",
				"restartNeeded": false,
				"warnings":      errors,
			})
			return
		}
		// Settings were updated and reloaded successfully
		c.JSON(http.StatusOK, gin.H{
			"message":       "Settings updated and fail2ban reloaded",
			"restartNeeded": false,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "Settings updated",
		"restartNeeded": newSettings.RestartNeeded,
	})
}

// =========================================================================
//  Filters
// =========================================================================

// Returns all available filter names for the selected server.
func ListFiltersHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("ListFiltersHandler called (handlers.go)")
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	server := conn.Server()
	if server.Type == "local" {
		dir := "/etc/fail2ban/filter.d"
		if _, statErr := os.Stat(dir); statErr != nil {
			if os.IsNotExist(statErr) {
				c.JSON(http.StatusOK, gin.H{"filters": []string{}, "messageKey": "filter_debug.local_missing"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read filter directory: " + statErr.Error()})
			return
		}
	}

	filters, err := conn.GetFilters(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list filters: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"filters": filters})
}

// Returns the content of a specific filter file.
func GetFilterContentHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("GetFilterContentHandler called (handlers.go)")
	filterName := c.Param("filter")
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	content, filePath, err := conn.GetFilterConfig(c.Request.Context(), filterName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get filter content: " + err.Error()})
		return
	}

	content = fail2ban.RemoveComments(content)

	c.JSON(http.StatusOK, gin.H{
		"content":    content,
		"filterPath": filePath,
	})
}

// Runs fail2ban-regex against provided log lines and filter content.
func TestFilterHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("TestFilterHandler called (handlers.go)")
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req struct {
		FilterName    string   `json:"filterName"`
		LogLines      []string `json:"logLines"`
		FilterContent string   `json:"filterContent"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	output, filterPath, err := conn.TestFilter(c.Request.Context(), req.FilterName, req.LogLines, req.FilterContent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to test filter: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"output":     output,
		"filterPath": filterPath,
	})
}

// Creates a new filter definition file.
func CreateFilterHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("CreateFilterHandler called (handlers.go)")

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var req struct {
		FilterName string `json:"filterName" binding:"required"`
		Content    string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON: " + err.Error()})
		return
	}

	// Validate filter name
	if err := fail2ban.ValidateFilterName(req.FilterName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Content == "" {
		req.Content = fmt.Sprintf("# Filter: %s\n", req.FilterName)
	}

	// Create the filter
	if err := conn.CreateFilter(c.Request.Context(), req.FilterName, req.Content); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create filter: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Filter '%s' created successfully", req.FilterName)})
}

// Removes a filter definition file.
func DeleteFilterHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("DeleteFilterHandler called (handlers.go)")

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	filterName := c.Param("filter")
	if filterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Filter name is required"})
		return
	}

	if err := fail2ban.ValidateFilterName(filterName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := conn.DeleteFilter(c.Request.Context(), filterName); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete filter: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Filter '%s' deleted successfully", filterName)})
}

// =========================================================================
//  Restart
// =========================================================================

// Restarts (or reloads) the Fail2ban service on the selected server.
func RestartFail2banHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("RestartFail2banHandler called (handlers.go)")

	serverID := c.Query("serverId")
	var conn fail2ban.Connector
	var err error

	if serverID != "" {
		manager := fail2ban.GetManager()
		conn, err = manager.Connector(serverID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Server not found: " + err.Error()})
			return
		}
	} else {
		// Uses the default connector from the context
		conn, err = resolveConnector(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	server := conn.Server()

	// Attempts to restart the fail2ban service via the connector.
	mode, err := fail2ban.RestartFail2ban(server.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Only calls MarkRestartDone if the service was successfully restarted
	//if err := config.MarkRestartDone(server.ID); err != nil {
	//	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	//	return
	//}
	msg := "Fail2ban service restarted successfully"
	if mode == "reload" {
		msg = "Fail2ban configuration reloaded successfully (no systemd service restart)"
	}
	c.JSON(http.StatusOK, gin.H{
		"message": msg,
		"mode":    mode,
		"server":  server,
	})
}

// =========================================================================
//  Email Alerts and SMTP
// =========================================================================

// loadLocale returns cached translations for the given language, loading from disk if needed.
func loadLocale(lang string) (map[string]string, error) {
	localeCacheLock.RLock()
	if cached, ok := localeCache[lang]; ok {
		localeCacheLock.RUnlock()
		return cached, nil
	}
	localeCacheLock.RUnlock()

	// Determines the locale file path
	var localePath string
	_, container := os.LookupEnv("CONTAINER")
	if container {
		localePath = fmt.Sprintf("/app/locales/%s.json", lang)
	} else {
		localePath = fmt.Sprintf("./internal/locales/%s.json", lang)
	}

	data, err := os.ReadFile(localePath)
	if err != nil {
		// Falls back to English if the locale file is not found
		if lang != "en" {
			return loadLocale("en")
		}
		return nil, fmt.Errorf("failed to read locale file: %w", err)
	}

	var translations map[string]string
	if err := json.Unmarshal(data, &translations); err != nil {
		return nil, fmt.Errorf("failed to parse locale file: %w", err)
	}

	localeCacheLock.Lock()
	localeCache[lang] = translations
	localeCacheLock.Unlock()

	return translations, nil
}

// Resolves a translation key, falling back to English.
func getEmailTranslation(lang, key string) string {
	translations, err := loadLocale(lang)
	if err != nil {
		if lang != "en" {
			translations, err = loadLocale("en")
			if err != nil {
				return key
			}
		} else {
			return key
		}
	}

	if translation, ok := translations[key]; ok {
		return translation
	}

	if lang != "en" {
		enTranslations, err := loadLocale("en")
		if err == nil {
			if enTranslation, ok := enTranslations[key]; ok {
				return enTranslation
			}
		}
	}
	return key
}

// Reads the email template style from environment variable (default: "modern").
func getEmailStyle() string {
	style := os.Getenv("emailStyle")
	if style == "classic" {
		return "classic"
	}
	return "modern"
}

// Connects to the SMTP server and delivers a single HTML message.
func sendEmail(to, subject, body string, settings config.AppSettings) error {
	// Skips sending if the destination email is still the default placeholder
	if strings.EqualFold(strings.TrimSpace(to), "alerts@example.com") {
		log.Printf("⚠️ sendEmail skipped: destination email is still the default placeholder (alerts@example.com). Please update the 'Destination Email' in Settings → Alert Settings.")
		return nil
	}

	if settings.SMTP.Host == "" || settings.SMTP.Username == "" || settings.SMTP.Password == "" || settings.SMTP.From == "" {
		err := errors.New("SMTP settings are incomplete. Please configure all required fields")
		log.Printf("❌ sendEmail validation failed: %v (Host: %q, Username: %q, From: %q)", err, settings.SMTP.Host, settings.SMTP.Username, settings.SMTP.From)
		return err
	}

	if settings.SMTP.Port <= 0 || settings.SMTP.Port > 65535 {
		err := errors.New("SMTP port must be between 1 and 65535")
		log.Printf("❌ sendEmail validation failed: %v (Port: %d)", err, settings.SMTP.Port)
		return err
	}

	msgID := fmt.Sprintf("<%d.%s@fail2ban-ui>", time.Now().UnixNano(), settings.SMTP.From)
	message := "From: " + settings.SMTP.From + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"Message-ID: " + msgID + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
		"\r\n" + body
	msg := []byte(message)

	smtpHost := settings.SMTP.Host
	smtpPort := settings.SMTP.Port
	smtpAddr := net.JoinHostPort(smtpHost, fmt.Sprintf("%d", smtpPort))

	tlsConfig := &tls.Config{
		ServerName:         smtpHost,
		InsecureSkipVerify: settings.SMTP.InsecureSkipVerify,
	}

	authMethod := settings.SMTP.AuthMethod
	if authMethod == "" {
		authMethod = "auto"
	}
	auth, err := getSMTPAuth(settings.SMTP.Username, settings.SMTP.Password, authMethod, smtpHost)
	if err != nil {
		log.Printf("❌ sendEmail: failed to create SMTP auth (method: %q): %v", authMethod, err)
		return fmt.Errorf("failed to create SMTP auth: %w", err)
	}
	log.Printf("📧 sendEmail: Using SMTP auth method: %q, host: %s, port: %d, useTLS: %v, insecureSkipVerify: %v", authMethod, smtpHost, smtpPort, settings.SMTP.UseTLS, settings.SMTP.InsecureSkipVerify)

	// Determines the connection type based on the port and UseTLS setting
	// Port 465 typically uses implicit TLS (SMTPS)
	// Port 587 typically uses STARTTLS
	useImplicitTLS := (smtpPort == 465) || (settings.SMTP.UseTLS && smtpPort != 587 && smtpPort != 25)
	useSTARTTLS := settings.SMTP.UseTLS && (smtpPort == 587 || (smtpPort != 465 && smtpPort != 25))

	var client *smtp.Client

	if useImplicitTLS {
		conn, err := tls.Dial("tcp", smtpAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect via TLS: %w", err)
		}
		defer conn.Close()

		client, err = smtp.NewClient(conn, smtpHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
	} else {
		conn, err := net.DialTimeout("tcp", smtpAddr, 30*time.Second)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
		defer conn.Close()

		client, err = smtp.NewClient(conn, smtpHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}

		if useSTARTTLS {
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("failed to start TLS: %w", err)
			}
		}
	}

	defer func() {
		if client != nil {
			client.Quit()
		}
	}()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			log.Printf("❌ sendEmail: SMTP authentication failed: %v", err)
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
		log.Printf("📧 sendEmail: SMTP authentication successful")
	}

	err = sendSMTPMessage(client, settings.SMTP.From, to, msg)
	if err != nil {
		log.Printf("❌ sendEmail: Failed to send message: %v", err)
		return err
	}
	log.Printf("📧 sendEmail: Successfully sent email to %s", to)
	return nil
}

// Sends the actual message
// Performs the MAIL/RCPT/DATA sequence on an open SMTP connection.
func sendSMTPMessage(client *smtp.Client, from, to string, msg []byte) error {
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to start data command: %w", err)
	}
	defer wc.Close()
	if _, err = wc.Write(msg); err != nil {
		return fmt.Errorf("failed to write email content: %w", err)
	}
	client.Quit()
	return nil
}

// Builds paragraph-based details for the classic email template.
func renderClassicEmailDetails(details []emailDetail) string {
	if len(details) == 0 {
		return `<p>No metadata available.</p>`
	}
	var b strings.Builder
	for _, d := range details {
		b.WriteString(`<p><span class="label">` + html.EscapeString(d.Label) + `:</span> ` + html.EscapeString(d.Value) + `</p>`)
		b.WriteString("\n")
	}
	return b.String()
}

// Renders the original email template layout.
func buildClassicEmailBody(title, intro string, details []emailDetail, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText, supportEmail string) string {
	detailRows := renderClassicEmailDetails(details)
	year := time.Now().Year()
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
    body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 20px auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0px 2px 4px rgba(0,0,0,0.1); }
    .header { text-align: center; padding-bottom: 10px; border-bottom: 2px solid #005DE0; }
    .header img { max-width: 150px; }
    .header h2 { color: #005DE0; margin: 10px 0; font-size: 24px; }
    .content { padding: 15px; }
    .details { background: #f9f9f9; padding: 15px; border-left: 4px solid #5579f8; margin-bottom: 10px; }
    .footer { text-align: center; color: #888; font-size: 12px; padding-top: 10px; border-top: 1px solid #ddd; margin-top: 15px; }
    .footer a { color: #005DE0; text-decoration: none; }
    .footer a:hover { color: #0044b3; text-decoration: underline; }
    .label { font-weight: bold; color: #333; }
    a { color: #005DE0; text-decoration: none; }
    a:hover { color: #0044b3; text-decoration: underline; }
    pre {
        background: #222;
        color: #ddd;
        font-family: "Courier New", Courier, monospace;
        font-size: 12px;
        padding: 10px;
        border-radius: 5px;
        overflow-x: auto;
        white-space: pre-wrap;
    }
    @media screen and (max-width: 600px) {
        .container { width: 90%%; padding: 10px; }
        .header h2 { font-size: 20px; }
        .details p { font-size: 14px; }
        .footer { font-size: 10px; }
    }
</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="https://swissmakers.ch/wp-content/uploads/2023/09/cyber.png" alt="Swissmakers GmbH" width="150" />
            <h2>🚨 %s</h2>
        </div>
        <div class="content">
            <p>%s</p>
            <div class="details">
                %s
            </div>
            <h3>🔍 %s</h3>
            %s
            <h3>📄 %s</h3>
            %s
        </div>
        <div class="footer">
            <p>%s</p>
            <p>For security inquiries, contact <a href="mailto:%s">%s</a></p>
            <p>&copy; %d Swissmakers GmbH. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(intro), detailRows, html.EscapeString(whoisTitle), whoisHTML, html.EscapeString(logsTitle), logsHTML, html.EscapeString(footerText), html.EscapeString(supportEmail), html.EscapeString(supportEmail), year)
}

// Renders the LOTR-themed email template.
func buildLOTREmailBody(title, intro string, details []emailDetail, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText string) string {
	detailRows := renderEmailDetails(details)
	year := strconv.Itoa(time.Now().Year())
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>%s</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { margin:0; padding:0; background: linear-gradient(135deg, #0d2818 0%%, #1a4d2e 50%%, #2d0a4f 100%%); font-family: Georgia, "Times New Roman", serif; color:#f4e8d0; line-height:1.6; -webkit-font-smoothing:antialiased; }
    .email-wrapper { width:100%%; padding:20px 10px; background: linear-gradient(135deg, #0d2818 0%%, #1a4d2e 50%%, #2d0a4f 100%%); }
    .email-container { max-width:640px; margin:0 auto; background:#f4e8d0; border:4px solid #d4af37; border-radius:12px; box-shadow:0 8px 32px rgba(0,0,0,0.6), inset 0 0 40px rgba(212,175,55,0.1); overflow:hidden; position:relative; }
    .email-container::before { content:''; position:absolute; top:0; left:0; right:0; bottom:0; background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(139,115,85,0.03) 2px, rgba(139,115,85,0.03) 4px); pointer-events:none; }
    .email-header { background: linear-gradient(180deg, #c1121f 0%%, #ff6b35 30%%, #d4af37 70%%, #1a4d2e 100%%); color:#ffffff; padding:40px 28px; text-align:center; position:relative; overflow:hidden; }
    .email-header::before { content:''; position:absolute; top:0; left:0; right:0; bottom:0; background: radial-gradient(circle at center, rgba(255,255,255,0.1) 0%%, transparent 70%%); animation: fireFlicker 3s ease-in-out infinite; }
    @keyframes fireFlicker { 0%%,100%% { opacity:0.6; } 50%% { opacity:1; } }
    .email-header-brand { margin:0 0 12px; font-size:12px; letter-spacing:0.4em; text-transform:uppercase; opacity:0.9; font-weight:600; font-family:'Cinzel', serif; position:relative; z-index:1; }
    .email-header-title { margin:20px 0; font-size:42px; font-weight:700; line-height:1.1; text-shadow: 0 0 20px rgba(255,255,255,0.8), 0 0 40px rgba(255,107,53,0.6), 0 0 60px rgba(193,18,31,0.4); font-family:'Cinzel', serif; letter-spacing:0.1em; position:relative; z-index:1; animation: textGlow 2s ease-in-out infinite; }
    @keyframes textGlow { 0%%,100%% { text-shadow: 0 0 20px rgba(255,255,255,0.8), 0 0 40px rgba(255,107,53,0.6), 0 0 60px rgba(193,18,31,0.4); } 50%% { text-shadow: 0 0 30px rgba(255,255,255,1), 0 0 60px rgba(255,107,53,0.8), 0 0 90px rgba(193,18,31,0.6); } }
    .ring-divider { text-align:center; margin:30px 0; position:relative; }
    .ring-divider::before { content:'⚔'; position:absolute; left:20%%; top:50%%; transform:translateY(-50%%); font-size:24px; color:#d4af37; background:#f4e8d0; padding:0 15px; }
    .ring-divider::after { content:'⚔'; position:absolute; right:20%%; top:50%%; transform:translateY(-50%%); font-size:24px; color:#d4af37; background:#f4e8d0; padding:0 15px; }
    .ring-divider-line { height:3px; background:linear-gradient(90deg, transparent 0%%, #d4af37 20%%, #d4af37 80%%, transparent 100%%); margin:0 25%%; }
    .email-body { padding:36px 28px; background:#f4e8d0; color:#3d2817; }
    .email-intro { font-size:18px; line-height:1.8; margin:0 0 28px; color:#3d2817; font-style:italic; text-align:center; }
    .email-details-wrapper { background:#e8d5b7; border:3px solid #8b7355; border-radius:8px; padding:24px; margin:0 0 32px; box-shadow:inset 0 2px 4px rgba(0,0,0,0.1); }
    .email-details-wrapper p { margin:12px 0; font-size:15px; line-height:1.7; color:#3d2817; }
    .email-details-wrapper p:first-child { margin-top:0; }
    .email-details-wrapper p:last-child { margin-bottom:0; }
    .email-detail-label { font-weight:700; color:#1a4d2e; margin-right:8px; font-family:'Cinzel', serif; }
    .email-section { margin:36px 0 0; }
    .email-section-title { font-size:16px; text-transform:uppercase; letter-spacing:0.2em; color:#1a4d2e; margin:0 0 16px; font-weight:700; font-family:'Cinzel', serif; border-bottom:2px solid #d4af37; padding-bottom:8px; }
    .email-terminal { background:#1a1a1a; color:#d4af37; padding:20px; font-family:"Courier New", Courier, monospace; border-radius:8px; font-size:13px; line-height:1.7; white-space:pre-wrap; word-break:break-word; overflow-x:auto; margin:0; border:2px solid #8b7355; box-shadow:inset 0 0 20px rgba(212,175,55,0.1); }
    .email-log-stack { background:#0f0f0f; border-radius:8px; padding:16px; border:2px solid #8b7355; }
    .email-log-line { font-family:"Courier New", Courier, monospace; font-size:12px; line-height:1.6; color:#d4af37; padding:8px 12px; border-radius:6px; margin:0 0 6px; background:rgba(212,175,55,0.1); border-left:3px solid #d4af37; }
    .email-log-line:last-child { margin-bottom:0; }
    .email-log-line-alert { background:rgba(193,18,31,0.3); color:#ff6b35; border-left-color:#c1121f; }
    .email-muted { color:#8b7355; font-size:14px; line-height:1.6; font-style:italic; }
    .email-footer { border-top:3px solid #d4af37; padding:24px 28px; font-size:13px; color:#3d2817; text-align:center; background:#e8d5b7; font-family:'Cinzel', serif; }
    .email-footer-text { margin:0 0 8px; font-weight:600; }
    .email-footer-copyright { margin:0; font-size:11px; color:#8b7355; }
    .email-header a { color:#ffffff !important; text-decoration:underline; }
    .email-header a:hover { color:#f4e8d0 !important; }
    a { color:#1a4d2e; text-decoration:none; }
    a:hover { color:#2d0a4f; text-decoration:underline; }
    @media only screen and (max-width:600px) {
      .email-wrapper { padding:12px 8px; }
      .email-header { padding:30px 20px; }
      .email-header-title { font-size:32px; }
      .email-body { padding:28px 20px; }
      .email-intro { font-size:16px; }
      .email-details-wrapper { padding:20px; }
      .email-footer { padding:20px 16px; }
    }
    @media only screen and (max-width:480px) {
      .email-header-title { font-size:28px; }
      .email-body { padding:24px 16px; }
      .email-details-wrapper { padding:16px; }
    }
  </style>
</head>
<body>
  <div class="email-wrapper">
    <div class="email-container">
      <div class="email-header">
        <p class="email-header-brand">Middle-earth Security</p>
        <h1 class="email-header-title">YOU SHALL NOT PASS</h1>
        <div class="ring-divider">
          <div class="ring-divider-line"></div>
        </div>
      </div>
      <div class="email-body">
        <p class="email-intro">%s</p>
        <div class="email-details-wrapper">
          %s
        </div>
        <div class="email-section">
          <p class="email-section-title">%s</p>
          %s
        </div>
        <div class="email-section">
          <p class="email-section-title">%s</p>
          %s
        </div>
      </div>
      <div class="email-footer">
        <p class="email-footer-text">%s</p>
        <p class="email-footer-copyright">© %s Swissmakers GmbH. All rights reserved.</p>
      </div>
    </div>
  </div>
</body>
</html>`, html.EscapeString(title), html.EscapeString(intro), detailRows, html.EscapeString(whoisTitle), whoisHTML, html.EscapeString(logsTitle), logsHTML, html.EscapeString(footerText), year)
}

// Renders the default responsive email template.
func buildModernEmailBody(title, intro string, details []emailDetail, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText string) string {
	detailRows := renderEmailDetails(details)
	year := strconv.Itoa(time.Now().Year())
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>%s</title>
  <style>
    * { box-sizing: border-box; }
    body { margin:0; padding:0; background-color:#f6f8fb; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; color:#1f2933; line-height:1.6; -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale; }
    .email-wrapper { width:100%%; padding:20px 10px; }
    .email-container { max-width:640px; margin:0 auto; background:#ffffff; border-radius:20px; box-shadow:0 4px 20px rgba(0,0,0,0.08), 0 0 0 1px rgba(0,0,0,0.04); overflow:hidden; }
    .email-header { background:linear-gradient(135deg,#004cff 0%%,#6c2bd9 100%%); background-color:#004cff; color:#ffffff !important; padding:32px 28px; text-align:center; }
    .email-header-brand { margin:0 0 8px; font-size:11px; letter-spacing:0.3em; text-transform:uppercase; opacity:0.9; font-weight:600; color:#ffffff !important; }
    .email-header-title { margin:0 0 10px; font-size:26px; font-weight:700; line-height:1.2; color:#ffffff !important; }
    .email-header a { color:#ffffff !important; text-decoration:underline; }
    .email-header a:hover { color:#e0e7ff !important; }
    .email-body { padding:36px 28px; }
    a { color:#2563eb; text-decoration:none; }
    a:hover { color:#1d4ed8; text-decoration:underline; }
    .email-intro { font-size:16px; line-height:1.7; margin:0 0 28px; color:#4b5563; }
    .email-details-wrapper { background:#f9fafb; border-radius:12px; padding:20px; margin:0 0 32px; border:1px solid #e5e7eb; }
    .email-details-wrapper p { margin:8px 0; font-size:14px; line-height:1.6; color:#111827; }
    .email-details-wrapper p:first-child { margin-top:0; }
    .email-details-wrapper p:last-child { margin-bottom:0; }
    .email-detail-label { font-weight:700; color:#374151; margin-right:8px; }
    .email-section { margin:36px 0 0; }
    .email-section-title { font-size:13px; text-transform:uppercase; letter-spacing:0.1em; color:#6b7280; margin:0 0 16px; font-weight:700; }
    .email-terminal { background:#111827; color:#f3f4f6; padding:20px; font-family:"SFMono-Regular","Consolas","Liberation Mono","Courier New",monospace; border-radius:12px; font-size:12px; line-height:1.7; white-space:pre-wrap; word-break:break-word; overflow-x:auto; margin:0; }
    .email-log-stack { background:#0f172a; border-radius:12px; padding:16px; }
    .email-log-line { font-family:"SFMono-Regular","Consolas","Liberation Mono","Courier New",monospace; font-size:12px; line-height:1.6; color:#cbd5f5; padding:8px 12px; border-radius:8px; margin:0 0 6px; background:rgba(255,255,255,0.05); }
    .email-log-line:last-child { margin-bottom:0; }
    .email-log-line-alert { background:rgba(248,113,113,0.25); color:#ffffff; border:1px solid rgba(248,113,113,0.5); }
    .email-muted { color:#9ca3af; font-size:13px; line-height:1.6; }
    .email-footer { border-top:1px solid #e5e7eb; padding:24px 28px; font-size:12px; color:#6b7280; text-align:center; background:#fafbfc; }
    .email-footer-text { margin:0 0 8px; }
    .email-footer-copyright { margin:0; font-size:11px; color:#9ca3af; }
    @media only screen and (max-width:600px) {
      .email-wrapper { padding:12px 8px; }
      .email-header { padding:24px 20px; background-color:#004cff !important; }
      .email-header-brand { color:#ffffff !important; }
      .email-header-title { font-size:22px; color:#ffffff !important; }
      .email-body { padding:28px 20px; }
      .email-intro { font-size:15px; }
      .email-details-wrapper { padding:16px; }
      .email-details-wrapper p { font-size:14px; margin:10px 0; }
      .email-footer { padding:20px 16px; }
    }
    @media only screen and (max-width:480px) {
      .email-header { background-color:#004cff !important; }
      .email-header-brand { color:#ffffff !important; }
      .email-header-title { font-size:20px; color:#ffffff !important; }
      .email-body { padding:24px 16px; }
      .email-details-wrapper { padding:12px; }
    }
    @media print {
      .email-header { background:#004cff !important; background-color:#004cff !important; color:#ffffff !important; }
      .email-header-brand { color:#ffffff !important; }
      .email-header-title { color:#ffffff !important; }
      .email-header a { color:#ffffff !important; }
      a { color:#2563eb !important; }
    }
  </style>
</head>
<body>
  <div class="email-wrapper">
    <div class="email-container">
      <div class="email-header">
        <p class="email-header-brand">Fail2Ban UI</p>
        <h1 class="email-header-title">%s</h1>
      </div>
      <div class="email-body">
        <p class="email-intro">%s</p>
        <div class="email-details-wrapper">
          %s
        </div>
        <div class="email-section">
          <p class="email-section-title">%s</p>
          %s
        </div>
        <div class="email-section">
          <p class="email-section-title">%s</p>
          %s
        </div>
      </div>
      <div class="email-footer">
        <p class="email-footer-text">%s</p>
        <p class="email-footer-copyright">© %s Swissmakers GmbH. All rights reserved.</p>
      </div>
    </div>
  </div>
</body>
</html>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(intro), detailRows, html.EscapeString(whoisTitle), whoisHTML, html.EscapeString(logsTitle), logsHTML, html.EscapeString(footerText), year)
}

// Builds table rows for the modern/LOTR email templates.
func renderEmailDetails(details []emailDetail) string {
	if len(details) == 0 {
		return `<p class="email-muted">No metadata available.</p>`
	}
	var b strings.Builder
	for _, d := range details {
		b.WriteString(`<p><span class="email-detail-label">` + html.EscapeString(d.Label) + `:</span> ` + html.EscapeString(d.Value) + `</p>`)
		b.WriteString("\n")
	}
	return b.String()
}

// Wraps raw WHOIS text in a styled <pre> block for email.
func formatWhoisForEmail(whois string, lang string, isModern bool) string {
	noDataMsg := getEmailTranslation(lang, "email.whois.no_data")
	if strings.TrimSpace(whois) == "" {
		if isModern {
			return `<p class="email-muted">` + html.EscapeString(noDataMsg) + `</p>`
		}
		return `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(noDataMsg) + `</pre>`
	}
	if isModern {
		return `<pre class="email-terminal">` + html.EscapeString(whois) + `</pre>`
	}
	return `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(whois) + `</pre>`
}

// Highlights suspicious lines and HTTP status codes in email logs.
func formatLogsForEmail(ip, logs string, lang string, isModern bool) string {
	noLogsMsg := getEmailTranslation(lang, "email.logs.no_data")
	if strings.TrimSpace(logs) == "" {
		if isModern {
			return `<p class="email-muted">` + html.EscapeString(noLogsMsg) + `</p>`
		}
		return `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(noLogsMsg) + `</pre>`
	}
	if isModern {
		var b strings.Builder
		b.WriteString(`<div class="email-log-stack">`)
		lines := strings.Split(logs, "\n")
		for _, line := range lines {
			trimmed := strings.TrimRight(line, "\r")
			if trimmed == "" {
				continue
			}
			class := "email-log-line"
			if isSuspiciousLogLineEmail(trimmed, ip) {
				class = "email-log-line email-log-line-alert"
			}
			b.WriteString(`<div class="` + class + `">` + html.EscapeString(trimmed) + `</div>`)
		}
		b.WriteString(`</div>`)
		return b.String()
	}
	return `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(logs) + `</pre>`
}

// Checks if the line contains known attack indicators.
func isSuspiciousLogLineEmail(line, ip string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	lowered := strings.ToLower(trimmed)
	containsIP := ip != "" && strings.Contains(trimmed, ip)
	statusCode := extractStatusCodeFromLine(trimmed)
	hasBadStatus := statusCode >= 300
	hasIndicator := false
	for _, indicator := range suspiciousLogIndicators {
		if strings.Contains(lowered, indicator) {
			hasIndicator = true
			break
		}
	}
	if containsIP {
		return hasBadStatus || hasIndicator
	}
	return (hasBadStatus || hasIndicator) && ip == ""
}

// Parses the HTTP status code from a log line.
func extractStatusCodeFromLine(line string) int {
	if match := httpQuotedStatusPattern.FindStringSubmatch(line); len(match) == 2 {
		if code, err := strconv.Atoi(match[1]); err == nil {
			return code
		}
	}
	if match := httpPlainStatusPattern.FindStringSubmatch(line); len(match) == 2 {
		if code, err := strconv.Atoi(match[1]); err == nil {
			return code
		}
	}
	return 0
}

// Composes and sends the ban notification email.
func sendBanAlert(ip, jail, hostname, failures, whois, logs, country string, settings config.AppSettings) error {
	lang := settings.Language
	if lang == "" {
		lang = "en"
	}
	isLOTRMode := config.IsLOTRModeActive(settings.AlertCountries)
	var subject string
	if isLOTRMode {
		subject = fmt.Sprintf("[Middle-earth] %s: %s %s %s",
			getEmailTranslation(lang, "lotr.email.title"),
			ip,
			getEmailTranslation(lang, "email.ban.subject.from"),
			hostname)
	} else {
		subject = fmt.Sprintf("[Fail2Ban] %s: %s %s %s %s", jail,
			getEmailTranslation(lang, "email.ban.subject.banned"),
			ip,
			getEmailTranslation(lang, "email.ban.subject.from"),
			hostname)
	}
	emailStyle := getEmailStyle()
	isModern := emailStyle == "modern"

	var title, intro, whoisTitle, logsTitle, footerText string
	if isLOTRMode {
		title = getEmailTranslation(lang, "lotr.email.title")
		intro = getEmailTranslation(lang, "lotr.email.intro")
		whoisTitle = getEmailTranslation(lang, "email.ban.whois_title")
		logsTitle = getEmailTranslation(lang, "email.ban.logs_title")
		footerText = getEmailTranslation(lang, "lotr.email.footer")
	} else {
		title = getEmailTranslation(lang, "email.ban.title")
		intro = getEmailTranslation(lang, "email.ban.intro")
		whoisTitle = getEmailTranslation(lang, "email.ban.whois_title")
		logsTitle = getEmailTranslation(lang, "email.ban.logs_title")
		footerText = getEmailTranslation(lang, "email.footer.text")
	}
	supportEmail := "support@swissmakers.ch"

	var details []emailDetail
	if isLOTRMode {
		bannedIPLabel := getEmailTranslation(lang, "lotr.email.details.dark_servant_location")
		jailLabel := getEmailTranslation(lang, "lotr.email.details.realm_protection")
		countryLabelKey := getEmailTranslation(lang, "lotr.email.details.origins")
		var countryLabel string
		if country != "" {
			countryLabel = fmt.Sprintf("%s %s", countryLabelKey, country)
		} else {
			countryLabel = fmt.Sprintf("%s Unknown", countryLabelKey)
		}
		timestampLabel := getEmailTranslation(lang, "lotr.email.details.banished_at")

		details = []emailDetail{
			{Label: bannedIPLabel, Value: ip},
			{Label: jailLabel, Value: jail},
			{Label: getEmailTranslation(lang, "email.ban.details.hostname"), Value: hostname},
			{Label: getEmailTranslation(lang, "email.ban.details.failed_attempts"), Value: failures},
			{Label: countryLabel, Value: ""},
			{Label: timestampLabel, Value: time.Now().UTC().Format(time.RFC3339)},
		}
	} else {
		details = []emailDetail{
			{Label: getEmailTranslation(lang, "email.ban.details.banned_ip"), Value: ip},
			{Label: getEmailTranslation(lang, "email.ban.details.jail"), Value: jail},
			{Label: getEmailTranslation(lang, "email.ban.details.hostname"), Value: hostname},
			{Label: getEmailTranslation(lang, "email.ban.details.failed_attempts"), Value: failures},
			{Label: getEmailTranslation(lang, "email.ban.details.country"), Value: country},
			{Label: getEmailTranslation(lang, "email.ban.details.timestamp"), Value: time.Now().UTC().Format(time.RFC3339)},
		}
	}

	whoisHTML := formatWhoisForEmail(whois, lang, isModern)
	logsHTML := formatLogsForEmail(ip, logs, lang, isModern)

	var body string
	if isLOTRMode {
		body = buildLOTREmailBody(title, intro, details, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText)
	} else if isModern {
		body = buildModernEmailBody(title, intro, details, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText)
	} else {
		body = buildClassicEmailBody(title, intro, details, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText, supportEmail)
	}

	return sendEmail(settings.Destemail, subject, body, settings)
}

// Composes and sends the unban notification email.
func sendUnbanAlert(ip, jail, hostname, whois, country string, settings config.AppSettings) error {
	lang := settings.Language
	if lang == "" {
		lang = "en"
	}
	isLOTRMode := config.IsLOTRModeActive(settings.AlertCountries)
	var subject string
	if isLOTRMode {
		subject = fmt.Sprintf("[Middle-earth] %s: %s %s %s",
			getEmailTranslation(lang, "lotr.email.unban.title"),
			ip,
			getEmailTranslation(lang, "email.unban.subject.from"),
			hostname)
	} else {
		subject = fmt.Sprintf("[Fail2Ban] %s: %s %s %s %s", jail,
			getEmailTranslation(lang, "email.unban.subject.unbanned"),
			ip,
			getEmailTranslation(lang, "email.unban.subject.from"),
			hostname)
	}
	emailStyle := getEmailStyle()
	isModern := emailStyle == "modern"

	var title, intro, whoisTitle, footerText string
	if isLOTRMode {
		title = getEmailTranslation(lang, "lotr.email.unban.title")
		intro = getEmailTranslation(lang, "lotr.email.unban.intro")
		whoisTitle = getEmailTranslation(lang, "email.ban.whois_title")
		footerText = getEmailTranslation(lang, "lotr.email.footer")
	} else {
		title = getEmailTranslation(lang, "email.unban.title")
		intro = getEmailTranslation(lang, "email.unban.intro")
		whoisTitle = getEmailTranslation(lang, "email.ban.whois_title")
		footerText = getEmailTranslation(lang, "email.footer.text")
	}
	supportEmail := "support@swissmakers.ch"
	var details []emailDetail
	if isLOTRMode {
		details = []emailDetail{
			{Label: getEmailTranslation(lang, "lotr.email.unban.details.restored_ip"), Value: ip},
			{Label: getEmailTranslation(lang, "email.unban.details.jail"), Value: jail},
			{Label: getEmailTranslation(lang, "email.unban.details.hostname"), Value: hostname},
			{Label: getEmailTranslation(lang, "email.unban.details.country"), Value: country},
			{Label: getEmailTranslation(lang, "email.unban.details.timestamp"), Value: time.Now().UTC().Format(time.RFC3339)},
		}
	} else {
		details = []emailDetail{
			{Label: getEmailTranslation(lang, "email.unban.details.unbanned_ip"), Value: ip},
			{Label: getEmailTranslation(lang, "email.unban.details.jail"), Value: jail},
			{Label: getEmailTranslation(lang, "email.unban.details.hostname"), Value: hostname},
			{Label: getEmailTranslation(lang, "email.unban.details.country"), Value: country},
			{Label: getEmailTranslation(lang, "email.unban.details.timestamp"), Value: time.Now().UTC().Format(time.RFC3339)},
		}
	}

	whoisHTML := formatWhoisForEmail(whois, lang, isModern)

	var body string
	if isLOTRMode {
		body = buildLOTREmailBody(title, intro, details, whoisHTML, "", whoisTitle, "", footerText)
	} else if isModern {
		body = buildModernEmailBody(title, intro, details, whoisHTML, "", whoisTitle, "", footerText)
	} else {
		body = buildClassicEmailBody(title, intro, details, whoisHTML, "", whoisTitle, "", footerText, supportEmail)
	}
	return sendEmail(settings.Destemail, subject, body, settings)
}

// Sends a test email to verify the SMTP configuration.
func TestEmailHandler(c *gin.Context) {
	settings := config.GetSettings()

	lang := settings.Language
	if lang == "" {
		lang = "en"
	}
	testDetails := []emailDetail{
		{Label: getEmailTranslation(lang, "email.test.details.recipient"), Value: settings.Destemail},
		{Label: getEmailTranslation(lang, "email.test.details.smtp_host"), Value: settings.SMTP.Host},
		{Label: getEmailTranslation(lang, "email.test.details.triggered_at"), Value: time.Now().Format(time.RFC1123)},
	}

	title := getEmailTranslation(lang, "email.test.title")
	intro := getEmailTranslation(lang, "email.test.intro")
	whoisTitle := getEmailTranslation(lang, "email.ban.whois_title")
	logsTitle := getEmailTranslation(lang, "email.ban.logs_title")
	footerText := getEmailTranslation(lang, "email.footer.text")
	whoisNoData := getEmailTranslation(lang, "email.test.whois_no_data")
	supportEmail := "support@swissmakers.ch"
	emailStyle := getEmailStyle()
	isModern := emailStyle == "modern"

	whoisHTML := `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(whoisNoData) + `</pre>`
	if isModern {
		whoisHTML = `<p class="email-muted">` + html.EscapeString(whoisNoData) + `</p>`
	}

	sampleLogs := getEmailTranslation(lang, "email.test.sample_logs")
	logsHTML := formatLogsForEmail("", sampleLogs, lang, isModern)

	var testBody string
	if isModern {
		testBody = buildModernEmailBody(title, intro, testDetails, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText)
	} else {
		testBody = buildClassicEmailBody(title, intro, testDetails, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText, supportEmail)
	}

	subject := getEmailTranslation(lang, "email.test.subject")

	err := sendEmail(
		settings.Destemail,
		subject,
		testBody,
		settings,
	)
	if err != nil {
		log.Printf("❌ Test email failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send test email: " + err.Error()})
		return
	}
	log.Println("✅ Test email sent successfully!")
	c.JSON(http.StatusOK, gin.H{"message": "Test email sent successfully!"})
}

// Returns the SMTP auth mechanism based on authMethod ("auto", "login", "plain", "cram-md5").
func getSMTPAuth(username, password, authMethod, host string) (smtp.Auth, error) {
	if username == "" || password == "" {
		return nil, nil
	}
	authMethod = strings.ToLower(strings.TrimSpace(authMethod))
	if authMethod == "" || authMethod == "auto" {
		// Auto-detect: prefers LOGIN for Office365/Gmail, falls back to PLAIN (default)
		authMethod = "login"
	}
	switch authMethod {
	case "login":
		return LoginAuth(username, password), nil
	case "plain":
		return smtp.PlainAuth("", username, password, host), nil
	case "cram-md5":
		return smtp.CRAMMD5Auth(username, password), nil
	default:
		return nil, fmt.Errorf("unsupported auth method: %s (supported: login, plain, cram-md5)", authMethod)
	}
}

// Implements the LOGIN authentication mechanism used by Office365, Gmail, and other providers that require LOGIN instead of PLAIN
type loginAuth struct {
	username, password string
}

func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte(a.username), nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, errors.New("unexpected server challenge")
		}
	}
	return nil, nil
}

// =========================================================================
//  Auth Handlers
// =========================================================================

// Initiates the OIDC login flow or renders the login page.
func LoginHandler(c *gin.Context) {
	oidcClient := auth.GetOIDCClient()
	if oidcClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OIDC authentication is not configured"})
		return
	}
	oidcConfig := auth.GetConfig()
	if oidcConfig != nil && oidcConfig.SkipLoginPage {
		stateBytes := make([]byte, 32)
		if _, err := rand.Read(stateBytes); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state parameter"})
			return
		}
		state := base64.URLEncoding.EncodeToString(stateBytes)

		// Determine if we're using HTTPS (if not, the state cookie is not secure)
		isSecure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"

		// Stores the state in a session cookie for validation
		stateCookie := &http.Cookie{
			Name:     "oidc_state",
			Value:    state,
			Path:     "/",
			MaxAge:   600,
			HttpOnly: true,
			Secure:   isSecure,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(c.Writer, stateCookie)
		config.DebugLog("Set state cookie: %s (Secure: %v)", state, isSecure)

		// Gets the authorization URL and redirects to it
		authURL := oidcClient.GetAuthURL(state)
		c.Redirect(http.StatusFound, authURL)
		return
	}

	// Checks if this is a redirect action (triggered by clicking the login button)
	if c.Query("action") == "redirect" {
		stateBytes := make([]byte, 32)
		if _, err := rand.Read(stateBytes); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state parameter"})
			return
		}
		state := base64.URLEncoding.EncodeToString(stateBytes)

		// Determines if we're using HTTPS (if not, the state cookie is not secure)
		isSecure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"

		// Stores the state in a session cookie for validation
		stateCookie := &http.Cookie{
			Name:     "oidc_state",
			Value:    state,
			Path:     "/",
			MaxAge:   600,
			HttpOnly: true,
			Secure:   isSecure,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(c.Writer, stateCookie)
		config.DebugLog("Set state cookie: %s (Secure: %v)", state, isSecure)

		// Get authorization URL and redirect
		authURL := oidcClient.GetAuthURL(state)
		c.Redirect(http.StatusFound, authURL)
		return
	}
	renderIndexPage(c)
}

// Handles the OIDC callback, exchanging the code for a session.
func CallbackHandler(c *gin.Context) {
	oidcClient := auth.GetOIDCClient()
	if oidcClient == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "OIDC authentication is not configured"})
		return
	}
	stateCookie, err := c.Cookie("oidc_state")
	if err != nil {
		config.DebugLog("Failed to get state cookie: %v", err)
		config.DebugLog("Request cookies: %v", c.Request.Cookies())
		config.DebugLog("Request URL: %s", c.Request.URL.String())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing state parameter", "details": err.Error()})
		return
	}
	isSecure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "oidc_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})
	returnedState := c.Query("state")
	if returnedState != stateCookie {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}
	code := c.Query("code")
	if code == "" {
		errorDesc := c.Query("error_description")
		if errorDesc != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "OIDC authentication failed: " + errorDesc})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing authorization code"})
		}
		return
	}
	token, err := oidcClient.ExchangeCode(c.Request.Context(), code)
	if err != nil {
		config.DebugLog("Failed to exchange code for token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange authorization code"})
		return
	}
	userInfo, err := oidcClient.VerifyToken(c.Request.Context(), token)
	if err != nil {
		config.DebugLog("Failed to verify token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify authentication token"})
		return
	}
	// Create the session
	if err := auth.CreateSession(c.Writer, c.Request, userInfo, oidcClient.Config.SessionMaxAge); err != nil {
		config.DebugLog("Failed to create session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}
	config.DebugLog("User authenticated: %s (%s)", userInfo.Username, userInfo.Email)
	// Redirect to main page
	c.Redirect(http.StatusFound, "/")
}

// Clears the session and redirects to the OIDC provider logout.
func LogoutHandler(c *gin.Context) {
	oidcClient := auth.GetOIDCClient()
	// Clears the session
	auth.DeleteSession(c.Writer, c.Request)
	// If a provider logout URL is configured, redirects there
	// Otherwise, auto-constructs the logout URL for standard OIDC providers
	if oidcClient != nil {
		logoutURL := oidcClient.Config.LogoutURL
		if logoutURL == "" && oidcClient.Config.IssuerURL != "" {
			issuerURL := oidcClient.Config.IssuerURL
			redirectURI := oidcClient.Config.RedirectURL
			if strings.Contains(redirectURI, "/auth/callback") {
				redirectURI = strings.TrimSuffix(redirectURI, "/auth/callback")
			}
			redirectURI = redirectURI + "/auth/login"
			redirectURIEncoded := url.QueryEscape(redirectURI)
			clientIDEncoded := url.QueryEscape(oidcClient.Config.ClientID)

			switch oidcClient.Config.Provider {
			case "keycloak":
				// Keycloak requires client_id when using post_logout_redirect_uri
				// Format: {issuer}/protocol/openid-connect/logout?post_logout_redirect_uri={redirect}&client_id={client_id}
				logoutURL = fmt.Sprintf("%s/protocol/openid-connect/logout?post_logout_redirect_uri=%s&client_id=%s", issuerURL, redirectURIEncoded, clientIDEncoded)
			case "pocketid":
				// Pocket-ID uses a different logout endpoint (https://pocket-id.io/docs/oidc/#end-session)
				// Format: {issuer}/api/oidc/end-session?redirect_uri={redirect}
				logoutURL = fmt.Sprintf("%s/api/oidc/end-session?redirect_uri=%s", issuerURL, redirectURIEncoded)
			case "authentik":
				// OIDC format for Authentik (https://docs.goauthentik.io/docs/providers/oidc/#logout)
				// Format: {issuer}/protocol/openid-connect/logout?redirect_uri={redirect}
				logoutURL = fmt.Sprintf("%s/protocol/openid-connect/logout?redirect_uri=%s", issuerURL, redirectURIEncoded)
			default:
				logoutURL = fmt.Sprintf("%s/protocol/openid-connect/logout?redirect_uri=%s", issuerURL, redirectURIEncoded)
			}
		}
		if logoutURL != "" {
			config.DebugLog("Redirecting to provider logout: %s", logoutURL)
			c.Redirect(http.StatusFound, logoutURL)
			return
		}
	}
	c.Redirect(http.StatusFound, "/auth/login")
}

// Returns the current authentication status as JSON.
func AuthStatusHandler(c *gin.Context) {
	if !auth.IsEnabled() {
		c.JSON(http.StatusOK, gin.H{
			"enabled":       false,
			"authenticated": false,
		})
		return
	}

	oidcConfig := auth.GetConfig()
	skipLoginPage := false
	if oidcConfig != nil {
		skipLoginPage = oidcConfig.SkipLoginPage
	}

	session, err := auth.GetSession(c.Request)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled":       true,
			"authenticated": false,
			"skipLoginPage": skipLoginPage,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled":       true,
		"authenticated": true,
		"skipLoginPage": skipLoginPage,
		"user": gin.H{
			"id":       session.UserID,
			"email":    session.Email,
			"name":     session.Name,
			"username": session.Username,
		},
	})
}

// Returns the authenticated user's profile information.
func UserInfoHandler(c *gin.Context) {
	if !auth.IsEnabled() {
		c.JSON(http.StatusOK, gin.H{"authenticated": false})
		return
	}

	session, err := auth.GetSession(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"user": gin.H{
			"id":       session.UserID,
			"email":    session.Email,
			"name":     session.Name,
			"username": session.Username,
		},
	})
}
