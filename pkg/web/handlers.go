// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2025 Swissmakers GmbH (https://swissmakers.ch)
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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/oschwald/maxminddb-golang"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// SummaryResponse is what we return from /api/summary
type SummaryResponse struct {
	Jails []fail2ban.JailInfo `json:"jails"`
}

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

// SummaryHandler returns a JSON summary of all jails, including
// number of banned IPs, how many are new in the last hour, etc.
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
	c.JSON(http.StatusOK, resp)
}

// UnbanIPHandler unbans a given IP in a specific jail.
func UnbanIPHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("UnbanIPHandler called (handlers.go)") // entry point
	jail := c.Param("jail")
	ip := c.Param("ip")

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

// BanNotificationHandler processes incoming ban notifications from Fail2Ban.
func BanNotificationHandler(c *gin.Context) {
	var request struct {
		ServerID string `json:"serverId"`
		IP       string `json:"ip" binding:"required"`
		Jail     string `json:"jail" binding:"required"`
		Hostname string `json:"hostname"`
		Failures string `json:"failures"`
		Whois    string `json:"whois"`
		Logs     string `json:"logs"`
	}

	// **DEBUGGING: Log Raw JSON Body**
	body, _ := io.ReadAll(c.Request.Body)
	log.Printf("----------------------------------------------------")
	log.Printf("Request Content-Length: %d", c.Request.ContentLength)
	log.Printf("Request Headers: %v", c.Request.Header)
	log.Printf("Request Headers: %v", c.Request.Body)

	log.Printf("----------------------------------------------------")

	config.DebugLog("📩 Incoming Ban Notification: %s\n", string(body))

	// Rebind body so Gin can parse it again (important!)
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	log.Printf("Request Content-Length: %d", c.Request.ContentLength)
	log.Printf("Request Headers: %v", c.Request.Header)
	log.Printf("Request Headers: %v", c.Request.Body)

	// Parse JSON request body
	if err := c.ShouldBindJSON(&request); err != nil {
		var verr validator.ValidationErrors
		if errors.As(err, &verr) {
			for _, fe := range verr {
				log.Printf("❌ Validierungsfehler: Feld '%s' verletzt Regel '%s'", fe.Field(), fe.ActualTag())
			}
		} else {
			log.Printf("❌ JSON-Parsing Fehler: %v", err)
		}
		log.Printf("Raw JSON: %s", string(body))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// **DEBUGGING: Log Parsed Request**
	log.Printf("✅ Parsed Ban Request - IP: %s, Jail: %s, Hostname: %s, Failures: %s",
		request.IP, request.Jail, request.Hostname, request.Failures)

	server, err := resolveServerForNotification(request.ServerID, request.Hostname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Handle the Fail2Ban notification
	if err := HandleBanNotification(c.Request.Context(), server, request.IP, request.Jail, request.Hostname, request.Failures, request.Whois, request.Logs); err != nil {
		log.Printf("❌ Failed to process ban notification: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process ban notification: " + err.Error()})
		return
	}

	// Respond with success
	c.JSON(http.StatusOK, gin.H{"message": "Ban notification processed successfully"})
}

// ListBanEventsHandler returns stored ban events from the internal database.
func ListBanEventsHandler(c *gin.Context) {
	serverID := c.Query("serverId")
	limit := 100
	if limitStr := c.DefaultQuery("limit", "100"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	var since time.Time
	if sinceStr := c.Query("since"); sinceStr != "" {
		if parsed, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = parsed
		}
	}

	events, err := storage.ListBanEvents(c.Request.Context(), serverID, limit, since)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}

// BanStatisticsHandler returns aggregated ban counts per server.
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

// BanInsightsHandler returns aggregate stats for countries and recurring IPs.
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	recurring, err := storage.ListRecurringIPStats(ctx, since, minCount, limit, serverID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

// ListServersHandler returns configured Fail2ban servers.
func ListServersHandler(c *gin.Context) {
	servers := config.ListServers()
	c.JSON(http.StatusOK, gin.H{"servers": servers})
}

// UpsertServerHandler creates or updates a Fail2ban server configuration.
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

	// Only update action files if:
	// 1. Server was just enabled (transition from disabled to enabled)
	// 2. Server is a remote server (SSH or Agent)
	// Note: ReloadFromSettings already calls ensureAction when creating connectors,
	// but we need to update if the server was just enabled to ensure it has the latest callback URL
	if justEnabled && (server.Type == "ssh" || server.Type == "agent") {
		if err := fail2ban.GetManager().UpdateActionFileForServer(c.Request.Context(), server.ID); err != nil {
			config.DebugLog("Warning: failed to update action file for server %s: %v", server.Name, err)
			// Don't fail the request, just log the warning
		}
	}

	c.JSON(http.StatusOK, gin.H{"server": server})
}

// DeleteServerHandler removes a server configuration.
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

// SetDefaultServerHandler marks a server as default.
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

// ListSSHKeysHandler returns SSH keys available on the UI host.
func ListSSHKeysHandler(c *gin.Context) {
	var dir string
	// Check if running inside a container
	if _, container := os.LookupEnv("CONTAINER"); container {
		// In container, check /config/.ssh
		dir = "/config/.ssh"
	} else {
		// On host, check ~/.ssh
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
		if strings.HasPrefix(name, "id_") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") {
			keys = append(keys, filepath.Join(dir, name))
		}
	}
	if len(keys) == 0 {
		c.JSON(http.StatusOK, gin.H{"keys": []string{}, "messageKey": "servers.form.no_keys"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

// TestServerHandler verifies connectivity to a configured Fail2ban server.
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

	c.JSON(http.StatusOK, gin.H{"messageKey": "servers.actions.test_success"})
}

// HandleBanNotification processes Fail2Ban notifications, checks geo-location, stores the event, and sends alerts.
func HandleBanNotification(ctx context.Context, server config.Fail2banServer, ip, jail, hostname, failures, whois, logs string) error {
	// Load settings to get alert countries
	settings := config.GetSettings()

	// Lookup the country for the given IP
	country, err := lookupCountry(ip)
	if err != nil {
		log.Printf("⚠️ GeoIP lookup failed for IP %s: %v", ip, err)
		country = ""
	}

	event := storage.BanEventRecord{
		ServerID:   server.ID,
		ServerName: server.Name,
		Jail:       jail,
		IP:         ip,
		Country:    country,
		Hostname:   hostname,
		Failures:   failures,
		Whois:      whois,
		Logs:       logs,
		OccurredAt: time.Now().UTC(),
	}
	if err := storage.RecordBanEvent(ctx, event); err != nil {
		log.Printf("⚠️ Failed to record ban event: %v", err)
	}

	// Check if country is in alert list
	displayCountry := country
	if displayCountry == "" {
		displayCountry = "UNKNOWN"
	}

	if !shouldAlertForCountry(country, settings.AlertCountries) {
		log.Printf("❌ IP %s belongs to %s, which is NOT in alert countries (%v). No alert sent.", ip, displayCountry, settings.AlertCountries)
		return nil
	}

	// Send email notification
	if err := sendBanAlert(ip, jail, hostname, failures, whois, logs, country, settings); err != nil {
		log.Printf("❌ Failed to send alert email: %v", err)
		return err
	}

	log.Printf("✅ Email alert sent for banned IP %s (%s)", ip, displayCountry)
	return nil
}

// lookupCountry finds the country ISO code for a given IP using MaxMind GeoLite2 database.
func lookupCountry(ip string) (string, error) {
	// Convert the IP string to net.IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	// Open the GeoIP database
	db, err := maxminddb.Open("/usr/share/GeoIP/GeoLite2-Country.mmdb")
	if err != nil {
		return "", fmt.Errorf("failed to open GeoIP database: %w", err)
	}
	defer db.Close()

	// Define the structure to store the lookup result
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}

	// Perform the lookup using net.IP type
	if err := db.Lookup(parsedIP, &record); err != nil {
		return "", fmt.Errorf("GeoIP lookup error: %w", err)
	}

	// Return the country code
	return record.Country.ISOCode, nil
}

// shouldAlertForCountry checks if an IP’s country is in the allowed alert list.
func shouldAlertForCountry(country string, alertCountries []string) bool {
	if len(alertCountries) == 0 || strings.Contains(strings.Join(alertCountries, ","), "ALL") {
		return true // If "ALL" is selected, alert for all bans
	}
	for _, c := range alertCountries {
		if strings.EqualFold(country, c) {
			return true
		}
	}
	return false
}

// IndexHandler serves the HTML page
func IndexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"timestamp": time.Now().Format(time.RFC1123),
	})
}

// GetJailFilterConfigHandler returns the raw filter config for a given jail
func GetJailFilterConfigHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("GetJailFilterConfigHandler called (handlers.go)") // entry point
	jail := c.Param("jail")
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := conn.GetFilterConfig(c.Request.Context(), jail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"jail":   jail,
		"config": cfg,
	})
}

// SetJailFilterConfigHandler overwrites the current filter config with new content
func SetJailFilterConfigHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("SetJailFilterConfigHandler called (handlers.go)") // entry point
	jail := c.Param("jail")
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Parse JSON body (containing the new filter content)
	var req struct {
		Config string `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}

	if err := conn.SetFilterConfig(c.Request.Context(), jail, req.Config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := conn.Reload(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "filter saved but reload failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Filter updated and fail2ban reloaded"})
}

// ManageJailsHandler returns a list of all jails (from jail.local and jail.d)
// including their enabled status.
func ManageJailsHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("ManageJailsHandler called (handlers.go)") // entry point
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

// UpdateJailManagementHandler updates the enabled state for each jail.
// Expected JSON format: { "JailName1": true, "JailName2": false, ... }
// After updating, the Fail2ban service is restarted.
func UpdateJailManagementHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("UpdateJailManagementHandler called (handlers.go)") // entry point
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var updates map[string]bool
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON: " + err.Error()})
		return
	}
	// Update jail configuration file(s) with the new enabled states.
	if err := conn.UpdateJailEnabledStates(c.Request.Context(), updates); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update jail settings: " + err.Error()})
		return
	}
	if err := config.MarkRestartNeeded(conn.Server().ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Jail settings updated successfully"})
}

// GetSettingsHandler returns the entire AppSettings struct as JSON
func GetSettingsHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("GetSettingsHandler called (handlers.go)") // entry point
	s := config.GetSettings()
	c.JSON(http.StatusOK, s)
}

// UpdateSettingsHandler updates the AppSettings from a JSON body
func UpdateSettingsHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("UpdateSettingsHandler called (handlers.go)") // entry point
	var req config.AppSettings
	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Println("JSON binding error:", err) // Debug
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid JSON",
			"details": err.Error(),
		})
		return
	}
	config.DebugLog("JSON binding successful, updating settings (handlers.go)")

	oldSettings := config.GetSettings()
	newSettings, err := config.UpdateSettings(req)
	if err != nil {
		fmt.Println("Error updating settings:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	config.DebugLog("Settings updated successfully (handlers.go)")

	// Check if callback URL changed - if so, update action files for all active remote servers
	callbackURLChanged := oldSettings.CallbackURL != newSettings.CallbackURL

	if err := fail2ban.GetManager().ReloadFromSettings(config.GetSettings()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reload fail2ban connectors: " + err.Error()})
		return
	}

	// Update action files for remote servers if callback URL changed
	if callbackURLChanged {
		if err := fail2ban.GetManager().UpdateActionFiles(c.Request.Context()); err != nil {
			config.DebugLog("Warning: failed to update some remote action files: %v", err)
			// Don't fail the request, just log the warning
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "Settings updated",
		"restartNeeded": newSettings.RestartNeeded,
	})
}

// ListFiltersHandler returns a JSON array of filter names
// found as *.conf in /etc/fail2ban/filter.d
func ListFiltersHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("ListFiltersHandler called (handlers.go)") // entry point
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	server := conn.Server()
	if server.Type == "local" {
		// For local, check if directory exists first
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

func TestFilterHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("TestFilterHandler called (handlers.go)") // entry point
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var req struct {
		FilterName string   `json:"filterName"`
		LogLines   []string `json:"logLines"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	matches, err := conn.TestFilter(c.Request.Context(), req.FilterName, req.LogLines)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to test filter: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"matches": matches})
}

// ApplyFail2banSettings updates /etc/fail2ban/jail.local [DEFAULT] with our JSON
func ApplyFail2banSettings(jailLocalPath string) error {
	config.DebugLog("----------------------------")
	config.DebugLog("ApplyFail2banSettings called (handlers.go)") // entry point
	s := config.GetSettings()

	// open /etc/fail2ban/jail.local, parse or do a simplistic approach:
	// TODO: -> maybe we store [DEFAULT] block in memory, replace lines
	// or do a line-based approach. Example is simplistic:

	newLines := []string{
		"[DEFAULT]",
		fmt.Sprintf("bantime.increment = %t", s.BantimeIncrement),
		fmt.Sprintf("ignoreip = %s", s.IgnoreIP),
		fmt.Sprintf("bantime = %s", s.Bantime),
		fmt.Sprintf("findtime = %s", s.Findtime),
		fmt.Sprintf("maxretry = %d", s.Maxretry),
		fmt.Sprintf("destemail = %s", s.Destemail),
		//fmt.Sprintf("sender = %s", s.Sender),
		"",
	}
	content := strings.Join(newLines, "\n")

	return os.WriteFile(jailLocalPath, []byte(content), 0644)
}

// RestartFail2banHandler reloads the Fail2ban service
func RestartFail2banHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("ApplyFail2banSettings called (handlers.go)") // entry point

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	server := conn.Server()

	// Attempt to restart the fail2ban service.
	restartErr := fail2ban.RestartFail2ban(server.ID)
	if restartErr != nil {
		// Check if running inside a container.
		if _, container := os.LookupEnv("CONTAINER"); container && server.Type == "local" {
			// In a container, the restart command may fail (since fail2ban runs on the host).
			// Log the error and continue, so we can mark the restart as done.
			log.Printf("Warning: restart failed inside container (expected behavior): %v", restartErr)
		} else {
			// On the host, a restart error is not acceptable.
			c.JSON(http.StatusInternalServerError, gin.H{"error": restartErr.Error()})
			return
		}
	}

	// Only call MarkRestartDone if we either successfully restarted the service or we are in a container.
	if err := config.MarkRestartDone(server.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Fail2ban restarted successfully"})
}

// *******************************************************************
// *                 Unified Email Sending Function :                *
// *******************************************************************
func sendEmail(to, subject, body string, settings config.AppSettings) error {
	// Validate SMTP settings
	if settings.SMTP.Host == "" || settings.SMTP.Username == "" || settings.SMTP.Password == "" || settings.SMTP.From == "" {
		return errors.New("SMTP settings are incomplete. Please configure all required fields")
	}

	// Format message with **correct HTML headers**
	message := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n"+
		"MIME-Version: 1.0\nContent-Type: text/html; charset=\"UTF-8\"\n\n%s",
		settings.SMTP.From, to, subject, body)
	msg := []byte(message)

	// SMTP Connection Config
	smtpHost := settings.SMTP.Host
	smtpPort := settings.SMTP.Port
	auth := LoginAuth(settings.SMTP.Username, settings.SMTP.Password)
	smtpAddr := net.JoinHostPort(smtpHost, fmt.Sprintf("%d", smtpPort))

	// **Choose Connection Type**
	switch smtpPort {
	case 465:
		// SMTPS (Implicit TLS) - Not supported at the moment.
		tlsConfig := &tls.Config{ServerName: smtpHost}
		conn, err := tls.Dial("tcp", smtpAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect via TLS: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, smtpHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer client.Quit()

		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}

		return sendSMTPMessage(client, settings.SMTP.From, to, msg)

	case 587:
		// STARTTLS (Explicit TLS)
		conn, err := net.Dial("tcp", smtpAddr)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, smtpHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer client.Quit()

		// Start TLS Upgrade
		tlsConfig := &tls.Config{ServerName: smtpHost}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}

		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}

		return sendSMTPMessage(client, settings.SMTP.From, to, msg)
	}

	return errors.New("unsupported SMTP port. Use 587 (STARTTLS) or 465 (SMTPS)")
}

// Helper Function to Send SMTP Message
func sendSMTPMessage(client *smtp.Client, from, to string, msg []byte) error {
	// Set sender & recipient
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	// Send email body
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to start data command: %w", err)
	}
	defer wc.Close()

	if _, err = wc.Write(msg); err != nil {
		return fmt.Errorf("failed to write email content: %w", err)
	}

	// Close connection
	client.Quit()
	return nil
}

// *******************************************************************
// *                      sendBanAlert Function :                    *
// *******************************************************************
func sendBanAlert(ip, jail, hostname, failures, whois, logs, country string, settings config.AppSettings) error {
	subject := fmt.Sprintf("[Fail2Ban] %s: Banned %s from %s", jail, ip, hostname)

	// Improved Responsive HTML Email
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fail2Ban Alert</title>
<style>
    body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 20px auto; background: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0px 2px 4px rgba(0,0,0,0.1); }
    .header { text-align: center; padding-bottom: 10px; border-bottom: 2px solid #005DE0; }
    .header img { max-width: 150px; }
    .header h2 { color: #005DE0; margin: 10px 0; font-size: 24px; }
    .content { padding: 15px; }
    .details { background: #f9f9f9; padding: 15px; border-left: 4px solid #5579f8; margin-bottom: 10px; }
    .footer { text-align: center; color: #888; font-size: 12px; padding-top: 10px; border-top: 1px solid #ddd; margin-top: 15px; }
    .label { font-weight: bold; color: #333; }
    pre {
        background: #222; /* Dark terminal-like background */
        color: #ddd; /* Light text */
        font-family: "Courier New", Courier, monospace; /* Monospace font */
        font-size: 12px; /* Smaller font size */
        padding: 10px;
        border-radius: 5px;
        overflow-x: auto; /* Scroll horizontally if needed */
        white-space: pre-wrap; /* Preserve line breaks */
    }
    /* Mobile Styles */
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
        <!-- HEADER -->
        <div class="header">
            <img src="https://swissmakers.ch/wp-content/uploads/2023/09/cyber.png" alt="Swissmakers GmbH" width="150" />
            <h2>🚨 Security Alert from Fail2Ban-UI</h2>
        </div>

        <!-- ALERT MESSAGE -->
        <div class="content">
            <p>A new IP has been banned due to excessive failed login attempts.</p>

            <div class="details">
                <p><span class="label">📌 Banned IP:</span> %s</p>
                <p><span class="label">🛡️ Jail Name:</span> %s</p>
                <p><span class="label">🏠 Hostname:</span> %s</p>
                <p><span class="label">🚫 Failed Attempts:</span> %s</p>
                <p><span class="label">🌍 Country:</span> %s</p>
            </div>

            <h3>🔍 More Information about Attacker:</h3>
            <pre>%s</pre>

            <h3>📄 Server Log Entries:</h3>
            <pre>%s</pre>
        </div>

        <!-- FOOTER -->
        <div class="footer">
            <p>This email was generated automatically by Fail2Ban.</p>
            <p>For security inquiries, contact <a href="mailto:support@swissmakers.ch">support@swissmakers.ch</a></p>
            <p>&copy; %d Swissmakers GmbH. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`, ip, jail, hostname, failures, country, whois, logs, time.Now().Year())

	// Send the email
	return sendEmail(settings.Destemail, subject, body, settings)
}

// *******************************************************************
// *               TestEmailHandler to send test-mail :              *
// *******************************************************************
func TestEmailHandler(c *gin.Context) {
	settings := config.GetSettings()

	err := sendEmail(
		settings.Destemail,
		"Test Email from Fail2Ban UI",
		"This is a test email sent from the Fail2Ban UI to verify SMTP settings.",
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

// *******************************************************************
// *                 Office365 LOGIN Authentication :                *
// *******************************************************************
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
