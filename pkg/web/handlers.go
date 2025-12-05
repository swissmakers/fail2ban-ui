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
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
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
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// SummaryResponse is what we return from /api/summary
type SummaryResponse struct {
	Jails []fail2ban.JailInfo `json:"jails"`
}

type emailDetail struct {
	Label string
	Value string
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

	// Ensure jail.local structure is properly initialized for newly enabled/added servers
	if justEnabled || !wasEnabled {
		conn, err := fail2ban.GetManager().Connector(server.ID)
		if err == nil {
			if err := conn.EnsureJailLocalStructure(c.Request.Context()); err != nil {
				config.DebugLog("Warning: failed to ensure jail.local structure for server %s: %v", server.Name, err)
				// Don't fail the request, just log the warning
			} else {
				config.DebugLog("Successfully ensured jail.local structure for server %s", server.Name)
			}
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

	evaluateAdvancedActions(ctx, settings, server, ip)

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

// GetJailFilterConfigHandler returns both the filter config and jail config for a given jail
func GetJailFilterConfigHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("GetJailFilterConfigHandler called (handlers.go)") // entry point
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
	var jailCfg string
	var jailCfgLoaded bool
	var filterErr error

	// First, try to load filter config using jail name
	config.DebugLog("Loading filter config for jail: %s", jail)
	filterCfg, filterErr = conn.GetFilterConfig(c.Request.Context(), jail)
	if filterErr != nil {
		config.DebugLog("Failed to load filter config with jail name, trying to find filter from jail config: %v", filterErr)

		// Load jail config first to check for custom filter directive
		var jailErr error
		jailCfg, jailErr = conn.GetJailConfig(c.Request.Context(), jail)
		if jailErr != nil {
			config.DebugLog("Failed to load jail config: %v", jailErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load filter config: " + filterErr.Error() + ". Also failed to load jail config: " + jailErr.Error()})
			return
		}
		jailCfgLoaded = true
		config.DebugLog("Jail config loaded, length: %d", len(jailCfg))

		// Extract filter name from jail config
		filterName := fail2ban.ExtractFilterFromJailConfig(jailCfg)
		if filterName == "" {
			config.DebugLog("No filter directive found in jail config")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load filter config: " + filterErr.Error() + ". No filter directive found in jail config."})
			return
		}

		config.DebugLog("Found filter directive in jail config: %s, trying to load that filter", filterName)
		// Try loading the filter specified in jail config
		filterCfg, filterErr = conn.GetFilterConfig(c.Request.Context(), filterName)
		if filterErr != nil {
			config.DebugLog("Failed to load filter config for %s: %v", filterName, filterErr)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to load filter config. Tried '%s' (jail name) and '%s' (from jail config), both failed. Last error: %v", jail, filterName, filterErr),
			})
			return
		}
		config.DebugLog("Successfully loaded filter config for %s (from jail config directive)", filterName)
	}
	config.DebugLog("Filter config loaded, length: %d", len(filterCfg))

	// Load jail config if not already loaded
	if !jailCfgLoaded {
		config.DebugLog("Loading jail config for jail: %s", jail)
		var jailErr error
		jailCfg, jailErr = conn.GetJailConfig(c.Request.Context(), jail)
		if jailErr != nil {
			config.DebugLog("Failed to load jail config: %v", jailErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load jail config: " + jailErr.Error()})
			return
		}
		config.DebugLog("Jail config loaded, length: %d", len(jailCfg))
	}

	c.JSON(http.StatusOK, gin.H{
		"jail":       jail,
		"filter":     filterCfg,
		"jailConfig": jailCfg,
	})
}

// SetJailFilterConfigHandler overwrites both the filter config and jail config with new content
func SetJailFilterConfigHandler(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			config.DebugLog("PANIC in SetJailFilterConfigHandler: %v", r)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Internal server error: %v", r)})
		}
	}()

	config.DebugLog("----------------------------")
	config.DebugLog("SetJailFilterConfigHandler called (handlers.go)") // entry point
	jail := c.Param("jail")
	config.DebugLog("Jail name: %s", jail)

	conn, err := resolveConnector(c)
	if err != nil {
		config.DebugLog("Failed to resolve connector: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	config.DebugLog("Connector resolved: %s (type: %s)", conn.Server().Name, conn.Server().Type)

	// Parse JSON body (containing both filter and jail content)
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

	// Save filter config
	if req.Filter != "" {
		config.DebugLog("Saving filter config for jail: %s", jail)
		if err := conn.SetFilterConfig(c.Request.Context(), jail, req.Filter); err != nil {
			config.DebugLog("Failed to save filter config: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save filter config: " + err.Error()})
			return
		}
		config.DebugLog("Filter config saved successfully")
	} else {
		config.DebugLog("No filter config provided, skipping")
	}

	// Save jail config
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

	// Reload fail2ban
	config.DebugLog("Reloading fail2ban")
	if err := conn.Reload(c.Request.Context()); err != nil {
		config.DebugLog("Failed to reload fail2ban: %v", err)
		// Still return success but warn about reload failure
		// The config was saved successfully, user can manually reload
		c.JSON(http.StatusOK, gin.H{
			"message": "Config saved successfully, but fail2ban reload failed",
			"warning": "Please check the fail2ban configuration and reload manually: " + err.Error(),
		})
		return
	}
	config.DebugLog("Fail2ban reloaded successfully")

	c.JSON(http.StatusOK, gin.H{"message": "Filter and jail config updated and fail2ban reloaded"})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// equalStringSlices compares two string slices for equality
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

// TestLogpathHandler tests a logpath and returns matching files
func TestLogpathHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("TestLogpathHandler called (handlers.go)") // entry point
	jail := c.Param("jail")
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get jail config to extract logpath
	jailCfg, err := conn.GetJailConfig(c.Request.Context(), jail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load jail config: " + err.Error()})
		return
	}

	// Extract logpath from jail config
	logpath := fail2ban.ExtractLogpathFromJailConfig(jailCfg)
	if logpath == "" {
		c.JSON(http.StatusOK, gin.H{"files": []string{}, "message": "No logpath configured for this jail"})
		return
	}

	// Test the logpath
	files, err := conn.TestLogpath(c.Request.Context(), logpath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to test logpath: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logpath": logpath,
		"files":   files,
	})
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

// ListPermanentBlocksHandler exposes the permanent block log.
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

// AdvancedActionsTestHandler allows manual block/unblock tests.
func AdvancedActionsTestHandler(c *gin.Context) {
	var req struct {
		Action   string `json:"action"`
		IP       string `json:"ip"`
		ServerID string `json:"serverId"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if req.IP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
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
	server := config.Fail2banServer{}
	if req.ServerID != "" {
		if srv, ok := config.GetServerByID(req.ServerID); ok {
			server = srv
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "server not found"})
			return
		}
	}

	// Check if IP is already blocked before attempting action (for block action only)
	skipLoggingIfAlreadyBlocked := false
	if action == "block" && settings.AdvancedActions.Integration != "" {
		active, checkErr := storage.IsPermanentBlockActive(c.Request.Context(), req.IP, settings.AdvancedActions.Integration)
		if checkErr == nil && active {
			// IP is already blocked, we'll check the error message after the call
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
		// Check if error indicates IP is already blocked - show as info instead of error
		if skipLoggingIfAlreadyBlocked {
			errMsg := strings.ToLower(err.Error())
			if strings.Contains(errMsg, "already have such entry") ||
				strings.Contains(errMsg, "already exists") ||
				strings.Contains(errMsg, "duplicate") {
				// IP is already blocked, return info message with original error
				c.JSON(http.StatusOK, gin.H{"message": err.Error(), "info": true})
				return
			}
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Action %s completed for %s", action, req.IP)})
}

// UpdateJailManagementHandler updates the enabled state for each jail.
// Expected JSON format: { "JailName1": true, "JailName2": false, ... }
// After updating, fail2ban is reloaded to apply the changes.
func UpdateJailManagementHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("UpdateJailManagementHandler called (handlers.go)") // entry point
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
	// Update jail configuration file(s) with the new enabled states.
	if err := conn.UpdateJailEnabledStates(c.Request.Context(), updates); err != nil {
		config.DebugLog("Error updating jail enabled states: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update jail settings: " + err.Error()})
		return
	}
	config.DebugLog("Successfully updated jail enabled states")
	// Reload fail2ban to apply the changes (reload is sufficient for jail enable/disable)
	if err := conn.Reload(c.Request.Context()); err != nil {
		config.DebugLog("Warning: failed to reload fail2ban after updating jail settings: %v", err)
		// Still return success but warn about reload failure
		c.JSON(http.StatusOK, gin.H{
			"message": "Jail settings updated successfully, but fail2ban reload failed",
			"warning": "Please reload fail2ban manually: " + err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Jail settings updated and fail2ban reloaded successfully"})
}

// GetSettingsHandler returns the entire AppSettings struct as JSON
func GetSettingsHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("GetSettingsHandler called (handlers.go)") // entry point
	s := config.GetSettings()

	// Check if PORT environment variable is set
	envPort, envPortSet := config.GetPortFromEnv()

	// Create response with PORT env info
	response := make(map[string]interface{})
	responseBytes, _ := json.Marshal(s)
	json.Unmarshal(responseBytes, &response)

	// Add PORT environment variable information
	response["portFromEnv"] = envPort
	response["portEnvSet"] = envPortSet

	// If PORT env is set, override the port value in response
	if envPortSet {
		response["port"] = envPort
	}

	c.JSON(http.StatusOK, response)
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

	// Check if PORT environment variable is set - if so, ignore port changes from request
	envPort, envPortSet := config.GetPortFromEnv()
	if envPortSet {
		// Don't allow port changes when PORT env is set
		req.Port = envPort
	}

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

	// Check if Fail2Ban DEFAULT settings changed and push to all enabled servers
	// Compare IgnoreIPs arrays
	ignoreIPsChanged := !equalStringSlices(oldSettings.IgnoreIPs, newSettings.IgnoreIPs)
	defaultSettingsChanged := oldSettings.BantimeIncrement != newSettings.BantimeIncrement ||
		ignoreIPsChanged ||
		oldSettings.Bantime != newSettings.Bantime ||
		oldSettings.Findtime != newSettings.Findtime ||
		oldSettings.Maxretry != newSettings.Maxretry ||
		oldSettings.Destemail != newSettings.Destemail ||
		oldSettings.Banaction != newSettings.Banaction ||
		oldSettings.BanactionAllports != newSettings.BanactionAllports

	if defaultSettingsChanged {
		config.DebugLog("Fail2Ban DEFAULT settings changed, pushing to all enabled servers")
		connectors := fail2ban.GetManager().Connectors()
		var errors []string
		for _, conn := range connectors {
			server := conn.Server()
			config.DebugLog("Updating DEFAULT settings on server: %s (type: %s)", server.Name, server.Type)
			if err := conn.UpdateDefaultSettings(c.Request.Context(), newSettings); err != nil {
				errorMsg := fmt.Sprintf("Failed to update DEFAULT settings on %s: %v", server.Name, err)
				config.DebugLog("Error: %s", errorMsg)
				errors = append(errors, errorMsg)
			} else {
				config.DebugLog("Successfully updated DEFAULT settings on %s", server.Name)
				// Reload fail2ban to apply the changes
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
			// Don't fail the request, but include warnings in response
			c.JSON(http.StatusOK, gin.H{
				"message":       "Settings updated",
				"restartNeeded": false, // We reloaded, so no restart needed
				"warnings":      errors,
			})
			return
		}
		// Settings were updated and reloaded successfully, no restart needed
		c.JSON(http.StatusOK, gin.H{
			"message":       "Settings updated and fail2ban reloaded",
			"restartNeeded": false, // We reloaded, so no restart needed
		})
		return
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

	output, err := conn.TestFilter(c.Request.Context(), req.FilterName, req.LogLines)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to test filter: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"output": output})
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
		fmt.Sprintf("ignoreip = %s", strings.Join(s.IgnoreIPs, " ")),
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
	config.DebugLog("RestartFail2banHandler called (handlers.go)") // entry point

	// Check if serverId is provided in query parameter
	serverID := c.Query("serverId")
	var conn fail2ban.Connector
	var err error

	if serverID != "" {
		// Use specific server
		manager := fail2ban.GetManager()
		conn, err = manager.Connector(serverID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Server not found: " + err.Error()})
			return
		}
	} else {
		// Use default connector from context
		conn, err = resolveConnector(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
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

// loadLocale loads a locale JSON file and returns a map of translations
func loadLocale(lang string) (map[string]string, error) {
	localeCacheLock.RLock()
	if cached, ok := localeCache[lang]; ok {
		localeCacheLock.RUnlock()
		return cached, nil
	}
	localeCacheLock.RUnlock()

	// Determine locale file path
	var localePath string
	_, container := os.LookupEnv("CONTAINER")
	if container {
		localePath = fmt.Sprintf("/app/locales/%s.json", lang)
	} else {
		localePath = fmt.Sprintf("./internal/locales/%s.json", lang)
	}

	// Read locale file
	data, err := os.ReadFile(localePath)
	if err != nil {
		// Fallback to English if locale file not found
		if lang != "en" {
			return loadLocale("en")
		}
		return nil, fmt.Errorf("failed to read locale file: %w", err)
	}

	var translations map[string]string
	if err := json.Unmarshal(data, &translations); err != nil {
		return nil, fmt.Errorf("failed to parse locale file: %w", err)
	}

	// Cache the translations
	localeCacheLock.Lock()
	localeCache[lang] = translations
	localeCacheLock.Unlock()

	return translations, nil
}

// getEmailTranslation gets a translation key from the locale, with fallback to English
func getEmailTranslation(lang, key string) string {
	translations, err := loadLocale(lang)
	if err != nil {
		// Try English as fallback
		if lang != "en" {
			translations, err = loadLocale("en")
			if err != nil {
				return key // Return key if all else fails
			}
		} else {
			return key
		}
	}

	if translation, ok := translations[key]; ok {
		return translation
	}

	// Fallback to English if key not found
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

// getEmailStyle returns the email style from environment variable, defaulting to "modern"
func getEmailStyle() string {
	style := os.Getenv("emailStyle")
	if style == "classic" {
		return "classic"
	}
	return "modern"
}

// isLOTRModeActive checks if LOTR mode is enabled in alert countries
func isLOTRModeActive(alertCountries []string) bool {
	if len(alertCountries) == 0 {
		return false
	}
	for _, country := range alertCountries {
		if strings.EqualFold(country, "LOTR") {
			return true
		}
	}
	return false
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

// renderClassicEmailDetails creates paragraph-based details for classic email template
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

// buildClassicEmailBody creates the classic email template (original design with multilingual support)
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
    .label { font-weight: bold; color: #333; }
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

// buildLOTREmailBody creates the dramatic LOTR-themed email template with "You Shall Not Pass" styling
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

// buildModernEmailBody creates the modern responsive email template (new design)
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
    .email-header { background:linear-gradient(135deg,#004cff 0%%,#6c2bd9 100%%); color:#ffffff; padding:32px 28px; text-align:center; }
    .email-header-brand { margin:0 0 8px; font-size:11px; letter-spacing:0.3em; text-transform:uppercase; opacity:0.9; font-weight:600; }
    .email-header-title { margin:0 0 10px; font-size:26px; font-weight:700; line-height:1.2; }
    .email-body { padding:36px 28px; }
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
      .email-header { padding:24px 20px; }
      .email-header-title { font-size:22px; }
      .email-body { padding:28px 20px; }
      .email-intro { font-size:15px; }
      .email-details-wrapper { padding:16px; }
      .email-details-wrapper p { font-size:14px; margin:10px 0; }
      .email-footer { padding:20px 16px; }
    }
    @media only screen and (max-width:480px) {
      .email-header-title { font-size:20px; }
      .email-body { padding:24px 16px; }
      .email-details-wrapper { padding:12px; }
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

func formatWhoisForEmail(whois string, lang string, isModern bool) string {
	noDataMsg := getEmailTranslation(lang, "email.whois.no_data")
	if strings.TrimSpace(whois) == "" {
		if isModern {
			return `<p class="email-muted">` + html.EscapeString(noDataMsg) + `</p>`
		}
		return `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(noDataMsg) + `</pre>`
	}
	// Use <pre> to preserve all whitespace and newlines exactly as they are
	if isModern {
		return `<pre class="email-terminal">` + html.EscapeString(whois) + `</pre>`
	}
	return `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(whois) + `</pre>`
}

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

	// Classic format: simple pre tag
	return `<pre style="background: #222; color: #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap;">` + html.EscapeString(logs) + `</pre>`
}

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

// *******************************************************************
// *                      sendBanAlert Function :                    *
// *******************************************************************
func sendBanAlert(ip, jail, hostname, failures, whois, logs, country string, settings config.AppSettings) error {
	lang := settings.Language
	if lang == "" {
		lang = "en"
	}

	// Check if LOTR mode is active for subject line
	isLOTRMode := isLOTRModeActive(settings.AlertCountries)

	// Get translations
	var subject string
	if isLOTRMode {
		subject = fmt.Sprintf("[Middle-earth] The Dark Lord's Servant Has Been Banished: %s from %s", ip, hostname)
	} else {
		subject = fmt.Sprintf("[Fail2Ban] %s: %s %s %s %s", jail,
			getEmailTranslation(lang, "email.ban.subject.banned"),
			ip,
			getEmailTranslation(lang, "email.ban.subject.from"),
			hostname)
	}

	// Determine email style and LOTR mode
	emailStyle := getEmailStyle()
	isModern := emailStyle == "modern"

	// Get translations - use LOTR translations if in LOTR mode
	var title, intro, whoisTitle, logsTitle, footerText string
	if isLOTRMode {
		title = getEmailTranslation(lang, "lotr.email.title")
		if title == "lotr.email.title" {
			title = "A Dark Servant Has Been Banished"
		}
		intro = getEmailTranslation(lang, "lotr.email.intro")
		if intro == "lotr.email.intro" {
			intro = "The guardians of Middle-earth have detected a threat and banished it from the realm."
		}
		whoisTitle = getEmailTranslation(lang, "email.ban.whois_title")
		logsTitle = getEmailTranslation(lang, "email.ban.logs_title")
		footerText = getEmailTranslation(lang, "lotr.email.footer")
		if footerText == "lotr.email.footer" {
			footerText = "May the servers be protected. One ban to rule them all."
		}
	} else {
		title = getEmailTranslation(lang, "email.ban.title")
		intro = getEmailTranslation(lang, "email.ban.intro")
		whoisTitle = getEmailTranslation(lang, "email.ban.whois_title")
		logsTitle = getEmailTranslation(lang, "email.ban.logs_title")
		footerText = getEmailTranslation(lang, "email.footer.text")
	}
	supportEmail := "support@swissmakers.ch"

	// Format details with LOTR terminology if in LOTR mode
	var details []emailDetail
	if isLOTRMode {
		// Transform labels to LOTR terminology
		bannedIPLabel := getEmailTranslation(lang, "lotr.email.details.dark_servant_location")
		if bannedIPLabel == "lotr.email.details.dark_servant_location" {
			bannedIPLabel = "The Dark Servant's Location"
		}
		jailLabel := getEmailTranslation(lang, "lotr.email.details.realm_protection")
		if jailLabel == "lotr.email.details.realm_protection" {
			jailLabel = "The Realm of Protection"
		}
		countryLabelKey := getEmailTranslation(lang, "lotr.email.details.origins")
		var countryLabel string
		if countryLabelKey == "lotr.email.details.origins" {
			// Use default English format
			if country != "" {
				countryLabel = fmt.Sprintf("Origins from the %s Lands", country)
			} else {
				countryLabel = "Origins from Unknown Lands"
			}
		} else {
			// Use translated label and append country
			if country != "" {
				countryLabel = fmt.Sprintf("%s %s", countryLabelKey, country)
			} else {
				countryLabel = fmt.Sprintf("%s Unknown", countryLabelKey)
			}
		}
		timestampLabel := getEmailTranslation(lang, "lotr.email.details.banished_at")
		if timestampLabel == "lotr.email.details.banished_at" {
			timestampLabel = "Banished at the"
		}

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
		// Use LOTR-themed email template
		body = buildLOTREmailBody(title, intro, details, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText)
	} else if isModern {
		body = buildModernEmailBody(title, intro, details, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText)
	} else {
		body = buildClassicEmailBody(title, intro, details, whoisHTML, logsHTML, whoisTitle, logsTitle, footerText, supportEmail)
	}

	return sendEmail(settings.Destemail, subject, body, settings)
}

// *******************************************************************
// *               TestEmailHandler to send test-mail :              *
// *******************************************************************
func TestEmailHandler(c *gin.Context) {
	settings := config.GetSettings()

	lang := settings.Language
	if lang == "" {
		lang = "en"
	}

	// Get translations
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

	// Determine email style
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
