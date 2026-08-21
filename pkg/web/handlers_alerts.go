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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oschwald/maxminddb-golang"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/enrichment"
	"github.com/swissmakers/fail2ban-ui/internal/httpx"
	"github.com/swissmakers/fail2ban-ui/internal/integrations"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// =========================================================================
//  Notification Processing (Internal)
// =========================================================================

// Resolves the country via the configured GeoIP provider
func resolveCountry(ip, providedCountry string, settings config.AppSettings) string {
	if providedCountry != "" {
		return providedCountry
	}
	if settings.GeoIPProvider == "builtin" {
		return ""
	}
	country, err := lookupCountry(ip, settings.GeoIPProvider, settings.GeoIPDatabasePath)
	if err != nil {
		log.Printf("WARNING: GeoIP lookup failed for IP %s: %v", ip, err)
		return ""
	}
	return country
}

func HandleBanNotification(ctx context.Context, server config.Fail2banServer, ip, jail, hostname, failures, whois, logs string) error {
	jail = sanitizeHeaderValue(jail)
	hostname = sanitizeHeaderValue(hostname)
	failures = sanitizeHeaderValue(failures)
	settings := config.GetSettings()
	country := resolveCountry(ip, "", settings)
	filteredLogs := filterRelevantLogs(logs, ip, settings.MaxLogLines)
	event := storage.BanEventRecord{
		ServerID:   server.ID,
		ServerName: server.Name,
		Jail:       jail,
		IP:         ip,
		Country:    country,
		Hostname:   hostname,
		Failures:   failures,
		Whois:      whois,
		Logs:       filteredLogs,
		EventType:  "ban",
		OccurredAt: time.Now().UTC(),
	}
	eventID, err := storage.RecordBanEvent(ctx, event)
	if err != nil {
		log.Printf("WARNING: Failed to record ban event: %v", err)
	}
	event.ID = eventID

	// Broadcasts the ban event to WebSocket clients
	if wsHub != nil {
		wsHub.BroadcastBanEvent(event)
	}

	evaluateAdvancedActions(ctx, settings, server, ip)

	enrichAndAlertAsync(eventID, "ban", ip, jail, hostname, failures, filteredLogs, whois, country, settings)
	return nil
}

// Records an unban event, broadcasts it via WebSocket, and sends an email alert if enabled.
func HandleUnbanNotification(ctx context.Context, server config.Fail2banServer, ip, jail, hostname, whois, country string) error {
	jail = sanitizeHeaderValue(jail)
	hostname = sanitizeHeaderValue(hostname)
	settings := config.GetSettings()
	if country == "" || whois == "" {
		if storedCountry, storedWhois, err := storage.LatestBanEnrichmentForIP(ctx, ip); err == nil {
			if country == "" {
				country = storedCountry
			}
			if whois == "" {
				whois = storedWhois
			}
		} else {
			log.Printf("WARNING: failed to look up stored enrichment for IP %s: %v", ip, err)
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
		Whois:      whois,
		Logs:       "",
		EventType:  "unban",
		OccurredAt: time.Now().UTC(),
	}
	eventID, err := storage.RecordBanEvent(ctx, event)
	if err != nil {
		log.Printf("WARNING: Failed to record unban event: %v", err)
	}
	event.ID = eventID

	// Broadcasts the unban event to WebSocket clients
	if wsHub != nil {
		wsHub.BroadcastUnbanEvent(event)
	}

	enrichAndAlertAsync(eventID, "unban", ip, jail, hostname, "", "", whois, country, settings)
	return nil
}

// =========================================================================
//  Alert Dispatch
// =========================================================================

// Completes whois enrichment and dispatches alerts in the background
// Whois lookups can take up to 10 seconds and should never block the fail2ban callback response
func enrichAndAlertAsync(eventID int64, alertType, ip, jail, hostname, failures, logs, providedWhois, country string, settings config.AppSettings) {
	go func() {
		whoisData := providedWhois
		if whoisData == "" {
			log.Printf("Performing whois lookup for IP %s", ip)
			data, err := lookupWhois(ip)
			if err != nil {
				log.Printf("WARNING: Whois lookup failed for IP %s: %v", ip, err)
			} else {
				whoisData = data
			}
		}
		if country == "" {
			if resolved, err := lookupCountry(ip, settings.GeoIPProvider, settings.GeoIPDatabasePath); err == nil {
				country = resolved
			} else {
				log.Printf("WARNING: GeoIP lookup failed for IP %s: %v", ip, err)
			}
		}
		if country == "" && whoisData != "" {
			if extracted := extractCountryFromWhois(whoisData); extracted != "" {
				country = extracted
				log.Printf("Extracted country %s from whois data for IP %s", country, ip)
			}
		}
		if eventID > 0 && (whoisData != "" || country != "") {
			updateCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := storage.UpdateBanEventEnrichment(updateCtx, eventID, whoisData, country); err != nil {
				log.Printf("WARNING: Failed to store whois enrichment for event %d: %v", eventID, err)
			} else if wsHub != nil {
				if enriched, found, err := storage.GetBanEventByID(updateCtx, eventID); err == nil && found {
					enriched.Whois = ""
					enriched.Logs = ""
					wsHub.BroadcastBanEventUpdate(enriched)
				}
			}
			cancel()
		}

		displayCountry := country
		if displayCountry == "" {
			displayCountry = "UNKNOWN"
		}
		if alertType == "unban" {
			if !settings.EmailAlertsForUnbans {
				log.Printf("Alerts for unbans are disabled. No alert sent for IP %s", ip)
				return
			}
			if !shouldAlertForCountry(country, settings.AlertCountries) {
				log.Printf("IP %s belongs to %s, which is NOT in alert countries (%v). No alert sent.", ip, displayCountry, settings.AlertCountries)
				return
			}
		} else {
			if !shouldAlertForCountry(country, settings.AlertCountries) {
				log.Printf("ERROR: IP %s belongs to %s, which is NOT in alert countries (%v). No alert sent.", ip, displayCountry, settings.AlertCountries)
				return
			}
			if !settings.EmailAlertsForBans {
				log.Printf("ERROR: Alerts for bans are disabled. No alert sent for IP %s", ip)
				return
			}
		}

		if err := dispatchAlert(alertType, ip, jail, hostname, failures, whoisData, logs, country, settings); err != nil {
			log.Printf("ERROR: Failed to send %s alert for IP %s: %v", alertType, ip, err)
			if wsHub != nil {
				wsHub.BroadcastToast("error", fmt.Sprintf("Failed to send %s alert for %s: %v", alertType, ip, err))
			}
		}
	}()
}

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
	if err := integrations.ValidateOutboundURL(cfg.URL, "webhook URL"); err != nil {
		return err
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

	method, ok := normalizeWebhookMethod(cfg.Method)
	if !ok {
		// Stored settings predating method validation fall back to POST.
		method = "POST"
	}

	req, err := http.NewRequest(method, cfg.URL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range cfg.Headers {
		key := strings.TrimSpace(k)
		if key == "" || !headerNameRe.MatchString(key) {
			continue
		}
		req.Header.Set(key, sanitizeHeaderValue(v))
	}

	client := httpx.Client(15*time.Second, cfg.SkipTLSVerify)

	_, status, err := httpx.DoChecked(client, req, "webhook")
	if err != nil {
		return err
	}

	log.Printf("Webhook alert sent: %s %s -> %d", method, cfg.URL, status)
	return nil
}

// Sends a document to the configured Elasticsearch index.
func sendElasticsearchAlert(alertType, ip, jail, hostname, failures, whois, logs, country string, settings config.AppSettings) error {
	cfg := settings.Elasticsearch
	if err := integrations.ValidateOutboundURL(cfg.URL, "elasticsearch URL"); err != nil {
		return err
	}

	index := cfg.Index
	if index == "" {
		index = "fail2ban-events"
	}
	if err := integrations.ValidateElasticsearchIndex(index); err != nil {
		return err
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

	// Parses log lines into structured ECS fields
	if logFields := enrichment.ParseLogLines(logs, jail); logFields != nil {
		for k, v := range logFields {
			doc[k] = v
		}
	}

	// Parses whois text into structured fields
	if whoisFields := enrichment.ParseWhois(whois); whoisFields != nil {
		for k, v := range whoisFields {
			doc[k] = v
		}
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal elasticsearch document: %w", err)
	}

	base, err := url.Parse(cfg.URL)
	if err != nil {
		return fmt.Errorf("invalid elasticsearch URL: %w", err)
	}
	// JoinPath percent-escapes each segment, so the index name cannot alter the
	// request path or query even if it slipped past validation.
	reqURL := base.JoinPath(indexName, "_doc").String()

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

	client := httpx.Client(15*time.Second, cfg.SkipTLSVerify)

	_, status, err := httpx.DoChecked(client, req, "elasticsearch")
	if err != nil {
		return err
	}

	log.Printf("Elasticsearch alert indexed: %s -> %d", reqURL, status)
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

var (
	geoIPMu   sync.Mutex
	geoIPDB   *maxminddb.Reader
	geoIPPath string
)

func getGeoIPReader(dbPath string) (*maxminddb.Reader, error) {
	geoIPMu.Lock()
	defer geoIPMu.Unlock()
	if geoIPDB != nil && geoIPPath == dbPath {
		return geoIPDB, nil
	}
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, err
	}
	if geoIPDB != nil {
		geoIPDB.Close()
	}
	geoIPDB = db
	geoIPPath = dbPath
	return db, nil
}

// Looks up the country ISO code using MaxMind GeoLite2 database.
func lookupCountryMaxMind(ip, dbPath string) (string, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	db, err := getGeoIPReader(dbPath)
	if err != nil {
		return "", fmt.Errorf("failed to open GeoIP database at %s: %w", dbPath, err)
	}

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
	// Must stay strict net.ParseIP (no CIDR): shared.ValidateIP accepts CIDR
	// and this value is interpolated into the outbound request URL.
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

	resp, err := httpx.Client(5*time.Second, false).Do(req)
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

	body, err := httpx.ReadLimited(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if result.Status == "fail" {
		return "", fmt.Errorf("ip-api.com error: %s", result.Message)
	}

	return result.CountryCode, nil
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
