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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/httpx"
)

var (
	threatIntelMu    sync.RWMutex
	threatIntelCache = make(map[string]threatIntelCacheEntry)
	threatIntelRetry = make(map[string]time.Time)
)

type threatIntelCacheEntry struct {
	Body      []byte
	CachedAt  time.Time
	ExpiresAt time.Time
}

const maxThreatIntelEntries = 1000

func pruneThreatIntelCachesLocked(now time.Time) {
	for k, entry := range threatIntelCache {
		if now.After(entry.ExpiresAt) {
			delete(threatIntelCache, k)
		}
	}
	for k, retryUntil := range threatIntelRetry {
		if now.After(retryUntil) {
			delete(threatIntelRetry, k)
		}
	}
	if len(threatIntelCache) > maxThreatIntelEntries {
		threatIntelCache = make(map[string]threatIntelCacheEntry)
	}
	if len(threatIntelRetry) > maxThreatIntelEntries {
		threatIntelRetry = make(map[string]time.Time)
	}
}

// =========================================================================
//  Threat Intelligence
// =========================================================================

// Queries threat-intel providers. -> We do it through the backend to avoid browser CORS issues.
func ThreatIntelHandler(c *gin.Context) {
	ip := strings.TrimSpace(c.Param("ip"))
	// Must stay strict net.ParseIP (no CIDR): shared.ValidateIP accepts CIDR
	// and this value is interpolated into the provider request URL.
	if net.ParseIP(ip) == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP address"})
		return
	}
	settings := config.GetSettings()
	provider := strings.ToLower(strings.TrimSpace(settings.ThreatIntel.Provider))
	if provider == "none" {
		c.JSON(http.StatusConflict, gin.H{"error": "Threat intelligence is disabled"})
		return
	}
	if provider != "alienvault" && provider != "abuseipdb" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid threat-intel provider configuration"})
		return
	}
	if provider == "alienvault" && strings.TrimSpace(settings.ThreatIntel.AlienVaultAPIKey) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing AlienVault API key in settings"})
		return
	}
	if provider == "abuseipdb" && strings.TrimSpace(settings.ThreatIntel.AbuseIPDBAPIKey) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing AbuseIPDB API key in settings"})
		return
	}

	cacheKey := provider + ":" + ip
	now := time.Now()

	threatIntelMu.RLock()
	cached, hasCached := threatIntelCache[cacheKey]
	retryUntil, hasRetry := threatIntelRetry[cacheKey]
	threatIntelMu.RUnlock()

	if hasCached && now.Before(cached.ExpiresAt) {
		c.Header("X-Threat-Intel-Cache", "hit")
		c.Header("Content-Type", "application/json")
		c.Data(http.StatusOK, "application/json", cached.Body)
		return
	}

	// Respect retry windows after upstream 429 responses.
	if hasRetry && now.Before(retryUntil) {
		if hasCached && len(cached.Body) > 0 {
			c.Header("X-Threat-Intel-Cache", "stale")
			c.Header("Content-Type", "application/json")
			c.Data(http.StatusOK, "application/json", cached.Body)
			return
		}
		secondsLeft := int(retryUntil.Sub(now).Seconds())
		if secondsLeft < 1 {
			secondsLeft = 1
		}
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":        fmt.Sprintf("Threat-intel provider rate limit reached. Please retry in %d seconds.", secondsLeft),
			"retryAfter":   secondsLeft,
			"fromUpstream": true,
		})
		return
	}
	requestURL := ""
	switch provider {
	case "alienvault":
		requestURL = "https://otx.alienvault.com/api/v1/indicators/IPv4/" + url.PathEscape(ip) + "/general"
	case "abuseipdb":
		requestURL = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + url.QueryEscape(ip) + "&maxAgeInDays=90&verbose=true"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported threat-intel provider"})
		return
	}

	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, requestURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}

	req.Header.Set("Accept", "application/json")
	switch provider {
	case "alienvault":
		req.Header.Set("X-OTX-API-KEY", strings.TrimSpace(settings.ThreatIntel.AlienVaultAPIKey))
	case "abuseipdb":
		req.Header.Set("Key", strings.TrimSpace(settings.ThreatIntel.AbuseIPDBAPIKey))
	}

	client := httpx.Client(12*time.Second, false)
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to query threat-intel provider"})
		return
	}
	defer resp.Body.Close()

	body, err := httpx.ReadLimited(resp.Body)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to read threat-intel provider response"})
		return
	}

	var parsedPayload any
	if err := json.Unmarshal(body, &parsedPayload); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid JSON from threat-intel provider"})
		return
	}

	responsePayload := gin.H{
		"provider":  provider,
		"ip":        ip,
		"fetchedAt": now.UTC().Format(time.RFC3339),
		"data":      parsedPayload,
	}
	responseBody, err := json.Marshal(responsePayload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build threat-intel response"})
		return
	}

	if resp.StatusCode == http.StatusOK {
		threatIntelMu.Lock()
		pruneThreatIntelCachesLocked(now)
		threatIntelCache[cacheKey] = threatIntelCacheEntry{
			Body:      append([]byte(nil), responseBody...),
			CachedAt:  now,
			ExpiresAt: now.Add(30 * time.Minute),
		}
		delete(threatIntelRetry, cacheKey)
		threatIntelMu.Unlock()
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		retryUntil = now.Add(parseRetryAfter(resp.Header.Get("Retry-After"), 2*time.Minute))
		threatIntelMu.Lock()
		pruneThreatIntelCachesLocked(now)
		threatIntelRetry[cacheKey] = retryUntil
		cached, hasCached = threatIntelCache[cacheKey]
		threatIntelMu.Unlock()

		if hasCached && len(cached.Body) > 0 {
			c.Header("X-Threat-Intel-Cache", "stale")
			c.Header("Content-Type", "application/json")
			c.Data(http.StatusOK, "application/json", cached.Body)
			return
		}

		secondsLeft := int(retryUntil.Sub(now).Seconds())
		if secondsLeft < 1 {
			secondsLeft = 1
		}
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":        fmt.Sprintf("Threat-intel provider rate limit reached. Please retry in %d seconds.", secondsLeft),
			"retryAfter":   secondsLeft,
			"fromUpstream": true,
		})
		return
	}

	c.Data(resp.StatusCode, "application/json", responseBody)
}

func parseRetryAfter(value string, fallback time.Duration) time.Duration {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	if secs, err := strconv.Atoi(trimmed); err == nil {
		if secs < 1 {
			secs = 1
		}
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(trimmed); err == nil {
		d := time.Until(at)
		if d < time.Second {
			return time.Second
		}
		return d
	}
	return fallback
}
