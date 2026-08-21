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
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/integrations"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

type SummaryResponse struct {
	ServerID         string              `json:"serverId"`
	Jails            []fail2ban.JailInfo `json:"jails"`
	JailLocalWarning bool                `json:"jailLocalWarning,omitempty"`
}

// =========================================================================
//  Dashboard
// =========================================================================

const summaryBannedPreviewLimit = 5

func SummaryHandler(c *gin.Context) {
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, buildErrorResponse(err, "dashboard.errors.summary_failed"))
		return
	}

	summary, err := conn.GetJailSummary(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "dashboard.errors.summary_failed"))
		return
	}
	resp := SummaryResponse{ServerID: conn.Server().ID, Jails: summary.Jails}

	serverID := conn.Server().ID
	since := time.Now().UTC().Add(-1 * time.Hour)
	recentCounts, countErr := storage.CountRecentBanEventsByJail(c.Request.Context(), serverID, since)
	if countErr != nil {
		config.DebugLog("Warning: failed to count recent bans for server %s: %v", serverID, countErr)
	}
	for i := range resp.Jails {
		resp.Jails[i].NewInLastHour = recentCounts[resp.Jails[i].JailName]
		if len(resp.Jails[i].BannedIPs) > summaryBannedPreviewLimit {
			resp.Jails[i].BannedIPs = resp.Jails[i].BannedIPs[:summaryBannedPreviewLimit]
		}
		if resp.Jails[i].BannedIPs == nil {
			resp.Jails[i].BannedIPs = []string{}
		}
	}

	// jail.local integrity comes back with the summary itself.
	switch {
	case summary.JailLocalExists && !summary.JailLocalManaged:
		resp.JailLocalWarning = true
	case !summary.JailLocalExists:
		// The user finished a migration and removed it -> recreate a managed one.
		if err := conn.EnsureJailLocalStructure(c.Request.Context()); err != nil {
			config.DebugLog("Warning: failed to initialize jail.local on summary request: %v", err)
		} else {
			config.DebugLog("Initialized fresh jail.local for server %s (file was missing)", conn.Server().Name)
		}
	}

	c.JSON(http.StatusOK, resp)
}

// Searches all servers and jails for a live ban of the given IP via
// fail2ban-client, unlike the dashboard which only searches stored ban events.
func SearchBannedIPHandler(c *gin.Context) {
	ip := c.Param("ip")
	if err := integrations.ValidateIP(ip); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP: " + err.Error()})
		return
	}

	type jailMatch struct {
		ServerID   string `json:"serverId"`
		ServerName string `json:"serverName"`
		Jail       string `json:"jail"`
	}
	type serverError struct {
		ServerID   string `json:"serverId"`
		ServerName string `json:"serverName"`
		Error      string `json:"error"`
	}

	var (
		mu      sync.Mutex
		matches []jailMatch
		errs    []serverError
		wg      sync.WaitGroup
	)

	for _, conn := range fail2ban.GetManager().Connectors() {
		wg.Add(1)
		go func(conn fail2ban.Connector) {
			defer wg.Done()
			server := conn.Server()

			ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
			defer cancel()

			infos, err := conn.GetJailInfos(ctx)
			if err != nil {
				mu.Lock()
				errs = append(errs, serverError{ServerID: server.ID, ServerName: server.Name, Error: err.Error()})
				mu.Unlock()
				return
			}
			for _, info := range infos {
				if info.TotalBanned == 0 {
					continue
				}
				banned := info.BannedIPs
				if len(banned) == 0 {
					banned, err = conn.GetBannedIPs(ctx, info.JailName)
					if err != nil {
						continue
					}
				}
				if slices.Contains(banned, ip) {
					mu.Lock()
					matches = append(matches, jailMatch{ServerID: server.ID, ServerName: server.Name, Jail: info.JailName})
					mu.Unlock()
				}
			}
		}(conn)
	}
	wg.Wait()

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].ServerName != matches[j].ServerName {
			return matches[i].ServerName < matches[j].ServerName
		}
		return matches[i].Jail < matches[j].Jail
	})

	c.JSON(http.StatusOK, gin.H{
		"ip":      ip,
		"banned":  len(matches) > 0,
		"matches": matches,
		"errors":  errs,
	})
}

// Returns paginated banned IPs for a specific jail on the selected server.
func ListJailBannedIPsHandler(c *gin.Context) {
	jail := c.Param("jail")
	if err := fail2ban.ValidateJailName(jail); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, buildErrorResponse(err, "dashboard.errors.summary_failed"))
		return
	}

	const (
		defaultLimit = 5
		maxLimit     = 100
		maxOffset    = 100000
	)

	limit := defaultLimit
	if limitStr := c.DefaultQuery("limit", strconv.Itoa(defaultLimit)); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			if parsed <= maxLimit {
				limit = parsed
			} else {
				limit = maxLimit
			}
		}
	}

	offset := 0
	if offsetStr := c.DefaultQuery("offset", "0"); offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			if parsed <= maxOffset {
				offset = parsed
			} else {
				offset = maxOffset
			}
		}
	}

	query := strings.TrimSpace(c.Query("q"))
	allIPs, err := conn.GetBannedIPs(c.Request.Context(), jail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "dashboard.errors.summary_failed"))
		return
	}

	filtered := allIPs
	if query != "" {
		lowerQuery := strings.ToLower(query)
		filtered = make([]string, 0, len(allIPs))
		for _, ip := range allIPs {
			if strings.Contains(strings.ToLower(ip), lowerQuery) {
				filtered = append(filtered, ip)
			}
		}
	}

	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	paged := filtered[offset:end]

	c.JSON(http.StatusOK, gin.H{
		"jail":      jail,
		"bannedIPs": paged,
		"total":     total,
		"hasMore":   end < total,
	})
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
	if err := fail2ban.ValidateJailName(jail); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, buildErrorResponse(err, "dashboard.manual_block.error"))
		return
	}

	if err := conn.BanIP(c.Request.Context(), jail, ip); err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "dashboard.manual_block.error"))
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
	if err := fail2ban.ValidateJailName(jail); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, buildErrorResponse(err, ""))
		return
	}

	if err := conn.UnbanIP(c.Request.Context(), jail, ip); err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, ""))
		return
	}
	fmt.Println(ip + " from jail " + jail + " unbanned successfully.")
	c.JSON(http.StatusOK, gin.H{
		"message": "IP unbanned successfully",
	})
}

// Processes incoming ban callbacks from Fail2Ban action scripts.
func BanNotificationHandler(c *gin.Context) {
	if !validateCallbackSecret(c) {
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

	// Reads the request body so it can be parsed and inspected (in debug mode).
	body, _ := io.ReadAll(c.Request.Body)
	config.DebugLog("Incoming ban notification (%d bytes): %s", c.Request.ContentLength, string(body))

	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	if err := c.ShouldBindJSON(&request); err != nil {
		var verr validator.ValidationErrors
		if errors.As(err, &verr) {
			for _, fe := range verr {
				log.Printf("ERROR: Validation error: Field '%s' violated rule '%s'", fe.Field(), fe.ActualTag())
			}
		} else {
			log.Printf("ERROR: JSON parsing error -> Action will not be recorded! Details: %v", err)
		}
		config.DebugLog("Raw JSON that failed to parse: %s", string(body))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	log.Printf("Parsed ban request successfully - IP: %s, Jail: %s, Hostname: %s, Failures: %s",
		request.IP, request.Jail, request.Hostname, request.Failures)

	if err := integrations.ValidateIP(request.IP); err != nil {
		log.Printf("WARNING: Invalid IP in ban notification: %s", request.IP)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP: " + err.Error()})
		return
	}

	server, err := resolveServerForNotification(request.ServerID, request.Hostname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := HandleBanNotification(c.Request.Context(), server, request.IP, request.Jail, request.Hostname, request.Failures, request.Whois, request.Logs); err != nil {
		log.Printf("ERROR: Failed to process ban notification: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process ban notification: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Ban notification processed successfully"})
}

// Processes incoming unban callbacks from Fail2Ban action scripts.
func UnbanNotificationHandler(c *gin.Context) {
	if !validateCallbackSecret(c) {
		return
	}

	var request struct {
		ServerID string `json:"serverId"`
		IP       string `json:"ip" binding:"required"`
		Jail     string `json:"jail" binding:"required"`
		Hostname string `json:"hostname"`
	}

	body, _ := io.ReadAll(c.Request.Body)
	config.DebugLog("Incoming unban notification: %s\n", string(body))

	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	if err := c.ShouldBindJSON(&request); err != nil {
		var verr validator.ValidationErrors
		if errors.As(err, &verr) {
			for _, fe := range verr {
				log.Printf("ERROR: Validation error: Field '%s' violated rule '%s'", fe.Field(), fe.ActualTag())
			}
		} else {
			log.Printf("ERROR: JSON parsing error -> Action will not be recorded! Details: %v", err)
		}
		log.Printf("Raw JSON: %s", string(body))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	log.Printf("Parsed unban request successfully - IP: %s, Jail: %s, Hostname: %s",
		request.IP, request.Jail, request.Hostname)

	if err := integrations.ValidateIP(request.IP); err != nil {
		log.Printf("WARNING: Invalid IP in unban notification: %s", request.IP)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP: " + err.Error()})
		return
	}

	server, err := resolveServerForNotification(request.ServerID, request.Hostname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := HandleUnbanNotification(c.Request.Context(), server, request.IP, request.Jail, request.Hostname, "", ""); err != nil {
		log.Printf("ERROR: Failed to process unban notification: %v\n", err)
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

	var since, until time.Time
	if sinceStr := c.Query("since"); sinceStr != "" {
		if parsed, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = parsed
		}
	}
	if untilStr := c.Query("until"); untilStr != "" {
		if parsed, err := time.Parse(time.RFC3339, untilStr); err == nil {
			until = parsed
		}
	}

	filter := storage.BanEventFilter{
		ServerID: serverID,
		Jail:     strings.TrimSpace(c.Query("jail")),
		Country:  strings.TrimSpace(c.Query("country")),
		Search:   strings.TrimSpace(c.Query("search")),
		Since:    since,
		Until:    until,
	}

	ctx := c.Request.Context()

	var (
		events   []storage.BanEventRecord
		listErr  error
		total    int64
		countErr error
		wg       sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		events, listErr = storage.ListBanEventsFiltered(ctx, filter, limit, offset)
	}()
	if offset == 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			total, countErr = storage.CountBanEventsFiltered(ctx, filter)
		}()
	}
	wg.Wait()

	if listErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": listErr.Error()})
		return
	}

	resp := gin.H{"events": events, "hasMore": len(events) == limit}
	if offset == 0 && countErr == nil {
		resp["total"] = total
	}
	c.JSON(http.StatusOK, resp)
}

// Returns the distinct countries seen across all stored events
func ListBanEventCountriesHandler(c *gin.Context) {
	countries, err := storage.ListBanEventCountries(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"countries": countries})
}

// Returns a single ban event including whois/logs fields.
func GetBanEventHandler(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event id"})
		return
	}

	event, found, err := storage.GetBanEventByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "event not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"event": event})
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

// Reports a failed insights sub-query as a 500 and returns true when it did
func failInsightsQuery(c *gin.Context, query string, err error) bool {
	if err == nil {
		return false
	}
	errorMsg := err.Error()
	if config.GetSettings().Debug {
		config.DebugLog("BanInsightsHandler: %s error: %v", query, err)
		errorMsg = fmt.Sprintf("%s failed: %v", query, err)
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": errorMsg})
	return true
}

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
	now := time.Now().UTC()

	// The three queries are independent; run them concurrently.
	var (
		countriesMap             map[string]int64
		recurring                []storage.RecurringIPStat
		totalOverall, totalToday int64
		totalWeek                int64
		countriesErr             error
		recurringErr             error
		totalsErr                error
		wg                       sync.WaitGroup
	)
	wg.Add(3)
	go func() {
		defer wg.Done()
		countriesMap, countriesErr = storage.CountBanEventsByCountry(ctx, since, serverID)
	}()
	go func() {
		defer wg.Done()
		recurring, recurringErr = storage.ListRecurringIPStats(ctx, since, minCount, limit, serverID)
	}()
	go func() {
		defer wg.Done()
		totalOverall, totalToday, totalWeek, totalsErr = storage.CountBanEventTotals(ctx, serverID, now)
	}()
	wg.Wait()

	if failInsightsQuery(c, "CountBanEventsByCountry", countriesErr) ||
		failInsightsQuery(c, "ListRecurringIPStats", recurringErr) ||
		failInsightsQuery(c, "CountBanEventTotals", totalsErr) {
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

// Bucket ladder for the timeline endpoint
var timelineBucketLadder = []int64{60, 300, 900, 1800, 3600, 10800, 21600, 43200, 86400}

const (
	timelineTargetBuckets = 180
	timelineMaxBuckets    = 500
)

func parseEventRange(c *gin.Context) (since, until time.Time, ok bool) {
	until = time.Now().UTC()
	if untilStr := c.Query("until"); untilStr != "" {
		parsed, err := time.Parse(time.RFC3339, untilStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'until' timestamp, expected RFC3339"})
			return since, until, false
		}
		until = parsed.UTC()
	}
	since = until.Add(-8 * time.Hour)
	if sinceStr := c.Query("since"); sinceStr != "" {
		parsed, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'since' timestamp, expected RFC3339"})
			return since, until, false
		}
		since = parsed.UTC()
	}
	if !until.After(since) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "'until' must be after 'since'"})
		return since, until, false
	}
	return since, until, true
}

func eventFilterFromQuery(c *gin.Context, since, until time.Time) storage.BanEventFilter {
	return storage.BanEventFilter{
		ServerID: c.Query("serverId"),
		Jail:     strings.TrimSpace(c.Query("jail")),
		Country:  strings.TrimSpace(c.Query("country")),
		Search:   strings.TrimSpace(c.Query("search")),
		Since:    since,
		Until:    until,
	}
}

func chooseBucketSeconds(since, until time.Time, override int64) int64 {
	rangeSeconds := until.Unix() - since.Unix()
	if rangeSeconds < 1 {
		rangeSeconds = 1
	}
	minAllowed := rangeSeconds/timelineMaxBuckets + 1
	if override > 0 {
		if override < minAllowed {
			return minAllowed
		}
		return override
	}
	for _, b := range timelineBucketLadder {
		if rangeSeconds/b <= timelineTargetBuckets {
			return b
		}
	}
	bucket := timelineBucketLadder[len(timelineBucketLadder)-1]
	for rangeSeconds/bucket > timelineMaxBuckets {
		bucket *= 2
	}
	return bucket
}

// Returns time-bucketed ban/unban counts for the insights timeline.
func BanTimelineHandler(c *gin.Context) {
	since, until, ok := parseEventRange(c)
	if !ok {
		return
	}
	var override int64
	if bucketStr := c.Query("bucket"); bucketStr != "" {
		if parsed, err := strconv.ParseInt(bucketStr, 10, 64); err == nil && parsed > 0 {
			override = parsed
		}
	}
	bucketSeconds := chooseBucketSeconds(since, until, override)

	buckets, err := storage.BanEventTimeline(c.Request.Context(), eventFilterFromQuery(c, since, until), bucketSeconds)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var totalBans, totalUnbans int64
	for _, b := range buckets {
		totalBans += b.Bans
		totalUnbans += b.Unbans
	}
	c.JSON(http.StatusOK, gin.H{
		"since":         since,
		"until":         until,
		"bucketSeconds": bucketSeconds,
		"buckets":       buckets,
		"totals":        gin.H{"bans": totalBans, "unbans": totalUnbans},
	})
}

// Returns per-IP ban aggregates for a time range
func ListBanEventIPsHandler(c *gin.Context) {
	since, until, ok := parseEventRange(c)
	if !ok {
		return
	}
	limit := 2000
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 10000 {
			limit = parsed
		}
	}

	ips, total, err := storage.ListBanEventIPs(c.Request.Context(), eventFilterFromQuery(c, since, until), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if ips == nil {
		ips = []storage.BanEventIPStat{}
	}
	c.JSON(http.StatusOK, gin.H{
		"ips":       ips,
		"total":     total,
		"truncated": total > int64(len(ips)),
		"since":     since,
		"until":     until,
	})
}

func BanEventIPActivityHandler(c *gin.Context) {
	since, until, ok := parseEventRange(c)
	if !ok {
		return
	}
	minOverlap := 3
	if minOverlapStr := c.Query("minOverlap"); minOverlapStr != "" {
		if parsed, err := strconv.Atoi(minOverlapStr); err == nil && parsed >= 1 {
			minOverlap = parsed
		}
	}

	periods, err := storage.ListBanEventIPActivity(c.Request.Context(), eventFilterFromQuery(c, since, until), minOverlap)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if periods == nil {
		periods = []storage.IPActivityPeriod{}
	}
	c.JSON(http.StatusOK, gin.H{"periods": periods})
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
