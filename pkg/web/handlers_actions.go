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
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/integrations"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// =========================================================================
//  Advanced Actions
// =========================================================================

func requireConfiguredIntegration(c *gin.Context) (config.AppSettings, bool) {
	settings := config.GetSettings()
	if settings.AdvancedActions.Integration == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no integration configured. Please configure an integration (MikroTik, pfSense, or OPNsense) in Advanced Actions settings first"})
		return settings, false
	}
	integration, ok := integrations.Get(settings.AdvancedActions.Integration)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("integration %s not found or not registered", settings.AdvancedActions.Integration)})
		return settings, false
	}
	if err := integration.Validate(settings.AdvancedActions); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("integration configuration is invalid: %v", err)})
		return settings, false
	}
	return settings, true
}

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

	settings, ok := requireConfiguredIntegration(c)
	if !ok {
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

const bulkBlockMaxIPs = 500
const bulkBlockAbortThreshold = 5

// Permanently blocks a list of IPs via the configured advanced-actions integration
func BulkPermanentBlockHandler(c *gin.Context) {
	var req struct {
		IPs []string `json:"ips"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if len(req.IPs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ips is required"})
		return
	}
	if len(req.IPs) > bulkBlockMaxIPs {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("too many IPs (max %d per request)", bulkBlockMaxIPs)})
		return
	}

	settings, ok := requireConfiguredIntegration(c)
	if !ok {
		return
	}

	actingUser := ""
	if sessionValue, exists := c.Get("session"); exists {
		if session, ok := sessionValue.(*auth.Session); ok && session != nil {
			actingUser = session.Username
			if actingUser == "" {
				actingUser = session.Email
			}
		}
	}

	// Dedupe preserving order.
	seen := make(map[string]bool, len(req.IPs))
	ips := make([]string, 0, len(req.IPs))
	for _, raw := range req.IPs {
		ip := strings.TrimSpace(raw)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		ips = append(ips, ip)
	}

	type bulkBlockResult struct {
		IP      string `json:"ip"`
		Status  string `json:"status"`
		Message string `json:"message,omitempty"`
	}
	results := make([]bulkBlockResult, 0, len(ips))
	summary := map[string]int{
		"requested": len(ips), "blocked": 0, "alreadyBlocked": 0,
		"skipped": 0, "invalid": 0, "failed": 0, "aborted": 0,
	}

	ctx := c.Request.Context()
	consecutiveErrors := 0
	lastErrorMsg := ""
	aborted := false

	for _, ip := range ips {
		if aborted {
			results = append(results, bulkBlockResult{IP: ip, Status: "aborted"})
			summary["aborted"]++
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			results = append(results, bulkBlockResult{IP: ip, Status: "invalid", Message: "not a valid IP address"})
			summary["invalid"]++
			continue
		}
		if shared.IsReservedIP(parsed) {
			results = append(results, bulkBlockResult{IP: ip, Status: "skipped_private", Message: "private/reserved address"})
			summary["skipped"]++
			continue
		}
		if active, err := storage.IsPermanentBlockActive(ctx, ip, settings.AdvancedActions.Integration); err == nil && active {
			results = append(results, bulkBlockResult{IP: ip, Status: "already_blocked"})
			summary["alreadyBlocked"]++
			continue
		}

		err := runAdvancedIntegrationAction(ctx, "block", ip, settings, config.Fail2banServer{}, map[string]any{
			"reason":    "bulk_insights",
			"user":      actingUser,
			"batchSize": len(ips),
		}, false)
		if err != nil {
			results = append(results, bulkBlockResult{IP: ip, Status: "error", Message: err.Error()})
			summary["failed"]++
			if err.Error() == lastErrorMsg {
				consecutiveErrors++
			} else {
				consecutiveErrors = 1
				lastErrorMsg = err.Error()
			}
			if consecutiveErrors >= bulkBlockAbortThreshold {
				aborted = true
			}
			continue
		}
		consecutiveErrors = 0
		lastErrorMsg = ""
		results = append(results, bulkBlockResult{IP: ip, Status: "blocked"})
		summary["blocked"]++
	}

	log.Printf("Bulk permanent block: user=%s requested=%d blocked=%d alreadyBlocked=%d skipped=%d invalid=%d failed=%d aborted=%d",
		actingUser, summary["requested"], summary["blocked"], summary["alreadyBlocked"],
		summary["skipped"], summary["invalid"], summary["failed"], summary["aborted"])

	c.JSON(http.StatusOK, gin.H{"results": results, "summary": summary})
}
