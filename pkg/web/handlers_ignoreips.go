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
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
)

// =========================================================================
//  IgnoreIP / Allowed IP Management
// =========================================================================

const (
	defaultIgnoreIPLimit = 10
	maxIgnoreIPLimit     = 100
)

const (
	jailAllowedIPManagementEnabledEnv   = "JAIL_ALLOWED_IP_MANAGEMENT_ENABLED"
	jailAllowedIPManagementMinAccessEnv = "JAIL_ALLOWED_IP_MANAGEMENT_MIN_ACCESS"
)

// Jail-specific allowed-IP management is enabled unless explicitly disabled
// with JAIL_ALLOWED_IP_MANAGEMENT_ENABLED=false.
func jailAllowedIPManagementEnabled() bool {
	return os.Getenv(jailAllowedIPManagementEnabledEnv) != "false"
}

func jailAllowedIPManagementMinAccess() string {
	minAccess := os.Getenv(jailAllowedIPManagementMinAccessEnv)
	if minAccess == "admin" {
		return "admin"
	}
	return "support"
}

func requireJailAllowedIPManagement(c *gin.Context) bool {
	if jailAllowedIPManagementEnabled() {
		return true
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "Jail Allowed IP Management is disabled"})
	return false
}

// ListJailAllowedIPsHandler returns global and jail-specific ignoreip entries
// for the requested jail. Query parameters: serverId, limit, offset, and q.
func ListJailAllowedIPsHandler(c *gin.Context) {
	if !requireJailAllowedIPManagement(c) {
		return
	}

	jail := strings.TrimSpace(c.Param("jail"))
	if jail == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "jail path parameter is required"})
		return
	}

	limit := defaultIgnoreIPLimit
	if limitStr := c.DefaultQuery("limit", strconv.Itoa(defaultIgnoreIPLimit)); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= maxIgnoreIPLimit {
			limit = parsed
		}
	}
	offset := 0
	if offsetStr := c.DefaultQuery("offset", "0"); offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	search := strings.TrimSpace(c.Query("q"))
	settings := config.GetSettings()
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, buildErrorResponse(err, "dashboard.errors.summary_failed"))
		return
	}

	globalIPs := settings.IgnoreIPs
	if globalIPs == nil {
		globalIPs = []string{}
	}
	jailIPs, err := fail2ban.GetJailIgnoreIPs(c.Request.Context(), conn, jail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "ignoreip.error.read_failed"))
		return
	}

	// Global settings apply to every jail. Keep those entries read-only in the
	// response and expose only jail-specific values as removable entries.
	jailIPs = subtractIgnoreIPs(jailIPs, globalIPs)
	filteredGlobals := filterIgnoreIPs(globalIPs, search)
	filteredJailIPs := filterIgnoreIPs(jailIPs, search)
	paged, total, hasMore := paginateIgnoreIPs(filteredJailIPs, offset, limit)

	c.JSON(http.StatusOK, gin.H{
		"serverId":  conn.Server().ID,
		"jail":      jail,
		"globalIps": filteredGlobals,
		"jailIps":   paged,
		"total":     total,
		"hasMore":   hasMore,
	})
}

func filterIgnoreIPs(ips []string, search string) []string {
	if ips == nil {
		ips = []string{}
	}
	if search == "" {
		return ips
	}
	needle := strings.ToLower(search)
	filtered := make([]string, 0, len(ips))
	for _, ip := range ips {
		if strings.Contains(strings.ToLower(ip), needle) {
			filtered = append(filtered, ip)
		}
	}
	return filtered
}

func paginateIgnoreIPs(ips []string, offset, limit int) ([]string, int, bool) {
	total := len(ips)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return ips[offset:end], total, end < total
}

func subtractIgnoreIPs(ips, globalIPs []string) []string {
	globalSet := make(map[string]struct{}, len(globalIPs))
	for _, ip := range globalIPs {
		globalSet[strings.ToLower(ip)] = struct{}{}
	}
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, isGlobal := globalSet[strings.ToLower(ip)]; !isGlobal {
			result = append(result, ip)
		}
	}
	return result
}

// isValidIgnoreEntry accepts an IP address, CIDR range, or DNS hostname,
// which are the forms accepted by Fail2ban's ignoreip setting.
func isValidIgnoreEntry(value string) bool {
	if _, _, err := net.ParseCIDR(value); err == nil {
		return true
	}
	if net.ParseIP(value) != nil {
		return true
	}
	return isValidHostname(value)
}

func isValidHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-') {
				return false
			}
		}
	}
	return true
}

// AddJailAllowedIPHandler adds an address to a jail-specific ignoreip list.
func AddJailAllowedIPHandler(c *gin.Context) {
	if !requireJailAllowedIPManagement(c) {
		return
	}

	var req struct {
		Netmask string `json:"netmask" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "address is required", "messageKey": "ignoreip.error.missing_fields"})
		return
	}

	jail := strings.TrimSpace(c.Param("jail"))
	if jail == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "jail path parameter is required", "messageKey": "ignoreip.error.missing_fields"})
		return
	}
	req.Netmask = strings.TrimSpace(req.Netmask)
	if !isValidIgnoreEntry(req.Netmask) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid IP address, CIDR notation, or hostname", "messageKey": "ignoreip.error.invalid_format"})
		return
	}

	settings := config.GetSettings()
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, buildErrorResponse(err, "dashboard.errors.summary_failed"))
		return
	}

	for _, ip := range settings.IgnoreIPs {
		if strings.EqualFold(ip, req.Netmask) {
			c.JSON(http.StatusConflict, gin.H{"error": "Address already exists in the global ignore list", "messageKey": "ignoreip.error.already_exists_global"})
			return
		}
	}

	currentIPs, err := fail2ban.GetJailIgnoreIPs(c.Request.Context(), conn, jail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "ignoreip.error.read_failed"))
		return
	}
	perJailIPs := subtractIgnoreIPs(currentIPs, settings.IgnoreIPs)
	for _, ip := range perJailIPs {
		if strings.EqualFold(ip, req.Netmask) {
			c.JSON(http.StatusConflict, gin.H{"error": "Address already exists for this jail", "messageKey": "ignoreip.error.already_exists"})
			return
		}
	}

	newIPs := make([]string, 0, len(perJailIPs)+1)
	newIPs = append(newIPs, perJailIPs...)
	newIPs = append(newIPs, req.Netmask)
	if err := fail2ban.SetJailIgnoreIPs(c.Request.Context(), conn, jail, newIPs); err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "ignoreip.error.write_failed"))
		return
	}

	logAllowedIPChange(c, "added", req.Netmask, "jail", fmt.Sprintf("%s on server %s", jail, conn.Server().ID))
	c.JSON(http.StatusOK, gin.H{"message": "Allowed IP added successfully", "address": req.Netmask})
}

// DeleteJailAllowedIPHandler removes an address from a jail-specific ignoreip list.
func DeleteJailAllowedIPHandler(c *gin.Context) {
	if !requireJailAllowedIPManagement(c) {
		return
	}

	jail := strings.TrimSpace(c.Param("jail"))
	netmask := strings.TrimSpace(c.Query("netmask"))
	if jail == "" || netmask == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "jail path and address query parameters are required", "messageKey": "ignoreip.error.missing_fields"})
		return
	}

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, buildErrorResponse(err, "dashboard.errors.summary_failed"))
		return
	}

	currentIPs, err := fail2ban.GetJailIgnoreIPs(c.Request.Context(), conn, jail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "ignoreip.error.read_failed"))
		return
	}

	settings := config.GetSettings()
	perJailIPs := subtractIgnoreIPs(currentIPs, settings.IgnoreIPs)
	newPerJailIPs, found := removeIgnoreIP(perJailIPs, netmask)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Address not found in this jail's ignore list", "messageKey": "ignoreip.error.not_found"})
		return
	}

	if err := fail2ban.SetJailIgnoreIPs(c.Request.Context(), conn, jail, newPerJailIPs); err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "ignoreip.error.write_failed"))
		return
	}

	logAllowedIPChange(c, "removed", netmask, "jail", fmt.Sprintf("%s on server %s", jail, conn.Server().ID))
	c.JSON(http.StatusOK, gin.H{"message": "Address removed successfully", "address": netmask})
}

func removeIgnoreIP(ips []string, value string) ([]string, bool) {
	result := make([]string, 0, len(ips))
	found := false
	for _, ip := range ips {
		if strings.EqualFold(ip, value) {
			found = true
			continue
		}
		result = append(result, ip)
	}
	return result, found
}

func logAllowedIPChange(c *gin.Context, action, address, scope, location string) {
	user := extractActingUser(c)
	message := fmt.Sprintf("[AllowedIP] User %s %s %s in %s", user, action, address, scope)
	if location != "" {
		message += " " + location
	}
	log.Print(message)
	config.DebugLog("%s", message)
}

func extractActingUser(c *gin.Context) string {
	if sessionValue, exists := c.Get("session"); exists {
		if session, ok := sessionValue.(*auth.Session); ok && session != nil {
			if session.Username != "" {
				return session.Username
			}
			if session.Email != "" {
				return session.Email
			}
		}
	}
	return "unknown"
}
