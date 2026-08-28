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
	globalJailSentinel   = "__global__"
)

func allowedIPFeatureEnabled() bool {
	return os.Getenv("ALLOWED_IP_ENABLED") == "true"
}

func requireAllowedIPFeature(c *gin.Context) bool {
	if allowedIPFeatureEnabled() {
		return true
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "Allowed IP Management is disabled"})
	return false
}

// ListAllowedIPsHandler returns ignoreip entries for a jail or the global list.
// Query parameters: serverId, jail (or __global__), limit, offset, and q.
func ListAllowedIPsHandler(c *gin.Context) {
	if !requireAllowedIPFeature(c) {
		return
	}

	jail := strings.TrimSpace(c.Query("jail"))
	if jail == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "jail parameter is required"})
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
	if jail == globalJailSentinel {
		globalIPs := filterIgnoreIPs(settings.IgnoreIPs, search)
		paged, total, hasMore := paginateIgnoreIPs(globalIPs, offset, limit)
		c.JSON(http.StatusOK, gin.H{
			"jail":      globalJailSentinel,
			"globalIps": []string{},
			"jailIps":   paged,
			"total":     total,
			"hasMore":   hasMore,
		})
		return
	}

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, buildErrorResponse(err, "dashboard.errors.summary_failed"))
		return
	}

	globalIPs := settings.IgnoreIPs
	if globalIPs == nil {
		globalIPs = []string{}
	}
	jailIPs, err := conn.GetJailIgnoreIPs(c.Request.Context(), jail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "ignoreip.error.read_failed"))
		return
	}

	// Per-jail files written by this feature include the global entries. Keep
	// those global values read-only in the response and expose only the
	// jail-specific values as removable entries.
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

// AddAllowedIPHandler adds an address to the global list or a jail-specific list.
func AddAllowedIPHandler(c *gin.Context) {
	if !requireAllowedIPFeature(c) {
		return
	}

	var req struct {
		Jail    string `json:"jail" binding:"required"`
		Netmask string `json:"netmask" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "jail and address are required", "messageKey": "ignoreip.error.missing_fields"})
		return
	}

	req.Jail = strings.TrimSpace(req.Jail)
	req.Netmask = strings.TrimSpace(req.Netmask)
	if !isValidIgnoreEntry(req.Netmask) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Invalid IP address, CIDR notation, or hostname", "messageKey": "ignoreip.error.invalid_format"})
		return
	}

	settings := config.GetSettings()
	if req.Jail == globalJailSentinel {
		for _, ip := range settings.IgnoreIPs {
			if strings.EqualFold(ip, req.Netmask) {
				c.JSON(http.StatusConflict, gin.H{"error": "Address already exists in the global ignore list", "messageKey": "ignoreip.error.already_exists_global"})
				return
			}
		}

		oldGlobals := append([]string(nil), settings.IgnoreIPs...)
		newGlobals := append(append([]string(nil), settings.IgnoreIPs...), req.Netmask)
		newSettings := settings
		newSettings.IgnoreIPs = newGlobals
		if _, err := config.UpdateSettings(newSettings); err != nil {
			c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "ignoreip.error.write_failed"))
			return
		}

		warnings := syncPerJailIgnoreIPsAfterGlobalChange(c.Request.Context(), oldGlobals, newGlobals)
		logAllowedIPChange(c, "added", req.Netmask, "global ignore list", "")
		c.JSON(http.StatusOK, gin.H{"message": "Allowed IP added to global ignore list", "address": req.Netmask, "warnings": warnings})
		return
	}

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, buildErrorResponse(err, "dashboard.errors.summary_failed"))
		return
	}

	currentIPs, err := conn.GetJailIgnoreIPs(c.Request.Context(), req.Jail)
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

	newIPs := make([]string, 0, len(settings.IgnoreIPs)+len(perJailIPs)+1)
	newIPs = append(newIPs, settings.IgnoreIPs...)
	newIPs = append(newIPs, perJailIPs...)
	newIPs = append(newIPs, req.Netmask)
	if err := conn.SetJailIgnoreIPs(c.Request.Context(), req.Jail, newIPs); err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "ignoreip.error.write_failed"))
		return
	}

	logAllowedIPChange(c, "added", req.Netmask, "jail", fmt.Sprintf("%s on server %s", req.Jail, conn.Server().ID))
	c.JSON(http.StatusOK, gin.H{"message": "Allowed IP added successfully", "address": req.Netmask})
}

// DeleteAllowedIPHandler removes an address from the global list or a
// jail-specific list.
func DeleteAllowedIPHandler(c *gin.Context) {
	if !requireAllowedIPFeature(c) {
		return
	}

	jail := strings.TrimSpace(c.Query("jail"))
	netmask := strings.TrimSpace(c.Query("netmask"))
	if jail == "" || netmask == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "jail and address query parameters are required", "messageKey": "ignoreip.error.missing_fields"})
		return
	}

	if jail == globalJailSentinel {
		settings := config.GetSettings()
		oldGlobals := append([]string(nil), settings.IgnoreIPs...)
		newGlobals, found := removeIgnoreIP(settings.IgnoreIPs, netmask)
		if !found {
			c.JSON(http.StatusNotFound, gin.H{"error": "Address not found in the global ignore list", "messageKey": "ignoreip.error.not_found"})
			return
		}

		newSettings := settings
		newSettings.IgnoreIPs = newGlobals
		if _, err := config.UpdateSettings(newSettings); err != nil {
			c.JSON(http.StatusInternalServerError, buildErrorResponse(err, "ignoreip.error.write_failed"))
			return
		}

		warnings := syncPerJailIgnoreIPsAfterGlobalChange(c.Request.Context(), oldGlobals, newGlobals)
		logAllowedIPChange(c, "removed", netmask, "global ignore list", "")
		c.JSON(http.StatusOK, gin.H{"message": "Address removed from global ignore list", "address": netmask, "warnings": warnings})
		return
	}

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, buildErrorResponse(err, "dashboard.errors.summary_failed"))
		return
	}

	currentIPs, err := conn.GetJailIgnoreIPs(c.Request.Context(), jail)
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

	mergedIPs := make([]string, 0, len(settings.IgnoreIPs)+len(newPerJailIPs))
	mergedIPs = append(mergedIPs, settings.IgnoreIPs...)
	mergedIPs = append(mergedIPs, newPerJailIPs...)
	if err := conn.SetJailIgnoreIPs(c.Request.Context(), jail, mergedIPs); err != nil {
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

// syncPerJailIgnoreIPsAfterGlobalChange updates each managed connector after
// the global ignoreip list changes. Existing jail-specific values are retained.
func syncPerJailIgnoreIPsAfterGlobalChange(ctx context.Context, oldGlobals, newGlobals []string) []string {
	warnings := make([]string, 0)
	oldSet := make(map[string]struct{}, len(oldGlobals))
	for _, ip := range oldGlobals {
		oldSet[strings.ToLower(ip)] = struct{}{}
	}

	for _, conn := range fail2ban.GetManager().Connectors() {
		serverName := conn.Server().Name
		if serverName == "" {
			serverName = conn.Server().ID
		}

		if err := conn.UpdateDefaultSettings(ctx); err != nil {
			msg := fmt.Sprintf("Failed to update DEFAULT ignoreip on %s: %v", serverName, err)
			config.DebugLog("[AllowedIP] %s", msg)
			warnings = append(warnings, msg)
		} else if err := conn.Reload(ctx); err != nil {
			msg := fmt.Sprintf("Updated DEFAULT ignoreip on %s, but reload failed: %v", serverName, err)
			config.DebugLog("[AllowedIP] %s", msg)
			warnings = append(warnings, msg)
		}

		jailInfos, err := conn.GetJailInfos(ctx)
		if err != nil {
			msg := fmt.Sprintf("Failed to list jails on %s for global sync: %v", serverName, err)
			config.DebugLog("[AllowedIP] %s", msg)
			warnings = append(warnings, msg)
			continue
		}
		for _, jailInfo := range jailInfos {
			rawIPs, err := conn.GetJailIgnoreIPs(ctx, jailInfo.JailName)
			if err != nil {
				msg := fmt.Sprintf("Failed to read ignoreip for jail %s on %s: %v", jailInfo.JailName, serverName, err)
				config.DebugLog("[AllowedIP] %s", msg)
				warnings = append(warnings, msg)
				continue
			}

			perJailIPs := make([]string, 0, len(rawIPs))
			hadOldGlobal := false
			for _, ip := range rawIPs {
				if _, isOldGlobal := oldSet[strings.ToLower(ip)]; isOldGlobal {
					hadOldGlobal = true
					continue
				}
				perJailIPs = append(perJailIPs, ip)
			}

			// Do not introduce a jail-level override for a jail that was never
			// touched by allowed-IP management. An existing override consisting
			// of old global values must be updated so it does not mask DEFAULT.
			if !hadOldGlobal && len(perJailIPs) == 0 {
				continue
			}

			mergedIPs := make([]string, 0, len(newGlobals)+len(perJailIPs))
			mergedIPs = append(mergedIPs, newGlobals...)
			mergedIPs = append(mergedIPs, perJailIPs...)
			if err := conn.SetJailIgnoreIPs(ctx, jailInfo.JailName, mergedIPs); err != nil {
				msg := fmt.Sprintf("Failed to update jail %s on %s after global change: %v", jailInfo.JailName, serverName, err)
				config.DebugLog("[AllowedIP] %s", msg)
				warnings = append(warnings, msg)
			}
		}
	}
	return warnings
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
