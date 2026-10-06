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
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
)

type appSettingsResponse struct {
	config.AppSettings
	PortFromEnv        int    `json:"portFromEnv"`
	PortEnvSet         bool   `json:"portEnvSet"`
	CallbackUrlEnvSet  bool   `json:"callbackUrlEnvSet"`
	CallbackUrlFromEnv string `json:"callbackUrlFromEnv"`
}

type settingsUpdateResponse struct {
	Message       string   `json:"message,omitempty"`
	SyncPending   bool     `json:"syncPending"`
	RestartNeeded bool     `json:"restartNeeded"`
	Warnings      []string `json:"warnings,omitempty"`
}

// =========================================================================
//  App Settings
// =========================================================================

// Returns the current AppSettings as JSON.
func GetSettingsHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("GetSettingsHandler called")
	s := config.GetSettings()
	s.Servers = nil
	isAdmin := userHasAdminAccess(c)
	if !isAdmin {
		s = config.AppSettings{
			Language:       s.Language,
			AlertCountries: s.AlertCountries,
		}
	}

	envPort, envPortSet := config.GetPortFromEnv()
	envCallbackURL, envCallbackURLSet := config.GetCallbackURLFromEnv()

	response := appSettingsResponse{AppSettings: maskAppSettingsSecrets(s)}
	if isAdmin {
		response.PortFromEnv = envPort
		response.PortEnvSet = envPortSet
		response.CallbackUrlEnvSet = envCallbackURLSet
		response.CallbackUrlFromEnv = envCallbackURL
	}

	if isAdmin && envPortSet {
		response.Port = envPort
	}
	if isAdmin && envCallbackURLSet {
		response.CallbackURL = envCallbackURL
	}

	c.JSON(http.StatusOK, response)
}

func applyEnvLockedSettings(req *config.AppSettings) {
	envPort, envPortSet := config.GetPortFromEnv()
	if envPortSet {
		req.Port = envPort
	}
	envCallbackURL, envCallbackURLSet := config.GetCallbackURLFromEnv()
	if envCallbackURLSet {
		req.CallbackURL = envCallbackURL
	}
}

func applySettingsUpdate(c *gin.Context, req config.AppSettings) {
	applyEnvLockedSettings(&req)
	restoreMaskedSecrets(&req, config.GetSettings())
	if err := normalizeAndValidateSettingsRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, buildErrorResponse(err, ""))
		return
	}

	oldSettings := config.GetSettings()
	oldDefaults := config.BuildJailLocalContent()
	newSettings, err := config.UpdateSettings(req)
	if err != nil {
		log.Printf("ERROR: updating settings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	config.DebugLog("Settings updated successfully")

	callbackURLChanged := oldSettings.CallbackURL != newSettings.CallbackURL
	callbackSecretChanged := oldSettings.CallbackSecret != newSettings.CallbackSecret
	callbackChanged := callbackURLChanged || callbackSecretChanged

	if err := config.ReloadFail2banManager(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reload fail2ban connectors: " + err.Error()})
		return
	}

	var warnings []string
	warn := func(format string, v ...interface{}) {
		msg := fmt.Sprintf(format, v...)
		log.Printf("WARNING: %s", msg)
		warnings = append(warnings, msg)
	}

	defaultSettingsChanged := oldDefaults != config.BuildJailLocalContent()
	manager := fail2ban.GetManager()
	connectors := manager.Connectors()
	if callbackChanged || defaultSettingsChanged {
		for _, conn := range connectors {
			manager.RequestConfigSync(conn.Server().ID, callbackChanged, defaultSettingsChanged)
		}
	}
	for _, err := range manager.SyncAll(c.Request.Context(), 20*time.Second) {
		warn("%v", err)
	}
	statuses := make([]fail2ban.ConfigSyncStatus, 0, len(connectors))
	for _, conn := range connectors {
		statuses = append(statuses, manager.ConfigSyncStatus(conn.Server().ID))
	}
	syncPending, restartNeeded := settingsSyncFlags(statuses)

	c.JSON(http.StatusOK, settingsUpdateResponse{
		Message:       "Settings updated",
		SyncPending:   syncPending,
		RestartNeeded: restartNeeded,
		Warnings:      warnings,
	})
}

// syncPending -> some host has not received the files yet
// restartNeeded -> files are written but not active.
func settingsSyncFlags(statuses []fail2ban.ConfigSyncStatus) (syncPending, restartNeeded bool) {
	for _, st := range statuses {
		switch st.Phase {
		case fail2ban.SyncPending:
			syncPending = true
		case fail2ban.SyncWritten:
			restartNeeded = true
		}
	}
	return syncPending, restartNeeded
}

// Saves new settings, pushes defaults to servers, and reloads.
func UpdateSettingsHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("UpdateSettingsHandler called")
	var req config.AppSettings
	if err := c.ShouldBindJSON(&req); err != nil {
		config.DebugLog("settings JSON binding error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid JSON",
			"details": err.Error(),
		})
		return
	}
	config.DebugLog("JSON binding successful, updating settings")
	applySettingsUpdate(c, req)
}

// =========================================================================
//  Filters
// =========================================================================

// Returns all available filter names for the selected server.
func ListFiltersHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("ListFiltersHandler called")
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	filters, err := conn.GetFilters(c.Request.Context())
	if errors.Is(err, fail2ban.ErrFilterDirMissing) {
		c.JSON(http.StatusOK, gin.H{"filters": []string{}, "messageKey": "filter_debug.local_missing"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list filters: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"filters": filters})
}

// Returns the content of a specific filter file.
func GetFilterContentHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("GetFilterContentHandler called")
	filterName := c.Param("filter")
	if err := fail2ban.ValidateFilterName(filterName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
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
	config.DebugLog("TestFilterHandler called")
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
	if err := fail2ban.ValidateFilterName(req.FilterName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
	config.DebugLog("CreateFilterHandler called")

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
	existing, err := conn.GetFilters(c.Request.Context())
	if err != nil && !errors.Is(err, fail2ban.ErrFilterDirMissing) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check existing filters: " + err.Error()})
		return
	}
	if slices.Contains(existing, req.FilterName) {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("filter '%s' already exists", req.FilterName), "messageKey": "filters.errors.already_exists", "filter": req.FilterName})
		return
	}

	if req.Content == "" {
		req.Content = fmt.Sprintf("# Filter: %s\n", req.FilterName)
	}

	if err := conn.CreateFilter(c.Request.Context(), req.FilterName, req.Content); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create filter: " + err.Error()})
		return
	}

	// Reload so a jail referencing this filter can pick it up immediately.
	if err := conn.Reload(c.Request.Context()); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("Filter '%s' created, but fail2ban reload reported a problem", req.FilterName),
			"warning": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Filter '%s' created and applied successfully", req.FilterName)})
}

// Removes a filter definition file.
func DeleteFilterHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("DeleteFilterHandler called")

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

	// Reload so fail2ban notices the removal (and reports if a jail still needs it).
	if err := conn.Reload(c.Request.Context()); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("Filter '%s' deleted, but fail2ban reload reported a problem", filterName),
			"warning": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Filter '%s' deleted and applied successfully", filterName)})
}

// =========================================================================
//  Restart
// =========================================================================

// Restarts (or reloads) the Fail2ban service on the selected server.
func RestartFail2banHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("RestartFail2banHandler called")

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	server := conn.Server()

	// browser disconnect must not abort a restart halfway
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 2*time.Minute)
	defer cancel()
	// Attempts to restart the fail2ban service via the connector.
	mode, err := fail2ban.GetManager().ApplyAndRestart(ctx, server.ID)
	if errors.Is(err, fail2ban.ErrConfigNotApplied) {
		c.JSON(http.StatusConflict, buildErrorResponse(err, "servers.errors.config_not_applied"))
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, buildErrorResponse(err, ""))
		return
	}

	msg := "Fail2ban service restarted successfully"
	if mode == "reload" {
		msg = "Fail2ban configuration reloaded successfully (no systemd service restart)"
	}
	c.JSON(http.StatusOK, gin.H{
		"message": msg,
		"mode":    mode,
		"server":  maskServer(server),
	})
}
