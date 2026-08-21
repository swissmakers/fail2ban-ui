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
	"net/http"
	"os"

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
	RestartNeeded bool     `json:"restartNeeded"`
	Warnings      []string `json:"warnings,omitempty"`
}

// =========================================================================
//  App Settings
// =========================================================================

// Returns the current AppSettings as JSON.
func GetSettingsHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("GetSettingsHandler called (handlers.go)")
	s := config.GetSettings()
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	oldSettings := config.GetSettings()
	newSettings, err := config.UpdateSettings(req)
	if err != nil {
		fmt.Println("Error updating settings:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	config.DebugLog("Settings updated successfully (handlers.go)")

	callbackURLChanged := oldSettings.CallbackURL != newSettings.CallbackURL
	callbackSecretChanged := oldSettings.CallbackSecret != newSettings.CallbackSecret
	callbackChanged := callbackURLChanged || callbackSecretChanged

	if err := config.ReloadFail2banManager(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reload fail2ban connectors: " + err.Error()})
		return
	}

	if callbackChanged {
		config.DebugLog("Callback URL or secret changed, updating action files and reloading fail2ban on all servers")

		if err := fail2ban.GetManager().UpdateActionFiles(c.Request.Context()); err != nil {
			config.DebugLog("Warning: failed to update some remote action files: %v", err)
		}

		connectors := fail2ban.GetManager().Connectors()
		for _, conn := range connectors {
			server := conn.Server()
			if (server.Type == "ssh" || server.Type == "agent") && server.Enabled {
				config.DebugLog("Reloading fail2ban on %s after callback change", server.Name)
				if err := conn.Reload(c.Request.Context()); err != nil {
					config.DebugLog("Warning: failed to reload fail2ban on %s after updating action file: %v", server.Name, err)
				} else {
					config.DebugLog("Successfully reloaded fail2ban on %s", server.Name)
				}
			}
		}

		settings := config.GetSettings()
		for _, server := range settings.Servers {
			if server.Type == "local" && server.Enabled {
				if err := config.EnsureLocalFail2banAction(server); err != nil {
					config.DebugLog("Warning: failed to update local action file: %v", err)
				} else {
					if conn, err := fail2ban.GetManager().Connector(server.ID); err == nil {
						config.DebugLog("Reloading local fail2ban after callback change")
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
		var updateErrors []string
		for _, conn := range connectors {
			server := conn.Server()
			config.DebugLog("Updating DEFAULT settings on server: %s (type: %s)", server.Name, server.Type)
			if err := conn.UpdateDefaultSettings(c.Request.Context()); err != nil {
				errorMsg := fmt.Sprintf("Failed to update DEFAULT settings on %s: %v", server.Name, err)
				log.Printf("WARNING: %s", errorMsg)
				updateErrors = append(updateErrors, errorMsg)
			} else {
				config.DebugLog("Successfully updated DEFAULT settings on %s", server.Name)
				if err := conn.Reload(c.Request.Context()); err != nil {
					config.DebugLog("Warning: failed to reload fail2ban on %s after updating DEFAULT settings: %v", server.Name, err)
					updateErrors = append(updateErrors, fmt.Sprintf("Settings updated on %s, but reload failed: %v", server.Name, err))
				} else {
					config.DebugLog("Successfully reloaded fail2ban on %s", server.Name)
				}
			}
		}
		c.JSON(http.StatusOK, settingsUpdateResponse{
			Message:       "Settings updated",
			RestartNeeded: false,
			Warnings:      updateErrors,
		})
		return
	}

	c.JSON(http.StatusOK, settingsUpdateResponse{
		Message:       "Settings updated",
		RestartNeeded: newSettings.RestartNeeded,
	})
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
	applySettingsUpdate(c, req)
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
	config.DebugLog("RestartFail2banHandler called (handlers.go)")

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	server := conn.Server()

	// Attempts to restart the fail2ban service via the connector.
	mode, err := fail2ban.RestartFail2ban(server.ID)
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
