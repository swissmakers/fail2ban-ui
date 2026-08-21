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
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
)

// =========================================================================
//  Jail Config
// =========================================================================

// Returns the filter and jail config for a given jail.
func GetJailFilterConfigHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("GetJailFilterConfigHandler called (handlers.go)")
	jail := c.Param("jail")
	config.DebugLog("Jail name: %s", jail)

	if err := fail2ban.ValidateJailName(jail); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	conn, err := resolveConnector(c)
	if err != nil {
		config.DebugLog("Failed to resolve connector: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	config.DebugLog("Connector resolved: %s", conn.Server().Name)

	var filterCfg string
	var filterFilePath string
	var jailCfg string
	var jailFilePath string
	var filterErr error

	// Always load jail config first to determine which filter to load
	config.DebugLog("Loading jail config for jail: %s", jail)
	var jailErr error
	jailCfg, jailFilePath, jailErr = conn.GetJailConfig(c.Request.Context(), jail)
	if jailErr != nil {
		config.DebugLog("Failed to load jail config: %v", jailErr)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load jail config: " + jailErr.Error()})
		return
	}
	config.DebugLog("Jail config loaded, length: %d, file: %s", len(jailCfg), jailFilePath)

	// Extracts the filter name from the jail config, or uses the jail name as fallback
	filterName := fail2ban.ExtractFilterFromJailConfig(jailCfg)
	if filterName == "" {
		// No filter directive found, uses the jail name as filter name
		filterName = jail
		config.DebugLog("No filter directive found in jail config, using jail name as filter name: %s", filterName)
	} else {
		config.DebugLog("Found filter directive in jail config: %s", filterName)
	}

	// Loads the filter config using the filter name determined from the jail config
	config.DebugLog("Loading filter config for filter: %s", filterName)
	filterCfg, filterFilePath, filterErr = conn.GetFilterConfig(c.Request.Context(), filterName)
	if filterErr != nil {
		config.DebugLog("Failed to load filter config for %s: %v", filterName, filterErr)
		config.DebugLog("Continuing without filter config (filter may not exist yet)")
		filterCfg = ""
		filterFilePath = ""
	} else {
		config.DebugLog("Filter config loaded, length: %d, file: %s", len(filterCfg), filterFilePath)
	}

	c.JSON(http.StatusOK, gin.H{
		"jail":           jail,
		"filter":         filterCfg,
		"filterFilePath": filterFilePath,
		"jailConfig":     jailCfg,
		"jailFilePath":   jailFilePath,
	})
}

// Saves updated filter/jail config and reloads Fail2ban.
func SetJailFilterConfigHandler(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			config.DebugLog("PANIC in SetJailFilterConfigHandler: %v", r)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Internal server error: %v", r)})
		}
	}()
	config.DebugLog("----------------------------")
	config.DebugLog("SetJailFilterConfigHandler called (handlers.go)")
	jail := c.Param("jail")
	config.DebugLog("Jail name: %s", jail)

	if err := fail2ban.ValidateJailName(jail); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	conn, err := resolveConnector(c)
	if err != nil {
		config.DebugLog("Failed to resolve connector: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	config.DebugLog("Connector resolved: %s (type: %s)", conn.Server().Name, conn.Server().Type)

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

	if req.Filter != "" {
		originalJailCfg, _, err := conn.GetJailConfig(c.Request.Context(), jail)
		if err != nil {
			config.DebugLog("Failed to load original jail config to determine filter name: %v", err)
			originalJailCfg = req.Jail
		}

		// Extracts the original filter name (the one that was loaded when the modal opened)
		originalFilterName := fail2ban.ExtractFilterFromJailConfig(originalJailCfg)
		if originalFilterName == "" {
			// No filter directive found in original config, uses the jail name as filter name
			originalFilterName = jail
			config.DebugLog("No filter directive found in original jail config, using jail name as filter name: %s", originalFilterName)
		} else {
			config.DebugLog("Found original filter directive in jail config: %s", originalFilterName)
		}

		newFilterName := fail2ban.ExtractFilterFromJailConfig(req.Jail)
		if newFilterName == "" {
			newFilterName = jail
		}

		// If the filter name changed, saves to the original filter name
		// This prevents overwriting a different filter with the old filter's content
		if originalFilterName != newFilterName {
			config.DebugLog("Filter name changed from %s to %s, saving filter to original name: %s", originalFilterName, newFilterName, originalFilterName)
		} else {
			config.DebugLog("Filter name unchanged: %s", originalFilterName)
		}

		config.DebugLog("Saving filter config for filter: %s", originalFilterName)
		if err := conn.SetFilterConfig(c.Request.Context(), originalFilterName, req.Filter); err != nil {
			config.DebugLog("Failed to save filter config: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save filter config: " + err.Error()})
			return
		}
		config.DebugLog("Filter config saved successfully to filter: %s", originalFilterName)
	} else {
		config.DebugLog("No filter config provided, skipping")
	}

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

	config.DebugLog("Reloading fail2ban")
	if err := conn.Reload(c.Request.Context()); err != nil {
		log.Printf("WARNING: Config saved but fail2ban reload failed: %v", err)
		// If reload fails, we automatically disable the jail so Fail2ban won't crash on next restart (invalid filter/jail config)
		disableUpdate := map[string]bool{jail: false}
		if disableErr := conn.UpdateJailEnabledStates(c.Request.Context(), disableUpdate); disableErr != nil {
			log.Printf("WARNING: Failed to auto-disable jail %s after reload failure: %v", jail, disableErr)
			c.JSON(http.StatusOK, gin.H{
				"message": "Config saved successfully, but fail2ban reload failed",
				"warning": err.Error(),
			})
			return
		}
		if reloadErr2 := conn.Reload(c.Request.Context()); reloadErr2 != nil {
			log.Printf("WARNING: Failed to reload fail2ban after auto-disabling jail %s: %v", jail, reloadErr2)
		}
		c.JSON(http.StatusOK, gin.H{
			"message":          "Config saved successfully, but fail2ban reload failed",
			"warning":          err.Error(),
			"jailAutoDisabled": true,
			"jailName":         jail,
		})
		return
	}
	config.DebugLog("Fail2ban reloaded successfully")
	c.JSON(http.StatusOK, gin.H{"message": "Filter and jail config updated and fail2ban reloaded"})
}

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

// Validates that a jail's log path resolves to real files.
func TestLogpathHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("TestLogpathHandler called (handlers.go)")
	jail := c.Param("jail")
	if err := fail2ban.ValidateJailName(jail); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var originalLogpath string

	var reqBody struct {
		Logpath string `json:"logpath"`
	}
	if err := c.ShouldBindJSON(&reqBody); err == nil && reqBody.Logpath != "" {
		originalLogpath = strings.TrimSpace(reqBody.Logpath)
		config.DebugLog("Using logpath from request body: %s", originalLogpath)
	} else {
		// Falls back to reading from the saved jail config
		jailCfg, _, err := conn.GetJailConfig(c.Request.Context(), jail)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load jail config: " + err.Error()})
			return
		}

		originalLogpath = fail2ban.ExtractLogpathFromJailConfig(jailCfg)
		if originalLogpath == "" {
			c.JSON(http.StatusOK, gin.H{
				"original_logpath": "",
				"resolved_logpath": "",
				"files":            []string{},
				"message":          "No logpath configured for this jail",
			})
			return
		}
		config.DebugLog("Using logpath from saved jail config: %s", originalLogpath)
	}

	if originalLogpath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No logpath provided"})
		return
	}

	server := conn.Server()
	isLocalServer := server.Type == "local"

	// Splits the logpath by newlines and spaces (Fail2ban supports multiple logpaths separated by spaces or newlines)
	// First splits by newlines, then splits each line by spaces
	var logpaths []string
	for _, line := range strings.Split(originalLogpath, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		paths := strings.Fields(line)
		logpaths = append(logpaths, paths...)
	}

	var allResults []map[string]interface{}

	for _, logpathLine := range logpaths {
		logpathLine = strings.TrimSpace(logpathLine)
		if logpathLine == "" {
			continue
		}
		_, resolvedPath, filesOnServer, err := conn.TestLogpathWithResolution(c.Request.Context(), logpathLine)
		if err != nil {
			if errors.Is(err, fail2ban.ErrLogpathInaccessible) {
				allResults = append(allResults, map[string]interface{}{
					"logpath":       logpathLine,
					"resolved_path": resolvedPath,
					"found":         false,
					"inaccessible":  true,
					"files":         []string{},
					"error":         "",
					"message":       "Cannot verify: the log directory is not readable by the connector's SSH user. fail2ban runs as root and will read it, so the jail can still be enabled.",
				})
				continue
			}
			allResults = append(allResults, map[string]interface{}{
				"logpath":       logpathLine,
				"resolved_path": resolvedPath,
				"found":         false,
				"files":         []string{},
				"error":         err.Error(),
			})
			continue
		}
		allResults = append(allResults, map[string]interface{}{
			"logpath":       logpathLine,
			"resolved_path": resolvedPath,
			"found":         len(filesOnServer) > 0,
			"files":         filesOnServer,
			"error":         "",
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"original_logpath": originalLogpath,
		"is_local_server":  isLocalServer,
		"results":          allResults,
	})
}

// =========================================================================
//  Jail Management
// =========================================================================

// Returns all jails (enabled and disabled) for the manage-jails modal.
func ManageJailsHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("ManageJailsHandler called (handlers.go)")
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

func getJailNames(jails map[string]bool) []string {
	names := make([]string, 0, len(jails))
	for name := range jails {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func splitLogpaths(raw string) []string {
	var out []string
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		out = append(out, parts...)
	}
	return out
}

var jailErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`Errors in jail '([^']+)'`),
	regexp.MustCompile(`Have not found any log file for (\S+) jail`),
}

func parseJailErrorsFromReloadOutput(output string) []string {
	var problematicJails []string
	for _, line := range strings.Split(output, "\n") {
		for _, pattern := range jailErrorPatterns {
			for _, matches := range pattern.FindAllStringSubmatch(line, -1) {
				if len(matches) > 1 {
					problematicJails = append(problematicJails, matches[1])
				}
			}
		}
	}

	seen := make(map[string]bool)
	uniqueJails := []string{}
	for _, jail := range problematicJails {
		if !seen[jail] {
			seen[jail] = true
			uniqueJails = append(uniqueJails, jail)
		}
	}

	return uniqueJails
}

// Enables/disables jails and reloads Fail2ban.
func UpdateJailManagementHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("UpdateJailManagementHandler called (handlers.go)")
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

	// Validates every jail name before any filesystem operation.
	for jailName := range updates {
		if err := fail2ban.ValidateJailName(jailName); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	// Tracks which jails were enabled (for error recovery)
	enabledJails := make(map[string]bool)
	for jailName, enabled := range updates {
		if enabled {
			enabledJails[jailName] = true
		}
	}

	// Pre-validates logpath resolution for jails that are about to be enabled.
	// This prevents enabling jails with broken/non-existent logpaths.
	for jailName := range enabledJails {
		jailCfg, _, cfgErr := conn.GetJailConfig(c.Request.Context(), jailName)
		if cfgErr != nil {
			c.JSON(http.StatusOK, gin.H{
				"error": fmt.Sprintf("Jail '%s' cannot be enabled: failed to read jail config: %v", jailName, cfgErr),
			})
			return
		}

		rawLogpath := strings.TrimSpace(fail2ban.ExtractLogpathFromJailConfig(jailCfg))
		if rawLogpath == "" {
			c.JSON(http.StatusOK, gin.H{
				"error": fmt.Sprintf("Jail '%s' cannot be enabled: no logpath configured. Please configure a valid logpath first.", jailName),
			})
			return
		}

		paths := splitLogpaths(rawLogpath)
		if len(paths) == 0 {
			c.JSON(http.StatusOK, gin.H{
				"error": fmt.Sprintf("Jail '%s' cannot be enabled: logpath is empty after parsing. Please configure a valid logpath first.", jailName),
			})
			return
		}

		foundAnyFiles := false
		inaccessible := false
		var checkErrors []string
		for _, lp := range paths {
			_, resolvedPath, filesOnServer, testErr := conn.TestLogpathWithResolution(c.Request.Context(), lp)
			if testErr != nil {
				if errors.Is(testErr, fail2ban.ErrLogpathInaccessible) {
					inaccessible = true
					continue
				}
				checkErrors = append(checkErrors, fmt.Sprintf("%s (%v)", lp, testErr))
				continue
			}
			if len(filesOnServer) > 0 {
				foundAnyFiles = true
				break
			}
			if strings.TrimSpace(resolvedPath) == "" {
				resolvedPath = lp
			}
			checkErrors = append(checkErrors, fmt.Sprintf("%s (resolved: %s, no files found)", lp, resolvedPath))
		}

		if !foundAnyFiles {
			if inaccessible {
				log.Printf("WARNING: cannot verify logpath(s) for jail %s on server %s (log directory not readable by the connector's user); enabling anyway and relying on fail2ban (root) to read them",
					jailName, conn.Server().Name)
			} else {
				c.JSON(http.StatusOK, gin.H{
					"error": fmt.Sprintf("Jail '%s' cannot be enabled because no matching log files were found for its logpath(s): %s", jailName, strings.Join(checkErrors, "; ")),
				})
				return
			}
		}
	}

	if err := conn.UpdateJailEnabledStates(c.Request.Context(), updates); err != nil {
		config.DebugLog("Error updating jail enabled states: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update jail settings: " + err.Error()})
		return
	}
	config.DebugLog("Successfully updated jail enabled states")

	// Reloads fail2ban to apply the changes
	reloadErr := conn.Reload(c.Request.Context())

	var problematicJails []string
	var detailedErrorOutput string
	if reloadErr != nil {
		errMsg := reloadErr.Error()
		config.DebugLog("Error: failed to reload fail2ban after updating jail settings: %v", reloadErr)

		if output, ok := fail2ban.CommandOutput(reloadErr); ok {
			detailedErrorOutput = output
			problematicJails = parseJailErrorsFromReloadOutput(detailedErrorOutput)
		} else if idx := strings.Index(errMsg, "output:"); idx >= 0 {
			detailedErrorOutput = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(errMsg[idx+len("output:"):]), ")"))
			problematicJails = parseJailErrorsFromReloadOutput(detailedErrorOutput)
		}

		if detailedErrorOutput != "" {
			errMsg = strings.TrimSpace(detailedErrorOutput)
		}

		if len(problematicJails) > 0 {
			config.DebugLog("Found %d problematic jail(s) in reload output: %v", len(problematicJails), problematicJails)

			disableUpdate := make(map[string]bool)
			for _, jailName := range problematicJails {
				disableUpdate[jailName] = false
			}

			if disableErr := conn.UpdateJailEnabledStates(c.Request.Context(), disableUpdate); disableErr != nil {
				config.DebugLog("Error disabling problematic jails: %v", disableErr)
			} else if reloadErr2 := conn.Reload(c.Request.Context()); reloadErr2 != nil {
				config.DebugLog("Error: failed to reload fail2ban after disabling problematic jails: %v", reloadErr2)
			} else {
				// Recovered by disabling the offenders only
				var revertedToggled []string
				for _, jailName := range problematicJails {
					if enabledJails[jailName] {
						revertedToggled = append(revertedToggled, jailName)
					}
				}
				if len(revertedToggled) > 0 {
					c.JSON(http.StatusOK, gin.H{
						"error":         fmt.Sprintf("Jail '%s' was enabled but caused a reload error: %s. It has been automatically disabled.", strings.Join(revertedToggled, "', '"), errMsg),
						"autoDisabled":  true,
						"enabledJails":  revertedToggled,
						"disabledJails": problematicJails,
					})
					return
				}
				config.DebugLog("Disabled unrelated broken jail(s) %v; requested change kept", problematicJails)
				c.JSON(http.StatusOK, gin.H{
					"message":       fmt.Sprintf("Your change was applied. Unrelated jail '%s' has a broken configuration and was automatically disabled (%s).", strings.Join(problematicJails, "', '"), errMsg),
					"messageKey":    "jails.manage.offender_disabled",
					"disabledJails": problematicJails,
				})
				return
			}
		}

		if len(enabledJails) > 0 {
			config.DebugLog("Reload failed after enabling %d jail(s), auto-disabling all enabled jails: %v", len(enabledJails), enabledJails)

			disableUpdate := make(map[string]bool)
			for jailName := range enabledJails {
				disableUpdate[jailName] = false
			}

			if disableErr := conn.UpdateJailEnabledStates(c.Request.Context(), disableUpdate); disableErr != nil {
				config.DebugLog("Error disabling jails after reload failure: %v", disableErr)
				c.JSON(http.StatusOK, gin.H{
					"error":        fmt.Sprintf("Failed to reload fail2ban: %s. Additionally, failed to auto-disable enabled jails: %v", errMsg, disableErr),
					"autoDisabled": false,
					"enabledJails": getJailNames(enabledJails),
				})
				return
			}

			// Reloads again after disabling
			if reloadErr = conn.Reload(c.Request.Context()); reloadErr != nil {
				config.DebugLog("Error: failed to reload fail2ban after disabling jails: %v", reloadErr)
				c.JSON(http.StatusOK, gin.H{
					"error":        fmt.Sprintf("Failed to reload fail2ban after disabling jails: %v", reloadErr),
					"autoDisabled": true,
					"enabledJails": getJailNames(enabledJails),
				})
				return
			}

			config.DebugLog("Successfully disabled %d jail(s) and reloaded fail2ban", len(enabledJails))
			jailNamesList := getJailNames(enabledJails)
			if len(jailNamesList) == 1 {
				c.JSON(http.StatusOK, gin.H{
					"error":        fmt.Sprintf("Jail '%s' was enabled but caused a reload error: %s. It has been automatically disabled.", jailNamesList[0], errMsg),
					"autoDisabled": true,
					"enabledJails": jailNamesList,
					"message":      fmt.Sprintf("Jail '%s' was automatically disabled due to configuration error", jailNamesList[0]),
				})
			} else {
				c.JSON(http.StatusOK, gin.H{
					"error":        fmt.Sprintf("Jails %v were enabled but caused a reload error: %s. They have been automatically disabled.", jailNamesList, errMsg),
					"autoDisabled": true,
					"enabledJails": jailNamesList,
					"message":      fmt.Sprintf("%d jail(s) were automatically disabled due to configuration error", len(jailNamesList)),
				})
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"error": fmt.Sprintf("Failed to reload fail2ban: %s", errMsg),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Jail settings updated and fail2ban reloaded successfully"})
}

// Creates a new jail with the given name and optional config.
func CreateJailHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("CreateJailHandler called (handlers.go)")

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var req struct {
		JailName string `json:"jailName" binding:"required"`
		Content  string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON: " + err.Error()})
		return
	}

	if err := fail2ban.ValidateJailName(req.JailName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Content == "" {
		req.Content = fmt.Sprintf("[%s]\nenabled = false\n", req.JailName)
	}

	if err := conn.CreateJail(c.Request.Context(), req.JailName, req.Content); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create jail: " + err.Error()})
		return
	}

	// The new jail file is on disk but inactive until fail2ban re-reads its config.
	if err := conn.Reload(c.Request.Context()); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("Jail '%s' created, but fail2ban reload reported a problem", req.JailName),
			"warning": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Jail '%s' created and applied successfully", req.JailName)})
}

// Removes a jail and its config file.
func DeleteJailHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("DeleteJailHandler called (handlers.go)")

	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	jailName := c.Param("jail")
	if jailName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Jail name is required"})
		return
	}

	if err := fail2ban.ValidateJailName(jailName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := conn.DeleteJail(c.Request.Context(), jailName); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete jail: " + err.Error()})
		return
	}

	// Reload so the removed jail is actually stopped on the daemon.
	if err := conn.Reload(c.Request.Context()); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("Jail '%s' deleted, but fail2ban reload reported a problem", jailName),
			"warning": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Jail '%s' deleted and applied successfully", jailName)})
}
