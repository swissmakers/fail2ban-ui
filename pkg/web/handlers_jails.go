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
	config.DebugLog("GetJailFilterConfigHandler called")
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
	filterName := fail2ban.FilterNameForJail(jail, jailCfg)

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
	submitOperation(c, "jail.config")
}

// Validates that a jail's log path resolves to real files.
func TestLogpathHandler(c *gin.Context) {
	config.DebugLog("----------------------------")
	config.DebugLog("TestLogpathHandler called")
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
	// Fail2ban accepts several logpaths separated by spaces or newlines.
	logpaths := strings.Fields(originalLogpath)

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
					"message":       "Cannot verify: the connector cannot read the log directory. Check its directory permissions. Fail2Ban must validate the configuration before the jail can be enabled.",
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
	config.DebugLog("ManageJailsHandler called")
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	view, err := SnapshotForServer(c.Request.Context(), conn)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load jails: " + err.Error()})
		return
	}
	resp := snapshotMetadata(view)
	resp["jails"] = view.Configured
	c.JSON(http.StatusOK, resp)
}

func getJailNames(jails map[string]bool) []string {
	names := make([]string, 0, len(jails))
	for name := range jails {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
	submitOperation(c, "jail.manage")
}

// Creates a new jail with the given name and optional config.
func CreateJailHandler(c *gin.Context) {
	submitOperation(c, "jail.create")
}

// Removes a jail and its config file.
func DeleteJailHandler(c *gin.Context) {
	submitOperation(c, "jail.delete")
}

// Active jails count too a jail defined only in jail.conf (such as sshd for example) has no jail.d file
func jailNameTaken(name string, defined, active []fail2ban.JailInfo) bool {
	for _, list := range [][]fail2ban.JailInfo{defined, active} {
		for _, j := range list {
			if j.JailName == name {
				return true
			}
		}
	}
	return false
}
