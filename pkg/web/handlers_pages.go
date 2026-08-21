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
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
	"github.com/swissmakers/fail2ban-ui/internal/httpx"
	"github.com/swissmakers/fail2ban-ui/internal/version"
)

type localeOption struct {
	Code  string
	Label string
}

type githubReleaseResponse struct {
	TagName string `json:"tag_name"`
}

// =========================================================================
//  Page Rendering
// =========================================================================

// Renders the main SPA page with template variables.
func renderIndexPage(c *gin.Context) {
	disableExternalIP := os.Getenv("DISABLE_EXTERNAL_IP_LOOKUP") == "true" || os.Getenv("DISABLE_EXTERNAL_IP_LOOKUP") == "1"
	autoDark := os.Getenv("AUTODARK") == "true" || os.Getenv("AUTODARK") == "1"
	languageOptions := listLocaleOptions()

	oidcEnabled := auth.IsEnabled()
	skipLoginPage := false
	if oidcEnabled {
		oidcConfig := auth.GetConfig()
		if oidcConfig != nil {
			skipLoginPage = oidcConfig.SkipLoginPage
		}
	}

	updateCheckEnabled := os.Getenv("UPDATE_CHECK") != "false"

	urlPrefix := BasePath()

	c.HTML(http.StatusOK, "index.html", gin.H{
		"timestamp":          time.Now().Format(time.RFC1123),
		"version":            time.Now().Unix(),
		"appVersion":         version.Version,
		"updateCheckEnabled": updateCheckEnabled,
		"disableExternalIP":  disableExternalIP,
		"autoDark":           autoDark,
		"languageOptions":    languageOptions,
		"oidcEnabled":        oidcEnabled,
		"skipLoginPage":      skipLoginPage,
		"URLPrefix":          urlPrefix,
	})
}

func listLocaleOptions() []localeOption {
	entries, err := fs.ReadDir(LocalesFS, ".")
	if err != nil {
		return []localeOption{{Code: "en", Label: "en"}}
	}
	options := make([]localeOption, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}
		code := strings.TrimSuffix(name, ".json")
		if code == "" {
			continue
		}
		data, readErr := fs.ReadFile(LocalesFS, name)
		label := code
		if readErr == nil {
			label = localeLabelFromJSON(data, code)
		}
		options = append(options, localeOption{
			Code:  code,
			Label: label,
		})
	}
	if len(options) == 0 {
		return []localeOption{{Code: "en", Label: "en"}}
	}
	sort.Slice(options, func(i, j int) bool {
		if options[i].Code == "en" {
			return true
		}
		if options[j].Code == "en" {
			return false
		}
		return strings.ToLower(options[i].Label) < strings.ToLower(options[j].Label)
	})

	return options
}

func localeLabelFromJSON(data []byte, fallback string) string {
	if len(data) == 0 {
		return fallback
	}
	var translations map[string]string
	if err := json.Unmarshal(data, &translations); err != nil {
		return fallback
	}
	if label, ok := translations["meta.language_name"]; ok && strings.TrimSpace(label) != "" {
		return label
	}
	return fallback
}

// =========================================================================
//  Version
// =========================================================================

// Returns the app version and checks GitHub for updates.
func GetVersionHandler(c *gin.Context) {
	updateCheckEnabled := os.Getenv("UPDATE_CHECK") != "false"
	out := gin.H{
		"version":              version.Version,
		"update_check_enabled": updateCheckEnabled,
	}
	if !updateCheckEnabled {
		c.JSON(http.StatusOK, out)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/swissmakers/fail2ban-ui/releases/latest", nil)
	if err != nil {
		c.JSON(http.StatusOK, out)
		return
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := httpx.Client(10*time.Second, false).Do(req)
	if err != nil {
		c.JSON(http.StatusOK, out)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusOK, out)
		return
	}
	body, err := httpx.ReadLimited(resp.Body)
	if err != nil {
		c.JSON(http.StatusOK, out)
		return
	}
	var gh githubReleaseResponse
	if err := json.Unmarshal(body, &gh); err != nil {
		c.JSON(http.StatusOK, out)
		return
	}
	latest := strings.TrimPrefix(strings.TrimSpace(gh.TagName), "v")
	out["latest_version"] = latest
	out["update_available"] = versionLess(version.Version, latest)
	c.JSON(http.StatusOK, out)
}

// Checks if a version is less than another version.
func versionLess(a, b string) bool {
	parse := func(s string) []int {
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		parts := strings.Split(s, ".")
		out := make([]int, 0, len(parts))
		for _, p := range parts {
			n, _ := strconv.Atoi(p)
			out = append(out, n)
		}
		return out
	}
	pa, pb := parse(a), parse(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		va, vb := 0, 0
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va < vb {
			return true
		}
		if va > vb {
			return false
		}
	}
	return false
}
