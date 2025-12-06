// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2025 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fail2ban

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// GetFilterConfig returns the filter configuration using the default connector.
func GetFilterConfig(jail string) (string, error) {
	conn, err := GetManager().DefaultConnector()
	if err != nil {
		return "", err
	}
	return conn.GetFilterConfig(context.Background(), jail)
}

// SetFilterConfig writes the filter configuration using the default connector.
func SetFilterConfig(jail, newContent string) error {
	conn, err := GetManager().DefaultConnector()
	if err != nil {
		return err
	}
	return conn.SetFilterConfig(context.Background(), jail, newContent)
}

// ensureFilterLocalFile ensures that a .local file exists for the given filter.
// If .local doesn't exist, it copies from .conf if available.
// Returns error if neither .local nor .conf exists (filters must have base .conf).
func ensureFilterLocalFile(filterName string) error {
	// Validate filter name - must not be empty
	filterName = strings.TrimSpace(filterName)
	if filterName == "" {
		return fmt.Errorf("filter name cannot be empty")
	}

	filterDPath := "/etc/fail2ban/filter.d"
	localPath := filepath.Join(filterDPath, filterName+".local")
	confPath := filepath.Join(filterDPath, filterName+".conf")

	// Check if .local already exists
	if _, err := os.Stat(localPath); err == nil {
		config.DebugLog("Filter .local file already exists: %s", localPath)
		return nil
	}

	// Try to copy from .conf if it exists
	if _, err := os.Stat(confPath); err == nil {
		config.DebugLog("Copying filter config from .conf to .local: %s -> %s", confPath, localPath)
		content, err := os.ReadFile(confPath)
		if err != nil {
			return fmt.Errorf("failed to read filter .conf file %s: %w", confPath, err)
		}
		if err := os.WriteFile(localPath, content, 0644); err != nil {
			return fmt.Errorf("failed to write filter .local file %s: %w", localPath, err)
		}
		config.DebugLog("Successfully copied filter config to .local file")
		return nil
	}

	// Neither exists, return error (filters must have base .conf)
	return fmt.Errorf("filter .conf file does not exist: %s (filters must have a base .conf file)", confPath)
}

// readFilterConfigWithFallback reads filter config from .local first, then falls back to .conf.
func readFilterConfigWithFallback(filterName string) (string, error) {
	// Validate filter name - must not be empty
	filterName = strings.TrimSpace(filterName)
	if filterName == "" {
		return "", fmt.Errorf("filter name cannot be empty")
	}

	filterDPath := "/etc/fail2ban/filter.d"
	localPath := filepath.Join(filterDPath, filterName+".local")
	confPath := filepath.Join(filterDPath, filterName+".conf")

	// Try .local first
	if content, err := os.ReadFile(localPath); err == nil {
		config.DebugLog("Reading filter config from .local: %s", localPath)
		return string(content), nil
	}

	// Fallback to .conf
	if content, err := os.ReadFile(confPath); err == nil {
		config.DebugLog("Reading filter config from .conf: %s", confPath)
		return string(content), nil
	}

	// Neither exists, return error
	return "", fmt.Errorf("filter config not found: neither %s nor %s exists", localPath, confPath)
}

// GetFilterConfigLocal reads a filter configuration from the local filesystem.
// Prefers .local over .conf files.
func GetFilterConfigLocal(jail string) (string, error) {
	return readFilterConfigWithFallback(jail)
}

// SetFilterConfigLocal writes the filter configuration to the local filesystem.
// Always writes to .local file, ensuring it exists first by copying from .conf if needed.
func SetFilterConfigLocal(jail, newContent string) error {
	// Ensure .local file exists (copy from .conf if needed)
	if err := ensureFilterLocalFile(jail); err != nil {
		return err
	}

	localPath := filepath.Join("/etc/fail2ban/filter.d", jail+".local")
	if err := os.WriteFile(localPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write filter .local file for %s: %w", jail, err)
	}
	config.DebugLog("Successfully wrote filter config to .local file: %s", localPath)
	return nil
}

// GetFiltersLocal returns a list of filter names from /etc/fail2ban/filter.d
// Returns unique filter names from both .conf and .local files (prefers .local if both exist)
func GetFiltersLocal() ([]string, error) {
	dir := "/etc/fail2ban/filter.d"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read filter directory: %w", err)
	}
	filterMap := make(map[string]bool)

	// First pass: collect all .local files (these take precedence)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".local") {
			name := strings.TrimSuffix(entry.Name(), ".local")
			filterMap[name] = true
		}
	}

	// Second pass: collect .conf files that don't have corresponding .local files
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
			name := strings.TrimSuffix(entry.Name(), ".conf")
			if !filterMap[name] {
				filterMap[name] = true
			}
		}
	}

	var filters []string
	for name := range filterMap {
		filters = append(filters, name)
	}
	sort.Strings(filters)
	return filters, nil
}

func normalizeLogLines(logLines []string) []string {
	var cleaned []string
	for _, line := range logLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cleaned = append(cleaned, line)
	}
	return cleaned
}

// TestFilterLocal tests a filter against log lines using fail2ban-regex
// Returns the full output of fail2ban-regex command and the filter path used
// Uses .local file if it exists, otherwise falls back to .conf file
func TestFilterLocal(filterName string, logLines []string) (string, string, error) {
	cleaned := normalizeLogLines(logLines)
	if len(cleaned) == 0 {
		return "No log lines provided.\n", "", nil
	}

	// Try .local first, then fallback to .conf
	localPath := filepath.Join("/etc/fail2ban/filter.d", filterName+".local")
	confPath := filepath.Join("/etc/fail2ban/filter.d", filterName+".conf")

	var filterPath string
	if _, err := os.Stat(localPath); err == nil {
		filterPath = localPath
		config.DebugLog("TestFilterLocal: using .local file: %s", filterPath)
	} else if _, err := os.Stat(confPath); err == nil {
		filterPath = confPath
		config.DebugLog("TestFilterLocal: using .conf file: %s", filterPath)
	} else {
		return "", "", fmt.Errorf("filter %s not found (checked both .local and .conf): %w", filterName, err)
	}

	// Create a temporary log file with all log lines
	tmpFile, err := os.CreateTemp("", "fail2ban-test-*.log")
	if err != nil {
		return "", filterPath, fmt.Errorf("failed to create temporary log file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write all log lines to the temp file
	for _, logLine := range cleaned {
		if _, err := tmpFile.WriteString(logLine + "\n"); err != nil {
			return "", filterPath, fmt.Errorf("failed to write to temporary log file: %w", err)
		}
	}
	tmpFile.Close()

	// Run fail2ban-regex with the log file and filter config
	// Format: fail2ban-regex /path/to/logfile /etc/fail2ban/filter.d/filter-name.conf
	cmd := exec.Command("fail2ban-regex", tmpFile.Name(), filterPath)
	out, _ := cmd.CombinedOutput()
	output := string(out)

	// Return the full output regardless of exit code (fail2ban-regex may exit non-zero for no matches)
	// The output contains useful information even when there are no matches
	return output, filterPath, nil
}
