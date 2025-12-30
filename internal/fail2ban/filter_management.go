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
	"regexp"
	"sort"
	"strings"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// GetFilterConfig returns the filter configuration using the default connector.
// Returns (config, filePath, error)
func GetFilterConfig(jail string) (string, string, error) {
	conn, err := GetManager().DefaultConnector()
	if err != nil {
		return "", "", err
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
// If .local doesn't exist, it copies from .conf if available, or creates an empty file.
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

	// Neither exists, create empty .local file
	config.DebugLog("Neither .local nor .conf exists for filter %s, creating empty .local file", filterName)
	if err := os.WriteFile(localPath, []byte(""), 0644); err != nil {
		return fmt.Errorf("failed to create empty filter .local file %s: %w", localPath, err)
	}
	config.DebugLog("Successfully created empty filter .local file: %s", localPath)
	return nil
}

// readFilterConfigWithFallback reads filter config from .local first, then falls back to .conf.
// Returns (content, filePath, error)
func readFilterConfigWithFallback(filterName string) (string, string, error) {
	// Validate filter name - must not be empty
	filterName = strings.TrimSpace(filterName)
	if filterName == "" {
		return "", "", fmt.Errorf("filter name cannot be empty")
	}

	filterDPath := "/etc/fail2ban/filter.d"
	localPath := filepath.Join(filterDPath, filterName+".local")
	confPath := filepath.Join(filterDPath, filterName+".conf")

	// Try .local first
	if content, err := os.ReadFile(localPath); err == nil {
		config.DebugLog("Reading filter config from .local: %s", localPath)
		return string(content), localPath, nil
	}

	// Fallback to .conf
	if content, err := os.ReadFile(confPath); err == nil {
		config.DebugLog("Reading filter config from .conf: %s", confPath)
		return string(content), confPath, nil
	}

	// Neither exists, return error with .local path (will be created on save)
	return "", localPath, fmt.Errorf("filter config not found: neither %s nor %s exists", localPath, confPath)
}

// GetFilterConfigLocal reads a filter configuration from the local filesystem.
// Prefers .local over .conf files.
// Returns (content, filePath, error)
func GetFilterConfigLocal(jail string) (string, string, error) {
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

// ValidateFilterName validates a filter name format.
// Returns an error if the name is invalid (empty, contains invalid characters, or is reserved).
func ValidateFilterName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("filter name cannot be empty")
	}

	// Check for invalid characters (only alphanumeric, dash, underscore allowed)
	invalidChars := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	if invalidChars.MatchString(name) {
		return fmt.Errorf("filter name '%s' contains invalid characters. Only alphanumeric characters, dashes, and underscores are allowed", name)
	}

	return nil
}

// ListFilterFiles lists all filter files in the specified directory.
// Returns full paths to .local and .conf files.
func ListFilterFiles(directory string) ([]string, error) {
	var files []string

	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("failed to read filter directory %s: %w", directory, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Skip hidden files and invalid names
		if strings.HasPrefix(name, ".") {
			continue
		}

		// Only include .local and .conf files
		if strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".conf") {
			fullPath := filepath.Join(directory, name)
			files = append(files, fullPath)
		}
	}

	return files, nil
}

// DiscoverFiltersFromFiles discovers all filters from the filesystem.
// Reads from /etc/fail2ban/filter.d/ directory, preferring .local files over .conf files.
// Returns unique filter names.
func DiscoverFiltersFromFiles() ([]string, error) {
	filterDPath := "/etc/fail2ban/filter.d"

	// Check if directory exists
	if _, err := os.Stat(filterDPath); os.IsNotExist(err) {
		// Directory doesn't exist, return empty list
		return []string{}, nil
	}

	// List all filter files
	files, err := ListFilterFiles(filterDPath)
	if err != nil {
		return nil, err
	}

	filterMap := make(map[string]bool)      // Track unique filter names
	processedFiles := make(map[string]bool) // Track base names to avoid duplicates

	// First pass: collect all .local files (these take precedence)
	for _, filePath := range files {
		if !strings.HasSuffix(filePath, ".local") {
			continue
		}

		filename := filepath.Base(filePath)
		baseName := strings.TrimSuffix(filename, ".local")
		if baseName == "" {
			continue
		}

		// Skip if we've already processed this base name
		if processedFiles[baseName] {
			continue
		}

		processedFiles[baseName] = true
		filterMap[baseName] = true
	}

	// Second pass: collect .conf files that don't have corresponding .local files
	for _, filePath := range files {
		if !strings.HasSuffix(filePath, ".conf") {
			continue
		}

		filename := filepath.Base(filePath)
		baseName := strings.TrimSuffix(filename, ".conf")
		if baseName == "" {
			continue
		}

		// Skip if we've already processed a .local file with the same base name
		if processedFiles[baseName] {
			continue
		}

		processedFiles[baseName] = true
		filterMap[baseName] = true
	}

	// Convert map to sorted slice
	var filters []string
	for name := range filterMap {
		filters = append(filters, name)
	}
	sort.Strings(filters)

	return filters, nil
}

// CreateFilter creates a new filter in filter.d/{name}.local.
// If the filter already exists, it will be overwritten.
func CreateFilter(filterName, content string) error {
	if err := ValidateFilterName(filterName); err != nil {
		return err
	}

	filterDPath := "/etc/fail2ban/filter.d"
	localPath := filepath.Join(filterDPath, filterName+".local")

	// Ensure directory exists
	if err := os.MkdirAll(filterDPath, 0755); err != nil {
		return fmt.Errorf("failed to create filter.d directory: %w", err)
	}

	// Write the file
	if err := os.WriteFile(localPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create filter file %s: %w", localPath, err)
	}

	config.DebugLog("Created filter file: %s", localPath)
	return nil
}

// DeleteFilter deletes a filter's .local and .conf files from filter.d/ if they exist.
// Both files are deleted to ensure complete removal of the filter configuration.
func DeleteFilter(filterName string) error {
	if err := ValidateFilterName(filterName); err != nil {
		return err
	}

	filterDPath := "/etc/fail2ban/filter.d"
	localPath := filepath.Join(filterDPath, filterName+".local")
	confPath := filepath.Join(filterDPath, filterName+".conf")

	var deletedFiles []string
	var lastErr error

	// Delete .local file if it exists
	if _, err := os.Stat(localPath); err == nil {
		if err := os.Remove(localPath); err != nil {
			lastErr = fmt.Errorf("failed to delete filter file %s: %w", localPath, err)
		} else {
			deletedFiles = append(deletedFiles, localPath)
			config.DebugLog("Deleted filter file: %s", localPath)
		}
	}

	// Delete .conf file if it exists
	if _, err := os.Stat(confPath); err == nil {
		if err := os.Remove(confPath); err != nil {
			lastErr = fmt.Errorf("failed to delete filter file %s: %w", confPath, err)
		} else {
			deletedFiles = append(deletedFiles, confPath)
			config.DebugLog("Deleted filter file: %s", confPath)
		}
	}

	// If no files were deleted and no error occurred, it means neither file existed
	if len(deletedFiles) == 0 && lastErr == nil {
		return fmt.Errorf("filter file %s or %s does not exist", localPath, confPath)
	}

	// Return the last error if any occurred
	if lastErr != nil {
		return lastErr
	}

	return nil
}

// GetFiltersLocal returns a list of filter names from /etc/fail2ban/filter.d
// Returns unique filter names from both .conf and .local files (prefers .local if both exist)
// This is the canonical implementation - now uses DiscoverFiltersFromFiles()
func GetFiltersLocal() ([]string, error) {
	return DiscoverFiltersFromFiles()
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
