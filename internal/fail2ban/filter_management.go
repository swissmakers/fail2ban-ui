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

// RemoveComments removes all lines that start with # (comments) from filter content
// and trims leading/trailing empty newlines
// This is exported for use in handlers that need to display filter content without comments
func RemoveComments(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip lines that start with # (comments)
		if !strings.HasPrefix(trimmed, "#") {
			result = append(result, line)
		}
	}

	// Remove leading empty lines
	for len(result) > 0 && strings.TrimSpace(result[0]) == "" {
		result = result[1:]
	}

	// Remove trailing empty lines
	for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
		result = result[:len(result)-1]
	}

	return strings.Join(result, "\n")
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

// extractVariablesFromContent extracts variable names from [DEFAULT] section of filter content
func extractVariablesFromContent(content string) map[string]bool {
	variables := make(map[string]bool)
	lines := strings.Split(content, "\n")
	inDefaultSection := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check for [DEFAULT] section
		if strings.HasPrefix(trimmed, "[DEFAULT]") {
			inDefaultSection = true
			continue
		}

		// Check for end of [DEFAULT] section (next section starts)
		if inDefaultSection && strings.HasPrefix(trimmed, "[") {
			inDefaultSection = false
			continue
		}

		// Extract variable name from [DEFAULT] section
		if inDefaultSection && !strings.HasPrefix(trimmed, "#") && strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				varName := strings.TrimSpace(parts[0])
				if varName != "" {
					variables[varName] = true
				}
			}
		}
	}

	return variables
}

// removeDuplicateVariables removes variable definitions from included content that already exist in main filter
func removeDuplicateVariables(includedContent string, mainVariables map[string]bool) string {
	lines := strings.Split(includedContent, "\n")
	var result strings.Builder
	inDefaultSection := false
	removedCount := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		originalLine := line

		// Check for [DEFAULT] section
		if strings.HasPrefix(trimmed, "[DEFAULT]") {
			inDefaultSection = true
			result.WriteString(originalLine)
			result.WriteString("\n")
			continue
		}

		// Check for end of [DEFAULT] section (next section starts)
		if inDefaultSection && strings.HasPrefix(trimmed, "[") {
			inDefaultSection = false
			result.WriteString(originalLine)
			result.WriteString("\n")
			continue
		}

		// In [DEFAULT] section, check if variable already exists in main filter
		if inDefaultSection && !strings.HasPrefix(trimmed, "#") && strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				varName := strings.TrimSpace(parts[0])
				if mainVariables[varName] {
					// Skip this line - variable will be defined in main filter (takes precedence)
					removedCount++
					config.DebugLog("Removing variable '%s' from included file (will be overridden by main filter)", varName)
					continue
				}
			}
		}

		result.WriteString(originalLine)
		result.WriteString("\n")
	}

	if removedCount > 0 {
		config.DebugLog("Removed %d variable definitions from included file (overridden by main filter)", removedCount)
	}

	return result.String()
}

// resolveFilterIncludes parses the filter content to find [INCLUDES] section
// and loads the included files, combining them with the main filter content.
// Returns: combined content with before files + main filter + after files
// Duplicate variables in main filter are removed if they exist in included files
// currentFilterName: name of the current filter being tested (to avoid self-inclusion)
func resolveFilterIncludes(filterContent string, filterDPath string, currentFilterName string) (string, error) {
	lines := strings.Split(filterContent, "\n")
	var beforeFiles []string
	var afterFiles []string
	var inIncludesSection bool
	var mainContent strings.Builder

	// Parse the filter content to find [INCLUDES] section
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check for [INCLUDES] section
		if strings.HasPrefix(trimmed, "[INCLUDES]") {
			inIncludesSection = true
			continue
		}

		// Check for end of [INCLUDES] section (next section starts)
		if inIncludesSection && strings.HasPrefix(trimmed, "[") {
			inIncludesSection = false
		}

		// Parse before and after directives
		if inIncludesSection {
			if strings.HasPrefix(strings.ToLower(trimmed), "before") {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					file := strings.TrimSpace(parts[1])
					if file != "" {
						beforeFiles = append(beforeFiles, file)
					}
				}
				continue
			}
			if strings.HasPrefix(strings.ToLower(trimmed), "after") {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					file := strings.TrimSpace(parts[1])
					if file != "" {
						afterFiles = append(afterFiles, file)
					}
				}
				continue
			}
		}

		// Collect main content (everything except [INCLUDES] section)
		if !inIncludesSection {
			if i > 0 {
				mainContent.WriteString("\n")
			}
			mainContent.WriteString(line)
		}
	}

	// Extract variables from main filter content first
	mainContentStr := mainContent.String()
	mainVariables := extractVariablesFromContent(mainContentStr)

	// Build combined content: before files + main filter + after files
	var combined strings.Builder

	// Load and append before files, removing duplicates that exist in main filter
	for _, fileName := range beforeFiles {
		// Remove any existing extension to get base name
		baseName := fileName
		if strings.HasSuffix(baseName, ".local") {
			baseName = strings.TrimSuffix(baseName, ".local")
		} else if strings.HasSuffix(baseName, ".conf") {
			baseName = strings.TrimSuffix(baseName, ".conf")
		}

		// Skip if this is the same filter (avoid self-inclusion)
		if baseName == currentFilterName {
			config.DebugLog("Skipping self-inclusion of filter '%s' in before files", baseName)
			continue
		}

		// Always try .local first, then .conf (matching fail2ban's behavior)
		localPath := filepath.Join(filterDPath, baseName+".local")
		confPath := filepath.Join(filterDPath, baseName+".conf")

		var content []byte
		var err error
		var filePath string

		// Try .local first
		if content, err = os.ReadFile(localPath); err == nil {
			filePath = localPath
			config.DebugLog("Loading included filter file from .local: %s", filePath)
		} else if content, err = os.ReadFile(confPath); err == nil {
			filePath = confPath
			config.DebugLog("Loading included filter file from .conf: %s", filePath)
		} else {
			config.DebugLog("Warning: could not load included filter file '%s' or '%s': %v", localPath, confPath, err)
			continue // Skip if neither file exists
		}

		contentStr := string(content)
		// Remove variables from included file that are defined in main filter (main filter takes precedence)
		cleanedContent := removeDuplicateVariables(contentStr, mainVariables)
		combined.WriteString(cleanedContent)
		if !strings.HasSuffix(cleanedContent, "\n") {
			combined.WriteString("\n")
		}
		combined.WriteString("\n")
	}

	// Append main filter content (unchanged - this is what the user is editing)
	combined.WriteString(mainContentStr)
	if !strings.HasSuffix(mainContentStr, "\n") {
		combined.WriteString("\n")
	}

	// Load and append after files, also removing duplicates that exist in main filter
	for _, fileName := range afterFiles {
		// Remove any existing extension to get base name
		baseName := fileName
		if strings.HasSuffix(baseName, ".local") {
			baseName = strings.TrimSuffix(baseName, ".local")
		} else if strings.HasSuffix(baseName, ".conf") {
			baseName = strings.TrimSuffix(baseName, ".conf")
		}

		// Note: Self-inclusion in "after" directive is intentional in fail2ban
		// (e.g., after = apache-common.local is standard pattern for .local files)
		// So we always load it, even if it's the same filter name

		// Always try .local first, then .conf (matching fail2ban's behavior)
		localPath := filepath.Join(filterDPath, baseName+".local")
		confPath := filepath.Join(filterDPath, baseName+".conf")

		var content []byte
		var err error
		var filePath string

		// Try .local first
		if content, err = os.ReadFile(localPath); err == nil {
			filePath = localPath
			config.DebugLog("Loading included filter file from .local: %s", filePath)
		} else if content, err = os.ReadFile(confPath); err == nil {
			filePath = confPath
			config.DebugLog("Loading included filter file from .conf: %s", filePath)
		} else {
			config.DebugLog("Warning: could not load included filter file '%s' or '%s': %v", localPath, confPath, err)
			continue // Skip if neither file exists
		}

		contentStr := string(content)
		// Remove variables from included file that are defined in main filter (main filter takes precedence)
		cleanedContent := removeDuplicateVariables(contentStr, mainVariables)
		combined.WriteString("\n")
		combined.WriteString(cleanedContent)
		if !strings.HasSuffix(cleanedContent, "\n") {
			combined.WriteString("\n")
		}
	}

	return combined.String(), nil
}

// TestFilterLocal tests a filter against log lines using fail2ban-regex
// Returns the full output of fail2ban-regex command and the filter path used
// Uses .local file if it exists, otherwise falls back to .conf file
// If filterContent is provided, it creates a temporary filter file and uses that instead
func TestFilterLocal(filterName string, logLines []string, filterContent string) (string, string, error) {
	cleaned := normalizeLogLines(logLines)
	if len(cleaned) == 0 {
		return "No log lines provided.\n", "", nil
	}

	var filterPath string
	var tempFilterFile *os.File
	var err error

	// If custom filter content is provided, create a temporary filter file
	if filterContent != "" {
		tempFilterFile, err = os.CreateTemp("", "fail2ban-filter-*.conf")
		if err != nil {
			return "", "", fmt.Errorf("failed to create temporary filter file: %w", err)
		}
		defer os.Remove(tempFilterFile.Name())
		defer tempFilterFile.Close()

		// Resolve filter includes to get complete filter content with all dependencies
		filterDPath := "/etc/fail2ban/filter.d"
		contentToWrite, err := resolveFilterIncludes(filterContent, filterDPath, filterName)
		if err != nil {
			config.DebugLog("Warning: failed to resolve filter includes, using original content: %v", err)
			contentToWrite = filterContent
		}

		// Ensure it ends with a newline for proper parsing
		if !strings.HasSuffix(contentToWrite, "\n") {
			contentToWrite += "\n"
		}

		if _, err := tempFilterFile.WriteString(contentToWrite); err != nil {
			return "", "", fmt.Errorf("failed to write temporary filter file: %w", err)
		}

		// Ensure the file is synced to disk
		if err := tempFilterFile.Sync(); err != nil {
			return "", "", fmt.Errorf("failed to sync temporary filter file: %w", err)
		}

		tempFilterFile.Close()
		filterPath = tempFilterFile.Name()
		config.DebugLog("TestFilterLocal: using custom filter content from temporary file: %s (size: %d bytes, includes resolved: %v)", filterPath, len(contentToWrite), err == nil)
	} else {
		// Try .local first, then fallback to .conf
		localPath := filepath.Join("/etc/fail2ban/filter.d", filterName+".local")
		confPath := filepath.Join("/etc/fail2ban/filter.d", filterName+".conf")

		if _, err := os.Stat(localPath); err == nil {
			filterPath = localPath
			config.DebugLog("TestFilterLocal: using .local file: %s", filterPath)
		} else if _, err := os.Stat(confPath); err == nil {
			filterPath = confPath
			config.DebugLog("TestFilterLocal: using .conf file: %s", filterPath)
		} else {
			return "", "", fmt.Errorf("filter %s not found (checked both .local and .conf): %w", filterName, err)
		}
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
