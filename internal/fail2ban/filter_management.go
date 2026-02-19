// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
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

// Returns the filter configuration using the default connector.
func GetFilterConfig(jail string) (string, string, error) {
	conn, err := GetManager().DefaultConnector()
	if err != nil {
		return "", "", err
	}
	return conn.GetFilterConfig(context.Background(), jail)
}

// Writes the filter configuration using the default connector.
func SetFilterConfig(jail, newContent string) error {
	conn, err := GetManager().DefaultConnector()
	if err != nil {
		return err
	}
	return conn.SetFilterConfig(context.Background(), jail, newContent)
}

func ensureFilterLocalFile(filterName string) error {
	filterName = strings.TrimSpace(filterName)
	if filterName == "" {
		return fmt.Errorf("filter name cannot be empty")
	}

	filterDPath := "/etc/fail2ban/filter.d"
	localPath := filepath.Join(filterDPath, filterName+".local")
	confPath := filepath.Join(filterDPath, filterName+".conf")

	if _, err := os.Stat(localPath); err == nil {
		config.DebugLog("Filter .local file already exists: %s", localPath)
		return nil
	}

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

	config.DebugLog("Neither .local nor .conf exists for filter %s, creating empty .local file", filterName)
	if err := os.WriteFile(localPath, []byte(""), 0644); err != nil {
		return fmt.Errorf("failed to create empty filter .local file %s: %w", localPath, err)
	}
	config.DebugLog("Successfully created empty filter .local file: %s", localPath)
	return nil
}

func RemoveComments(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") {
			result = append(result, line)
		}
	}

	for len(result) > 0 && strings.TrimSpace(result[0]) == "" {
		result = result[1:]
	}

	for len(result) > 0 && strings.TrimSpace(result[len(result)-1]) == "" {
		result = result[:len(result)-1]
	}

	return strings.Join(result, "\n")
}

// Reads filter config from .local first, then falls back to .conf.
func readFilterConfigWithFallback(filterName string) (string, string, error) {
	filterName = strings.TrimSpace(filterName)
	if filterName == "" {
		return "", "", fmt.Errorf("filter name cannot be empty")
	}

	filterDPath := "/etc/fail2ban/filter.d"
	localPath := filepath.Join(filterDPath, filterName+".local")
	confPath := filepath.Join(filterDPath, filterName+".conf")

	if content, err := os.ReadFile(localPath); err == nil {
		config.DebugLog("Reading filter config from .local: %s", localPath)
		return string(content), localPath, nil
	}

	if content, err := os.ReadFile(confPath); err == nil {
		config.DebugLog("Reading filter config from .conf: %s", confPath)
		return string(content), confPath, nil
	}
	return "", localPath, fmt.Errorf("filter config not found: neither %s nor %s exists", localPath, confPath)
}

func GetFilterConfigLocal(jail string) (string, string, error) {
	return readFilterConfigWithFallback(jail)
}

func SetFilterConfigLocal(jail, newContent string) error {
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

// Validates a filter name format.
func ValidateFilterName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("filter name cannot be empty")
	}

	invalidChars := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	if invalidChars.MatchString(name) {
		return fmt.Errorf("filter name '%s' contains invalid characters. Only alphanumeric characters, dashes, and underscores are allowed", name)
	}

	return nil
}

// Lists all filter files in the specified directory.
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
		if strings.HasPrefix(name, ".") {
			continue
		}
		if strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".conf") {
			fullPath := filepath.Join(directory, name)
			files = append(files, fullPath)
		}
	}

	return files, nil
}

// Returns all filters from the filesystem.
func DiscoverFiltersFromFiles() ([]string, error) {
	filterDPath := "/etc/fail2ban/filter.d"

	if _, err := os.Stat(filterDPath); os.IsNotExist(err) {
		return []string{}, nil
	}

	files, err := ListFilterFiles(filterDPath)
	if err != nil {
		return nil, err
	}

	filterMap := make(map[string]bool)
	processedFiles := make(map[string]bool)

	for _, filePath := range files {
		if !strings.HasSuffix(filePath, ".local") {
			continue
		}

		filename := filepath.Base(filePath)
		baseName := strings.TrimSuffix(filename, ".local")
		if baseName == "" {
			continue
		}

		if processedFiles[baseName] {
			continue
		}

		processedFiles[baseName] = true
		filterMap[baseName] = true
	}

	for _, filePath := range files {
		if !strings.HasSuffix(filePath, ".conf") {
			continue
		}
		filename := filepath.Base(filePath)
		baseName := strings.TrimSuffix(filename, ".conf")
		if baseName == "" {
			continue
		}
		if processedFiles[baseName] {
			continue
		}
		processedFiles[baseName] = true
		filterMap[baseName] = true
	}

	var filters []string
	for name := range filterMap {
		filters = append(filters, name)
	}
	sort.Strings(filters)

	return filters, nil
}

// Creates a new filter.
func CreateFilter(filterName, content string) error {
	if err := ValidateFilterName(filterName); err != nil {
		return err
	}
	filterDPath := "/etc/fail2ban/filter.d"
	localPath := filepath.Join(filterDPath, filterName+".local")
	if err := os.MkdirAll(filterDPath, 0755); err != nil {
		return fmt.Errorf("failed to create filter.d directory: %w", err)
	}
	if err := os.WriteFile(localPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create filter file %s: %w", localPath, err)
	}
	config.DebugLog("Created filter file: %s", localPath)
	return nil
}

// Deletes a filter's .local and .conf files from filter.d/ if they exist.
func DeleteFilter(filterName string) error {
	if err := ValidateFilterName(filterName); err != nil {
		return err
	}

	filterDPath := "/etc/fail2ban/filter.d"
	localPath := filepath.Join(filterDPath, filterName+".local")
	confPath := filepath.Join(filterDPath, filterName+".conf")

	var deletedFiles []string
	var lastErr error

	if _, err := os.Stat(localPath); err == nil {
		if err := os.Remove(localPath); err != nil {
			lastErr = fmt.Errorf("failed to delete filter file %s: %w", localPath, err)
		} else {
			deletedFiles = append(deletedFiles, localPath)
			config.DebugLog("Deleted filter file: %s", localPath)
		}
	}
	if _, err := os.Stat(confPath); err == nil {
		if err := os.Remove(confPath); err != nil {
			lastErr = fmt.Errorf("failed to delete filter file %s: %w", confPath, err)
		} else {
			deletedFiles = append(deletedFiles, confPath)
			config.DebugLog("Deleted filter file: %s", confPath)
		}
	}
	if len(deletedFiles) == 0 && lastErr == nil {
		return fmt.Errorf("filter file %s or %s does not exist", localPath, confPath)
	}
	if lastErr != nil {
		return lastErr
	}
	return nil
}

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

// Extracts variable names from [DEFAULT] section of filter content.
func extractVariablesFromContent(content string) map[string]bool {
	variables := make(map[string]bool)
	lines := strings.Split(content, "\n")
	inDefaultSection := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[DEFAULT]") {
			inDefaultSection = true
			continue
		}
		// Check for end of [DEFAULT] section (next section starts)
		if inDefaultSection && strings.HasPrefix(trimmed, "[") {
			inDefaultSection = false
			continue
		}
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

func removeDuplicateVariables(includedContent string, mainVariables map[string]bool) string {
	lines := strings.Split(includedContent, "\n")
	var result strings.Builder
	inDefaultSection := false
	removedCount := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		originalLine := line

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

		if inDefaultSection && !strings.HasPrefix(trimmed, "#") && strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				varName := strings.TrimSpace(parts[0])
				if mainVariables[varName] {
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

func resolveFilterIncludes(filterContent string, filterDPath string, currentFilterName string) (string, error) {
	lines := strings.Split(filterContent, "\n")
	var beforeFiles []string
	var afterFiles []string
	var inIncludesSection bool
	var mainContent strings.Builder

	// Parse the filter content to find [INCLUDES] section
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[INCLUDES]") {
			inIncludesSection = true
			continue
		}

		if inIncludesSection && strings.HasPrefix(trimmed, "[") {
			inIncludesSection = false
		}

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

	var combined strings.Builder

	for _, fileName := range beforeFiles {
		baseName := fileName
		if strings.HasSuffix(baseName, ".local") {
			baseName = strings.TrimSuffix(baseName, ".local")
		} else if strings.HasSuffix(baseName, ".conf") {
			baseName = strings.TrimSuffix(baseName, ".conf")
		}

		if baseName == currentFilterName {
			config.DebugLog("Skipping self-inclusion of filter '%s' in before files", baseName)
			continue
		}

		localPath := filepath.Join(filterDPath, baseName+".local")
		confPath := filepath.Join(filterDPath, baseName+".conf")

		var content []byte
		var err error
		var filePath string

		if content, err = os.ReadFile(localPath); err == nil {
			filePath = localPath
			config.DebugLog("Loading included filter file from .local: %s", filePath)
		} else if content, err = os.ReadFile(confPath); err == nil {
			filePath = confPath
			config.DebugLog("Loading included filter file from .conf: %s", filePath)
		} else {
			config.DebugLog("Warning: could not load included filter file '%s' or '%s': %v", localPath, confPath, err)
			continue
		}

		contentStr := string(content)
		// Remove variables from included file that are defined in main filter.
		cleanedContent := removeDuplicateVariables(contentStr, mainVariables)
		combined.WriteString(cleanedContent)
		if !strings.HasSuffix(cleanedContent, "\n") {
			combined.WriteString("\n")
		}
		combined.WriteString("\n")
	}

	combined.WriteString(mainContentStr)
	if !strings.HasSuffix(mainContentStr, "\n") {
		combined.WriteString("\n")
	}

	for _, fileName := range afterFiles {
		baseName := fileName
		if strings.HasSuffix(baseName, ".local") {
			baseName = strings.TrimSuffix(baseName, ".local")
		} else if strings.HasSuffix(baseName, ".conf") {
			baseName = strings.TrimSuffix(baseName, ".conf")
		}

		localPath := filepath.Join(filterDPath, baseName+".local")
		confPath := filepath.Join(filterDPath, baseName+".conf")

		var content []byte
		var err error
		var filePath string

		if content, err = os.ReadFile(localPath); err == nil {
			filePath = localPath
			config.DebugLog("Loading included filter file from .local: %s", filePath)
		} else if content, err = os.ReadFile(confPath); err == nil {
			filePath = confPath
			config.DebugLog("Loading included filter file from .conf: %s", filePath)
		} else {
			config.DebugLog("Warning: could not load included filter file '%s' or '%s': %v", localPath, confPath, err)
			continue
		}
		contentStr := string(content)
		cleanedContent := removeDuplicateVariables(contentStr, mainVariables)
		combined.WriteString("\n")
		combined.WriteString(cleanedContent)
		if !strings.HasSuffix(cleanedContent, "\n") {
			combined.WriteString("\n")
		}
	}

	return combined.String(), nil
}

// =========================================================================
//  Filter Testing
// =========================================================================

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

		filterDPath := "/etc/fail2ban/filter.d"
		contentToWrite, err := resolveFilterIncludes(filterContent, filterDPath, filterName)
		if err != nil {
			config.DebugLog("Warning: failed to resolve filter includes, using original content: %v", err)
			contentToWrite = filterContent
		}

		if !strings.HasSuffix(contentToWrite, "\n") {
			contentToWrite += "\n"
		}

		if _, err := tempFilterFile.WriteString(contentToWrite); err != nil {
			return "", "", fmt.Errorf("failed to write temporary filter file: %w", err)
		}

		if err := tempFilterFile.Sync(); err != nil {
			return "", "", fmt.Errorf("failed to sync temporary filter file: %w", err)
		}

		tempFilterFile.Close()
		filterPath = tempFilterFile.Name()
		config.DebugLog("TestFilterLocal: using custom filter content from temporary file: %s (size: %d bytes, includes resolved: %v)", filterPath, len(contentToWrite), err == nil)
	} else {
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

	for _, logLine := range cleaned {
		if _, err := tmpFile.WriteString(logLine + "\n"); err != nil {
			return "", filterPath, fmt.Errorf("failed to write to temporary log file: %w", err)
		}
	}
	tmpFile.Close()

	cmd := exec.Command("fail2ban-regex", tmpFile.Name(), filterPath)
	out, _ := cmd.CombinedOutput()
	output := string(out)

	return output, filterPath, nil
}
