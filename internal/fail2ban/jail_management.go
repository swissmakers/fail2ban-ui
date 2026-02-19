package fail2ban

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

func ensureJailLocalFile(jailName string) error {
	jailName = strings.TrimSpace(jailName)
	if jailName == "" {
		return fmt.Errorf("jail name cannot be empty")
	}

	jailDPath := "/etc/fail2ban/jail.d"
	localPath := filepath.Join(jailDPath, jailName+".local")
	confPath := filepath.Join(jailDPath, jailName+".conf")

	if _, err := os.Stat(localPath); err == nil {
		config.DebugLog("Jail .local file already exists: %s", localPath)
		return nil
	}

	if _, err := os.Stat(confPath); err == nil {
		config.DebugLog("Copying jail config from .conf to .local: %s -> %s", confPath, localPath)
		content, err := os.ReadFile(confPath)
		if err != nil {
			return fmt.Errorf("failed to read jail .conf file %s: %w", confPath, err)
		}
		if err := os.WriteFile(localPath, content, 0644); err != nil {
			return fmt.Errorf("failed to write jail .local file %s: %w", localPath, err)
		}
		config.DebugLog("Successfully copied jail config to .local file")
		return nil
	}

	config.DebugLog("Creating minimal jail .local file: %s", localPath)
	if err := os.MkdirAll(jailDPath, 0755); err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}
	minimalContent := fmt.Sprintf("[%s]\n", jailName)
	if err := os.WriteFile(localPath, []byte(minimalContent), 0644); err != nil {
		return fmt.Errorf("failed to create jail .local file %s: %w", localPath, err)
	}
	config.DebugLog("Successfully created minimal jail .local file")
	return nil
}

// =========================================================================
//  Config Read/Write
// =========================================================================

func readJailConfigWithFallback(jailName string) (string, string, error) {
	jailName = strings.TrimSpace(jailName)
	if jailName == "" {
		return "", "", fmt.Errorf("jail name cannot be empty")
	}

	jailDPath := "/etc/fail2ban/jail.d"
	localPath := filepath.Join(jailDPath, jailName+".local")
	confPath := filepath.Join(jailDPath, jailName+".conf")

	if content, err := os.ReadFile(localPath); err == nil {
		config.DebugLog("Reading jail config from .local: %s", localPath)
		return string(content), localPath, nil
	}

	if content, err := os.ReadFile(confPath); err == nil {
		config.DebugLog("Reading jail config from .conf: %s", confPath)
		return string(content), confPath, nil
	}

	config.DebugLog("Neither .local nor .conf exists for jail %s, returning empty section", jailName)
	return fmt.Sprintf("[%s]\n", jailName), localPath, nil
}

// =========================================================================
//  Validation
// =========================================================================

func ValidateJailName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("jail name cannot be empty")
	}

	reservedNames := map[string]bool{
		"DEFAULT":  true,
		"INCLUDES": true,
	}
	if reservedNames[strings.ToUpper(name)] {
		return fmt.Errorf("jail name '%s' is reserved and cannot be used", name)
	}

	// Check for invalid characters (only alphanumeric, dash, underscore allowed)
	invalidChars := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	if invalidChars.MatchString(name) {
		return fmt.Errorf("jail name '%s' contains invalid characters. Only alphanumeric characters, dashes, and underscores are allowed", name)
	}

	return nil
}

// =========================================================================
//  Jail Discovery
// =========================================================================

func ListJailFiles(directory string) ([]string, error) {
	var files []string

	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("failed to read jail directory %s: %w", directory, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
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

// Returns all jails from /etc/fail2ban/jail.d directory.
func DiscoverJailsFromFiles() ([]JailInfo, error) {
	jailDPath := "/etc/fail2ban/jail.d"

	if _, err := os.Stat(jailDPath); os.IsNotExist(err) {
		return []JailInfo{}, nil
	}

	files, err := ListJailFiles(jailDPath)
	if err != nil {
		return nil, err
	}

	var allJails []JailInfo
	processedFiles := make(map[string]bool)
	processedJails := make(map[string]bool)

	// Parse .local files
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

		jails, err := parseJailConfigFile(filePath)
		if err != nil {
			config.DebugLog("Failed to parse jail file %s: %v", filePath, err)
			continue
		}

		for _, jail := range jails {
			if jail.JailName != "" && jail.JailName != "DEFAULT" && !processedJails[jail.JailName] {
				allJails = append(allJails, jail)
				processedJails[jail.JailName] = true
			}
		}
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

		jails, err := parseJailConfigFile(filePath)
		if err != nil {
			config.DebugLog("Failed to parse jail file %s: %v", filePath, err)
			continue
		}

		for _, jail := range jails {
			if jail.JailName != "" && jail.JailName != "DEFAULT" && !processedJails[jail.JailName] {
				allJails = append(allJails, jail)
				processedJails[jail.JailName] = true
			}
		}
	}

	return allJails, nil
}

// =========================================================================
//  Jail Creation
// =========================================================================

func CreateJail(jailName, content string) error {
	if err := ValidateJailName(jailName); err != nil {
		return err
	}

	jailDPath := "/etc/fail2ban/jail.d"
	localPath := filepath.Join(jailDPath, jailName+".local")

	if err := os.MkdirAll(jailDPath, 0755); err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}

	trimmed := strings.TrimSpace(content)
	expectedSection := fmt.Sprintf("[%s]", jailName)
	if !strings.HasPrefix(trimmed, expectedSection) {
		content = expectedSection + "\n" + content
	}

	if err := os.WriteFile(localPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create jail file %s: %w", localPath, err)
	}

	config.DebugLog("Created jail file: %s", localPath)
	return nil
}

// =========================================================================
//
//	Jail Deletion
//
// =========================================================================
func DeleteJail(jailName string) error {
	if err := ValidateJailName(jailName); err != nil {
		return err
	}

	jailDPath := "/etc/fail2ban/jail.d"
	localPath := filepath.Join(jailDPath, jailName+".local")
	confPath := filepath.Join(jailDPath, jailName+".conf")

	var deletedFiles []string
	var lastErr error

	if _, err := os.Stat(localPath); err == nil {
		if err := os.Remove(localPath); err != nil {
			lastErr = fmt.Errorf("failed to delete jail file %s: %w", localPath, err)
		} else {
			deletedFiles = append(deletedFiles, localPath)
			config.DebugLog("Deleted jail file: %s", localPath)
		}
	}

	if _, err := os.Stat(confPath); err == nil {
		if err := os.Remove(confPath); err != nil {
			lastErr = fmt.Errorf("failed to delete jail file %s: %w", confPath, err)
		} else {
			deletedFiles = append(deletedFiles, confPath)
			config.DebugLog("Deleted jail file: %s", confPath)
		}
	}

	if len(deletedFiles) == 0 && lastErr == nil {
		return fmt.Errorf("jail file %s or %s does not exist", localPath, confPath)
	}

	if lastErr != nil {
		return lastErr
	}

	return nil
}

// Returns all jails.
func GetAllJails() ([]JailInfo, error) {
	// Run migration once if enabled (experimental, off by default)
	if isJailAutoMigrationEnabled() {
		migrationOnce.Do(func() {
			config.DebugLog("JAIL_AUTOMIGRATION=true: running experimental jail.local → jail.d/ migration")
			if err := MigrateJailsFromJailLocal(); err != nil {
				config.DebugLog("Migration warning: %v", err)
			}
		})
	}

	jails, err := DiscoverJailsFromFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to discover jails from files: %w", err)
	}

	return jails, nil
}

func parseJailConfigFile(path string) ([]JailInfo, error) {
	var jails []JailInfo
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentJail string

	ignoredSections := map[string]bool{
		"DEFAULT":  true,
		"INCLUDES": true,
	}

	enabled := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if currentJail != "" && !ignoredSections[currentJail] {
				jails = append(jails, JailInfo{
					JailName: currentJail,
					Enabled:  enabled,
				})
			}
			currentJail = strings.TrimSpace(strings.Trim(line, "[]"))
			if currentJail == "" {
				currentJail = ""
				enabled = true
				continue
			}
			enabled = true
		} else if strings.HasPrefix(strings.ToLower(line), "enabled") {
			if currentJail != "" {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					value := strings.TrimSpace(parts[1])
					enabled = strings.EqualFold(value, "true")
				}
			}
		}
	}
	if currentJail != "" && !ignoredSections[currentJail] {
		jails = append(jails, JailInfo{
			JailName: currentJail,
			Enabled:  enabled,
		})
	}
	return jails, scanner.Err()
}

// =========================================================================
//  Jail Enabled from "Manage Jails"
// =========================================================================

func UpdateJailEnabledStates(updates map[string]bool) error {
	config.DebugLog("UpdateJailEnabledStates called with %d updates: %+v", len(updates), updates)
	jailDPath := "/etc/fail2ban/jail.d"

	for jailName, enabled := range updates {
		jailName = strings.TrimSpace(jailName)
		if jailName == "" {
			config.DebugLog("Skipping empty jail name in updates map")
			continue
		}
		config.DebugLog("Processing jail: %s, enabled: %t", jailName, enabled)

		// Ensure .local file exists
		if err := ensureJailLocalFile(jailName); err != nil {
			return fmt.Errorf("failed to ensure .local file for jail %s: %w", jailName, err)
		}
		jailFilePath := filepath.Join(jailDPath, jailName+".local")
		config.DebugLog("Jail file path: %s", jailFilePath)
		content, err := os.ReadFile(jailFilePath)
		if err != nil {
			return fmt.Errorf("failed to read jail .local file %s: %w", jailFilePath, err)
		}
		var lines []string
		if len(content) > 0 {
			lines = strings.Split(string(content), "\n")
		} else {
			lines = []string{fmt.Sprintf("[%s]", jailName)}
		}
		var outputLines []string
		var foundEnabled bool
		var currentJail string

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				currentJail = strings.Trim(trimmed, "[]")
				outputLines = append(outputLines, line)
			} else if strings.HasPrefix(strings.ToLower(trimmed), "enabled") {
				if currentJail == jailName {
					outputLines = append(outputLines, fmt.Sprintf("enabled = %t", enabled))
					foundEnabled = true
				} else {
					outputLines = append(outputLines, line)
				}
			} else {
				outputLines = append(outputLines, line)
			}
		}
		if !foundEnabled {
			var newLines []string
			for i, line := range outputLines {
				newLines = append(newLines, line)
				if strings.TrimSpace(line) == fmt.Sprintf("[%s]", jailName) {
					// Insert enabled line after the section header
					newLines = append(newLines, fmt.Sprintf("enabled = %t", enabled))
					if i+1 < len(outputLines) {
						newLines = append(newLines, outputLines[i+1:]...)
					}
					break
				}
			}
			if len(newLines) > len(outputLines) {
				outputLines = newLines
			} else {
				outputLines = append(outputLines, fmt.Sprintf("enabled = %t", enabled))
			}
		}
		newContent := strings.Join(outputLines, "\n")
		if !strings.HasSuffix(newContent, "\n") {
			newContent += "\n"
		}
		if err := os.WriteFile(jailFilePath, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to write jail file %s: %w", jailFilePath, err)
		}
		config.DebugLog("Updated jail %s: enabled = %t (file: %s)", jailName, enabled, jailFilePath)
	}
	return nil
}

// Returns the full jail configuration from /etc/fail2ban/jail.d/{jailName}.local
func GetJailConfig(jailName string) (string, string, error) {
	jailName = strings.TrimSpace(jailName)
	if jailName == "" {
		return "", "", fmt.Errorf("jail name cannot be empty")
	}

	config.DebugLog("GetJailConfig called for jail: %s", jailName)
	content, filePath, err := readJailConfigWithFallback(jailName)
	if err != nil {
		config.DebugLog("Failed to read jail config: %v", err)
		return "", "", fmt.Errorf("failed to read jail config for %s: %w", jailName, err)
	}

	config.DebugLog("Jail config read successfully, length: %d, file: %s", len(content), filePath)
	return content, filePath, nil
}

// Extracts the filter name from the jail configuration.
func ExtractFilterFromJailConfig(jailContent string) string {
	scanner := bufio.NewScanner(strings.NewReader(jailContent))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "filter") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				filterValue := strings.TrimSpace(parts[1])
				if idx := strings.Index(filterValue, "["); idx >= 0 {
					filterValue = filterValue[:idx]
				}
				return strings.TrimSpace(filterValue)
			}
		}
	}
	return ""
}

// Writes the full jail configuration to /etc/fail2ban/jail.d/{jailName}.local
func SetJailConfig(jailName, content string) error {
	jailName = strings.TrimSpace(jailName)
	if jailName == "" {
		return fmt.Errorf("jail name cannot be empty")
	}
	config.DebugLog("SetJailConfig called for jail: %s, content length: %d", jailName, len(content))

	jailDPath := "/etc/fail2ban/jail.d"
	if err := ensureJailLocalFile(jailName); err != nil {
		return fmt.Errorf("failed to ensure .local file for jail %s: %w", jailName, err)
	}

	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		config.DebugLog("Content is empty, creating minimal jail config")
		content = fmt.Sprintf("[%s]\n", jailName)
	} else {
		expectedSection := fmt.Sprintf("[%s]", jailName)
		lines := strings.Split(content, "\n")
		sectionFound := false
		sectionIndex := -1
		var sectionIndices []int

		// Find all section headers in the content
		for i, line := range lines {
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "[") && strings.HasSuffix(trimmedLine, "]") {
				sectionIndices = append(sectionIndices, i)
				if trimmedLine == expectedSection {
					if !sectionFound {
						sectionIndex = i
						sectionFound = true
						config.DebugLog("Correct section header found at line %d", i)
					} else {
						config.DebugLog("Duplicate correct section header found at line %d, will remove", i)
					}
				} else {
					config.DebugLog("Incorrect section header found at line %d: %s (expected %s)", i, trimmedLine, expectedSection)
					if sectionIndex == -1 {
						sectionIndex = i
					}
				}
			}
		}
		if len(sectionIndices) > 1 {
			config.DebugLog("Found %d section headers, removing duplicates", len(sectionIndices))
			var newLines []string
			keptFirst := false
			for i, line := range lines {
				trimmedLine := strings.TrimSpace(line)
				isSectionHeader := strings.HasPrefix(trimmedLine, "[") && strings.HasSuffix(trimmedLine, "]")

				if isSectionHeader {
					if !keptFirst && trimmedLine == expectedSection {
						newLines = append(newLines, expectedSection)
						keptFirst = true
						config.DebugLog("Keeping section header at line %d", i)
					} else {
						config.DebugLog("Removing duplicate/incorrect section header at line %d: %s", i, trimmedLine)
						continue
					}
				} else {
					newLines = append(newLines, line)
				}
			}
			lines = newLines
		}

		if !sectionFound {
			if sectionIndex >= 0 {
				config.DebugLog("Replacing incorrect section header at line %d", sectionIndex)
				lines[sectionIndex] = expectedSection
			} else {
				config.DebugLog("No section header found, prepending %s", expectedSection)
				lines = append([]string{expectedSection}, lines...)
			}
			content = strings.Join(lines, "\n")
		} else {
			content = strings.Join(lines, "\n")
		}
	}

	jailFilePath := filepath.Join(jailDPath, jailName+".local")
	config.DebugLog("Writing jail config to: %s", jailFilePath)
	if err := os.WriteFile(jailFilePath, []byte(content), 0644); err != nil {
		config.DebugLog("Failed to write jail config: %v", err)
		return fmt.Errorf("failed to write jail config for %s: %w", jailName, err)
	}
	config.DebugLog("Jail config written successfully to .local file")

	return nil
}

// =========================================================================
//  Logpath Operations
// =========================================================================

func TestLogpath(logpath string) ([]string, error) {
	if logpath == "" {
		return []string{}, nil
	}

	logpath = strings.TrimSpace(logpath)
	hasWildcard := strings.ContainsAny(logpath, "*?[")

	var matches []string

	if hasWildcard {
		matched, err := filepath.Glob(logpath)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern: %w", err)
		}
		matches = matched
	} else {
		info, err := os.Stat(logpath)
		if err != nil {
			if os.IsNotExist(err) {
				return []string{}, nil
			}
			return nil, fmt.Errorf("failed to stat path: %w", err)
		}

		if info.IsDir() {
			entries, err := os.ReadDir(logpath)
			if err != nil {
				return nil, fmt.Errorf("failed to read directory: %w", err)
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					fullPath := filepath.Join(logpath, entry.Name())
					matches = append(matches, fullPath)
				}
			}
		} else {
			matches = []string{logpath}
		}
	}

	return matches, nil
}

// Resolves variables in logpath and tests the resolved path.
func TestLogpathWithResolution(logpath string) (originalPath, resolvedPath string, files []string, err error) {
	originalPath = strings.TrimSpace(logpath)
	if originalPath == "" {
		return originalPath, "", []string{}, nil
	}
	resolvedPath, err = ResolveLogpathVariables(originalPath)
	if err != nil {
		return originalPath, "", nil, fmt.Errorf("failed to resolve logpath variables: %w", err)
	}
	if resolvedPath == "" {
		resolvedPath = originalPath
	}
	files, err = TestLogpath(resolvedPath)
	if err != nil {
		return originalPath, resolvedPath, nil, fmt.Errorf("failed to test logpath: %w", err)
	}

	return originalPath, resolvedPath, files, nil
}

// Extracts the logpath from the jail configuration.
func ExtractLogpathFromJailConfig(jailContent string) string {
	var logpaths []string
	scanner := bufio.NewScanner(strings.NewReader(jailContent))
	inLogpathLine := false
	currentLogpath := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			if inLogpathLine && currentLogpath != "" {
				paths := strings.Fields(currentLogpath)
				logpaths = append(logpaths, paths...)
				currentLogpath = ""
				inLogpathLine = false
			}
			continue
		}

		if strings.HasPrefix(strings.ToLower(line), "logpath") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				logpathValue := strings.TrimSpace(parts[1])
				if logpathValue != "" {
					currentLogpath = logpathValue
					inLogpathLine = true
				}
			}

		} else if inLogpathLine {
			if line != "" && !strings.Contains(line, "=") {
				currentLogpath += " " + line
			} else {
				if currentLogpath != "" {
					paths := strings.Fields(currentLogpath)
					logpaths = append(logpaths, paths...)
					currentLogpath = ""
				}
				inLogpathLine = false
			}

		} else if inLogpathLine && line == "" {
			if currentLogpath != "" {
				paths := strings.Fields(currentLogpath)
				logpaths = append(logpaths, paths...)
				currentLogpath = ""
			}
			inLogpathLine = false
		}
	}

	if currentLogpath != "" {
		paths := strings.Fields(currentLogpath)
		logpaths = append(logpaths, paths...)
	}

	return strings.Join(logpaths, "\n")
}

// Updates /etc/fail2ban/jail.local with the current settings.
func UpdateDefaultSettingsLocal(settings config.AppSettings) error {
	config.DebugLog("UpdateDefaultSettingsLocal called")
	return config.EnsureJailLocalStructure()
}

// =========================================================================
//  Jail Auto Migration (EXPERIMENTAL, runs only when JAIL_AUTOMIGRATION=true)
// =========================================================================

var (
	migrationOnce sync.Once
)

func isJailAutoMigrationEnabled() bool {
	return strings.EqualFold(os.Getenv("JAIL_AUTOMIGRATION"), "true")
}

// Migrates jail.local to jail.d/*.local.
func MigrateJailsFromJailLocal() error {
	localPath := "/etc/fail2ban/jail.local"
	jailDPath := "/etc/fail2ban/jail.d"

	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		return nil
	}
	content, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read jail.local: %w", err)
	}
	sections, defaultContent, err := parseJailSectionsUncommented(string(content))
	if err != nil {
		return fmt.Errorf("failed to parse jail.local: %w", err)
	}
	if len(sections) == 0 {
		config.DebugLog("No jails to migrate from jail.local")
		return nil
	}
	backupPath := localPath + ".backup." + fmt.Sprintf("%d", time.Now().Unix())
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	config.DebugLog("Created backup of jail.local at %s", backupPath)

	if err := os.MkdirAll(jailDPath, 0755); err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}
	migratedCount := 0
	for jailName, jailContent := range sections {
		if jailName == "" {
			continue
		}
		jailFilePath := filepath.Join(jailDPath, jailName+".local")
		if _, err := os.Stat(jailFilePath); err == nil {
			config.DebugLog("Skipping migration for jail %s: .local file already exists", jailName)
			continue
		}
		enabledSet := strings.Contains(jailContent, "enabled") || strings.Contains(jailContent, "Enabled")
		if !enabledSet {
			lines := strings.Split(jailContent, "\n")
			modifiedContent := ""
			for i, line := range lines {
				modifiedContent += line + "\n"
				if i == 0 && strings.HasPrefix(strings.TrimSpace(line), "[") && strings.HasSuffix(strings.TrimSpace(line), "]") {
					modifiedContent += "enabled = false\n"
				}
			}
			jailContent = modifiedContent
		} else {
			jailContent = regexp.MustCompile(`(?m)^\s*enabled\s*=\s*true\s*$`).ReplaceAllString(jailContent, "enabled = false")
		}
		if err := os.WriteFile(jailFilePath, []byte(jailContent), 0644); err != nil {
			return fmt.Errorf("failed to write jail file %s: %w", jailFilePath, err)
		}
		config.DebugLog("Migrated jail %s to %s (enabled = false)", jailName, jailFilePath)
		migratedCount++
	}
	if migratedCount > 0 {
		newLocalContent := defaultContent

		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		var inCommentedJail bool
		var commentedJailContent strings.Builder
		var commentedJailName string
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				originalLine := strings.TrimSpace(line)
				if strings.HasPrefix(originalLine, "#[") {
					if inCommentedJail && commentedJailName != "" {
						newLocalContent += commentedJailContent.String()
					}
					inCommentedJail = true
					commentedJailContent.Reset()
					commentedJailName = strings.Trim(trimmed, "[]")
					if strings.HasPrefix(commentedJailName, "#") {
						commentedJailName = strings.TrimSpace(strings.TrimPrefix(commentedJailName, "#"))
					}
					commentedJailContent.WriteString(line)
					commentedJailContent.WriteString("\n")
				} else {
					if inCommentedJail && commentedJailName != "" {
						newLocalContent += commentedJailContent.String()
						inCommentedJail = false
						commentedJailContent.Reset()
					}
				}
			} else if inCommentedJail {
				commentedJailContent.WriteString(line)
				commentedJailContent.WriteString("\n")
			}
		}
		if inCommentedJail && commentedJailName != "" {
			newLocalContent += commentedJailContent.String()
		}

		if !strings.HasSuffix(newLocalContent, "\n") {
			newLocalContent += "\n"
		}
		if err := os.WriteFile(localPath, []byte(newLocalContent), 0644); err != nil {
			return fmt.Errorf("failed to rewrite jail.local: %w", err)
		}
		config.DebugLog("Migration completed: moved %d jails to jail.d/", migratedCount)
	}
	return nil
}

// Parses an existing jail configuration and returns all jail sections from the file.
func parseJailSectionsUncommented(content string) (map[string]string, string, error) {
	sections := make(map[string]string)
	var defaultContent strings.Builder

	ignoredSections := map[string]bool{
		"DEFAULT":  true,
		"INCLUDES": true,
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentSection string
	var currentContent strings.Builder
	inDefault := false
	sectionIsCommented := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			originalLine := strings.TrimSpace(line)
			isCommented := strings.HasPrefix(originalLine, "#")

			if currentSection != "" {
				sectionContent := strings.TrimSpace(currentContent.String())
				if inDefault {
					defaultContent.WriteString(sectionContent)
					if !strings.HasSuffix(sectionContent, "\n") {
						defaultContent.WriteString("\n")
					}
				} else if !ignoredSections[currentSection] && !sectionIsCommented {
					sections[currentSection] = sectionContent
				}
			}

			if isCommented {
				sectionName := strings.Trim(trimmed, "[]")
				if strings.HasPrefix(sectionName, "#") {
					sectionName = strings.TrimSpace(strings.TrimPrefix(sectionName, "#"))
				}
				currentSection = sectionName
				sectionIsCommented = true
			} else {
				currentSection = strings.Trim(trimmed, "[]")
				sectionIsCommented = false
			}
			currentContent.Reset()
			currentContent.WriteString(line)
			currentContent.WriteString("\n")
			inDefault = (currentSection == "DEFAULT")
		} else {
			currentContent.WriteString(line)
			currentContent.WriteString("\n")
		}
	}

	if currentSection != "" {
		sectionContent := strings.TrimSpace(currentContent.String())
		if inDefault {
			defaultContent.WriteString(sectionContent)
		} else if !ignoredSections[currentSection] && !sectionIsCommented {
			sections[currentSection] = sectionContent
		}
	}

	return sections, defaultContent.String(), scanner.Err()
}
