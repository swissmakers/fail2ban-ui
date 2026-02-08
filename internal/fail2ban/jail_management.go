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

var (
	migrationOnce sync.Once
)

// ensureJailLocalFile ensures that a .local file exists for the given jail.
// If .local doesn't exist, it copies from .conf if available, or creates a minimal section.
func ensureJailLocalFile(jailName string) error {
	// Validate jail name - must not be empty
	jailName = strings.TrimSpace(jailName)
	if jailName == "" {
		return fmt.Errorf("jail name cannot be empty")
	}

	jailDPath := "/etc/fail2ban/jail.d"
	localPath := filepath.Join(jailDPath, jailName+".local")
	confPath := filepath.Join(jailDPath, jailName+".conf")

	// Check if .local already exists
	if _, err := os.Stat(localPath); err == nil {
		config.DebugLog("Jail .local file already exists: %s", localPath)
		return nil
	}

	// Try to copy from .conf if it exists
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

	// Neither exists, create minimal section
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

// readJailConfigWithFallback reads jail config from .local first, then falls back to .conf.
// Returns (content, filePath, error)
func readJailConfigWithFallback(jailName string) (string, string, error) {
	// Validate jail name - must not be empty
	jailName = strings.TrimSpace(jailName)
	if jailName == "" {
		return "", "", fmt.Errorf("jail name cannot be empty")
	}

	jailDPath := "/etc/fail2ban/jail.d"
	localPath := filepath.Join(jailDPath, jailName+".local")
	confPath := filepath.Join(jailDPath, jailName+".conf")

	// Try .local first
	if content, err := os.ReadFile(localPath); err == nil {
		config.DebugLog("Reading jail config from .local: %s", localPath)
		return string(content), localPath, nil
	}

	// Fallback to .conf
	if content, err := os.ReadFile(confPath); err == nil {
		config.DebugLog("Reading jail config from .conf: %s", confPath)
		return string(content), confPath, nil
	}

	// Neither exists, return empty section with .local path (will be created on save)
	config.DebugLog("Neither .local nor .conf exists for jail %s, returning empty section", jailName)
	return fmt.Sprintf("[%s]\n", jailName), localPath, nil
}

// ValidateJailName validates a jail name format.
// Returns an error if the name is invalid (empty, contains invalid characters, or is reserved).
func ValidateJailName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("jail name cannot be empty")
	}

	// Reserved names that should not be used
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

// ListJailFiles lists all jail config files in the specified directory.
// Returns full paths to .local and .conf files.
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

// DiscoverJailsFromFiles discovers all jails from the filesystem.
// Reads from /etc/fail2ban/jail.d/ directory, preferring .local files over .conf files.
// Returns all jails found (enabled and disabled).
func DiscoverJailsFromFiles() ([]JailInfo, error) {
	jailDPath := "/etc/fail2ban/jail.d"

	// Check if directory exists
	if _, err := os.Stat(jailDPath); os.IsNotExist(err) {
		// Directory doesn't exist, return empty list
		return []JailInfo{}, nil
	}

	// List all jail files
	files, err := ListJailFiles(jailDPath)
	if err != nil {
		return nil, err
	}

	var allJails []JailInfo
	processedFiles := make(map[string]bool) // Track base names to avoid duplicates
	processedJails := make(map[string]bool) // Track jail names to avoid duplicates

	// First pass: process all .local files
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

		// Parse the file
		jails, err := parseJailConfigFile(filePath)
		if err != nil {
			config.DebugLog("Failed to parse jail file %s: %v", filePath, err)
			continue
		}

		// Add jails from this file
		for _, jail := range jails {
			if jail.JailName != "" && jail.JailName != "DEFAULT" && !processedJails[jail.JailName] {
				allJails = append(allJails, jail)
				processedJails[jail.JailName] = true
			}
		}
	}

	// Second pass: process .conf files that don't have corresponding .local files
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

		// Parse the file
		jails, err := parseJailConfigFile(filePath)
		if err != nil {
			config.DebugLog("Failed to parse jail file %s: %v", filePath, err)
			continue
		}

		// Add jails from this file
		for _, jail := range jails {
			if jail.JailName != "" && jail.JailName != "DEFAULT" && !processedJails[jail.JailName] {
				allJails = append(allJails, jail)
				processedJails[jail.JailName] = true
			}
		}
	}

	return allJails, nil
}

// CreateJail creates a new jail in jail.d/{name}.local.
// If the jail already exists, it will be overwritten.
func CreateJail(jailName, content string) error {
	if err := ValidateJailName(jailName); err != nil {
		return err
	}

	jailDPath := "/etc/fail2ban/jail.d"
	localPath := filepath.Join(jailDPath, jailName+".local")

	// Ensure directory exists
	if err := os.MkdirAll(jailDPath, 0755); err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}

	// Validate content starts with correct section header
	trimmed := strings.TrimSpace(content)
	expectedSection := fmt.Sprintf("[%s]", jailName)
	if !strings.HasPrefix(trimmed, expectedSection) {
		// Prepend the section header if missing
		content = expectedSection + "\n" + content
	}

	// Write the file
	if err := os.WriteFile(localPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create jail file %s: %w", localPath, err)
	}

	config.DebugLog("Created jail file: %s", localPath)
	return nil
}

// DeleteJail deletes a jail's .local and .conf files from jail.d/ if they exist.
// Both files are deleted to ensure complete removal of the jail configuration.
func DeleteJail(jailName string) error {
	if err := ValidateJailName(jailName); err != nil {
		return err
	}

	jailDPath := "/etc/fail2ban/jail.d"
	localPath := filepath.Join(jailDPath, jailName+".local")
	confPath := filepath.Join(jailDPath, jailName+".conf")

	var deletedFiles []string
	var lastErr error

	// Delete .local file if it exists
	if _, err := os.Stat(localPath); err == nil {
		if err := os.Remove(localPath); err != nil {
			lastErr = fmt.Errorf("failed to delete jail file %s: %w", localPath, err)
		} else {
			deletedFiles = append(deletedFiles, localPath)
			config.DebugLog("Deleted jail file: %s", localPath)
		}
	}

	// Delete .conf file if it exists
	if _, err := os.Stat(confPath); err == nil {
		if err := os.Remove(confPath); err != nil {
			lastErr = fmt.Errorf("failed to delete jail file %s: %w", confPath, err)
		} else {
			deletedFiles = append(deletedFiles, confPath)
			config.DebugLog("Deleted jail file: %s", confPath)
		}
	}

	// If no files were deleted and no error occurred, it means neither file existed
	if len(deletedFiles) == 0 && lastErr == nil {
		return fmt.Errorf("jail file %s or %s does not exist", localPath, confPath)
	}

	// Return the last error if any occurred
	if lastErr != nil {
		return lastErr
	}

	return nil
}

// GetAllJails reads jails from /etc/fail2ban/jail.local (DEFAULT only) and /etc/fail2ban/jail.d directory.
// Automatically migrates legacy jails from jail.local to jail.d on first call.
// Now uses DiscoverJailsFromFiles() for file-based discovery.
func GetAllJails() ([]JailInfo, error) {
	// Run migration once if needed
	migrationOnce.Do(func() {
		if err := MigrateJailsToJailD(); err != nil {
			config.DebugLog("Migration warning: %v", err)
		}
	})

	// Discover jails from filesystem
	jails, err := DiscoverJailsFromFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to discover jails from files: %w", err)
	}

	return jails, nil
}

// parseJailConfigFile parses a jail configuration file and returns a slice of JailInfo.
// It assumes each jail section is defined by [JailName] and that an "enabled" line may exist.
func parseJailConfigFile(path string) ([]JailInfo, error) {
	var jails []JailInfo
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentJail string

	// Sections that should be ignored (not jails)
	ignoredSections := map[string]bool{
		"DEFAULT":  true,
		"INCLUDES": true,
	}

	// default value is true if "enabled" is missing; we set it for each section.
	enabled := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// When a new section starts, save the previous jail if exists.
			if currentJail != "" && !ignoredSections[currentJail] {
				jails = append(jails, JailInfo{
					JailName: currentJail,
					Enabled:  enabled,
				})
			}
			// Start a new jail section.
			currentJail = strings.TrimSpace(strings.Trim(line, "[]"))
			// Skip empty jail names (e.g., from malformed config files with [])
			if currentJail == "" {
				currentJail = "" // Reset to empty to skip this section
				enabled = true
				continue
			}
			// Reset to default for the new section.
			enabled = true
		} else if strings.HasPrefix(strings.ToLower(line), "enabled") {
			// Only process enabled line if we have a valid jail name
			if currentJail != "" {
				// Expect format: enabled = true/false
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					value := strings.TrimSpace(parts[1])
					enabled = strings.EqualFold(value, "true")
				}
			}
		}
	}
	// Add the final jail if one exists.
	if currentJail != "" && !ignoredSections[currentJail] {
		jails = append(jails, JailInfo{
			JailName: currentJail,
			Enabled:  enabled,
		})
	}
	return jails, scanner.Err()
}

// UpdateJailEnabledStates updates the enabled state for each jail based on the provided updates map.
// Updates only the corresponding .local file in /etc/fail2ban/jail.d/ for each jail.
// Creates .local file by copying from .conf if needed, preserving original .conf files.
func UpdateJailEnabledStates(updates map[string]bool) error {
	config.DebugLog("UpdateJailEnabledStates called with %d updates: %+v", len(updates), updates)
	jailDPath := "/etc/fail2ban/jail.d"

	// Ensure jail.d directory exists
	if err := os.MkdirAll(jailDPath, 0755); err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}

	// Update each jail in its own .local file
	for jailName, enabled := range updates {
		// Validate jail name - skip empty or invalid names
		jailName = strings.TrimSpace(jailName)
		if jailName == "" {
			config.DebugLog("Skipping empty jail name in updates map")
			continue
		}

		config.DebugLog("Processing jail: %s, enabled: %t", jailName, enabled)

		// Ensure .local file exists (copy from .conf if needed)
		if err := ensureJailLocalFile(jailName); err != nil {
			return fmt.Errorf("failed to ensure .local file for jail %s: %w", jailName, err)
		}

		jailFilePath := filepath.Join(jailDPath, jailName+".local")
		config.DebugLog("Jail file path: %s", jailFilePath)

		// Read existing .local file
		content, err := os.ReadFile(jailFilePath)
		if err != nil {
			return fmt.Errorf("failed to read jail .local file %s: %w", jailFilePath, err)
		}

		var lines []string
		if len(content) > 0 {
			lines = strings.Split(string(content), "\n")
		} else {
			// Create new file with jail section
			lines = []string{fmt.Sprintf("[%s]", jailName)}
		}

		// Update or add enabled line
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

		// If enabled line not found, add it after the jail section header
		if !foundEnabled {
			var newLines []string
			for i, line := range outputLines {
				newLines = append(newLines, line)
				if strings.TrimSpace(line) == fmt.Sprintf("[%s]", jailName) {
					// Insert enabled line after the section header
					newLines = append(newLines, fmt.Sprintf("enabled = %t", enabled))
					// Add remaining lines
					if i+1 < len(outputLines) {
						newLines = append(newLines, outputLines[i+1:]...)
					}
					break
				}
			}
			if len(newLines) > len(outputLines) {
				outputLines = newLines
			} else {
				// Fallback: append at the end
				outputLines = append(outputLines, fmt.Sprintf("enabled = %t", enabled))
			}
		}

		// Write updated content
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

// MigrateJailsToJailD migrates all non-DEFAULT jails from jail.local to individual files in jail.d/.
// Creates a backup of jail.local before migration. If a jail already exists in jail.d, jail.local takes precedence.
func MigrateJailsToJailD() error {
	localPath := "/etc/fail2ban/jail.local"
	jailDPath := "/etc/fail2ban/jail.d"

	// Check if jail.local exists
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		return nil // Nothing to migrate
	}

	// Read jail.local content
	content, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read jail.local: %w", err)
	}

	// Parse content to extract sections
	sections, defaultContent, err := parseJailSections(string(content))
	if err != nil {
		return fmt.Errorf("failed to parse jail.local: %w", err)
	}

	// If no non-DEFAULT jails found, nothing to migrate
	if len(sections) == 0 {
		return nil
	}

	// Create backup of jail.local
	backupPath := localPath + ".backup." + fmt.Sprintf("%d", os.Getpid())
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	config.DebugLog("Created backup of jail.local at %s", backupPath)

	// Ensure jail.d directory exists
	if err := os.MkdirAll(jailDPath, 0755); err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}

	// Write each jail to its own file in jail.d/
	for jailName, jailContent := range sections {
		jailFilePath := filepath.Join(jailDPath, jailName+".conf")

		// Check if file already exists
		if _, err := os.Stat(jailFilePath); err == nil {
			// File exists - jail.local takes precedence, so overwrite
			config.DebugLog("Overwriting existing jail file %s with content from jail.local", jailFilePath)
		}

		// Write jail content to file
		if err := os.WriteFile(jailFilePath, []byte(jailContent), 0644); err != nil {
			return fmt.Errorf("failed to write jail file %s: %w", jailFilePath, err)
		}
	}

	// Rewrite jail.local with only DEFAULT section
	newLocalContent := defaultContent
	if !strings.HasSuffix(newLocalContent, "\n") {
		newLocalContent += "\n"
	}
	if err := os.WriteFile(localPath, []byte(newLocalContent), 0644); err != nil {
		return fmt.Errorf("failed to rewrite jail.local: %w", err)
	}

	config.DebugLog("Migration completed: moved %d jails to jail.d/", len(sections))
	return nil
}

// parseJailSections parses jail.local content and returns:
// - map of jail name to jail content (excluding DEFAULT and INCLUDES)
// - DEFAULT section content
func parseJailSections(content string) (map[string]string, string, error) {
	sections := make(map[string]string)
	var defaultContent strings.Builder

	// Sections that should be ignored (not jails)
	ignoredSections := map[string]bool{
		"DEFAULT":  true,
		"INCLUDES": true,
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentSection string
	var currentContent strings.Builder
	inDefault := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			// Save previous section
			if currentSection != "" {
				sectionContent := strings.TrimSpace(currentContent.String())
				if inDefault {
					defaultContent.WriteString(sectionContent)
					if !strings.HasSuffix(sectionContent, "\n") {
						defaultContent.WriteString("\n")
					}
				} else if !ignoredSections[currentSection] {
					// Only save if it's not an ignored section
					sections[currentSection] = sectionContent
				}
			}

			// Start new section
			currentSection = strings.Trim(trimmed, "[]")
			currentContent.Reset()
			currentContent.WriteString(line)
			currentContent.WriteString("\n")
			inDefault = (currentSection == "DEFAULT")
		} else {
			currentContent.WriteString(line)
			currentContent.WriteString("\n")
		}
	}

	// Save final section
	if currentSection != "" {
		sectionContent := strings.TrimSpace(currentContent.String())
		if inDefault {
			defaultContent.WriteString(sectionContent)
		} else if !ignoredSections[currentSection] {
			// Only save if it's not an ignored section
			sections[currentSection] = sectionContent
		}
	}

	return sections, defaultContent.String(), scanner.Err()
}

// parseJailSectionsUncommented parses jail.local content and returns:
// - map of jail name to jail content (excluding DEFAULT, INCLUDES, and commented sections)
// - DEFAULT section content (including commented lines)
// Only extracts non-commented jail sections
func parseJailSectionsUncommented(content string) (map[string]string, string, error) {
	sections := make(map[string]string)
	var defaultContent strings.Builder

	// Sections that should be ignored (not jails)
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

		// Check if this is a section header
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			// Check if the section is commented
			originalLine := strings.TrimSpace(line)
			isCommented := strings.HasPrefix(originalLine, "#")

			// Save previous section
			if currentSection != "" {
				sectionContent := strings.TrimSpace(currentContent.String())
				if inDefault {
					// Always include DEFAULT section content (even if commented)
					defaultContent.WriteString(sectionContent)
					if !strings.HasSuffix(sectionContent, "\n") {
						defaultContent.WriteString("\n")
					}
				} else if !ignoredSections[currentSection] && !sectionIsCommented {
					// Only save non-commented, non-ignored sections
					sections[currentSection] = sectionContent
				}
			}

			// Start new section
			if isCommented {
				// Remove the # from the section name
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

	// Save final section
	if currentSection != "" {
		sectionContent := strings.TrimSpace(currentContent.String())
		if inDefault {
			defaultContent.WriteString(sectionContent)
		} else if !ignoredSections[currentSection] && !sectionIsCommented {
			// Only save if it's not an ignored section and not commented
			sections[currentSection] = sectionContent
		}
	}

	return sections, defaultContent.String(), scanner.Err()
}

// MigrateJailsFromJailLocal migrates non-commented jail sections from jail.local to jail.d/*.local files.
// This should be called when a server is added or enabled to migrate legacy jails.
func MigrateJailsFromJailLocal() error {
	localPath := "/etc/fail2ban/jail.local"
	jailDPath := "/etc/fail2ban/jail.d"

	// Check if jail.local exists
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		return nil // Nothing to migrate
	}

	// Read jail.local content
	content, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read jail.local: %w", err)
	}

	// Parse content to extract non-commented sections
	sections, defaultContent, err := parseJailSectionsUncommented(string(content))
	if err != nil {
		return fmt.Errorf("failed to parse jail.local: %w", err)
	}

	// If no non-commented, non-DEFAULT jails found, nothing to migrate
	if len(sections) == 0 {
		config.DebugLog("No jails to migrate from jail.local")
		return nil
	}

	// Create backup of jail.local
	backupPath := localPath + ".backup." + fmt.Sprintf("%d", time.Now().Unix())
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	config.DebugLog("Created backup of jail.local at %s", backupPath)

	// Ensure jail.d directory exists
	if err := os.MkdirAll(jailDPath, 0755); err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}

	// Write each jail to its own .local file in jail.d/
	migratedCount := 0
	for jailName, jailContent := range sections {
		// Skip empty jail names
		if jailName == "" {
			continue
		}

		jailFilePath := filepath.Join(jailDPath, jailName+".local")

		// Check if .local file already exists
		if _, err := os.Stat(jailFilePath); err == nil {
			// File already exists - skip migration for this jail
			config.DebugLog("Skipping migration for jail %s: .local file already exists", jailName)
			continue
		}

		// Ensure enabled = false is set by default for migrated jails
		// Check if enabled is already set in the content
		enabledSet := strings.Contains(jailContent, "enabled") || strings.Contains(jailContent, "Enabled")
		if !enabledSet {
			// Add enabled = false at the beginning of the jail section
			// Find the first line after [jailName]
			lines := strings.Split(jailContent, "\n")
			modifiedContent := ""
			for i, line := range lines {
				modifiedContent += line + "\n"
				// After the section header, add enabled = false
				if i == 0 && strings.HasPrefix(strings.TrimSpace(line), "[") && strings.HasSuffix(strings.TrimSpace(line), "]") {
					modifiedContent += "enabled = false\n"
				}
			}
			jailContent = modifiedContent
		} else {
			// If enabled is set, ensure it's false by replacing any enabled = true
			jailContent = regexp.MustCompile(`(?m)^\s*enabled\s*=\s*true\s*$`).ReplaceAllString(jailContent, "enabled = false")
		}

		// Write jail content to .local file
		if err := os.WriteFile(jailFilePath, []byte(jailContent), 0644); err != nil {
			return fmt.Errorf("failed to write jail file %s: %w", jailFilePath, err)
		}
		config.DebugLog("Migrated jail %s to %s (enabled = false)", jailName, jailFilePath)
		migratedCount++
	}

	// Only rewrite jail.local if we actually migrated something
	if migratedCount > 0 {
		// Rewrite jail.local with only DEFAULT section and commented jails
		// We need to preserve commented sections, so we'll reconstruct the file
		newLocalContent := defaultContent

		// Add back commented sections that weren't migrated
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		var inCommentedJail bool
		var commentedJailContent strings.Builder
		var commentedJailName string
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				// Check if this is a commented section
				originalLine := strings.TrimSpace(line)
				if strings.HasPrefix(originalLine, "#[") {
					// Save previous commented jail if any
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
					// Non-commented section - save previous commented jail if any
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
		// Save final commented jail if any
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

// GetJailConfig reads the full jail configuration from /etc/fail2ban/jail.d/{jailName}.local
// Falls back to .conf if .local doesn't exist.
func GetJailConfig(jailName string) (string, string, error) {
	// Validate jail name
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

// SetJailConfig writes the full jail configuration to /etc/fail2ban/jail.d/{jailName}.local
// Ensures .local file exists first by copying from .conf if needed.
func SetJailConfig(jailName, content string) error {
	// Validate jail name
	jailName = strings.TrimSpace(jailName)
	if jailName == "" {
		return fmt.Errorf("jail name cannot be empty")
	}

	config.DebugLog("SetJailConfig called for jail: %s, content length: %d", jailName, len(content))

	jailDPath := "/etc/fail2ban/jail.d"

	// Ensure jail.d directory exists
	if err := os.MkdirAll(jailDPath, 0755); err != nil {
		config.DebugLog("Failed to create jail.d directory: %v", err)
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}
	config.DebugLog("jail.d directory ensured")

	// Ensure .local file exists (copy from .conf if needed)
	if err := ensureJailLocalFile(jailName); err != nil {
		return fmt.Errorf("failed to ensure .local file for jail %s: %w", jailName, err)
	}

	// Validate and fix the jail section header
	// The content might start with comments, so we need to find the section header
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

		// Remove duplicate section headers (keep only the first correct one)
		if len(sectionIndices) > 1 {
			config.DebugLog("Found %d section headers, removing duplicates", len(sectionIndices))
			var newLines []string
			keptFirst := false
			for i, line := range lines {
				trimmedLine := strings.TrimSpace(line)
				isSectionHeader := strings.HasPrefix(trimmedLine, "[") && strings.HasSuffix(trimmedLine, "]")

				if isSectionHeader {
					if !keptFirst && trimmedLine == expectedSection {
						// Keep the first correct section header
						newLines = append(newLines, expectedSection)
						keptFirst = true
						config.DebugLog("Keeping section header at line %d", i)
					} else {
						// Skip duplicate or incorrect section headers
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
				// Replace incorrect section header
				config.DebugLog("Replacing incorrect section header at line %d", sectionIndex)
				lines[sectionIndex] = expectedSection
			} else {
				// No section header found, prepend it
				config.DebugLog("No section header found, prepending %s", expectedSection)
				lines = append([]string{expectedSection}, lines...)
			}
			content = strings.Join(lines, "\n")
		} else {
			// Section header is correct, but we may have removed duplicates
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

// TestLogpath tests a logpath pattern and returns matching files.
// Supports wildcards/glob patterns (e.g., /var/log/*.log) and directory paths.
// This function tests the path as-is without variable resolution.
func TestLogpath(logpath string) ([]string, error) {
	if logpath == "" {
		return []string{}, nil
	}

	// Trim whitespace
	logpath = strings.TrimSpace(logpath)

	// Check if it's a glob pattern (contains *, ?, or [)
	hasWildcard := strings.ContainsAny(logpath, "*?[")

	var matches []string

	if hasWildcard {
		// Use filepath.Glob for pattern matching
		matched, err := filepath.Glob(logpath)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern: %w", err)
		}
		matches = matched
	} else {
		// Check if it's a directory
		info, err := os.Stat(logpath)
		if err != nil {
			if os.IsNotExist(err) {
				return []string{}, nil // Path doesn't exist, return empty
			}
			return nil, fmt.Errorf("failed to stat path: %w", err)
		}

		if info.IsDir() {
			// List files in directory
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
			// It's a file, return it
			matches = []string{logpath}
		}
	}

	return matches, nil
}

// TestLogpathWithResolution resolves variables in logpath and tests the resolved path.
// Returns the original path, resolved path, matching files, and any error.
func TestLogpathWithResolution(logpath string) (originalPath, resolvedPath string, files []string, err error) {
	originalPath = strings.TrimSpace(logpath)
	if originalPath == "" {
		return originalPath, "", []string{}, nil
	}

	// Resolve variables
	resolvedPath, err = ResolveLogpathVariables(originalPath)
	if err != nil {
		return originalPath, "", nil, fmt.Errorf("failed to resolve logpath variables: %w", err)
	}

	// If resolution didn't change the path, resolvedPath will be the same
	if resolvedPath == "" {
		resolvedPath = originalPath
	}

	// Test the resolved path
	files, err = TestLogpath(resolvedPath)
	if err != nil {
		return originalPath, resolvedPath, nil, fmt.Errorf("failed to test logpath: %w", err)
	}

	return originalPath, resolvedPath, files, nil
}

// ExtractLogpathFromJailConfig extracts the logpath value(s) from jail configuration content.
// Supports multiple logpaths in a single line (space-separated) or multiple lines.
// Fail2ban supports both formats:
//
//	logpath = /var/log/file1.log /var/log/file2.log
//	logpath = /var/log/file1.log
//	         /var/log/file2.log
//
// Returns all logpaths joined by newlines.
func ExtractLogpathFromJailConfig(jailContent string) string {
	var logpaths []string
	scanner := bufio.NewScanner(strings.NewReader(jailContent))
	inLogpathLine := false
	currentLogpath := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments
		if strings.HasPrefix(line, "#") {
			if inLogpathLine && currentLogpath != "" {
				// End of logpath block at comment, process current logpath
				paths := strings.Fields(currentLogpath)
				logpaths = append(logpaths, paths...)
				currentLogpath = ""
				inLogpathLine = false
			}
			continue
		}

		// Check if this line starts with logpath =
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
			// Continuation line (indented or starting with space)
			// Fail2ban allows continuation lines for logpath
			if line != "" && !strings.Contains(line, "=") {
				// This is a continuation line, append to current logpath
				currentLogpath += " " + line
			} else {
				// End of logpath block, process current logpath
				if currentLogpath != "" {
					// Split by spaces to handle multiple logpaths in one line
					paths := strings.Fields(currentLogpath)
					logpaths = append(logpaths, paths...)
					currentLogpath = ""
				}
				inLogpathLine = false
			}
		} else if inLogpathLine && line == "" {
			// Empty line might end the logpath block
			if currentLogpath != "" {
				paths := strings.Fields(currentLogpath)
				logpaths = append(logpaths, paths...)
				currentLogpath = ""
			}
			inLogpathLine = false
		}
	}

	// Process any remaining logpath
	if currentLogpath != "" {
		paths := strings.Fields(currentLogpath)
		logpaths = append(logpaths, paths...)
	}

	// Join multiple logpaths with newlines
	return strings.Join(logpaths, "\n")
}

// ExtractFilterFromJailConfig extracts the filter name from jail configuration content.
// Handles formats like: filter = sshd, filter = sshd[mode=aggressive], etc.
// Returns the base filter name (without parameters in brackets).
func ExtractFilterFromJailConfig(jailContent string) string {
	scanner := bufio.NewScanner(strings.NewReader(jailContent))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "filter") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				filterValue := strings.TrimSpace(parts[1])
				// Extract base filter name (before [ if present)
				if idx := strings.Index(filterValue, "["); idx >= 0 {
					filterValue = filterValue[:idx]
				}
				return strings.TrimSpace(filterValue)
			}
		}
	}
	return ""
}

// UpdateDefaultSettingsLocal updates specific keys in the [DEFAULT] section of /etc/fail2ban/jail.local
// with the provided settings, preserving all other content including the ui-custom-action section.
// Removes commented lines (starting with #) before applying updates.
func UpdateDefaultSettingsLocal(settings config.AppSettings) error {
	config.DebugLog("UpdateDefaultSettingsLocal called")
	localPath := "/etc/fail2ban/jail.local"

	// Read existing file if it exists
	var existingContent string
	if content, err := os.ReadFile(localPath); err == nil {
		existingContent = string(content)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read jail.local: %w", err)
	}

	// Remove commented lines (lines starting with #) but preserve:
	// - Banner lines (containing "Fail2Ban-UI" or "fail2ban-ui")
	// - action_mwlg and action override lines
	lines := strings.Split(existingContent, "\n")
	var uncommentedLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Keep empty lines, banner lines, action_mwlg lines, action override lines, and lines that don't start with #
		isBanner := strings.Contains(line, "Fail2Ban-UI") || strings.Contains(line, "fail2ban-ui")
		isActionMwlg := strings.Contains(trimmed, "action_mwlg")
		isActionOverride := strings.Contains(trimmed, "action = %(action_mwlg)s")
		if trimmed == "" || !strings.HasPrefix(trimmed, "#") || isBanner || isActionMwlg || isActionOverride {
			uncommentedLines = append(uncommentedLines, line)
		}
	}
	existingContent = strings.Join(uncommentedLines, "\n")

	// Convert IgnoreIPs array to space-separated string
	ignoreIPStr := strings.Join(settings.IgnoreIPs, " ")
	if ignoreIPStr == "" {
		ignoreIPStr = "127.0.0.1/8 ::1"
	}
	// Set default banaction values if not set
	banaction := settings.Banaction
	if banaction == "" {
		banaction = "nftables-multiport"
	}
	banactionAllports := settings.BanactionAllports
	if banactionAllports == "" {
		banactionAllports = "nftables-allports"
	}
	chain := settings.Chain
	if chain == "" {
		chain = "INPUT"
	}
	// Define the keys we want to update
	keysToUpdate := map[string]string{
		"enabled":            fmt.Sprintf("enabled = %t", settings.DefaultJailEnable),
		"bantime.increment":  fmt.Sprintf("bantime.increment = %t", settings.BantimeIncrement),
		"ignoreip":           fmt.Sprintf("ignoreip = %s", ignoreIPStr),
		"bantime":            fmt.Sprintf("bantime = %s", settings.Bantime),
		"findtime":           fmt.Sprintf("findtime = %s", settings.Findtime),
		"maxretry":           fmt.Sprintf("maxretry = %d", settings.Maxretry),
		"banaction":          fmt.Sprintf("banaction = %s", banaction),
		"banaction_allports": fmt.Sprintf("banaction_allports = %s", banactionAllports),
		"chain":              fmt.Sprintf("chain = %s", chain),
	}
	if settings.BantimeRndtime != "" {
		keysToUpdate["bantime.rndtime"] = fmt.Sprintf("bantime.rndtime = %s", settings.BantimeRndtime)
	}
	defaultKeysOrder := []string{"enabled", "bantime.increment", "ignoreip", "bantime", "findtime", "maxretry", "banaction", "banaction_allports", "chain"}
	if settings.BantimeRndtime != "" {
		defaultKeysOrder = append(defaultKeysOrder, "bantime.rndtime")
	}

	// Track which keys we've updated
	keysUpdated := make(map[string]bool)

	// Parse existing content and update only specific keys in DEFAULT section
	if existingContent == "" {
		// File doesn't exist, create new one with banner and DEFAULT section
		var newLines []string
		newLines = append(newLines, strings.Split(strings.TrimRight(config.JailLocalBanner(), "\n"), "\n")...)
		newLines = append(newLines, "[DEFAULT]")
		for _, key := range defaultKeysOrder {
			newLines = append(newLines, keysToUpdate[key])
		}
		newLines = append(newLines, "")
		newContent := strings.Join(newLines, "\n")
		if err := os.WriteFile(localPath, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to write jail.local: %w", err)
		}
		config.DebugLog("Created new jail.local with banner and DEFAULT section")
		return nil
	}

	// Parse and update only specific keys in DEFAULT section
	lines = strings.Split(existingContent, "\n")
	var outputLines []string
	inDefault := false
	defaultSectionFound := false

	// Always add the full banner at the start
	outputLines = append(outputLines, strings.Split(strings.TrimRight(config.JailLocalBanner(), "\n"), "\n")...)

	// Skip everything before [DEFAULT] section (old banner, comments, empty lines)
	foundSection := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			// Found a section - stop skipping and process this line
			foundSection = true
		}
		if !foundSection {
			// Skip lines before any section (old banner, comments, empty lines)
			continue
		}

		// Process lines after we found a section
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			sectionName := strings.Trim(trimmed, "[]")
			if sectionName == "DEFAULT" {
				// Start of DEFAULT section
				inDefault = true
				defaultSectionFound = true
				outputLines = append(outputLines, line)
			} else {
				// Other section - stop DEFAULT mode
				inDefault = false
				outputLines = append(outputLines, line)
			}
		} else if inDefault {
			// We're in DEFAULT section - check if this line is a key we need to update
			keyUpdated := false
			// When user cleared bantime.rndtime, remove the line from config instead of keeping old value
			if settings.BantimeRndtime == "" {
				if matched, _ := regexp.MatchString(`^\s*bantime\.rndtime\s*=`, trimmed); matched {
					keyUpdated = true
					// don't append: line is removed
				}
			}
			if !keyUpdated {
				for key, newValue := range keysToUpdate {
					// Check if this line contains the key (with or without spaces around =)
					keyPattern := "^\\s*" + regexp.QuoteMeta(key) + "\\s*="
					if matched, _ := regexp.MatchString(keyPattern, trimmed); matched {
						outputLines = append(outputLines, newValue)
						keysUpdated[key] = true
						keyUpdated = true
						break
					}
				}
			}
			if !keyUpdated {
				// Keep the line as-is (might be other DEFAULT settings or action_mwlg)
				outputLines = append(outputLines, line)
			}
		} else {
			// Keep lines outside DEFAULT section (preserves ui-custom-action and other content)
			outputLines = append(outputLines, line)
		}
	}

	// If DEFAULT section wasn't found, create it at the beginning
	if !defaultSectionFound {
		defaultLines := []string{"[DEFAULT]"}
		for _, key := range defaultKeysOrder {
			defaultLines = append(defaultLines, keysToUpdate[key])
		}
		defaultLines = append(defaultLines, "")
		outputLines = append(defaultLines, outputLines...)
	} else {
		// Add any missing keys to the DEFAULT section
		for _, key := range defaultKeysOrder {
			if !keysUpdated[key] {
				// Find the DEFAULT section and insert after it
				for i, line := range outputLines {
					if strings.TrimSpace(line) == "[DEFAULT]" {
						// Insert after [DEFAULT] header
						outputLines = append(outputLines[:i+1], append([]string{keysToUpdate[key]}, outputLines[i+1:]...)...)
						break
					}
				}
			}
		}
	}

	newContent := strings.Join(outputLines, "\n")
	if err := os.WriteFile(localPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write jail.local: %w", err)
	}

	config.DebugLog("Updated specific keys in DEFAULT section of jail.local")
	return nil
}
