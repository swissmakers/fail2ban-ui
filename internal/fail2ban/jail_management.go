package fail2ban

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

var (
	migrationOnce sync.Once
)

// GetAllJails reads jails from /etc/fail2ban/jail.local (DEFAULT only) and /etc/fail2ban/jail.d directory.
// Automatically migrates legacy jails from jail.local to jail.d on first call.
func GetAllJails() ([]JailInfo, error) {
	// Run migration once if needed
	migrationOnce.Do(func() {
		if err := MigrateJailsToJailD(); err != nil {
			config.DebugLog("Migration warning: %v", err)
		}
	})

	var jails []JailInfo

	// Parse only DEFAULT section from jail.local (skip other jails)
	localPath := "/etc/fail2ban/jail.local"
	if _, err := os.Stat(localPath); err == nil {
		defaultJails, err := parseJailConfigFileOnlyDefault(localPath)
		if err == nil {
			jails = append(jails, defaultJails...)
		}
	}

	// Parse jails from jail.d directory
	jailDPath := "/etc/fail2ban/jail.d"
	if _, err := os.Stat(jailDPath); err == nil {
		files, err := os.ReadDir(jailDPath)
		if err == nil {
			for _, f := range files {
				if !f.IsDir() && filepath.Ext(f.Name()) == ".conf" {
					fullPath := filepath.Join(jailDPath, f.Name())
					dJails, err := parseJailConfigFile(fullPath)
					if err == nil {
						jails = append(jails, dJails...)
					}
				}
			}
		}
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
			currentJail = strings.Trim(line, "[]")
			// Reset to default for the new section.
			enabled = true
		} else if strings.HasPrefix(strings.ToLower(line), "enabled") {
			// Expect format: enabled = true/false
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				value := strings.TrimSpace(parts[1])
				enabled = strings.EqualFold(value, "true")
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
// Updates only the corresponding file in /etc/fail2ban/jail.d/ for each jail.
func UpdateJailEnabledStates(updates map[string]bool) error {
	jailDPath := "/etc/fail2ban/jail.d"

	// Ensure jail.d directory exists
	if err := os.MkdirAll(jailDPath, 0755); err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}

	// Update each jail in its own file
	for jailName, enabled := range updates {
		jailFilePath := filepath.Join(jailDPath, jailName+".conf")

		// Read existing file if it exists
		content, err := os.ReadFile(jailFilePath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to read jail file %s: %w", jailFilePath, err)
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
		if err := os.WriteFile(jailFilePath, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to write jail file %s: %w", jailFilePath, err)
		}
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

// parseJailConfigFileOnlyDefault parses only the DEFAULT section from a jail config file.
func parseJailConfigFileOnlyDefault(path string) ([]JailInfo, error) {
	var jails []JailInfo
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// We scan through the file but don't return any jails from DEFAULT section
	// This function exists to validate the file can be read
	for scanner.Scan() {
		// Just scan through - we don't need to parse anything for DEFAULT
	}

	// We don't return DEFAULT as a jail, but we could if needed
	// For now, we only return jails from DEFAULT if they're explicitly listed (unlikely)
	return jails, scanner.Err()
}

// GetJailConfig reads the full jail configuration from /etc/fail2ban/jail.d/{jailName}.conf
func GetJailConfig(jailName string) (string, error) {
	config.DebugLog("GetJailConfig called for jail: %s", jailName)
	jailDPath := "/etc/fail2ban/jail.d"
	jailFilePath := filepath.Join(jailDPath, jailName+".conf")
	config.DebugLog("Reading jail config from: %s", jailFilePath)

	content, err := os.ReadFile(jailFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			config.DebugLog("Jail config file does not exist, returning empty section")
			// Return empty jail section if file doesn't exist
			return fmt.Sprintf("[%s]\n", jailName), nil
		}
		config.DebugLog("Failed to read jail config file: %v", err)
		return "", fmt.Errorf("failed to read jail config for %s: %w", jailName, err)
	}

	config.DebugLog("Jail config read successfully, length: %d", len(content))
	return string(content), nil
}

// SetJailConfig writes the full jail configuration to /etc/fail2ban/jail.d/{jailName}.conf
func SetJailConfig(jailName, content string) error {
	config.DebugLog("SetJailConfig called for jail: %s, content length: %d", jailName, len(content))

	jailDPath := "/etc/fail2ban/jail.d"

	// Ensure jail.d directory exists
	if err := os.MkdirAll(jailDPath, 0755); err != nil {
		config.DebugLog("Failed to create jail.d directory: %v", err)
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}
	config.DebugLog("jail.d directory ensured")

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

	jailFilePath := filepath.Join(jailDPath, jailName+".conf")
	config.DebugLog("Writing jail config to: %s", jailFilePath)
	if err := os.WriteFile(jailFilePath, []byte(content), 0644); err != nil {
		config.DebugLog("Failed to write jail config: %v", err)
		return fmt.Errorf("failed to write jail config for %s: %w", jailName, err)
	}
	config.DebugLog("Jail config written successfully")

	return nil
}

// TestLogpath tests a logpath pattern and returns matching files.
// Supports wildcards/glob patterns (e.g., /var/log/*.log) and directory paths.
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

// ExtractLogpathFromJailConfig extracts the logpath value from jail configuration content.
func ExtractLogpathFromJailConfig(jailContent string) string {
	scanner := bufio.NewScanner(strings.NewReader(jailContent))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(strings.ToLower(line), "logpath") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
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
		banaction = "iptables-multiport"
	}
	banactionAllports := settings.BanactionAllports
	if banactionAllports == "" {
		banactionAllports = "iptables-allports"
	}
	// Define the keys we want to update
	keysToUpdate := map[string]string{
		"bantime.increment":  fmt.Sprintf("bantime.increment = %t", settings.BantimeIncrement),
		"ignoreip":           fmt.Sprintf("ignoreip = %s", ignoreIPStr),
		"bantime":            fmt.Sprintf("bantime = %s", settings.Bantime),
		"findtime":           fmt.Sprintf("findtime = %s", settings.Findtime),
		"maxretry":           fmt.Sprintf("maxretry = %d", settings.Maxretry),
		"destemail":          fmt.Sprintf("destemail = %s", settings.Destemail),
		"banaction":          fmt.Sprintf("banaction = %s", banaction),
		"banaction_allports": fmt.Sprintf("banaction_allports = %s", banactionAllports),
	}

	// Track which keys we've updated
	keysUpdated := make(map[string]bool)

	// Parse existing content and update only specific keys in DEFAULT section
	if existingContent == "" {
		// File doesn't exist, create new one with DEFAULT section
		defaultLines := []string{"[DEFAULT]"}
		for _, key := range []string{"bantime.increment", "ignoreip", "bantime", "findtime", "maxretry", "destemail"} {
			defaultLines = append(defaultLines, keysToUpdate[key])
		}
		defaultLines = append(defaultLines, "")
		newContent := strings.Join(defaultLines, "\n")
		if err := os.WriteFile(localPath, []byte(newContent), 0644); err != nil {
			return fmt.Errorf("failed to write jail.local: %w", err)
		}
		config.DebugLog("Created new jail.local with DEFAULT section")
		return nil
	}

	// Parse and update only specific keys in DEFAULT section
	lines = strings.Split(existingContent, "\n")
	var outputLines []string
	inDefault := false
	defaultSectionFound := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

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
		for _, key := range []string{"bantime.increment", "ignoreip", "bantime", "findtime", "maxretry", "destemail"} {
			defaultLines = append(defaultLines, keysToUpdate[key])
		}
		defaultLines = append(defaultLines, "")
		outputLines = append(defaultLines, outputLines...)
	} else {
		// Add any missing keys to the DEFAULT section
		for _, key := range []string{"bantime.increment", "ignoreip", "bantime", "findtime", "maxretry", "destemail"} {
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
