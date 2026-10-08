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

package fail2ban

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

var ErrLogpathInaccessible = errors.New("logpath directory not accessible to the connector")

func ensureJailLocalFile(jailName, configPath string) error {
	return ensureLocalConfigFile(jailKind, jailName, configPath)
}

// =========================================================================
//  Config Read/Write
// =========================================================================

func readJailConfigWithFallback(jailName, configPath string) (string, string, error) {
	content, path, found, err := readLocalConfigWithFallback(jailKind, jailName, configPath)
	if err != nil {
		return "", "", err
	}
	if !found {
		debugf("Neither .local nor .conf exists for jail %s, returning empty section", jailName)
		return jailKind.seed(strings.TrimSpace(jailName)), path, nil
	}
	return content, path, nil
}

// =========================================================================
//  Validation
// =========================================================================

var enabledTruePattern = regexp.MustCompile(`(?m)^\s*enabled\s*=\s*true\s*$`)

// ALL and CHECK-INTEGRITY collide with fixed agent routes under /v1/jails/.
var reservedJailNames = map[string]bool{"DEFAULT": true, "INCLUDES": true, "ALL": true, "CHECK-INTEGRITY": true}

func ValidateJailName(name string) error {
	name = strings.TrimSpace(name)

	if reservedJailNames[strings.ToUpper(name)] {
		return fmt.Errorf("jail name '%s' is reserved and cannot be used", name)
	}

	return validateConfigName(name, "jail name")
}

// =========================================================================
//  Jail Discovery
// =========================================================================

// Returns all jails from the given config path's jail.d directory.
func DiscoverJailsFromFiles(configPath string) ([]JailInfo, error) {
	jailDPath := JailDir(configPath)

	if _, err := os.Stat(jailDPath); os.IsNotExist(err) {
		return []JailInfo{}, nil
	}

	files, err := listConfigFiles(jailKind, jailDPath)
	if err != nil {
		return nil, err
	}

	acc := newJailAccumulator()
	for _, suffix := range []string{".conf", ".local"} {
		for _, filePath := range files {
			if !strings.HasSuffix(filePath, suffix) {
				continue
			}
			content, err := os.ReadFile(filePath)
			if err != nil {
				return nil, fmt.Errorf("read jail file %s: %w", filePath, err)
			}
			acc.add(string(content), strings.TrimPrefix(suffix, "."))
		}
	}
	return acc.jails, nil
}

// =========================================================================
//  Jail Creation
// =========================================================================

func CreateJail(jailName, content, configPath string) error {
	if err := ValidateJailName(jailName); err != nil {
		return err
	}
	return createLocalConfigFile(jailKind, jailName, content, configPath)
}

// =========================================================================
//
//	Jail Deletion
//
// =========================================================================
func DeleteJail(jailName, configPath string) error {
	if err := ValidateJailName(jailName); err != nil {
		return err
	}
	return deleteLocalConfigFiles(jailKind, jailName, configPath)
}

// Returns all jails from the given config path.
func GetAllJails(configPath string) ([]JailInfo, error) {
	jails, err := DiscoverJailsFromFiles(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to discover jails from files: %w", err)
	}

	return jails, nil
}

// Returns the jail section names of a jail file body, in order.
func jailSectionNames(content string) []string {
	var names []string
	for _, line := range strings.Split(content, "\n") {
		if name, ok := sectionHeaderName(line); ok && name != "" && !isReservedSection(name) {
			names = append(names, name)
		}
	}
	return names
}

// =========================================================================
//  Jail Enabled from "Manage Jails"
// =========================================================================

func UpdateJailEnabledStates(updates map[string]bool, configPath string) error {
	debugf("UpdateJailEnabledStates called with %d updates: %+v", len(updates), updates)
	jailDPath := JailDir(configPath)

	for jailName, enabled := range updates {
		jailName = strings.TrimSpace(jailName)
		if jailName == "" {
			debugf("Skipping empty jail name in updates map")
			continue
		}
		if err := ValidateJailName(jailName); err != nil {
			return fmt.Errorf("invalid jail name in updates map: %w", err)
		}
		debugf("Processing jail: %s, enabled: %t", jailName, enabled)

		definingFiles, err := jailFilesDefining(jailName, jailDPath)
		if err != nil {
			return err
		}
		if len(definingFiles) == 0 {
			if err := ensureJailLocalFile(jailName, configPath); err != nil {
				return fmt.Errorf("failed to ensure .local file for jail %s: %w", jailName, err)
			}
			jailFilePath, err := resolveWithinDir(jailDPath, jailName, ".local")
			if err != nil {
				return err
			}
			definingFiles = []string{jailFilePath}
		}
		for _, jailFilePath := range definingFiles {
			if err := setJailEnabledInFile(jailFilePath, jailName, enabled); err != nil {
				return err
			}
			debugf("Updated jail %s: enabled = %t (file: %s)", jailName, enabled, jailFilePath)
		}
	}
	return nil
}

// Returns all jail.d/*.local files (sorted) containing a [jailName] section
func jailFilesDefining(jailName, jailDPath string) ([]string, error) {
	entries, err := os.ReadDir(jailDPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read jail.d directory %s: %w", jailDPath, err)
	}
	sectionHeader := fmt.Sprintf("[%s]", jailName)
	var files []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".local") {
			continue
		}
		path := filepath.Join(jailDPath, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			debugf("Skipping unreadable jail file %s: %v", path, err)
			continue
		}
		for _, line := range strings.Split(string(content), "\n") {
			if strings.TrimSpace(line) == sectionHeader {
				files = append(files, path)
				break
			}
		}
	}
	return files, nil
}

// Rewrites (or inserts) the enabled line of the [jailName] section in one file
func setJailEnabledInFile(jailFilePath, jailName string, enabled bool) error {
	content, err := os.ReadFile(jailFilePath)
	if err != nil {
		return fmt.Errorf("failed to read jail .local file %s: %w", jailFilePath, err)
	}
	newContent := rewriteJailEnabled(string(content), jailName, enabled)
	if err := writeConfigAtomic(jailFilePath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write jail file %s: %w", jailFilePath, err)
	}
	return nil
}

func containsJailSection(content, jailName string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "["+jailName+"]" {
			return true
		}
	}
	return false
}

// Rewrites (or inserts) the enabled line of the [jailName] section in the given file content
// Shared by the local and SSH connectors
func rewriteJailEnabled(content, jailName string, enabled bool) string {
	var lines []string
	if len(content) > 0 {
		lines = strings.Split(content, "\n")
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
	return newContent
}

// Returns the full jail configuration from /etc/fail2ban/jail.d/{jailName}.local (falling back to .conf)
func GetJailConfig(jailName, configPath string) (string, string, error) {
	jailName = strings.TrimSpace(jailName)
	if jailName == "" {
		return "", "", fmt.Errorf("jail name cannot be empty")
	}

	debugf("GetJailConfig called for jail: %s", jailName)
	content, filePath, err := readJailConfigWithFallback(jailName, configPath)
	if err != nil {
		debugf("Failed to read jail config: %v", err)
		return "", "", fmt.Errorf("failed to read jail config for %s: %w", jailName, err)
	}

	debugf("Jail config read successfully, length: %d, file: %s", len(content), filePath)
	return content, filePath, nil
}

// Returns the filter a jail uses: its filter directive, else the jail name.
func FilterNameForJail(jailName, jailContent string) string {
	if f := filterDirective(jailContent); f != "" {
		return f
	}
	return jailName
}

// Extracts the filter name from the jail configuration.
func filterDirective(jailContent string) string {
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

// Ensures one [jailName] header: dedupes it, else renames the first jail header, else prepends one.
func NormalizeJailSection(jailName, content string) string {
	want := "[" + jailName + "]"
	if strings.TrimSpace(content) == "" {
		return want + "\n"
	}
	lines := strings.Split(content, "\n")
	firstOther := -1
	hasWanted := false
	for i, line := range lines {
		name, ok := sectionHeaderName(line)
		if !ok {
			continue
		}
		if name == jailName {
			hasWanted = true
			break
		}
		if firstOther < 0 && !isReservedSection(name) {
			firstOther = i
		}
	}
	switch {
	case hasWanted:
		kept := make([]string, 0, len(lines))
		seen := false
		for _, line := range lines {
			if name, ok := sectionHeaderName(line); ok && name == jailName {
				if seen {
					continue
				}
				seen = true
			}
			kept = append(kept, line)
		}
		lines = kept
	case firstOther >= 0:
		lines[firstOther] = want
	default:
		lines = append([]string{want}, lines...)
	}
	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out
}

func sectionHeaderName(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if len(t) < 2 || t[0] != '[' || t[len(t)-1] != ']' {
		return "", false
	}
	return strings.TrimSpace(t[1 : len(t)-1]), true
}

func isReservedSection(name string) bool {
	return name == "DEFAULT" || name == "INCLUDES"
}

// Writes the full jail configuration to /etc/fail2ban/jail.d/{jailName}.local
func SetJailConfig(jailName, content, configPath string) error {
	jailName = strings.TrimSpace(jailName)
	if jailName == "" {
		return fmt.Errorf("jail name cannot be empty")
	}
	if err := ValidateJailName(jailName); err != nil {
		return err
	}
	debugf("SetJailConfig called for jail: %s, content length: %d", jailName, len(content))

	jailDPath := JailDir(configPath)
	if err := ensureJailLocalFile(jailName, configPath); err != nil {
		return fmt.Errorf("failed to ensure .local file for jail %s: %w", jailName, err)
	}

	jailFilePath, err := resolveWithinDir(jailDPath, jailName, ".local")
	if err != nil {
		return err
	}
	debugf("Writing jail config to: %s", jailFilePath)
	if err := writeConfigAtomic(jailFilePath, []byte(content), 0644); err != nil {
		debugf("Failed to write jail config: %v", err)
		return fmt.Errorf("failed to write jail config for %s: %w", jailName, err)
	}
	debugf("Jail config written successfully to .local file")

	return nil
}

// =========================================================================
//  Logpath Operations
// =========================================================================

// Glob variant of shared.ValidateAbsolutePath's charset: same allowlist plus
// the glob metacharacters '*', '?' and '[]' that logpaths may contain.
var safeLogpathRe = regexp.MustCompile(`^[A-Za-z0-9 ._/*?\[\]-]+$`)

func sanitizeLogpath(logpath string) (string, error) {
	logpath = strings.TrimSpace(logpath)
	if logpath == "" {
		return "", nil
	}
	if strings.ContainsRune(logpath, 0) {
		return "", fmt.Errorf("invalid log path")
	}
	if !filepath.IsAbs(logpath) {
		return "", fmt.Errorf("log path %q must be absolute", logpath)
	}
	if !safeLogpathRe.MatchString(logpath) {
		return "", fmt.Errorf("log path %q contains unsupported characters", logpath)
	}
	if strings.Contains(logpath, "..") {
		return "", fmt.Errorf("log path %q must not contain '..'", logpath)
	}
	return logpath, nil
}

func TestLogpath(logpath string) ([]string, error) {
	logpath, err := sanitizeLogpath(logpath)
	if err != nil {
		return nil, err
	}
	if logpath == "" {
		return []string{}, nil
	}
	hasWildcard := strings.ContainsAny(logpath, "*?[")

	var matches []string

	if hasWildcard {
		matched, err := filepath.Glob(logpath)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern: %w", err)
		}
		if len(matched) == 0 {
			if _, statErr := os.ReadDir(filepath.Dir(logpath)); statErr != nil && os.IsPermission(statErr) {
				return nil, ErrLogpathInaccessible
			}
		}
		matches = matched
	} else {
		info, err := os.Stat(logpath)
		if err != nil {
			if os.IsNotExist(err) {
				return []string{}, nil
			}
			if os.IsPermission(err) {
				return nil, ErrLogpathInaccessible
			}
			return nil, fmt.Errorf("failed to stat path: %w", err)
		}

		if info.IsDir() {
			entries, err := os.ReadDir(logpath)
			if err != nil {
				if os.IsPermission(err) {
					return nil, ErrLogpathInaccessible
				}
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
func TestLogpathWithResolution(logpath, configPath string) (originalPath, resolvedPath string, files []string, err error) {
	originalPath = strings.TrimSpace(logpath)
	if originalPath == "" {
		return originalPath, "", []string{}, nil
	}
	resolvedPath, err = ResolveLogpathVariables(originalPath, configPath)
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
		}
	}

	if currentLogpath != "" {
		paths := strings.Fields(currentLogpath)
		logpaths = append(logpaths, paths...)
	}

	return strings.Join(logpaths, "\n")
}

// =========================================================================
//  Jail Auto Migration (EXPERIMENTAL, runs only when JAIL_AUTOMIGRATION=true)
// =========================================================================

// Config roots already migrated in this process; the migration writes a backup even when it moves nothing.
var migratedRoots sync.Map

func isJailAutoMigrationEnabled() bool {
	return shared.EnvBool("JAIL_AUTOMIGRATION")
}

// Migrates jail.local to jail.d/*.local.
func MigrateJailsFromJailLocal(configPath string) error {
	localPath := JailLocal(configPath)
	jailDPath := JailDir(configPath)

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
		debugf("No jails to migrate from jail.local")
		return nil
	}
	backupPath := localPath + ".backup." + fmt.Sprintf("%d", time.Now().Unix())
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	debugf("Created backup of jail.local at %s", backupPath)

	if err := os.MkdirAll(jailDPath, 0755); err != nil {
		return fmt.Errorf("failed to create jail.d directory: %w", err)
	}
	migratedCount := 0
	for jailName, jailContent := range sections {
		if jailName == "" {
			continue
		}
		jailFilePath, err := resolveWithinDir(jailDPath, jailName, ".local")
		if err != nil {
			debugf("Skipping migration for jail %q: %v", jailName, err)
			continue
		}
		if _, err := os.Stat(jailFilePath); err == nil {
			debugf("Skipping migration for jail %s: .local file already exists", jailName)
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
			jailContent = enabledTruePattern.ReplaceAllString(jailContent, "enabled = false")
		}
		if err := os.WriteFile(jailFilePath, []byte(jailContent), 0644); err != nil {
			return fmt.Errorf("failed to write jail file %s: %w", jailFilePath, err)
		}
		debugf("Migrated jail %s to %s (enabled = false)", jailName, jailFilePath)
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
		debugf("Migration completed: moved %d jails to jail.d/", migratedCount)
	}
	return nil
}

// Parses an existing jail configuration and returns all jail sections from the file.
func parseJailSectionsUncommented(content string) (map[string]string, string, error) {
	sections := make(map[string]string)
	var defaultContent strings.Builder

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
				} else if !isReservedSection(currentSection) && !sectionIsCommented {
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
		} else if !isReservedSection(currentSection) && !sectionIsCommented {
			sections[currentSection] = sectionContent
		}
	}

	return sections, defaultContent.String(), scanner.Err()
}
