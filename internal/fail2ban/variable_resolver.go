// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2025 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the PolyForm Shield License 1.0.0.
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://polyformproject.org/licenses/shield/1.0.0/
//
//     or in the LICENSE file in this repository.
//
// Required Notice: Copyright Swissmakers GmbH (https://swissmakers.ch)

package fail2ban

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// =========================================================================
//  Pattern Matching
// =========================================================================

var variablePattern = regexp.MustCompile(`%\(([^)]+)\)s`)

func extractVariablesFromString(s string) []string {
	matches := variablePattern.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil
	}

	var variables []string
	for _, match := range matches {
		if len(match) > 1 {
			variables = append(variables, match[1])
		}
	}
	return variables
}

// =========================================================================
//  Variable Lookup
// =========================================================================

func searchVariableInFile(filePath, varName string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentVar string
	var currentValue strings.Builder
	var inMultiLine bool
	var pendingLine string
	var pendingLineOriginal string

	for {
		var originalLine string
		var line string

		if pendingLine != "" {
			originalLine = pendingLineOriginal
			line = pendingLine
			pendingLine = ""
			pendingLineOriginal = ""
		} else {
			if !scanner.Scan() {
				break
			}
			originalLine = scanner.Text()
			line = strings.TrimSpace(originalLine)
		}

		if !inMultiLine && (strings.HasPrefix(line, "#") || line == "") {
			continue
		}

		if !inMultiLine {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				if strings.EqualFold(key, varName) {
					debugf("findVariableDefinition: found variable '%s' = '%s' in file %s", key, value, filePath)
					currentVar = key
					currentValue.WriteString(value)

					if scanner.Scan() {
						nextLineOriginal := scanner.Text()
						nextLineTrimmed := strings.TrimSpace(nextLineOriginal)

						isContinuation := nextLineTrimmed != "" &&
							!strings.HasPrefix(nextLineTrimmed, "#") &&
							!strings.HasPrefix(nextLineTrimmed, "[") &&
							(strings.HasPrefix(nextLineOriginal, " ") || strings.HasPrefix(nextLineOriginal, "\t") ||
								(!strings.Contains(nextLineTrimmed, "=")))

						if isContinuation {
							inMultiLine = true
							pendingLine = nextLineTrimmed
							pendingLineOriginal = nextLineOriginal
							continue
						} else {
							return strings.TrimSpace(currentValue.String()), nil
						}
					} else {
						return strings.TrimSpace(currentValue.String()), nil
					}
				}
			}
		} else {
			trimmedLine := strings.TrimSpace(originalLine)

			if strings.HasPrefix(trimmedLine, "[") {
				return strings.TrimSpace(currentValue.String()), nil
			}

			if strings.Contains(trimmedLine, "=") && !strings.HasPrefix(originalLine, " ") && !strings.HasPrefix(originalLine, "\t") {
				return strings.TrimSpace(currentValue.String()), nil
			}

			if currentValue.Len() > 0 {
				currentValue.WriteString(" ")
			}
			currentValue.WriteString(trimmedLine)

			if scanner.Scan() {
				nextLineOriginal := scanner.Text()
				nextLineTrimmed := strings.TrimSpace(nextLineOriginal)

				if nextLineTrimmed == "" ||
					strings.HasPrefix(nextLineTrimmed, "#") ||
					strings.HasPrefix(nextLineTrimmed, "[") ||
					(strings.Contains(nextLineTrimmed, "=") && !strings.HasPrefix(nextLineOriginal, " ") && !strings.HasPrefix(nextLineOriginal, "\t")) {
					return strings.TrimSpace(currentValue.String()), nil
				}
				pendingLine = nextLineTrimmed
				pendingLineOriginal = nextLineOriginal
				continue
			} else {
				return strings.TrimSpace(currentValue.String()), nil
			}
		}
	}

	if inMultiLine && currentVar != "" {
		return strings.TrimSpace(currentValue.String()), nil
	}

	return "", nil
}

// Searches for a variable definition in all .local files first, then .conf files under /etc/fail2ban/ and subdirectories.
// Returns the FIRST value found (prioritizing .local over .conf).
func findVariableDefinition(varName, fail2banPath string) (string, error) {
	fail2banPath = NormalizeConfigPath(fail2banPath)
	debugf("findVariableDefinition: searching for variable '%s'", varName)

	if _, err := os.Stat(fail2banPath); os.IsNotExist(err) {
		return "", fmt.Errorf("variable '%s' not found: /etc/fail2ban directory does not exist", varName)
	}

	var foundValue string
	err := filepath.Walk(fail2banPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".local") {
			return nil
		}

		value, err := searchVariableInFile(path, varName)
		if err != nil {
			return nil
		}

		if value != "" {
			foundValue = value
			return filepath.SkipAll
		}
		return nil
	})

	if foundValue != "" {
		debugf("findVariableDefinition: returning value '%s' for variable '%s' (from .local file)", foundValue, varName)
		return foundValue, nil
	}

	if err != nil && err != filepath.SkipAll {
		return "", err
	}

	debugf("findVariableDefinition: variable '%s' not found in .local files, searching .conf files", varName)
	err = filepath.Walk(fail2banPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".conf") {
			return nil
		}

		value, err := searchVariableInFile(path, varName)
		if err != nil {
			return nil
		}

		if value != "" {
			foundValue = value
			return filepath.SkipAll
		}
		return nil
	})

	if foundValue != "" {
		debugf("findVariableDefinition: returning value '%s' for variable '%s' (from .conf file)", foundValue, varName)
		return foundValue, nil
	}

	if err != nil && err != filepath.SkipAll {
		return "", err
	}

	debugf("findVariableDefinition: variable '%s' not found", varName)
	return "", fmt.Errorf("variable '%s' not found in Fail2Ban configuration files", varName)
}

// =========================================================================
//  Resolution
// =========================================================================

func resolveVariableRecursive(varName string, visited map[string]bool, fail2banPath string) (string, error) {
	if visited[varName] {
		return "", fmt.Errorf("circular reference detected for variable '%s'", varName)
	}

	visited[varName] = true
	defer delete(visited, varName)

	value, err := findVariableDefinition(varName, fail2banPath)
	if err != nil {
		return "", err
	}

	resolved := value
	maxIterations := 10
	iteration := 0

	for iteration < maxIterations {
		variables := extractVariablesFromString(resolved)
		if len(variables) == 0 {
			debugf("resolveVariableRecursive: '%s' fully resolved to '%s'", varName, resolved)
			break
		}
		debugf("resolveVariableRecursive: iteration %d for '%s', found %d variables in '%s': %v", iteration+1, varName, len(variables), resolved, variables)

		for _, nestedVar := range variables {
			if visited[nestedVar] {
				return "", fmt.Errorf("circular reference detected: '%s' -> '%s'", varName, nestedVar)
			}

			debugf("resolveVariableRecursive: resolving nested variable '%s' for '%s'", nestedVar, varName)
			nestedValue, err := resolveVariableRecursive(nestedVar, visited, fail2banPath)
			if err != nil {
				return "", fmt.Errorf("failed to resolve variable '%s' in '%s': %w", nestedVar, varName, err)
			}

			debugf("resolveVariableRecursive: resolved '%s' to '%s' for '%s'", nestedVar, nestedValue, varName)
			pattern := fmt.Sprintf("%%\\(%s\\)s", regexp.QuoteMeta(nestedVar))
			re := regexp.MustCompile(pattern)
			beforeReplace := resolved
			resolved = re.ReplaceAllString(resolved, nestedValue)
			debugf("resolveVariableRecursive: replaced pattern '%s' in '%s' with '%s', result: '%s'", pattern, beforeReplace, nestedValue, resolved)

			if beforeReplace == resolved {
				debugf("resolveVariableRecursive: WARNING - replacement did not change string! Pattern: '%s', Before: '%s', After: '%s'", pattern, beforeReplace, resolved)
				return "", fmt.Errorf("failed to replace variable '%s' in '%s': pattern '%s' did not match", nestedVar, beforeReplace, pattern)
			}
		}
		remainingVars := extractVariablesFromString(resolved)
		if len(remainingVars) == 0 {
			debugf("resolveVariableRecursive: '%s' fully resolved to '%s' after replacements", varName, resolved)
			break
		}
		iteration++
	}

	if iteration >= maxIterations {
		return "", fmt.Errorf("maximum resolution iterations reached for variable '%s', possible circular reference. Last resolved value: '%s'", varName, resolved)
	}
	return resolved, nil
}

// Expands %(var)s patterns in logpath using fail2ban config path.
func ResolveLogpathVariables(logpath, fail2banPath string) (string, error) {
	if logpath == "" {
		return "", nil
	}
	logpath = strings.TrimSpace(logpath)

	resolved := logpath
	maxIterations := 10
	iteration := 0

	for iteration < maxIterations {
		variables := extractVariablesFromString(resolved)
		if len(variables) == 0 {
			break
		}

		debugf("ResolveLogpathVariables: iteration %d, found %d variables in '%s'", iteration+1, len(variables), resolved)

		visited := make(map[string]bool)
		for _, varName := range variables {
			debugf("ResolveLogpathVariables: resolving variable '%s' from string '%s'", varName, resolved)
			varValue, err := resolveVariableRecursive(varName, visited, fail2banPath)
			if err != nil {
				return "", fmt.Errorf("failed to resolve variable '%s': %w", varName, err)
			}

			debugf("ResolveLogpathVariables: resolved variable '%s' to '%s'", varName, varValue)

			pattern := fmt.Sprintf("%%\\(%s\\)s", regexp.QuoteMeta(varName))
			re := regexp.MustCompile(pattern)
			beforeReplace := resolved
			resolved = re.ReplaceAllString(resolved, varValue)
			debugf("ResolveLogpathVariables: replaced pattern '%s' in '%s' with '%s', result: '%s'", pattern, beforeReplace, varValue, resolved)
		}

		iteration++
	}

	if iteration >= maxIterations {
		return "", fmt.Errorf("maximum resolution iterations reached, possible circular reference in logpath '%s'", logpath)
	}

	debugf("Resolved logpath: '%s' -> '%s'", logpath, resolved)
	return resolved, nil
}
