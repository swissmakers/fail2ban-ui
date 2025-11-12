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
	"strings"
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

// GetFilterConfigLocal reads a filter configuration from the local filesystem.
func GetFilterConfigLocal(jail string) (string, error) {
	configPath := filepath.Join("/etc/fail2ban/filter.d", jail+".conf")
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config for jail %s: %v", jail, err)
	}
	return string(content), nil
}

// SetFilterConfigLocal writes the filter configuration to the local filesystem.
func SetFilterConfigLocal(jail, newContent string) error {
	configPath := filepath.Join("/etc/fail2ban/filter.d", jail+".conf")
	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write config for jail %s: %v", jail, err)
	}
	return nil
}

// GetFiltersLocal returns a list of filter names from /etc/fail2ban/filter.d
func GetFiltersLocal() ([]string, error) {
	dir := "/etc/fail2ban/filter.d"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read filter directory: %w", err)
	}
	var filters []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
			name := strings.TrimSuffix(entry.Name(), ".conf")
			filters = append(filters, name)
		}
	}
	return filters, nil
}

// TestFilterLocal tests a filter against log lines using fail2ban-regex
func TestFilterLocal(filterName string, logLines []string) ([]string, error) {
	if len(logLines) == 0 {
		return []string{}, nil
	}
	filterPath := filepath.Join("/etc/fail2ban/filter.d", filterName+".conf")
	if _, err := os.Stat(filterPath); err != nil {
		return nil, fmt.Errorf("filter %s not found: %w", filterName, err)
	}
	// Use fail2ban-regex with filter file directly - it handles everything
	// Format: fail2ban-regex "log line" /etc/fail2ban/filter.d/filter-name.conf
	var matches []string
	for _, logLine := range logLines {
		logLine = strings.TrimSpace(logLine)
		if logLine == "" {
			continue
		}
		cmd := exec.Command("fail2ban-regex", logLine, filterPath)
		out, err := cmd.CombinedOutput()
		output := strings.ToLower(string(out))
		// fail2ban-regex returns success (exit 0) if the line matches
		// Look for "matched" or "success" in output
		if err == nil {
			if strings.Contains(output, "matched") ||
				strings.Contains(output, "success") ||
				strings.Contains(output, "1 matched") {
				matches = append(matches, logLine)
			}
		}
	}
	return matches, nil
}
