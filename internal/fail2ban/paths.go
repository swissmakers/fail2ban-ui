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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// The standard Fail2ban configuration directory on Linux.
const DefaultConfigRoot = "/etc/fail2ban"

// Allowlist for jail/filter names that become filesystem path segments.
var safeConfigNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func NormalizeConfigPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return DefaultConfigRoot
	}
	cleaned := filepath.Clean(trimmed)
	if err := shared.ValidateAbsolutePath(cleaned, "config path"); err != nil {
		log.Printf("warning: ignoring unsafe config path %q, falling back to %s", path, DefaultConfigRoot)
		return DefaultConfigRoot
	}
	return cleaned
}

// Validates a user-supplied jail or filter name used as a single path segment.
func validateConfigName(name, label string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%s cannot be empty", label)
	}
	if !safeConfigNameRe.MatchString(name) {
		return fmt.Errorf("%s '%s' contains invalid characters. Only alphanumeric characters, dashes, and underscores are allowed", label, name)
	}
	if name[0] == '-' {
		return fmt.Errorf("%s '%s' must not start with a dash", label, name)
	}
	return nil
}

// Validates a jail or filter name for safe use as a single path segment.
func safeConfigName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if err := validateConfigName(name, "name"); err != nil {
		return "", err
	}
	return name, nil
}

// Validates name, joins dir/name+suffix, and guarantees the cleaned result stays inside dir.
func resolveWithinDir(dir, name, suffix string) (string, error) {
	safeName, err := safeConfigName(name)
	if err != nil {
		return "", err
	}
	cleanDir := filepath.Clean(dir)
	candidate := filepath.Join(cleanDir, safeName+suffix)
	if candidate != cleanDir && !strings.HasPrefix(candidate, cleanDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("resolved path %q escapes base directory %q", candidate, cleanDir)
	}
	return candidate, nil
}

// Returns jail.d under the given config root.
func JailDir(configPath string) string {
	return filepath.Join(NormalizeConfigPath(configPath), "jail.d")
}

// Returns filter.d under the given config root.
func FilterDir(configPath string) string {
	return filepath.Join(NormalizeConfigPath(configPath), "filter.d")
}

// Returns the path to jail.local under the given config root.
func JailLocal(configPath string) string {
	return filepath.Join(NormalizeConfigPath(configPath), "jail.local")
}

// Returns action.d under the given config root.
func ActionDir(configPath string) string {
	return filepath.Join(NormalizeConfigPath(configPath), "action.d")
}

// Returns the UI-managed custom action path.
func CustomActionFile(configPath string) string {
	return filepath.Join(ActionDir(configPath), "ui-custom-action.conf")
}
