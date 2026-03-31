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
	"path/filepath"
	"strings"
)

// The standard Fail2ban configuration directory on Linux.
const DefaultConfigRoot = "/etc/fail2ban"

// Returns a cleaned path; empty input yields DefaultConfigRoot.
func NormalizeConfigPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return DefaultConfigRoot
	}
	return filepath.Clean(trimmed)
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
