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

package shared

import (
	"os"
	"path/filepath"
	"strings"
)

// Reports whether an environment variable is set to 1, true, yes or on.
func EnvBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Whether callback requests skip TLS verification (CALLBACK_INSECURE_TLS).
func CallbackInsecureTLS() bool {
	return EnvBool("CALLBACK_INSECURE_TLS")
}

// Directory for SSH keys and known_hosts: /config/.ssh in the container image, ~/.ssh on a host.
func SSHDir() (string, error) {
	if _, container := os.LookupEnv("CONTAINER"); container {
		return "/config/.ssh", nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh"), nil
}
