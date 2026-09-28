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
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// These values end up in a root-executed fail2ban action, so only plain URL/token characters pass.
var (
	callbackURLRe = regexp.MustCompile(`^(?i:https?)://([A-Za-z0-9._-]+|\[[0-9A-Fa-f:.]+\])(:([0-9]{1,5}))?(/[A-Za-z0-9._~/-]*)?$`)
	serverIDRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Checks a callback base URL; the value must already be trimmed of whitespace and trailing slashes.
func ValidateCallbackURL(url string) error {
	m := callbackURLRe.FindStringSubmatch(url)
	if m == nil {
		return fmt.Errorf("invalid callback URL %q: use http(s)://host[:port][/path] with only letters, digits and . _ ~ / -", url)
	}
	if m[3] != "" {
		if port, _ := strconv.Atoi(m[3]); port < 1 || port > 65535 {
			return fmt.Errorf("invalid callback URL %q: port out of range", url)
		}
	}
	return nil
}

// Checks a callback secret; empty is allowed and means "generate one".
func ValidateCallbackSecret(secret string) error {
	for _, r := range secret {
		if r < 0x21 || r > 0x7e || strings.ContainsRune("'\"\\`$%<>", r) {
			return fmt.Errorf("callback secret contains an unsupported character: use printable ASCII without spaces, quotes, \\, `, $, %%, < or >")
		}
	}
	return nil
}

func ValidateServerID(id string) error {
	if !serverIDRe.MatchString(id) {
		return fmt.Errorf("invalid server id %q: only letters, digits, '.', '-' and '_' are allowed", id)
	}
	return nil
}
