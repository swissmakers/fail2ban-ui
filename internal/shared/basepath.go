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
	"strings"
	"sync"
)

var (
	basePathMu    sync.RWMutex
	basePath      string
	basePathKnown bool
)

// Returns the normalized BASE_PATH prefix ("" for root), read from the environment on first use.
func BasePath() string {
	basePathMu.RLock()
	if basePathKnown {
		defer basePathMu.RUnlock()
		return basePath
	}
	basePathMu.RUnlock()
	basePathMu.Lock()
	defer basePathMu.Unlock()
	if !basePathKnown {
		basePath, basePathKnown = NormalizeBasePath(os.Getenv("BASE_PATH")), true
	}
	return basePath
}

// Overrides the prefix -> tests use it instead of BASE_PATH, which is read only once.
func SetBasePath(raw string) {
	basePathMu.Lock()
	defer basePathMu.Unlock()
	basePath, basePathKnown = NormalizeBasePath(raw), true
}

// NormalizeBasePath returns a safe URL prefix, without a trailing slash.
func NormalizeBasePath(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "/" {
		return ""
	}
	// We reject control characters, backslashes, and scheme separators.
	if strings.ContainsAny(s, ":\\\r\n") {
		return ""
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	if strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") {
		return ""
	}
	return strings.TrimSuffix(s, "/")
}
