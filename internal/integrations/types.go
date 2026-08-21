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

package integrations

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// =========================================================================
//  Types
// =========================================================================

// Block/Unblock request for an integration.
type Request struct {
	Context context.Context
	IP      string
	Config  config.AdvancedActionsConfig
	Server  config.Fail2banServer

	Logger func(format string, args ...interface{})
}

// =========================================================================
//  Input Validation
// =========================================================================

// Matches only alphanumeric characters, hyphens, underscores and dots
var safeIdentifier = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)
var safeESIndex = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,254}$`)

func ValidateElasticsearchIndex(index string) error {
	if index == "" {
		return fmt.Errorf("elasticsearch index is required")
	}
	if !safeESIndex.MatchString(index) {
		return fmt.Errorf("invalid elasticsearch index %q: use lowercase letters, digits, '.', '-' and '_'", index)
	}
	if strings.Contains(index, "..") {
		return fmt.Errorf("elasticsearch index must not contain '..': %q", index)
	}
	return nil
}

// Validates that the string is a valid IPv4/IPv6 address or CIDR notation and contains no shell metacharacters.
// Canonical implementation lives in shared (also used by the fail2ban connectors).
func ValidateIP(ip string) error {
	return shared.ValidateIP(ip)
}

// Validates that an user-configured base URL is well-formed and uses an allowed scheme (http/https).
func ValidateOutboundURL(rawURL, label string) error {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return fmt.Errorf("%s is required", label)
	}
	if strings.ContainsAny(trimmed, "\r\n") {
		return fmt.Errorf("%s contains invalid control characters", label)
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", label, err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("%s must use http or https", label)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s must include a host", label)
	}
	return nil
}

// Validates that a user-supplied name (address list, alias, etc.) contains only safe characters and cannot be used for injection attacks.
func ValidateIdentifier(name, label string) error {
	if name == "" {
		return fmt.Errorf("%s is required", label)
	}
	if !safeIdentifier.MatchString(name) {
		return fmt.Errorf("%s contains invalid characters: %q", label, name)
	}
	if name == "." || strings.Contains(name, "..") {
		return fmt.Errorf("%s must not contain '..': %q", label, name)
	}
	return nil
}

// Exposes functionality required by an external firewall vendor.
type Integration interface {
	ID() string
	DisplayName() string
	BlockIP(req Request) error
	UnblockIP(req Request) error
	Validate(cfg config.AdvancedActionsConfig) error
}

var registry = map[string]Integration{}

// =========================================================================
//  Registry
// =========================================================================

// Adds an integration to the registry.
func Register(integration Integration) {
	if integration == nil {
		return
	}
	registry[integration.ID()] = integration
}

// Returns the integration by id.
func Get(id string) (Integration, bool) {
	integration, ok := registry[id]
	return integration, ok
}
