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
	"net"
	"regexp"
	"strings"
)

var (
	// An action.d name with optional [key=value,...] arguments, e.g. nftables[type=allports].
	banactionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}(\[[A-Za-z0-9_.,=:/ -]{0,128}\])?$`)
	chainRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
)

// Ensures a value is a well-formed IPv4/IPv6 address or CIDR before it is handed to fail2ban-client
func ValidateIP(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	if net.ParseIP(ip) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(ip); err == nil {
		return nil
	}
	return fmt.Errorf("invalid IP address or CIDR: %q", ip)
}

func IsReservedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate()
}

func ValidatePort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}
	return nil
}

// Splits a comma-separated string into trimmed, non-empty entries.
func SplitCommaList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// Checks one ignoreip entry: an IP, a CIDR range or a hostname.
func ValidateIgnoreIPEntry(entry string) error {
	if ValidateIP(entry) == nil {
		return nil
	}
	labels := strings.Split(entry, ".")
	if strings.ContainsAny(entry, ":/") || ValidateHost(entry) != nil || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return fmt.Errorf("invalid ignoreip entry %q: use an IP address, CIDR range or hostname", entry)
	}
	return nil
}

func ValidateBanactionName(name string) error {
	if !banactionRe.MatchString(name) {
		return fmt.Errorf("invalid banaction %q", name)
	}
	return nil
}

func ValidateChainName(name string) error {
	if !chainRe.MatchString(name) {
		return fmt.Errorf("invalid chain name %q", name)
	}
	return nil
}
