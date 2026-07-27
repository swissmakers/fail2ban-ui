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

// Shared types, helpers, and high-level functions used across all connectors.
package fail2ban

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// =========================================================================
//  Validation
// =========================================================================

// Ensures an IP/CIDR is well-formed
func ValidateIP(ip string) error {
	return shared.ValidateIP(ip)
}

// Inspects fail2ban-client reload output for the markers tha indicate the daemon reloaded but a jail/filter failed to apply
func checkReloadOutput(output string) error {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" || trimmed == "OK" {
		return nil
	}
	if strings.Contains(output, "Errors in jail") || strings.Contains(output, "Unable to read the filter") {
		return fmt.Errorf("fail2ban reload completed but with errors (output: %s)", trimmed)
	}
	return nil
}

// Marker that identifies a jail.local as generated and owned by Fail2ban-UI
const managedJailLocalMarker = "ui-custom-action"

// =========================================================================
//  Shared fail2ban-client Output Parsers
// =========================================================================

// Locates the banned payload line. fail2ban prints the whole repr as one line on stdout, but a fail2ban.conf with 'logtarget = STDOUT' makes the
// client write its own log lines to stdout first, so skip anything ahead of the first line that starts the list.
func extractBannedPayload(out string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			return trimmed, true
		}
	}
	return "", false
}

// Appends the minimum-version hint only when fail2ban actually rejected the command
func bannedVersionHint(out string) string {
	lower := strings.ToLower(out)
	if strings.Contains(lower, "not supported") || strings.Contains(lower, "invalid command") || strings.Contains(lower, "usage:") {
		return " (the `banned` command needs fail2ban 0.11 or newer)"
	}
	return ""
}

func parseBannedJails(out string) ([]JailInfo, error) {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return nil, fmt.Errorf("empty output from `fail2ban-client banned`")
	}
	payload, found := extractBannedPayload(trimmed)
	if !found {
		return nil, fmt.Errorf("unexpected output from `fail2ban-client banned`: %s%s", truncateForError(trimmed), bannedVersionHint(trimmed))
	}
	s := &reprScanner{in: payload}
	if !s.accept('[') {
		return nil, fmt.Errorf("unexpected output from `fail2ban-client banned`: %s", truncateForError(s.in))
	}

	infos := []JailInfo{}
	s.skipSpace()
	for !s.accept(']') {
		if s.done() {
			return nil, fmt.Errorf("unterminated jail list in `fail2ban-client banned` output")
		}
		if !s.accept('{') {
			return nil, fmt.Errorf("expected a jail entry at offset %d in `fail2ban-client banned` output", s.pos)
		}
		name, err := s.quotedString()
		if err != nil {
			return nil, fmt.Errorf("bad jail name in `fail2ban-client banned` output: %w", err)
		}
		if !s.accept(':') {
			return nil, fmt.Errorf("missing ':' after jail %q in `fail2ban-client banned` output", name)
		}
		ips, err := s.stringList()
		if err != nil {
			return nil, fmt.Errorf("bad banned IP list for jail %q: %w", name, err)
		}
		if !s.accept('}') {
			return nil, fmt.Errorf("unterminated entry for jail %q in `fail2ban-client banned` output", name)
		}
		infos = append(infos, JailInfo{
			JailName:    name,
			TotalBanned: len(ips),
			BannedIPs:   ips,
			Enabled:     true,
		})
		s.accept(',')
		s.skipSpace()
	}

	sort.SliceStable(infos, func(i, j int) bool { return infos[i].JailName < infos[j].JailName })
	return infos, nil
}

// Keeps parse errors readable when the remote returns something unexpected.
func truncateForError(s string) string {
	const limit = 120
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}

// Minimal scanner for the subset of Python repr that fail2ban emits
type reprScanner struct {
	in  string
	pos int
}

func (s *reprScanner) rest() string { return s.in[s.pos:] }
func (s *reprScanner) done() bool   { return s.pos >= len(s.in) }

func (s *reprScanner) skipSpace() {
	for s.pos < len(s.in) && (s.in[s.pos] == ' ' || s.in[s.pos] == '\t' || s.in[s.pos] == '\n' || s.in[s.pos] == '\r') {
		s.pos++
	}
}

func (s *reprScanner) accept(c byte) bool {
	s.skipSpace()
	if s.pos < len(s.in) && s.in[s.pos] == c {
		s.pos++
		return true
	}
	return false
}

// Reads a 'single' or "double" quoted string, honouring backslash escapes.
func (s *reprScanner) quotedString() (string, error) {
	s.skipSpace()
	if s.done() {
		return "", fmt.Errorf("unexpected end of input")
	}
	quote := s.in[s.pos]
	if quote != '\'' && quote != '"' {
		return "", fmt.Errorf("expected a quoted string at offset %d", s.pos)
	}
	s.pos++
	var b strings.Builder
	for s.pos < len(s.in) {
		c := s.in[s.pos]
		switch c {
		case '\\':
			if s.pos+1 >= len(s.in) {
				return "", fmt.Errorf("dangling escape at offset %d", s.pos)
			}
			b.WriteByte(s.in[s.pos+1])
			s.pos += 2
		case quote:
			s.pos++
			return b.String(), nil
		default:
			b.WriteByte(c)
			s.pos++
		}
	}
	return "", fmt.Errorf("unterminated string starting at offset %d", s.pos)
}

// Reads ['a', 'b'] into a slice -> an empty list yields a non-nil empty slice.
func (s *reprScanner) stringList() ([]string, error) {
	if !s.accept('[') {
		return nil, fmt.Errorf("expected a list at offset %d", s.pos)
	}
	items := []string{}
	s.skipSpace()
	for !s.accept(']') {
		if s.done() {
			return nil, fmt.Errorf("unterminated list")
		}
		item, err := s.quotedString()
		if err != nil {
			return nil, err
		}
		items = append(items, item)
		s.accept(',')
		s.skipSpace()
	}
	return items, nil
}

func fail2banArgs(socketPath string, args ...string) []string {
	if socketPath == "" {
		return args
	}
	return append([]string{"-s", socketPath}, args...)
}

func isNonConfigFile(filename string) bool {
	return strings.Contains(filename, "README") ||
		strings.HasSuffix(filename, ".bak") ||
		strings.HasSuffix(filename, "~") ||
		strings.HasSuffix(filename, ".old") ||
		strings.HasSuffix(filename, ".rpmnew") ||
		strings.HasSuffix(filename, ".rpmsave")
}

func dedupeConfigBaseNames(localFiles, confFiles []string) []string {
	seen := make(map[string]bool)
	var names []string
	add := func(paths []string, suffix string) {
		for _, p := range paths {
			filename := filepath.Base(p)
			if isNonConfigFile(filename) {
				continue
			}
			base := strings.TrimSuffix(filename, suffix)
			if base == "" || base == filename || seen[base] {
				continue
			}
			seen[base] = true
			names = append(names, base)
		}
	}
	add(localFiles, ".local")
	add(confFiles, ".conf")
	sort.Strings(names)
	return names
}

func checkPingOutput(out string, err error, label string) error {
	trimmed := strings.TrimSpace(out)
	if err != nil {
		return fmt.Errorf("%s ping error: %w (output: %s)", label, err, trimmed)
	}
	if !strings.Contains(strings.ToLower(trimmed), "pong") {
		return fmt.Errorf("unexpected %s ping output: %s", label, trimmed)
	}
	return nil
}

// =========================================================================
//  Types
// =========================================================================

// A single Fail2ban jail
type JailInfo struct {
	JailName      string   `json:"jailName"`
	TotalBanned   int      `json:"totalBanned"`
	NewInLastHour int      `json:"newInLastHour"`
	BannedIPs     []string `json:"bannedIPs"`
	Enabled       bool     `json:"enabled"`
}

// Result of one summary fetch
type JailSummary struct {
	Jails            []JailInfo
	JailLocalExists  bool
	JailLocalManaged bool
}

// =========================================================================
//  Service Control
// =========================================================================

func RestartFail2ban(serverID string) (string, error) {
	manager := GetManager()
	var (
		conn Connector
		err  error
	)
	if serverID != "" {
		conn, err = manager.Connector(serverID)
	} else {
		conn, err = manager.DefaultConnector()
	}
	if err != nil {
		return "", err
	}
	if withMode, ok := conn.(interface {
		RestartWithMode(ctx context.Context) (string, error)
	}); ok {
		return withMode.RestartWithMode(context.Background())
	}
	if err := conn.Restart(context.Background()); err != nil {
		return "", err
	}
	return "restart", nil
}
