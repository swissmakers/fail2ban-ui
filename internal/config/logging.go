// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2025 Swissmakers GmbH (https://swissmakers.ch)
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

package config

import (
	"fmt"
	"io"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
)

// =========================================================================
//  Debug Logging
// =========================================================================

var debugEnabled atomic.Bool

type logRedactor struct {
	values   []string
	replacer *strings.Replacer
}

var logSecrets atomic.Pointer[logRedactor]
var callbackHeaderPattern = regexp.MustCompile(`(?i)(X-Callback-Secret\s*:\s*)[^\s"'\\]+`)

// Shorter values would redact common substrings (digits, header values) across every log line.
const minRedactedSecretLen = 8

// Retired values are kept on top of the full current set, never in place of it.
const maxRetiredSecrets = 256

// Called while holding settingsLock; readers must never take that lock while logging.
func refreshLogSecretsLocked() {
	s := currentSettings
	current := []string{s.CallbackSecret, s.SMTP.Password, s.ThreatIntel.AlienVaultAPIKey,
		s.ThreatIntel.AbuseIPDBAPIKey, s.Elasticsearch.APIKey, s.Elasticsearch.Password,
		s.AdvancedActions.Mikrotik.Password, s.AdvancedActions.PfSense.APIToken,
		s.AdvancedActions.OPNsense.APIKey,
		s.AdvancedActions.OPNsense.APISecret, s.AdvancedActions.UniFi.APIKey,
		s.Webhook.URL}
	if u, err := url.Parse(s.Elasticsearch.URL); err == nil && u.User != nil {
		current = append(current, s.Elasticsearch.URL)
	}
	for _, server := range s.Servers {
		current = append(current, server.AgentSecret)
	}
	for _, value := range s.Webhook.Headers {
		current = append(current, value)
	}
	seen := make(map[string]bool)
	var values []string
	add := func(value string) {
		if len(value) >= minRedactedSecretLen && !seen[value] {
			seen[value] = true
			values = append(values, value)
		}
	}
	for _, value := range current {
		add(value)
	}
	limit := len(values) + maxRetiredSecrets
	if old := logSecrets.Load(); old != nil {
		for _, value := range old.values {
			if len(values) >= limit {
				break
			}
			add(value)
		}
	}
	// Match longer secrets first so a shared prefix cannot leave a suffix exposed.
	ordered := append([]string(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	var pairs []string
	for _, value := range ordered {
		pairs = append(pairs, value, "[REDACTED]")
	}
	logSecrets.Store(&logRedactor{values: values, replacer: strings.NewReplacer(pairs...)})
}

func RedactLog(message string) string {
	message = callbackHeaderPattern.ReplaceAllString(message, "${1}[REDACTED]")
	if redactor := logSecrets.Load(); redactor != nil {
		return redactor.replacer.Replace(message)
	}
	return message
}

type redactingLogWriter struct{ io.Writer }

func (w redactingLogWriter) Write(p []byte) (int, error) {
	_, err := io.WriteString(w.Writer, RedactLog(string(p)))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func setDebugFlag(enabled bool) {
	debugEnabled.Store(enabled)
}

// Prints debug messages if debug mode is enabled.
func DebugLog(format string, v ...interface{}) {
	if !debugEnabled.Load() {
		return
	}
	if len(v) > 0 {
		log.Print(RedactLog(fmt.Sprintf(format, v...)))
	} else {
		log.Println(RedactLog(format))
	}
}
