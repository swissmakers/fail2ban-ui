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

// LEGACY, WILL BE REMOVED IN FUTURE VERSIONS.
package fail2ban

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"time"
)

// =========================================================================
//  Types
// =========================================================================

var logRegex = regexp.MustCompile(`^(\S+\s+\S+) fail2ban\.actions.*?\[\d+\]: NOTICE\s+\[(\S+)\]\s+Ban\s+(\S+)`)

// This is a single ban event from the fail2ban log. REMOVE THIS TYPE.
type BanEvent struct {
	Time    time.Time
	Jail    string
	IP      string
	LogLine string
}

// =========================================================================
//  Log Parsing
// =========================================================================

// ParseBanLog reads the fail2ban log and returns events grouped by jail.
func ParseBanLog(logPath string) (map[string][]BanEvent, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open fail2ban log: %v", err)
	}
	defer file.Close()

	eventsByJail := make(map[string][]BanEvent)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		matches := logRegex.FindStringSubmatch(line)
		if len(matches) == 4 {
			timestampStr := matches[1]
			jail := matches[2]
			ip := matches[3]

			parsedTime, err := time.Parse("2006-01-02 15:04:05,000", timestampStr)
			if err != nil {
				continue
			}

			ev := BanEvent{
				Time:    parsedTime,
				Jail:    jail,
				IP:      ip,
				LogLine: line,
			}

			eventsByJail[jail] = append(eventsByJail[jail], ev)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return eventsByJail, nil
}
