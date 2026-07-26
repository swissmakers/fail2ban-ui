// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"reflect"
	"testing"
)

func TestParseJailErrorsFromReloadOutput(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   []string
	}{
		{
			"missing log file (production case)",
			"2026-07-25 10:59:46,905 fail2ban                [399]: ERROR   Failed during configuration: Have not found any log file for recidive jail",
			[]string{"recidive"},
		},
		{
			"errors in jail with skipping (legacy format)",
			"ERROR  Errors in jail 'apache-badbots'. Skipping...",
			[]string{"apache-badbots"},
		},
		{
			"errors in jail without skipping",
			"ERROR  Errors in jail 'sshd'.",
			[]string{"sshd"},
		},
		{
			"multiple jails deduplicated",
			"Have not found any log file for recidive jail\nErrors in jail 'recidive'. Skipping\nHave not found any log file for sshd jail",
			[]string{"recidive", "sshd"},
		},
		{
			"no jail-specific errors",
			"ERROR  Unable to read the filter 'broken'",
			[]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseJailErrorsFromReloadOutput(tc.output)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseJailErrorsFromReloadOutput = %v, want %v", got, tc.want)
			}
		})
	}
}
