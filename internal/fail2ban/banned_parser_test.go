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

package fail2ban

import (
	"strings"
	"testing"
)

const realBannedOutput = `[{'apache-auth': ['102.220.160.200', '185.93.89.147']}, {'apache-overflows': []}, {'apache-nohome': []}, {'apache-fakegooglebot': ['11.10.99.99', '11.22.33.44']}, {'apache-shellshock': []}, {'swissmakers-apache-auth': []}, {'swissmakers-apache-badbots': ['135.237.127.94', '139.162.110.42', '172.105.196.91']}, {'swissmakers-apache-dos': []}, {'swissmakers-apache-exploit-attempts': ['104.208.94.19', '110.35.80.116']}, {'swissmakers-apache-scanner': ['110.35.80.116', '118.194.251.37', '119.179.253.111']}]`

func TestParseBannedJails(t *testing.T) {
	t.Run("real production output", func(t *testing.T) {
		infos, err := parseBannedJails(realBannedOutput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(infos) != 10 {
			t.Fatalf("expected 10 jails, got %d: %+v", len(infos), infos)
		}
		// Results must be sorted by jail name
		for i := 1; i < len(infos); i++ {
			if infos[i-1].JailName > infos[i].JailName {
				t.Fatalf("jails must be sorted, got %s before %s", infos[i-1].JailName, infos[i].JailName)
			}
		}
		byName := map[string]JailInfo{}
		for _, j := range infos {
			byName[j.JailName] = j
		}
		if got := byName["apache-auth"]; got.TotalBanned != 2 || got.BannedIPs[0] != "102.220.160.200" {
			t.Fatalf("apache-auth wrong: %+v", got)
		}
		if got := byName["apache-overflows"]; got.TotalBanned != 0 || got.BannedIPs == nil {
			t.Fatalf("empty jail must have a non-nil empty list, got %+v", got)
		}
		if got := byName["swissmakers-apache-scanner"]; got.TotalBanned != 3 {
			t.Fatalf("scanner count wrong: %+v", got)
		}
		// Every jail reported by banned is running
		for _, j := range infos {
			if !j.Enabled {
				t.Fatalf("jail %s should be marked enabled: %+v", j.JailName, j)
			}
			if j.TotalBanned != len(j.BannedIPs) {
				t.Fatalf("TotalBanned must match the IP list length for %s: %+v", j.JailName, j)
			}
		}
	})

	t.Run("no jails", func(t *testing.T) {
		infos, err := parseBannedJails("[]")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(infos) != 0 {
			t.Fatalf("expected no jails, got %+v", infos)
		}
	})

	t.Run("single jail with no bans", func(t *testing.T) {
		infos, err := parseBannedJails("[{'apache-auth': []}]")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(infos) != 1 || infos[0].JailName != "apache-auth" || infos[0].TotalBanned != 0 {
			t.Fatalf("unexpected result: %+v", infos)
		}
		if infos[0].BannedIPs == nil {
			t.Fatal("BannedIPs must be an empty slice, not nil (it is serialized to JSON)")
		}
	})

	t.Run("IPv6 and CIDR entries", func(t *testing.T) {
		infos, err := parseBannedJails("[{'sshd': ['2001:db8::1', '::1', '10.0.0.0/8']}]")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"2001:db8::1", "::1", "10.0.0.0/8"}
		if len(infos[0].BannedIPs) != len(want) {
			t.Fatalf("got %+v", infos[0].BannedIPs)
		}
		for i := range want {
			if infos[0].BannedIPs[i] != want[i] {
				t.Fatalf("got %+v, want %+v", infos[0].BannedIPs, want)
			}
		}
	})

	t.Run("trailing newline and surrounding whitespace", func(t *testing.T) {
		if _, err := parseBannedJails("\n  [{'sshd': ['1.2.3.4']}]  \n"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("double-quoted strings are accepted", func(t *testing.T) {
		infos, err := parseBannedJails(`[{"sshd": ["1.2.3.4"]}]`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if infos[0].JailName != "sshd" || infos[0].BannedIPs[0] != "1.2.3.4" {
			t.Fatalf("unexpected result: %+v", infos)
		}
	})

	t.Run("escaped quote inside a name", func(t *testing.T) {
		infos, err := parseBannedJails(`[{'we\'ird': []}]`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if infos[0].JailName != "we'ird" {
			t.Fatalf("escape not handled: %q", infos[0].JailName)
		}
	})

	// Malformed input must fail visible -> silently returning zero jails would
	// render a dashboard claiming nothing is banned
	t.Run("malformed input is an error, never an empty result", func(t *testing.T) {
		cases := map[string]string{
			"empty":                   "",
			"whitespace only":         "   \n ",
			"fail2ban error text":     "Sorry but the command 'xdspfkpw' is not supported",
			"missing outer bracket":   "{'sshd': []}",
			"unterminated list":       "[{'sshd': ['1.2.3.4']}",
			"unterminated string":     "[{'sshd: []}]",
			"missing colon":           "[{'sshd' []}]",
			"unterminated inner list": "[{'sshd': ['1.2.3.4'}]",
			"not a list of dicts":     "['sshd']",
		}
		for name, in := range cases {
			t.Run(name, func(t *testing.T) {
				infos, err := parseBannedJails(in)
				if err == nil {
					t.Fatalf("expected an error, got %+v", infos)
				}
			})
		}
	})

	t.Run("parse errors stay readable for huge payloads", func(t *testing.T) {
		_, err := parseBannedJails(strings.Repeat("x", 5000))
		if err == nil {
			t.Fatal("expected an error")
		}
		if len(err.Error()) > 400 {
			t.Fatalf("error message should be truncated, got %d bytes", len(err.Error()))
		}
	})
}
