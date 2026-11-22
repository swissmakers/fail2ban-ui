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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const (
	stockNftables110 = `_nft_get_handle_id = grep -oP '@<addr_set>\s+.*\s+\Khandle\s+(\d+)$'
_nft_shutdown_table = { <nftables> list table <table_family> <table> | grep -qP '^\s+set\s+'; } || {
`
	stockNftables111 = `_nft_get_handle_id = sed -nE 's/.*@<addr_set>\s+.*\s+\#\s*(handle\s+[0-9]+)$/\1/p'
_nft_shutdown_table = { <nftables> list table <table_family> <table> | grep -qE '^\s+set\s+'; } || {
`
	adminNftablesLocal = "[Init]\ntable = f2b-admin\n"
)

func TestNftablesNeedsGrepFix(t *testing.T) {
	cases := []struct {
		name  string
		stock string
		want  bool
	}{
		{"fail2ban 1.1.0", stockNftables110, true},
		{"fail2ban 1.1.1", stockNftables111, false},
		{"no nftables.conf", "", false},
		{"other layout with grep -P", "actionstop = nft list table | grep -qP x\n", false},
	}
	for _, c := range cases {
		if got := nftablesNeedsGrepFix(c.stock); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// Runs every case through the local writer and through the remote script, which must agree.
func TestNftablesFix(t *testing.T) {
	cases := []struct {
		name     string
		stock    string
		existing string
		want     string
		foreign  bool
	}{
		{"writes the fix for 1.1.0", stockNftables110, "", nftablesFixContent, false},
		{"keeps a current fix", stockNftables110, nftablesFixContent, nftablesFixContent, false},
		{"replaces an outdated fix", stockNftables110, nftablesFixMarker + "\nold\n", nftablesFixContent, false},
		{"leaves an admin file alone", stockNftables110, adminNftablesLocal, adminNftablesLocal, true},
		{"removes the fix once fail2ban is fixed", stockNftables111, nftablesFixContent, "", false},
		{"leaves an admin file alone on a fixed fail2ban", stockNftables111, adminNftablesLocal, adminNftablesLocal, false},
		{"does nothing without nftables.conf", "", "", "", false},
	}
	appliers := map[string]func(t *testing.T, root string) (foreign bool){
		"local": func(t *testing.T, root string) bool {
			return ensureLocalNftablesFix(root) != nil
		},
		"remote script": func(t *testing.T, root string) bool {
			script, err := buildNftablesFixScript(ActionDir(root))
			if err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("sh", "-c", script).CombinedOutput()
			if err != nil {
				t.Fatalf("script failed: %v %s", err, out)
			}
			return extractMarkerValue(string(out), nftablesFixForeignMarker) != ""
		},
	}
	for mode, apply := range appliers {
		for _, c := range cases {
			t.Run(mode+"/"+c.name, func(t *testing.T) {
				root := t.TempDir()
				dir := ActionDir(root)
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				fixPath := filepath.Join(dir, nftablesFixFile)
				if c.stock != "" {
					if err := os.WriteFile(filepath.Join(dir, "nftables.conf"), []byte(c.stock), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				if c.existing != "" {
					if err := os.WriteFile(fixPath, []byte(c.existing), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				if foreign := apply(t, root); foreign != c.foreign {
					t.Errorf("foreign = %v, want %v", foreign, c.foreign)
				}
				got, err := os.ReadFile(fixPath)
				if c.want == "" {
					if !os.IsNotExist(err) {
						t.Errorf("nftables.local must not exist, got %q (err %v)", got, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != c.want {
					t.Errorf("nftables.local = %q, want %q", got, c.want)
				}
			})
		}
	}
}
