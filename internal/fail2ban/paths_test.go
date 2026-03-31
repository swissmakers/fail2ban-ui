// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
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

package fail2ban

import (
	"path/filepath"
	"testing"
)

func TestNormalizeConfigPath(t *testing.T) {
	t.Parallel()
	if got := NormalizeConfigPath(""); got != DefaultConfigRoot {
		t.Fatalf("empty: got %q want %q", got, DefaultConfigRoot)
	}
	if got := NormalizeConfigPath("  "); got != DefaultConfigRoot {
		t.Fatalf("whitespace: got %q want %q", got, DefaultConfigRoot)
	}
	if got := NormalizeConfigPath("/opt/fail2ban"); got != "/opt/fail2ban" {
		t.Fatalf("clean path: got %q", got)
	}
	if got := NormalizeConfigPath("/etc/fail2ban/../fail2ban/"); got != "/etc/fail2ban" {
		t.Fatalf("clean: got %q", got)
	}
}

func TestPathLayout(t *testing.T) {
	t.Parallel()
	root := "/tmp/f2b-test"
	wantJail := filepath.Join(root, "jail.d")
	if got := JailDir(root); got != wantJail {
		t.Fatalf("JailDir: got %q want %q", got, wantJail)
	}
	wantFilter := filepath.Join(root, "filter.d")
	if got := FilterDir(root); got != wantFilter {
		t.Fatalf("FilterDir: got %q want %q", got, wantFilter)
	}
	wantLocal := filepath.Join(root, "jail.local")
	if got := JailLocal(root); got != wantLocal {
		t.Fatalf("JailLocal: got %q want %q", got, wantLocal)
	}
	wantAction := filepath.Join(root, "action.d", "ui-custom-action.conf")
	if got := CustomActionFile(root); got != wantAction {
		t.Fatalf("CustomActionFile: got %q want %q", got, wantAction)
	}
}
