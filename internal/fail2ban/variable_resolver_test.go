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
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLogpathVariablesAtPath_customRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	localPath := filepath.Join(root, "vars.local")
	content := "my_custom_log = /tmp/from-custom-root.log\n"
	if err := os.WriteFile(localPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveLogpathVariables("%(my_custom_log)s", root)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/from-custom-root.log" {
		t.Fatalf("resolved logpath: got %q", got)
	}
}
