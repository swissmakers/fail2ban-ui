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

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseJailDefaults(t *testing.T) {
	content := `# written by Fail2ban-UI
[INCLUDES]
before = paths-debian.conf

[DEFAULT]
bantime = 48h
bantime.rndtime = 30m
ignoreip =
  maxretry=3

[sshd]
enabled = true
bantime = 10m
maxretry = 5

[ default ]
findtime = 30m
`
	got, err := parseJailDefaults(strings.NewReader(content))
	if err != nil {
		t.Fatalf("parseJailDefaults: %v", err)
	}
	want := map[string]string{"bantime": "48h", "bantime.rndtime": "30m", "ignoreip": "", "maxretry": "3", "findtime": "30m"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseJailDefaults = %v, want %v", got, want)
	}
}

func TestBuildJailLocalContentIgnoreIPExtraHook(t *testing.T) {
	content := buildJailLocalContent(AppSettings{IgnoreIPs: []string{"127.0.0.1/8", "10.0.0.0/8"}})
	want := "ignoreip_extra =\nignoreip = 127.0.0.1/8 10.0.0.0/8 %(ignoreip_extra)s\n"
	if !strings.Contains(content, want) {
		t.Fatalf("managed [DEFAULT] must define the empty hook before ignoreip, got:\n%s", content)
	}
}

func TestInitializeFromJailFileDropsIgnoreIPExtraRef(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jail.local")
	content := buildJailLocalContent(AppSettings{IgnoreIPs: []string{"127.0.0.1/8", "203.0.113.10"}})
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	settingsLock.Lock()
	old, oldFile := currentSettings, jailFile
	jailFile = path
	settingsLock.Unlock()
	t.Cleanup(func() {
		settingsLock.Lock()
		currentSettings, jailFile = old, oldFile
		settingsLock.Unlock()
	})

	if err := initializeFromJailFile(); err != nil {
		t.Fatalf("initializeFromJailFile: %v", err)
	}
	settingsLock.RLock()
	got := currentSettings.IgnoreIPs
	settingsLock.RUnlock()
	if want := []string{"127.0.0.1/8", "203.0.113.10"}; !reflect.DeepEqual(got, want) {
		t.Errorf("IgnoreIPs = %v, want %v", got, want)
	}
}
