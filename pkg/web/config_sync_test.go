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

package web

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
)

func TestAdvancedBanSettingsArePushed(t *testing.T) {
	original := config.GetSettings()
	t.Cleanup(func() { fail2ban.GetManager().Close(); _, _ = config.UpdateSettings(original) })
	dir := t.TempDir()
	record := filepath.Join(dir, "commands")
	t.Setenv("REVIEW_COMMANDS", record)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	fake := `#!/bin/sh
printf '%s\n' "$*" >> "$REVIEW_COMMANDS"
case "$*" in
 *"-O check"*) exit 0 ;;
 *"test -d"*) echo "/config/fail2ban"; exit 0 ;;
 *"cat "*) echo "[DEFAULT]"; echo "action = ui-custom-action"; exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(fake), 0700); err != nil {
		t.Fatal(err)
	}
	settings := config.GetSettings()
	settings.Debug = false
	settings.Servers = []config.Fail2banServer{{ID: "review", Name: "review", Type: "ssh", Host: "127.0.0.1", Port: 22, SSHUser: "review", SSHKeyPath: filepath.Join(dir, "key"), Enabled: true, IsDefault: true}}
	_, err := config.UpdateSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.ReloadFail2banManager(); err != nil {
		t.Fatal(err)
	}
	if err := fail2ban.GetManager().SyncServerConfig(context.Background(), "review"); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name   string
		change func(*config.AppSettings)
	}{
		{"factor", func(s *config.AppSettings) { s.BantimeFactor = "17" }},
		{"maxtime", func(s *config.AppSettings) { s.BantimeMaxtime = "137d" }},
		{"overalljails", func(s *config.AppSettings) { s.BantimeOveralljails = !s.BantimeOveralljails }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(record, nil, 0600); err != nil {
				t.Fatal(err)
			}
			settings := config.GetSettings()
			tc.change(&settings)
			rr := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rr)
			c.Request = httptest.NewRequest("POST", "/api/settings", nil)
			applySettingsUpdate(c, settings)
			if rr.Code != 200 {
				t.Fatalf("settings save failed: %d %s", rr.Code, rr.Body.String())
			}
			commands, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			// fail2ban-client words are shell-quoted individually on the wire.
			words := strings.ReplaceAll(string(commands), "'", "")
			// The reload must load the probed tree; the client, not the daemon, parses the config.
			if !strings.Contains(words, "jail.local") || !strings.Contains(words, "-c /config/fail2ban reload") {
				t.Fatalf("bantime.%s saved but no DEFAULT file push or Fail2Ban reload was attempted", tc.name)
			}
		})
	}
}

func TestCallbackStorageFailureReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := HandleUnbanNotification(ctx, config.Fail2banServer{ID: "test"}, "192.0.2.1", "sshd", "host", "test whois", "CH"); err == nil {
		t.Fatal("failed storage insert was acknowledged")
	}
}
