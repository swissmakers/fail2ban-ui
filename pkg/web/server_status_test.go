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
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
)

func TestSettingsSyncFlags(t *testing.T) {
	st := func(phase string) fail2ban.ConfigSyncStatus { return fail2ban.ConfigSyncStatus{Phase: phase} }
	tests := []struct {
		name                     string
		statuses                 []fail2ban.ConfigSyncStatus
		wantPending, wantRestart bool
	}{
		{name: "none", statuses: nil},
		{name: "all applied", statuses: []fail2ban.ConfigSyncStatus{st(fail2ban.SyncApplied), st(fail2ban.SyncApplied)}},
		{name: "one unreachable", statuses: []fail2ban.ConfigSyncStatus{st(fail2ban.SyncApplied), st(fail2ban.SyncPending)}, wantPending: true},
		{name: "one written", statuses: []fail2ban.ConfigSyncStatus{st(fail2ban.SyncWritten)}, wantRestart: true},
		{name: "both", statuses: []fail2ban.ConfigSyncStatus{st(fail2ban.SyncWritten), st(fail2ban.SyncPending)}, wantPending: true, wantRestart: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pending, restart := settingsSyncFlags(tt.statuses)
			if pending != tt.wantPending || restart != tt.wantRestart {
				t.Fatalf("got pending=%v restart=%v, want %v %v", pending, restart, tt.wantPending, tt.wantRestart)
			}
		})
	}
}

func TestHealthForRole(t *testing.T) {
	no := false
	h := fail2ban.ServerHealth{State: fail2ban.HealthDegraded, CheckedAt: time.Unix(1700000000, 0), Fail2banOK: true, CallbackOK: &no, Error: "curl to http://10.0.0.5:8080 failed"}
	raw, err := json.Marshal(healthForRole(h, false))
	if err != nil {
		t.Fatal(err)
	}
	var viewer map[string]any
	_ = json.Unmarshal(raw, &viewer)
	if len(viewer) != 2 || viewer["state"] != "degraded" || viewer["checkedAt"] == nil {
		t.Fatalf("read-only view must carry only state and checkedAt: %s", raw)
	}
	admin, _ := json.Marshal(healthForRole(h, true))
	if !strings.Contains(string(admin), "callbackOk") || !strings.Contains(string(admin), `"error"`) {
		t.Fatalf("admin view lost details: %s", admin)
	}
}

func TestJailNameTaken(t *testing.T) {
	defined := []fail2ban.JailInfo{{JailName: "nginx"}}
	active := []fail2ban.JailInfo{{JailName: "sshd"}}
	for name, want := range map[string]bool{"nginx": true, "sshd": true, "postfix": false, "SSHD": false} {
		if got := jailNameTaken(name, defined, active); got != want {
			t.Errorf("jailNameTaken(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestClampInt(t *testing.T) {
	tests := []struct {
		raw         string
		def, lo, hi int
		want        int
	}{
		{"", 5, 1, 100, 5},
		{"abc", 5, 1, 100, 5},
		{"0", 5, 1, 100, 5},
		{"-3", 0, 0, 10, 0},
		{"7", 5, 1, 100, 7},
		{" 42 ", 5, 1, 100, 42},
		{"1000", 5, 1, 100, 100},
		{"0", 9, 0, 10, 0},
	}
	for _, tt := range tests {
		if got := clampInt(tt.raw, tt.def, tt.lo, tt.hi); got != tt.want {
			t.Errorf("clampInt(%q, %d, %d, %d) = %d, want %d", tt.raw, tt.def, tt.lo, tt.hi, got, tt.want)
		}
	}
}

func TestSessionFromContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if sessionFromContext(c) != nil {
		t.Fatal("no session stored must give nil")
	}
	c.Set("session", "not a session")
	if sessionFromContext(c) != nil {
		t.Fatal("a foreign value must give nil")
	}
	want := &auth.Session{Username: "alice"}
	c.Set("session", want)
	if sessionFromContext(c) != want {
		t.Fatal("stored session not returned")
	}
}
