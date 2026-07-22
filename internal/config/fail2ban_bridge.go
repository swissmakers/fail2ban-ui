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

package config

import "github.com/swissmakers/fail2ban-ui/internal/fail2ban"

// =========================================================================
//  Bridge between config and fail2ban --> used for both dependency injection and manager reload orchestration.
// =========================================================================

type fail2banRuntime struct{}

func (fail2banRuntime) DebugLog(format string, v ...interface{}) {
	DebugLog(format, v...)
}

func (fail2banRuntime) CallbackURL() string {
	return GetCallbackURL()
}

func (fail2banRuntime) CallbackSecret() string {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	return currentSettings.CallbackSecret
}

func (fail2banRuntime) BuildFail2banActionConfig(callbackURL, serverID, secret string) string {
	return BuildFail2banActionConfig(callbackURL, serverID, secret)
}

func (fail2banRuntime) BuildJailLocalContent() string {
	return BuildJailLocalContent()
}

func registerFail2banProvider() {
	fail2ban.SetProvider(fail2banRuntime{})
}

func ReloadFail2banManager() error {
	s := GetSettings()
	for _, srv := range s.Servers {
		if srv.Enabled && srv.Type == "local" {
			if err := EnsureLocalFail2banAction(srv); err != nil {
				DebugLog("Warning: failed to ensure local fail2ban action for server %s: %v", srv.Name, err)
			}
		}
	}
	return fail2ban.GetManager().ReloadFromServers(s.Servers)
}
