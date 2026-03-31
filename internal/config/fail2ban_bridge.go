// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the PolyForm Shield License 1.0.0.
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://polyformproject.org/licenses/shield/1.0.0/
//
//     or in the LICENSE file in this repository.
//
// Required Notice: Copyright Swissmakers GmbH (https://swissmakers.ch)

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
				return err
			}
		}
	}
	return fail2ban.GetManager().ReloadFromServers(s.Servers)
}
