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

package fail2ban

import "sync"

// Supplies application settings needed by connectors without importing config.
type Provider interface {
	DebugLog(format string, v ...interface{})
	CallbackURL() string
	CallbackSecret() string
	BuildFail2banActionConfig(callbackURL, serverID, secret string) string
	BuildJailLocalContent() string
}

var (
	providerMu sync.RWMutex
	provider   Provider
)

// Registers the application bridge (typically from internal/config at init).
func SetProvider(p Provider) {
	providerMu.Lock()
	provider = p
	providerMu.Unlock()
}

func mustProvider() Provider {
	providerMu.RLock()
	p := provider
	providerMu.RUnlock()
	if p == nil {
		return noopProvider{}
	}
	return p
}

func debugf(format string, v ...interface{}) {
	mustProvider().DebugLog(format, v...)
}

type noopProvider struct{}

func (noopProvider) DebugLog(format string, v ...interface{}) {}

func (noopProvider) CallbackURL() string { return "" }

func (noopProvider) CallbackSecret() string { return "" }

func (noopProvider) BuildFail2banActionConfig(callbackURL, serverID, secret string) string {
	return ""
}

func (noopProvider) BuildJailLocalContent() string { return "" }
