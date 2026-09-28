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

package fail2ban

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

type ConfigSyncStatus struct {
	Pending     bool      `json:"pending"`
	Error       string    `json:"error,omitempty"`
	LastAttempt time.Time `json:"lastAttempt,omitempty"`
	LastWritten time.Time `json:"lastWritten,omitempty"`
	LastApplied time.Time `json:"lastApplied,omitempty"`
}

type configSyncState struct {
	mu               sync.Mutex
	run              chan struct{}
	generation       uint64
	action, defaults bool
	failures         int
	status           ConfigSyncStatus
}

const maxConfigRetryDelay = 15 * time.Minute

// Monitor retries back off per host; explicit sync requests are never delayed.
func configRetryDelay(failures int) time.Duration {
	if failures <= 1 {
		return 0
	}
	if failures > 6 {
		return maxConfigRetryDelay
	}
	return min(tunnelCheckInterval<<(failures-1), maxConfigRetryDelay)
}

func (m *Manager) syncState(id string) *configSyncState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.configSync == nil {
		m.configSync = make(map[string]*configSyncState)
	}
	state := m.configSync[id]
	if state == nil {
		state = &configSyncState{run: make(chan struct{}, 1)}
		m.configSync[id] = state
	}
	return state
}

func (m *Manager) RequestConfigSync(id string, action, defaults bool) {
	state := m.syncState(id)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.generation++
	state.action = state.action || action
	state.defaults = state.defaults || defaults
	state.failures = 0
	state.status.Pending = true
}

func (m *Manager) ConfigSyncStatus(id string) ConfigSyncStatus {
	m.mu.RLock()
	state := m.configSync[id]
	m.mu.RUnlock()
	if state == nil {
		return ConfigSyncStatus{}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.status
}

func (m *Manager) configRetryDue(id string) bool {
	m.mu.RLock()
	state := m.configSync[id]
	m.mu.RUnlock()
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.status.Pending && time.Since(state.status.LastAttempt) >= configRetryDelay(state.failures)
}

func (m *Manager) SyncServerConfig(ctx context.Context, id string) error {
	state := m.syncState(id)
	select {
	case state.run <- struct{}{}:
		defer func() { <-state.run }()
	case <-ctx.Done():
		return ctx.Err()
	}
	state.mu.Lock()
	if !state.status.Pending {
		state.mu.Unlock()
		return nil
	}
	generation, action, defaults := state.generation, state.action, state.defaults
	state.status.LastAttempt = time.Now().UTC()
	state.mu.Unlock()

	conn, err := m.Connector(id)
	if err != nil {
		state.mu.Lock()
		state.failures++
		state.status.Error = err.Error()
		state.mu.Unlock()
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if action {
		err = updateConnectorAction(ctx, conn)
	}
	if err == nil && defaults {
		err = conn.EnsureJailLocalStructure(ctx)
	}
	if err == nil {
		state.mu.Lock()
		state.status.LastWritten = time.Now().UTC()
		state.mu.Unlock()
		if validator, ok := conn.(interface{ ValidateConfiguration(context.Context) error }); ok {
			err = validator.ValidateConfiguration(ctx)
		}
		if err == nil {
			err = conn.Reload(ctx)
		}
	}
	state.mu.Lock()
	if err != nil {
		state.failures++
		message := fmt.Sprintf("config sync for %s failed: %v", conn.Server().Name, err)
		if state.status.Error != message {
			log.Printf("warning: %s (will retry)", message)
		}
		state.status.Error = message
		state.mu.Unlock()
		return fmt.Errorf("%s", message)
	}
	state.failures = 0
	state.status.LastApplied = time.Now().UTC()
	state.status.Error = ""
	applied := state.generation == generation
	if applied {
		state.action, state.defaults = false, false
		state.status.Pending = false
	}
	state.mu.Unlock()
	if applied {
		if p, ok := mustProvider().(interface{ ConfigApplied(string) }); ok {
			p.ConfigApplied(id)
		}
	}
	log.Printf("applied Fail2Ban configuration on %s", conn.Server().Name)
	return nil
}

// Retry without requiring an open dashboard or another settings change.
func (m *Manager) RetryPendingConfig(ctx context.Context) {
	var wg sync.WaitGroup
	for _, conn := range m.Connectors() {
		id := conn.Server().ID
		if !m.configRetryDue(id) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.SyncServerConfig(ctx, id)
		}()
	}
	wg.Wait()
}
