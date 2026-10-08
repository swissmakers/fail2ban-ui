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
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// Sync phases: pending = not yet written, written = on disk but not active, applied = active.
const (
	SyncPending = "pending"
	SyncWritten = "written"
	SyncApplied = "applied"
)

// Returned when a restart is refused because the host's configuration is not in a loadable state.
var ErrConfigNotApplied = errors.New("configuration is not applied")

type ConfigSyncStatus struct {
	Pending     bool      `json:"pending"`
	Phase       string    `json:"phase"`
	Error       string    `json:"error,omitempty"`
	LastAttempt time.Time `json:"lastAttempt,omitzero"`
	LastWritten time.Time `json:"lastWritten,omitzero"`
	LastApplied time.Time `json:"lastApplied,omitzero"`
}

type configSyncState struct {
	mu               sync.Mutex
	run              chan struct{}
	generation       uint64
	writtenGen       uint64
	action, defaults bool
	failures         int
	status           ConfigSyncStatus
}

func syncPhase(pending bool, writtenGen, generation uint64) string {
	switch {
	case !pending:
		return SyncApplied
	case writtenGen == generation:
		return SyncWritten
	default:
		return SyncPending
	}
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
	return min(monitorInterval<<(failures-1), maxConfigRetryDelay)
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
		return ConfigSyncStatus{Phase: SyncApplied}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	status := state.status
	status.Phase = syncPhase(status.Pending, state.writtenGen, state.generation)
	return status
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
	if !m.ownsOperation(ctx, id) {
		m.mu.RLock()
		schedule := m.configSyncScheduler
		m.mu.RUnlock()
		if schedule != nil {
			schedule(id)
			return nil
		}
	}
	ctx, release, err := m.BeginOperation(ctx, id, "", "config_sync")
	if err != nil {
		return err
	}
	defer release()
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
	if OperationID(ctx) == "" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	if err := OperationCheckpoint(ctx, "writing"); err != nil {
		return err
	}
	if action {
		err = updateConnectorAction(ctx, conn)
	}
	if err == nil && defaults {
		err = conn.EnsureJailLocalStructure(ctx)
	}
	if err == nil {
		state.mu.Lock()
		state.status.LastWritten = time.Now().UTC()
		state.writtenGen = generation
		state.mu.Unlock()
		if err = OperationCheckpoint(ctx, "validating"); err == nil {
			err = conn.ValidateConfiguration(ctx)
		}
		if err == nil {
			if err = OperationCheckpoint(ctx, "applying"); err == nil {
				if reloadErr := conn.Reload(ctx); reloadErr != nil {
					err = fmt.Errorf("%w: %v", ErrOperationOutcomeUnknown, reloadErr)
				} else {
					err = OperationCheckpoint(ctx, "applied")
					if err != nil {
						err = fmt.Errorf("%w: %v", ErrOperationOutcomeUnknown, err)
					}
				}
			}
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
		return fmt.Errorf("config sync for %s failed: %w", conn.Server().Name, err)
	}
	state.markAppliedLocked(generation)
	state.mu.Unlock()
	log.Printf("applied Fail2Ban configuration on %s", conn.Server().Name)
	return nil
}

func (state *configSyncState) markAppliedLocked(generation uint64) {
	state.failures = 0
	state.status.LastApplied = time.Now().UTC()
	state.status.Error = ""
	if state.generation == generation {
		state.action, state.defaults = false, false
		state.status.Pending = false
	}
}

// Applies pending config, then restarts fail2ban; refuses when the files on the host would not load.
func (m *Manager) ApplyAndRestart(ctx context.Context, id string) (string, error) {
	ctx, release, err := m.BeginOperation(ctx, id, "", "restart")
	if err != nil {
		return "", err
	}
	defer release()
	conn, err := m.Connector(id)
	if err != nil {
		return "", err
	}
	if m.ConfigSyncStatus(id).Pending {
		// A failed reload is fine here as long as the files were written; the restart loads them.
		if syncErr := m.SyncServerConfig(ctx, id); syncErr != nil {
			if errors.Is(syncErr, ErrOperationOutcomeUnknown) {
				return "", syncErr
			}
			if m.ConfigSyncStatus(id).Phase == SyncPending {
				return "", fmt.Errorf("%w: %v", ErrConfigNotApplied, syncErr)
			}
		}
	}
	if err := conn.ValidateConfiguration(ctx); err != nil {
		return "", fmt.Errorf("%w: %v", ErrConfigNotApplied, err)
	}
	state := m.syncState(id)
	state.mu.Lock()
	generation, written := state.generation, state.writtenGen == state.generation
	state.mu.Unlock()
	mode, err := conn.Restart(ctx)
	if err != nil {
		return mode, err
	}
	if written {
		state.mu.Lock()
		state.markAppliedLocked(generation)
		state.mu.Unlock()
	}
	return mode, nil
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
