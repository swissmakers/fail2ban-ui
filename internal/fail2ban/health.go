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
	"log"
	"sync"
	"time"
)

type HealthState string

const (
	HealthOK       HealthState = "ok"
	HealthDegraded HealthState = "degraded"
	HealthDown     HealthState = "down"
	HealthUnknown  HealthState = "unknown"
)

// Result of the last monitor probe of one server.
type ServerHealth struct {
	State      HealthState `json:"state"`
	CheckedAt  time.Time   `json:"checkedAt,omitzero"`
	Fail2banOK bool        `json:"fail2banOk"`
	CallbackOK *bool       `json:"callbackOk,omitempty"`
	Error      string      `json:"error,omitempty"`
}

const (
	healthProbeTimeout  = 20 * time.Second
	healthProbeParallel = 16
	repairDebounce      = 5 * time.Minute
)

func deriveHealthState(h ServerHealth) HealthState {
	switch {
	case !h.Fail2banOK:
		return HealthDown
	case h.CallbackOK != nil && !*h.CallbackOK:
		return HealthDegraded
	default:
		return HealthOK
	}
}

// Returns the last probe result; unknown until the monitor probed the server.
func (m *Manager) Health(id string) ServerHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if h, ok := m.health[id]; ok {
		return h
	}
	return ServerHealth{State: HealthUnknown}
}

// Registers a callback for health state transitions.
func (m *Manager) SetHealthListener(fn func(serverID string, h ServerHealth)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthListener = fn
}

// Drops the result when conn was replaced or removed while it was being probed.
func (m *Manager) recordHealth(conn Connector, h ServerHealth, now time.Time) {
	srv := conn.Server()
	id, name := srv.ID, srv.Name
	h.State = deriveHealthState(h)
	h.CheckedAt = now.UTC()
	m.mu.Lock()
	if m.connectors[id] != conn {
		m.mu.Unlock()
		return
	}
	if m.health == nil {
		m.health = make(map[string]ServerHealth)
	}
	prev, had := m.health[id]
	m.health[id] = h
	listener := m.healthListener
	m.mu.Unlock()

	if had && prev.State == h.State && prev.Error == h.Error {
		return
	}
	if h.State == HealthOK {
		log.Printf("server %s is healthy", name)
	} else {
		log.Printf("warning: server %s is %s: %s", name, h.State, h.Error)
	}
	if listener != nil && (!had || prev.State != h.State) {
		listener(id, h)
	}
}

// Probes every enabled server concurrently and records the results.
func (m *Manager) ProbeAll(ctx context.Context) {
	sem := make(chan struct{}, healthProbeParallel)
	var wg sync.WaitGroup
	for _, conn := range m.Connectors() {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			probeCtx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
			defer cancel()
			h := conn.ProbeHealth(probeCtx)
			if ctx.Err() != nil {
				return
			}
			m.recordHealth(conn, h, time.Now())
			if d, ok := conn.(interface{ actionDrifted() bool }); ok && d.actionDrifted() {
				m.Repair(ctx, conn.Server().ID, true, false)
			}
		})
	}
	wg.Wait()
}

// Re-pushes drifted config at most once per debounce window per server.
func (m *Manager) Repair(ctx context.Context, id string, action, defaults bool) bool {
	if !action && !defaults {
		return false
	}
	m.mu.Lock()
	if last, ok := m.repairAt[id]; ok && time.Since(last) < repairDebounce {
		m.mu.Unlock()
		return false
	}
	if m.repairAt == nil {
		m.repairAt = make(map[string]time.Time)
	}
	m.repairAt[id] = time.Now()
	m.mu.Unlock()
	m.RequestConfigSync(id, action, defaults)
	_ = m.SyncServerConfig(ctx, id)
	return true
}
