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
	"strings"
	"sync"
	"time"
)

type HealthState string

const (
	HealthOK       HealthState = "ok"
	HealthDegraded HealthState = "degraded"
	HealthDown     HealthState = "down"
	HealthUnknown  HealthState = "unknown"
	HealthBusy     HealthState = "busy"
)

// Result of the last monitor probe of one server.
type ServerHealth struct {
	State         HealthState `json:"state"`
	CheckedAt     time.Time   `json:"checkedAt,omitzero"`
	Fail2banOK    bool        `json:"fail2banOk"`
	CallbackOK    *bool       `json:"callbackOk,omitempty"`
	Error         string      `json:"error,omitempty"`
	TransportOK   *bool       `json:"transportOk,omitempty"`
	OperationID   string      `json:"operationId,omitempty"`
	Busy          bool        `json:"busy,omitempty"`
	operationBusy bool
}

const (
	healthProbeTimeout  = 20 * time.Second
	healthProbeParallel = 16
	repairDebounce      = 5 * time.Minute
)

func deriveHealthState(h ServerHealth) HealthState {
	switch {
	case h.TransportOK != nil && !*h.TransportOK:
		return HealthDown
	case h.Busy:
		return HealthBusy
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
	h, ok := m.health[id]
	m.mu.RUnlock()
	if !ok {
		h = ServerHealth{State: HealthUnknown}
	}
	return m.operationHealth(id, h)
}

// Daemon deadlines during a known mutation are expected contention, not proof
// that the server disconnected. Keep concrete connection failures visible.
func (m *Manager) operationHealth(id string, h ServerHealth) ServerHealth {
	activity, active := m.OperationStatus(id)
	if !active {
		if h.operationBusy || h.OperationID != "" {
			h.Busy = false
			h.OperationID = ""
			h.operationBusy = false
		}
		if h.State == HealthBusy {
			h.State = deriveHealthState(h)
		}
		return h
	}
	h.OperationID = activity.ID
	message := strings.ToLower(h.Error)
	if !h.Fail2banOK {
		for _, failure := range []string{"connection refused", "connection reset", "connection timed out", "no route to host", "host key", "permission denied", "could not resolve", "no such file or directory"} {
			if strings.Contains(message, failure) {
				h.Busy = false
				h.State = HealthDown
				return h
			}
		}
	}
	if h.TransportOK != nil && !*h.TransportOK {
		h.Busy = false
		h.State = HealthDown
		return h
	}
	if h.Fail2banOK || h.State == HealthUnknown || h.Error == "" ||
		(h.TransportOK != nil && *h.TransportOK) || strings.Contains(message, "deadline") || strings.Contains(message, "timed out") ||
		strings.Contains(message, "timeout") || strings.Contains(message, "signal: killed") || strings.Contains(message, "context canceled") {
		h.Busy = true
		h.operationBusy = true
		h.State = HealthBusy
	}
	return h
}

// Registers a callback for health state transitions.
func (m *Manager) SetHealthListener(fn func(serverID string, h ServerHealth)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthListener = fn
}

// ObserveDaemonResponse records a successful authoritative runtime read. A
// timeout from a previous busy period must not survive verified completion until
// the next periodic ping. This says nothing new about callback delivery.
func (m *Manager) ObserveDaemonResponse(conn Connector) {
	id := conn.Server().ID
	m.mu.RLock()
	h := m.health[id]
	m.mu.RUnlock()
	previouslyResponsive := h.Fail2banOK
	h.Fail2banOK = true
	transportOK := true
	h.TransportOK = &transportOK
	if h.operationBusy {
		h.Busy = false
		h.operationBusy = false
	}
	h.OperationID = ""
	if h.CallbackOK != nil && !*h.CallbackOK {
		if !previouslyResponsive || h.Error == "" {
			h.Error = "Fail2ban responded, but callback health still requires verification"
		}
	} else {
		h.Error = ""
	}
	m.recordHealth(conn, h, time.Now())
}

func (m *Manager) recordProbeHealth(conn Connector, h ServerHealth, started, finished time.Time) {
	m.recordHealthResult(conn, h, finished, started)
}

// Drops the result when conn was replaced or removed while it was being probed.
func (m *Manager) recordHealth(conn Connector, h ServerHealth, now time.Time) {
	m.recordHealthResult(conn, h, now, time.Time{})
}

func (m *Manager) recordHealthResult(conn Connector, h ServerHealth, now, probeStarted time.Time) {
	srv := conn.Server()
	id, name := srv.ID, srv.Name
	h.State = deriveHealthState(h)
	h = m.operationHealth(id, h)
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
	// A failed ping never checked the callback path. Preserve a known callback
	// failure so a later successful daemon read cannot silently clear it.
	if !h.Fail2banOK && h.CallbackOK == nil && had && prev.CallbackOK != nil && !*prev.CallbackOK {
		h.CallbackOK = prev.CallbackOK
	}
	// Check under the same lock as the write: a successful read after a probe
	// started is newer evidence than that probe's late timeout.
	if !probeStarted.IsZero() && !h.Fail2banOK && had && prev.Fail2banOK && prev.CheckedAt.After(probeStarted) {
		m.mu.Unlock()
		return
	}
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
			started := time.Now()
			h := conn.ProbeHealth(probeCtx)
			if ctx.Err() != nil {
				return
			}
			m.recordProbeHealth(conn, h, started, time.Now())
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
