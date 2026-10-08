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
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// A timeout after command submission cannot tell us whether the daemon applied
// the command. Callers must verify its outcome instead of retrying or rolling back.
var ErrOperationOutcomeUnknown = errors.New("Fail2Ban operation outcome is unknown")

// SetConfigSyncScheduler routes every automatic or request-triggered config
// sync into the application's durable queue. Passing nil restores direct mode
// for standalone callers and tests. The callback must return promptly.
func (m *Manager) SetConfigSyncScheduler(schedule func(string)) {
	m.mu.Lock()
	m.configSyncScheduler = schedule
	m.mu.Unlock()
}

func (m *Manager) ownsOperation(ctx context.Context, serverID string) bool {
	lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease)
	if !ok || lease.manager != m || m.operationTargetKey(lease.serverID) != m.operationTargetKey(serverID) {
		return false
	}
	lease.gate.mu.Lock()
	defer lease.gate.mu.Unlock()
	return lease.gate.owner == lease
}

func normalizedOperationSocket(socket string) string {
	if strings.TrimSpace(socket) == "" {
		socket = "/var/run/fail2ban/fail2ban.sock"
	}
	return strings.Replace(filepath.Clean(socket), "/var/run/", "/run/", 1)
}

func operationTarget(server shared.Fail2banServer) string {
	switch server.Type {
	case "local":
		// The daemon socket, not a UI entry or client config directory, identifies
		// the process that must never receive overlapping mutations.
		return "local:" + normalizedOperationSocket(server.SocketPath)
	case "ssh":
		port := server.Port
		if port == 0 {
			port = 22
		}
		return fmt.Sprintf("ssh:%s:%d:%s", strings.ToLower(strings.Trim(server.Host, "[]")), port, normalizedOperationSocket(server.SocketPath))
	case "agent":
		if u, err := url.Parse(server.AgentURL); err == nil {
			u.Scheme = strings.ToLower(u.Scheme)
			host, port := strings.ToLower(u.Hostname()), u.Port()
			if port == "80" && u.Scheme == "http" || port == "443" && u.Scheme == "https" {
				port = ""
			}
			if port != "" {
				u.Host = net.JoinHostPort(host, port)
			} else {
				u.Host = host
				if strings.Contains(host, ":") {
					u.Host = "[" + host + "]"
				}
			}
			u.Path = strings.TrimRight(u.Path, "/")
			u.RawQuery = ""
			u.Fragment = ""
			u.User = nil
			return "agent:" + u.String()
		}
	}
	return "server:" + server.ID
}

func (m *Manager) operationTargetKey(serverID string) string {
	m.mu.RLock()
	target := m.operationTargets[serverID]
	m.mu.RUnlock()
	if target == "" {
		return "server:" + serverID
	}
	return target
}

func (m *Manager) SameOperationTarget(a, b string) bool {
	return m.operationTargetKey(a) == m.operationTargetKey(b)
}

// ConfigureOperationTargets must run before recovery reserves leases. Aliases
// for the same endpoint share one gate. Moving/removing a busy entry is refused.
func (m *Manager) ConfigureOperationTargets(servers []shared.Fail2banServer) error {
	next := make(map[string]string, len(servers))
	for _, server := range servers {
		next[server.ID] = operationTarget(server)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, previous := range m.operationTargets {
		if next[id] == previous {
			continue
		}
		if value, ok := m.operationGates.Load(previous); ok {
			gate := value.(*operationGate)
			gate.mu.Lock()
			busy := gate.owner != nil
			gate.mu.Unlock()
			if busy {
				return fmt.Errorf("server %s has an operation in progress; its endpoint cannot be changed or removed", id)
			}
		}
	}
	m.operationTargets = next
	return nil
}

type OperationActivity struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	StartedAt time.Time `json:"startedAt"`
}

type operationGate struct {
	changed  chan struct{}
	mu       sync.Mutex
	owner    *operationLease
	activity OperationActivity
}

// GuardServerConfiguration keeps operation admission out of the small window
// between a server-edit preflight and its persisted connector replacement.
// Release it before scheduling or waiting for any daemon operation.
func (m *Manager) GuardServerConfiguration() func() {
	m.operationAdmission.Lock()
	var once sync.Once
	return func() { once.Do(m.operationAdmission.Unlock) }
}

type operationLease struct {
	manager  *Manager
	serverID string
	gate     *operationGate
	id       string
}
type operationLeaseKey struct{}

type operationCheckpointKey struct{}

func WithOperationCheckpoint(ctx context.Context, checkpoint func(context.Context, string) error) context.Context {
	return context.WithValue(ctx, operationCheckpointKey{}, checkpoint)
}

// OperationCheckpoint journals phase boundaries before their side effects.
func OperationCheckpoint(ctx context.Context, phase string) error {
	if checkpoint, ok := ctx.Value(operationCheckpointKey{}).(func(context.Context, string) error); ok {
		return checkpoint(ctx, phase)
	}
	return nil
}

// BeginOperation serializes complete configuration transactions with restarts
// and automatic configuration repair. A lease is reentrant only through its
// returned context; merely supplying an identical operation ID does not bypass it.
// It deliberately does not require a connector, allowing startup recovery to
// reserve a target before any background monitor can mutate its configuration.
func (m *Manager) BeginOperation(ctx context.Context, serverID, operationID, kind string) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if held, ok := ctx.Value(operationLeaseKey{}).(*operationLease); ok && held.manager == m && m.operationTargetKey(held.serverID) == m.operationTargetKey(serverID) {
		held.gate.mu.Lock()
		owns := held.gate.owner == held
		held.gate.mu.Unlock()
		if owns {
			return ctx, func() {}, nil
		}
	}
	var gate *operationGate
	var lease *operationLease
	for {
		m.operationAdmission.RLock()
		if err := ctx.Err(); err != nil {
			m.operationAdmission.RUnlock()
			return nil, nil, err
		}
		value, _ := m.operationGates.LoadOrStore(m.operationTargetKey(serverID), &operationGate{changed: make(chan struct{})})
		gate = value.(*operationGate)
		gate.mu.Lock()
		if gate.owner == nil {
			lease = &operationLease{manager: m, serverID: serverID, gate: gate, id: operationID}
			gate.owner = lease
			gate.activity = OperationActivity{ID: operationID, Kind: kind, StartedAt: time.Now().UTC()}
			gate.mu.Unlock()
			m.operationAdmission.RUnlock()
			break
		}
		changed := gate.changed
		gate.mu.Unlock()
		m.operationAdmission.RUnlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			gate.mu.Lock()
			gate.owner = nil
			gate.activity = OperationActivity{}
			close(gate.changed)
			gate.changed = make(chan struct{})
			gate.mu.Unlock()
		})
	}
	return context.WithValue(ctx, operationLeaseKey{}, lease), release, nil
}

func (m *Manager) OperationStatus(serverID string) (OperationActivity, bool) {
	value, ok := m.operationGates.Load(m.operationTargetKey(serverID))
	if !ok {
		return OperationActivity{}, false
	}
	gate := value.(*operationGate)
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.activity, gate.owner != nil
}

func OperationID(ctx context.Context) string {
	if held, ok := ctx.Value(operationLeaseKey{}).(*operationLease); ok {
		return held.id
	}
	return ""
}
