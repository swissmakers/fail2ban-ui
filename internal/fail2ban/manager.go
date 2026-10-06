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
	"reflect"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// =========================================================================
//  Connector Interface
// =========================================================================

// Connector is the communication backend for a Fail2ban server.
type Connector interface {
	Server() shared.Fail2banServer

	GetJailSummary(ctx context.Context) (*JailSummary, error)
	GetBannedIPs(ctx context.Context, jail string) ([]string, error)
	UnbanIP(ctx context.Context, jail, ip string) error
	BanIP(ctx context.Context, jail, ip string) error
	Reload(ctx context.Context) error
	// Restart restarts fail2ban, or reloads it where no service manager is usable; returns "restart" or "reload".
	Restart(ctx context.Context) (mode string, err error)
	// ValidateConfiguration checks the on-disk configuration without applying it.
	ValidateConfiguration(ctx context.Context) error
	// ProbeHealth checks fail2ban and the callback path without side effects.
	ProbeHealth(ctx context.Context) ServerHealth
	GetFilterConfig(ctx context.Context, jail string) (string, string, error)
	SetFilterConfig(ctx context.Context, jail, content string) error

	// Jail management
	GetAllJails(ctx context.Context) ([]JailInfo, error)
	UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error

	// Filter operations
	GetFilters(ctx context.Context) ([]string, error)
	TestFilter(ctx context.Context, filterName string, logLines []string, filterContent string) (output string, filterPath string, err error)

	// Jail configuration operations
	GetJailConfig(ctx context.Context, jail string) (string, string, error)
	SetJailConfig(ctx context.Context, jail, content string) error
	TestLogpathWithResolution(ctx context.Context, logpath string) (originalPath, resolvedPath string, files []string, err error)

	// Jail local structure management (jail.local carries the [DEFAULT] block).
	EnsureJailLocalStructure(ctx context.Context) error

	// CheckJailLocalIntegrity checks whether jail.local exists and contains the
	// ui-custom-action marker, which indicates it is managed by Fail2ban-UI.
	CheckJailLocalIntegrity(ctx context.Context) (bool, bool, error)

	// Jail and filter creation/deletion
	CreateJail(ctx context.Context, jailName, content string) error
	DeleteJail(ctx context.Context, jailName string) error
	CreateFilter(ctx context.Context, filterName, content string) error
	DeleteFilter(ctx context.Context, filterName string) error

	Close() error
}

// =========================================================================
//  Manager
// =========================================================================

// Holds connectors for all configured Fail2ban servers.
type Manager struct {
	reloadMu        sync.Mutex
	mu              sync.RWMutex
	connectors      map[string]Connector
	defaultServerID string
	monitorStop     chan struct{}
	monitorKick     chan struct{}
	monitorWG       sync.WaitGroup
	configSync      map[string]*configSyncState
	health          map[string]ServerHealth
	healthListener  func(string, ServerHealth)
	repairAt        map[string]time.Time
}

const monitorInterval = 45 * time.Second

var (
	managerOnce sync.Once
	managerInst *Manager
)

func GetManager() *Manager {
	managerOnce.Do(func() {
		managerInst = &Manager{
			connectors:  make(map[string]Connector),
			monitorKick: make(chan struct{}, 1),
		}
	})
	return managerInst
}

// Rebuilds connectors from the given server list (typically all servers, enabled or not).
func (m *Manager) ReloadFromServers(servers []shared.Fail2banServer) error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	m.mu.RLock()
	old := m.connectors
	m.mu.RUnlock()
	connectors := make(map[string]Connector)
	defaultID := pickDefaultServerID(servers)

	keep := make(map[string]struct{}, len(servers))
	for _, srv := range servers {
		keep[srv.ID] = struct{}{}
	}
	pruneHostKeyIssues(keep)

	var added []string
	for _, srv := range servers {
		if !srv.Enabled {
			continue
		}
		if previous := old[srv.ID]; previous != nil && sameConnectorConfig(previous.Server(), srv) {
			if ssh, ok := previous.(*SSHConnector); !ok || !sshTunnelConfigChanged(ssh, srv) {
				connectors[srv.ID] = previous
				continue
			}
		}
		conn, err := NewConnector(srv)
		if err != nil {
			return fmt.Errorf("failed to initialise connector for %s (%s): %w", srv.Name, srv.ID, err)
		}
		connectors[srv.ID] = conn
		added = append(added, srv.ID)
	}

	m.mu.Lock()
	m.connectors = connectors
	m.defaultServerID = defaultID
	for id := range m.configSync {
		if _, live := connectors[id]; !live {
			delete(m.configSync, id)
		}
	}
	for id := range m.health {
		if connectors[id] != old[id] {
			delete(m.health, id)
		}
	}
	for id := range m.repairAt {
		if _, live := connectors[id]; !live {
			delete(m.repairAt, id)
		}
	}
	m.syncMonitorLocked()
	m.mu.Unlock()

	// Requested only after the swap, so an in-flight retry cannot apply this generation to the old connector.
	for _, id := range added {
		m.RequestConfigSync(id, true, true)
	}
	// Tear down the connectors of the servers that were removed, disabled or replaced
	for id, conn := range old {
		if next := connectors[id]; next != conn {
			releaseConnector(conn, next)
		}
	}
	if len(added) > 0 {
		select {
		case m.monitorKick <- struct{}{}:
		default:
		}
	}
	return nil
}

// Closes a connector that left the registry; an agent no longer addressed by this entry stops posting callbacks.
func releaseConnector(old, next Connector) {
	switch prev := old.(type) {
	case *AgentConnector:
		if replacement, same := next.(*AgentConnector); !same || replacement.base.String() != prev.base.String() {
			go prev.deregister()
		}
	case *SSHConnector:
		// An unchanged transport shares the ControlMaster socket with the replacement.
		if replacement, same := next.(*SSHConnector); same && !sshTunnelConfigChanged(prev, replacement.server) {
			return
		}
	}
	if err := old.Close(); err != nil {
		debugf("failed to close connector %s: %v", old.Server().ID, err)
	}
}

func sameConnectorConfig(a, b shared.Fail2banServer) bool {
	a.UpdatedAt, b.UpdatedAt = time.Time{}, time.Time{}
	a.IsDefault, b.IsDefault = false, false
	return reflect.DeepEqual(a, b)
}

func (m *Manager) Close() {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	m.mu.Lock()
	if m.monitorStop != nil {
		close(m.monitorStop)
		m.monitorStop = nil
	}
	m.mu.Unlock()
	m.monitorWG.Wait()
	m.mu.Lock()
	connectors := m.connectors
	m.connectors = make(map[string]Connector)
	m.mu.Unlock()
	for id, conn := range connectors {
		if err := conn.Close(); err != nil {
			debugf("failed to close connector %s: %v", id, err)
		}
	}
}

// Starts or stops the server health and config retry monitor.
func (m *Manager) syncMonitorLocked() {
	hasConnectors := len(m.connectors) > 0
	switch {
	case hasConnectors && m.monitorStop == nil:
		m.monitorStop = make(chan struct{})
		m.monitorWG.Add(1)
		go m.serverMonitorLoop(m.monitorStop)
		log.Printf("server health and config sync monitor started (interval %s)", monitorInterval)
	case !hasConnectors && m.monitorStop != nil:
		close(m.monitorStop)
		m.monitorStop = nil
		log.Printf("server monitor stopped (no enabled servers)")
	}
}

// Probes server health and retries pending config pushes, immediately and then every interval.
func (m *Manager) serverMonitorLoop(stop <-chan struct{}) {
	defer m.monitorWG.Done()
	monitorCtx, stopMonitor := context.WithCancel(context.Background())
	defer stopMonitor()
	go func() {
		select {
		case <-stop:
			stopMonitor()
		case <-monitorCtx.Done():
		}
	}()
	run := func() {
		ctx, cancel := context.WithTimeout(monitorCtx, 40*time.Second)
		defer cancel()
		var wg sync.WaitGroup
		wg.Go(func() { m.RetryPendingConfig(ctx) })
		wg.Go(func() { m.ProbeAll(ctx) })
		wg.Wait()
	}
	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()
	run()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			run()
		case <-m.monitorKick:
			run()
		}
	}
}

func pickDefaultServerID(servers []shared.Fail2banServer) string {
	var fallback string
	for _, srv := range servers {
		if !srv.Enabled {
			continue
		}
		if fallback == "" {
			fallback = srv.ID
		}
		if srv.IsDefault {
			return srv.ID
		}
	}
	return fallback
}

// Returns the connector for the specified server ID.
func (m *Manager) Connector(serverID string) (Connector, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if serverID == "" {
		return nil, fmt.Errorf("server id must be provided")
	}
	conn, ok := m.connectors[serverID]
	if !ok {
		return nil, fmt.Errorf("connector for server %s not found or not enabled", serverID)
	}
	return conn, nil
}

// Returns the connector for the default enabled server.
func (m *Manager) DefaultConnector() (Connector, error) {
	m.mu.RLock()
	id := m.defaultServerID
	m.mu.RUnlock()
	if id == "" {
		return nil, fmt.Errorf("no active fail2ban server configured")
	}
	return m.Connector(id)
}

// Returns all connectors.
func (m *Manager) Connectors() []Connector {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Connector, 0, len(m.connectors))
	for _, conn := range m.connectors {
		result = append(result, conn)
	}
	return result
}

// =========================================================================
//  Action File Management
// =========================================================================

func updateConnectorAction(ctx context.Context, conn Connector) error {
	switch c := conn.(type) {
	case *SSHConnector:
		return c.ensureAction(ctx)
	case *AgentConnector:
		return c.ensureCallbackConfig(ctx)
	case *LocalConnector:
		return WriteLocalActionFile(c.configPath(), mustProvider().CallbackURL(), c.Server().ID)
	default:
		return nil
	}
}

// Applies pending config on every enabled server concurrently; returns the failures by server ID.
func (m *Manager) SyncAll(ctx context.Context, perHostTimeout time.Duration) map[string]error {
	var mu sync.Mutex
	var wg sync.WaitGroup
	failed := make(map[string]error)
	for _, conn := range m.Connectors() {
		id := conn.Server().ID
		if !m.ConfigSyncStatus(id).Pending {
			continue
		}
		wg.Go(func() {
			hostCtx, cancel := context.WithTimeout(ctx, perHostTimeout)
			defer cancel()
			if err := m.SyncServerConfig(hostCtx, id); err != nil {
				mu.Lock()
				failed[id] = err
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return failed
}

// =========================================================================
//  Connector Factory
// =========================================================================

func NewConnector(server shared.Fail2banServer) (Connector, error) {
	switch server.Type {
	case "local":
		return NewLocalConnector(server), nil
	case "ssh":
		return newSSHConnector(server)
	case "agent":
		return NewAgentConnector(server)
	default:
		return nil, fmt.Errorf("unsupported server type %s", server.Type)
	}
}
