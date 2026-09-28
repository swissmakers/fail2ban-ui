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

	GetJailInfos(ctx context.Context) ([]JailInfo, error)
	GetJailSummary(ctx context.Context) (*JailSummary, error)
	GetBannedIPs(ctx context.Context, jail string) ([]string, error)
	UnbanIP(ctx context.Context, jail, ip string) error
	BanIP(ctx context.Context, jail, ip string) error
	Reload(ctx context.Context) error
	Restart(ctx context.Context) error
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
	tunnelMonStop   chan struct{}
	monitorWG       sync.WaitGroup
	configSync      map[string]*configSyncState
}

const tunnelCheckInterval = 45 * time.Second

var (
	managerOnce sync.Once
	managerInst *Manager
)

func GetManager() *Manager {
	managerOnce.Do(func() {
		managerInst = &Manager{
			connectors: make(map[string]Connector),
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
		if oldSSH, ok := old[srv.ID].(*SSHConnector); ok && sshTunnelConfigChanged(oldSSH, srv) {
			_ = oldSSH.Close()
		}
		conn, err := NewConnector(srv)
		if err != nil {
			return fmt.Errorf("failed to initialise connector for %s (%s): %w", srv.Name, srv.ID, err)
		}
		connectors[srv.ID] = conn
		m.RequestConfigSync(srv.ID, true, true)
	}

	// Tear down the SSH master of the server that were removed or disabled
	for id, conn := range old {
		if _, still := connectors[id]; still {
			continue
		}
		if oldSSH, ok := conn.(*SSHConnector); ok {
			_ = oldSSH.Close()
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Keep sync state of removed servers: an in-flight sync still holds it, so replacing it would allow two concurrent syncs.
	m.connectors = connectors
	m.defaultServerID = defaultID
	m.syncTunnelMonitorLocked()
	return nil
}

func sameConnectorConfig(a, b shared.Fail2banServer) bool {
	a.UpdatedAt, b.UpdatedAt = time.Time{}, time.Time{}
	a.RestartNeeded, b.RestartNeeded = false, false
	a.IsDefault, b.IsDefault = false, false
	return reflect.DeepEqual(a, b)
}

func (m *Manager) Close() {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	m.mu.Lock()
	if m.tunnelMonStop != nil {
		close(m.tunnelMonStop)
		m.tunnelMonStop = nil
	}
	m.mu.Unlock()
	// A sync may still be persisting its result. Join the monitor without
	// holding the registry lock before storage can close.
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

// Starts or stops the connector health and config retry monitor
func (m *Manager) syncTunnelMonitorLocked() {
	hasConnectors := len(m.connectors) > 0
	switch {
	case hasConnectors && m.tunnelMonStop == nil:
		m.tunnelMonStop = make(chan struct{})
		m.monitorWG.Add(1)
		go m.tunnelMonitorLoop(m.tunnelMonStop)
		log.Printf("connector health and config sync monitor started (interval %s)", tunnelCheckInterval)
	case !hasConnectors && m.tunnelMonStop != nil:
		close(m.tunnelMonStop)
		m.tunnelMonStop = nil
		log.Printf("connector monitor stopped (no enabled servers)")
	}
}

// Periodically verifies reverse-tunnel SSH masters and re-establishes dead ones.
func (m *Manager) tunnelMonitorLoop(stop <-chan struct{}) {
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
	ticker := time.NewTicker(tunnelCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(monitorCtx, 40*time.Second)
			m.RetryPendingConfig(ctx)
			m.CheckTunnels(ctx)
			cancel()
		}
	}
}

// Runs the reverse-tunnel health check for every SSH connector with an active tunnel
func (m *Manager) CheckTunnels(ctx context.Context) {
	m.mu.RLock()
	var tunneled []*SSHConnector
	for _, conn := range m.connectors {
		if sc, ok := conn.(*SSHConnector); ok && sc.tunnelPort > 0 {
			tunneled = append(tunneled, sc)
		}
	}
	m.mu.RUnlock()

	var wg sync.WaitGroup
	for _, sc := range tunneled {
		wg.Add(1)
		go func(sc *SSHConnector) {
			defer wg.Done()
			checkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			sc.CheckTunnelHealth(checkCtx)
		}(sc)
	}
	wg.Wait()
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

func (m *Manager) RepairActionFile(ctx context.Context, serverID string) {
	m.mu.RLock()
	conn := m.connectors[serverID]
	m.mu.RUnlock()

	sc, ok := conn.(*SSHConnector)
	if !ok || !sc.beginActionRepair() {
		return
	}
	m.RequestConfigSync(serverID, true, false)
	_ = m.SyncServerConfig(ctx, serverID)
}

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

// Pushes runtime config to all enabled connectors, including local ones, then reloads Fail2Ban.
// Is intended to run once at startup after the connector registry was rebuilt.
func (m *Manager) SyncRemoteStartupConfig(ctx context.Context, perHostTimeout time.Duration) (synced int, failed int) {
	if perHostTimeout <= 0 {
		perHostTimeout = 30 * time.Second
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, conn := range m.Connectors() {
		id := conn.Server().ID
		m.RequestConfigSync(id, true, true)
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostCtx, cancel := context.WithTimeout(ctx, perHostTimeout)
			defer cancel()
			err := m.SyncServerConfig(hostCtx, id)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				synced++
			} else {
				failed++
			}
		}()
	}
	wg.Wait()
	return synced, failed
}

// =========================================================================
//  Connector Factory
// =========================================================================

func NewConnector(server shared.Fail2banServer) (Connector, error) {
	switch server.Type {
	case "local":
		if isJailAutoMigrationEnabled() {
			debugf("JAIL_AUTOMIGRATION=true: running experimental jail.local -> jail.d/ migration for local server %s", server.Name)
			if err := MigrateJailsFromJailLocal(server.ConfigPath); err != nil {
				return nil, fmt.Errorf("failed to initialise local fail2ban connector for %s: %w", server.Name, err)
			}
		}
		return NewLocalConnector(server), nil
	case "ssh":
		return NewSSHConnector(server)
	case "agent":
		return NewAgentConnector(server)
	default:
		return nil, fmt.Errorf("unsupported server type %s", server.Type)
	}
}

// Updates action files for all active remote connectors (SSH and Agent).
func (m *Manager) UpdateActionFiles(ctx context.Context) error {
	m.mu.RLock()
	connectors := make([]Connector, 0, len(m.connectors))
	for _, conn := range m.connectors {
		server := conn.Server()
		// Only update remote servers (SSH and Agent), not local
		if server.Type == "ssh" || server.Type == "agent" {
			connectors = append(connectors, conn)
		}
	}
	m.mu.RUnlock()

	var lastErr error
	for _, conn := range connectors {
		if err := updateConnectorAction(ctx, conn); err != nil {
			log.Printf("warning: failed to update action file for server %s: %v", conn.Server().Name, err)
			lastErr = err
		}
	}
	return lastErr
}

// Updates the action file for a single server.
func (m *Manager) UpdateActionFileForServer(ctx context.Context, serverID string) error {
	m.mu.RLock()
	conn, ok := m.connectors[serverID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("connector for server %s not found or not enabled", serverID)
	}
	return updateConnectorAction(ctx, conn)
}
