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

package fail2ban

import (
	"context"
	"fmt"
	"sync"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// =========================================================================
//  Connector Interface
// =========================================================================

// Connector is the communication backend for a Fail2ban server.
type Connector interface {
	ID() string
	Server() shared.Fail2banServer

	GetJailInfos(ctx context.Context) ([]JailInfo, error)
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
	TestLogpath(ctx context.Context, logpath string) ([]string, error)
	TestLogpathWithResolution(ctx context.Context, logpath string) (originalPath, resolvedPath string, files []string, err error)

	// Default settings operations
	UpdateDefaultSettings(ctx context.Context) error

	// Jail local structure management
	EnsureJailLocalStructure(ctx context.Context) error

	// CheckJailLocalIntegrity checks whether jail.local exists and contains the
	// ui-custom-action marker, which indicates it is managed by Fail2ban-UI.
	CheckJailLocalIntegrity(ctx context.Context) (bool, bool, error)

	// Jail and filter creation/deletion
	CreateJail(ctx context.Context, jailName, content string) error
	DeleteJail(ctx context.Context, jailName string) error
	CreateFilter(ctx context.Context, filterName, content string) error
	DeleteFilter(ctx context.Context, filterName string) error
}

// =========================================================================
//  Manager
// =========================================================================

// Holds connectors for all configured Fail2ban servers.
type Manager struct {
	mu              sync.RWMutex
	connectors      map[string]Connector
	defaultServerID string
}

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
	m.mu.Lock()
	defer m.mu.Unlock()

	connectors := make(map[string]Connector)
	defaultID := pickDefaultServerID(servers)

	for _, srv := range servers {
		if !srv.Enabled {
			continue
		}
		conn, err := newConnectorForServer(srv)
		if err != nil {
			return fmt.Errorf("failed to initialise connector for %s (%s): %w", srv.Name, srv.ID, err)
		}
		connectors[srv.ID] = conn
	}

	m.connectors = connectors
	m.defaultServerID = defaultID
	return nil
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
			fmt.Printf("warning: failed to update action file for server %s: %v\n", conn.Server().Name, err)
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

func updateConnectorAction(ctx context.Context, conn Connector) error {
	switch c := conn.(type) {
	case *SSHConnector:
		return c.ensureAction(ctx)
	case *AgentConnector:
		return c.ensureAction(ctx)
	default:
		return nil
	}
}

// =========================================================================
//  Connector Factory
// =========================================================================

func newConnectorForServer(server shared.Fail2banServer) (Connector, error) {
	switch server.Type {
	case "local":
		if isJailAutoMigrationEnabled() {
			debugf("JAIL_AUTOMIGRATION=true: running experimental jail.local → jail.d/ migration for local server %s", server.Name)
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
