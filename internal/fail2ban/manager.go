package fail2ban

import (
	"context"
	"fmt"
	"sync"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// Connector describes a communication backend for a Fail2ban server.
type Connector interface {
	ID() string
	Server() config.Fail2banServer

	GetJailInfos(ctx context.Context) ([]JailInfo, error)
	GetBannedIPs(ctx context.Context, jail string) ([]string, error)
	UnbanIP(ctx context.Context, jail, ip string) error
	Reload(ctx context.Context) error
	Restart(ctx context.Context) error
	GetFilterConfig(ctx context.Context, jail string) (string, string, error) // Returns (config, filePath, error)
	SetFilterConfig(ctx context.Context, jail, content string) error
	FetchBanEvents(ctx context.Context, limit int) ([]BanEvent, error)

	// Jail management
	GetAllJails(ctx context.Context) ([]JailInfo, error)
	UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error

	// Filter operations
	GetFilters(ctx context.Context) ([]string, error)
	TestFilter(ctx context.Context, filterName string, logLines []string) (output string, filterPath string, err error)

	// Jail configuration operations
	GetJailConfig(ctx context.Context, jail string) (string, string, error) // Returns (config, filePath, error)
	SetJailConfig(ctx context.Context, jail, content string) error
	TestLogpath(ctx context.Context, logpath string) ([]string, error)
	TestLogpathWithResolution(ctx context.Context, logpath string) (originalPath, resolvedPath string, files []string, err error)

	// Default settings operations
	UpdateDefaultSettings(ctx context.Context, settings config.AppSettings) error

	// Jail local structure management
	EnsureJailLocalStructure(ctx context.Context) error

	// Jail and filter creation/deletion
	CreateJail(ctx context.Context, jailName, content string) error
	DeleteJail(ctx context.Context, jailName string) error
	CreateFilter(ctx context.Context, filterName, content string) error
	DeleteFilter(ctx context.Context, filterName string) error
}

// Manager orchestrates all connectors for configured Fail2ban servers.
type Manager struct {
	mu         sync.RWMutex
	connectors map[string]Connector
}

var (
	managerOnce sync.Once
	managerInst *Manager
)

// GetManager returns the singleton connector manager.
func GetManager() *Manager {
	managerOnce.Do(func() {
		managerInst = &Manager{
			connectors: make(map[string]Connector),
		}
	})
	return managerInst
}

// ReloadFromSettings rebuilds connectors using the provided settings.
func (m *Manager) ReloadFromSettings(settings config.AppSettings) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	connectors := make(map[string]Connector)
	for _, srv := range settings.Servers {
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
	return nil
}

// Connector returns the connector for the specified server ID.
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

// DefaultConnector returns the default connector as defined in settings.
func (m *Manager) DefaultConnector() (Connector, error) {
	server := config.GetDefaultServer()
	if server.ID == "" {
		return nil, fmt.Errorf("no active fail2ban server configured")
	}
	return m.Connector(server.ID)
}

// Connectors returns all connectors.
func (m *Manager) Connectors() []Connector {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Connector, 0, len(m.connectors))
	for _, conn := range m.connectors {
		result = append(result, conn)
	}
	return result
}

// UpdateActionFiles updates action files for all active remote connectors (SSH and Agent).
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

// UpdateActionFileForServer updates the action file for a specific server by ID.
func (m *Manager) UpdateActionFileForServer(ctx context.Context, serverID string) error {
	m.mu.RLock()
	conn, ok := m.connectors[serverID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("connector for server %s not found or not enabled", serverID)
	}
	return updateConnectorAction(ctx, conn)
}

// updateConnectorAction updates the action file for a specific connector.
func updateConnectorAction(ctx context.Context, conn Connector) error {
	switch c := conn.(type) {
	case *SSHConnector:
		return c.ensureAction(ctx)
	case *AgentConnector:
		return c.ensureAction(ctx)
	default:
		return nil // Local connectors are handled separately
	}
}

func newConnectorForServer(server config.Fail2banServer) (Connector, error) {
	switch server.Type {
	case "local":
		// IMPORTANT: Run migration FIRST before ensuring structure
		// This ensures any legacy jails in jail.local are migrated to jail.d/*.local
		// before ensureJailLocalStructure() overwrites jail.local
		if err := MigrateJailsFromJailLocal(); err != nil {
			return nil, fmt.Errorf("failed to initialise local fail2ban connector for %s: %w", server.Name, err)
		}

		if err := config.EnsureLocalFail2banAction(server); err != nil {
			return nil, fmt.Errorf("failed to ensure local fail2ban action for %s: %w", server.Name, err)
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
