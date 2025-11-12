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
	GetFilterConfig(ctx context.Context, jail string) (string, error)
	SetFilterConfig(ctx context.Context, jail, content string) error
	FetchBanEvents(ctx context.Context, limit int) ([]BanEvent, error)

	// Jail management
	GetAllJails(ctx context.Context) ([]JailInfo, error)
	UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error

	// Filter operations
	GetFilters(ctx context.Context) ([]string, error)
	TestFilter(ctx context.Context, filterName string, logLines []string) ([]string, error)
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

func newConnectorForServer(server config.Fail2banServer) (Connector, error) {
	switch server.Type {
	case "local":
		if err := config.EnsureLocalFail2banAction(server); err != nil {
			fmt.Printf("warning: failed to ensure local fail2ban action: %v\n", err)
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
