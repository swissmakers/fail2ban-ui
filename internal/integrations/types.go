package integrations

import (
	"context"
	"fmt"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// Request represents a block/unblock request for an integration plugin.
type Request struct {
	Context context.Context
	IP      string
	Config  config.AdvancedActionsConfig
	Server  config.Fail2banServer

	Logger func(format string, args ...interface{})
}

// Integration exposes functionality required by an external firewall vendor.
type Integration interface {
	ID() string
	DisplayName() string
	BlockIP(req Request) error
	UnblockIP(req Request) error
	Validate(cfg config.AdvancedActionsConfig) error
}

var registry = map[string]Integration{}

// Register adds an integration to the global registry.
func Register(integration Integration) {
	if integration == nil {
		return
	}
	registry[integration.ID()] = integration
}

// Get returns the integration by id.
func Get(id string) (Integration, bool) {
	integration, ok := registry[id]
	return integration, ok
}

// MustGet obtains the integration or panics – used during init.
func MustGet(id string) Integration {
	integration, ok := Get(id)
	if !ok {
		panic(fmt.Sprintf("integration %s not registered", id))
	}
	return integration
}

// Supported returns ids of all registered integrations.
func Supported() []string {
	keys := make([]string, 0, len(registry))
	for id := range registry {
		keys = append(keys, id)
	}
	return keys
}
