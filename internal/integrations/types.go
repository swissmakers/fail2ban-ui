package integrations

import (
	"context"
	"fmt"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// =========================================================================
//  Types
// =========================================================================

// Block/Unblock request for an integration.
type Request struct {
	Context context.Context
	IP      string
	Config  config.AdvancedActionsConfig
	Server  config.Fail2banServer

	Logger func(format string, args ...interface{})
}

// Exposes functionality required by an external firewall vendor.
type Integration interface {
	ID() string
	DisplayName() string
	BlockIP(req Request) error
	UnblockIP(req Request) error
	Validate(cfg config.AdvancedActionsConfig) error
}

var registry = map[string]Integration{}

// =========================================================================
//  Registry
// =========================================================================

// Adds an integration to the registry.
func Register(integration Integration) {
	if integration == nil {
		return
	}
	registry[integration.ID()] = integration
}

// Returns the integration by id.
func Get(id string) (Integration, bool) {
	integration, ok := registry[id]
	return integration, ok
}

// Returns the integration or panics.
func MustGet(id string) Integration {
	integration, ok := Get(id)
	if !ok {
		panic(fmt.Sprintf("integration %s not registered", id))
	}
	return integration
}

// Returns all registered integration ids.
func Supported() []string {
	keys := make([]string, 0, len(registry))
	for id := range registry {
		keys = append(keys, id)
	}
	return keys
}
