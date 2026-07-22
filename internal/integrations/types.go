package integrations

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
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

// =========================================================================
//  Input Validation
// =========================================================================

// Matches only alphanumeric characters, hyphens, underscores and dots
var safeIdentifier = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

// Validates that the string is a valid IPv4/IPv6 address or CIDR notation and contains no shell metacharacters.
// Canonical implementation lives in shared (also used by the fail2ban connectors).
func ValidateIP(ip string) error {
	return shared.ValidateIP(ip)
}

// Validates that an user-configured base URL is well-formed and uses an allowed scheme (http/https).
func ValidateOutboundURL(rawURL, label string) error {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return fmt.Errorf("%s is required", label)
	}
	if strings.ContainsAny(trimmed, "\r\n") {
		return fmt.Errorf("%s contains invalid control characters", label)
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", label, err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("%s must use http or https", label)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s must include a host", label)
	}
	return nil
}

// Caps how much of a firewall API response is read into memory, so a hostile or broken endpoint cannot exhaust memory.
const maxIntegrationResponseBytes = 5 << 20 // 5 MiB

// returns client for credential-bearing firewall API requests. Redirects are NOT followed, Go strips Authorization on cross-host
// redirects but not custom headers (x-api-key), so following one would replay credentials to the redirect target.
func integrationHTTPClient(timeout time.Duration, skipTLSVerify bool) *http.Client {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if skipTLSVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return client
}

// Reads at most maxIntegrationResponseBytes from a body.
func readLimitedResponse(body io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(body, maxIntegrationResponseBytes))
}

// Validates that a user-supplied name (address list, alias, etc.) contains only safe characters and cannot be used for injection attacks.
func ValidateIdentifier(name, label string) error {
	if name == "" {
		return fmt.Errorf("%s is required", label)
	}
	if !safeIdentifier.MatchString(name) {
		return fmt.Errorf("%s contains invalid characters: %q", label, name)
	}
	return nil
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
