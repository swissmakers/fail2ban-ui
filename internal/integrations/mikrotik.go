package integrations

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

type mikrotikIntegration struct{}

func init() {
	Register(&mikrotikIntegration{})
}

// =========================================================================
//  Interface Implementation
// =========================================================================

func (m *mikrotikIntegration) ID() string {
	return "mikrotik"
}

func (m *mikrotikIntegration) DisplayName() string {
	return "Mikrotik RouterOS"
}

func (m *mikrotikIntegration) Validate(cfg config.AdvancedActionsConfig) error {
	if cfg.Mikrotik.Host == "" {
		return fmt.Errorf("mikrotik host is required")
	}
	if cfg.Mikrotik.Username == "" {
		return fmt.Errorf("mikrotik username is required")
	}
	if cfg.Mikrotik.Password == "" && cfg.Mikrotik.SSHKeyPath == "" {
		return fmt.Errorf("mikrotik password or SSH key path is required")
	}
	if cfg.Mikrotik.AddressList == "" {
		return fmt.Errorf("mikrotik address list is required")
	}
	return nil
}

// =========================================================================
//  Block/Unblock
// =========================================================================

func (m *mikrotikIntegration) BlockIP(req Request) error {
	if err := m.Validate(req.Config); err != nil {
		return err
	}
	if err := ValidateIP(req.IP); err != nil {
		return fmt.Errorf("mikrotik block: %w", err)
	}
	if err := ValidateIdentifier(req.Config.Mikrotik.AddressList, "address list"); err != nil {
		return fmt.Errorf("mikrotik block: %w", err)
	}
	cmd := fmt.Sprintf(`/ip firewall address-list add list=%s address=%s comment="Fail2ban-UI permanent block"`,
		req.Config.Mikrotik.AddressList, req.IP)
	return m.runCommand(req, cmd)
}

func (m *mikrotikIntegration) UnblockIP(req Request) error {
	if err := m.Validate(req.Config); err != nil {
		return err
	}
	if err := ValidateIP(req.IP); err != nil {
		return fmt.Errorf("mikrotik unblock: %w", err)
	}
	if err := ValidateIdentifier(req.Config.Mikrotik.AddressList, "address list"); err != nil {
		return fmt.Errorf("mikrotik unblock: %w", err)
	}
	cmd := fmt.Sprintf(`/ip firewall address-list remove [/ip firewall address-list find address=%s list=%s]`,
		req.IP, req.Config.Mikrotik.AddressList)
	return m.runCommand(req, cmd)
}

// =========================================================================
//  SSH Communication
// =========================================================================

func (m *mikrotikIntegration) runCommand(req Request, command string) error {
	cfg := req.Config.Mikrotik

	authMethods := []ssh.AuthMethod{}
	if cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(cfg.Password))
	}
	if cfg.SSHKeyPath != "" {
		key, err := os.ReadFile(cfg.SSHKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read mikrotik ssh key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to parse mikrotik ssh key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if len(authMethods) == 0 {
		return fmt.Errorf("no authentication method available for mikrotik")
	}

	port := cfg.Port
	if port == 0 {
		port = 22
	}

	clientCfg := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	address := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", port))
	client, err := ssh.Dial("tcp", address, clientCfg)
	if err != nil {
		if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				return fmt.Errorf("connection to mikrotik at %s timed out: %w", address, err)
			}
		}
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Err != nil {
				return fmt.Errorf("failed to connect to mikrotik at %s: %v (check host, port %d, and network connectivity)", address, opErr.Err, port)
			}
		}
		return fmt.Errorf("failed to connect to mikrotik at %s: %w (check host, port %d, username, and credentials)", address, err, port)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create mikrotik ssh session: %w", err)
	}
	defer session.Close()

	if req.Logger != nil {
		req.Logger("Running Mikrotik command: %s", command)
	}

	output, err := session.CombinedOutput(command)
	if err != nil {
		return fmt.Errorf("mikrotik command failed: %w (output: %s)", err, string(output))
	}
	if req.Logger != nil {
		req.Logger("Mikrotik command output: %s", string(output))
	}
	return nil
}
