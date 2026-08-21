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

package shared

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// A hostname or IP literal
	hostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:_-]*$`)
	// A POSIX-ish user name
	sshUserRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	// An absolute filesystem path with no shell
	absPathRe = regexp.MustCompile(`^[A-Za-z0-9 ._/-]+$`)
)

func ValidateHost(host string) error {
	if host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	if !hostRe.MatchString(host) {
		return fmt.Errorf("invalid host %q: only letters, digits, '.', ':', '-' and '_' are allowed and it must not start with '-'", host)
	}
	return nil
}

// Checks an SSH login name. The value must already be normalized (trimmed).
func ValidateSSHUser(user string) error {
	if user == "" {
		return fmt.Errorf("sshUser cannot be empty")
	}
	if !sshUserRe.MatchString(user) {
		return fmt.Errorf("invalid sshUser %q: only letters, digits, '.', '-' and '_' are allowed and it must not start with '-'", user)
	}
	return nil
}

// Checks a filesystem path used for a key, socket or config root.
func ValidateAbsolutePath(path, label string) error {
	if path == "" {
		return nil
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("%s contains a null byte", label)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s %q must be an absolute path", label, path)
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("%s %q must be a clean path (no '.', '..' or duplicate separators)", label, path)
	}
	if !absPathRe.MatchString(path) {
		return fmt.Errorf("%s %q contains unsupported characters", label, path)
	}
	return nil
}

func ValidateServerFields(srv Fail2banServer) error {
	switch srv.Type {
	case "", "local":
		if err := ValidateAbsolutePath(srv.SocketPath, "socketPath"); err != nil {
			return err
		}
		if err := ValidateAbsolutePath(srv.ConfigPath, "configPath"); err != nil {
			return err
		}
	case "ssh":
		if err := ValidateHost(srv.Host); err != nil {
			return err
		}
		if err := ValidateSSHUser(srv.SSHUser); err != nil {
			return err
		}
		if err := ValidateAbsolutePath(srv.SSHKeyPath, "sshKeyPath"); err != nil {
			return err
		}
		if err := ValidateAbsolutePath(srv.SocketPath, "socketPath"); err != nil {
			return err
		}
		if err := ValidatePort(srv.Port); err != nil {
			return err
		}
	case "agent":
		// AgentURL is validated separately via NormalizeAgentURL
	default:
		return fmt.Errorf("unsupported server type %q", srv.Type)
	}
	return nil
}
