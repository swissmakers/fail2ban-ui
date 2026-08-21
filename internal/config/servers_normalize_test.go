// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"strings"
	"testing"
)

// Runs normalizeServersLocked against the given servers and returns the
// normalized result, restoring the package state afterwards.
func normalizeTestServers(t *testing.T, servers []Fail2banServer) []Fail2banServer {
	t.Helper()
	settingsLock.Lock()
	defer settingsLock.Unlock()
	orig := currentSettings
	defer func() { currentSettings = orig }()
	currentSettings.Servers = servers
	normalizeServersLocked()
	out := make([]Fail2banServer, len(currentSettings.Servers))
	copy(out, currentSettings.Servers)
	return out
}

func TestNormalizeServersNormalizesBeforeValidation(t *testing.T) {
	out := normalizeTestServers(t, []Fail2banServer{{
		ID: "s1", Name: "SSH Box", Type: " SSH ", Host: " 10.0.0.1 ",
		SSHUser: " root ", SSHKeyPath: "/config/.ssh//id_rsa",
		Enabled: true, EnabledSet: true,
	}})
	srv := out[0]
	if srv.Type != "ssh" {
		t.Errorf("type not normalized: %q", srv.Type)
	}
	if srv.Host != "10.0.0.1" {
		t.Errorf("host not trimmed: %q", srv.Host)
	}
	if srv.SSHUser != "root" {
		t.Errorf("sshUser not trimmed: %q", srv.SSHUser)
	}
	if srv.SSHKeyPath != "/config/.ssh/id_rsa" {
		t.Errorf("sshKeyPath not cleaned: %q", srv.SSHKeyPath)
	}
	if !srv.Enabled {
		t.Error("normalized server must stay enabled, got disabled")
	}
}

func TestNormalizeServersCleansLocalConfigPath(t *testing.T) {
	out := normalizeTestServers(t, []Fail2banServer{{
		ID: "l1", Name: "Local", Type: "local",
		SocketPath: "/var/run/fail2ban/fail2ban.sock", ConfigPath: "/etc/fail2ban/",
		Enabled: true, EnabledSet: true,
	}})
	if out[0].ConfigPath != "/etc/fail2ban" {
		t.Errorf("trailing-slash config path not cleaned: %q", out[0].ConfigPath)
	}
	if !out[0].Enabled {
		t.Error("server with cleanable config path must stay enabled")
	}
}

func TestNormalizeServersDisablesInvalid(t *testing.T) {
	out := normalizeTestServers(t, []Fail2banServer{
		{ID: "s1", Name: "Bad key", Type: "ssh", Host: "10.0.0.1", SSHUser: "root",
			SSHKeyPath: "~/.ssh/id_rsa", Enabled: true, EnabledSet: true},
		{ID: "s2", Name: "Bad agent", Type: "agent", AgentURL: "ftp://10.0.0.5",
			Enabled: true, EnabledSet: true},
		{ID: "s3", Name: "Good agent", Type: "agent", AgentURL: "10.0.0.6",
			Enabled: true, EnabledSet: true},
	})
	if out[0].Enabled {
		t.Error("server with relative sshKeyPath must be disabled")
	}
	if out[0].DisabledReason == "" {
		t.Error("auto-disabled server must carry a disabledReason")
	}
	if out[1].Enabled {
		t.Error("agent server with non-http agentUrl must be disabled")
	}
	if out[1].DisabledReason == "" {
		t.Error("auto-disabled agent server must carry a disabledReason")
	}
	if !out[2].Enabled {
		t.Error("agent server with valid agentUrl must stay enabled")
	}
	if out[2].DisabledReason != "" {
		t.Errorf("enabled server must have empty disabledReason, got %q", out[2].DisabledReason)
	}
	if !strings.HasPrefix(out[2].AgentURL, "http://") {
		t.Errorf("agentUrl not normalized: %q", out[2].AgentURL)
	}
}

func TestNormalizeServersKeepsManualDisableReasonless(t *testing.T) {
	out := normalizeTestServers(t, []Fail2banServer{{
		ID: "m1", Name: "Manually off", Type: "ssh", Host: "10.0.0.1", SSHUser: "root",
		Enabled: false, EnabledSet: true, DisabledReason: "stale imported value",
	}})
	if out[0].Enabled {
		t.Error("manually disabled server must stay disabled")
	}
	if out[0].DisabledReason != "" {
		t.Errorf("manually disabled server must have empty disabledReason, got %q", out[0].DisabledReason)
	}
}
