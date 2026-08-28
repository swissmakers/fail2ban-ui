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

package fail2ban

import (
	"reflect"
	"strings"
	"testing"
)

// These compile-time assertions cover all supported connectors without
// requiring a running local, SSH, or agent Fail2ban installation.
var (
	_ Connector = (*LocalConnector)(nil)
	_ Connector = (*SSHConnector)(nil)
	_ Connector = (*AgentConnector)(nil)
)

func TestParseIgnoreIPsFromConfig(t *testing.T) {
	content := `[DEFAULT]
ignoreip = 127.0.0.1

[sshd]
enabled = true
ignoreip = 10.0.0.0/8 host.example # comment

[nginx]
ignoreip = 192.0.2.1
`

	got := parseIgnoreIPsFromConfig(content, "sshd")
	want := []string{"10.0.0.0/8", "host.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseIgnoreIPsFromConfig() = %#v, want %#v", got, want)
	}

	if got := parseIgnoreIPsFromConfig(content, "missing"); got != nil {
		t.Fatalf("missing jail result = %#v, want nil", got)
	}
}

func TestSetIgnoreIPsInConfigPreservesOtherSections(t *testing.T) {
	content := `[sshd]
enabled = true
ignoreip = 10.0.0.0/8 # old value

[nginx]
ignoreip = 192.0.2.1
`

	got := setIgnoreIPsInConfig(content, "sshd", []string{"203.0.113.10", "2001:db8::/32"})
	if !strings.Contains(got, "[sshd]\nenabled = true\nignoreip = 203.0.113.10 2001:db8::/32") {
		t.Fatalf("target section was not updated:\n%s", got)
	}
	if !strings.Contains(got, "[nginx]\nignoreip = 192.0.2.1") {
		t.Fatalf("unrelated section was changed:\n%s", got)
	}
}

func TestSetIgnoreIPsInConfigInsertsMissingEntry(t *testing.T) {
	content := "[sshd]\nenabled = true\n"
	got := setIgnoreIPsInConfig(content, "sshd", []string{"203.0.113.10"})
	want := "[sshd]\nignoreip = 203.0.113.10\nenabled = true\n"
	if got != want {
		t.Fatalf("setIgnoreIPsInConfig() = %q, want %q", got, want)
	}
}
