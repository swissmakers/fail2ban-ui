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

package config

import (
	"strings"
	"testing"
)

func TestValidateServerUniqueness(t *testing.T) {
	t.Parallel()
	base := []Fail2banServer{
		{ID: "a", Name: "Primary", Type: "local", SocketPath: "/var/run/fail2ban/fail2ban.sock", ConfigPath: "/etc/fail2ban"},
		{ID: "b", Name: "Remote", Type: "ssh", Host: "10.0.0.1", SSHUser: "root"},
	}

	t.Run("duplicate name", func(t *testing.T) {
		t.Parallel()
		in := Fail2banServer{ID: "new", Name: "Primary", Type: "local", SocketPath: "/run/other.sock", ConfigPath: "/opt/f2b"}
		if err := validateServerUniqueness(in, base); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("duplicate local socket", func(t *testing.T) {
		t.Parallel()
		in := Fail2banServer{ID: "new", Name: "Other", Type: "local", SocketPath: "/var/run/fail2ban/fail2ban.sock", ConfigPath: "/opt/f2b"}
		if err := validateServerUniqueness(in, base); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("duplicate local config path", func(t *testing.T) {
		t.Parallel()
		in := Fail2banServer{ID: "new", Name: "Other", Type: "local", SocketPath: "/run/other.sock", ConfigPath: "/etc/fail2ban"}
		if err := validateServerUniqueness(in, base); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("same id update skipped", func(t *testing.T) {
		t.Parallel()
		in := Fail2banServer{ID: "a", Name: "Primary", Type: "local", SocketPath: "/var/run/fail2ban/fail2ban.sock", ConfigPath: "/etc/fail2ban"}
		if err := validateServerUniqueness(in, base); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ssh ignores local keys", func(t *testing.T) {
		t.Parallel()
		in := Fail2banServer{ID: "c", Name: "Another SSH", Type: "ssh", Host: "10.0.0.2", SSHUser: "root", SocketPath: "/var/run/fail2ban/fail2ban.sock"}
		if err := validateServerUniqueness(in, base); err != nil {
			t.Fatal(err)
		}
	})
}

func TestFail2banActionTemplateRobustness(t *testing.T) {
	t.Parallel()

	// Unresolved fail2ban tags must never appear bare in shell position (they get
	// parsed as redirections/filenames).
	if strings.Contains(fail2banActionTemplate, "tac <logpath>") {
		t.Fatal("logpath must not be used directly in shell syntax; unresolved tags are parsed as redirections")
	}
	if strings.Contains(fail2banActionTemplate, `tac "$logpath"`) {
		t.Fatal(`tac "$logpath" is quoted; globbed/multi-file logpaths will not expand and logs will be empty`)
	}
	for _, want := range []string{
		"logpath='<logpath>'",
		`tac $logpath`,
		"grep -a",
		"LC_ALL=C tr -cd '\\11\\12\\15\\40-\\176'",
		"jq -n",
		"--arg logs",
		"journalctl",
	} {
		if !strings.Contains(fail2banActionTemplate, want) {
			t.Fatalf("action template missing %q", want)
		}
	}

	// The identity fields must be present so a ban is reported even with no logs.
	for _, want := range []string{"--arg ip '<ip>'", "--arg jail '<name>'"} {
		if !strings.Contains(fail2banActionTemplate, want) {
			t.Fatalf("action template missing identity field %q", want)
		}
	}
}

func TestFail2banActionConfigEscapesPercent(t *testing.T) {
	t.Parallel()

	content := BuildFail2banActionConfig("http://127.0.0.1:9999", "srv-test", "secret")
	for i := 0; i < len(content); i++ {
		if content[i] != '%' {
			continue
		}
		if i+1 >= len(content) {
			t.Fatalf("action config ends with a bare '%%' at offset %d", i)
		}
		switch content[i+1] {
		case '%':
			i++
		case '(':

		default:
			t.Fatalf("action config contains bare '%%' followed by %q at offset %d: %q",
				content[i+1], i, content[max(0, i-40):min(len(content), i+40)])
		}
	}
}
