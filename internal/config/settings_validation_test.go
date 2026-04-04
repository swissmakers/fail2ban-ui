// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the PolyForm Shield License 1.0.0.
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://polyformproject.org/licenses/shield/1.0.0/
//
//     or in the LICENSE file in this repository.
//
// Required Notice: Copyright Swissmakers GmbH (https://swissmakers.ch)

package config

import "testing"

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
