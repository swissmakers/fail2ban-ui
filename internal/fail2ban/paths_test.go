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

package fail2ban

import (
	"path/filepath"
	"testing"
)

func TestNormalizeConfigPath(t *testing.T) {
	t.Parallel()
	if got := NormalizeConfigPath(""); got != DefaultConfigRoot {
		t.Fatalf("empty: got %q want %q", got, DefaultConfigRoot)
	}
	if got := NormalizeConfigPath("  "); got != DefaultConfigRoot {
		t.Fatalf("whitespace: got %q want %q", got, DefaultConfigRoot)
	}
	if got := NormalizeConfigPath("/opt/fail2ban"); got != "/opt/fail2ban" {
		t.Fatalf("clean path: got %q", got)
	}
	if got := NormalizeConfigPath("/etc/fail2ban/../fail2ban/"); got != "/etc/fail2ban" {
		t.Fatalf("clean: got %q", got)
	}
}

func TestPathLayout(t *testing.T) {
	t.Parallel()
	root := "/tmp/f2b-test"
	wantJail := filepath.Join(root, "jail.d")
	if got := JailDir(root); got != wantJail {
		t.Fatalf("JailDir: got %q want %q", got, wantJail)
	}
	wantFilter := filepath.Join(root, "filter.d")
	if got := FilterDir(root); got != wantFilter {
		t.Fatalf("FilterDir: got %q want %q", got, wantFilter)
	}
	wantLocal := filepath.Join(root, "jail.local")
	if got := JailLocal(root); got != wantLocal {
		t.Fatalf("JailLocal: got %q want %q", got, wantLocal)
	}
	wantAction := filepath.Join(root, "action.d", "ui-custom-action.conf")
	if got := CustomActionFile(root); got != wantAction {
		t.Fatalf("CustomActionFile: got %q want %q", got, wantAction)
	}
}
