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
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLogpathVariablesAtPath_customRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	localPath := filepath.Join(root, "vars.local")
	content := "my_custom_log = /tmp/from-custom-root.log\n"
	if err := os.WriteFile(localPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveLogpathVariables("%(my_custom_log)s", root)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/from-custom-root.log" {
		t.Fatalf("resolved logpath: got %q", got)
	}
}
