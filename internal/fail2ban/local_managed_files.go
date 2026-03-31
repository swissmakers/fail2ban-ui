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
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Writes jail.local when missing or already UI-managed.
func EnsureManagedJailLocal(configPath string, content []byte) error {
	debugf("Running EnsureManagedJailLocal()")
	jailPath := JailLocal(configPath)
	rootDir := NormalizeConfigPath(configPath)
	if _, err := os.Stat(filepath.Dir(jailPath)); os.IsNotExist(err) {
		return fmt.Errorf("fail2ban configuration directory does not exist at %s — install fail2ban or set the correct configuration path for this server", rootDir)
	}
	var existingContent string
	fileExists := false
	if raw, err := os.ReadFile(jailPath); err == nil {
		existingContent = string(raw)
		fileExists = strings.TrimSpace(existingContent) != ""
	}
	if fileExists && !strings.Contains(existingContent, "ui-custom-action") {
		debugf("jail.local file exists but is not managed by Fail2ban-UI - skipping overwrite")
		return nil
	}
	if err := os.WriteFile(jailPath, content, 0644); err != nil {
		return fmt.Errorf("failed to write jail.local: %v", err)
	}
	debugf("Created/updated jail.local with proper content.")
	return nil
}

// Writes ui-custom-action.conf next to the given config root.
func WriteLocalActionFile(configPath, callbackURL, serverID string) error {
	debugf("Running WriteLocalActionFile()")
	p := mustProvider()
	actionPath := CustomActionFile(configPath)
	actionDir := ActionDir(configPath)
	if _, err := os.Stat(actionDir); os.IsNotExist(err) {
		return fmt.Errorf("fail2ban action.d directory does not exist at %s — install fail2ban or set the correct configuration path for this server", actionDir)
	}
	secret := p.CallbackSecret()
	cfg := p.BuildFail2banActionConfig(callbackURL, serverID, secret)
	if err := os.WriteFile(actionPath, []byte(cfg), 0644); err != nil {
		return fmt.Errorf("failed to write action file: %w", err)
	}
	debugf("Custom-action file successfully written to %s\n", actionPath)
	return nil
}

// Ensures jail.local and the UI action file for a local tree.
func EnsureLocalConnectorArtifacts(callbackURL, serverID, configPath string) error {
	debugf("ensureFail2banActionFiles called")
	jailPath := JailLocal(configPath)
	if _, err := os.Stat(filepath.Dir(jailPath)); os.IsNotExist(err) {
		return nil
	}
	p := mustProvider()
	content := []byte(p.BuildJailLocalContent())
	if err := EnsureManagedJailLocal(configPath, content); err != nil {
		return err
	}
	return WriteLocalActionFile(configPath, callbackURL, serverID)
}
