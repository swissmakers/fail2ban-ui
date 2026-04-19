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

package fail2ban

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ensureWritableDirectory(path, purpose string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s does not exist at %s", purpose, path)
		}
		return fmt.Errorf("failed to access %s at %s: %w", purpose, path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s path is not a directory: %s", purpose, path)
	}
	probe, err := os.CreateTemp(path, ".fail2ban-ui-writecheck-*")
	if err != nil {
		return fmt.Errorf("%s is not writable at %s: %w", purpose, path, err)
	}
	probeName := probe.Name()
	_ = probe.Close()
	_ = os.Remove(probeName)
	return nil
}

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
		rootDir := NormalizeConfigPath(configPath)
		return fmt.Errorf("fail2ban configuration directory does not exist at %s — install fail2ban or set the correct configuration path for this server", rootDir)
	}
	actionDir := ActionDir(configPath)
	if err := ensureWritableDirectory(actionDir, "fail2ban action.d directory"); err != nil {
		return err
	}
	if err := WriteLocalActionFile(configPath, callbackURL, serverID); err != nil {
		return err
	}
	p := mustProvider()
	content := []byte(p.BuildJailLocalContent())
	if err := EnsureManagedJailLocal(configPath, content); err != nil {
		return err
	}
	return nil
}
