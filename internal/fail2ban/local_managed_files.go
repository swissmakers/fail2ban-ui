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

func EnsureManagedJailLocal(configPath string, content []byte) error {
	debugf("Running EnsureManagedJailLocal()")
	jailPath := JailLocal(configPath)
	rootDir := NormalizeConfigPath(configPath)
	if _, err := os.Stat(filepath.Dir(jailPath)); os.IsNotExist(err) {
		return fmt.Errorf("fail2ban configuration directory does not exist at %s  -  install fail2ban or set the correct configuration path for this server", rootDir)
	}
	var existingContent string
	fileExists := false
	if raw, err := os.ReadFile(jailPath); err == nil {
		existingContent = string(raw)
		fileExists = strings.TrimSpace(existingContent) != ""
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot inspect existing jail.local: %w", err)
	}
	if fileExists && !strings.Contains(existingContent, managedJailLocalMarker) {
		debugf("jail.local file exists but is not managed by Fail2ban-UI - skipping overwrite")
		return nil
	}
	if err := writeConfigAtomic(jailPath, content, 0644); err != nil {
		return fmt.Errorf("failed to write jail.local: %v", err)
	}
	debugf("Created/updated jail.local with proper content.")
	return nil
}

func WriteLocalActionFile(configPath, callbackURL, serverID string) error {
	debugf("Running WriteLocalActionFile()")
	p := mustProvider()
	actionPath := CustomActionFile(configPath)
	if err := ensureWritableDirectory(ActionDir(configPath), "fail2ban action.d directory"); err != nil {
		return err
	}
	cfg, err := p.BuildFail2banActionConfig(callbackURL, serverID, p.CallbackSecret())
	if err != nil {
		return fmt.Errorf("refusing to write the action file: %w", err)
	}
	if err := writeConfigAtomic(actionPath, []byte(cfg), 0600); err != nil {
		return fmt.Errorf("failed to write action file: %w", err)
	}
	debugf("Custom-action file successfully written to %s\n", actionPath)
	return nil
}
