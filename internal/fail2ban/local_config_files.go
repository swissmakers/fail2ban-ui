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

// Shared .local/.conf handling for jail.d and filter.d on the local
// filesystem. Jails and filters follow the same rules, so they share one
// implementation parameterised by kind, mirroring the (dir, name, kind)
// helpers the ssh connector already uses.

package fail2ban

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type configKind struct {
	noun string
	dir  func(configPath string) string
	seed func(name string) string
}

var (
	jailKind = configKind{
		noun: "jail",
		dir:  JailDir,
		seed: func(name string) string { return fmt.Sprintf("[%s]\n", name) },
	}
	filterKind = configKind{
		noun: "filter",
		dir:  FilterDir,
		seed: func(string) string { return "" },
	}
)

// Resolves the .local and .conf paths for a named config file, rejecting any name that would escape directory
func (k configKind) paths(name, configPath string) (dir, localPath, confPath string, err error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", "", fmt.Errorf("%s name cannot be empty", k.noun)
	}
	dir = k.dir(configPath)
	if localPath, err = resolveWithinDir(dir, name, ".local"); err != nil {
		return "", "", "", err
	}
	if confPath, err = resolveWithinDir(dir, name, ".conf"); err != nil {
		return "", "", "", err
	}
	return dir, localPath, confPath, nil
}

// Makes sure .local file exists -> kept as-is when present, otherwise seed from the .conf
func ensureLocalConfigFile(k configKind, name, configPath string) error {
	dir, localPath, confPath, err := k.paths(name, configPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(localPath); err == nil {
		debugf("%s .local file already exists: %s", k.noun, localPath)
		return nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create %s directory: %w", dir, err)
	}

	if _, err := os.Stat(confPath); err == nil {
		debugf("Copying %s config from .conf to .local: %s -> %s", k.noun, confPath, localPath)
		content, err := os.ReadFile(confPath)
		if err != nil {
			return fmt.Errorf("failed to read %s .conf file %s: %w", k.noun, confPath, err)
		}
		if err := os.WriteFile(localPath, content, 0644); err != nil {
			return fmt.Errorf("failed to write %s .local file %s: %w", k.noun, localPath, err)
		}
		debugf("Successfully copied %s config to .local file", k.noun)
		return nil
	}

	debugf("Neither .local nor .conf exists for %s %s, creating .local file", k.noun, name)
	if err := os.WriteFile(localPath, []byte(k.seed(strings.TrimSpace(name))), 0644); err != nil {
		return fmt.Errorf("failed to create %s .local file %s: %w", k.noun, localPath, err)
	}
	debugf("Successfully created %s .local file: %s", k.noun, localPath)
	return nil
}

// Reads config from .local first then .conf
func readLocalConfigWithFallback(k configKind, name, configPath string) (content, path string, found bool, err error) {
	_, localPath, confPath, err := k.paths(name, configPath)
	if err != nil {
		return "", "", false, err
	}
	if data, err := os.ReadFile(localPath); err == nil {
		debugf("Reading %s config from .local: %s", k.noun, localPath)
		return string(data), localPath, true, nil
	}
	if data, err := os.ReadFile(confPath); err == nil {
		debugf("Reading %s config from .conf: %s", k.noun, confPath)
		return string(data), confPath, true, nil
	}
	return "", localPath, false, nil
}

// Lists .local and .conf files in a jail.d or filter.d directory
func listConfigFiles(k configKind, directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s directory %s: %w", k.noun, directory, err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".conf") {
			files = append(files, filepath.Join(directory, name))
		}
	}
	return files, nil
}

func createLocalConfigFile(k configKind, name, content, sectionHeader, configPath string) error {
	dir, localPath, _, err := k.paths(name, configPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create %s directory: %w", dir, err)
	}
	if sectionHeader != "" && !strings.HasPrefix(strings.TrimSpace(content), sectionHeader) {
		content = sectionHeader + "\n" + content
	}
	if err := os.WriteFile(localPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create %s file %s: %w", k.noun, localPath, err)
	}
	debugf("Created %s file: %s", k.noun, localPath)
	return nil
}

func deleteLocalConfigFiles(k configKind, name, configPath string) error {
	_, localPath, confPath, err := k.paths(name, configPath)
	if err != nil {
		return err
	}
	deleted := 0
	var lastErr error
	for _, path := range []string{localPath, confPath} {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := os.Remove(path); err != nil {
			lastErr = fmt.Errorf("failed to delete %s file %s: %w", k.noun, path, err)
			continue
		}
		deleted++
		debugf("Deleted %s file: %s", k.noun, path)
	}

	if lastErr != nil {
		return lastErr
	}
	if deleted == 0 {
		return fmt.Errorf("%s file %s or %s does not exist", k.noun, localPath, confPath)
	}
	return nil
}
