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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Replace a complete file only after the staged data has reached disk. Keep
// the previous content in a private backup, without replacing it on a retry.
func writeConfigAtomic(path string, content []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			if resolved, err = os.Readlink(path); err != nil {
				return err
			}
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(filepath.Dir(path), resolved)
			}
		}
		path = resolved
	}
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if mode != 0600 {
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			mode = info.Mode().Perm()
		}
		if bytes.Equal(old, content) {
			return os.Chmod(path, mode)
		}
		if err := replaceFileAtomic(path+".f2bui.bak", old, 0600); err != nil {
			return fmt.Errorf("back up %s: %w", path, err)
		}
	}
	return replaceFileAtomic(path, content, mode)
}

func replaceFileAtomic(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".f2bui-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(content); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

// The rename only survives a crash once the directory entry is flushed as well.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
