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
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// The logpath is interpolated into a remote shell script, so the SSH connector
// must apply the same sanitizeLogpath gate as the local implementation.
func TestSSHTestLogpathRejectsUnsafePaths(t *testing.T) {
	sc := &SSHConnector{server: shared.Fail2banServer{Host: "10.0.0.1", SSHUser: "f2b"}}
	unsafe := []string{
		"/var/log/x; rm -rf /",
		"/var/log/`id`.log",
		"/var/log/$(reboot).log",
		"relative/app.log",
		"/var/log/../../etc/passwd",
		"/var/log/app\x00.log",
	}
	for _, p := range unsafe {
		if _, err := sc.TestLogpath(context.Background(), p); err == nil {
			t.Errorf("TestLogpath(%q) should be rejected", p)
		}
	}
	matches, err := sc.TestLogpath(context.Background(), "   ")
	if err != nil || len(matches) != 0 {
		t.Errorf("blank logpath should return no matches without error, got %v, %v", matches, err)
	}
}

// Execute the exact SSH probe in a local shell, against real permissions and
// paths, so marker-only mocks cannot hide false permission/missing-file results.
func TestSSHLogpathProbeFilesystem(t *testing.T) {
	withFakeSSH(t, `for arg do command="$arg"; done
exec sh -c "$command"
`)
	dir := t.TempDir()
	logFile := filepath.Join(dir, "httpd-error_log")
	if err := os.WriteFile(logFile, []byte("test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sc := testSSHConnector()
	for _, pattern := range []string{logFile, filepath.Join(dir, "*error_log"), dir} {
		files, err := sc.TestLogpath(context.Background(), pattern)
		if err != nil || !reflect.DeepEqual(files, []string{logFile}) {
			t.Fatalf("readable %s: %v, %v", pattern, files, err)
		}
	}
	files, err := sc.TestLogpath(context.Background(), filepath.Join(dir, "missing*"))
	if err != nil || len(files) != 0 {
		t.Fatalf("missing path: %v, %v", files, err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission bits")
	}
	if err := os.Chmod(dir, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	_, err = sc.TestLogpath(context.Background(), filepath.Join(dir, "*error_log"))
	if !errors.Is(err, ErrLogpathInaccessible) {
		t.Fatalf("restricted directory: %v", err)
	}
}
