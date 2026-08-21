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
	"strings"
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

const testNoiceString = `echo "2026-07-26 18:20:56,221 fail2ban.configreader   [18]: ERROR   Found no accessible config files for 'fail2ban' under /etc/fail2ban" >&2
echo "2026-07-26 18:20:56,221 fail2ban.configreader   [18]: ERROR   No section: 'Definition'" >&2
`

func testLocalConnector(t *testing.T) *LocalConnector {
	t.Helper()
	return NewLocalConnector(shared.Fail2banServer{
		Name:       "local-test",
		Type:       "local",
		ConfigPath: t.TempDir(),
	})
}

func TestLocalGetJailSummarySurvivesStderrNoise(t *testing.T) {
	withFakeBinary(t, "fail2ban-client", testNoiceString+`echo "[{'sshd': ['1.2.3.4', '5.6.7.8']}, {'nginx': []}]"
exit 0
`)
	lc := testLocalConnector(t)

	summary, err := lc.GetJailSummary(context.Background())
	if err != nil {
		t.Fatalf("stderr noise must not break the summary (issue #186): %v", err)
	}
	if len(summary.Jails) != 2 {
		t.Fatalf("expected 2 jails, got %+v", summary.Jails)
	}
	byName := map[string]JailInfo{}
	for _, j := range summary.Jails {
		byName[j.JailName] = j
	}
	if got := byName["sshd"]; got.TotalBanned != 2 || got.BannedIPs[1] != "5.6.7.8" {
		t.Fatalf("sshd wrong: %+v", got)
	}
	if got := byName["nginx"]; got.TotalBanned != 0 {
		t.Fatalf("nginx wrong: %+v", got)
	}
}

func TestLocalGetBannedIPsSurvivesStderrNoise(t *testing.T) {
	withFakeBinary(t, "fail2ban-client", testNoiceString+`echo "1.2.3.4 5.6.7.8"
exit 0
`)
	lc := testLocalConnector(t)

	ips, err := lc.GetBannedIPs(context.Background(), "sshd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 2 || ips[0] != "1.2.3.4" || ips[1] != "5.6.7.8" {
		t.Fatalf("stderr noise leaked into the IP list: %v", ips)
	}
}

func TestLocalCommandFailureKeepsBothStreams(t *testing.T) {
	withFakeBinary(t, "fail2ban-client", `echo "partial stdout"
echo "stderr detail" >&2
exit 255
`)
	lc := testLocalConnector(t)

	_, err := lc.GetJailSummary(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "partial stdout") || !strings.Contains(err.Error(), "stderr detail") {
		t.Fatalf("failure diagnostics must carry both streams, got: %v", err)
	}
}

func TestLocalReloadIncompleteMountHint(t *testing.T) {
	withFakeBinary(t, "fail2ban-client", `echo "2026-07-26 18:20:56,221 fail2ban.configreader   [18]: ERROR   Found no accessible config files for 'fail2ban' under /etc/fail2ban" >&2
exit 255
`)
	lc := testLocalConnector(t)

	err := lc.Reload(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "full configuration tree") {
		t.Fatalf("expected the incomplete-mount hint, got: %v", err)
	}
	output, ok := CommandOutput(err)
	if !ok {
		t.Fatalf("reload errors must carry a *CommandError for the recovery ladder, got: %v", err)
	}
	if !strings.Contains(output, "Found no accessible config files") {
		t.Fatalf("captured command output is missing the daemon message, got: %q", output)
	}
}

func TestLocalCommandErrorsAreNotLabelledSSH(t *testing.T) {
	withFakeBinary(t, "fail2ban-client", `echo "boom" >&2
exit 1
`)
	lc := testLocalConnector(t)

	_, err := lc.GetBannedIPs(context.Background(), "sshd")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "ssh command failed") {
		t.Fatalf("local failures must not be reported as ssh failures, got: %v", err)
	}
	if !strings.Contains(err.Error(), "fail2ban-client command failed") {
		t.Fatalf("expected the fail2ban-client label, got: %v", err)
	}
}

func TestLocalReloadPlainFailureHasNoMountHint(t *testing.T) {
	withFakeBinary(t, "fail2ban-client", `echo "ERROR   NOK: something else" >&2
exit 255
`)
	lc := testLocalConnector(t)

	err := lc.Reload(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "full configuration tree") {
		t.Fatalf("mount hint must only fire for the config-visibility case, got: %v", err)
	}
}
