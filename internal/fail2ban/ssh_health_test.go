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
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLiveMasterDoesNotHideCallbackFailure(t *testing.T) {
	sc := regressionConnector(t)
	sc.tunnelPort, sc.forwardPort = 9443, 8080
	withFakeSSH(t, `case "$*" in *"-O check"*) exit 0 ;; esac
cat >/dev/null
printf '404'
`)
	if err := sc.checkCallback(context.Background()); err == nil {
		t.Fatal("broken callback reported healthy")
	}
	withFakeSSH(t, `case "$*" in *"-O check"*) exit 0 ;; esac
cat >/dev/null
printf '200'
`)
	if err := sc.checkCallback(context.Background()); err != nil {
		t.Fatalf("recovery not detected: %v", err)
	}
}

func TestBrokenForwardIsRebuilt(t *testing.T) {
	sc := regressionConnector(t)
	sc.tunnelPort, sc.forwardPort = 9443, 8080
	marker := filepath.Join(t.TempDir(), "recreated")
	t.Setenv("F2B_HEALTH_MARKER", marker)
	withFakeSSH(t, `case "$*" in
 *"-O check"*) if [ -f "$F2B_HEALTH_MARKER.closed" ]; then exit 1; fi; exit 0 ;;
 *"-O exit"*) touch "$F2B_HEALTH_MARKER.closed"; exit 0 ;;
 *"-R "*) rm -f "$F2B_HEALTH_MARKER.closed"; touch "$F2B_HEALTH_MARKER"; exit 0 ;;
esac
cat >/dev/null
if [ -f "$F2B_HEALTH_MARKER" ]; then printf '200'; else printf '000'; exit 7; fi
`)
	err := sc.checkCallback(context.Background())
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatal("dead forward was not rebuilt")
	}
	if err != nil {
		t.Fatalf("callback did not recover: %v", err)
	}
}

func TestProbeDoesNotPutSecretInArguments(t *testing.T) {
	SetProvider(testProvider{})
	defer SetProvider(noopProvider{})
	sc := regressionConnector(t)
	sc.tunnelPort = 9443
	record := filepath.Join(t.TempDir(), "header")
	t.Setenv("F2B_HEALTH_HEADER", record)
	withFakeSSH(t, `case "$*" in *"X-Callback-Secret:"*) exit 1 ;; esac
cat > "$F2B_HEALTH_HEADER"
printf '200'
`)
	if _, err := sc.probeCallback(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "X-Callback-Secret: "+mustProvider().CallbackSecret()+"\n" {
		t.Fatal("secret not sent through stdin")
	}
}
