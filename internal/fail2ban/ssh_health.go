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
	"fmt"
	"strings"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// Pings fail2ban, then checks that the remote host can reach this UI's callback endpoint.
func (sc *SSHConnector) ProbeHealth(ctx context.Context) ServerHealth {
	if err := pingFail2ban(ctx, sc.runFail2banCommand, "remote fail2ban"); err != nil {
		return ServerHealth{Error: err.Error()}
	}
	h := ServerHealth{Fail2banOK: true}
	err := sc.checkCallback(ctx)
	ok := err == nil
	h.CallbackOK = &ok
	if err != nil {
		h.Error = err.Error()
	}
	return h
}

// Probe from the remote host, through the reverse listener on tunnel servers, to the actual UI.
// Feed the secret on stdin so it cannot appear in SSH arguments or debug logs.
func (sc *SSHConnector) probeCallback(ctx context.Context) (string, error) {
	if err := sc.acquireSession(ctx); err != nil {
		return "", err
	}
	defer sc.releaseSession()
	target := sc.actionCallbackURL() + "/api/healthcheck/callback"
	insecure := ""
	if strings.HasPrefix(strings.ToLower(target), "https://") && shared.CallbackInsecureTLS() {
		insecure = "--insecure "
	}
	command := "curl --silent --show-error " + insecure + "--connect-timeout 3 --max-time 5 --output /dev/null --write-out '%{http_code}' --header @- " + shellQuote(target)
	header := "X-Callback-Secret: " + mustProvider().CallbackSecret() + "\n"
	out, _, err := sc.execSSH(ctx, sc.buildSSHArgs([]string{command}), strings.NewReader(header))
	code := strings.TrimSpace(out)
	if err != nil {
		return code, fmt.Errorf("callback probe failed: %w", err)
	}
	if code != "200" {
		return code, fmt.Errorf("callback health endpoint returned HTTP %s", code)
	}
	return code, nil
}
