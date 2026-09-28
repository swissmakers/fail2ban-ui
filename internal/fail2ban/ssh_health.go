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
	"log"
	"strings"
	"time"
)

type SSHHealthStatus struct {
	SSHError          string    `json:"sshError,omitempty"`
	CallbackHealthy   bool      `json:"callbackHealthy"`
	CallbackError     string    `json:"callbackError,omitempty"`
	CallbackCheckedAt time.Time `json:"callbackCheckedAt,omitempty"`
}

func (sc *SSHConnector) HealthStatus() SSHHealthStatus {
	sc.healthMu.RLock()
	defer sc.healthMu.RUnlock()
	return sc.health
}

func (sc *SSHConnector) recordSSHResult(err error) {
	sc.healthMu.Lock()
	defer sc.healthMu.Unlock()
	message := ""
	if err != nil {
		message = err.Error()
	}
	if message != "" && sc.health.SSHError != message {
		log.Printf("warning: SSH command on %s failed: %s", sc.server.Name, message)
	}
	sc.health.SSHError = message
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// Probe from the remote host, through the reverse listener, to the actual UI.
// Feed the secret on stdin so it cannot appear in SSH arguments or debug logs.
func (sc *SSHConnector) probeCallback(ctx context.Context) (string, error) {
	if err := sc.acquireSession(ctx); err != nil {
		return "", err
	}
	defer sc.releaseSession()
	command := "curl --silent --show-error --connect-timeout 3 --max-time 5 --output /dev/null --write-out '%{http_code}' --header @- " + shellQuote(sc.actionCallbackURL()+"/api/healthcheck/callback")
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

func (sc *SSHConnector) recordCallbackResult(err error) {
	sc.healthMu.Lock()
	defer sc.healthMu.Unlock()
	message := ""
	if err != nil {
		message = err.Error()
	}
	if message != "" && message != sc.health.CallbackError {
		log.Printf("warning: reverse tunnel callback for %s is unhealthy: %s", sc.server.Name, message)
	} else if err == nil && !sc.health.CallbackHealthy {
		log.Printf("reverse tunnel callback for %s is healthy (port %d)", sc.server.Name, sc.tunnelPort)
	}
	sc.health.CallbackError = message
	sc.health.CallbackHealthy = err == nil
	sc.health.CallbackCheckedAt = time.Now().UTC()
}
