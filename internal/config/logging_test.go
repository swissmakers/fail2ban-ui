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

package config

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"
)

func TestLogsRedactCurrentAndRotatedSecrets(t *testing.T) {
	settingsLock.Lock()
	old := currentSettings
	currentSettings.CallbackSecret = "dummy-old-callback-secret"
	currentSettings.SMTP.Password = "dummy-smtp-password"
	refreshLogSecretsLocked()
	currentSettings.CallbackSecret = "dummy-new-callback-secret"
	currentSettings.SMTP.Password = "dummy-smtp"
	refreshLogSecretsLocked()
	refreshLogSecretsLocked()
	settingsLock.Unlock()
	t.Cleanup(func() {
		settingsLock.Lock()
		currentSettings = old
		refreshLogSecretsLocked()
		settingsLock.Unlock()
		setDebugFlag(old.Debug)
	})
	var out bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(prev)
	setDebugFlag(true)
	DebugLog("values: %s %s %s", "dummy-old-callback-secret", "dummy-new-callback-secret", "dummy-smtp-password")
	w := redactingLogWriter{&out}
	_, err := w.Write([]byte(`X-Callback-Secret: an-unknown-old-secret`))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"dummy-old-callback-secret", "dummy-new-callback-secret", "dummy-smtp-password", "an-unknown-old-secret"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("secret escaped log redaction: %s", secret)
		}
	}
	if got := RedactLog("dummy-smtp-password"); got != "[REDACTED]" {
		t.Fatalf("partial secret exposed after repeated refresh: %q", got)
	}
}

func withLogSecrets(t *testing.T, mutate func(*AppSettings)) {
	t.Helper()
	settingsLock.Lock()
	old := currentSettings
	logSecrets.Store(nil)
	mutate(&currentSettings)
	refreshLogSecretsLocked()
	settingsLock.Unlock()
	t.Cleanup(func() {
		settingsLock.Lock()
		currentSettings = old
		logSecrets.Store(nil)
		refreshLogSecretsLocked()
		settingsLock.Unlock()
	})
}

func TestRedactionIgnoresShortValues(t *testing.T) {
	withLogSecrets(t, func(s *AppSettings) {
		s.Webhook.Headers = map[string]string{"X-Retry": "1", "Content-Type": "json"}
	})
	line := "ban 10.0.0.1 in jail sshd, payload json"
	if got := RedactLog(line); got != line {
		t.Fatalf("short non-secret values shredded the log line: %q", got)
	}
}

func TestRedactionCoversWebhookAndCredentialedURLs(t *testing.T) {
	withLogSecrets(t, func(s *AppSettings) {
		s.Webhook.URL = "https://hooks.slack.com/services/T000/B000/secrettoken123"
		s.Elasticsearch.URL = "https://elastic:hunter2pass@es.example.com:9200"
	})
	for _, leaked := range []string{
		`webhook request failed: Post "https://hooks.slack.com/services/T000/B000/secrettoken123": dial tcp: timeout`,
		`elasticsearch request failed: https://elastic:hunter2pass@es.example.com:9200`,
	} {
		if got := RedactLog(leaked); strings.Contains(got, "secrettoken123") || strings.Contains(got, "hunter2pass") {
			t.Errorf("URL secret escaped redaction: %q", got)
		}
	}
}

func TestRedactionKeepsAllCurrentSecretsAtScale(t *testing.T) {
	withLogSecrets(t, func(s *AppSettings) {
		s.Servers = nil
		for i := 0; i < 400; i++ {
			// Fixed width, so no secret is a prefix of another and masks a dropped one.
			s.Servers = append(s.Servers, Fail2banServer{AgentSecret: fmt.Sprintf("agent-secret-%04d", i)})
		}
	})
	last := currentSettings.Servers[len(currentSettings.Servers)-1].AgentSecret
	if got := RedactLog("token=" + last); got != "token=[REDACTED]" {
		t.Fatalf("a current agent secret was dropped by the redaction cap: %q", got)
	}
}
