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

package web

import (
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// When the frontend saves settings unchanged, it POSTs this back and the save handlers restore the real stored value (see restoreMaskedSecrets).
// This keeps secrets out of GET /api/settings and /api/servers responses.
const secretMaskSentinel = "__f2bui_secret_unchanged__"

func maskSecret(value string) string {
	if value == "" {
		return ""
	}
	return secretMaskSentinel
}

func restoreSecret(incoming, stored string) string {
	if incoming == secretMaskSentinel {
		return stored
	}
	return incoming
}

func maskAppSettingsSecrets(s config.AppSettings) config.AppSettings {
	s.CallbackSecret = maskSecret(s.CallbackSecret)
	s.SMTP.Password = maskSecret(s.SMTP.Password)
	s.ThreatIntel.AlienVaultAPIKey = maskSecret(s.ThreatIntel.AlienVaultAPIKey)
	s.ThreatIntel.AbuseIPDBAPIKey = maskSecret(s.ThreatIntel.AbuseIPDBAPIKey)
	s.Elasticsearch.APIKey = maskSecret(s.Elasticsearch.APIKey)
	s.Elasticsearch.Password = maskSecret(s.Elasticsearch.Password)
	s.AdvancedActions.Mikrotik.Password = maskSecret(s.AdvancedActions.Mikrotik.Password)
	s.AdvancedActions.PfSense.APIToken = maskSecret(s.AdvancedActions.PfSense.APIToken)
	s.AdvancedActions.PfSense.APISecret = maskSecret(s.AdvancedActions.PfSense.APISecret)
	s.AdvancedActions.OPNsense.APIKey = maskSecret(s.AdvancedActions.OPNsense.APIKey)
	s.AdvancedActions.OPNsense.APISecret = maskSecret(s.AdvancedActions.OPNsense.APISecret)

	if len(s.Webhook.Headers) > 0 {
		masked := make(map[string]string, len(s.Webhook.Headers))
		for k, v := range s.Webhook.Headers {
			masked[k] = maskSecret(v)
		}
		s.Webhook.Headers = masked
	}

	if len(s.Servers) > 0 {
		s.Servers = maskServerSecrets(s.Servers)
	}
	return s
}

func restoreMaskedSecrets(req *config.AppSettings, stored config.AppSettings) {
	req.CallbackSecret = restoreSecret(req.CallbackSecret, stored.CallbackSecret)
	req.SMTP.Password = restoreSecret(req.SMTP.Password, stored.SMTP.Password)
	req.ThreatIntel.AlienVaultAPIKey = restoreSecret(req.ThreatIntel.AlienVaultAPIKey, stored.ThreatIntel.AlienVaultAPIKey)
	req.ThreatIntel.AbuseIPDBAPIKey = restoreSecret(req.ThreatIntel.AbuseIPDBAPIKey, stored.ThreatIntel.AbuseIPDBAPIKey)
	req.Elasticsearch.APIKey = restoreSecret(req.Elasticsearch.APIKey, stored.Elasticsearch.APIKey)
	req.Elasticsearch.Password = restoreSecret(req.Elasticsearch.Password, stored.Elasticsearch.Password)
	req.AdvancedActions.Mikrotik.Password = restoreSecret(req.AdvancedActions.Mikrotik.Password, stored.AdvancedActions.Mikrotik.Password)
	req.AdvancedActions.PfSense.APIToken = restoreSecret(req.AdvancedActions.PfSense.APIToken, stored.AdvancedActions.PfSense.APIToken)
	req.AdvancedActions.PfSense.APISecret = restoreSecret(req.AdvancedActions.PfSense.APISecret, stored.AdvancedActions.PfSense.APISecret)
	req.AdvancedActions.OPNsense.APIKey = restoreSecret(req.AdvancedActions.OPNsense.APIKey, stored.AdvancedActions.OPNsense.APIKey)
	req.AdvancedActions.OPNsense.APISecret = restoreSecret(req.AdvancedActions.OPNsense.APISecret, stored.AdvancedActions.OPNsense.APISecret)

	for k, v := range req.Webhook.Headers {
		if v == secretMaskSentinel {
			req.Webhook.Headers[k] = stored.Webhook.Headers[k]
		}
	}

	if len(req.Servers) > 0 {
		storedByID := make(map[string]string, len(stored.Servers))
		for _, srv := range stored.Servers {
			storedByID[srv.ID] = srv.AgentSecret
		}
		for i := range req.Servers {
			req.Servers[i].AgentSecret = restoreSecret(req.Servers[i].AgentSecret, storedByID[req.Servers[i].ID])
		}
	}
}

func maskServer(server shared.Fail2banServer) shared.Fail2banServer {
	server.AgentSecret = maskSecret(server.AgentSecret)
	return server
}

func maskServerSecrets(servers []shared.Fail2banServer) []shared.Fail2banServer {
	out := make([]shared.Fail2banServer, len(servers))
	copy(out, servers)
	for i := range out {
		out[i].AgentSecret = maskSecret(out[i].AgentSecret)
	}
	return out
}

// stripServerConnectionDetails removes connection information non-admin users
// have no need to see (support users only ban/unban through the UI).
func stripServerConnectionDetails(servers []shared.Fail2banServer) []shared.Fail2banServer {
	for i := range servers {
		servers[i].Host = ""
		servers[i].Port = 0
		servers[i].SocketPath = ""
		servers[i].ConfigPath = ""
		servers[i].SSHUser = ""
		servers[i].SSHKeyPath = ""
		servers[i].AgentURL = ""
		servers[i].AgentSecret = ""
	}
	return servers
}
