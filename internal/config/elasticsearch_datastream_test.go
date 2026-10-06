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

package config

import "testing"

func TestElasticsearchDataStream(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"empty uses default", "", DefaultElasticsearchDataStream},
		{"blank uses default", "  ", DefaultElasticsearchDataStream},
		{"legacy daily-index base migrates", "fail2ban-events", DefaultElasticsearchDataStream},
		{"legacy name with spaces migrates", " fail2ban-events ", DefaultElasticsearchDataStream},
		{"custom stream is kept", "logs-fail2ban_ui.events-prod", "logs-fail2ban_ui.events-prod"},
		{"custom stream is trimmed", " security-fail2ban ", "security-fail2ban"},
		{"legacy-looking prefix is kept", "fail2ban-events-x", "fail2ban-events-x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ElasticsearchDataStream(tt.in); got != tt.want {
				t.Errorf("ElasticsearchDataStream(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSetDefaultsMigratesLegacyElasticsearchIndex(t *testing.T) {
	settingsLock.Lock()
	old := currentSettings
	currentSettings.Elasticsearch.Index = "fail2ban-events"
	setDefaultsLocked()
	got := currentSettings.Elasticsearch.Index
	currentSettings = old
	refreshLogSecretsLocked()
	settingsLock.Unlock()
	setDebugFlag(old.Debug)
	if got != DefaultElasticsearchDataStream {
		t.Errorf("stored legacy index became %q, want %q", got, DefaultElasticsearchDataStream)
	}
}
