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

package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func initOnLegacyDB(t *testing.T, legacyDDL string) string {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "fail2ban-ui-legacy.db")
	legacy, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	if _, err := legacy.Exec(legacyDDL); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	if db != nil {
		_ = db.Close()
	}
	db = nil
	initOnce = sync.Once{}
	initErr = nil
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
		db = nil
		initOnce = sync.Once{}
		initErr = nil
	})

	if err := Init(dbPath); err != nil {
		t.Fatalf("Init on legacy database: %v", err)
	}
	return dbPath
}

// original app_settings table, before any of the later columns existed
const legacyAppSettingsDDL = `
CREATE TABLE app_settings (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	language TEXT,
	port INTEGER,
	debug INTEGER,
	restart_needed INTEGER,
	callback_url TEXT,
	alert_countries TEXT,
	smtp_host TEXT,
	smtp_port INTEGER,
	smtp_username TEXT,
	smtp_password TEXT,
	smtp_from TEXT,
	smtp_use_tls INTEGER,
	bantime_increment INTEGER,
	ignore_ip TEXT,
	bantime TEXT,
	findtime TEXT,
	maxretry INTEGER,
	destemail TEXT
);
INSERT INTO app_settings (id, language, port, bantime) VALUES (1, 'de', 8080, '10m');`

func TestEnsureSchemaUpgradesLegacyAppSettings(t *testing.T) {
	initOnLegacyDB(t, legacyAppSettingsDDL)

	ctx := context.Background()
	rec := AppSettingsRecord{
		Language:             "fr",
		Port:                 9090,
		EmailAlertsForBans:   true,
		EmailAlertsForUnbans: true,
		DefaultJailEnable:    true,
		Banaction:            "iptables-multiport",
		BanactionAllports:    "iptables-allports",
		AdvancedActionsJSON:  `{"integration":"mikrotik"}`,
		GeoIPProvider:        "builtin",
		GeoIPDatabasePath:    "/usr/share/GeoIP/City.mmdb",
		MaxLogLines:          42,
		CallbackSecret:       "s3cr3t",
		AlertProvider:        "webhook",
		ThreatIntelJSON:      `{"provider":"none"}`,
	}
	if err := SaveAppSettings(ctx, rec); err != nil {
		t.Fatalf("SaveAppSettings on upgraded legacy database: %v", err)
	}

	got, found, err := GetAppSettings(ctx)
	if err != nil {
		t.Fatalf("GetAppSettings: %v", err)
	}
	if !found {
		t.Fatal("settings row missing after save")
	}
	if got.Language != "fr" || got.Port != 9090 {
		t.Errorf("base columns not round-tripped: %+v", got)
	}
	if !got.EmailAlertsForBans || !got.EmailAlertsForUnbans {
		t.Errorf("email alert flags not round-tripped: %+v", got)
	}
	if got.CallbackSecret != "s3cr3t" || got.Banaction != "iptables-multiport" || got.MaxLogLines != 42 {
		t.Errorf("previously unmigrated columns not round-tripped: %+v", got)
	}
	if got.AlertProvider != "webhook" || got.GeoIPProvider != "builtin" {
		t.Errorf("later columns not round-tripped: %+v", got)
	}
}

// table that exists but predates every optional column must be brought fully up to date, for every table in the schema
func TestEnsureSchemaAddsEveryDefinedColumn(t *testing.T) {
	const minimalDDL = `
CREATE TABLE app_settings (id INTEGER PRIMARY KEY CHECK (id = 1));
CREATE TABLE servers (id TEXT PRIMARY KEY);
CREATE TABLE ban_events (id INTEGER PRIMARY KEY AUTOINCREMENT);
CREATE TABLE permanent_blocks (id INTEGER PRIMARY KEY AUTOINCREMENT);`

	initOnLegacyDB(t, minimalDDL)

	for _, table := range schemaTables {
		existing, err := tableColumns(context.Background(), table.name)
		if err != nil {
			t.Fatalf("inspect %s: %v", table.name, err)
		}
		for _, c := range table.columns {
			if !existing[c.name] {
				t.Errorf("column %s.%s was not added to the existing table", table.name, c.name)
			}
		}
	}
}

func TestSchemaMatchesExpectedColumns(t *testing.T) {
	initTestStorage(t)

	expected := map[string][]string{
		"app_settings": {
			"id", "language", "port", "debug", "restart_needed", "callback_url", "callback_secret",
			"alert_countries", "email_alerts_for_bans", "email_alerts_for_unbans", "smtp_host", "smtp_port",
			"smtp_username", "smtp_password", "smtp_from", "smtp_use_tls", "bantime_increment",
			"default_jail_enable", "ignore_ip", "bantime", "findtime", "maxretry", "destemail", "banaction",
			"banaction_allports", "advanced_actions", "geoip_provider", "geoip_database_path", "max_log_lines",
			"event_retention_days", "console_output", "smtp_insecure_skip_verify", "smtp_auth_method", "chain",
			"bantime_rndtime", "bantime_maxtime", "bantime_factor", "bantime_overalljails", "alert_provider",
			"webhook", "elasticsearch", "threat_intel",
		},
		"servers": {
			"id", "name", "type", "host", "port", "socket_path", "config_path", "ssh_user", "ssh_key_path",
			"agent_url", "agent_secret", "hostname", "tags", "is_default", "enabled", "reverse_tunnel",
			"tunnel_port", "needs_restart", "created_at", "updated_at",
		},
		"ban_events": {
			"id", "server_id", "server_name", "jail", "ip", "country", "hostname", "failures", "whois",
			"logs", "event_type", "occurred_at", "created_at",
		},
		"permanent_blocks": {
			"id", "ip", "integration", "status", "details", "message", "server_id", "created_at", "updated_at",
		},
	}

	for table, want := range expected {
		got, err := tableColumns(context.Background(), table)
		if err != nil {
			t.Fatalf("inspect %s: %v", table, err)
		}
		for _, name := range want {
			if !got[name] {
				t.Errorf("fresh schema for %s is missing column %s", table, name)
			}
		}
		if len(got) != len(want) {
			t.Errorf("%s has %d columns, want %d (an added column must also be listed here)", table, len(got), len(want))
		}
	}
}

// Running Init twice must not attempt any further schema changes
func TestEnsureSchemaIsIdempotent(t *testing.T) {
	initTestStorage(t)

	ctx := context.Background()
	before, err := tableColumns(ctx, "app_settings")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := ensureSchema(ctx); err != nil {
			t.Fatalf("repeat ensureSchema: %v", err)
		}
	}
	after, err := tableColumns(ctx, "app_settings")
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Errorf("column count changed on repeat run: %d -> %d", len(before), len(after))
	}
}

func TestEnsureSchemaRejectsUnrepairableTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "broken.db")
	broken, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken.Exec(`CREATE TABLE app_settings (language TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := broken.Close(); err != nil {
		t.Fatal(err)
	}

	if db != nil {
		_ = db.Close()
	}
	db = nil
	initOnce = sync.Once{}
	initErr = nil
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
		db = nil
		initOnce = sync.Once{}
		initErr = nil
	})

	err = Init(dbPath)
	if err == nil {
		t.Fatal("Init must fail when a table is missing its primary key")
	}
	if !strings.Contains(err.Error(), "app_settings") || !strings.Contains(err.Error(), "id") {
		t.Errorf("error must name the table and column, got: %v", err)
	}
}
