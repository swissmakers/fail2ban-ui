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

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// =========================================================================
//  Database Connection
// =========================================================================

var (
	db          *sql.DB
	initOnce    sync.Once
	initErr     error
	defaultPath = "fail2ban-ui.db"
)

// =========================================================================
//  Conversion Helpers
// =========================================================================

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func intToBool(i int) bool {
	return i != 0
}

func stringFromNull(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

func intFromNull(ni sql.NullInt64) int {
	if ni.Valid {
		return int(ni.Int64)
	}
	return 0
}

const (
	storageTimeFormat       = "2006-01-02T15:04:05.000000000Z"
	legacyStorageTimeFormat = "2006-01-02 15:04:05.999999999"
)

func formatStorageTime(t time.Time) string {
	return t.UTC().Format(storageTimeFormat)
}

// All rows are canonical RFC3339 after migrateLegacyTimestamps, so two layouts suffice
func parseStorageTime(s string) time.Time {
	if t, err := time.Parse(storageTimeFormat, s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// All rows are RFC3339 (legacy formats are rewritten by migrateLegacyTimestamps),
// so a plain string comparison is correct and keeps the occurred_at indexes usable.
func addOccurredAtSinceFilter(query *string, args *[]any, since time.Time) {
	if since.IsZero() {
		return
	}
	*query += " AND occurred_at >= ?"
	*args = append(*args, formatStorageTime(since))
}

// Turns user input into an FTS5 MATCH expression. -> each whitespace token becomes a quoted prefix phrase ("203.0.113"* matches 203.0.113.45), joined with implicit AND
func buildFTSMatch(search string) string {
	var parts []string
	for _, token := range strings.Fields(search) {
		token = strings.ReplaceAll(token, `"`, `""`)
		parts = append(parts, `"`+token+`"*`)
	}
	return strings.Join(parts, " ")
}

func addSearchFilter(query *string, args *[]any, search string) {
	if search == "" {
		return
	}
	if ftsAvailable {
		*query += " AND id IN (SELECT rowid FROM ban_events_fts WHERE ban_events_fts MATCH ?)"
		*args = append(*args, buildFTSMatch(search))
		return
	}
	*query += " AND (ip LIKE ? OR jail LIKE ? OR server_name LIKE ? OR COALESCE(hostname,'') LIKE ? OR COALESCE(country,'') LIKE ?)"
	pattern := "%" + search + "%"
	for i := 0; i < 5; i++ {
		*args = append(*args, pattern)
	}
}

type BanEventFilter struct {
	ServerID string
	Jail     string
	Country  string
	Search   string
	Since    time.Time
	Until    time.Time
	BansOnly bool
}

// Returns a condition fragment (starting with " AND ..." or empty) to append after "WHERE 1=1", plus the positional args
func (f BanEventFilter) buildWhere() (string, []any) {
	conditions := ""
	args := []any{}

	if f.ServerID != "" {
		conditions += " AND server_id = ?"
		args = append(args, f.ServerID)
	}
	if f.Jail != "" {
		conditions += " AND jail = ?"
		args = append(args, f.Jail)
	}
	if f.BansOnly {
		conditions += " AND (event_type = 'ban' OR event_type IS NULL)"
	}
	addOccurredAtSinceFilter(&conditions, &args, f.Since)
	if !f.Until.IsZero() {
		// Same string-comparison reasoning as addOccurredAtSinceFilter.
		conditions += " AND occurred_at < ?"
		args = append(args, formatStorageTime(f.Until))
	}
	addSearchFilter(&conditions, &args, strings.TrimSpace(f.Search))
	if f.Country != "" && f.Country != "all" {
		if f.Country == "__unknown__" {
			conditions += " AND (country IS NULL OR country = '')"
		} else {
			conditions += " AND LOWER(COALESCE(country,'')) = ?"
			args = append(args, strings.ToLower(f.Country))
		}
	}
	return conditions, args
}

// =========================================================================
//  Types
// =========================================================================

type AppSettingsRecord struct {
	Language               string
	Port                   int
	Debug                  bool
	RestartNeeded          bool
	CallbackURL            string
	CallbackSecret         string
	AlertCountriesJSON     string
	EmailAlertsForBans     bool
	EmailAlertsForUnbans   bool
	ConsoleOutput          bool
	SMTPHost               string
	SMTPPort               int
	SMTPUsername           string
	SMTPPassword           string
	SMTPFrom               string
	SMTPUseTLS             bool
	SMTPInsecureSkipVerify bool
	SMTPAuthMethod         string
	BantimeIncrement       bool
	DefaultJailEnable      bool
	IgnoreIP               string
	Bantime                string
	Findtime               string
	MaxRetry               int
	DestEmail              string
	Banaction              string
	BanactionAllports      string
	Chain                  string
	BantimeRndtime         string
	BantimeMaxtime         string
	BantimeFactor          string
	BantimeOveralljails    bool
	AdvancedActionsJSON    string
	GeoIPProvider          string
	GeoIPDatabasePath      string
	MaxLogLines            int
	EventRetentionDays     int
	AlertProvider          string
	WebhookJSON            string
	ElasticsearchJSON      string
	ThreatIntelJSON        string
}

type ServerRecord struct {
	ID                   string
	Name                 string
	Type                 string
	Host                 string
	Port                 int
	SocketPath           string
	ConfigPath           string
	SSHUser              string
	SSHKeyPath           string
	AgentURL             string
	AgentSecret          string
	Hostname             string
	TagsJSON             string
	IsDefault            bool
	Enabled              bool
	ReverseTunnelEnabled bool
	NeedsRestart         bool
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type BanEventRecord struct {
	ID         int64     `json:"id"`
	ServerID   string    `json:"serverId"`
	ServerName string    `json:"serverName"`
	Jail       string    `json:"jail"`
	IP         string    `json:"ip"`
	Country    string    `json:"country"`
	Hostname   string    `json:"hostname"`
	Failures   string    `json:"failures"`
	Whois      string    `json:"whois"`
	Logs       string    `json:"logs"`
	HasWhois   bool      `json:"hasWhois"`
	HasLogs    bool      `json:"hasLogs"`
	EventType  string    `json:"eventType"`
	OccurredAt time.Time `json:"occurredAt"`
	CreatedAt  time.Time `json:"createdAt"`
}

type RecurringIPStat struct {
	IP       string    `json:"ip"`
	Country  string    `json:"country"`
	Count    int64     `json:"count"`
	LastSeen time.Time `json:"lastSeen"`
}

type PermanentBlockRecord struct {
	ID          int64     `json:"id"`
	IP          string    `json:"ip"`
	Integration string    `json:"integration"`
	Status      string    `json:"status"`
	Details     string    `json:"details"`
	Message     string    `json:"message"`
	ServerID    string    `json:"serverId"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// Initialize the database.
func Init(dbPath string) error {
	initOnce.Do(func() {
		if dbPath == "" {
			dbPath = defaultPath
		}
		if err := ensureDirectory(dbPath); err != nil {
			initErr = err
			return
		}

		if err := ensureSSHDirectory(); err != nil {
			log.Printf("Warning: failed to ensure .ssh directory: %v", err)
		}

		var err error
		db, err = sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout=5000", dbPath))
		if err != nil {
			initErr = err
			return
		}

		if err = db.Ping(); err != nil {
			initErr = err
			return
		}

		restrictDatabasePermissions(dbPath)

		if initErr = ensureSchema(context.Background()); initErr != nil {
			return
		}
		if initErr = migrateLegacyTimestamps(context.Background()); initErr != nil {
			return
		}
		ensureBanEventsFTS(context.Background())

		// Refreshes planner statistics so index choices stay sane as the
		// data distribution changes (recommended by the SQLite docs).
		if _, err := db.ExecContext(context.Background(), `PRAGMA optimize`); err != nil {
			log.Printf("Warning: PRAGMA optimize failed: %v", err)
		}
	})
	return initErr
}

// Is set when the ban_events_fts full-text index exists. -> search queries fall back to LIKE when it could not be created
var ftsAvailable bool

// Creates the FTS5 full-text index over the searchable ban_events
func ensureBanEventsFTS(ctx context.Context) {
	const ddl = `
CREATE VIRTUAL TABLE IF NOT EXISTS ban_events_fts USING fts5(
	ip, jail, server_name, hostname, country,
	content='ban_events', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS ban_events_fts_ai AFTER INSERT ON ban_events BEGIN
	INSERT INTO ban_events_fts(rowid, ip, jail, server_name, hostname, country)
	VALUES (new.id, new.ip, new.jail, new.server_name, new.hostname, new.country);
END;
CREATE TRIGGER IF NOT EXISTS ban_events_fts_ad AFTER DELETE ON ban_events BEGIN
	INSERT INTO ban_events_fts(ban_events_fts, rowid, ip, jail, server_name, hostname, country)
	VALUES ('delete', old.id, old.ip, old.jail, old.server_name, old.hostname, old.country);
END;
CREATE TRIGGER IF NOT EXISTS ban_events_fts_au AFTER UPDATE OF ip, jail, server_name, hostname, country ON ban_events BEGIN
	INSERT INTO ban_events_fts(ban_events_fts, rowid, ip, jail, server_name, hostname, country)
	VALUES ('delete', old.id, old.ip, old.jail, old.server_name, old.hostname, old.country);
	INSERT INTO ban_events_fts(rowid, ip, jail, server_name, hostname, country)
	VALUES (new.id, new.ip, new.jail, new.server_name, new.hostname, new.country);
END;`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		log.Printf("WARNING: full-text search index unavailable, falling back to slow LIKE search: %v", err)
		return
	}

	var indexedRows, eventRows int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ban_events_fts_docsize`).Scan(&indexedRows); err != nil {
		log.Printf("WARNING: full-text search index unreadable, falling back to slow LIKE search: %v", err)
		return
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ban_events`).Scan(&eventRows); err != nil {
		log.Printf("WARNING: failed to count ban events for FTS backfill: %v", err)
		return
	}
	if indexedRows != eventRows {
		start := time.Now()
		if _, err := db.ExecContext(ctx, `INSERT INTO ban_events_fts(ban_events_fts) VALUES('rebuild')`); err != nil {
			log.Printf("WARNING: FTS rebuild failed, falling back to slow LIKE search: %v", err)
			return
		}
		log.Printf("Built full-text search index for %d ban events in %s (had %d indexed)", eventRows, time.Since(start).Round(time.Millisecond), indexedRows)
	}
	ftsAvailable = true
}

// Rewrites legacy Go-default timestamps ("2006-01-02 15:04:05.999999999 +0000 UTC")
// to RFC3339 so occurred_at / created_at compare correctly as strings and the
// occurred_at indexes stay usable.
func migrateLegacyTimestamps(ctx context.Context) error {
	for _, column := range []string{"occurred_at", "created_at"} {
		query := fmt.Sprintf(
			`UPDATE ban_events SET %[1]s = replace(substr(%[1]s, 1, length(%[1]s)-10), ' ', 'T') || 'Z' WHERE %[1]s LIKE '%% +0000 UTC'`,
			column,
		)
		res, err := db.ExecContext(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to migrate legacy %s timestamps: %w", column, err)
		}
		if affected, err := res.RowsAffected(); err == nil && affected > 0 {
			log.Printf("Migrated %d legacy %s timestamps to RFC3339", affected, column)
		}
	}
	return nil
}

// chmods the database to 0600: as a tiny security hardening. Runs on every boot so
// databases created 0644 by earlier versions are fixed too.
func restrictDatabasePermissions(dbPath string) {
	if dbPath == ":memory:" {
		return
	}
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: failed to restrict permissions on %s: %v", p, err)
		}
	}
}

// Close the database.
func Close() error {
	if db == nil {
		return nil
	}
	return db.Close()
}

// Get the app settings.
func GetAppSettings(ctx context.Context) (AppSettingsRecord, bool, error) {
	if db == nil {
		return AppSettingsRecord{}, false, errors.New("storage not initialised")
	}

	row := db.QueryRowContext(ctx, `
SELECT language, port, debug, restart_needed, callback_url, callback_secret, alert_countries, email_alerts_for_bans, email_alerts_for_unbans, smtp_host, smtp_port, smtp_username, smtp_password, smtp_from, smtp_use_tls, bantime_increment, default_jail_enable, ignore_ip, bantime, findtime, maxretry, destemail, banaction, banaction_allports, advanced_actions, geoip_provider, geoip_database_path, max_log_lines, event_retention_days, console_output, smtp_insecure_skip_verify, smtp_auth_method, chain, bantime_rndtime, bantime_maxtime, bantime_factor, bantime_overalljails, alert_provider, webhook, elasticsearch, threat_intel
FROM app_settings
WHERE id = 1`)

	var (
		lang, callback, callbackSecret, alerts, smtpHost, smtpUser, smtpPass, smtpFrom, ignoreIP, bantime, findtime, destemail, banaction, banactionAllports, chain, bantimeRndtime, bantimeMaxtime, bantimeFactor, advancedActions, geoipProvider, geoipDatabasePath, smtpAuthMethod sql.NullString
		alertProvider, webhookJSON, elasticsearchJSON, threatIntelJSON                                                                                                                                                                                                                sql.NullString
		port, smtpPort, maxretry, maxLogLines, eventRetentionDays                                                                                                                                                                                                                     sql.NullInt64
		debug, restartNeeded, smtpTLS, bantimeInc, bantimeOveralljails, defaultJailEn, emailAlertsForBans, emailAlertsForUnbans, consoleOutput, smtpInsecureSkipVerify                                                                                                                sql.NullInt64
	)

	err := row.Scan(&lang, &port, &debug, &restartNeeded, &callback, &callbackSecret, &alerts, &emailAlertsForBans, &emailAlertsForUnbans, &smtpHost, &smtpPort, &smtpUser, &smtpPass, &smtpFrom, &smtpTLS, &bantimeInc, &defaultJailEn, &ignoreIP, &bantime, &findtime, &maxretry, &destemail, &banaction, &banactionAllports, &advancedActions, &geoipProvider, &geoipDatabasePath, &maxLogLines, &eventRetentionDays, &consoleOutput, &smtpInsecureSkipVerify, &smtpAuthMethod, &chain, &bantimeRndtime, &bantimeMaxtime, &bantimeFactor, &bantimeOveralljails, &alertProvider, &webhookJSON, &elasticsearchJSON, &threatIntelJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return AppSettingsRecord{}, false, nil
	}
	if err != nil {
		return AppSettingsRecord{}, false, err
	}

	rec := AppSettingsRecord{
		Language:               stringFromNull(lang),
		Port:                   intFromNull(port),
		Debug:                  intToBool(intFromNull(debug)),
		RestartNeeded:          intToBool(intFromNull(restartNeeded)),
		CallbackURL:            stringFromNull(callback),
		CallbackSecret:         stringFromNull(callbackSecret),
		AlertCountriesJSON:     stringFromNull(alerts),
		EmailAlertsForBans:     intToBool(intFromNull(emailAlertsForBans)),
		EmailAlertsForUnbans:   intToBool(intFromNull(emailAlertsForUnbans)),
		SMTPHost:               stringFromNull(smtpHost),
		SMTPPort:               intFromNull(smtpPort),
		SMTPUsername:           stringFromNull(smtpUser),
		SMTPPassword:           stringFromNull(smtpPass),
		SMTPFrom:               stringFromNull(smtpFrom),
		SMTPUseTLS:             intToBool(intFromNull(smtpTLS)),
		SMTPInsecureSkipVerify: intToBool(intFromNull(smtpInsecureSkipVerify)),
		SMTPAuthMethod:         stringFromNull(smtpAuthMethod),
		BantimeIncrement:       intToBool(intFromNull(bantimeInc)),
		DefaultJailEnable:      intToBool(intFromNull(defaultJailEn)),
		IgnoreIP:               stringFromNull(ignoreIP),
		Bantime:                stringFromNull(bantime),
		Findtime:               stringFromNull(findtime),
		MaxRetry:               intFromNull(maxretry),
		DestEmail:              stringFromNull(destemail),
		Banaction:              stringFromNull(banaction),
		BanactionAllports:      stringFromNull(banactionAllports),
		Chain:                  stringFromNull(chain),
		BantimeRndtime:         stringFromNull(bantimeRndtime),
		BantimeMaxtime:         stringFromNull(bantimeMaxtime),
		BantimeFactor:          stringFromNull(bantimeFactor),
		BantimeOveralljails:    intToBool(intFromNull(bantimeOveralljails)),
		AdvancedActionsJSON:    stringFromNull(advancedActions),
		GeoIPProvider:          stringFromNull(geoipProvider),
		GeoIPDatabasePath:      stringFromNull(geoipDatabasePath),
		MaxLogLines:            intFromNull(maxLogLines),
		EventRetentionDays:     intFromNull(eventRetentionDays),
		AlertProvider:          stringFromNull(alertProvider),
		WebhookJSON:            stringFromNull(webhookJSON),
		ElasticsearchJSON:      stringFromNull(elasticsearchJSON),
		ThreatIntelJSON:        stringFromNull(threatIntelJSON),
		ConsoleOutput:          intToBool(intFromNull(consoleOutput)),
	}

	return rec, true, nil
}

func SaveAppSettings(ctx context.Context, rec AppSettingsRecord) error {
	if db == nil {
		return errors.New("storage not initialised")
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO app_settings (
	id, language, port, debug, restart_needed, callback_url, callback_secret, alert_countries, email_alerts_for_bans, email_alerts_for_unbans, smtp_host, smtp_port, smtp_username, smtp_password, smtp_from, smtp_use_tls, bantime_increment, default_jail_enable, ignore_ip, bantime, findtime, maxretry, destemail, banaction, banaction_allports, advanced_actions, geoip_provider, geoip_database_path, max_log_lines, event_retention_days, console_output, smtp_insecure_skip_verify, smtp_auth_method, chain, bantime_rndtime, bantime_maxtime, bantime_factor, bantime_overalljails, alert_provider, webhook, elasticsearch, threat_intel
) VALUES (
	1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
) ON CONFLICT(id) DO UPDATE SET
	language = excluded.language,
	port = excluded.port,
	debug = excluded.debug,
	restart_needed = excluded.restart_needed,
	callback_url = excluded.callback_url,
	callback_secret = excluded.callback_secret,
	alert_countries = excluded.alert_countries,
	email_alerts_for_bans = excluded.email_alerts_for_bans,
	email_alerts_for_unbans = excluded.email_alerts_for_unbans,
	smtp_host = excluded.smtp_host,
	smtp_port = excluded.smtp_port,
	smtp_username = excluded.smtp_username,
	smtp_password = excluded.smtp_password,
	smtp_from = excluded.smtp_from,
	smtp_use_tls = excluded.smtp_use_tls,
	bantime_increment = excluded.bantime_increment,
	default_jail_enable = excluded.default_jail_enable,
	ignore_ip = excluded.ignore_ip,
	bantime = excluded.bantime,
	findtime = excluded.findtime,
	maxretry = excluded.maxretry,
	destemail = excluded.destemail,
	banaction = excluded.banaction,
	banaction_allports = excluded.banaction_allports,
	advanced_actions = excluded.advanced_actions,
	geoip_provider = excluded.geoip_provider,
	geoip_database_path = excluded.geoip_database_path,
	max_log_lines = excluded.max_log_lines,
	event_retention_days = excluded.event_retention_days,
	console_output = excluded.console_output,
	smtp_insecure_skip_verify = excluded.smtp_insecure_skip_verify,
	smtp_auth_method = excluded.smtp_auth_method,
	chain = excluded.chain,
	bantime_rndtime = excluded.bantime_rndtime,
	bantime_maxtime = excluded.bantime_maxtime,
	bantime_factor = excluded.bantime_factor,
	bantime_overalljails = excluded.bantime_overalljails,
	alert_provider = excluded.alert_provider,
	webhook = excluded.webhook,
	elasticsearch = excluded.elasticsearch,
	threat_intel = excluded.threat_intel
`, rec.Language,
		rec.Port,
		boolToInt(rec.Debug),
		boolToInt(rec.RestartNeeded),
		rec.CallbackURL,
		rec.CallbackSecret,
		rec.AlertCountriesJSON,
		boolToInt(rec.EmailAlertsForBans),
		boolToInt(rec.EmailAlertsForUnbans),
		rec.SMTPHost,
		rec.SMTPPort,
		rec.SMTPUsername,
		rec.SMTPPassword,
		rec.SMTPFrom,
		boolToInt(rec.SMTPUseTLS),
		boolToInt(rec.BantimeIncrement),
		boolToInt(rec.DefaultJailEnable),
		rec.IgnoreIP,
		rec.Bantime,
		rec.Findtime,
		rec.MaxRetry,
		rec.DestEmail,
		rec.Banaction,
		rec.BanactionAllports,
		rec.AdvancedActionsJSON,
		rec.GeoIPProvider,
		rec.GeoIPDatabasePath,
		rec.MaxLogLines,
		rec.EventRetentionDays,
		boolToInt(rec.ConsoleOutput),
		boolToInt(rec.SMTPInsecureSkipVerify),
		rec.SMTPAuthMethod,
		rec.Chain,
		rec.BantimeRndtime,
		rec.BantimeMaxtime,
		rec.BantimeFactor,
		boolToInt(rec.BantimeOveralljails),
		rec.AlertProvider,
		rec.WebhookJSON,
		rec.ElasticsearchJSON,
		rec.ThreatIntelJSON)
	return err
}

// =========================================================================
//  Servers
// =========================================================================

func ListServers(ctx context.Context) ([]ServerRecord, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}

	rows, err := db.QueryContext(ctx, `
SELECT id, name, type, host, port, socket_path, config_path, ssh_user, ssh_key_path, agent_url, agent_secret, hostname, tags, is_default, enabled, reverse_tunnel, needs_restart, created_at, updated_at
FROM servers
ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ServerRecord
	for rows.Next() {
		var rec ServerRecord
		var host, socket, configPath, sshUser, sshKey, agentURL, agentSecret, hostname, tags sql.NullString
		var name, serverType sql.NullString
		var created, updated sql.NullString
		var port sql.NullInt64
		var isDefault, enabled, reverseTunnel, needsRestart sql.NullInt64

		if err := rows.Scan(
			&rec.ID,
			&name,
			&serverType,
			&host,
			&port,
			&socket,
			&configPath,
			&sshUser,
			&sshKey,
			&agentURL,
			&agentSecret,
			&hostname,
			&tags,
			&isDefault,
			&enabled,
			&reverseTunnel,
			&needsRestart,
			&created,
			&updated,
		); err != nil {
			return nil, err
		}

		rec.Name = stringFromNull(name)
		rec.Type = stringFromNull(serverType)
		rec.Host = stringFromNull(host)
		rec.Port = intFromNull(port)
		rec.SocketPath = stringFromNull(socket)
		rec.ConfigPath = stringFromNull(configPath)
		rec.SSHUser = stringFromNull(sshUser)
		rec.SSHKeyPath = stringFromNull(sshKey)
		rec.AgentURL = stringFromNull(agentURL)
		rec.AgentSecret = stringFromNull(agentSecret)
		rec.Hostname = stringFromNull(hostname)
		rec.TagsJSON = stringFromNull(tags)
		rec.IsDefault = intToBool(intFromNull(isDefault))
		rec.Enabled = intToBool(intFromNull(enabled))
		rec.ReverseTunnelEnabled = intToBool(intFromNull(reverseTunnel))
		rec.NeedsRestart = intToBool(intFromNull(needsRestart))

		if created.Valid {
			if t, err := time.Parse(time.RFC3339Nano, created.String); err == nil {
				rec.CreatedAt = t
			}
		}
		if updated.Valid {
			if t, err := time.Parse(time.RFC3339Nano, updated.String); err == nil {
				rec.UpdatedAt = t
			}
		}

		records = append(records, rec)
	}

	return records, rows.Err()
}

func ReplaceServers(ctx context.Context, servers []ServerRecord) error {
	if db == nil {
		return errors.New("storage not initialised")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, `DELETE FROM servers`); err != nil {
		return err
	}

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO servers (
	id, name, type, host, port, socket_path, config_path, ssh_user, ssh_key_path, agent_url, agent_secret, hostname, tags, is_default, enabled, reverse_tunnel, needs_restart, created_at, updated_at
) VALUES (
	?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, srv := range servers {
		createdAt := srv.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}
		updatedAt := srv.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = createdAt
		}
		if _, err = stmt.ExecContext(ctx,
			srv.ID,
			srv.Name,
			srv.Type,
			srv.Host,
			srv.Port,
			srv.SocketPath,
			srv.ConfigPath,
			srv.SSHUser,
			srv.SSHKeyPath,
			srv.AgentURL,
			srv.AgentSecret,
			srv.Hostname,
			srv.TagsJSON,
			boolToInt(srv.IsDefault),
			boolToInt(srv.Enabled),
			boolToInt(srv.ReverseTunnelEnabled),
			boolToInt(srv.NeedsRestart),
			createdAt.Format(time.RFC3339Nano),
			updatedAt.Format(time.RFC3339Nano),
		); err != nil {
			return err
		}
	}

	err = tx.Commit()
	return err
}

// =========================================================================
//  Ban Events Records
// =========================================================================

// Stores a ban/unban event into the database.
func RecordBanEvent(ctx context.Context, record BanEventRecord) (int64, error) {
	if db == nil {
		return 0, errors.New("storage not initialised")
	}

	if record.ServerID == "" {
		return 0, errors.New("server id is required")
	}
	now := time.Now().UTC()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	if record.OccurredAt.IsZero() {
		record.OccurredAt = now
	}
	// If the event type is not set, we set it to "ban" by default.
	eventType := record.EventType
	if eventType == "" {
		eventType = "ban"
	}

	const query = `
INSERT INTO ban_events (
	server_id, server_name, jail, ip, country, hostname, failures, whois, logs, event_type, occurred_at, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	res, err := db.ExecContext(
		ctx,
		query,
		record.ServerID,
		record.ServerName,
		record.Jail,
		record.IP,
		record.Country,
		record.Hostname,
		record.Failures,
		record.Whois,
		record.Logs,
		eventType,
		formatStorageTime(record.OccurredAt),
		formatStorageTime(record.CreatedAt),
	)
	if err != nil {
		return 0, err
	}

	return res.LastInsertId()
}

// Fills in whois on an already stored event; used by the asynchronous enrichment after the callback has been answered.
func UpdateBanEventEnrichment(ctx context.Context, id int64, whois, country string) error {
	if db == nil {
		return errors.New("storage not initialised")
	}
	if id <= 0 {
		return errors.New("event id is required")
	}
	_, err := db.ExecContext(ctx,
		`UPDATE ban_events SET whois = ?, country = CASE WHEN ? = '' THEN country ELSE ? END WHERE id = ?`,
		whois, country, country, id)
	return err
}

// Returns the distinct set of countries seen across all stored events
func ListBanEventCountries(ctx context.Context) ([]string, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT COALESCE(country, '') FROM ban_events ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var countries []string
	for rows.Next() {
		var country string
		if err := rows.Scan(&country); err != nil {
			return nil, err
		}
		countries = append(countries, country)
	}
	return countries, rows.Err()
}

const (
	// MaxBanEventsLimit is the maximum number of events per API request (pagination page size).
	MaxBanEventsLimit = 50
	// MaxBanEventsOffset is the maximum offset (total events loaded in UI capped for browser stability).
	MaxBanEventsOffset = 1000
)

// Returns ban events matching the filter, ordered by occurred_at DESC.
// Search is applied via FTS (or LIKE fallback) on ip, jail, server_name, hostname, country.
// limit is capped at MaxBanEventsLimit; offset is capped at MaxBanEventsOffset.
func ListBanEventsFiltered(ctx context.Context, f BanEventFilter, limit, offset int) ([]BanEventRecord, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}
	if limit <= 0 || limit > MaxBanEventsLimit {
		limit = MaxBanEventsLimit
	}
	if offset < 0 || offset > MaxBanEventsOffset {
		offset = 0
	}

	from := "FROM ban_events"
	search := strings.TrimSpace(f.Search)
	if search != "" && ftsAvailable {
		var matches int64
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ban_events_fts WHERE ban_events_fts MATCH ?`, buildFTSMatch(search)).Scan(&matches); err == nil && matches > broadSearchThreshold {
			from = "FROM ban_events INDEXED BY idx_ban_events_occurred_at"
		}
	}

	baseQuery := `
SELECT id, server_id, server_name, jail, ip, country, hostname, failures,
       (whois IS NOT NULL AND whois <> '') AS has_whois,
       (logs IS NOT NULL AND logs <> '') AS has_logs,
       event_type, occurred_at, created_at
` + from + `
WHERE 1=1`
	conditions, args := f.buildWhere()
	baseQuery += conditions

	baseQuery += " ORDER BY occurred_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []BanEventRecord
	for rows.Next() {
		var rec BanEventRecord
		var eventType sql.NullString
		var hasWhois, hasLogs int64
		if err := rows.Scan(
			&rec.ID,
			&rec.ServerID,
			&rec.ServerName,
			&rec.Jail,
			&rec.IP,
			&rec.Country,
			&rec.Hostname,
			&rec.Failures,
			&hasWhois,
			&hasLogs,
			&eventType,
			&rec.OccurredAt,
			&rec.CreatedAt,
		); err != nil {
			return nil, err
		}
		rec.HasWhois = hasWhois != 0
		rec.HasLogs = hasLogs != 0
		if eventType.Valid {
			rec.EventType = eventType.String
		} else {
			rec.EventType = "ban"
		}
		results = append(results, rec)
	}
	return results, rows.Err()
}

// GetBanEventByID returns a single ban event including the whois/logs fields.
func GetBanEventByID(ctx context.Context, id int64) (BanEventRecord, bool, error) {
	if db == nil {
		return BanEventRecord{}, false, errors.New("storage not initialised")
	}

	const query = `
SELECT id, server_id, server_name, jail, ip, country, hostname, failures, whois, logs, event_type, occurred_at, created_at
FROM ban_events
WHERE id = ?`

	var rec BanEventRecord
	var eventType sql.NullString
	err := db.QueryRowContext(ctx, query, id).Scan(
		&rec.ID,
		&rec.ServerID,
		&rec.ServerName,
		&rec.Jail,
		&rec.IP,
		&rec.Country,
		&rec.Hostname,
		&rec.Failures,
		&rec.Whois,
		&rec.Logs,
		&eventType,
		&rec.OccurredAt,
		&rec.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return BanEventRecord{}, false, nil
	}
	if err != nil {
		return BanEventRecord{}, false, err
	}
	if eventType.Valid {
		rec.EventType = eventType.String
	} else {
		rec.EventType = "ban"
	}
	rec.HasWhois = rec.Whois != ""
	rec.HasLogs = rec.Logs != ""
	return rec, true, nil
}

// Upper bound for counting search matches
const MaxSearchCount = 5000

// Above this many FTS matches a search term counts as "broad": the list query
// then walks the occurred_at index and probes the match set instead of sorting the whole match set.
const broadSearchThreshold = 10000

// Returns the total count of ban events matching the same filters as ListBanEventsFiltered.
func CountBanEventsFiltered(ctx context.Context, f BanEventFilter) (int64, error) {
	if db == nil {
		return 0, errors.New("storage not initialised")
	}

	// A search without further filters is answered index-only by FTS.
	search := strings.TrimSpace(f.Search)
	if search != "" && ftsAvailable && f.ServerID == "" && f.Jail == "" && !f.BansOnly &&
		f.Since.IsZero() && f.Until.IsZero() && (f.Country == "" || f.Country == "all") {
		var total int64
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ban_events_fts WHERE ban_events_fts MATCH ?`, buildFTSMatch(search)).Scan(&total); err != nil {
			return 0, err
		}
		if total > MaxSearchCount {
			total = MaxSearchCount + 1
		}
		return total, nil
	}

	conditions, args := f.buildWhere()

	query := `SELECT COUNT(*) FROM ban_events WHERE 1=1` + conditions
	if search != "" {
		query = fmt.Sprintf(`SELECT COUNT(*) FROM (SELECT 1 FROM ban_events WHERE 1=1%s LIMIT %d)`, conditions, MaxSearchCount+1)
	}

	var total int64
	if err := db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// Returns simple aggregation per server.
func CountBanEventsByServer(ctx context.Context, since time.Time) (map[string]int64, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}

	query := `
SELECT server_id, COUNT(*) 
FROM ban_events
WHERE 1=1`
	args := []any{}

	addOccurredAtSinceFilter(&query, &args, since)

	query += " GROUP BY server_id"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var serverID string
		var count int64
		if err := rows.Scan(&serverID, &count); err != nil {
			return nil, err
		}
		result[serverID] = count
	}

	return result, rows.Err()
}

// Returns total number of ban events optionally filtered by time and server.
func CountBanEvents(ctx context.Context, since time.Time, serverID string) (int64, error) {
	if db == nil {
		return 0, errors.New("storage not initialised")
	}

	query := `
SELECT COUNT(*)
FROM ban_events
WHERE 1=1`
	args := []any{}

	if serverID != "" {
		query += " AND server_id = ?"
		args = append(args, serverID)
	}

	addOccurredAtSinceFilter(&query, &args, since)

	var total int64
	if err := db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// Returns per-jail ban-event counts for one server since the provided timestamp, in a single query.
func CountRecentBanEventsByJail(ctx context.Context, serverID string, since time.Time) (map[string]int, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}
	if serverID == "" {
		return nil, errors.New("server id is required")
	}

	query := `
SELECT jail, COUNT(*)
FROM ban_events
WHERE server_id = ?
  AND (event_type = 'ban' OR event_type IS NULL)`
	args := []any{serverID}
	addOccurredAtSinceFilter(&query, &args, since)
	query += " GROUP BY jail"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var jail string
		var count int
		if err := rows.Scan(&jail, &count); err != nil {
			return nil, err
		}
		counts[jail] = count
	}
	return counts, rows.Err()
}

// Returns total number of ban events for a specific IP and optional server.
func CountBanEventsByIP(ctx context.Context, ip, serverID string) (int64, error) {
	if db == nil {
		return 0, errors.New("storage not initialised")
	}
	if ip == "" {
		return 0, errors.New("ip is required")
	}

	query := `
SELECT COUNT(*)
FROM ban_events INDEXED BY idx_ban_events_ip
WHERE ip = ? AND (event_type = 'ban' OR event_type IS NULL)`
	args := []any{ip}

	if serverID != "" {
		query += " AND server_id = ?"
		args = append(args, serverID)
	}

	var total int64
	if err := db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// Returns aggregation per country code, optionally filtered by server.
func CountBanEventsByCountry(ctx context.Context, since time.Time, serverID string) (map[string]int64, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}

	from := "FROM ban_events"
	if !since.IsZero() {
		from = "FROM ban_events INDEXED BY idx_ban_events_occurred_at_ip"
	}
	query := `
SELECT COALESCE(country, '') AS country, COUNT(*)
` + from + `
WHERE 1=1`
	args := []any{}

	if serverID != "" {
		query += " AND server_id = ?"
		args = append(args, serverID)
	}

	addOccurredAtSinceFilter(&query, &args, since)

	query += " GROUP BY COALESCE(country, '')"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var country sql.NullString
		var count int64
		if err := rows.Scan(&country, &count); err != nil {
			return nil, err
		}
		result[stringFromNull(country)] = count
	}

	return result, rows.Err()
}

// Returns overall / today / week ban-event counts in a single query
func CountBanEventTotals(ctx context.Context, serverID string, now time.Time) (overall, today, week int64, err error) {
	if db == nil {
		return 0, 0, 0, errors.New("storage not initialised")
	}

	query := `
SELECT COUNT(*),
       COALESCE(SUM(occurred_at >= ?), 0),
       COALESCE(SUM(occurred_at >= ?), 0)
FROM ban_events
WHERE 1=1`
	args := []any{
		formatStorageTime(now.Add(-24 * time.Hour)),
		formatStorageTime(now.Add(-7 * 24 * time.Hour)),
	}
	if serverID != "" {
		query += " AND server_id = ?"
		args = append(args, serverID)
	}

	err = db.QueryRowContext(ctx, query, args...).Scan(&overall, &today, &week)
	return overall, today, week, err
}

// =========================================================================
//  Timeline & IP Aggregation
// =========================================================================

type TimelineBucket struct {
	Start  time.Time `json:"start"`
	Bans   int64     `json:"bans"`
	Unbans int64     `json:"unbans"`
}

const maxTimelineBuckets = 1000

// Returns ban / unban counts bucketed into bucketSeconds-wide intervals aligned to epoch multiples, zero-filled across [f.Since, f.Until)
func BanEventTimeline(ctx context.Context, f BanEventFilter, bucketSeconds int64) ([]TimelineBucket, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}
	if bucketSeconds <= 0 {
		return nil, errors.New("bucket size must be positive")
	}
	if f.Since.IsZero() || f.Until.IsZero() || !f.Until.After(f.Since) {
		return nil, errors.New("a valid since/until range is required")
	}
	startBucket := (f.Since.Unix() / bucketSeconds) * bucketSeconds
	endEpoch := f.Until.Unix()
	if (endEpoch-startBucket)/bucketSeconds+1 > maxTimelineBuckets {
		return nil, errors.New("time range yields too many buckets")
	}

	conditions, args := f.buildWhere()
	query := `
SELECT (CAST(strftime('%s', occurred_at) AS INTEGER) / ?) * ? AS bucket,
       SUM(CASE WHEN event_type = 'unban' THEN 0 ELSE 1 END) AS bans,
       SUM(CASE WHEN event_type = 'unban' THEN 1 ELSE 0 END) AS unbans
FROM ban_events
WHERE 1=1` + conditions + `
GROUP BY bucket
ORDER BY bucket`
	queryArgs := append([]any{bucketSeconds, bucketSeconds}, args...)

	rows, err := db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type bucketCounts struct{ bans, unbans int64 }
	counts := make(map[int64]bucketCounts)
	for rows.Next() {
		var bucket, bans, unbans int64
		if err := rows.Scan(&bucket, &bans, &unbans); err != nil {
			return nil, err
		}
		counts[bucket] = bucketCounts{bans: bans, unbans: unbans}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	buckets := make([]TimelineBucket, 0, (endEpoch-startBucket)/bucketSeconds+1)
	for ts := startBucket; ts < endEpoch; ts += bucketSeconds {
		c := counts[ts]
		buckets = append(buckets, TimelineBucket{
			Start:  time.Unix(ts, 0).UTC(),
			Bans:   c.bans,
			Unbans: c.unbans,
		})
	}
	return buckets, nil
}

// Aggregates ban events per IP within a time range.
type BanEventIPStat struct {
	IP        string    `json:"ip"`
	Country   string    `json:"country"`
	Count     int64     `json:"count"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	Jails     string    `json:"jails"`
}

// Returns per-IP ban aggregates ordered by count desc, plus the total number of
// distinct IPs matching the filter so callers can detect truncation.
func ListBanEventIPs(ctx context.Context, f BanEventFilter, limit int) ([]BanEventIPStat, int64, error) {
	if db == nil {
		return nil, 0, errors.New("storage not initialised")
	}
	if limit <= 0 || limit > 10000 {
		limit = 2000
	}
	f.BansOnly = true

	conditions, args := f.buildWhere()
	query := `
SELECT ip,
       MAX(COALESCE(country, '')) AS country,
       COUNT(*) AS cnt,
       MIN(occurred_at) AS first_seen,
       MAX(occurred_at) AS last_seen,
       GROUP_CONCAT(DISTINCT jail) AS jails
FROM ban_events
WHERE ip != ''` + conditions + `
GROUP BY ip
ORDER BY cnt DESC, ip
LIMIT ?`
	queryArgs := append(append([]any{}, args...), limit)

	rows, err := db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []BanEventIPStat
	for rows.Next() {
		var stat BanEventIPStat
		var firstSeen, lastSeen, jails sql.NullString
		if err := rows.Scan(&stat.IP, &stat.Country, &stat.Count, &firstSeen, &lastSeen, &jails); err != nil {
			return nil, 0, err
		}
		if firstSeen.Valid {
			stat.FirstSeen = parseStorageTime(firstSeen.String)
		}
		if lastSeen.Valid {
			stat.LastSeen = parseStorageTime(lastSeen.String)
		}
		stat.Jails = stringFromNull(jails)
		results = append(results, stat)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var total int64
	countQuery := `SELECT COUNT(DISTINCT ip) FROM ban_events WHERE ip != ''` + conditions
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	return results, total, nil
}

type IPActivityPeriod struct {
	Day     string `json:"day"`
	Overlap int64  `json:"overlap"`
	Events  int64  `json:"events"`
}

func ListBanEventIPActivity(ctx context.Context, f BanEventFilter, minOverlap int) ([]IPActivityPeriod, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}
	if f.Since.IsZero() || f.Until.IsZero() || !f.Until.After(f.Since) {
		return nil, errors.New("a valid since/until range is required")
	}
	if minOverlap < 1 {
		minOverlap = 1
	}
	f.BansOnly = true

	innerConditions, innerArgs := f.buildWhere()
	query := `
SELECT strftime('%Y-%m-%d', occurred_at) AS day,
       COUNT(DISTINCT ip) AS overlap,
       COUNT(*) AS events
FROM ban_events
WHERE ip != ''
  AND (event_type = 'ban' OR event_type IS NULL)
  AND ip IN (SELECT DISTINCT ip FROM ban_events WHERE ip != ''` + innerConditions + `)
  AND (occurred_at < ? OR occurred_at >= ?)`
	args := append(append([]any{}, innerArgs...), formatStorageTime(f.Since), formatStorageTime(f.Until))

	if f.ServerID != "" {
		query += " AND server_id = ?"
		args = append(args, f.ServerID)
	}

	query += `
GROUP BY day
HAVING overlap >= ?
ORDER BY overlap DESC, day DESC
LIMIT 20`
	args = append(args, minOverlap)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []IPActivityPeriod
	for rows.Next() {
		var period IPActivityPeriod
		if err := rows.Scan(&period.Day, &period.Overlap, &period.Events); err != nil {
			return nil, err
		}
		results = append(results, period)
	}
	return results, rows.Err()
}

// Deletes all ban event records.
func ClearBanEvents(ctx context.Context) (int64, error) {
	if db == nil {
		return 0, errors.New("storage not initialised")
	}
	res, err := db.ExecContext(ctx, `DELETE FROM ban_events`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Deletes ban event records older than the cutoff (event retention)
func PruneBanEventsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	if db == nil {
		return 0, errors.New("storage not initialised")
	}
	res, err := db.ExecContext(ctx, `DELETE FROM ban_events WHERE occurred_at < ?`, formatStorageTime(cutoff))
	if err != nil {
		return 0, err
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if deleted > 0 {
		if _, err := db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			log.Printf("Warning: wal_checkpoint after ban-event prune failed: %v", err)
		}
	}
	return deleted, nil
}

// =========================================================================
//  Recurring IP Statistics
// =========================================================================

// Returns IPs that have been banned at least minCount times, optionally filtered by server.
func ListRecurringIPStats(ctx context.Context, since time.Time, minCount, limit int, serverID string) ([]RecurringIPStat, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}

	if minCount < 2 {
		minCount = 2
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	from := "FROM ban_events"
	if !since.IsZero() {
		from = "FROM ban_events INDEXED BY idx_ban_events_occurred_at_ip"
	}
	query := `
SELECT ip, COALESCE(country, '') AS country, COUNT(*) AS cnt, MAX(occurred_at) AS last_seen
` + from + `
WHERE ip != '' AND (event_type = 'ban' OR event_type IS NULL)`
	args := []any{}

	if serverID != "" {
		query += " AND server_id = ?"
		args = append(args, serverID)
	}

	addOccurredAtSinceFilter(&query, &args, since)

	query += `
GROUP BY ip, COALESCE(country, '')
HAVING cnt >= ?
ORDER BY cnt DESC, last_seen DESC
LIMIT ?`

	args = append(args, minCount, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []RecurringIPStat
	for rows.Next() {
		var stat RecurringIPStat
		var lastSeenStr sql.NullString
		if err := rows.Scan(&stat.IP, &stat.Country, &stat.Count, &lastSeenStr); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if lastSeenStr.Valid && lastSeenStr.String != "" {
			formats := []string{
				"2006-01-02 15:04:05.999999999 -0700 MST",
				time.RFC3339Nano,
				time.RFC3339,
				"2006-01-02 15:04:05.999999999+00:00",
				"2006-01-02 15:04:05+00:00",
				"2006-01-02 15:04:05.999999999",
				"2006-01-02 15:04:05",
				"2006-01-02T15:04:05.999999999Z",
				"2006-01-02T15:04:05Z",
				"2006-01-02T15:04:05.999999999",
				"2006-01-02T15:04:05",
			}
			parsed := time.Time{}
			for _, format := range formats {
				if t, parseErr := time.Parse(format, lastSeenStr.String); parseErr == nil {
					parsed = t.UTC()
					break
				}
			}
			if parsed.IsZero() {
				log.Printf("ERROR: Could not parse lastSeen datetime '%s' (length: %d) for IP %s. All format attempts failed.", lastSeenStr.String, len(lastSeenStr.String), stat.IP)
			}
			stat.LastSeen = parsed
		} else {
			log.Printf("WARNING: lastSeen is NULL or empty for IP %s", stat.IP)
		}
		results = append(results, stat)
	}

	return results, rows.Err()
}

// =========================================================================
//  Schema Management
// =========================================================================

func ensureSchema(ctx context.Context) error {
	if db == nil {
		return errors.New("storage not initialised")
	}

	const createTables = `
CREATE TABLE IF NOT EXISTS app_settings (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	-- Basic app settings
	language TEXT,
	port INTEGER,
	debug INTEGER,
	restart_needed INTEGER,
	-- Callback settings
	callback_url TEXT,
	callback_secret TEXT,
	-- Alert settings
	alert_countries TEXT,
	email_alerts_for_bans INTEGER DEFAULT 1,
	email_alerts_for_unbans INTEGER DEFAULT 0,
	-- SMTP settings
	smtp_host TEXT,
	smtp_port INTEGER,
	smtp_username TEXT,
	smtp_password TEXT,
	smtp_from TEXT,
	smtp_use_tls INTEGER,
	-- Fail2Ban DEFAULT settings
	bantime_increment INTEGER,
	default_jail_enable INTEGER,
	ignore_ip TEXT,
	bantime TEXT,
	findtime TEXT,
	maxretry INTEGER,
	destemail TEXT,
	banaction TEXT,
	banaction_allports TEXT,
	-- Advanced features
	advanced_actions TEXT,
	geoip_provider TEXT,
	geoip_database_path TEXT,
	max_log_lines INTEGER,
	event_retention_days INTEGER DEFAULT 180,
	-- Console output settings
	console_output INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS servers (
	id TEXT PRIMARY KEY,
	name TEXT,
	type TEXT,
	host TEXT,
	port INTEGER,
	socket_path TEXT,
	config_path TEXT,
	ssh_user TEXT,
	ssh_key_path TEXT,
	agent_url TEXT,
	agent_secret TEXT,
	hostname TEXT,
	tags TEXT,
	is_default INTEGER,
	enabled INTEGER,
	reverse_tunnel INTEGER DEFAULT 0,
	needs_restart INTEGER DEFAULT 0,
	created_at TEXT,
	updated_at TEXT
);

CREATE TABLE IF NOT EXISTS ban_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	server_id TEXT NOT NULL,
	server_name TEXT NOT NULL,
	jail TEXT NOT NULL,
	ip TEXT NOT NULL,
	country TEXT,
	hostname TEXT,
	failures TEXT,
	whois TEXT,
	logs TEXT,
	event_type TEXT NOT NULL DEFAULT 'ban',
	occurred_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS permanent_blocks (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ip TEXT NOT NULL,
	integration TEXT NOT NULL,
	status TEXT NOT NULL,
	details TEXT,
	message TEXT,
	server_id TEXT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE(ip, integration)
);
`

	const createIndexes = `
CREATE INDEX IF NOT EXISTS idx_ban_events_server_id ON ban_events(server_id);
CREATE INDEX IF NOT EXISTS idx_ban_events_occurred_at ON ban_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_ban_events_ip ON ban_events(ip);
CREATE INDEX IF NOT EXISTS idx_ban_events_server_jail_occurred_at ON ban_events(server_id, jail, occurred_at);
CREATE INDEX IF NOT EXISTS idx_ban_events_occurred_at_ip ON ban_events(occurred_at, ip, country, event_type, server_id);
CREATE INDEX IF NOT EXISTS idx_ban_events_server_occurred_at ON ban_events(server_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_ban_events_country ON ban_events(country);

CREATE INDEX IF NOT EXISTS idx_perm_blocks_status ON permanent_blocks(status);
CREATE INDEX IF NOT EXISTS idx_perm_blocks_updated_at ON permanent_blocks(updated_at);
`

	// Columns added after a table first shipped. CREATE TABLE IF NOT EXISTS is a no-op on existing databases, so every later column needs an entry here
	alterColumns := []string{
		`ALTER TABLE app_settings ADD COLUMN console_output INTEGER DEFAULT 0`,
		`ALTER TABLE app_settings ADD COLUMN smtp_insecure_skip_verify INTEGER DEFAULT 0`,
		`ALTER TABLE app_settings ADD COLUMN smtp_auth_method TEXT DEFAULT 'auto'`,
		`ALTER TABLE app_settings ADD COLUMN chain TEXT DEFAULT 'INPUT'`,
		`ALTER TABLE app_settings ADD COLUMN bantime_rndtime TEXT DEFAULT ''`,
		`ALTER TABLE app_settings ADD COLUMN bantime_maxtime TEXT DEFAULT ''`,
		`ALTER TABLE app_settings ADD COLUMN bantime_factor TEXT DEFAULT ''`,
		`ALTER TABLE app_settings ADD COLUMN bantime_overalljails INTEGER DEFAULT 0`,
		`ALTER TABLE app_settings ADD COLUMN alert_provider TEXT DEFAULT 'email'`,
		`ALTER TABLE app_settings ADD COLUMN webhook TEXT DEFAULT '{}'`,
		`ALTER TABLE app_settings ADD COLUMN elasticsearch TEXT DEFAULT '{}'`,
		`ALTER TABLE app_settings ADD COLUMN threat_intel TEXT DEFAULT '{}'`,
		`ALTER TABLE servers ADD COLUMN config_path TEXT`,
		`ALTER TABLE servers ADD COLUMN reverse_tunnel INTEGER DEFAULT 0`,
		`ALTER TABLE app_settings ADD COLUMN event_retention_days INTEGER DEFAULT 180`,
		`ALTER TABLE ban_events ADD COLUMN event_type TEXT NOT NULL DEFAULT 'ban'`,
	}

	if _, err := db.ExecContext(ctx, createTables); err != nil {
		return err
	}
	for _, ddl := range alterColumns {
		if err := addColumnIfMissing(ctx, ddl); err != nil {
			return err
		}
	}
	if _, err := db.ExecContext(ctx, createIndexes); err != nil {
		return err
	}
	return nil
}

func addColumnIfMissing(ctx context.Context, ddl string) error {
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return err
		}
	}
	return nil
}

func ensureDirectory(path string) error {
	if path == ":memory:" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

// Ensures .ssh exists for SSH key storage (/config/.ssh in container, ~/.ssh on host).
func ensureSSHDirectory() error {
	var sshDir string
	if _, container := os.LookupEnv("CONTAINER"); container {
		sshDir = "/config/.ssh"
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory: %w", err)
		}
		sshDir = filepath.Join(home, ".ssh")
	}

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return fmt.Errorf("failed to create .ssh directory at %s: %w", sshDir, err)
	}

	return nil
}

// =========================================================================
//  Permanent Blocks Records
// =========================================================================

// Stores or updates a permanent block entry.
func UpsertPermanentBlock(ctx context.Context, rec PermanentBlockRecord) error {
	if db == nil {
		return errors.New("storage not initialised")
	}
	if rec.IP == "" || rec.Integration == "" {
		return errors.New("ip and integration are required")
	}
	now := time.Now().UTC()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now
	if rec.Status == "" {
		rec.Status = "blocked"
	}

	const query = `
INSERT INTO permanent_blocks (ip, integration, status, details, message, server_id, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(ip, integration) DO UPDATE SET
	status = excluded.status,
	details = excluded.details,
	message = excluded.message,
	server_id = excluded.server_id,
	updated_at = excluded.updated_at`

	_, err := db.ExecContext(ctx, query,
		rec.IP,
		rec.Integration,
		rec.Status,
		rec.Details,
		rec.Message,
		rec.ServerID,
		rec.CreatedAt.Format(time.RFC3339Nano),
		rec.UpdatedAt.Format(time.RFC3339Nano),
	)
	return err
}

// Returns a permanent block entry.
func GetPermanentBlock(ctx context.Context, ip, integration string) (PermanentBlockRecord, bool, error) {
	if db == nil {
		return PermanentBlockRecord{}, false, errors.New("storage not initialised")
	}
	if ip == "" || integration == "" {
		return PermanentBlockRecord{}, false, errors.New("ip and integration are required")
	}

	row := db.QueryRowContext(ctx, `
SELECT id, ip, integration, status, details, message, server_id, created_at, updated_at
FROM permanent_blocks
WHERE ip = ? AND integration = ?`, ip, integration)

	var rec PermanentBlockRecord
	var createdAt, updatedAt sql.NullString
	if err := row.Scan(&rec.ID, &rec.IP, &rec.Integration, &rec.Status, &rec.Details, &rec.Message, &rec.ServerID, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PermanentBlockRecord{}, false, nil
		}
		return PermanentBlockRecord{}, false, err
	}
	if createdAt.Valid {
		if ts, err := time.Parse(time.RFC3339Nano, createdAt.String); err == nil {
			rec.CreatedAt = ts
		}
	}
	if updatedAt.Valid {
		if ts, err := time.Parse(time.RFC3339Nano, updatedAt.String); err == nil {
			rec.UpdatedAt = ts
		}
	}
	return rec, true, nil
}

// Returns recent permanent block entries.
func ListPermanentBlocks(ctx context.Context, limit int) ([]PermanentBlockRecord, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	rows, err := db.QueryContext(ctx, `
SELECT id, ip, integration, status, details, message, server_id, created_at, updated_at
FROM permanent_blocks
ORDER BY updated_at DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []PermanentBlockRecord
	for rows.Next() {
		var rec PermanentBlockRecord
		var createdAt, updatedAt sql.NullString
		if err := rows.Scan(&rec.ID, &rec.IP, &rec.Integration, &rec.Status, &rec.Details, &rec.Message, &rec.ServerID, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		if createdAt.Valid {
			if ts, err := time.Parse(time.RFC3339Nano, createdAt.String); err == nil {
				rec.CreatedAt = ts
			}
		}
		if updatedAt.Valid {
			if ts, err := time.Parse(time.RFC3339Nano, updatedAt.String); err == nil {
				rec.UpdatedAt = ts
			}
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// Returns true when IP is currently blocked by integration.
func IsPermanentBlockActive(ctx context.Context, ip, integration string) (bool, error) {
	rec, found, err := GetPermanentBlock(ctx, ip, integration)
	if err != nil || !found {
		return false, err
	}
	return rec.Status == "blocked", nil
}

// Deletes all permanent block records.
func ClearPermanentBlocks(ctx context.Context) (int64, error) {
	if db == nil {
		return 0, errors.New("storage not initialised")
	}
	res, err := db.ExecContext(ctx, `DELETE FROM permanent_blocks`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
