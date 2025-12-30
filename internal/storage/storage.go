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

var (
	db          *sql.DB
	initOnce    sync.Once
	initErr     error
	defaultPath = "fail2ban-ui.db"
)

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

type AppSettingsRecord struct {
	// Basic app settings
	Language      string
	Port          int
	Debug         bool
	RestartNeeded bool
	// Callback settings
	CallbackURL    string
	CallbackSecret string
	// Alert settings
	AlertCountriesJSON   string
	EmailAlertsForBans   bool
	EmailAlertsForUnbans bool
	// SMTP settings
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
	SMTPUseTLS   bool
	// Fail2Ban DEFAULT settings
	BantimeIncrement  bool
	DefaultJailEnable bool
	IgnoreIP          string // Stored as space-separated string, converted to array in AppSettings
	Bantime           string
	Findtime          string
	MaxRetry          int
	DestEmail         string
	Banaction         string
	BanactionAllports string
	// Advanced features
	AdvancedActionsJSON string
	GeoIPProvider       string
	GeoIPDatabasePath   string
	MaxLogLines         int
}

type ServerRecord struct {
	ID           string
	Name         string
	Type         string
	Host         string
	Port         int
	SocketPath   string
	LogPath      string
	SSHUser      string
	SSHKeyPath   string
	AgentURL     string
	AgentSecret  string
	Hostname     string
	TagsJSON     string
	IsDefault    bool
	Enabled      bool
	NeedsRestart bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// BanEventRecord represents a single ban or unban event stored in the internal database.
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
	EventType  string    `json:"eventType"`
	OccurredAt time.Time `json:"occurredAt"`
	CreatedAt  time.Time `json:"createdAt"`
}

// RecurringIPStat represents aggregation info for repeatedly banned IPs.
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

// Init initializes the internal storage. Safe to call multiple times.
func Init(dbPath string) error {
	initOnce.Do(func() {
		if dbPath == "" {
			dbPath = defaultPath
		}
		if err := ensureDirectory(dbPath); err != nil {
			initErr = err
			return
		}

		// Ensure .ssh directory exists (for SSH key storage)
		if err := ensureSSHDirectory(); err != nil {
			// Log but don't fail - .ssh directory creation is not critical
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

		initErr = ensureSchema(context.Background())
	})
	return initErr
}

// Close closes the underlying database if it has been initialised.
func Close() error {
	if db == nil {
		return nil
	}
	return db.Close()
}

func GetAppSettings(ctx context.Context) (AppSettingsRecord, bool, error) {
	if db == nil {
		return AppSettingsRecord{}, false, errors.New("storage not initialised")
	}

	row := db.QueryRowContext(ctx, `
SELECT language, port, debug, restart_needed, callback_url, callback_secret, alert_countries, email_alerts_for_bans, email_alerts_for_unbans, smtp_host, smtp_port, smtp_username, smtp_password, smtp_from, smtp_use_tls, bantime_increment, default_jail_enable, ignore_ip, bantime, findtime, maxretry, destemail, banaction, banaction_allports, advanced_actions, geoip_provider, geoip_database_path, max_log_lines
FROM app_settings
WHERE id = 1`)

	var (
		lang, callback, callbackSecret, alerts, smtpHost, smtpUser, smtpPass, smtpFrom, ignoreIP, bantime, findtime, destemail, banaction, banactionAllports, advancedActions, geoipProvider, geoipDatabasePath sql.NullString
		port, smtpPort, maxretry, maxLogLines                                                                                                                                                                   sql.NullInt64
		debug, restartNeeded, smtpTLS, bantimeInc, defaultJailEn, emailAlertsForBans, emailAlertsForUnbans                                                                                                      sql.NullInt64
	)

	err := row.Scan(&lang, &port, &debug, &restartNeeded, &callback, &callbackSecret, &alerts, &emailAlertsForBans, &emailAlertsForUnbans, &smtpHost, &smtpPort, &smtpUser, &smtpPass, &smtpFrom, &smtpTLS, &bantimeInc, &defaultJailEn, &ignoreIP, &bantime, &findtime, &maxretry, &destemail, &banaction, &banactionAllports, &advancedActions, &geoipProvider, &geoipDatabasePath, &maxLogLines)
	if errors.Is(err, sql.ErrNoRows) {
		return AppSettingsRecord{}, false, nil
	}
	if err != nil {
		return AppSettingsRecord{}, false, err
	}

	rec := AppSettingsRecord{
		// Basic app settings
		Language:      stringFromNull(lang),
		Port:          intFromNull(port),
		Debug:         intToBool(intFromNull(debug)),
		RestartNeeded: intToBool(intFromNull(restartNeeded)),
		// Callback settings
		CallbackURL:    stringFromNull(callback),
		CallbackSecret: stringFromNull(callbackSecret),
		// Alert settings
		AlertCountriesJSON:   stringFromNull(alerts),
		EmailAlertsForBans:   intToBool(intFromNull(emailAlertsForBans)),
		EmailAlertsForUnbans: intToBool(intFromNull(emailAlertsForUnbans)),
		// SMTP settings
		SMTPHost:     stringFromNull(smtpHost),
		SMTPPort:     intFromNull(smtpPort),
		SMTPUsername: stringFromNull(smtpUser),
		SMTPPassword: stringFromNull(smtpPass),
		SMTPFrom:     stringFromNull(smtpFrom),
		SMTPUseTLS:   intToBool(intFromNull(smtpTLS)),
		// Fail2Ban DEFAULT settings
		BantimeIncrement:  intToBool(intFromNull(bantimeInc)),
		DefaultJailEnable: intToBool(intFromNull(defaultJailEn)),
		IgnoreIP:          stringFromNull(ignoreIP),
		Bantime:           stringFromNull(bantime),
		Findtime:          stringFromNull(findtime),
		MaxRetry:          intFromNull(maxretry),
		DestEmail:         stringFromNull(destemail),
		Banaction:         stringFromNull(banaction),
		BanactionAllports: stringFromNull(banactionAllports),
		// Advanced features
		AdvancedActionsJSON: stringFromNull(advancedActions),
		GeoIPProvider:       stringFromNull(geoipProvider),
		GeoIPDatabasePath:   stringFromNull(geoipDatabasePath),
		MaxLogLines:         intFromNull(maxLogLines),
	}

	return rec, true, nil
}

func SaveAppSettings(ctx context.Context, rec AppSettingsRecord) error {
	if db == nil {
		return errors.New("storage not initialised")
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO app_settings (
	id, language, port, debug, restart_needed, callback_url, callback_secret, alert_countries, email_alerts_for_bans, email_alerts_for_unbans, smtp_host, smtp_port, smtp_username, smtp_password, smtp_from, smtp_use_tls, bantime_increment, default_jail_enable, ignore_ip, bantime, findtime, maxretry, destemail, banaction, banaction_allports, advanced_actions, geoip_provider, geoip_database_path, max_log_lines
) VALUES (
	1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
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
	max_log_lines = excluded.max_log_lines
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
	)
	return err
}

func ListServers(ctx context.Context) ([]ServerRecord, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}

	rows, err := db.QueryContext(ctx, `
SELECT id, name, type, host, port, socket_path, log_path, ssh_user, ssh_key_path, agent_url, agent_secret, hostname, tags, is_default, enabled, needs_restart, created_at, updated_at
FROM servers
ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ServerRecord
	for rows.Next() {
		var rec ServerRecord
		var host, socket, logPath, sshUser, sshKey, agentURL, agentSecret, hostname, tags sql.NullString
		var name, serverType sql.NullString
		var created, updated sql.NullString
		var port sql.NullInt64
		var isDefault, enabled, needsRestart sql.NullInt64

		if err := rows.Scan(
			&rec.ID,
			&name,
			&serverType,
			&host,
			&port,
			&socket,
			&logPath,
			&sshUser,
			&sshKey,
			&agentURL,
			&agentSecret,
			&hostname,
			&tags,
			&isDefault,
			&enabled,
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
		rec.LogPath = stringFromNull(logPath)
		rec.SSHUser = stringFromNull(sshUser)
		rec.SSHKeyPath = stringFromNull(sshKey)
		rec.AgentURL = stringFromNull(agentURL)
		rec.AgentSecret = stringFromNull(agentSecret)
		rec.Hostname = stringFromNull(hostname)
		rec.TagsJSON = stringFromNull(tags)
		rec.IsDefault = intToBool(intFromNull(isDefault))
		rec.Enabled = intToBool(intFromNull(enabled))
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
	id, name, type, host, port, socket_path, log_path, ssh_user, ssh_key_path, agent_url, agent_secret, hostname, tags, is_default, enabled, needs_restart, created_at, updated_at
) VALUES (
	?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
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
			srv.LogPath,
			srv.SSHUser,
			srv.SSHKeyPath,
			srv.AgentURL,
			srv.AgentSecret,
			srv.Hostname,
			srv.TagsJSON,
			boolToInt(srv.IsDefault),
			boolToInt(srv.Enabled),
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

func DeleteServer(ctx context.Context, id string) error {
	if db == nil {
		return errors.New("storage not initialised")
	}
	_, err := db.ExecContext(ctx, `DELETE FROM servers WHERE id = ?`, id)
	return err
}

// RecordBanEvent stores a ban event in the database.
func RecordBanEvent(ctx context.Context, record BanEventRecord) error {
	if db == nil {
		return errors.New("storage not initialised")
	}

	if record.ServerID == "" {
		return errors.New("server id is required")
	}
	now := time.Now().UTC()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	if record.OccurredAt.IsZero() {
		record.OccurredAt = now
	}

	// Default to 'ban' if event type is not set
	eventType := record.EventType
	if eventType == "" {
		eventType = "ban"
	}

	const query = `
INSERT INTO ban_events (
	server_id, server_name, jail, ip, country, hostname, failures, whois, logs, event_type, occurred_at, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.ExecContext(
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
		record.OccurredAt.UTC(),
		record.CreatedAt.UTC(),
	)
	if err != nil {
		return err
	}

	return nil
}

// ListBanEvents returns ban events ordered by creation date descending.
func ListBanEvents(ctx context.Context, serverID string, limit int, since time.Time) ([]BanEventRecord, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}

	if limit <= 0 || limit > 500 {
		limit = 100
	}

	baseQuery := `
SELECT id, server_id, server_name, jail, ip, country, hostname, failures, whois, logs, event_type, occurred_at, created_at
FROM ban_events
WHERE 1=1`

	args := []any{}
	if serverID != "" {
		baseQuery += " AND server_id = ?"
		args = append(args, serverID)
	}
	if !since.IsZero() {
		baseQuery += " AND occurred_at >= ?"
		args = append(args, since.UTC())
	}

	baseQuery += " ORDER BY occurred_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []BanEventRecord
	for rows.Next() {
		var rec BanEventRecord
		var eventType sql.NullString
		if err := rows.Scan(
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
		); err != nil {
			return nil, err
		}
		// Default to 'ban' if event_type is NULL (for backward compatibility)
		if eventType.Valid {
			rec.EventType = eventType.String
		} else {
			rec.EventType = "ban"
		}
		results = append(results, rec)
	}

	return results, rows.Err()
}

// CountBanEventsByServer returns simple aggregation per server.
func CountBanEventsByServer(ctx context.Context, since time.Time) (map[string]int64, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}

	query := `
SELECT server_id, COUNT(*) 
FROM ban_events
WHERE 1=1`
	args := []any{}

	if !since.IsZero() {
		query += " AND occurred_at >= ?"
		args = append(args, since.UTC())
	}

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

// CountBanEvents returns total number of ban events optionally filtered by time and server.
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

	if !since.IsZero() {
		query += " AND occurred_at >= ?"
		args = append(args, since.UTC())
	}

	var total int64
	if err := db.QueryRowContext(ctx, query, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// CountBanEventsByIP returns total number of ban events for a specific IP and optional server.
func CountBanEventsByIP(ctx context.Context, ip, serverID string) (int64, error) {
	if db == nil {
		return 0, errors.New("storage not initialised")
	}
	if ip == "" {
		return 0, errors.New("ip is required")
	}

	query := `
SELECT COUNT(*)
FROM ban_events
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

// CountBanEventsByCountry returns aggregation per country code, optionally filtered by server.
func CountBanEventsByCountry(ctx context.Context, since time.Time, serverID string) (map[string]int64, error) {
	if db == nil {
		return nil, errors.New("storage not initialised")
	}

	query := `
SELECT COALESCE(country, '') AS country, COUNT(*)
FROM ban_events
WHERE 1=1`
	args := []any{}

	if serverID != "" {
		query += " AND server_id = ?"
		args = append(args, serverID)
	}

	if !since.IsZero() {
		query += " AND occurred_at >= ?"
		args = append(args, since.UTC())
	}

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

// ListRecurringIPStats returns IPs that have been banned at least minCount times, optionally filtered by server.
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

	query := `
SELECT ip, COALESCE(country, '') AS country, COUNT(*) AS cnt, MAX(occurred_at) AS last_seen
FROM ban_events
WHERE ip != '' AND (event_type = 'ban' OR event_type IS NULL)`
	args := []any{}

	if serverID != "" {
		query += " AND server_id = ?"
		args = append(args, serverID)
	}

	if !since.IsZero() {
		query += " AND occurred_at >= ?"
		args = append(args, since.UTC())
	}

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
		// First, scan as string to see what format SQLite returns
		// Then parse it properly
		var lastSeenStr sql.NullString
		if err := rows.Scan(&stat.IP, &stat.Country, &stat.Count, &lastSeenStr); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		if lastSeenStr.Valid && lastSeenStr.String != "" {
			// Try to parse the datetime string
			// SQLite stores DATETIME as TEXT, format depends on how it was inserted
			// The modernc.org/sqlite driver returns MAX(occurred_at) in format:
			// "2006-01-02 15:04:05.999999999 -0700 MST" (e.g., "2025-11-22 12:17:24.697430041 +0000 UTC")
			formats := []string{
				"2006-01-02 15:04:05.999999999 -0700 MST", // Format returned by MAX() in SQLite
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
			parsed := time.Time{} // zero time
			for _, format := range formats {
				if t, parseErr := time.Parse(format, lastSeenStr.String); parseErr == nil {
					parsed = t.UTC()
					break
				}
			}
			// If still zero, log the actual string for debugging
			if parsed.IsZero() {
				log.Printf("ERROR: Could not parse lastSeen datetime '%s' (length: %d) for IP %s. All format attempts failed.", lastSeenStr.String, len(lastSeenStr.String), stat.IP)
			}
			stat.LastSeen = parsed
		} else {
			// Log when lastSeen is NULL or empty
			log.Printf("WARNING: lastSeen is NULL or empty for IP %s", stat.IP)
		}
		results = append(results, stat)
	}

	return results, rows.Err()
}

func ensureSchema(ctx context.Context) error {
	if db == nil {
		return errors.New("storage not initialised")
	}

	const createTable = `
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
	max_log_lines INTEGER
);

CREATE TABLE IF NOT EXISTS servers (
	id TEXT PRIMARY KEY,
	name TEXT,
	type TEXT,
	host TEXT,
	port INTEGER,
	socket_path TEXT,
	log_path TEXT,
	ssh_user TEXT,
	ssh_key_path TEXT,
	agent_url TEXT,
	agent_secret TEXT,
	hostname TEXT,
	tags TEXT,
	is_default INTEGER,
	enabled INTEGER,
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

CREATE INDEX IF NOT EXISTS idx_ban_events_server_id ON ban_events(server_id);
CREATE INDEX IF NOT EXISTS idx_ban_events_occurred_at ON ban_events(occurred_at);

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

CREATE INDEX IF NOT EXISTS idx_perm_blocks_status ON permanent_blocks(status);
`

	if _, err := db.ExecContext(ctx, createTable); err != nil {
		return err
	}

	// NOTE: Database migrations for feature releases
	// For this version, we start with a fresh schema. Future feature releases
	// that require database schema changes should add migration logic here.
	// Example migration pattern:
	//   if _, err := db.ExecContext(ctx, `ALTER TABLE table_name ADD COLUMN new_column TYPE DEFAULT value`); err != nil {
	//     if err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
	//       return err
	//     }
	//   }
	_ = strings.Contains // Keep strings import for migration example above

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

// ensureSSHDirectory ensures the .ssh directory exists for SSH key storage.
// In containers, this is /config/.ssh, on the host it's ~/.ssh
func ensureSSHDirectory() error {
	var sshDir string
	// Check if running inside a container
	if _, container := os.LookupEnv("CONTAINER"); container {
		// In container, use /config/.ssh
		sshDir = "/config/.ssh"
	} else {
		// On host, use ~/.ssh
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory: %w", err)
		}
		sshDir = filepath.Join(home, ".ssh")
	}

	// Create directory with proper permissions (0700 for .ssh)
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return fmt.Errorf("failed to create .ssh directory at %s: %w", sshDir, err)
	}

	return nil
}

// UpsertPermanentBlock records or updates a permanent block entry.
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

// GetPermanentBlock retrieves a permanent block entry.
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

// ListPermanentBlocks returns recent permanent block entries.
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

// IsPermanentBlockActive returns true when IP is currently blocked by integration.
func IsPermanentBlockActive(ctx context.Context, ip, integration string) (bool, error) {
	rec, found, err := GetPermanentBlock(ctx, ip, integration)
	if err != nil || !found {
		return false, err
	}
	return rec.Status == "blocked", nil
}
