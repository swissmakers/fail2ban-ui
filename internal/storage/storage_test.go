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
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRestrictDatabasePermissions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	if err := os.WriteFile(dbPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	restrictDatabasePermissions(dbPath)
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("db perm = %o, want 600", perm)
	}
}

func initTestStorage(t *testing.T) {
	t.Helper()

	if db != nil {
		_ = db.Close()
	}
	db = nil
	initOnce = sync.Once{}
	initErr = nil

	dbPath := filepath.Join(t.TempDir(), "fail2ban-ui-test.db")
	if err := Init(dbPath); err != nil {
		t.Fatalf("Init: %v", err)
	}

	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
		db = nil
		initOnce = sync.Once{}
		initErr = nil
	})
}

func TestEnsureSchemaMigratesLegacyBanEvents(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fail2ban-ui-legacy.db")
	legacy, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	const legacySchema = `
CREATE TABLE ban_events (
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
	occurred_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL
);`
	if _, err := legacy.Exec(legacySchema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	if _, err := legacy.Exec(
		`INSERT INTO ban_events (server_id, server_name, jail, ip, occurred_at, created_at)
		 VALUES ('local', 'Local', 'sshd', '203.0.113.7', '2026-01-02 03:04:05', '2026-01-02 03:04:05')`,
	); err != nil {
		t.Fatalf("insert legacy row: %v", err)
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

	var eventType string
	if err := db.QueryRow(`SELECT event_type FROM ban_events WHERE ip = '203.0.113.7'`).Scan(&eventType); err != nil {
		t.Fatalf("read migrated event_type: %v", err)
	}
	if eventType != "ban" {
		t.Fatalf("migrated event_type = %q, want %q", eventType, "ban")
	}

	var indexName string
	if err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_ban_events_occurred_at_ip'`,
	).Scan(&indexName); err != nil {
		t.Fatalf("index idx_ban_events_occurred_at_ip missing after migration: %v", err)
	}
}

func TestReplaceServersRoundTrip(t *testing.T) {
	initTestStorage(t)

	ctx := context.Background()
	want := ServerRecord{
		ID:                   "srv-1",
		Name:                 "Remote via SSH",
		Type:                 "ssh",
		Host:                 "203.0.113.10",
		Port:                 22,
		SSHUser:              "fail2ban",
		SSHKeyPath:           "/config/.ssh/id_ed25519",
		TagsJSON:             `["prod"]`,
		IsDefault:            true,
		Enabled:              true,
		ReverseTunnelEnabled: true,
		CreatedAt:            time.Date(2026, 5, 27, 14, 30, 0, 0, time.UTC),
		UpdatedAt:            time.Date(2026, 5, 27, 15, 0, 0, 0, time.UTC),
	}

	if err := ReplaceServers(ctx, []ServerRecord{want}); err != nil {
		t.Fatalf("ReplaceServers: %v", err)
	}
	records, err := ListServers(ctx)
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records)=%d want 1", len(records))
	}
	got := records[0]
	if got != want {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestBanEventsFTSSearchAndEnrichment(t *testing.T) {
	initTestStorage(t)
	if !ftsAvailable {
		t.Fatal("FTS index not available in fresh database")
	}

	ctx := context.Background()
	id1, err := RecordBanEvent(ctx, BanEventRecord{
		ServerID: "srv-1", ServerName: "web frontend", Jail: "swissmakers-nextcloud",
		IP: "203.0.113.45", Country: "UA", EventType: "ban",
	})
	if err != nil || id1 <= 0 {
		t.Fatalf("RecordBanEvent: id=%d err=%v", id1, err)
	}
	id2, err := RecordBanEvent(ctx, BanEventRecord{
		ServerID: "srv-2", ServerName: "mail relay", Jail: "postfix-sasl",
		IP: "198.51.100.7", EventType: "ban",
	})
	if err != nil || id2 <= 0 {
		t.Fatalf("RecordBanEvent: id=%d err=%v", id2, err)
	}

	searchTotal := func(term string) int64 {
		t.Helper()
		total, err := CountBanEventsFiltered(ctx, BanEventFilter{Search: term})
		if err != nil {
			t.Fatalf("CountBanEventsFiltered(%q): %v", term, err)
		}
		return total
	}

	// Full word, word prefix, and IP fragment must all match via FTS
	for term, want := range map[string]int64{
		"nextcloud":   1,
		"next":        1,
		"203.0.113":   1,
		"mail":        1,
		"nosuchthing": 0,
	} {
		if got := searchTotal(term); got != want {
			t.Fatalf("search %q total=%d want %d", term, got, want)
		}
	}

	events, err := ListBanEventsFiltered(ctx, BanEventFilter{Search: "nextcloud"}, 10, 0)
	if err != nil || len(events) != 1 || events[0].IP != "203.0.113.45" {
		t.Fatalf("ListBanEventsFiltered(nextcloud) = %+v, err=%v", events, err)
	}

	// Enrichment fills whois and country; the country change must reach FTS.
	if err := UpdateBanEventEnrichment(ctx, id2, "netname: EXAMPLE-NET", "BR"); err != nil {
		t.Fatalf("UpdateBanEventEnrichment: %v", err)
	}
	rec, found, err := GetBanEventByID(ctx, id2)
	if err != nil || !found || rec.Whois != "netname: EXAMPLE-NET" || rec.Country != "BR" {
		t.Fatalf("enriched record = %+v found=%v err=%v", rec, found, err)
	}
	if got := searchTotal("BR"); got != 1 {
		t.Fatalf("search after country update total=%d want 1", got)
	}
	// Empty country must not overwrite an existing one.
	if err := UpdateBanEventEnrichment(ctx, id1, "whois text", ""); err != nil {
		t.Fatalf("UpdateBanEventEnrichment: %v", err)
	}
	if rec, _, _ := GetBanEventByID(ctx, id1); rec.Country != "UA" {
		t.Fatalf("country overwritten by empty enrichment: %q", rec.Country)
	}

	// Deletes (retention prune) must drop rows from the FTS index too.
	if _, err := PruneBanEventsBefore(ctx, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("PruneBanEventsBefore: %v", err)
	}
	if got := searchTotal("nextcloud"); got != 0 {
		t.Fatalf("search after prune total=%d want 0", got)
	}

	countries, err := ListBanEventCountries(ctx)
	if err != nil {
		t.Fatalf("ListBanEventCountries: %v", err)
	}
	if len(countries) != 0 {
		t.Fatalf("countries after prune = %v, want empty", countries)
	}
}

// Reproduces the production scenario: ban_events already holds rows when the
// FTS index is first created. The index must be backfilled (counting the fts
// table itself reads the content table and always matches the docsize
// shadow table is the real indicator), and deletes must not corrupt it.
func TestBanEventsFTSBackfillsExistingRows(t *testing.T) {
	initTestStorage(t)
	ctx := context.Background()

	// Simulate a pre-FTS database, drop the index and triggers, then insert.
	for _, stmt := range []string{
		`DROP TRIGGER ban_events_fts_ai`,
		`DROP TRIGGER ban_events_fts_ad`,
		`DROP TRIGGER ban_events_fts_au`,
		`DROP TABLE ban_events_fts`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	ftsAvailable = false
	if _, err := RecordBanEvent(ctx, BanEventRecord{
		ServerID: "srv-1", ServerName: "legacy box", Jail: "sshd",
		IP: "192.0.2.99", Country: "DE", EventType: "ban",
		OccurredAt: time.Now().UTC().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("RecordBanEvent: %v", err)
	}

	ensureBanEventsFTS(ctx)
	if !ftsAvailable {
		t.Fatal("FTS not available after ensureBanEventsFTS")
	}

	total, err := CountBanEventsFiltered(ctx, BanEventFilter{Search: "legacy"})
	if err != nil || total != 1 {
		t.Fatalf("search for pre-existing row: total=%d err=%v (backfill missing)", total, err)
	}
	// Deleting the backfilled row must work (this failed with CORRUPT_VTAB
	// when the index was empty while the delete trigger fired).
	deleted, err := PruneBanEventsBefore(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("PruneBanEventsBefore on backfilled index: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("pruned %d rows, want 1", deleted)
	}
}

func TestCountRecentBanEventsByJail(t *testing.T) {
	initTestStorage(t)

	ctx := context.Background()
	now := time.Date(2026, 5, 27, 14, 30, 0, 123456789, time.UTC)
	since := now.Add(-1 * time.Hour)

	events := []BanEventRecord{
		{ServerID: "srv-1", ServerName: "server 1", Jail: "sshd", IP: "192.0.2.10", EventType: "ban", OccurredAt: now.Add(-10 * time.Minute)},
		{ServerID: "srv-1", ServerName: "server 1", Jail: "sshd", IP: "192.0.2.11", EventType: "ban", OccurredAt: now.Add(-2 * time.Hour)},
		{ServerID: "srv-1", ServerName: "server 1", Jail: "sshd", IP: "192.0.2.12", EventType: "unban", OccurredAt: now.Add(-5 * time.Minute)},
		{ServerID: "srv-1", ServerName: "server 1", Jail: "nginx", IP: "192.0.2.13", EventType: "ban", OccurredAt: now.Add(-5 * time.Minute)},
		{ServerID: "srv-2", ServerName: "server 2", Jail: "sshd", IP: "192.0.2.14", EventType: "ban", OccurredAt: now.Add(-5 * time.Minute)},
	}
	for _, event := range events {
		if _, err := RecordBanEvent(ctx, event); err != nil {
			t.Fatalf("RecordBanEvent: %v", err)
		}
	}

	got, err := CountRecentBanEventsByJail(ctx, "srv-1", since)
	if err != nil {
		t.Fatalf("CountRecentBanEventsByJail: %v", err)
	}
	if got["sshd"] != 1 {
		t.Fatalf("recent ban count=%d want 1", got["sshd"])
	}
}

func TestRecordBanEventUsesSortableStorageTime(t *testing.T) {
	initTestStorage(t)

	ctx := context.Background()
	occurredAt := time.Date(2026, 5, 27, 14, 27, 38, 369492374, time.UTC)
	event := BanEventRecord{
		ServerID:   "srv-1",
		ServerName: "server 1",
		Jail:       "sshd",
		IP:         "192.0.2.10",
		EventType:  "ban",
		OccurredAt: occurredAt,
	}
	if _, err := RecordBanEvent(ctx, event); err != nil {
		t.Fatalf("RecordBanEvent: %v", err)
	}

	var rawOccurredAt string
	if err := db.QueryRowContext(ctx, `SELECT occurred_at FROM ban_events WHERE server_id = ? AND jail = ?`, "srv-1", "sshd").Scan(&rawOccurredAt); err != nil {
		t.Fatalf("query occurred_at: %v", err)
	}
	if want := formatStorageTime(occurredAt); rawOccurredAt != want {
		t.Fatalf("occurred_at=%q want %q", rawOccurredAt, want)
	}

	got, err := CountRecentBanEventsByJail(ctx, "srv-1", occurredAt.Add(-time.Minute))
	if err != nil {
		t.Fatalf("CountRecentBanEventsByJail: %v", err)
	}
	if got["sshd"] != 1 {
		t.Fatalf("recent ban count=%d want 1", got["sshd"])
	}
}

func TestListBanEventsFilteredOmitsHeavyFields(t *testing.T) {
	initTestStorage(t)

	ctx := context.Background()
	now := time.Now().UTC()
	withDetail := BanEventRecord{
		ServerID:   "srv-1",
		ServerName: "server 1",
		Jail:       "sshd",
		IP:         "192.0.2.10",
		EventType:  "ban",
		Whois:      "whois block for 192.0.2.10",
		Logs:       "Jan  1 00:00:00 sshd failed login",
		OccurredAt: now.Add(-1 * time.Minute),
	}
	withoutDetail := BanEventRecord{
		ServerID:   "srv-1",
		ServerName: "server 1",
		Jail:       "sshd",
		IP:         "192.0.2.11",
		EventType:  "ban",
		OccurredAt: now.Add(-2 * time.Minute),
	}
	for _, event := range []BanEventRecord{withDetail, withoutDetail} {
		if _, err := RecordBanEvent(ctx, event); err != nil {
			t.Fatalf("RecordBanEvent: %v", err)
		}
	}

	events, err := ListBanEventsFiltered(ctx, BanEventFilter{ServerID: "srv-1"}, 50, 0)
	if err != nil {
		t.Fatalf("ListBanEventsFiltered: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events want 2", len(events))
	}

	var detailID int64
	for _, ev := range events {
		if ev.Whois != "" || ev.Logs != "" {
			t.Fatalf("list event should omit whois/logs, got whois=%q logs=%q", ev.Whois, ev.Logs)
		}
		switch ev.IP {
		case "192.0.2.10":
			detailID = ev.ID
			if !ev.HasWhois || !ev.HasLogs {
				t.Fatalf("event %s should report hasWhois/hasLogs true", ev.IP)
			}
		case "192.0.2.11":
			if ev.HasWhois || ev.HasLogs {
				t.Fatalf("event %s should report hasWhois/hasLogs false", ev.IP)
			}
		}
	}

	full, found, err := GetBanEventByID(ctx, detailID)
	if err != nil {
		t.Fatalf("GetBanEventByID: %v", err)
	}
	if !found {
		t.Fatalf("GetBanEventByID: event %d not found", detailID)
	}
	if full.Whois != withDetail.Whois || full.Logs != withDetail.Logs {
		t.Fatalf("detail mismatch: whois=%q logs=%q", full.Whois, full.Logs)
	}
	if !full.HasWhois || !full.HasLogs {
		t.Fatalf("detail should report hasWhois/hasLogs true")
	}

	if _, found, err := GetBanEventByID(ctx, 999999); err != nil {
		t.Fatalf("GetBanEventByID(missing): %v", err)
	} else if found {
		t.Fatalf("GetBanEventByID(missing): expected not found")
	}
}

func TestMigrateLegacyTimestampsNormalizesAndFilters(t *testing.T) {
	initTestStorage(t)

	ctx := context.Background()
	_, err := db.ExecContext(ctx, `
INSERT INTO ban_events (server_id, server_name, jail, ip, event_type, occurred_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"srv-1",
		"server 1",
		"sshd",
		"192.0.2.10",
		"ban",
		"2026-05-27 14:27:38.369492374 +0000 UTC",
		"2026-05-27 14:27:38.369492374 +0000 UTC",
	)
	if err != nil {
		t.Fatalf("insert legacy event: %v", err)
	}

	if err := migrateLegacyTimestamps(ctx); err != nil {
		t.Fatalf("migrateLegacyTimestamps: %v", err)
	}

	var occurredAt, createdAt string
	if err := db.QueryRowContext(ctx, `SELECT occurred_at, created_at FROM ban_events WHERE server_id = 'srv-1'`).Scan(&occurredAt, &createdAt); err != nil {
		t.Fatalf("select migrated row: %v", err)
	}
	want := "2026-05-27T14:27:38.369492374Z"
	if occurredAt != want || createdAt != want {
		t.Fatalf("migrated timestamps = %q / %q, want %q", occurredAt, createdAt, want)
	}

	// The migrated row must now be found by the plain since filter.
	since := time.Date(2026, 5, 27, 13, 30, 0, 0, time.UTC)
	got, err := CountRecentBanEventsByJail(ctx, "srv-1", since)
	if err != nil {
		t.Fatalf("CountRecentBanEventsByJail: %v", err)
	}
	if got["sshd"] != 1 {
		t.Fatalf("recent ban count=%d want 1", got["sshd"])
	}
	got, err = CountRecentBanEventsByJail(ctx, "srv-1", since.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("CountRecentBanEventsByJail: %v", err)
	}
	if got["sshd"] != 0 {
		t.Fatalf("recent ban count=%d want 0 for later since", got["sshd"])
	}
}

func TestBanEventFilterUntilIsExclusive(t *testing.T) {
	initTestStorage(t)

	ctx := context.Background()
	cutoff := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	for i, occurredAt := range []time.Time{
		cutoff.Add(-time.Minute),
		cutoff,
		cutoff.Add(time.Minute),
	} {
		if _, err := RecordBanEvent(ctx, BanEventRecord{
			ServerID: "srv-1", ServerName: "server 1", Jail: "sshd",
			IP: "192.0.2.10", EventType: "ban", OccurredAt: occurredAt,
		}); err != nil {
			t.Fatalf("RecordBanEvent %d: %v", i, err)
		}
	}

	filter := BanEventFilter{Since: cutoff.Add(-time.Hour), Until: cutoff}
	total, err := CountBanEventsFiltered(ctx, filter)
	if err != nil {
		t.Fatalf("CountBanEventsFiltered: %v", err)
	}
	if total != 1 {
		t.Fatalf("count with until=%v is %d, want 1 (until must be exclusive)", cutoff, total)
	}
	events, err := ListBanEventsFiltered(ctx, filter, 10, 0)
	if err != nil || len(events) != 1 {
		t.Fatalf("ListBanEventsFiltered = %d events, err=%v, want 1", len(events), err)
	}
}

func TestBanEventTimelineBucketsAndZeroFill(t *testing.T) {
	initTestStorage(t)

	ctx := context.Background()
	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	events := []BanEventRecord{
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.1", EventType: "ban", OccurredAt: base.Add(5 * time.Minute)},
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.2", EventType: "ban", OccurredAt: base.Add(30 * time.Minute)},
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.1", EventType: "unban", OccurredAt: base.Add(40 * time.Minute)},
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.3", EventType: "ban", OccurredAt: base.Add(2*time.Hour + 10*time.Minute)},
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.4", EventType: "ban", OccurredAt: base.Add(4 * time.Hour)},
	}
	for i, event := range events {
		if _, err := RecordBanEvent(ctx, event); err != nil {
			t.Fatalf("RecordBanEvent %d: %v", i, err)
		}
	}

	filter := BanEventFilter{Since: base, Until: base.Add(3 * time.Hour)}
	buckets, err := BanEventTimeline(ctx, filter, 3600)
	if err != nil {
		t.Fatalf("BanEventTimeline: %v", err)
	}
	if len(buckets) != 3 {
		t.Fatalf("got %d buckets, want 3 (zero-filled)", len(buckets))
	}
	if !buckets[0].Start.Equal(base) {
		t.Fatalf("bucket[0].Start=%v want %v", buckets[0].Start, base)
	}
	if buckets[0].Bans != 2 || buckets[0].Unbans != 1 {
		t.Fatalf("bucket[0] = %+v, want bans=2 unbans=1", buckets[0])
	}
	if buckets[1].Bans != 0 || buckets[1].Unbans != 0 {
		t.Fatalf("bucket[1] = %+v, want zero-filled empty bucket", buckets[1])
	}
	if buckets[2].Bans != 1 || buckets[2].Unbans != 0 {
		t.Fatalf("bucket[2] = %+v, want bans=1", buckets[2])
	}
}

func TestListBanEventIPsAggregatesAndTruncates(t *testing.T) {
	initTestStorage(t)

	ctx := context.Background()
	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	events := []BanEventRecord{
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.1", Country: "DE", EventType: "ban", OccurredAt: base},
		{ServerID: "srv-1", ServerName: "s1", Jail: "nginx", IP: "192.0.2.1", Country: "DE", EventType: "ban", OccurredAt: base.Add(10 * time.Minute)},
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.1", EventType: "unban", OccurredAt: base.Add(20 * time.Minute)}, // not counted
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "198.51.100.7", Country: "BR", EventType: "ban", OccurredAt: base.Add(5 * time.Minute)},
	}
	for i, event := range events {
		if _, err := RecordBanEvent(ctx, event); err != nil {
			t.Fatalf("RecordBanEvent %d: %v", i, err)
		}
	}

	filter := BanEventFilter{Since: base.Add(-time.Hour), Until: base.Add(time.Hour)}
	stats, total, err := ListBanEventIPs(ctx, filter, 10)
	if err != nil {
		t.Fatalf("ListBanEventIPs: %v", err)
	}
	if total != 2 || len(stats) != 2 {
		t.Fatalf("total=%d len=%d, want 2/2", total, len(stats))
	}
	top := stats[0]
	if top.IP != "192.0.2.1" || top.Count != 2 || top.Country != "DE" {
		t.Fatalf("top stat = %+v, want 192.0.2.1 count=2 country=DE (unban must not count)", top)
	}
	if !top.FirstSeen.Equal(base) || !top.LastSeen.Equal(base.Add(10*time.Minute)) {
		t.Fatalf("first/last seen = %v / %v", top.FirstSeen, top.LastSeen)
	}
	if top.Jails != "sshd,nginx" && top.Jails != "nginx,sshd" {
		t.Fatalf("jails = %q, want both sshd and nginx", top.Jails)
	}

	// limit=1 truncates but reports the full distinct count
	stats, total, err = ListBanEventIPs(ctx, filter, 1)
	if err != nil || len(stats) != 1 || total != 2 {
		t.Fatalf("truncated: len=%d total=%d err=%v, want 1/2", len(stats), total, err)
	}
}

func TestListBanEventIPActivityFindsOverlappingDays(t *testing.T) {
	initTestStorage(t)

	ctx := context.Background()
	incident := time.Date(2026, 6, 10, 8, 0, 0, 0, time.UTC)
	earlier := time.Date(2026, 4, 15, 20, 0, 0, 0, time.UTC)
	events := []BanEventRecord{
		// current incident: 3 IPs
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.1", EventType: "ban", OccurredAt: incident},
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.2", EventType: "ban", OccurredAt: incident.Add(time.Minute)},
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.3", EventType: "ban", OccurredAt: incident.Add(2 * time.Minute)},
		// two months earlier: 2 of the same IPs plus an unrelated one
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.1", EventType: "ban", OccurredAt: earlier},
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.2", EventType: "ban", OccurredAt: earlier.Add(time.Minute)},
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "203.0.113.9", EventType: "ban", OccurredAt: earlier.Add(2 * time.Minute)},
	}
	for i, event := range events {
		if _, err := RecordBanEvent(ctx, event); err != nil {
			t.Fatalf("RecordBanEvent %d: %v", i, err)
		}
	}

	filter := BanEventFilter{Since: incident.Add(-time.Hour), Until: incident.Add(time.Hour)}
	periods, err := ListBanEventIPActivity(ctx, filter, 2)
	if err != nil {
		t.Fatalf("ListBanEventIPActivity: %v", err)
	}
	if len(periods) != 1 {
		t.Fatalf("got %d periods, want 1: %+v", len(periods), periods)
	}
	if periods[0].Day != "2026-04-15" || periods[0].Overlap != 2 || periods[0].Events != 2 {
		t.Fatalf("period = %+v, want day=2026-04-15 overlap=2 events=2", periods[0])
	}

	periods, err = ListBanEventIPActivity(ctx, filter, 3)
	if err != nil || len(periods) != 0 {
		t.Fatalf("minOverlap=3: got %d periods err=%v, want 0", len(periods), err)
	}
}

func TestCountBanEventTotals(t *testing.T) {
	initTestStorage(t)

	ctx := context.Background()
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	events := []BanEventRecord{
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.1", EventType: "ban", OccurredAt: now.Add(-time.Hour)},           // today+week
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.2", EventType: "ban", OccurredAt: now.Add(-3 * 24 * time.Hour)},  // week
		{ServerID: "srv-1", ServerName: "s1", Jail: "sshd", IP: "192.0.2.3", EventType: "ban", OccurredAt: now.Add(-30 * 24 * time.Hour)}, // overall only
		{ServerID: "srv-2", ServerName: "s2", Jail: "sshd", IP: "192.0.2.4", EventType: "ban", OccurredAt: now.Add(-time.Hour)},
	}
	for i, event := range events {
		if _, err := RecordBanEvent(ctx, event); err != nil {
			t.Fatalf("RecordBanEvent %d: %v", i, err)
		}
	}

	overall, today, week, err := CountBanEventTotals(ctx, "", now)
	if err != nil {
		t.Fatalf("CountBanEventTotals: %v", err)
	}
	if overall != 4 || today != 2 || week != 3 {
		t.Fatalf("totals = %d/%d/%d, want 4/2/3", overall, today, week)
	}

	overall, today, week, err = CountBanEventTotals(ctx, "srv-1", now)
	if err != nil {
		t.Fatalf("CountBanEventTotals(srv-1): %v", err)
	}
	if overall != 3 || today != 1 || week != 2 {
		t.Fatalf("srv-1 totals = %d/%d/%d, want 3/1/2", overall, today, week)
	}
}
