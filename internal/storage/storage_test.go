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
		total, err := CountBanEventsFiltered(ctx, "", time.Time{}, term, "")
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

	events, err := ListBanEventsFiltered(ctx, "", 10, 0, time.Time{}, "nextcloud", "")
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

	total, err := CountBanEventsFiltered(ctx, "", time.Time{}, "legacy", "")
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

	events, err := ListBanEventsFiltered(ctx, "srv-1", 50, 0, time.Time{}, "", "")
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
