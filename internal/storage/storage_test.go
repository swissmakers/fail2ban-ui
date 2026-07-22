// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.gnu.org/licenses/gpl-3.0.en.html
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
		if err := RecordBanEvent(ctx, event); err != nil {
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
	if err := RecordBanEvent(ctx, event); err != nil {
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
		if err := RecordBanEvent(ctx, event); err != nil {
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

func TestCountRecentBanEventsByJailSupportsLegacyTimestampText(t *testing.T) {
	initTestStorage(t)

	ctx := context.Background()
	since := time.Date(2026, 5, 27, 13, 30, 0, 0, time.UTC)
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

	got, err := CountRecentBanEventsByJail(ctx, "srv-1", since)
	if err != nil {
		t.Fatalf("CountRecentBanEventsByJail: %v", err)
	}
	if got["sshd"] != 1 {
		t.Fatalf("recent ban count=%d want 1", got["sshd"])
	}
}
