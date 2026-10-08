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

package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

type snapshotTestConnector struct {
	fail2ban.Connector
	id      string
	mu      sync.Mutex
	calls   int
	err     error
	release chan struct{}
	started chan struct{}
}

func (c *snapshotTestConnector) Server() shared.Fail2banServer {
	return shared.Fail2banServer{ID: c.id, Name: c.id, Type: "local"}
}
func (c *snapshotTestConnector) GetJailSummary(ctx context.Context) (*fail2ban.JailSummary, error) {
	c.mu.Lock()
	c.calls++
	err := c.err
	release, started := c.release, c.started
	c.started = nil
	c.mu.Unlock()
	if started != nil {
		close(started)
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return &fail2ban.JailSummary{Jails: []fail2ban.JailInfo{{JailName: "example", Enabled: true, TotalBanned: 2, BannedIPs: []string{"192.0.2.1", "192.0.2.2"}}}, JailLocalExists: true, JailLocalManaged: true}, nil
}
func (c *snapshotTestConnector) GetAllJails(context.Context) ([]fail2ban.JailInfo, error) {
	return []fail2ban.JailInfo{{JailName: "example", Enabled: true}, {JailName: "disabled", Enabled: false}}, nil
}
func (c *snapshotTestConnector) count() int { c.mu.Lock(); defer c.mu.Unlock(); return c.calls }

func awaitSnapshot(t *testing.T, c fail2ban.Connector) *ServerSnapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		view, err := SnapshotForServer(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		if view.Available && !view.Refreshing {
			return view
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("snapshot never became available")
	return nil
}

func TestSnapshotReadsDoNotWaitOrMultiplySlowDaemonCommands(t *testing.T) {
	c := &snapshotTestConnector{id: "snapshot-nonblocking", release: make(chan struct{}), started: make(chan struct{})}
	started := c.started
	before := time.Now()
	view, err := SnapshotForServer(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(before) > time.Second || view.Available || !view.Refreshing {
		t.Fatalf("unexpected initial snapshot: %+v", view)
	}
	<-started
	for range 20 {
		view, err = SnapshotForServer(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
	}
	if c.count() != 1 {
		t.Fatalf("concurrent readers started %d daemon requests", c.count())
	}
	close(c.release)
	view = awaitSnapshot(t, c)
	if len(view.Configured) != 2 || len(view.Summary.Jails[0].BannedIPs) != 2 {
		t.Fatalf("incomplete snapshot: %+v", view)
	}
}

func TestSnapshotSurvivesReloadDuringOperationAndCannotBeMutatedByReader(t *testing.T) {
	c := &snapshotTestConnector{id: "snapshot-persisted"}
	view, err := RefreshServerSnapshot(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	observed := view.ObservedAt
	view.Summary.Jails[0].BannedIPs[0] = "changed"
	view.Configured[0].Enabled = false
	read, err := SnapshotForServer(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if read.Summary.Jails[0].BannedIPs[0] != "192.0.2.1" || !read.Configured[0].Enabled {
		t.Fatal("reader mutated shared snapshot")
	}
	_, release, err := fail2ban.GetManager().BeginOperation(context.Background(), c.id, "op-persisted", "toggle")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	serverSnapshots.mu.Lock()
	delete(serverSnapshots.entries, c.id)
	serverSnapshots.mu.Unlock()
	read, err = SnapshotForServer(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !read.Available || !read.Stale || read.Refreshing || read.OperationID != "op-persisted" || !read.ObservedAt.Equal(observed) {
		t.Fatalf("persisted busy snapshot: %+v", read)
	}
	if c.count() != 1 {
		t.Fatal("busy snapshot queried daemon")
	}
}

func TestFailedRefreshPreservesLastConfirmedCounts(t *testing.T) {
	c := &snapshotTestConnector{id: "snapshot-refresh-failed"}
	previous, err := RefreshServerSnapshot(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.err = errors.New("daemon command timed out")
	c.mu.Unlock()
	if _, err := RefreshServerSnapshot(context.Background(), c); err == nil {
		t.Fatal("missing refresh error")
	}
	view, err := SnapshotForServer(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Available || !view.Stale || view.StaleReason != "refresh_failed" || view.Summary.Jails[0].TotalBanned != 2 || !view.ObservedAt.Equal(previous.ObservedAt) {
		t.Fatalf("failed refresh corrupted counts: %+v", view)
	}
}

func TestSnapshotHTTPAndWebSocketMetadataHideConnectorDiagnostics(t *testing.T) {
	diagnostic := "ssh: private-host.example using /root/.ssh/private-admin-key: command failed with private output"
	view := &ServerSnapshot{ServerID: "safe-server-id", Available: true, Stale: true, StaleReason: "refresh_failed", Error: diagnostic}
	assertSafe := func(payload []byte) {
		t.Helper()
		for _, sensitive := range []string{"private-host.example", "/root/.ssh/private-admin-key", "private output"} {
			if strings.Contains(string(payload), sensitive) {
				t.Fatalf("public snapshot leaked connector diagnostic %q: %s", sensitive, payload)
			}
		}
		if !strings.Contains(string(payload), "Unable to refresh server status") {
			t.Fatalf("refresh failure was hidden instead of explained: %s", payload)
		}
	}
	// The same metadata is embedded in the summary, jail list, and ban list HTTP
	// responses; it must remain safe before any role-specific response handling.
	c, response := newTestContext(http.MethodGet, "/api/summary", "")
	c.JSON(http.StatusOK, snapshotMetadata(view))
	assertSafe(response.Body.Bytes())
	message, err := snapshotEvent(view)
	if err != nil {
		t.Fatal(err)
	}
	assertSafe(message)
	var event struct {
		Type string         `json:"type"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(message, &event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "snapshot_update" || event.Data["staleReason"] != "refresh_failed" {
		t.Fatalf("safe update lost its usable status: %s", message)
	}
	if view.Error != diagnostic {
		t.Fatal("public redaction destroyed the internal diagnostic")
	}
}
