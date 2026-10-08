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
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

const snapshotFreshFor = 10 * time.Second
const snapshotRefreshTimeout = 8 * time.Second

type ServerSnapshot struct {
	ServerID    string                `json:"serverId"`
	Summary     *fail2ban.JailSummary `json:"-"`
	Configured  []fail2ban.JailInfo   `json:"-"`
	ObservedAt  time.Time             `json:"observedAt,omitzero"`
	Available   bool                  `json:"available"`
	Stale       bool                  `json:"stale"`
	Refreshing  bool                  `json:"refreshing"`
	StaleReason string                `json:"staleReason,omitempty"`
	Error       string                `json:"error,omitempty"`
	OperationID string                `json:"operationId,omitempty"`
}

type snapshotPayload struct {
	Summary    *fail2ban.JailSummary `json:"summary"`
	Configured []fail2ban.JailInfo   `json:"configured"`
}
type snapshotEntry struct {
	mu          sync.Mutex
	fingerprint string
	loaded      bool
	value       *ServerSnapshot
	refresh     chan struct{}
	lastAttempt time.Time
	lastError   string
	invalidated bool
	version     uint64
}
type snapshotCache struct {
	mu      sync.Mutex
	entries map[string]*snapshotEntry
}

var serverSnapshots = snapshotCache{entries: make(map[string]*snapshotEntry)}

func (cache *snapshotCache) entry(conn fail2ban.Connector) *snapshotEntry {
	fingerprint := serverFingerprint(conn.Server())
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry := cache.entries[conn.Server().ID]
	if entry == nil || entry.fingerprint != fingerprint {
		entry = &snapshotEntry{fingerprint: fingerprint, refresh: make(chan struct{}, 1)}
		cache.entries[conn.Server().ID] = entry
	}
	return entry
}

func cloneJails(jails []fail2ban.JailInfo) []fail2ban.JailInfo {
	if jails == nil {
		return nil
	}
	cloned := slices.Clone(jails)
	for i := range cloned {
		cloned[i].BannedIPs = slices.Clone(cloned[i].BannedIPs)
	}
	return cloned
}

func cloneSnapshot(source *ServerSnapshot) *ServerSnapshot {
	if source == nil {
		return &ServerSnapshot{Stale: true, StaleReason: "initializing"}
	}
	clone := *source
	clone.Configured = cloneJails(source.Configured)
	if source.Summary != nil {
		summary := *source.Summary
		summary.Jails = cloneJails(summary.Jails)
		clone.Summary = &summary
	}
	return &clone
}

// SnapshotForServer never waits on Fail2Ban. Persisted last-confirmed data is
// loaded once, then readers receive copies while one bounded refresh runs.
func SnapshotForServer(ctx context.Context, conn fail2ban.Connector) (*ServerSnapshot, error) {
	entry := serverSnapshots.entry(conn)
	entry.mu.Lock()
	if !entry.loaded {
		loadCtx, cancel := context.WithTimeout(ctx, time.Second)
		payload, observed, err := storage.LoadServerSnapshot(loadCtx, conn.Server().ID, entry.fingerprint)
		cancel()
		if err == nil && len(payload) > 0 {
			var saved snapshotPayload
			if json.Unmarshal(payload, &saved) == nil && saved.Summary != nil {
				entry.value = &ServerSnapshot{ServerID: conn.Server().ID, Summary: saved.Summary, Configured: saved.Configured, ObservedAt: observed, Available: true}
			}
		}
		entry.loaded = true
	}
	view := cloneSnapshot(entry.value)
	view.ServerID = conn.Server().ID
	view.Error = entry.lastError
	activity, busy := fail2ban.GetManager().OperationStatus(conn.Server().ID)
	view.Stale = !view.Available || time.Since(view.ObservedAt) > snapshotFreshFor || view.Error != "" || busy || entry.invalidated
	if busy {
		view.StaleReason = "operation_in_progress"
		view.OperationID = activity.ID
	} else if view.Error != "" {
		view.StaleReason = "refresh_failed"
	} else if view.Available && view.Stale {
		view.StaleReason = "refresh_pending"
	}
	if !busy && view.Stale && time.Since(entry.lastAttempt) >= snapshotRefreshTimeout {
		select {
		case entry.refresh <- struct{}{}:
			entry.lastAttempt = time.Now()
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), snapshotRefreshTimeout)
				defer cancel()
				_, _ = refreshSnapshot(ctx, conn, entry)
				<-entry.refresh
			}()
		default:
		}
	}
	view.Refreshing = len(entry.refresh) > 0
	entry.mu.Unlock()
	return view, nil
}

// RefreshServerSnapshot is for operation verification. It always starts a new
// read after any older refresh has completed, so a pre-mutation result cannot
// accidentally verify a newer change. The operation owns the mutation lease.
func RefreshServerSnapshot(ctx context.Context, conn fail2ban.Connector) (*ServerSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, snapshotRefreshTimeout)
	defer cancel()
	entry := serverSnapshots.entry(conn)
	select {
	case entry.refresh <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-entry.refresh }()
	entry.mu.Lock()
	entry.lastAttempt = time.Now()
	entry.mu.Unlock()
	return refreshSnapshot(ctx, conn, entry)
}

func refreshSnapshot(ctx context.Context, conn fail2ban.Connector, entry *snapshotEntry) (*ServerSnapshot, error) {
	entry.mu.Lock()
	version := entry.version
	entry.mu.Unlock()
	summary, err := conn.GetJailSummary(ctx)
	if err == nil && summary == nil {
		err = fmt.Errorf("server returned no jail summary")
	}
	var configured []fail2ban.JailInfo
	if err == nil {
		configured, err = conn.GetAllJails(ctx)
	}
	if err != nil {
		entry.mu.Lock()
		entry.lastError = err.Error()
		view := cloneSnapshot(entry.value)
		entry.mu.Unlock()
		view.ServerID = conn.Server().ID
		view.Stale = true
		view.StaleReason = "refresh_failed"
		view.Error = err.Error()
		publishSnapshot(view)
		return view, err
	}
	fail2ban.GetManager().ObserveDaemonResponse(conn)
	view := &ServerSnapshot{ServerID: conn.Server().ID, Summary: summary, Configured: configured, ObservedAt: time.Now().UTC(), Available: true}
	payload, _ := json.Marshal(snapshotPayload{Summary: summary, Configured: configured})
	if err := storage.SaveServerSnapshot(ctx, view.ServerID, entry.fingerprint, view.ObservedAt, payload); err != nil {
		log.Printf("could not persist server snapshot for %s: %v", view.ServerID, err)
	}
	entry.mu.Lock()
	entry.value = cloneSnapshot(view)
	entry.loaded = true
	entry.lastError = ""
	entry.invalidated = entry.version != version
	if entry.invalidated {
		view.Stale = true
		view.StaleReason = "refresh_pending"
	}
	entry.mu.Unlock()
	publishSnapshot(view)
	return cloneSnapshot(view), nil
}

// A callback is evidence that the last full snapshot may have changed. Do not
// invent new totals from possibly duplicated or out-of-order notifications.
func InvalidateServerSnapshot(serverID string) {
	serverSnapshots.mu.Lock()
	var entries []*snapshotEntry
	for id, entry := range serverSnapshots.entries {
		if fail2ban.GetManager().SameOperationTarget(id, serverID) {
			entries = append(entries, entry)
		}
	}
	serverSnapshots.mu.Unlock()
	for _, entry := range entries {
		entry.mu.Lock()
		entry.invalidated = true
		entry.version++
		entry.lastAttempt = time.Time{}
		entry.mu.Unlock()
	}
}

func snapshotMetadata(view *ServerSnapshot) gin.H {
	// Snapshot metadata is shared with read-only HTTP and WebSocket consumers.
	// Keep connector diagnostics in the internal snapshot and admin health view;
	// errors can contain hostnames, remote paths, or command output.
	refreshError := ""
	if view.Error != "" {
		refreshError = "Unable to refresh server status. Check server health for details."
	}
	return gin.H{"serverId": view.ServerID, "available": view.Available, "stale": view.Stale, "refreshing": view.Refreshing, "observedAt": view.ObservedAt,
		"staleReason": view.StaleReason, "refreshError": refreshError, "operationId": view.OperationID}
}

func publishSnapshot(view *ServerSnapshot) {
	if wsHub == nil {
		return
	}
	data, err := snapshotEvent(view)
	if err != nil {
		return
	}
	select {
	case wsHub.broadcast <- data:
	default:
	}
}

func snapshotEvent(view *ServerSnapshot) ([]byte, error) {
	return json.Marshal(gin.H{"type": "snapshot_update", "serverId": view.ServerID, "data": snapshotMetadata(view)})
}
