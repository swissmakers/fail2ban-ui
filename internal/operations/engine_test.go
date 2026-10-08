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

package operations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

func testStore(t *testing.T) *storage.OperationStore {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "operations.db")+"?_pragma=busy_timeout=5000&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := storage.NewOperationStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store
}

func startEngine(t *testing.T, store *storage.OperationStore, executor Executor) *Engine {
	t.Helper()
	e := NewWithStore(store, executor)
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := e.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return e
}

func awaitState(t *testing.T, e *Engine, id, state string) Operation {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		op, err := e.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if op.State == state {
			return op
		}
		time.Sleep(5 * time.Millisecond)
	}
	op, _ := e.Get(context.Background(), id)
	t.Fatalf("operation %s state=%s, want %s", id, op.State, state)
	return Operation{}
}

func TestIndependentTargetsAndQueuedCancellation(t *testing.T) {
	store := testStore(t)
	started := make(chan Operation, 10)
	releaseA := make(chan struct{})
	e := startEngine(t, store, func(ctx context.Context, op Operation) (json.RawMessage, error) {
		started <- op
		if op.Target == "first" {
			select {
			case <-releaseA:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return json.RawMessage(`{"verified":true}`), nil
	})
	first, err := e.Submit(context.Background(), "a", "toggle", "first", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, first.ID, "running")
	second, err := e.Submit(context.Background(), "a", "toggle", "second", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.Submit(context.Background(), "b", "toggle", "other", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, other.ID, "succeeded")
	if _, err := e.Cancel(context.Background(), first.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("running cancel=%v", err)
	}
	if _, err := e.Cancel(context.Background(), second.ID); err != nil {
		t.Fatal(err)
	}
	close(releaseA)
	awaitState(t, e, first.ID, "succeeded")
	awaitState(t, e, second.ID, "cancelled")
	for len(started) > 0 {
		if op := <-started; op.ID == second.ID {
			t.Fatal("cancelled operation executed")
		}
	}
}

func TestRequestDisconnectAndIdempotency(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	e := startEngine(t, testStore(t), func(ctx context.Context, op Operation) (json.RawMessage, error) {
		if err := SaveRecovery(ctx, json.RawMessage(`{"before":"disabled"}`)); err != nil {
			return nil, err
		}
		if err := Report(ctx, "applying", "Waiting for firewall cleanup"); err != nil {
			return nil, err
		}
		close(started)
		select {
		case <-release:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	request, cancel := context.WithCancel(context.Background())
	op, err := e.Submit(request, "a", "toggle", "jail", "key", json.RawMessage(`{"enabled":false,"jail":"jail"}`))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	<-started
	retry, err := e.Submit(context.Background(), "a", "toggle", "jail", "key", json.RawMessage(`{"jail":"jail","enabled":false}`))
	if err != nil || retry.ID != op.ID {
		t.Fatalf("idempotent retry: %+v %v", retry, err)
	}
	if _, err := e.Submit(context.Background(), "a", "toggle", "jail", "key", json.RawMessage(`{"enabled":true}`)); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("mismatched retry=%v", err)
	}
	stored, err := e.Get(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != "running" || stored.Phase != "applying" || len(stored.Recovery) == 0 {
		t.Fatalf("operation interrupted or recovery missing: %+v", stored)
	}
	public, _ := json.Marshal(stored)
	var fields map[string]any
	_ = json.Unmarshal(public, &fields)
	if fields["payload"] != nil || fields["recovery"] != nil {
		t.Fatal("private operation content leaked")
	}
	close(release)
	awaitState(t, e, op.ID, "succeeded")
}

func TestRestartDoesNotReplayUncertainCommand(t *testing.T) {
	store := testStore(t)
	now := time.Now().UTC()
	old, _, err := store.Insert(context.Background(), Operation{ID: "old", ServerID: "a", Kind: "toggle", State: "queued", Phase: "queued", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimNext(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	executed := make(chan string, 5)
	e := startEngine(t, store, func(_ context.Context, op Operation) (json.RawMessage, error) { executed <- op.ID; return nil, nil })
	awaitState(t, e, old.ID, "reconciling")
	next, err := e.Submit(context.Background(), "a", "toggle", "next", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.Submit(context.Background(), "b", "toggle", "other", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, other.ID, "succeeded")
	if op, _ := e.Get(context.Background(), next.ID); op.State != "queued" {
		t.Fatalf("unverified server progressed: %s", op.State)
	}
	if _, err := e.Resolve(context.Background(), old.ID, json.RawMessage(`{"verified":true}`), nil); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, next.ID, "succeeded")
	for len(executed) > 0 {
		if id := <-executed; id == old.ID {
			t.Fatal("uncertain command blindly replayed")
		}
	}
}

func TestUnknownResultBlocksOnlyItsServer(t *testing.T) {
	e := startEngine(t, testStore(t), func(_ context.Context, op Operation) (json.RawMessage, error) {
		if op.Target == "lost-reply" {
			return nil, ErrOutcomeUnknown
		}
		return nil, nil
	})
	op, err := e.Submit(context.Background(), "a", "toggle", "lost-reply", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, op.ID, "reconciling")
	next, err := e.Submit(context.Background(), "a", "toggle", "next", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Cancel(context.Background(), op.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("reconciling cancel=%v", err)
	}
	if _, err := e.Resolve(context.Background(), op.ID, nil, ErrOutcomeUnknown); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	if _, err := e.Resolve(context.Background(), op.ID, nil, errors.New("verified not applied")); err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, next.ID, "succeeded")
}

func TestReconciliationReasonIsVisibleWithoutRepeatedNotifications(t *testing.T) {
	e := startEngine(t, testStore(t), func(context.Context, Operation) (json.RawMessage, error) { return nil, ErrOutcomeUnknown })
	op, err := e.Submit(context.Background(), "a", "reload", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	awaitState(t, e, op.ID, "reconciling")
	var mu sync.Mutex
	count := 0
	e.SetListener(func(updated Operation) {
		if updated.Message == "SSH connection refused; waiting to verify server state" {
			mu.Lock()
			count++
			mu.Unlock()
		}
	})
	message := "SSH connection refused; waiting to verify server state"
	if err := e.ReportReconciliation(context.Background(), op.ID, message); err != nil {
		t.Fatal(err)
	}
	first, _ := e.Get(context.Background(), op.ID)
	if err := e.ReportReconciliation(context.Background(), op.ID, message); err != nil {
		t.Fatal(err)
	}
	second, _ := e.Get(context.Background(), op.ID)
	mu.Lock()
	notifications := count
	mu.Unlock()
	if notifications != 1 || !second.UpdatedAt.Equal(first.UpdatedAt) || second.Message != message {
		t.Fatalf("duplicate recovery update: notifications=%d first=%+v second=%+v", notifications, first, second)
	}
	if _, err := e.Resolve(context.Background(), op.ID, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.ReportReconciliation(context.Background(), op.ID, "late update"); !errors.Is(err, ErrConflict) {
		t.Fatalf("modified completed operation: %v", err)
	}
}

func TestRecoveryAndActiveKindChecksDoNotUseHistoryPageLimit(t *testing.T) {
	store := testStore(t)
	now := time.Now().UTC()
	for i := range 1001 {
		op := Operation{ID: fmt.Sprintf("recover-%04d", i), ServerID: fmt.Sprintf("server-%04d", i), Kind: "server.sync", State: "reconciling", Phase: "reconciling", CreatedAt: now.Add(time.Duration(i) * time.Nanosecond), UpdatedAt: now}
		if _, _, err := store.Insert(context.Background(), op); err != nil {
			t.Fatal(err)
		}
	}
	e := NewWithStore(store, nil)
	visible, err := e.List(context.Background(), "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 1000 {
		t.Fatal("history endpoint lost its limit")
	}
	all, err := e.InFlight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1001 {
		t.Fatalf("recovery only saw %d interrupted targets", len(all))
	}
	active, err := e.HasActiveKind(context.Background(), "server-0000", "server.sync")
	if err != nil || !active {
		t.Fatalf("old in-flight operation hidden: active=%v err=%v", active, err)
	}
}
