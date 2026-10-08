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

// Package operations executes durable administrative intent independently of
// the initiating HTTP request. An uncertain remote outcome is never replayed.
package operations

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

type Operation = storage.Operation
type Executor func(context.Context, Operation) (json.RawMessage, error)

var (
	ErrOutcomeUnknown      = errors.New("operation outcome is unknown; reconciliation required")
	ErrNotFound            = storage.ErrOperationNotFound
	ErrConflict            = storage.ErrOperationConflict
	ErrIdempotencyConflict = storage.ErrIdempotencyConflict
	ErrNotStarted          = errors.New("operation worker is not running")
)

type Engine struct {
	store           *storage.OperationStore
	execute         Executor
	mu              sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	started, closed bool
	active          map[string]bool
	listener        func(Operation)
	wake            chan struct{}
	done            chan struct{}
	wg              sync.WaitGroup
}

func New(execute Executor) *Engine { return NewWithStore(storage.SharedOperationStore(), execute) }
func NewWithStore(store *storage.OperationStore, execute Executor) *Engine {
	return &Engine{store: store, execute: execute, active: make(map[string]bool), wake: make(chan struct{}, 1), done: make(chan struct{})}
}

// SetListener installs a fast, nonblocking notification callback. The durable
// GET API remains authoritative when a browser misses a notification.
func (e *Engine) SetListener(fn func(Operation)) { e.mu.Lock(); e.listener = fn; e.mu.Unlock() }
func (e *Engine) notify(op Operation) {
	e.mu.Lock()
	fn := e.listener
	e.mu.Unlock()
	if fn != nil {
		fn(op)
	}
}
func (e *Engine) kick() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.started {
		return errors.New("operation engine already started")
	}
	if e.execute == nil {
		return errors.New("operation executor is required")
	}
	if err := e.store.RecoverRunning(ctx); err != nil {
		return err
	}
	e.ctx, e.cancel = context.WithCancel(ctx)
	e.started = true
	e.wg.Add(1)
	go e.dispatch()
	go func() { e.wg.Wait(); close(e.done) }()
	return nil
}

func (e *Engine) Close(ctx context.Context) error {
	e.mu.Lock()
	if !e.started {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.cancel()
	e.mu.Unlock()
	select {
	case <-e.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) Submit(ctx context.Context, serverID, kind, target, idempotencyKey string, payload json.RawMessage) (Operation, error) {
	if serverID == "" || kind == "" {
		return Operation{}, errors.New("operation server and kind are required")
	}
	if len(idempotencyKey) > 200 {
		return Operation{}, errors.New("idempotency key is too long")
	}
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	var parsed any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return Operation{}, fmt.Errorf("invalid operation payload: %w", err)
	}
	// Canonical JSON makes a retried request independent of object field order.
	payload, _ = json.Marshal(parsed)
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return Operation{}, err
	}
	now := time.Now().UTC()
	op := Operation{ID: hex.EncodeToString(entropy[:]), ServerID: serverID, Kind: kind, Target: target,
		State: "queued", Phase: "queued", Message: "Waiting for earlier changes on this server", CreatedAt: now, UpdatedAt: now,
		Payload: payload, IdempotencyKey: idempotencyKey}
	e.mu.Lock()
	if !e.started || e.closed || e.ctx.Err() != nil {
		e.mu.Unlock()
		return Operation{}, ErrNotStarted
	}
	// Commit acceptance while shutdown is excluded. After commit, cancelling the
	// caller cannot cancel the operation or lose its queued intent.
	op, inserted, err := e.store.Insert(ctx, op)
	e.mu.Unlock()
	if err != nil {
		return Operation{}, err
	}
	if inserted {
		e.notify(op)
	}
	e.kick()
	return op, nil
}

func (e *Engine) Get(ctx context.Context, id string) (Operation, error) { return e.store.Get(ctx, id) }
func (e *Engine) List(ctx context.Context, serverID string, limit int) ([]Operation, error) {
	return e.store.List(ctx, serverID, limit)
}

func (e *Engine) InFlight(ctx context.Context) ([]Operation, error) { return e.store.InFlight(ctx) }
func (e *Engine) HasActiveKind(ctx context.Context, serverID, kind string) (bool, error) {
	return e.store.HasActiveKind(ctx, serverID, kind)
}

// ReportReconciliation exposes why an uncertain operation is still waiting,
// without flooding sockets or rewriting its timestamp for identical retries.
func (e *Engine) ReportReconciliation(ctx context.Context, id, message string) error {
	op, err := e.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if op.State != "reconciling" {
		return ErrConflict
	}
	if op.Phase == "reconciling" && op.Message == message {
		return nil
	}
	op, err = e.store.Report(ctx, id, "reconciling", message)
	if err == nil {
		e.notify(op)
	}
	return err
}

func (e *Engine) Cancel(ctx context.Context, id string) (Operation, error) {
	op, err := e.store.Finish(ctx, id, "queued", "cancelled", "Cancelled before execution", "", nil)
	if err == nil {
		e.notify(op)
		e.kick()
	}
	return op, err
}

// Resolve is only for a caller that has verified the actual configuration and
// daemon state after an interrupted command. It never re-executes that command.
func (e *Engine) Resolve(ctx context.Context, id string, result json.RawMessage, outcomeErr error) (Operation, error) {
	state, message, errorText := "succeeded", "Server state verified", ""
	if outcomeErr != nil {
		if errors.Is(outcomeErr, ErrOutcomeUnknown) {
			return Operation{}, ErrOutcomeUnknown
		}
		state, message, errorText = "failed", "Server state verified; the requested change did not complete", outcomeErr.Error()
	}
	op, err := e.store.Finish(ctx, id, "reconciling", state, message, errorText, result)
	if err == nil {
		e.notify(op)
		e.kick()
	}
	return op, err
}

func (e *Engine) dispatch() {
	defer e.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if e.ctx.Err() != nil {
			return
		}
		ids, err := e.store.RunnableServers(e.ctx)
		if err != nil && e.ctx.Err() == nil {
			log.Printf("operation queue refresh failed: %v", err)
		}
		for _, id := range ids {
			e.mu.Lock()
			if e.closed || e.ctx.Err() != nil {
				e.mu.Unlock()
				return
			}
			if !e.active[id] {
				e.active[id] = true
				e.wg.Add(1)
				go e.worker(id)
			}
			e.mu.Unlock()
		}
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
		case <-e.wake:
		}
	}
}

func (e *Engine) worker(serverID string) {
	defer func() { e.mu.Lock(); delete(e.active, serverID); e.mu.Unlock(); e.wg.Done(); e.kick() }()
	for e.ctx.Err() == nil {
		op, err := e.store.ClaimNext(e.ctx, serverID)
		if err != nil {
			if !errors.Is(err, ErrNotFound) && e.ctx.Err() == nil {
				log.Printf("operation claim for %s failed: %v", serverID, err)
			}
			return
		}
		e.notify(op)
		ctx := context.WithValue(e.ctx, executionKey{}, &execution{engine: e, id: op.ID})
		result, runErr := e.invoke(ctx, op)
		state, message, errorText := "succeeded", "Operation completed and verified", ""
		if runErr != nil {
			state, message, errorText = "failed", "Operation failed", runErr.Error()
		}
		if e.ctx.Err() != nil || errors.Is(runErr, ErrOutcomeUnknown) {
			state, message = "reconciling", "The command outcome is uncertain. Checking the server before further changes."
			if errorText == "" {
				errorText = ErrOutcomeUnknown.Error()
			}
		}
		// Persist the result even after shutdown cancels the executor.
		persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		finished, err := e.store.Finish(persistCtx, op.ID, "running", state, message, errorText, result)
		cancel()
		if err != nil {
			log.Printf("could not persist operation %s outcome (server remains blocked): %v", op.ID, err)
			return
		}
		e.notify(finished)
		if state == "reconciling" {
			return
		}
	}
}

func (e *Engine) invoke(ctx context.Context, op Operation) (result json.RawMessage, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: worker panic: %v", ErrOutcomeUnknown, r)
		}
	}()
	return e.execute(ctx, op)
}

type executionKey struct{}
type execution struct {
	engine *Engine
	id     string
}

func ID(ctx context.Context) string {
	if x, ok := ctx.Value(executionKey{}).(*execution); ok {
		return x.id
	}
	return ""
}

func Report(ctx context.Context, phase, message string) error {
	x, ok := ctx.Value(executionKey{}).(*execution)
	if !ok {
		return errors.New("no operation in context")
	}
	op, err := x.engine.store.Report(ctx, x.id, phase, message)
	if err == nil {
		x.engine.notify(op)
	}
	return err
}

// SaveRecovery must succeed before publishing an unvalidated configuration.
func SaveRecovery(ctx context.Context, data json.RawMessage) error {
	x, ok := ctx.Value(executionKey{}).(*execution)
	if !ok {
		return errors.New("no operation in context")
	}
	return x.engine.store.SaveRecovery(ctx, x.id, data)
}
