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
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Operation is durable intent and its last confirmed execution state. Payload
// and Recovery may contain configuration and must never be exposed by the API.
type Operation struct {
	ID             string          `json:"id"`
	ServerID       string          `json:"serverId"`
	Kind           string          `json:"kind"`
	Target         string          `json:"target,omitempty"`
	State          string          `json:"state"`
	Phase          string          `json:"phase"`
	Message        string          `json:"message,omitempty"`
	CreatedAt      time.Time       `json:"createdAt"`
	StartedAt      time.Time       `json:"startedAt,omitzero"`
	UpdatedAt      time.Time       `json:"updatedAt"`
	FinishedAt     time.Time       `json:"finishedAt,omitzero"`
	Error          string          `json:"error,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
	QueuePosition  int             `json:"queuePosition,omitempty"`
	Payload        json.RawMessage `json:"-"`
	Recovery       json.RawMessage `json:"-"`
	IdempotencyKey string          `json:"-"`
}

func (op Operation) Terminal() bool {
	return op.State == "succeeded" || op.State == "failed" || op.State == "cancelled"
}

var ErrOperationNotFound = errors.New("operation not found")
var ErrOperationConflict = errors.New("operation state changed or action is not allowed")
var ErrIdempotencyConflict = errors.New("idempotency key already used for a different operation")

type OperationStore struct{ db *sql.DB }

func NewOperationStore(database *sql.DB) *OperationStore { return &OperationStore{db: database} }
func SharedOperationStore() *OperationStore              { return NewOperationStore(db) }

func (s *OperationStore) EnsureSchema(ctx context.Context) error {
	if s.db == nil {
		return errors.New("storage not initialised")
	}
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS operations (
		id TEXT PRIMARY KEY, server_id TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
		state TEXT NOT NULL, phase TEXT NOT NULL, message TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL, started_at TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
		finished_at TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '',
		payload TEXT NOT NULL DEFAULT '', recovery TEXT NOT NULL DEFAULT '', idempotency_key TEXT NOT NULL DEFAULT ''
	);
	CREATE UNIQUE INDEX IF NOT EXISTS operations_idempotency ON operations(server_id, idempotency_key) WHERE idempotency_key <> '';
	CREATE INDEX IF NOT EXISTS operations_server_state ON operations(server_id, state, created_at);`)
	return err
}

const operationColumns = `id, server_id, kind, target, state, phase, message, created_at, started_at, updated_at, finished_at, error, result, payload, recovery, idempotency_key`

func scanOperation(row interface{ Scan(...any) error }) (Operation, error) {
	var op Operation
	var created, started, updated, finished, result, payload, recovery string
	err := row.Scan(&op.ID, &op.ServerID, &op.Kind, &op.Target, &op.State, &op.Phase, &op.Message,
		&created, &started, &updated, &finished, &op.Error, &result, &payload, &recovery, &op.IdempotencyKey)
	if errors.Is(err, sql.ErrNoRows) {
		return op, ErrOperationNotFound
	}
	op.CreatedAt, op.StartedAt, op.UpdatedAt, op.FinishedAt = parseStorageTime(created), parseStorageTime(started), parseStorageTime(updated), parseStorageTime(finished)
	op.Result, op.Payload, op.Recovery = json.RawMessage(result), json.RawMessage(payload), json.RawMessage(recovery)
	return op, err
}

func (s *OperationStore) Insert(ctx context.Context, op Operation) (Operation, bool, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO operations (`+operationColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, '', '', '', ?, '', ?)
		ON CONFLICT DO NOTHING`, op.ID, op.ServerID, op.Kind, op.Target, op.State, op.Phase, op.Message,
		formatStorageTime(op.CreatedAt), formatStorageTime(op.UpdatedAt), string(op.Payload), op.IdempotencyKey)
	if err != nil {
		return Operation{}, false, err
	}
	if op.IdempotencyKey != "" {
		existing, err := scanOperation(s.db.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE server_id = ? AND idempotency_key = ?`, op.ServerID, op.IdempotencyKey))
		if err != nil {
			return Operation{}, false, err
		}
		if existing.Kind != op.Kind || existing.Target != op.Target || string(existing.Payload) != string(op.Payload) {
			return Operation{}, false, ErrIdempotencyConflict
		}
		return existing, existing.ID == op.ID, nil
	}
	existing, err := s.Get(ctx, op.ID)
	return existing, true, err
}

func (s *OperationStore) Get(ctx context.Context, id string) (Operation, error) {
	op, err := scanOperation(s.db.QueryRowContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE id = ?`, id))
	if err == nil && op.State == "queued" {
		err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM operations WHERE server_id = ? AND state = 'queued' AND (created_at < ? OR (created_at = ? AND id <= ?))`, op.ServerID, formatStorageTime(op.CreatedAt), formatStorageTime(op.CreatedAt), op.ID).Scan(&op.QueuePosition)
	}
	return op, err
}

func (s *OperationStore) List(ctx context.Context, serverID string, limit int) ([]Operation, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT ` + operationColumns + ` FROM operations`
	var args []any
	if serverID != "" {
		query += ` WHERE server_id = ?`
		args = append(args, serverID)
	}
	// Active operations must never be pushed off the first page by history.
	query += ` ORDER BY CASE WHEN state IN ('running','reconciling') THEN 0 WHEN state = 'queued' THEN 1 ELSE 2 END, created_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ops := []Operation{}
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Do not query while rows owns a connection (tests also use a single connection).
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range ops {
		if ops[i].State == "queued" {
			full, err := s.Get(ctx, ops[i].ID)
			if err != nil {
				return nil, err
			}
			ops[i].QueuePosition = full.QueuePosition
		}
	}
	return ops, nil
}

// InFlight is for startup recovery, never for an unbounded public history API.
// Every interrupted target must be reserved, regardless of UI page size.
func (s *OperationStore) InFlight(ctx context.Context) ([]Operation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+operationColumns+` FROM operations WHERE state IN ('running','reconciling') ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ops := []Operation{}
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return ops, rows.Err()
}

func (s *OperationStore) HasActiveKind(ctx context.Context, serverID, kind string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM operations WHERE server_id = ? AND kind = ? AND state IN ('queued','running','reconciling'))`, serverID, kind).Scan(&exists)
	return exists, err
}

func (s *OperationStore) RecoverRunning(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE operations SET state = 'reconciling', phase = 'reconciling', message = 'The UI restarted before completion was confirmed. Checking the server before any further changes.', updated_at = ? WHERE state = 'running'`, formatStorageTime(time.Now()))
	return err
}

func (s *OperationStore) RunnableServers(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT server_id FROM operations q WHERE q.state = 'queued' AND NOT EXISTS (SELECT 1 FROM operations busy WHERE busy.server_id = q.server_id AND busy.state IN ('running', 'reconciling'))`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ClaimNext atomically chooses the oldest intent and excludes uncertain results.
func (s *OperationStore) ClaimNext(ctx context.Context, serverID string) (Operation, error) {
	now := formatStorageTime(time.Now())
	return scanOperation(s.db.QueryRowContext(ctx, `UPDATE operations SET state = 'running', phase = 'starting', message = 'Starting operation', started_at = ?, updated_at = ?
	WHERE id = (SELECT id FROM operations WHERE server_id = ? AND state = 'queued' ORDER BY created_at, id LIMIT 1)
	AND NOT EXISTS (SELECT 1 FROM operations WHERE server_id = ? AND state IN ('running','reconciling')) RETURNING `+operationColumns, now, now, serverID, serverID))
}

func (s *OperationStore) Report(ctx context.Context, id, phase, message string) (Operation, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE operations SET phase = ?, message = ?, updated_at = ? WHERE id = ? AND state IN ('running','reconciling')`, phase, message, formatStorageTime(time.Now()), id)
	if err := operationChanged(res, err); err != nil {
		return Operation{}, err
	}
	return s.Get(ctx, id)
}

func (s *OperationStore) SaveRecovery(ctx context.Context, id string, recovery json.RawMessage) error {
	if !json.Valid(recovery) {
		return fmt.Errorf("recovery data must be JSON")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE operations SET recovery = ?, updated_at = ? WHERE id = ? AND state IN ('running','reconciling')`, string(recovery), formatStorageTime(time.Now()), id)
	return operationChanged(res, err)
}

func (s *OperationStore) Finish(ctx context.Context, id, expectedState, state, message, errorText string, result json.RawMessage) (Operation, error) {
	if state != "succeeded" && state != "failed" && state != "cancelled" && state != "reconciling" {
		return Operation{}, ErrOperationConflict
	}
	if len(result) > 0 && !json.Valid(result) {
		return Operation{}, errors.New("operation result must be JSON")
	}
	now, finished := formatStorageTime(time.Now()), ""
	if state != "reconciling" {
		finished = now
	}
	res, err := s.db.ExecContext(ctx, `UPDATE operations SET state = ?, phase = ?, message = ?, error = ?, result = ?, updated_at = ?, finished_at = ? WHERE id = ? AND state = ?`, state, state, message, errorText, string(result), now, finished, id, expectedState)
	if err := operationChanged(res, err); err != nil {
		return Operation{}, err
	}
	return s.Get(ctx, id)
}

func operationChanged(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrOperationConflict
	}
	return nil
}
