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
	"time"
)

func ensureSnapshotSchema(ctx context.Context) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS server_snapshots (
		server_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, payload TEXT NOT NULL
	)`)
	return err
}

func LoadServerSnapshot(ctx context.Context, serverID, fingerprint string) (json.RawMessage, time.Time, error) {
	if db == nil {
		return nil, time.Time{}, errors.New("storage not initialised")
	}
	var payload, observed string
	err := db.QueryRowContext(ctx, `SELECT payload, observed_at FROM server_snapshots WHERE server_id = ? AND fingerprint = ?`, serverID, fingerprint).Scan(&payload, &observed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, nil
	}
	return json.RawMessage(payload), parseStorageTime(observed), err
}

func SaveServerSnapshot(ctx context.Context, serverID, fingerprint string, observedAt time.Time, payload json.RawMessage) error {
	if db == nil {
		return errors.New("storage not initialised")
	}
	if !json.Valid(payload) {
		return errors.New("snapshot payload must be JSON")
	}
	_, err := db.ExecContext(ctx, `INSERT INTO server_snapshots(server_id,fingerprint,observed_at,payload) VALUES(?,?,?,?)
		ON CONFLICT(server_id) DO UPDATE SET fingerprint=excluded.fingerprint,observed_at=excluded.observed_at,payload=excluded.payload`, serverID, fingerprint, formatStorageTime(observedAt), string(payload))
	return err
}
