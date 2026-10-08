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
	"sync"
	"sync/atomic"
	"testing"
)

func TestCallbackRetriesAreDeduplicated(t *testing.T) {
	initTestStorage(t)
	record := BanEventRecord{ServerID: "server-a", ServerName: "A", Jail: "sshd", IP: "192.0.2.1", CallbackID: "event-1"}
	var created atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, inserted, err := RecordBanEventOnce(context.Background(), record)
			if err != nil || id <= 0 {
				t.Errorf("record callback: id=%d err=%v", id, err)
				return
			}
			if inserted {
				created.Add(1)
			}
		}()
	}
	wg.Wait()
	if created.Load() != 1 {
		t.Fatalf("created %d rows for retries", created.Load())
	}
	record.ServerID = "server-b"
	if _, inserted, err := RecordBanEventOnce(context.Background(), record); err != nil || !inserted {
		t.Fatalf("another server's event was deduplicated: %v", err)
	}
	record.IP = "192.0.2.2"
	if _, _, err := RecordBanEventOnce(context.Background(), record); err == nil {
		t.Fatal("ID reuse with different event content must fail")
	}
	record.CallbackID = ""
	for i := 0; i < 2; i++ {
		if _, inserted, err := RecordBanEventOnce(context.Background(), record); err != nil || !inserted {
			t.Fatalf("legacy callback without an ID was dropped: %v", err)
		}
	}
}

func TestFailedCallbackInsertCanBeRetried(t *testing.T) {
	initTestStorage(t)
	record := BanEventRecord{ServerID: "server", Jail: "sshd", IP: "192.0.2.1", CallbackID: "retry"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := RecordBanEventOnce(ctx, record); err == nil {
		t.Fatal("canceled insert should fail")
	}
	if _, inserted, err := RecordBanEventOnce(context.Background(), record); err != nil || !inserted {
		t.Fatalf("failed insert incorrectly consumed the event ID: %v", err)
	}
}
