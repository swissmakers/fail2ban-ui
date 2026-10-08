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

package fail2ban

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

type syncTestConnector struct {
	Connector
	writeErr        error
	validationErr   error
	reloadErr       error
	restartErr      error
	writes, reloads int
	restarts        int
	onReload        func()
}

func (c *syncTestConnector) Restart(context.Context) (string, error) {
	c.restarts++
	return "restart", c.restartErr
}

func (c *syncTestConnector) Server() shared.Fail2banServer {
	return shared.Fail2banServer{ID: "test", Name: "test"}
}
func (c *syncTestConnector) EnsureJailLocalStructure(context.Context) error {
	c.writes++
	return c.writeErr
}
func (c *syncTestConnector) Reload(context.Context) error {
	c.reloads++
	if c.onReload != nil {
		c.onReload()
	}
	return c.reloadErr
}

func (c *syncTestConnector) ValidateConfiguration(context.Context) error {
	return c.validationErr
}

func TestConfigSyncDoesNotReloadInvalidConfiguration(t *testing.T) {
	conn := &syncTestConnector{validationErr: errors.New("invalid action configuration")}
	m := &Manager{connectors: map[string]Connector{"test": conn}}
	m.RequestConfigSync("test", false, true)
	if err := m.SyncServerConfig(context.Background(), "test"); err == nil {
		t.Fatal("validation failure was hidden")
	}
	status := m.ConfigSyncStatus("test")
	if conn.reloads != 0 || !status.Pending || status.Error == "" || status.LastWritten.IsZero() || !status.LastApplied.IsZero() {
		t.Fatalf("invalid configuration was applied or forgotten: %+v", status)
	}
	conn.validationErr = nil
	m.RetryPendingConfig(context.Background())
	if conn.reloads != 1 || m.ConfigSyncStatus("test").Pending {
		t.Fatal("corrected configuration was not retried")
	}
}

func TestConfigSyncRetriesOfflineDefaultsWithoutAnotherSave(t *testing.T) {
	conn := &syncTestConnector{writeErr: errors.New("host unavailable")}
	m := &Manager{connectors: map[string]Connector{"test": conn}}
	m.RequestConfigSync("test", false, true)
	if err := m.SyncServerConfig(context.Background(), "test"); err == nil {
		t.Fatal("write failure was hidden")
	}
	if conn.reloads != 0 || !m.ConfigSyncStatus("test").Pending {
		t.Fatal("failed write must not reload or clear pending work")
	}
	conn.writeErr = nil
	m.RetryPendingConfig(context.Background())
	if conn.reloads != 1 || conn.writes != 2 || m.ConfigSyncStatus("test").Pending {
		t.Fatalf("pending work was not recovered: %+v", m.ConfigSyncStatus("test"))
	}
}

func TestConfigSyncPreservesChangesQueuedDuringReload(t *testing.T) {
	conn := &syncTestConnector{}
	m := &Manager{connectors: map[string]Connector{"test": conn}}
	m.RequestConfigSync("test", false, true)
	conn.onReload = func() { m.RequestConfigSync("test", true, true) }
	if err := m.SyncServerConfig(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	if !m.ConfigSyncStatus("test").Pending {
		t.Fatal("older reload discarded the newer desired configuration")
	}
	conn.onReload = nil
	if err := m.SyncServerConfig(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	if m.ConfigSyncStatus("test").Pending || conn.reloads != 2 {
		t.Fatal("new configuration was not applied")
	}
}

func TestConfigRetryDelayBacksOff(t *testing.T) {
	cases := map[int]time.Duration{0: 0, 1: 0, 2: 2 * monitorInterval, 3: 4 * monitorInterval, 7: maxConfigRetryDelay, 500: maxConfigRetryDelay}
	for failures, want := range cases {
		if got := configRetryDelay(failures); got != want {
			t.Errorf("configRetryDelay(%d) = %v, want %v", failures, got, want)
		}
	}
	for f := 1; f < 64; f++ {
		if configRetryDelay(f) < configRetryDelay(f-1) || configRetryDelay(f) > maxConfigRetryDelay {
			t.Fatalf("delay not monotonic or above cap at %d failures", f)
		}
	}
}

func TestConfigRetryBacksOffUntilANewRequest(t *testing.T) {
	conn := &syncTestConnector{writeErr: errors.New("host unavailable")}
	m := &Manager{connectors: map[string]Connector{"test": conn}}
	m.RequestConfigSync("test", false, true)
	_ = m.SyncServerConfig(context.Background(), "test")
	m.RetryPendingConfig(context.Background())
	if conn.writes != 2 {
		t.Fatalf("first retry must run on the next tick, got %d writes", conn.writes)
	}
	m.RetryPendingConfig(context.Background())
	if conn.writes != 2 {
		t.Fatal("a repeatedly failing host was rewritten again without backing off")
	}
	m.RequestConfigSync("test", false, true)
	m.RetryPendingConfig(context.Background())
	if conn.writes != 3 {
		t.Fatal("a new sync request must reset the backoff")
	}
}

func TestConfigSyncRecordsMissingConnectorError(t *testing.T) {
	m := &Manager{connectors: map[string]Connector{}}
	m.RequestConfigSync("gone", true, true)
	if err := m.SyncServerConfig(context.Background(), "gone"); err == nil {
		t.Fatal("expected an error for a missing connector")
	}
	if status := m.ConfigSyncStatus("gone"); !status.Pending || status.Error == "" {
		t.Fatalf("pending sync without a reason: %+v", status)
	}
}

func TestConfigSyncStatusIsReadOnly(t *testing.T) {
	m := &Manager{}
	if status := m.ConfigSyncStatus("unknown"); status.Pending {
		t.Fatal("unknown server reported as pending")
	}
	if len(m.configSync) != 0 {
		t.Fatal("reading a status created sync state")
	}
}

var (
	_ Connector = (*SSHConnector)(nil)
	_ Connector = (*LocalConnector)(nil)
	_ Connector = (*AgentConnector)(nil)
)

func TestSyncPhase(t *testing.T) {
	tests := []struct {
		pending            bool
		writtenGen, genNow uint64
		want               string
	}{
		{false, 0, 0, SyncApplied},
		{false, 2, 3, SyncApplied},
		{true, 0, 1, SyncPending},
		{true, 3, 3, SyncWritten},
		{true, 2, 3, SyncPending},
	}
	for _, tt := range tests {
		if got := syncPhase(tt.pending, tt.writtenGen, tt.genNow); got != tt.want {
			t.Errorf("syncPhase(%v, %d, %d) = %s, want %s", tt.pending, tt.writtenGen, tt.genNow, got, tt.want)
		}
	}
}

func TestSyncStatusReportsWrittenPhaseAfterFailedReload(t *testing.T) {
	conn := &syncTestConnector{reloadErr: errors.New("daemon down")}
	m := &Manager{connectors: map[string]Connector{"test": conn}}
	m.RequestConfigSync("test", false, true)
	_ = m.SyncServerConfig(context.Background(), "test")
	if phase := m.ConfigSyncStatus("test").Phase; phase != SyncWritten {
		t.Fatalf("phase = %s, want written", phase)
	}
	m.RequestConfigSync("test", false, true)
	if phase := m.ConfigSyncStatus("test").Phase; phase != SyncPending {
		t.Fatalf("a newer request must be pending again, got %s", phase)
	}
}

func TestApplyAndRestart(t *testing.T) {
	t.Run("unknown reload outcome refuses a second service command", func(t *testing.T) {
		conn := &syncTestConnector{reloadErr: errors.New("daemon down")}
		m := &Manager{connectors: map[string]Connector{"test": conn}}
		m.RequestConfigSync("test", false, true)
		if _, err := m.ApplyAndRestart(context.Background(), "test"); !errors.Is(err, ErrOperationOutcomeUnknown) {
			t.Fatalf("ApplyAndRestart: %v, want unknown outcome", err)
		}
		if conn.restarts != 0 || !m.ConfigSyncStatus("test").Pending {
			t.Fatalf("restarts=%d status=%+v", conn.restarts, m.ConfigSyncStatus("test"))
		}
	})
	t.Run("unwritten config refuses restart", func(t *testing.T) {
		conn := &syncTestConnector{writeErr: errors.New("host unreachable")}
		m := &Manager{connectors: map[string]Connector{"test": conn}}
		m.RequestConfigSync("test", false, true)
		if _, err := m.ApplyAndRestart(context.Background(), "test"); !errors.Is(err, ErrConfigNotApplied) {
			t.Fatalf("err = %v, want ErrConfigNotApplied", err)
		}
		if conn.restarts != 0 {
			t.Fatal("restarted with files that never reached the host")
		}
	})
	t.Run("invalid config refuses restart", func(t *testing.T) {
		conn := &syncTestConnector{validationErr: errors.New("bad jail")}
		m := &Manager{connectors: map[string]Connector{"test": conn}}
		if _, err := m.ApplyAndRestart(context.Background(), "test"); !errors.Is(err, ErrConfigNotApplied) {
			t.Fatalf("err = %v, want ErrConfigNotApplied", err)
		}
		if conn.restarts != 0 {
			t.Fatal("restarted into an invalid configuration")
		}
	})
	t.Run("failed restart keeps pending", func(t *testing.T) {
		conn := &syncTestConnector{reloadErr: errors.New("daemon down"), restartErr: errors.New("systemctl failed")}
		m := &Manager{connectors: map[string]Connector{"test": conn}}
		m.RequestConfigSync("test", false, true)
		if _, err := m.ApplyAndRestart(context.Background(), "test"); err == nil {
			t.Fatal("restart failure was hidden")
		}
		if !m.ConfigSyncStatus("test").Pending {
			t.Fatal("config marked applied although the restart failed")
		}
	})
}
