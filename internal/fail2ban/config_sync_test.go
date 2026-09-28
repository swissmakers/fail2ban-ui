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
	writes, reloads int
	onReload        func()
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
	return nil
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
	cases := map[int]time.Duration{0: 0, 1: 0, 2: 2 * tunnelCheckInterval, 3: 4 * tunnelCheckInterval, 7: maxConfigRetryDelay, 500: maxConfigRetryDelay}
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

type appliedProbeProvider struct {
	testProvider
	m      *Manager
	called chan struct{}
}

func (p appliedProbeProvider) ConfigApplied(id string) {
	p.m.ConfigSyncStatus(id)
	close(p.called)
}

// ConfigApplied takes the settings lock and writes the DB, so it must not run under the sync lock.
func TestConfigAppliedRunsOutsideSyncLock(t *testing.T) {
	conn := &syncTestConnector{}
	m := &Manager{connectors: map[string]Connector{"test": conn}}
	probe := appliedProbeProvider{m: m, called: make(chan struct{})}
	SetProvider(probe)
	defer SetProvider(noopProvider{})
	m.RequestConfigSync("test", false, true)
	go func() { _ = m.SyncServerConfig(context.Background(), "test") }()
	select {
	case <-probe.called:
	case <-time.After(3 * time.Second):
		t.Fatal("deadlock: ConfigApplied was called while the sync lock was held")
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

// Config sync discovers validation through an optional interface; a rename would silently skip it.
var (
	_ interface{ ValidateConfiguration(context.Context) error } = (*SSHConnector)(nil)
	_ interface{ ValidateConfiguration(context.Context) error } = (*LocalConnector)(nil)
)
