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
	"strings"
	"testing"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

func TestOperationLeaseSerializesAndReenters(t *testing.T) {
	m := &Manager{}
	ctx, release, err := m.BeginOperation(context.Background(), "a", "operation-a", "toggle")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if OperationID(ctx) != "operation-a" {
		t.Fatal("operation identity lost")
	}
	_, nestedRelease, err := m.BeginOperation(ctx, "a", "", "config_sync")
	if err != nil {
		t.Fatal(err)
	}
	nestedRelease()
	if activity, busy := m.OperationStatus("a"); !busy || activity.ID != "operation-a" {
		t.Fatal("nested operation released outer lease")
	}
	limited, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := m.BeginOperation(limited, "a", "operation-a", "restart"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same textual ID bypassed lease: %v", err)
	}
	_, otherRelease, err := m.BeginOperation(context.Background(), "b", "operation-b", "restart")
	if err != nil {
		t.Fatal(err)
	}
	otherRelease()
	release()
	if _, busy := m.OperationStatus("a"); busy {
		t.Fatal("released lease stayed busy")
	}
}

func TestAliasesShareDaemonLeaseAndCannotBeReconfiguredWhileBusy(t *testing.T) {
	m := &Manager{}
	servers := []shared.Fail2banServer{{ID: "a", Type: "local", SocketPath: "/run/fail2ban/fail2ban.sock"}, {ID: "alias", Type: "local", SocketPath: "/var/run/fail2ban/fail2ban.sock", ConfigPath: "/different/config"}}
	if err := m.ConfigureOperationTargets(servers); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := m.BeginOperation(context.Background(), "a", "op", "toggle")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, busy := m.OperationStatus("alias"); !busy {
		t.Fatal("alias did not see daemon operation")
	}
	_, nestedRelease, err := m.BeginOperation(ctx, "alias", "op", "sync")
	if err != nil {
		t.Fatal(err)
	}
	nestedRelease()
	limited, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := m.BeginOperation(limited, "alias", "other", "toggle"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("alias bypassed mutation gate: %v", err)
	}
	servers[0].SocketPath = "/run/other.sock"
	if err := m.ConfigureOperationTargets(servers); err == nil {
		t.Fatal("active operation target was moved")
	}
	release()
	if err := m.ConfigureOperationTargets(servers); err != nil {
		t.Fatal(err)
	}
}

func TestConfigSyncSchedulerDefersWritesUntilDurableWorker(t *testing.T) {
	conn := &syncTestConnector{}
	m := &Manager{connectors: map[string]Connector{"test": conn}}
	m.RequestConfigSync("test", false, true)
	var queued []string
	m.SetConfigSyncScheduler(func(id string) { queued = append(queued, id) })
	if err := m.SyncServerConfig(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	if len(queued) != 1 || conn.writes != 0 || conn.reloads != 0 {
		t.Fatal("scheduler executed config writes inline")
	}
	ctx, release, err := m.BeginOperation(context.Background(), "test", "durable-sync", "server.sync")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var phases []string
	ctx = WithOperationCheckpoint(ctx, func(_ context.Context, phase string) error { phases = append(phases, phase); return nil })
	if err := m.SyncServerConfig(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	if conn.writes != 1 || conn.reloads != 1 || len(phases) != 4 {
		t.Fatalf("worker phases=%v writes=%d reloads=%d", phases, conn.writes, conn.reloads)
	}
}

func TestBusyConnectorCannotBeReplacedOrDisabled(t *testing.T) {
	server := shared.Fail2banServer{ID: "active", Type: "local", Name: "original", Enabled: true, SocketPath: "/run/fail2ban/fail2ban.sock"}
	old := NewLocalConnector(server)
	m := &Manager{connectors: map[string]Connector{server.ID: old}}
	if err := m.ConfigureOperationTargets([]shared.Fail2banServer{server}); err != nil {
		t.Fatal(err)
	}
	_, release, err := m.BeginOperation(context.Background(), server.ID, "active-op", "jail.manage")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	changed := server
	changed.Name = "replacement"
	if err := m.ReloadFromServers([]shared.Fail2banServer{changed}); err == nil {
		t.Fatal("replaced a live connector")
	}
	changed = server
	changed.Enabled = false
	if err := m.ReloadFromServers([]shared.Fail2banServer{changed}); err == nil {
		t.Fatal("disabled an active target")
	}
	if got, _ := m.Connector(server.ID); got != old {
		t.Fatal("rejected change altered the connector registry")
	}
}

func TestServerConfigurationGuardClosesAdmissionRace(t *testing.T) {
	m := &Manager{}
	releaseConfig := m.GuardServerConfiguration()
	started := make(chan struct{})
	acquired := make(chan struct{})
	go func() {
		close(started)
		_, release, err := m.BeginOperation(context.Background(), "a", "new", "toggle")
		if err == nil {
			close(acquired)
			release()
		}
	}()
	<-started
	select {
	case <-acquired:
		t.Fatal("operation started between server-edit preflight and persistence")
	case <-time.After(20 * time.Millisecond):
	}
	releaseConfig()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("configuration guard did not release operation admission")
	}
}

func TestVerifiedDaemonResponseClearsBusyTimeoutImmediately(t *testing.T) {
	conn := &probeTestConnector{id: "verified"}
	m := &Manager{connectors: map[string]Connector{"verified": conn}}
	_, release, err := m.BeginOperation(context.Background(), "verified", "stop-job", "jail.manage")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	m.recordHealth(conn, ServerHealth{Error: "fail2ban ping failed: signal: killed"}, time.Now())
	if h := m.Health("verified"); h.State != HealthBusy {
		t.Fatalf("stop not busy: %+v", h)
	}
	m.ObserveDaemonResponse(conn)
	if h := m.Health("verified"); h.State != HealthBusy || !h.Fail2banOK || h.Error != "" {
		t.Fatalf("verified response did not clear old timeout: %+v", h)
	}
	release()
	if h := m.Health("verified"); h.State != HealthOK || !h.Fail2banOK || h.Error != "" || h.OperationID != "" {
		t.Fatalf("finished operation still offline: %+v", h)
	}
}

func TestVerifiedDaemonResponsePreservesFailedCallbackHealth(t *testing.T) {
	conn := &probeTestConnector{id: "callback"}
	m := &Manager{connectors: map[string]Connector{"callback": conn}}
	no := false
	m.recordHealth(conn, ServerHealth{Fail2banOK: true, CallbackOK: &no, Error: "callback endpoint refused connection"}, time.Now())
	m.ObserveDaemonResponse(conn)
	if h := m.Health("callback"); h.State != HealthDegraded || !h.Fail2banOK || h.CallbackOK == nil || *h.CallbackOK || h.Error != "callback endpoint refused connection" {
		t.Fatalf("live daemon falsely repaired callback: %+v", h)
	}
	// A busy ping does not re-check callbacks, so its result omits CallbackOK.
	m.recordHealth(conn, ServerHealth{Error: "fail2ban ping failed: signal: killed"}, time.Now())
	m.ObserveDaemonResponse(conn)
	if h := m.Health("callback"); h.State != HealthDegraded || h.Error == "" || strings.Contains(h.Error, "signal: killed") {
		t.Fatalf("callback state lost or stale ping retained: %+v", h)
	}
}

func TestOlderProbeCannotOverwriteNewVerifiedResponse(t *testing.T) {
	conn := &probeTestConnector{id: "probe-race"}
	m := &Manager{connectors: map[string]Connector{"probe-race": conn}}
	started := time.Now().Add(-time.Second)
	m.ObserveDaemonResponse(conn)
	m.recordProbeHealth(conn, ServerHealth{Error: "fail2ban ping failed: signal: killed"}, started, time.Now())
	if h := m.Health("probe-race"); h.State != HealthOK || h.Error != "" {
		t.Fatalf("old probe replaced newer success: %+v", h)
	}
	m.recordProbeHealth(conn, ServerHealth{Error: "new connection refused"}, time.Now().Add(time.Second), time.Now().Add(2*time.Second))
	if h := m.Health("probe-race"); h.State != HealthDown {
		t.Fatalf("new failure was hidden: %+v", h)
	}
}

func TestOperationHealthDoesNotConfuseDaemonContentionAndNetworkLoss(t *testing.T) {
	m := &Manager{}
	_, release, err := m.BeginOperation(context.Background(), "a", "op", "toggle")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	h := m.operationHealth("a", ServerHealth{State: HealthDown, Error: "remote fail2ban ping failed: context deadline exceeded"})
	if h.State != HealthBusy || h.OperationID != "op" {
		t.Fatalf("busy daemon shown offline: %+v", h)
	}
	h = m.operationHealth("a", ServerHealth{State: HealthDown, Error: "ssh: connection refused"})
	if h.State != HealthDown || h.Busy {
		t.Fatalf("transport outage hidden: %+v", h)
	}
	no := false
	h = m.operationHealth("a", ServerHealth{State: HealthDown, Error: "timeout", TransportOK: &no})
	if h.State != HealthDown {
		t.Fatal("confirmed transport failure was suppressed")
	}
	h = m.operationHealth("a", ServerHealth{State: HealthDegraded, Fail2banOK: true, Error: "callback probe failed: connection refused", CallbackOK: &no})
	if h.State != HealthBusy || !h.Fail2banOK || h.Error == "" {
		t.Fatalf("callback outage was confused with target connectivity: %+v", h)
	}
}
