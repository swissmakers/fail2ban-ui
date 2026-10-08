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

func TestDeriveHealthState(t *testing.T) {
	yes, no := true, false
	tests := []struct {
		name string
		h    ServerHealth
		want HealthState
	}{
		{"fail2ban down", ServerHealth{Fail2banOK: false, CallbackOK: &yes}, HealthDown},
		{"callback n/a", ServerHealth{Fail2banOK: true}, HealthOK},
		{"callback ok", ServerHealth{Fail2banOK: true, CallbackOK: &yes}, HealthOK},
		{"callback broken", ServerHealth{Fail2banOK: true, CallbackOK: &no}, HealthDegraded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveHealthState(tt.h); got != tt.want {
				t.Fatalf("deriveHealthState = %s, want %s", got, tt.want)
			}
		})
	}
}

type probeTestConnector struct {
	syncTestConnector
	id     string
	health func(ctx context.Context) ServerHealth
}

func (c *probeTestConnector) Server() shared.Fail2banServer {
	return shared.Fail2banServer{ID: c.id, Name: c.id}
}
func (c *probeTestConnector) ProbeHealth(ctx context.Context) ServerHealth { return c.health(ctx) }
func (c *probeTestConnector) Close() error                                 { return nil }

func TestRecordHealthNotifiesOnStateChangeOnly(t *testing.T) {
	a := &probeTestConnector{id: "a"}
	m := &Manager{connectors: map[string]Connector{"a": a}}
	var events []HealthState
	m.SetHealthListener(func(_ string, h ServerHealth) { events = append(events, h.State) })
	now := time.Now()
	m.recordHealth(a, ServerHealth{Fail2banOK: true}, now)
	m.recordHealth(a, ServerHealth{Fail2banOK: true}, now)
	m.recordHealth(a, ServerHealth{Error: "down"}, now)
	m.recordHealth(a, ServerHealth{Error: "still down, other reason"}, now)
	m.recordHealth(&probeTestConnector{id: "gone"}, ServerHealth{Fail2banOK: true}, now)
	if len(events) != 2 || events[0] != HealthOK || events[1] != HealthDown {
		t.Fatalf("events = %v, want [ok down]", events)
	}
	if h := m.Health("a"); h.State != HealthDown || h.Error != "still down, other reason" || h.CheckedAt.IsZero() {
		t.Fatalf("latest health not stored: %+v", h)
	}
	if h := m.Health("gone"); h.State != HealthUnknown {
		t.Fatalf("removed server must stay unknown, got %+v", h)
	}
	m.connectors["a"] = &probeTestConnector{id: "a"}
	m.recordHealth(a, ServerHealth{Fail2banOK: true}, now)
	if m.Health("a").State != HealthDown {
		t.Fatal("a probe of a replaced connector must not overwrite the entry")
	}
}

func TestProbeAllRecordsSlowServerAsDown(t *testing.T) {
	slow := &probeTestConnector{id: "slow", health: func(ctx context.Context) ServerHealth {
		<-ctx.Done()
		return ServerHealth{Error: ctx.Err().Error()}
	}}
	fast := &probeTestConnector{id: "fast", health: func(context.Context) ServerHealth { return ServerHealth{Fail2banOK: true} }}
	m := &Manager{connectors: map[string]Connector{"slow": slow, "fast": fast}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	probeCtx, probeCancel := context.WithCancel(ctx)
	go func() { time.Sleep(50 * time.Millisecond); probeCancel() }()
	m.ProbeAll(probeCtx)
	if time.Since(start) > 2*time.Second {
		t.Fatal("ProbeAll waited for the slow server past its context")
	}
	if m.Health("fast").State != HealthOK {
		t.Fatalf("fast server = %+v", m.Health("fast"))
	}
	if m.Health("slow").State != HealthUnknown {
		t.Fatalf("a probe cut off by shutdown must not be recorded, got %+v", m.Health("slow"))
	}
}

func TestReloadPrunesServerState(t *testing.T) {
	m := &Manager{connectors: map[string]Connector{}, monitorKick: make(chan struct{}, 1)}
	gone := &probeTestConnector{id: "gone"}
	m.connectors["gone"] = gone
	m.recordHealth(gone, ServerHealth{Fail2banOK: true}, time.Now())
	m.RequestConfigSync("gone", true, true)
	m.repairAt = map[string]time.Time{"gone": time.Now()}
	if err := m.ReloadFromServers(nil); err != nil {
		t.Fatal(err)
	}
	if m.Health("gone").State != HealthUnknown || len(m.configSync) != 0 || len(m.repairAt) != 0 {
		t.Fatalf("state of a removed server survived: health=%+v sync=%d repair=%d", m.Health("gone"), len(m.configSync), len(m.repairAt))
	}
}

func TestRepairDebounce(t *testing.T) {
	conn := &syncTestConnector{writeErr: errors.New("offline")}
	m := &Manager{connectors: map[string]Connector{"test": conn}}
	if !m.Repair(context.Background(), "test", false, true) {
		t.Fatal("first repair must run")
	}
	if m.Repair(context.Background(), "test", false, true) {
		t.Fatal("repeat inside the debounce window must be skipped")
	}
	m.repairAt["test"] = time.Now().Add(-repairDebounce - time.Second)
	if !m.Repair(context.Background(), "test", false, true) {
		t.Fatal("repair after the window must run again")
	}
	if m.Repair(context.Background(), "other", false, false) {
		t.Fatal("nothing to repair must be a no-op")
	}
}
