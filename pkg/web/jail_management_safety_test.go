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
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/operations"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

type jailSafetyConnector struct {
	fail2ban.Connector
	mu                                     sync.Mutex
	id, config                             string
	enabled, running, original             bool
	files                                  []string
	probeErr, validationErr, reloadErr     error
	validations, writes, reloads, restores int
	reloadStarted, reloadRelease           chan struct{}
}

func (f *jailSafetyConnector) Server() shared.Fail2banServer {
	return shared.Fail2banServer{ID: f.id, Name: f.id}
}
func (f *jailSafetyConnector) GetJailConfig(context.Context, string) (string, string, error) {
	return f.config, "", nil
}
func (f *jailSafetyConnector) GetJailSummary(ctx context.Context) (*fail2ban.JailSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	summary := &fail2ban.JailSummary{Jails: []fail2ban.JailInfo{}, JailLocalExists: true, JailLocalManaged: true}
	if f.running {
		summary.Jails = append(summary.Jails, fail2ban.JailInfo{JailName: "example", Enabled: true})
	}
	return summary, ctx.Err()
}
func (f *jailSafetyConnector) GetAllJails(ctx context.Context) ([]fail2ban.JailInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []fail2ban.JailInfo{{JailName: "example", Enabled: f.enabled}}, ctx.Err()
}
func (f *jailSafetyConnector) TestLogpathWithResolution(_ context.Context, path string) (string, string, []string, error) {
	return path, path, f.files, f.probeErr
}
func (f *jailSafetyConnector) UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	f.writes++
	f.enabled = updates["example"]
	return nil
}
func (f *jailSafetyConnector) ValidateConfiguration(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validations++
	if f.enabled {
		return f.validationErr
	}
	return ctx.Err()
}
func (f *jailSafetyConnector) Reload(ctx context.Context) error {
	f.mu.Lock()
	f.reloads++
	start, release := f.reloadStarted, f.reloadRelease
	f.mu.Unlock()
	if start != nil {
		select {
		case start <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running = f.enabled
	return f.reloadErr
}
func (f *jailSafetyConnector) BackupConfiguration(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.original = f.enabled
	return nil
}
func (f *jailSafetyConnector) RestoreConfiguration(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = f.original
	f.restores++
	return nil
}
func (f *jailSafetyConnector) DeleteConfigurationBackup(context.Context, string) error { return nil }

func transactionTestEngine(t *testing.T, conn fail2ban.Connector) *operations.Engine {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "ops.db")+"?_pragma=busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewOperationStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := operations.NewWithStore(store, func(ctx context.Context, op operations.Operation) (json.RawMessage, error) {
		var p operationPayload
		_ = json.Unmarshal(op.Payload, &p)
		tx := operationTransaction{op: op, payload: p, conn: conn}
		response, err := tx.run(ctx)
		if response == nil {
			response = gin.H{}
		}
		if err != nil {
			response["error"] = err.Error()
		}
		data, _ := json.Marshal(response)
		return data, err
	})
	if err = e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = e.Close(ctx)
		_ = db.Close()
	})
	return e
}
func awaitOperation(t *testing.T, e *operations.Engine, id, state string) operations.Operation {
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
		if op.Terminal() {
			t.Fatalf("state=%s want=%s error=%s result=%s", op.State, state, op.Error, op.Result)
		}
		time.Sleep(5 * time.Millisecond)
	}
	op, _ := e.Get(context.Background(), id)
	t.Fatalf("timeout state=%s phase=%s want=%s error=%s", op.State, op.Phase, state, op.Error)
	return op
}
func submitJailUpdate(t *testing.T, e *operations.Engine, conn fail2ban.Connector, enabled bool) operations.Operation {
	t.Helper()
	payload, _ := json.Marshal(operationPayload{Fingerprint: serverFingerprint(conn.Server()), Body: json.RawMessage(fmt.Sprintf(`{"example":%t}`, enabled))})
	op, err := e.Submit(context.Background(), conn.Server().ID, "jail.manage", "example", "", payload)
	if err != nil {
		t.Fatal(err)
	}
	return op
}
func TestJailEnableRequiresFail2banValidation(t *testing.T) {
	for _, tc := range []struct {
		name, config                          string
		inaccessible, invalid, found, missing bool
	}{
		{name: "missing logpath rejected", config: "[example]\nbackend = polling\n", invalid: true},
		{name: "restricted missing logs rejected", config: "[example]\nlogpath = /var/log/httpd/*error_log\n", inaccessible: true, invalid: true},
		{name: "restricted valid logs accepted", config: "[example]\nlogpath = /var/log/httpd/*error_log\n", inaccessible: true},
		{name: "systemd needs no logpath", config: "[example]\nbackend = systemd\n"},
		{name: "inherited logpath accepted", config: "[example]\nenabled = false\n"},
		{name: "readable logpath accepted", config: "[example]\nlogpath = /var/log/app.log\n", found: true},
		{name: "missing files rejected before write", config: "[example]\nlogpath = /var/log/missing.log\n", missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &jailSafetyConnector{id: t.Name(), config: tc.config}
			if tc.inaccessible {
				conn.probeErr = fail2ban.ErrLogpathInaccessible
			}
			if tc.invalid {
				conn.validationErr = errors.New("Have not found any log file for example jail")
			}
			if tc.found {
				conn.files = []string{"/var/log/app.log"}
			}
			e := transactionTestEngine(t, conn)
			op := submitJailUpdate(t, e, conn, true)
			state := "succeeded"
			if tc.invalid || tc.missing {
				state = "failed"
			}
			op = awaitOperation(t, e, op.ID, state)
			conn.mu.Lock()
			defer conn.mu.Unlock()
			if state == "failed" && conn.enabled {
				t.Fatal("invalid configuration left enabled on disk")
			}
			if tc.missing {
				if conn.writes != 0 || conn.reloads != 0 {
					t.Fatal("known missing files must reject before writes")
				}
				return
			}
			if tc.invalid {
				if conn.reloads != 0 || conn.restores != 1 || !strings.Contains(string(op.Result), `"configurationRestored":true`) {
					t.Fatalf("unsafe rejection: reloads=%d restores=%d result=%s", conn.reloads, conn.restores, op.Result)
				}
			} else if conn.validations != 1 || conn.reloads != 1 {
				t.Fatalf("validations=%d reloads=%d", conn.validations, conn.reloads)
			}
		})
	}
}
func TestAcceptedJailChangeSurvivesBrowserDisconnect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	conn := &jailSafetyConnector{id: t.Name(), config: "[example]\n", reloadStarted: make(chan struct{}, 1), reloadRelease: make(chan struct{})}
	e := transactionTestEngine(t, conn)
	svc := &operationController{engine: e}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	c.Request = httptest.NewRequest("POST", "/api/jails/manage", strings.NewReader(`{"example":true}`)).WithContext(ctx)
	enqueueOperation(c, svc, conn, "jail.manage")
	if response.Code != http.StatusAccepted {
		t.Fatalf("expected immediate202: %d %s", response.Code, response.Body)
	}
	var accepted struct {
		Operation operations.Operation `json:"operation"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.reloadStarted:
	case <-time.After(time.Second):
		t.Fatal("reload did not start")
	}
	cancel()
	next := submitJailUpdate(t, e, conn, false)
	op, err := e.Get(context.Background(), next.ID)
	if err != nil || op.State != "queued" {
		t.Fatalf("second action did not queue: %+v %v", op, err)
	}
	if _, err = e.Cancel(context.Background(), next.ID); err != nil {
		t.Fatal(err)
	}
	close(conn.reloadRelease)
	awaitOperation(t, e, accepted.Operation.ID, "succeeded")
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.reloads != 1 || !conn.running {
		t.Fatalf("disconnect interrupted or replayed command: reloads=%d running=%v", conn.reloads, conn.running)
	}
}
func TestLostReloadReplyDoesNotRollbackOrRetry(t *testing.T) {
	conn := &jailSafetyConnector{id: t.Name(), config: "[example]\n", reloadErr: context.DeadlineExceeded}
	e := transactionTestEngine(t, conn)
	op := submitJailUpdate(t, e, conn, true)
	op = awaitOperation(t, e, op.ID, "reconciling")
	var payload operationPayload
	_ = json.Unmarshal(op.Payload, &payload)
	tx := operationTransaction{op: op, payload: payload, conn: conn}
	result, known, err := tx.reconcile(context.Background())
	if !known || err != nil {
		t.Fatalf("applied runtime did not reconcile: known=%v err=%v result=%v", known, err, result)
	}
	data, _ := json.Marshal(result)
	if _, err = e.Resolve(context.Background(), op.ID, data, nil); err != nil {
		t.Fatal(err)
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.restores != 0 || conn.reloads != 1 || !conn.enabled {
		t.Fatalf("lost reply caused mutation: restores=%d reloads=%d", conn.restores, conn.reloads)
	}
}
func TestInterruptedWriteRestoresWithoutReload(t *testing.T) {
	conn := &jailSafetyConnector{id: t.Name(), enabled: true, original: false, config: "[example]\n"}
	recovery, _ := json.Marshal(operationRecovery{Stage: "writing", BackupID: "saved"})
	tx := operationTransaction{op: operations.Operation{Recovery: recovery}, conn: conn}
	result, known, err := tx.reconcile(context.Background())
	if !known || err == nil || result["configurationRestored"] != true {
		t.Fatalf("recovery=%v known=%v err=%v", result, known, err)
	}
	if conn.enabled || conn.restores != 1 || conn.reloads != 0 {
		t.Fatalf("unsafe recovery %+v", conn)
	}
}

type offlineRestartConnector struct {
	*jailSafetyConnector
	serviceUp                           bool
	restarts, summaryReadsBeforeRestart int
}

func (c *offlineRestartConnector) GetJailSummary(ctx context.Context) (*fail2ban.JailSummary, error) {
	c.mu.Lock()
	up := c.serviceUp
	if !up {
		c.summaryReadsBeforeRestart++
	}
	c.mu.Unlock()
	if !up {
		return nil, errors.New("Fail2ban socket is unavailable while the daemon is stopped")
	}
	return c.jailSafetyConnector.GetJailSummary(ctx)
}

func (c *offlineRestartConnector) Restart(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "restart", err
	}
	c.restarts++
	c.serviceUp = true
	c.running = c.enabled
	return "restart", nil
}

func TestRestartOperationRecoversAnOfflineDaemon(t *testing.T) {
	conn := &offlineRestartConnector{jailSafetyConnector: &jailSafetyConnector{id: t.Name(), config: "[example]\n", enabled: true}}
	e := transactionTestEngine(t, conn)
	payload, _ := json.Marshal(operationPayload{Fingerprint: serverFingerprint(conn.Server())})
	op, err := e.Submit(context.Background(), conn.Server().ID, "server.restart", "", "", payload)
	if err != nil {
		t.Fatal(err)
	}
	op = awaitOperation(t, e, op.ID, "succeeded")
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if !conn.serviceUp || conn.restarts != 1 || conn.validations != 1 || conn.summaryReadsBeforeRestart != 0 {
		t.Fatalf("restart required an already-running daemon: up=%v restarts=%d validations=%d early-summary-reads=%d", conn.serviceUp, conn.restarts, conn.validations, conn.summaryReadsBeforeRestart)
	}
	if !strings.Contains(string(op.Result), `"mode":"restart"`) {
		t.Fatalf("restart mode missing: %s", op.Result)
	}
}

type slowStartRestartConnector struct {
	*jailSafetyConnector
}

func (c *slowStartRestartConnector) Restart(context.Context) (string, error) {
	return "restart", fmt.Errorf("%w: fail2ban ping error: socket missing", fail2ban.ErrRestartNotResponding)
}

func TestRestartAcceptedButSlowToAnswerReconcilesAsSucceeded(t *testing.T) {
	conn := &slowStartRestartConnector{&jailSafetyConnector{id: t.Name(), config: "[example]\n", enabled: true, running: true}}
	e := transactionTestEngine(t, conn)
	payload, _ := json.Marshal(operationPayload{Fingerprint: serverFingerprint(conn.Server())})
	op, err := e.Submit(context.Background(), conn.Server().ID, "server.restart", "", "", payload)
	if err != nil {
		t.Fatal(err)
	}
	op = awaitOperation(t, e, op.ID, "reconciling")
	var recovery operationRecovery
	if err := json.Unmarshal(op.Recovery, &recovery); err != nil || recovery.Stage != "applied" {
		t.Fatalf("an accepted restart must be recorded as applied: stage=%q err=%v", recovery.Stage, err)
	}
	tx := operationTransaction{op: op, payload: operationPayload{Fingerprint: serverFingerprint(conn.Server())}, conn: conn}
	result, known, err := tx.reconcile(context.Background())
	if !known || err != nil || result["outcomeUnconfirmed"] != nil {
		t.Fatalf("restart must reconcile as succeeded once Fail2ban answers: known=%v err=%v result=%v", known, err, result)
	}
}

func TestUnknownReloadCannotProveConfigurationFromMatchingJailStates(t *testing.T) {
	for _, kind := range []string{"jail.config", "jail.create", "filter.create", "filter.delete", "server.sync", "server.restart"} {
		t.Run(kind, func(t *testing.T) {
			conn := &jailSafetyConnector{id: t.Name(), config: "[example]\nenabled=true\nmaxretry=3\n", enabled: true, running: true}
			recovery, _ := json.Marshal(operationRecovery{Stage: "applying", DesiredStates: map[string]bool{"example": true}})
			tx := operationTransaction{op: operations.Operation{Kind: kind, Recovery: recovery}, payload: operationPayload{Jail: "example", Body: json.RawMessage(`{"jail":"[example]\nenabled=true\nmaxretry=20\n"}`)}, conn: conn}
			result, known, err := tx.reconcile(context.Background())
			if !known || err == nil || result["outcomeUnconfirmed"] != true {
				t.Fatalf("matching enabled flags falsely proved configuration: known=%v err=%v result=%v", known, err, result)
			}
			if conn.reloads != 0 || conn.restores != 0 || conn.writes != 0 {
				t.Fatal("uncertain configuration was replayed or rolled back")
			}
		})
	}
}

func TestBanVerificationUsesCanonicalAddresses(t *testing.T) {
	for _, tc := range []struct {
		requested, reported string
		equal               bool
	}{
		{"2001:0DB8:0000:0000:0000:0000:0000:1", "2001:db8::1", true},
		{"198.18.0.15/24", "198.18.0.0/24", true},
		{"198.18.0.1/32", "198.18.0.1", true},
		{"2001:db8::1", "2001:db8::2", false},
	} {
		tx := operationTransaction{op: operations.Operation{Kind: "jail.ban"}, payload: operationPayload{Jail: "example", IP: tc.requested}}
		snap := &ServerSnapshot{Summary: &fail2ban.JailSummary{Jails: []fail2ban.JailInfo{{JailName: "example", BannedIPs: []string{tc.reported}}}}}
		if err := tx.verify(snap); (err == nil) != tc.equal {
			t.Fatalf("verify %s as %s = %v", tc.requested, tc.reported, err)
		}
	}
}
