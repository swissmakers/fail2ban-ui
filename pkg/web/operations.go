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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/auth"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/operations"
	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

type operationPayload struct {
	Fingerprint string          `json:"fingerprint"`
	Body        json.RawMessage `json:"body,omitempty"`
	Jail        string          `json:"jail,omitempty"`
	Filter      string          `json:"filter,omitempty"`
	IP          string          `json:"ip,omitempty"`
}
type publicOperation struct {
	operations.Operation
	DesiredStates map[string]bool `json:"desiredStates,omitempty"`
}

func exposeOperation(op operations.Operation) publicOperation {
	view := publicOperation{Operation: op}
	if op.Kind == "jail.manage" {
		var p operationPayload
		if json.Unmarshal(op.Payload, &p) == nil {
			_ = json.Unmarshal(p.Body, &view.DesiredStates)
		}
	}
	return view
}

// Configuration errors can contain remote paths or command output. Read-only
// viewers receive progress metadata; only administrators receive diagnostics.
func redactOperation(view publicOperation, admin bool) publicOperation {
	if admin {
		view.Error = config.RedactLog(view.Error)
		return view
	}
	if view.State == "reconciling" {
		view.Message = "Checking the server before allowing further changes. An administrator can view diagnostic details."
	}
	if view.Error != "" {
		view.Error = "Operation failed. An administrator can view the details."
	}
	if view.State == "succeeded" {
		view.Result = json.RawMessage(`{"message":"Change applied and server state verified"}`)
	} else {
		view.Result = nil
	}
	return view
}

// Identify the actual target independently of display names, credentials and
// default-server selection. A queued change must never follow a repointed entry.
func serverFingerprint(s shared.Fail2banServer) string {
	data, _ := json.Marshal([]any{s.Type, s.Host, s.Port, s.SSHUser, s.SocketPath, s.ConfigPath, s.AgentURL})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type operationLease struct {
	ctx     context.Context
	release func()
}
type operationController struct {
	engine     *operations.Engine
	manager    *fail2ban.Manager
	mu         sync.Mutex
	scheduleMu sync.Mutex
	leases     map[string]operationLease
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
}

var operationService *operationController

// Reserve interrupted targets before connectors start their health/repair loop.
func PrepareOperations(ctx context.Context) error {
	svc := &operationController{manager: fail2ban.GetManager(), leases: map[string]operationLease{}, done: make(chan struct{})}
	if err := svc.manager.ConfigureOperationTargets(config.GetSettings().Servers); err != nil {
		return err
	}
	svc.ctx, svc.cancel = context.WithCancel(ctx)
	svc.engine = operations.New(svc.execute)
	pending, err := svc.engine.InFlight(ctx)
	if err != nil {
		return err
	}
	for _, op := range pending {
		if op.State != "running" && op.State != "reconciling" {
			continue
		}
		var recovery operationRecovery
		if len(op.Recovery) == 0 || (json.Unmarshal(op.Recovery, &recovery) == nil && (recovery.Stage == "preparing" || recovery.Stage == "restored")) {
			continue
		}
		leaseCtx, cancelLease := context.WithTimeout(ctx, time.Second)
		held, release, err := svc.manager.BeginOperation(leaseCtx, op.ServerID, op.ID, op.Kind)
		cancelLease()
		if err != nil {
			for _, lease := range svc.leases {
				lease.release()
			}
			return err
		}
		svc.leases[op.ID] = operationLease{ctx: context.WithoutCancel(held), release: release}
	}
	operationService = svc
	svc.manager.SetConfigSyncScheduler(svc.scheduleConfigSync)
	svc.engine.SetListener(func(op operations.Operation) {
		if op.Terminal() || op.Phase == "applying" {
			InvalidateServerSnapshot(op.ServerID)
		}
		if wsHub == nil {
			return
		}
		data, err := json.Marshal(gin.H{"type": "operation", "data": exposeOperation(op)})
		if err != nil {
			return
		}
		select {
		case wsHub.broadcast <- data:
		default:
		}
	})
	return nil
}
func StartOperations() error {
	if operationService == nil {
		return errors.New("operations not prepared")
	}
	svc := operationService
	if err := svc.engine.Start(svc.ctx); err != nil {
		return err
	}
	go svc.reconcileLoop()
	return nil
}
func CloseOperations(ctx context.Context) error {
	if operationService == nil {
		return nil
	}
	svc := operationService
	svc.cancel()
	err := svc.engine.Close(ctx)
	select {
	case <-svc.done:
	case <-ctx.Done():
		if err == nil {
			err = ctx.Err()
		}
	}
	return err
}
func (s *operationController) release(id string) {
	s.mu.Lock()
	lease, ok := s.leases[id]
	if ok {
		delete(s.leases, id)
	}
	s.mu.Unlock()
	if ok {
		lease.release()
	}
}

func submitOperation(c *gin.Context, kind string) {
	if operationService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Background operations are not available"})
		return
	}
	conn, err := resolveConnector(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, buildErrorResponse(err, ""))
		return
	}
	enqueueOperation(c, operationService, conn, kind)
}

func enqueueOperation(c *gin.Context, svc *operationController, conn fail2ban.Connector, kind string) {
	p := operationPayload{Fingerprint: serverFingerprint(conn.Server()), Jail: c.Param("jail"), Filter: c.Param("filter"), IP: c.Param("ip")}
	if c.Request.Body != nil {
		data, err := io.ReadAll(io.LimitReader(c.Request.Body, (1<<20)+1))
		if err != nil {
			c.JSON(400, gin.H{"error": "Unable to read request"})
			return
		}
		if len(data) > 1<<20 {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Request exceeds 1 MiB"})
			return
		}
		if len(strings.TrimSpace(string(data))) > 0 {
			if !json.Valid(data) {
				c.JSON(400, gin.H{"error": "Invalid JSON"})
				return
			}
			p.Body = data
		}
	}
	target, err := validateOperationPayload(kind, p)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	payload, _ := json.Marshal(p)
	op, err := svc.engine.Submit(c.Request.Context(), conn.Server().ID, kind, target, c.GetHeader("Idempotency-Key"), payload)
	if err != nil {
		status := 500
		if errors.Is(err, operations.ErrIdempotencyConflict) {
			status = 409
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.Header("Location", shared.BasePath()+"/api/operations/"+op.ID)
	c.JSON(http.StatusAccepted, gin.H{"operation": redactOperation(exposeOperation(op), userHasAdminAccess(c))})
}
func validateOperationPayload(kind string, p operationPayload) (string, error) {
	switch kind {
	case "jail.manage":
		var updates map[string]bool
		if err := json.Unmarshal(p.Body, &updates); err != nil {
			return "", errors.New("Expected jail enabled states")
		}
		if len(updates) == 0 {
			return "", errors.New("No jail updates provided")
		}
		names := make([]string, 0, len(updates))
		for name := range updates {
			if err := fail2ban.ValidateJailName(name); err != nil {
				return "", err
			}
			names = append(names, name)
		}
		sort.Strings(names)
		return strings.Join(names, ", "), nil
	case "jail.config":
		if err := fail2ban.ValidateJailName(p.Jail); err != nil {
			return "", err
		}
		var req jailConfigRequest
		if err := json.Unmarshal(p.Body, &req); err != nil {
			return "", err
		}
		if req.Jail == "" && req.Filter == "" {
			return "", errors.New("No configuration provided")
		}
		return p.Jail, nil
	case "jail.create":
		var req jailCreateRequest
		if err := json.Unmarshal(p.Body, &req); err != nil {
			return "", err
		}
		return req.JailName, fail2ban.ValidateJailName(req.JailName)
	case "jail.delete":
		return p.Jail, fail2ban.ValidateJailName(p.Jail)
	case "filter.create":
		var req filterCreateRequest
		if err := json.Unmarshal(p.Body, &req); err != nil {
			return "", err
		}
		return req.FilterName, fail2ban.ValidateFilterName(req.FilterName)
	case "filter.delete":
		return p.Filter, fail2ban.ValidateFilterName(p.Filter)
	case "jail.ban", "jail.unban":
		if err := fail2ban.ValidateJailName(p.Jail); err != nil {
			return "", err
		}
		if err := shared.ValidateIP(p.IP); err != nil {
			return "", err
		}
		return p.Jail + " / " + p.IP, nil
	case "server.restart", "server.sync":
		return "", nil
	default:
		return "", errors.New("Unknown operation kind")
	}
}
func ListOperationsHandler(c *gin.Context) {
	if operationService == nil {
		c.JSON(200, gin.H{"operations": []publicOperation{}})
		return
	}
	ops, err := operationService.engine.List(c.Request.Context(), c.Query("serverId"), 200)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	views := make([]publicOperation, 0, len(ops))
	for _, op := range ops {
		views = append(views, redactOperation(exposeOperation(op), userHasAdminAccess(c)))
	}
	c.JSON(200, gin.H{"operations": views})
}
func GetOperationHandler(c *gin.Context) {
	if operationService == nil {
		c.JSON(503, gin.H{"error": "Background operations are not available"})
		return
	}
	op, err := operationService.engine.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		status := 500
		if errors.Is(err, operations.ErrNotFound) {
			status = 404
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"operation": redactOperation(exposeOperation(op), userHasAdminAccess(c))})
}
func CancelOperationHandler(c *gin.Context) {
	if operationService == nil {
		c.JSON(503, gin.H{"error": "Background operations are not available"})
		return
	}
	op, err := operationService.engine.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "Operation not found"})
		return
	}
	permitted := userHasAdminAccess(c)
	if !permitted && (op.Kind == "jail.ban" || op.Kind == "jail.unban") {
		permitted = auth.SessionHasPermission(sessionFromContext(c), PermissionBan)
	}
	if !permitted {
		c.JSON(403, gin.H{"error": "Insufficient permissions"})
		return
	}
	op, err = operationService.engine.Cancel(c.Request.Context(), op.ID)
	if err != nil {
		c.JSON(409, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"operation": redactOperation(exposeOperation(op), userHasAdminAccess(c))})
}
func (s *operationController) execute(ctx context.Context, op operations.Operation) (result json.RawMessage, runErr error) {
	// A browser owns only submission. The worker owns the command lifetime.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	held, release, err := s.manager.BeginOperation(ctx, op.ServerID, op.ID, op.Kind)
	if err != nil {
		return nil, err
	}
	ctx = held
	s.mu.Lock()
	s.leases[op.ID] = operationLease{ctx: context.WithoutCancel(ctx), release: release}
	s.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			runErr = fmt.Errorf("%w: unexpected worker failure: %v", operations.ErrOutcomeUnknown, r)
		}
		if ctx.Err() != nil || errors.Is(runErr, fail2ban.ErrOperationOutcomeUnknown) {
			runErr = fmt.Errorf("%w: %v", operations.ErrOutcomeUnknown, runErr)
		}
		if !errors.Is(runErr, operations.ErrOutcomeUnknown) {
			s.release(op.ID)
		}
	}()
	conn, err := s.manager.Connector(op.ServerID)
	if err != nil {
		return nil, err
	}
	var payload operationPayload
	if err = json.Unmarshal(op.Payload, &payload); err != nil {
		return nil, err
	}
	if payload.Fingerprint != serverFingerprint(conn.Server()) {
		return nil, errors.New("Server connection changed after this operation was queued; submit the change again")
	}
	tx := operationTransaction{op: op, payload: payload, conn: conn}
	response, err := tx.run(ctx)
	if err != nil {
		if response == nil {
			response = gin.H{}
		}
		response["error"] = err.Error()
	}
	encoded, encodeErr := json.Marshal(response)
	if encodeErr != nil {
		return nil, encodeErr
	}
	return encoded, err
}
func (s *operationController) reconcileLoop() {
	defer close(s.done)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		s.reconcileAll()
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *operationController) reconcileAll() {
	ops, err := s.engine.InFlight(s.ctx)
	if err != nil {
		if s.ctx.Err() == nil {
			log.Printf("operation recovery list: %v", err)
		}
		return
	}
	var wg sync.WaitGroup
	for _, op := range ops {
		if op.State != "reconciling" {
			continue
		}
		wg.Add(1)
		go func(op operations.Operation) { defer wg.Done(); s.reconcile(op) }(op)
	}
	wg.Wait()
}
func (s *operationController) reconcile(op operations.Operation) {
	s.mu.Lock()
	lease, ok := s.leases[op.ID]
	s.mu.Unlock()
	if !ok {
		var recovery operationRecovery
		if len(op.Recovery) == 0 || (json.Unmarshal(op.Recovery, &recovery) == nil && (recovery.Stage == "preparing" || recovery.Stage == "restored")) {
			_, _ = s.engine.Resolve(s.ctx, op.ID, json.RawMessage(`{"error":"Operation interrupted before applying changes; submit it again"}`), errors.New("Interrupted before applying changes"))
		}
		return
	}
	ctx, cancel := context.WithTimeout(lease.ctx, 8*time.Second)
	defer cancel()
	// Also stop recovery reads when this process is shutting down.
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	conn, err := s.manager.Connector(op.ServerID)
	if err != nil {
		_ = s.engine.ReportReconciliation(ctx, op.ID, "Waiting for the original server connection to become available: "+err.Error())
		return
	}
	var p operationPayload
	if json.Unmarshal(op.Payload, &p) != nil || p.Fingerprint != serverFingerprint(conn.Server()) {
		_ = s.engine.ReportReconciliation(ctx, op.ID, "The server connection no longer matches the interrupted operation. Restore the original connection to verify its outcome.")
		return
	}
	tx := operationTransaction{op: op, payload: p, conn: conn}
	result, known, outcomeErr := tx.reconcile(ctx)
	if !known {
		message := "The previous command may still be running. Waiting for a confirmed server response before allowing more changes."
		if outcomeErr != nil {
			message = "Still checking the previous command: " + outcomeErr.Error()
		}
		_ = s.engine.ReportReconciliation(ctx, op.ID, message)
		return
	}
	encoded, _ := json.Marshal(result)
	if _, err := s.engine.Resolve(ctx, op.ID, encoded, outcomeErr); err != nil {
		return
	}
	tx.cleanup(ctx)
	s.release(op.ID)
}

// Automatic repairs and settings sync share the same durable queue and lease.
func (s *operationController) scheduleConfigSync(serverID string) {
	s.scheduleMu.Lock()
	defer s.scheduleMu.Unlock()
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
	defer cancel()
	active, err := s.engine.HasActiveKind(ctx, serverID, "server.sync")
	if err != nil {
		return
	}
	if active {
		return
	}
	conn, err := s.manager.Connector(serverID)
	if err != nil {
		return
	}
	p, _ := json.Marshal(operationPayload{Fingerprint: serverFingerprint(conn.Server())})
	if _, err := s.engine.Submit(ctx, serverID, "server.sync", "", "", p); err != nil && !errors.Is(err, operations.ErrNotStarted) {
		log.Printf("could not queue configuration sync for %s: %v", serverID, err)
	}
}
