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
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/operations"
)

type jailConfigRequest struct {
	Filter string `json:"filter"`
	Jail   string `json:"jail"`
}
type jailCreateRequest struct {
	JailName string `json:"jailName"`
	Content  string `json:"content"`
}
type filterCreateRequest struct {
	FilterName string `json:"filterName"`
	Content    string `json:"content"`
}

type operationRecovery struct {
	Stage         string          `json:"stage"`
	BackupID      string          `json:"backupId,omitempty"`
	DesiredStates map[string]bool `json:"desiredStates,omitempty"`
	Mode          string          `json:"mode,omitempty"`
	Failure       string          `json:"failure,omitempty"`
}
type operationTransaction struct {
	op       operations.Operation
	payload  operationPayload
	conn     fail2ban.Connector
	recovery operationRecovery
}

func (t *operationTransaction) checkpoint(ctx context.Context, stage string) error {
	t.recovery.Stage = stage
	data, err := json.Marshal(t.recovery)
	if err != nil {
		return err
	}
	if err = operations.SaveRecovery(ctx, data); err != nil {
		return err
	}
	messages := map[string]string{
		"preparing":    "Reading the current server state and saving a recovery copy",
		"writing":      "Saving configuration files on the server",
		"validating":   "Checking the complete configuration with Fail2ban",
		"applying":     "Fail2ban is applying the change. Stopping a jail may take time while firewall bans are removed.",
		"applied":      "Fail2ban acknowledged the change; checking the resulting state",
		"verifying":    "Refreshing the last confirmed jail states and ban counts",
		"rolling_back": "Validation failed; restoring the original configuration files",
		"restored":     "Original configuration files restored",
	}
	return operations.Report(ctx, stage, messages[stage])
}
func (t *operationTransaction) run(ctx context.Context) (gin.H, error) {
	if err := t.checkpoint(ctx, "preparing"); err != nil {
		return nil, err
	}

	if t.op.Kind == "server.restart" {
		if err := t.checkpoint(ctx, "validating"); err != nil {
			return nil, err
		}
		if err := t.conn.ValidateConfiguration(fail2ban.WithOperationPhase(ctx, "primary-validate")); err != nil {
			return gin.H{"messageKey": "servers.errors.config_not_applied"}, err
		}
		if err := t.checkpoint(ctx, "applying"); err != nil {
			return nil, err
		}
		mode, err := t.conn.Restart(fail2ban.WithOperationPhase(ctx, "primary-restart"))
		t.recovery.Mode = mode
		if err != nil {
			if errors.Is(err, fail2ban.ErrRestartNotResponding) {
				_ = t.checkpoint(ctx, "applied")
			}
			return nil, unknownOutcome(err)
		}
		if err := t.checkpoint(ctx, "applied"); err != nil {
			return nil, unknownOutcome(err)
		}
		return t.finish(ctx)
	}

	// No command has been sent while this bounded read waits. A busy daemon cannot
	// tie up an HTTP request, and the last confirmed snapshot stays available.
	readCtx, cancel := context.WithTimeout(ctx, snapshotReadTimeout)
	before, err := RefreshServerSnapshot(readCtx, t.conn)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("Cannot read current server state before changing it: %w", err)
	}
	if t.op.Kind == "jail.ban" || t.op.Kind == "jail.unban" {
		return t.runBan(ctx)
	}
	backupper, ok := t.conn.(fail2ban.ConfigurationBackupper)
	if !ok {
		return nil, errors.New("This connector cannot save recovery copies; upgrade it before changing configuration")
	}
	// Validate request against the snapshot taken under the per-server lease.
	if err := t.precheck(ctx, before.Configured, before.Summary.Jails); err != nil {
		result := gin.H{}
		if t.op.Kind == "jail.create" && strings.Contains(err.Error(), "already exists") {
			result["messageKey"] = "jails.errors.already_exists"
		}
		if t.op.Kind == "filter.create" && strings.Contains(err.Error(), "already exists") {
			result["messageKey"] = "filters.errors.already_exists"
		}
		return result, err
	}
	if err := backupper.BackupConfiguration(ctx, t.op.ID); err != nil {
		return nil, fmt.Errorf("Cannot save configuration recovery copy: %w", err)
	}
	t.recovery.BackupID = t.op.ID
	if err := t.checkpoint(ctx, "writing"); err != nil {
		return nil, err
	}
	if t.op.Kind == "server.sync" {
		syncCtx := fail2ban.WithOperationCheckpoint(ctx, t.checkpoint)
		syncCtx = fail2ban.WithOperationPhase(syncCtx, "primary-sync")
		err := fail2ban.GetManager().SyncServerConfig(syncCtx, t.op.ServerID)
		if err != nil {
			if t.recovery.Stage == "applying" || errors.Is(err, fail2ban.ErrOperationOutcomeUnknown) {
				return nil, unknownOutcome(err)
			}
			return t.rollback(ctx, err)
		}
	} else {
		if err := t.write(ctx); err != nil {
			return t.rollback(ctx, err)
		}
		if t.op.Kind == "jail.config" || t.op.Kind == "jail.create" {
			target := t.payload.Jail
			if t.op.Kind == "jail.create" {
				var req jailCreateRequest
				_ = json.Unmarshal(t.payload.Body, &req)
				target = req.JailName
			}
			configured, err := t.conn.GetAllJails(ctx)
			if err != nil {
				return t.rollback(ctx, err)
			}
			found := false
			for _, j := range configured {
				if j.JailName == target {
					t.recovery.DesiredStates = map[string]bool{target: j.Enabled}
					found = true
					break
				}
			}
			if !found {
				return t.rollback(ctx, fmt.Errorf("Saved configuration does not define jail '%s'", target))
			}
		}
		if err := t.checkpoint(ctx, "validating"); err != nil {
			return t.rollback(ctx, err)
		}
		if err := t.conn.ValidateConfiguration(fail2ban.WithOperationPhase(ctx, "primary-validate")); err != nil {
			return t.rollback(ctx, err)
		}
		// Persist intent before submitting the reload. A crash after this point is
		// ambiguous and must only use read-only reconciliation.
		if err := t.checkpoint(ctx, "applying"); err != nil {
			return t.rollback(ctx, err)
		}
		if err := t.conn.Reload(fail2ban.WithOperationPhase(ctx, "primary-reload")); err != nil {
			return nil, unknownOutcome(err)
		}
	}
	if err := t.checkpoint(ctx, "applied"); err != nil {
		return nil, unknownOutcome(err)
	}
	return t.finish(ctx)
}
func unknownOutcome(err error) error { return fmt.Errorf("%w: %v", operations.ErrOutcomeUnknown, err) }

func (t *operationTransaction) precheck(ctx context.Context, defined, active []fail2ban.JailInfo) error {
	switch t.op.Kind {
	case "jail.manage":
		var updates map[string]bool
		_ = json.Unmarshal(t.payload.Body, &updates)
		for name, enabled := range updates {
			if !jailNameTaken(name, defined, active) {
				return fmt.Errorf("Jail '%s' does not exist", name)
			}
			if enabled {
				if err := precheckJailLogpaths(ctx, t.conn, name); err != nil {
					return err
				}
			}
		}
		t.recovery.DesiredStates = updates
	case "jail.create":
		var req jailCreateRequest
		_ = json.Unmarshal(t.payload.Body, &req)
		if jailNameTaken(req.JailName, defined, active) {
			return fmt.Errorf("jail '%s' already exists", req.JailName)
		}
	case "jail.delete":
		if !jailNameTaken(t.payload.Jail, defined, active) {
			return fmt.Errorf("Jail '%s' does not exist", t.payload.Jail)
		}
		t.recovery.DesiredStates = map[string]bool{t.payload.Jail: false}
	case "filter.create":
		var req filterCreateRequest
		_ = json.Unmarshal(t.payload.Body, &req)
		names, err := t.conn.GetFilters(ctx)
		if err != nil && !errors.Is(err, fail2ban.ErrFilterDirMissing) {
			return err
		}
		if slices.Contains(names, req.FilterName) {
			return fmt.Errorf("filter '%s' already exists", req.FilterName)
		}
	}
	return nil
}

// Directory visibility is only a helpful early check. Privileged Fail2ban
// validation is authoritative for inherited logpaths and journal backends.
func precheckJailLogpaths(ctx context.Context, conn fail2ban.Connector, name string) error {
	cfg, _, err := conn.GetJailConfig(ctx, name)
	if err != nil {
		return fmt.Errorf("Cannot read jail '%s': %w", name, err)
	}
	paths := strings.Fields(fail2ban.ExtractLogpathFromJailConfig(cfg))
	if len(paths) == 0 {
		return nil
	}
	inaccessible := false
	for _, path := range paths {
		_, _, files, err := conn.TestLogpathWithResolution(ctx, path)
		if errors.Is(err, fail2ban.ErrLogpathInaccessible) {
			inaccessible = true
			continue
		}
		if err != nil {
			return fmt.Errorf("Cannot check logpath for jail '%s': %w", name, err)
		}
		if len(files) > 0 {
			return nil
		}
	}
	if inaccessible {
		return nil
	}
	return fmt.Errorf("Jail '%s' cannot be enabled: no matching log files were found", name)
}
func (t *operationTransaction) write(ctx context.Context) error {
	switch t.op.Kind {
	case "jail.manage":
		return t.conn.UpdateJailEnabledStates(ctx, t.recovery.DesiredStates)
	case "jail.config":
		var req jailConfigRequest
		_ = json.Unmarshal(t.payload.Body, &req)
		if req.Filter != "" {
			original, _, err := t.conn.GetJailConfig(ctx, t.payload.Jail)
			if err != nil {
				return err
			}
			if err := t.conn.SetFilterConfig(ctx, fail2ban.FilterNameForJail(t.payload.Jail, original), req.Filter); err != nil {
				return err
			}
		}
		if req.Jail != "" {
			return t.conn.SetJailConfig(ctx, t.payload.Jail, fail2ban.NormalizeJailSection(t.payload.Jail, req.Jail))
		}
	case "jail.create":
		var req jailCreateRequest
		_ = json.Unmarshal(t.payload.Body, &req)
		if strings.TrimSpace(req.Content) == "" {
			req.Content = "enabled = false\n"
		}
		return t.conn.CreateJail(ctx, req.JailName, fail2ban.NormalizeJailSection(req.JailName, req.Content))
	case "jail.delete":
		return t.conn.DeleteJail(ctx, t.payload.Jail)
	case "filter.create":
		var req filterCreateRequest
		_ = json.Unmarshal(t.payload.Body, &req)
		if req.Content == "" {
			req.Content = fmt.Sprintf("# Filter: %s\n", req.FilterName)
		}
		return t.conn.CreateFilter(ctx, req.FilterName, req.Content)
	case "filter.delete":
		return t.conn.DeleteFilter(ctx, t.payload.Filter)
	}
	return nil
}
func (t *operationTransaction) runBan(ctx context.Context) (gin.H, error) {
	if err := t.checkpoint(ctx, "applying"); err != nil {
		return nil, err
	}
	var err error
	if t.op.Kind == "jail.ban" {
		err = t.conn.BanIP(fail2ban.WithOperationPhase(ctx, "primary-ban"), t.payload.Jail, t.payload.IP)
	} else {
		err = t.conn.UnbanIP(fail2ban.WithOperationPhase(ctx, "primary-unban"), t.payload.Jail, t.payload.IP)
	}
	if err != nil {
		return gin.H{"messageKey": "dashboard.manual_block.error"}, unknownOutcome(err)
	}
	if err := t.checkpoint(ctx, "applied"); err != nil {
		return nil, unknownOutcome(err)
	}
	return t.finish(ctx)
}
func (t *operationTransaction) rollback(ctx context.Context, cause error) (gin.H, error) {
	// No daemon mutation was sent. Restoring this immutable copy is safe to retry,
	// including after a crash halfway through a multi-file configuration write.
	t.recovery.Failure = cause.Error()
	if err := t.checkpoint(ctx, "rolling_back"); err != nil {
		return nil, unknownOutcome(err)
	}
	backupper := t.conn.(fail2ban.ConfigurationBackupper)
	if err := backupper.RestoreConfiguration(ctx, t.recovery.BackupID); err != nil {
		return nil, unknownOutcome(fmt.Errorf("%v; restoring configuration failed: %w", cause, err))
	}
	if err := t.checkpoint(ctx, "restored"); err != nil {
		return nil, unknownOutcome(err)
	}
	t.cleanup(ctx)
	return gin.H{"error": cause.Error(), "configurationRestored": true, "message": "The change was rejected and the original configuration was restored. No reload was sent."}, cause
}
func (t *operationTransaction) finish(ctx context.Context) (gin.H, error) {
	if err := t.checkpoint(ctx, "verifying"); err != nil {
		return nil, unknownOutcome(err)
	}
	readCtx, cancel := context.WithTimeout(ctx, snapshotReadTimeout)
	defer cancel()
	snap, err := RefreshServerSnapshot(readCtx, t.conn)
	if err != nil {
		return nil, unknownOutcome(err)
	}
	if err = t.verify(snap); err != nil {
		return nil, unknownOutcome(err)
	}
	t.cleanup(ctx)
	result := gin.H{"message": "Change applied and server state verified"}
	if t.recovery.Mode != "" {
		result["mode"] = t.recovery.Mode
	}
	return result, nil
}
func (t *operationTransaction) verify(snap *ServerSnapshot) error {
	active := map[string]bool{}
	for _, j := range snap.Summary.Jails {
		active[j.JailName] = true
	}
	configured := map[string]bool{}
	for _, j := range snap.Configured {
		configured[j.JailName] = j.Enabled
	}
	for name, wanted := range t.recovery.DesiredStates {
		if active[name] != wanted {
			return fmt.Errorf("Jail '%s' runtime state does not yet match the requested state", name)
		}
		saved, exists := configured[name]
		if t.op.Kind != "jail.delete" && (!exists || saved != wanted) {
			return fmt.Errorf("Jail '%s' saved state does not match the requested state", name)
		}
	}
	if t.op.Kind == "jail.ban" || t.op.Kind == "jail.unban" {
		found := false
		for _, j := range snap.Summary.Jails {
			if j.JailName == t.payload.Jail {
				for _, ip := range j.BannedIPs {
					if canonicalBanAddress(ip) == canonicalBanAddress(t.payload.IP) {
						found = true
						break
					}
				}
			}
		}
		if found != (t.op.Kind == "jail.ban") {
			return errors.New("The requested IP ban state could not be confirmed")
		}
	}
	return nil
}
func (t *operationTransaction) cleanup(ctx context.Context) {
	if t.recovery.BackupID == "" {
		return
	}
	// Best effort only. An orphaned private backup is preferable to declaring a
	// completed daemon change uncertain because cleanup could not reach SSH.
	if b, ok := t.conn.(fail2ban.ConfigurationBackupper); ok {
		_ = b.DeleteConfigurationBackup(ctx, t.recovery.BackupID)
	}
}

func (t *operationTransaction) reconcile(ctx context.Context) (gin.H, bool, error) {
	if len(t.op.Recovery) > 0 {
		if err := json.Unmarshal(t.op.Recovery, &t.recovery); err != nil {
			return nil, false, err
		}
	}
	stage := t.recovery.Stage
	if stage == "" || stage == "preparing" {
		return gin.H{"error": "Interrupted before a command was submitted; submit the change again"}, true, errors.New("Interrupted before applying the change")
	}
	if stage == "writing" || stage == "validating" || stage == "rolling_back" {
		if t.recovery.BackupID == "" {
			return gin.H{"error": "Interrupted before applying the change"}, true, errors.New("Interrupted before applying the change")
		}
		b, ok := t.conn.(fail2ban.ConfigurationBackupper)
		if !ok {
			return nil, false, nil
		}
		if err := b.RestoreConfiguration(ctx, t.recovery.BackupID); err != nil {
			return nil, false, err
		}
		// Restoration changes files only. Never issue a reload as part of recovery.
		return gin.H{"configurationRestored": true, "error": "Interrupted change: original configuration files restored; no reload was sent"}, true, errors.New("Interrupted change was rolled back before reload")
	}
	if stage == "restored" {
		return gin.H{"configurationRestored": true, "error": t.recovery.Failure}, true, errors.New(t.recovery.Failure)
	}
	acknowledged := stage == "applied" || stage == "verifying"
	if agent, ok := t.conn.(*fail2ban.AgentConnector); ok && !acknowledged {
		kind, phase := "reload", "primary-reload"
		if t.op.Kind == "server.restart" {
			kind, phase = "restart", "primary-restart"
		}
		if t.op.Kind == "server.sync" {
			phase = "primary-sync"
		}
		if t.op.Kind == "jail.ban" {
			kind, phase = "ban", "primary-ban"
		}
		if t.op.Kind == "jail.unban" {
			kind, phase = "unban", "primary-unban"
		}
		remote, err := agent.ReconcileOperation(fail2ban.WithOperationPhase(ctx, phase), kind)
		if err != nil {
			return nil, false, err
		}
		if remote.State == "queued" || remote.State == "running" || (remote.State == "unknown" && !remote.Quiescent) {
			return nil, false, nil
		}
		acknowledged = remote.State == "succeeded"
	}
	snap, err := RefreshServerSnapshot(ctx, t.conn)
	if err != nil {
		return nil, false, err
	}
	if err = t.verify(snap); err != nil {
		// A completed read means the daemon is no longer occupied by this command.
		// Configuration remains validated; report a failed intended state honestly.
		return gin.H{"error": err.Error()}, true, err
	}
	if !acknowledged && t.op.Kind != "jail.manage" && t.op.Kind != "jail.delete" && t.op.Kind != "jail.ban" && t.op.Kind != "jail.unban" {
		err := errors.New("Fail2ban responds again, but the previous command reply was lost. Its completion could not be confirmed. Review the saved configuration before explicitly applying it again.")
		return gin.H{"error": err.Error(), "outcomeUnconfirmed": true}, true, err
	}
	return gin.H{"message": "Server state verified after the connection was restored"}, true, nil
}

// Fail2ban can canonicalize IPv6 notation and CIDR host bits in its replies.
// Compare address identity, not the text the user originally typed.
func canonicalBanAddress(value string) string {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		prefix = prefix.Masked()
		if prefix.Bits() == prefix.Addr().BitLen() {
			return prefix.Addr().String()
		}
		return prefix.String()
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.String()
	}
	return value
}
