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

// SSH transport: process execution, ControlMaster lifecycle,
// reverse-tunnel health, and ssh argument construction.
package fail2ban

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// Return the UI's configured listen port (from "Server Port" setting)
func uiServerPort() int {
	if p := mustProvider().ServerPort(); p > 0 {
		return p
	}
	return 8080
}

// Return the port bound on the remote host for the reverse tunnel
func resolveTunnelPort(server shared.Fail2banServer) int {
	if server.TunnelPort >= 1024 && server.TunnelPort <= 65535 {
		return server.TunnelPort
	}
	if server.TunnelPort != 0 {
		log.Printf("warning: invalid tunnelPort %d for server %s, falling back to the UI port", server.TunnelPort, server.Name)
	}
	return uiServerPort()
}

const sshMaxConcurrentSessions = 4
const masterRetryBackoff = 30 * time.Second

// Establishes the ControlMaster (which owns the -R reverse forward) unless the connector has been closed
// Serialized so concurrent commands cannot race to remove and re-create the same control socket
func (sc *SSHConnector) ensureMaster(ctx context.Context) {
	sc.masterMu.Lock()
	defer sc.masterMu.Unlock()
	if sc.closed.Load() {
		return
	}
	if sc.checkMaster(ctx) {
		sc.masterUp.Store(true)
		sc.masterFailUntil = time.Time{}
		return
	}
	sc.masterUp.Store(false)
	if time.Now().Before(sc.masterFailUntil) {
		return
	}
	if _, err := os.Stat(sc.controlPath()); err == nil {
		_ = os.Remove(sc.controlPath())
	}
	args := sc.buildMasterSSHArgs([]string{"true"})
	if _, stderr, err := sc.execSSH(ctx, args, nil); err != nil {
		if hk := sc.parseHostKeyError(stderr, err); hk != nil {
			RecordHostKeyIssue(hk)
		}
		sc.masterFailUntil = time.Now().Add(masterRetryBackoff)
		debugf("SSH control master establish failed for %s: %v", sc.server.Name, err)
		return
	}
	sc.masterFailUntil = time.Time{}
	sc.masterUp.Store(true)
}

// Only tunnel servers need a dedicated master (it owns the -R forward)
func (sc *SSHConnector) ensureMasterLazy(ctx context.Context) {
	if sc.masterUp.Load() {
		if _, err := os.Stat(sc.controlPath()); err == nil {
			return
		}
		sc.masterUp.Store(false)
	}
	sc.ensureMaster(ctx)
}

func (sc *SSHConnector) checkMaster(ctx context.Context) bool {
	check := exec.CommandContext(ctx, "ssh", "-O", "check", "-o", "ControlPath="+sc.controlPath(), "--", sc.sshTarget())
	return check.Run() == nil
}

// Verifies the SSH ControlMaster (and thus the reverse tunnel) and re-establishes it when it is down.
func (sc *SSHConnector) CheckTunnelHealth(ctx context.Context) {
	if sc.tunnelPort == 0 || sc.closed.Load() {
		return
	}

	if sc.checkMaster(ctx) {
		if !sc.tunnelWasUp {
			log.Printf("reverse tunnel for server %s is up (port %d)", sc.server.Name, sc.tunnelPort)
		}
		sc.tunnelWasUp = true
		sc.masterUp.Store(true)
		return
	}

	if sc.tunnelWasUp {
		log.Printf("reverse tunnel master for server %s is down, re-establishing", sc.server.Name)
	}
	sc.tunnelWasUp = false
	sc.ensureMaster(ctx)
	if sc.closed.Load() {
		return
	}
	if sc.checkMaster(ctx) {
		log.Printf("reverse tunnel for server %s re-established (port %d)", sc.server.Name, sc.tunnelPort)
		sc.tunnelWasUp = true
	} else {
		debugf("reverse tunnel for server %s still down after re-dial", sc.server.Name)
	}
}

// Terminates the SSH ControlMaster via its local control socket
func (sc *SSHConnector) exitControlMasterLocked() {
	sc.masterUp.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", "-O", "exit", "-o", "ControlPath="+sc.controlPath(), "--", sc.sshTarget())
	out, err := cmd.CombinedOutput()
	defer func() { _ = os.Remove(sc.controlPath()) }()
	if err != nil {
		msg := strings.ToLower(string(out))
		if !strings.Contains(msg, "no such file") && !strings.Contains(msg, "control socket connect") {
			debugf("failed to close SSH control master for %s: %v (%s)", sc.server.Name, err, strings.TrimSpace(string(out)))
		}
		return
	}
	debugf("closed SSH control master for %s", sc.server.Name)
}

func (sc *SSHConnector) Close() error {
	sc.closed.Store(true)
	sc.masterMu.Lock()
	defer sc.masterMu.Unlock()
	sc.exitControlMasterLocked()
	return nil
}

// Report whether the replacement server config requires tearing down the existing ControlMaster
func sshTunnelConfigChanged(old *SSHConnector, srv shared.Fail2banServer) bool {
	newTunnel := srv.Type == "ssh" && srv.ReverseTunnelEnabled
	if old.tunnelPort == 0 {
		return newTunnel
	}
	if !newTunnel {
		return true
	}
	if resolveTunnelPort(srv) != old.tunnelPort {
		return true
	}
	o := old.server
	return srv.Host != o.Host || srv.Port != o.Port || srv.SSHUser != o.SSHUser || srv.SSHKeyPath != o.SSHKeyPath
}

// How long a cancelled ssh gets to exit after SIGTERM before it is killed
const sshCancelGrace = 100 * time.Millisecond

// Runs one ssh process, keeping stdout and stderr strictly separate
func (sc *SSHConnector) execSSH(ctx context.Context, args []string, stdin io.Reader) (string, string, error) {
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: 0}
	cmd.Cancel = func() error {
		if cmd.Process == nil || cmd.Process.Pid <= 0 {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	cmd.WaitDelay = sshCancelGrace

	if stdin != nil {
		cmd.Stdin = stdin
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil && ctx.Err() != nil {
		return stdout.String(), stderr.String(), ctx.Err()
	}
	return stdout.String(), stderr.String(), err
}

// Caps how much remote output is embedded in logs and error messages
const maxLoggedOutputBytes = 2048

// Shortens s for logging, keeping the head and noting what was dropped.
func truncateForLog(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + fmt.Sprintf("... (truncated, %d bytes total)", len(s))
}

func summarizeSSHInvocation(args, command []string) string {
	sshOpts := args
	if len(command) <= len(args) {
		sshOpts = args[:len(args)-len(command)]
	}
	return "ssh " + strings.Join(sshOpts, " ") + " " + summarizeRemoteCommand(command)
}

// Condenses a remote command to a single log-friendly line
func summarizeRemoteCommand(command []string) string {
	joined := strings.Join(command, " ")
	trimmed := strings.TrimLeft(joined, " \t\n")
	first, _, multiline := strings.Cut(trimmed, "\n")
	first = strings.TrimSpace(first)
	if !multiline {
		return truncateForLog(first, maxLoggedOutputBytes)
	}
	lines := strings.Count(strings.TrimRight(trimmed, "\n"), "\n") + 1
	return fmt.Sprintf("%s ... (script, %d lines, %d bytes)", truncateForLog(first, 200), lines, len(joined))
}

type CommandError struct {
	Kind   string
	Output string
	Err    error
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("%s command failed: %v (output: %s)", e.Kind, e.Err, truncateForLog(e.Output, maxLoggedOutputBytes))
}

func (e *CommandError) Unwrap() error { return e.Err }

func CommandOutput(err error) (string, bool) {
	var ce *CommandError
	if errors.As(err, &ce) {
		return ce.Output, true
	}
	return "", false
}

func selectCommandOutput(kind, stdout, stderr string, err error) (string, error) {
	if err != nil {
		combined := strings.TrimSpace(strings.TrimSpace(stdout) + "\n" + strings.TrimSpace(stderr))
		return combined, &CommandError{Kind: kind, Output: combined, Err: err}
	}
	return strings.TrimSpace(stdout), nil
}

func (sc *SSHConnector) acquireSession(ctx context.Context) error {
	if sc.sessionSem == nil {
		return nil
	}
	select {
	case sc.sessionSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (sc *SSHConnector) releaseSession() {
	if sc.sessionSem != nil {
		<-sc.sessionSem
	}
}

var sshTransportStderrMarkers = []string{
	"ssh:",
	"connection closed",
	"connection refused",
	"connection reset",
	"connection timed out",
	"permission denied",
	"host key verification failed",
	"could not resolve hostname",
	"no route to host",
	"kex_exchange",
	"broken pipe",
	"control socket connect",
}

func isSSHTransportError(err error, stderr string) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 255 {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(stderr))
	if msg == "" {
		return true
	}
	for _, marker := range sshTransportStderrMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

func (sc *SSHConnector) runRemoteCommand(ctx context.Context, command []string) (string, error) {
	output, stderr, err := sc.runRemoteCommandOnce(ctx, command)
	var hk *SSHHostKeyError
	if errors.As(err, &hk) {
		return output, err
	}
	if err != nil && sc.tunnelPort > 0 && isSSHTransportError(err, stderr) && ctx.Err() == nil {
		// the master (or its socket) is likely dead.
		// Re-establish once and retry the command a single time.
		debugf("SSH transport failure [%s], re-establishing master and retrying: %v", sc.server.Name, err)
		sc.masterUp.Store(false)
		sc.ensureMaster(ctx)
		output, _, err = sc.runRemoteCommandOnce(ctx, command)
	}
	return output, err
}

func (sc *SSHConnector) runRemoteCommandOnce(ctx context.Context, command []string) (string, string, error) {
	sc.ensureMasterLazy(ctx)
	if err := sc.acquireSession(ctx); err != nil {
		return "", "", err
	}
	defer sc.releaseSession()

	args := sc.buildSSHArgs(command)
	debugf("SSH command [%s]: %s", sc.server.Name, summarizeSSHInvocation(args, command))
	stdout, stderr, execErr := sc.execSSH(ctx, args, nil)
	output, err := selectCommandOutput("ssh", stdout, stderr, execErr)
	if err != nil {
		if hk := sc.parseHostKeyError(stderr, err); hk != nil {
			RecordHostKeyIssue(hk)
			err = hk
		}
		debugf("SSH command error [%s]: %v", sc.server.Name, err)
		return output, stderr, err
	}
	ClearHostKeyIssue(sc.server.ID)
	if s := strings.TrimSpace(stderr); s != "" {
		debugf("SSH stderr ignored [%s]: %s", sc.server.Name, truncateForLog(s, maxLoggedOutputBytes))
	}
	debugf("SSH command output [%s]: %s", sc.server.Name, truncateForLog(output, maxLoggedOutputBytes))
	return output, stderr, nil
}

func (sc *SSHConnector) actionCallbackURL() string {
	if sc.tunnelPort > 0 {
		return fmt.Sprintf("http://localhost:%d", sc.tunnelPort)
	}
	return mustProvider().CallbackURL()
}

func (sc *SSHConnector) knownHostsPath() string {
	if keyDir := sc.sshKeyDir(); keyDir != "" {
		return filepath.Join(keyDir, "known_hosts")
	}
	if _, container := os.LookupEnv("CONTAINER"); container {
		return "/config/.ssh/known_hosts"
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".ssh", "known_hosts")
	}
	return ""
}

func (sc *SSHConnector) sshKeyDir() string {
	if sc.server.SSHKeyPath == "" {
		return ""
	}
	if err := shared.ValidateAbsolutePath(sc.server.SSHKeyPath, "sshKeyPath"); err != nil {
		debugf("ignoring invalid sshKeyPath for %s: %v", sc.server.Name, err)
		return ""
	}
	return filepath.Dir(filepath.Clean(sc.server.SSHKeyPath))
}

func (sc *SSHConnector) sshControlDir() string {
	var base string
	if keyDir := sc.sshKeyDir(); keyDir != "" {
		base = filepath.Join(keyDir, "ctl")
	} else if cache, err := os.UserCacheDir(); err == nil {
		base = filepath.Join(cache, "fail2ban-ui", "ssh-ctl")
	}
	if base != "" {
		if err := os.MkdirAll(base, 0o700); err == nil {
			return base
		}
	}
	return os.TempDir()
}

var unsafeSocketNameChars = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func (sc *SSHConnector) controlPath() string {
	id := unsafeSocketNameChars.ReplaceAllString(sc.server.ID, "_")
	host := unsafeSocketNameChars.ReplaceAllString(sc.server.Host, "_")
	name := fmt.Sprintf("ssh_control_%s_%s", id, host)
	return filepath.Join(sc.sshControlDir(), name)
}

func (sc *SSHConnector) sshTarget() string {
	if sc.server.SSHUser != "" {
		return fmt.Sprintf("%s@%s", sc.server.SSHUser, sc.server.Host)
	}
	return sc.server.Host
}

func (sc *SSHConnector) buildSSHArgs(command []string) []string {
	return sc.buildSSHArgsMode(command, false)
}

func (sc *SSHConnector) buildMasterSSHArgs(command []string) []string {
	return sc.buildSSHArgsMode(command, true)
}

func (sc *SSHConnector) buildSSHArgsMode(command []string, forMaster bool) []string {
	args := []string{"-o", "BatchMode=yes"}
	args = append(args,
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=5",
		"-o", "ServerAliveCountMax=2",
	)
	args = append(args,
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "LogLevel=ERROR",
	)
	if kh := sc.knownHostsPath(); kh != "" {
		args = append(args, "-o", "UserKnownHostsFile="+kh)
	}
	controlPath := fmt.Sprintf("ControlPath=%s", sc.controlPath())
	switch {
	case sc.tunnelPort > 0 && forMaster:
		args = append(args,
			"-o", "ControlMaster=auto",
			"-o", controlPath,
			"-o", "ControlPersist=0",
		)
		tunnelArg := fmt.Sprintf("%d:localhost:%d", sc.tunnelPort, sc.forwardPort)
		args = append(args, "-R", tunnelArg)
		debugf("SSH reverse tunnel enabled: -R %s with ControlPersist=0 (indefinite)", tunnelArg)
	case sc.tunnelPort > 0:
		args = append(args,
			"-o", "ControlMaster=no",
			"-o", controlPath,
		)
	default:
		args = append(args,
			"-o", "ControlMaster=auto",
			"-o", controlPath,
			"-o", "ControlPersist=300",
		)
	}
	if sc.server.SSHKeyPath != "" {
		args = append(args, "-i", sc.server.SSHKeyPath)
	}
	if sc.server.Port > 0 {
		args = append(args, "-p", strconv.Itoa(sc.server.Port))
	}
	args = append(args, "--", sc.sshTarget())
	args = append(args, command...)
	return args
}
