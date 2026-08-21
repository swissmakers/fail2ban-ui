// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Detection of changed-host-key failures, an in-memory issue registry surfaced in the
// server manager, and the admin-approved accept flow that repairs known_hosts

package fail2ban

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// =========================================================================
//  Typed Error
// =========================================================================

type SSHHostKeyError struct {
	ServerID       string
	ServerName     string
	Host           string
	Port           int
	Fingerprint    string
	KeyType        string
	KnownHostsPath string
	Err            error
}

func (e *SSHHostKeyError) Error() string {
	if e.Fingerprint != "" {
		return fmt.Sprintf("ssh host key for %s has changed (presented %s)", e.Host, e.Fingerprint)
	}
	return fmt.Sprintf("ssh host key verification failed for %s", e.Host)
}

func (e *SSHHostKeyError) Unwrap() error {
	return e.Err
}

type HostKeyMismatchError struct {
	Approved  string
	Presented string
}

func (e *HostKeyMismatchError) Error() string {
	return fmt.Sprintf("remote host key %s does not match the approved fingerprint %s", e.Presented, e.Approved)
}

func SSHErrorMessageKey(err error) string {
	var hk *SSHHostKeyError
	if errors.As(err, &hk) {
		return "servers.errors.host_key_changed"
	}
	return ""
}

// =========================================================================
//  Detection
// =========================================================================

var (
	hostKeyBannerRe      = regexp.MustCompile(`(?i)REMOTE HOST IDENTIFICATION HAS CHANGED|POSSIBLE DNS SPOOFING DETECTED|host key verification failed`)
	hostKeyFingerprintRe = regexp.MustCompile(`SHA256:[A-Za-z0-9+/]{43}`)
	hostKeyTypeRe        = regexp.MustCompile(`fingerprint for the ([A-Za-z0-9-]+) key sent by the remote host`)
)

// Classifies ssh stderr as a host-key failure; nil when it is something else.
func (sc *SSHConnector) parseHostKeyError(stderr string, cause error) *SSHHostKeyError {
	if !hostKeyBannerRe.MatchString(stderr) {
		return nil
	}
	hk := &SSHHostKeyError{
		ServerID:       sc.server.ID,
		ServerName:     sc.server.Name,
		Host:           sc.server.Host,
		Port:           sc.server.Port,
		Fingerprint:    hostKeyFingerprintRe.FindString(stderr),
		KnownHostsPath: sc.knownHostsPath(),
		Err:            cause,
	}
	if m := hostKeyTypeRe.FindStringSubmatch(stderr); m != nil {
		hk.KeyType = m[1]
	}
	return hk
}

// =========================================================================
//  In-memory Issue Registry
// =========================================================================

var (
	hostKeyIssuesMu sync.RWMutex
	hostKeyIssues   = make(map[string]*SSHHostKeyError)
)

func RecordHostKeyIssue(e *SSHHostKeyError) {
	if e == nil || e.ServerID == "" {
		return
	}
	hostKeyIssuesMu.Lock()
	defer hostKeyIssuesMu.Unlock()
	hostKeyIssues[e.ServerID] = e
}

func ClearHostKeyIssue(serverID string) {
	hostKeyIssuesMu.Lock()
	defer hostKeyIssuesMu.Unlock()
	delete(hostKeyIssues, serverID)
}

func HostKeyIssue(serverID string) *SSHHostKeyError {
	hostKeyIssuesMu.RLock()
	defer hostKeyIssuesMu.RUnlock()
	if e, ok := hostKeyIssues[serverID]; ok {
		cp := *e
		return &cp
	}
	return nil
}

func pruneHostKeyIssues(keep map[string]struct{}) {
	hostKeyIssuesMu.Lock()
	defer hostKeyIssuesMu.Unlock()
	for id := range hostKeyIssues {
		if _, ok := keep[id]; !ok {
			delete(hostKeyIssues, id)
		}
	}
}

// =========================================================================
//  Accept Flow
// =========================================================================

func NormalizeFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	if fp == "" {
		return ""
	}
	if !strings.HasPrefix(fp, "SHA256:") {
		fp = "SHA256:" + fp
	}
	return fp
}

// Replaces the pinned known_hosts entry for the server with the key the remote currently presents,
// but ONLY when that key matches the fingerprint the admin approved
func AcceptHostKey(ctx context.Context, server shared.Fail2banServer, approvedFP string) (string, error) {
	approvedFP = NormalizeFingerprint(approvedFP)
	if approvedFP == "" {
		return "", fmt.Errorf("approved fingerprint is required")
	}
	sc, err := newBareSSHConnector(server)
	if err != nil {
		return "", err
	}
	khPath := sc.knownHostsPath()
	if khPath == "" {
		return "", fmt.Errorf("cannot determine known_hosts path for server %s", server.Name)
	}

	key, err := scanHostKey(ctx, server.Host, server.Port)
	if err != nil {
		return "", fmt.Errorf("failed to read current host key from %s: %w", server.Host, err)
	}
	presentedFP := ssh.FingerprintSHA256(key)
	if subtle.ConstantTimeCompare([]byte(presentedFP), []byte(approvedFP)) != 1 {
		RecordHostKeyIssue(&SSHHostKeyError{
			ServerID:       server.ID,
			ServerName:     server.Name,
			Host:           server.Host,
			Port:           server.Port,
			Fingerprint:    presentedFP,
			KeyType:        key.Type(),
			KnownHostsPath: khPath,
		})
		return "", &HostKeyMismatchError{Approved: approvedFP, Presented: presentedFP}
	}

	pattern := knownHostsPattern(server.Host, server.Port)
	if err := removeKnownHostEntries(ctx, khPath, pattern); err != nil {
		return "", err
	}
	if err := appendKnownHostEntry(khPath, pattern, key); err != nil {
		return "", err
	}

	if _, _, err := sc.runRemoteCommandOnce(ctx, []string{"true"}); err != nil {
		return "", fmt.Errorf("host key accepted but connection check failed: %w", err)
	}
	ClearHostKeyIssue(server.ID)
	return presentedFP, nil
}

func knownHostsPattern(host string, port int) string {
	if port <= 0 {
		port = 22
	}
	return knownhosts.Normalize(net.JoinHostPort(host, strconv.Itoa(port)))
}

func scanHostKey(ctx context.Context, host string, port int) (ssh.PublicKey, error) {
	if port <= 0 {
		port = 22
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	errKeyCaptured := errors.New("host key captured")
	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			captured = key
			return errKeyCaptured
		},
		Timeout: 10 * time.Second,
	}
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	if captured != nil {
		return captured, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("ssh handshake with %s completed without presenting a host key", addr)
}

func removeKnownHostEntries(ctx context.Context, khPath, pattern string) error {
	if _, err := os.Stat(khPath); os.IsNotExist(err) {
		return nil
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return fmt.Errorf("ssh-keygen not found; cannot rewrite %s: %w", khPath, err)
	}
	cmd := exec.CommandContext(ctx, keygen, "-R", pattern, "-f", khPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ssh-keygen -R failed: %w (output: %s)", err, truncateForLog(strings.TrimSpace(string(out)), maxLoggedOutputBytes))
	}
	_ = os.Remove(khPath + ".old")
	return nil
}

func appendKnownHostEntry(khPath, pattern string, key ssh.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(khPath), 0o700); err != nil {
		return fmt.Errorf("failed to create known_hosts directory: %w", err)
	}
	f, err := os.OpenFile(khPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", khPath, err)
	}
	defer f.Close()
	if _, err := f.WriteString(knownhosts.Line([]string{pattern}, key) + "\n"); err != nil {
		return fmt.Errorf("failed to write known_hosts entry: %w", err)
	}
	return nil
}
