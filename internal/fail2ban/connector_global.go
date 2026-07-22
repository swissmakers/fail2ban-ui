// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Shared types, helpers, and high-level functions used across all connectors.
package fail2ban

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

// =========================================================================
//  Validation
// =========================================================================

// Ensures an IP/CIDR is well-formed
func ValidateIP(ip string) error {
	return shared.ValidateIP(ip)
}

// Inspects fail2ban-client reload output for the markers that indicate the daemon reloaded but a jail/filter failed to apply.
func checkReloadOutput(output string) error {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" || trimmed == "OK" {
		return nil
	}
	if strings.Contains(output, "Errors in jail") || strings.Contains(output, "Unable to read the filter") {
		return fmt.Errorf("fail2ban reload completed but with errors (output: %s)", trimmed)
	}
	return nil
}

// =========================================================================
//  Types
// =========================================================================

// JailInfo holds summary data for a single Fail2ban jail.
type JailInfo struct {
	JailName      string   `json:"jailName"`
	TotalBanned   int      `json:"totalBanned"`
	NewInLastHour int      `json:"newInLastHour"`
	BannedIPs     []string `json:"bannedIPs"`
	Enabled       bool     `json:"enabled"`
}

// =========================================================================
//  Service Control
// =========================================================================

// RestartFail2ban restarts (or reloads) the Fail2ban service on the given server.
func RestartFail2ban(serverID string) (string, error) {
	manager := GetManager()
	var (
		conn Connector
		err  error
	)
	if serverID != "" {
		conn, err = manager.Connector(serverID)
	} else {
		conn, err = manager.DefaultConnector()
	}
	if err != nil {
		return "", err
	}
	if withMode, ok := conn.(interface {
		RestartWithMode(ctx context.Context) (string, error)
	}); ok {
		return withMode.RestartWithMode(context.Background())
	}
	if err := conn.Restart(context.Background()); err != nil {
		return "", err
	}
	return "restart", nil
}

// =========================================================================
//  Jail Info Collection
// =========================================================================

// bannedIPsFn is the signature used by any connector's GetBannedIPs method.
type bannedIPsFn func(ctx context.Context, jail string) ([]string, error)

// Fans out to fetch banned IPs for each jail concurrently, then returns the results sorted alphabetically. (local connector)
func collectJailInfos(ctx context.Context, jails []string, getBannedIPs bannedIPsFn) ([]JailInfo, error) {
	return collectJailInfosLimited(ctx, jails, getBannedIPs, 0)
}

// Caps the number of concurrent getBannedIPs calls when maxConcurrent > 0. (SSH connector)
func collectJailInfosLimited(ctx context.Context, jails []string, getBannedIPs bannedIPsFn, maxConcurrent int) ([]JailInfo, error) {
	type jailResult struct {
		jail JailInfo
		err  error
	}
	results := make(chan jailResult, len(jails))
	var wg sync.WaitGroup

	var sem chan struct{}
	if maxConcurrent > 0 {
		sem = make(chan struct{}, maxConcurrent)
	}

	for _, jail := range jails {
		wg.Add(1)
		go func(j string) {
			defer wg.Done()
			if sem != nil {
				sem <- struct{}{}
				defer func() { <-sem }()
			}
			ips, err := getBannedIPs(ctx, j)
			if err != nil {
				results <- jailResult{err: err}
				return
			}
			totalBanned := len(ips)
			results <- jailResult{
				jail: JailInfo{
					JailName:    j,
					TotalBanned: totalBanned,
					BannedIPs:   []string{},
					Enabled:     true,
				},
			}
		}(jail)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var infos []JailInfo
	for r := range results {
		if r.err != nil {
			continue
		}
		infos = append(infos, r.jail)
	}

	sort.SliceStable(infos, func(i, j int) bool {
		return infos[i].JailName < infos[j].JailName
	})

	return infos, nil
}
