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
	"sort"
	"sync"
)

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

// collectJailInfos fans out to fetch banned IPs for each jail concurrently,
// then returns the results sorted alphabetically. Both the local and SSH
// connectors delegate to this function from their GetJailInfos methods.
func collectJailInfos(ctx context.Context, jails []string, getBannedIPs bannedIPsFn) ([]JailInfo, error) {
	type jailResult struct {
		jail JailInfo
		err  error
	}
	results := make(chan jailResult, len(jails))
	var wg sync.WaitGroup

	for _, jail := range jails {
		wg.Add(1)
		go func(j string) {
			defer wg.Done()
			ips, err := getBannedIPs(ctx, j)
			if err != nil {
				results <- jailResult{err: err}
				return
			}
			results <- jailResult{
				jail: JailInfo{
					JailName:    j,
					TotalBanned: len(ips),
					BannedIPs:   ips,
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
