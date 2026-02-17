// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2025 Swissmakers GmbH (https://swissmakers.ch)
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

package fail2ban

import "context"

// =========================================================================
//  Types
// =========================================================================

type JailInfo struct {
	JailName      string   `json:"jailName"`
	TotalBanned   int      `json:"totalBanned"`
	NewInLastHour int      `json:"newInLastHour"`
	BannedIPs     []string `json:"bannedIPs"`
	Enabled       bool     `json:"enabled"`
}

// =========================================================================
//  Client Functions
// =========================================================================

// Returns jail names from the default server.
func GetJails() ([]string, error) {
	conn, err := GetManager().DefaultConnector()
	if err != nil {
		return nil, err
	}
	infos, err := conn.GetJailInfos(context.Background())
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(infos))
	for _, info := range infos {
		names = append(names, info.JailName)
	}
	return names, nil
}

// Returns a slice of currently banned IPs for a specific jail.
func GetBannedIPs(jail string) ([]string, error) {
	conn, err := GetManager().DefaultConnector()
	if err != nil {
		return nil, err
	}
	return conn.GetBannedIPs(context.Background(), jail)
}

// Unbans an IP from the given jail.
func UnbanIP(jail, ip string) error {
	conn, err := GetManager().DefaultConnector()
	if err != nil {
		return err
	}
	return conn.UnbanIP(context.Background(), jail, ip)
}

// Returns extended info for each jail on the default server.
func BuildJailInfos(_ string) ([]JailInfo, error) {
	conn, err := GetManager().DefaultConnector()
	if err != nil {
		return nil, err
	}
	return conn.GetJailInfos(context.Background())
}

// Restarts (or reloads) the Fail2ban service.
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
