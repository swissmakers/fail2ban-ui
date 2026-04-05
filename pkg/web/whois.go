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
// distributed under the License is distributed on "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
)

// =========================================================================
//  Types and Constants
// =========================================================================

type cachedWhois struct {
	data      string
	timestamp time.Time
}

var (
	whoisCache      = make(map[string]cachedWhois)
	whoisCacheMutex sync.RWMutex
	cacheExpiry     = 24 * time.Hour
)

// =========================================================================
//  Lookup Whois Data
// =========================================================================

func lookupWhois(ip string) (string, error) {
	whoisCacheMutex.RLock()
	if cached, ok := whoisCache[ip]; ok {
		if time.Since(cached.timestamp) < cacheExpiry {
			whoisCacheMutex.RUnlock()
			return cached.data, nil
		}
	}
	whoisCacheMutex.RUnlock()

	done := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		whoisData, err := whois.Whois(ip)
		if err != nil {
			errChan <- err
			return
		}
		done <- whoisData
	}()

	var whoisData string
	select {
	case whoisData = <-done:
	case err := <-errChan:
		return "", fmt.Errorf("whois lookup failed: %w", err)
	case <-time.After(10 * time.Second):
		return "", fmt.Errorf("whois lookup timeout after 10 seconds")
	}

	whoisCacheMutex.Lock()
	whoisCache[ip] = cachedWhois{
		data:      whoisData,
		timestamp: time.Now(),
	}
	if len(whoisCache) > 1000 {
		now := time.Now()
		for k, v := range whoisCache {
			if now.Sub(v.timestamp) > cacheExpiry {
				delete(whoisCache, k)
			}
		}
	}
	whoisCacheMutex.Unlock()

	return whoisData, nil
}

// =========================================================================
//  Extract Country from Whois Data
// =========================================================================

func extractCountryFromWhois(whoisData string) string {
	lines := strings.Split(whoisData, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)

		if strings.HasPrefix(lineLower, "country:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				country := strings.TrimSpace(parts[1])
				if len(country) == 2 {
					return strings.ToUpper(country)
				}
			}
		}
		if strings.HasPrefix(lineLower, "country code:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				country := strings.TrimSpace(parts[1])
				if len(country) == 2 {
					return strings.ToUpper(country)
				}
			}
		}
	}
	return ""
}
