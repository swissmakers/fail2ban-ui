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

var (
	whoisCache      = make(map[string]cachedWhois)
	whoisCacheMutex sync.RWMutex
	cacheExpiry     = 24 * time.Hour
)

type cachedWhois struct {
	data      string
	timestamp time.Time
}

// lookupWhois performs a whois lookup for the given IP address.
// It uses caching to avoid repeated queries for the same IP.
func lookupWhois(ip string) (string, error) {
	// Check cache first
	whoisCacheMutex.RLock()
	if cached, ok := whoisCache[ip]; ok {
		if time.Since(cached.timestamp) < cacheExpiry {
			whoisCacheMutex.RUnlock()
			return cached.data, nil
		}
	}
	whoisCacheMutex.RUnlock()

	// Perform whois lookup with timeout
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
		// Success - cache will be updated below
	case err := <-errChan:
		return "", fmt.Errorf("whois lookup failed: %w", err)
	case <-time.After(10 * time.Second):
		return "", fmt.Errorf("whois lookup timeout after 10 seconds")
	}

	// Cache the result
	whoisCacheMutex.Lock()
	whoisCache[ip] = cachedWhois{
		data:      whoisData,
		timestamp: time.Now(),
	}
	// Clean old cache entries if cache is getting large
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

// extractCountryFromWhois attempts to extract country code from whois data.
// This is a fallback if GeoIP lookup fails.
func extractCountryFromWhois(whoisData string) string {
	lines := strings.Split(whoisData, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)

		// Look for country field
		if strings.HasPrefix(lineLower, "country:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				country := strings.TrimSpace(parts[1])
				if len(country) == 2 {
					return strings.ToUpper(country)
				}
			}
		}
		// Alternative format
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
