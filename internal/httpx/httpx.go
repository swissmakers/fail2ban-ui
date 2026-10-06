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

// Package httpx provides the shared client
package httpx

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const MaxResponseBytes = 5 << 20

var insecureTransport = sync.OnceValue(func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return t
})

func Transport(skipTLSVerify bool) http.RoundTripper {
	if skipTLSVerify {
		return insecureTransport()
	}
	return http.DefaultTransport
}

func Client(timeout time.Duration, skipTLSVerify bool) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: Transport(skipTLSVerify),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func ReadLimited(body io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(body, MaxResponseBytes))
}

// Sends req and turns any 4xx/5xx into an error carrying the capped body
func DoChecked(client *http.Client, req *http.Request, label string) ([]byte, int, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%s request failed: %w", label, err)
	}
	defer resp.Body.Close()

	body, readErr := ReadLimited(resp.Body)
	if resp.StatusCode >= 400 {
		return body, resp.StatusCode, fmt.Errorf("%s returned status %d: %s", label, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if readErr != nil {
		return nil, resp.StatusCode, fmt.Errorf("%s response could not be read: %w", label, readErr)
	}
	return body, resp.StatusCode, nil
}
