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

package httpx

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestClientDoesNotFollowRedirects(t *testing.T) {
	c := Client(5*time.Second, false)
	if c.CheckRedirect == nil {
		t.Fatal("CheckRedirect must be set")
	}
	if err := c.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}

func TestInsecureClientsShareTransport(t *testing.T) {
	a := Client(time.Second, true)
	b := Client(time.Second, true)
	if a.Transport != b.Transport {
		t.Error("insecure clients must share one pooled transport")
	}
	tr, ok := a.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("insecure transport is %T, want *http.Transport", a.Transport)
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("insecure transport must skip TLS verification")
	}
	if tr.Proxy == nil {
		t.Error("insecure transport must keep proxy-from-environment support")
	}
	if secure := Client(time.Second, false); secure.Transport != http.DefaultTransport {
		t.Error("secure client must use http.DefaultTransport")
	}
}

func TestReadLimitedTruncates(t *testing.T) {
	huge := strings.NewReader(strings.Repeat("a", MaxResponseBytes+1024))
	data, err := ReadLimited(huge)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != MaxResponseBytes {
		t.Errorf("ReadLimited returned %d bytes, want %d", len(data), MaxResponseBytes)
	}
}
