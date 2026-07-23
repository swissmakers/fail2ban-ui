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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func newTestContext(method, target, body string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	c.Request = req
	return c, w
}

func TestParseEventRange(t *testing.T) {
	t.Run("defaults to last 8h", func(t *testing.T) {
		c, _ := newTestContext(http.MethodGet, "/api/events/bans/timeline", "")
		since, until, ok := parseEventRange(c)
		if !ok {
			t.Fatal("expected ok")
		}
		if got := until.Sub(since); got != 8*time.Hour {
			t.Fatalf("default range = %v, want 8h", got)
		}
	})

	t.Run("malformed since is 400", func(t *testing.T) {
		c, w := newTestContext(http.MethodGet, "/api/events/bans/timeline?since=yesterday", "")
		if _, _, ok := parseEventRange(c); ok {
			t.Fatal("expected not ok")
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})

	t.Run("malformed until is 400", func(t *testing.T) {
		c, w := newTestContext(http.MethodGet, "/api/events/bans/timeline?until=2026-13-99", "")
		if _, _, ok := parseEventRange(c); ok {
			t.Fatal("expected not ok")
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})

	t.Run("until before since is 400", func(t *testing.T) {
		c, w := newTestContext(http.MethodGet,
			"/api/events/bans/timeline?since=2026-06-02T00:00:00Z&until=2026-06-01T00:00:00Z", "")
		if _, _, ok := parseEventRange(c); ok {
			t.Fatal("expected not ok")
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})

	t.Run("valid explicit range", func(t *testing.T) {
		c, _ := newTestContext(http.MethodGet,
			"/api/events/bans/timeline?since=2026-06-01T00:00:00Z&until=2026-06-02T00:00:00Z", "")
		since, until, ok := parseEventRange(c)
		if !ok {
			t.Fatal("expected ok")
		}
		if !since.Equal(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) || !until.Equal(time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("range = %v..%v", since, until)
		}
	})
}

func TestChooseBucketSeconds(t *testing.T) {
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		duration time.Duration
		override int64
		want     int64
	}{
		{"8h picks 5m buckets", 8 * time.Hour, 0, 300},
		{"48h picks 30m buckets", 48 * time.Hour, 0, 1800},
		{"30d picks 6h buckets", 30 * 24 * time.Hour, 0, 21600},
		{"180d picks 1d buckets", 180 * 24 * time.Hour, 0, 86400},
		{"override honored when sane", 8 * time.Hour, 600, 600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := chooseBucketSeconds(base, base.Add(tt.duration), tt.override); got != tt.want {
				t.Fatalf("chooseBucketSeconds(%v) = %d, want %d", tt.duration, got, tt.want)
			}
		})
	}

	t.Run("override clamped to bucket cap", func(t *testing.T) {
		got := chooseBucketSeconds(base, base.Add(30*24*time.Hour), 60)
		rangeSeconds := int64(30 * 24 * 3600)
		if rangeSeconds/got > timelineMaxBuckets {
			t.Fatalf("bucket %d yields %d buckets, cap is %d", got, rangeSeconds/got, timelineMaxBuckets)
		}
	})

	t.Run("never exceeds cap for huge ranges", func(t *testing.T) {
		got := chooseBucketSeconds(base, base.Add(5*365*24*time.Hour), 0)
		rangeSeconds := int64(5 * 365 * 24 * 3600)
		if rangeSeconds/got > timelineMaxBuckets {
			t.Fatalf("bucket %d yields %d buckets, cap is %d", got, rangeSeconds/got, timelineMaxBuckets)
		}
	})
}

func TestBulkPermanentBlockHandlerValidation(t *testing.T) {
	t.Run("invalid payload is 400", func(t *testing.T) {
		c, w := newTestContext(http.MethodPost, "/api/advanced-actions/blocks", `not json`)
		BulkPermanentBlockHandler(c)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})

	t.Run("empty ip list is 400", func(t *testing.T) {
		c, w := newTestContext(http.MethodPost, "/api/advanced-actions/blocks", `{"ips":[]}`)
		BulkPermanentBlockHandler(c)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
	})

	t.Run("over the cap is 400", func(t *testing.T) {
		ips := make([]string, bulkBlockMaxIPs+1)
		for i := range ips {
			ips[i] = fmt.Sprintf("203.0.113.%d", i%250)
		}
		body, _ := json.Marshal(map[string]any{"ips": ips})
		c, w := newTestContext(http.MethodPost, "/api/advanced-actions/blocks", string(body))
		BulkPermanentBlockHandler(c)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		if !strings.Contains(w.Body.String(), "too many IPs") {
			t.Fatalf("body = %s, want cap error", w.Body.String())
		}
	})

	t.Run("no integration configured is 400", func(t *testing.T) {
		// Default settings ship without an advanced-actions integration.
		c, w := newTestContext(http.MethodPost, "/api/advanced-actions/blocks", `{"ips":["203.0.113.7"]}`)
		BulkPermanentBlockHandler(c)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		if !strings.Contains(w.Body.String(), "no integration configured") {
			t.Fatalf("body = %s, want integration error", w.Body.String())
		}
	})
}
