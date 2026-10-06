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

package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

func TestDataStreamFields(t *testing.T) {
	tests := []struct {
		name, target string
		want         map[string]string
	}{
		{"default stream", "logs-fail2ban_ui.events-default", map[string]string{
			"data_stream.type": "logs", "data_stream.dataset": "fail2ban_ui.events", "data_stream.namespace": "default"}},
		{"custom namespace", "logs-fail2ban_ui.events-prod", map[string]string{
			"data_stream.type": "logs", "data_stream.dataset": "fail2ban_ui.events", "data_stream.namespace": "prod"}},
		{"custom name outside the scheme", "security-fail2ban", nil},
		{"not a logs type", "metrics-fail2ban-default", nil},
		{"too many parts", "logs-a-b-c", nil},
		{"empty dataset", "logs--default", nil},
		{"empty namespace", "logs-fail2ban-", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dataStreamFields(tt.target); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dataStreamFields(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestElasticsearchWriteError(t *testing.T) {
	esBody := func(reason string) []byte {
		return []byte(`{"error":{"root_cause":[{"reason":"` + reason + `"}],"type":"x","reason":"` + reason + `"},"status":0}`)
	}
	tests := []struct {
		name    string
		status  int
		body    []byte
		want    []string
		notWant []string
	}{
		{"existing plain index", 404, esBody("[require_data_stream] request flag is [true] and [idx] is not a data stream"),
			[]string{`"idx" is not a data stream`, config.DefaultElasticsearchDataStream, "request flag is [true]"}, []string{"root_cause"}},
		{"no data stream template", 404, esBody("no such index [idx] and the index creation request requires a data stream"),
			[]string{"is not a data stream", "requires a data stream"}, nil},
		{"missing privileges", 403, esBody("action [indices:data/write/bulk[s]] is unauthorized"),
			[]string{"create_doc and auto_configure", "is unauthorized"}, []string{"status 403"}},
		{"other 404 has no data stream hint", 404, esBody("no such index"),
			[]string{"status 404: no such index"}, []string{"data stream"}},
		{"data stream reason on other status has no hint", 400, esBody("mapping conflict in data stream"),
			[]string{"status 400: mapping conflict"}, []string{"not a data stream"}},
		{"bad credentials", 401, esBody("unable to authenticate"),
			[]string{"status 401: unable to authenticate"}, []string{"privileges"}},
		{"non-JSON body is passed through", 502, []byte(" bad gateway \n"),
			[]string{"status 502: bad gateway"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := elasticsearchWriteError("idx", tt.status, tt.body).Error()
			for _, w := range tt.want {
				if !strings.Contains(msg, w) {
					t.Errorf("error %q does not contain %q", msg, w)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(msg, w) {
					t.Errorf("error %q must not contain %q", msg, w)
				}
			}
		})
	}
}

func TestSendElasticsearchAlertWritesToDataStream(t *testing.T) {
	var gotPath, gotQuery, gotAuth string
	var gotDoc map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotAuth = r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotDoc)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	settings := config.AppSettings{Elasticsearch: config.ElasticsearchSettings{URL: srv.URL, Index: "fail2ban-events", APIKey: "k"}}
	if err := sendElasticsearchAlert("ban", "203.0.113.1", "sshd", "host", "3", "", "", "CH", settings); err != nil {
		t.Fatalf("sendElasticsearchAlert: %v", err)
	}
	if gotPath != "/logs-fail2ban_ui.events-default/_doc" || gotQuery != "require_data_stream=true" {
		t.Errorf("request went to %s?%s, want the default data stream with require_data_stream=true", gotPath, gotQuery)
	}
	if gotAuth != "ApiKey k" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotDoc["data_stream.dataset"] != "fail2ban_ui.events" || gotDoc["source.ip"] != "203.0.113.1" {
		t.Errorf("unexpected document: %v", gotDoc)
	}
}

func TestSendElasticsearchAlertReportsPlainIndexTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"reason":"[require_data_stream] request flag is [true] and [custom] is not a data stream"},"status":404}`))
	}))
	defer srv.Close()

	settings := config.AppSettings{Elasticsearch: config.ElasticsearchSettings{URL: srv.URL, Index: "custom"}}
	err := sendElasticsearchAlert("test", "203.0.113.1", "sshd", "host", "0", "", "", "XX", settings)
	if err == nil || !strings.Contains(err.Error(), `"custom" is not a data stream`) {
		t.Fatalf("want a data stream error, got %v", err)
	}
}
