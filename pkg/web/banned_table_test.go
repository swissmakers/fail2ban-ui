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
	"reflect"
	"testing"
)

func sampleRows() []bannedIPRow {
	return []bannedIPRow{
		{Jail: "sshd", IP: "10.0.0.1", BanTime: "2026-01-01T10:00:00Z"},
		{Jail: "httpd", IP: "203.0.113.5", BanTime: "2026-01-01T12:00:00Z"},
		{Jail: "sshd", IP: "10.0.0.2", BanTime: ""}, // no recorded ban event
		{Jail: "httpd", IP: "198.51.100.9", BanTime: ""},
	}
}

func TestSortBannedRowsByBanTimeNullsLast(t *testing.T) {
	rows := sampleRows()
	// desc: newest ban time first, rows without a time after all timed rows.
	sortBannedRows(rows, "banTime", "desc")
	var got []string
	for _, r := range rows {
		got = append(got, r.IP)
	}
	want := []string{"203.0.113.5", "10.0.0.1", "198.51.100.9", "10.0.0.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("banTime desc = %v, want %v", got, want)
	}

	// asc still keeps untimed rows last, but orders timed rows ascending.
	rows = sampleRows()
	sortBannedRows(rows, "banTime", "asc")
	got = got[:0]
	for _, r := range rows {
		got = append(got, r.IP)
	}
	want = []string{"10.0.0.1", "203.0.113.5", "198.51.100.9", "10.0.0.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("banTime asc = %v, want %v", got, want)
	}
}

func TestSortBannedRowsByJailAndIP(t *testing.T) {
	rows := sampleRows()
	sortBannedRows(rows, "jail", "asc")
	var got []string
	for _, r := range rows {
		got = append(got, r.Jail+"/"+r.IP)
	}
	want := []string{"httpd/198.51.100.9", "httpd/203.0.113.5", "sshd/10.0.0.1", "sshd/10.0.0.2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("jail asc = %v, want %v", got, want)
	}

	rows = sampleRows()
	sortBannedRows(rows, "jail", "desc")
	got = got[:0]
	for _, r := range rows {
		got = append(got, r.Jail+"/"+r.IP)
	}
	want = []string{"sshd/10.0.0.1", "sshd/10.0.0.2", "httpd/198.51.100.9", "httpd/203.0.113.5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("jail desc = %v, want %v", got, want)
	}

	rows = sampleRows()
	sortBannedRows(rows, "ip", "asc")
	got = got[:0]
	for _, r := range rows {
		got = append(got, r.IP)
	}
	want = []string{"10.0.0.1", "10.0.0.2", "198.51.100.9", "203.0.113.5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ip asc = %v, want %v", got, want)
	}

	rows = sampleRows()
	sortBannedRows(rows, "ip", "desc")
	got = got[:0]
	for _, r := range rows {
		got = append(got, r.IP)
	}
	want = []string{"203.0.113.5", "198.51.100.9", "10.0.0.2", "10.0.0.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ip desc = %v, want %v", got, want)
	}
}
