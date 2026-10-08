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
	"net"
	"testing"
)

func TestShouldAlertForCountry(t *testing.T) {
	tests := []struct {
		name      string
		country   string
		countries []string
		want      bool
	}{
		{name: "empty list alerts all", country: "CH", countries: nil, want: true},
		{name: "ALL", country: "CH", countries: []string{"ALL"}, want: true},
		{name: "match", country: "ch", countries: []string{"DE", "CH"}, want: true},
		{name: "no match", country: "US", countries: []string{"DE", "CH"}, want: false},
		{name: "only LOTR alerts all", country: "US", countries: []string{"LOTR"}, want: true},
		{name: "LOTR with ALL", country: "US", countries: []string{"LOTR", "ALL"}, want: true},
		{name: "LOTR with countries filters", country: "US", countries: []string{"LOTR", "CH"}, want: false},
		{name: "blank entries ignored", country: "US", countries: []string{" ", ""}, want: true},
		{name: "unknown country with filter", country: "", countries: []string{"CH"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldAlertForCountry(tt.country, tt.countries); got != tt.want {
				t.Fatalf("shouldAlertForCountry(%q, %q) = %v, want %v", tt.country, tt.countries, got, tt.want)
			}
		})
	}
}

func TestThreatIntelURL(t *testing.T) {
	tests := []struct {
		provider, ip, want string
		ok                 bool
	}{
		{"alienvault", "192.0.2.1", "https://otx.alienvault.com/api/v1/indicators/IPv4/192.0.2.1/general", true},
		{"alienvault", "2001:db8::1", "https://otx.alienvault.com/api/v1/indicators/IPv6/2001:db8::1/general", true},
		{"alienvault", "::ffff:192.0.2.1", "https://otx.alienvault.com/api/v1/indicators/IPv4/192.0.2.1/general", true},
		{"abuseipdb", "2001:db8::1", "https://api.abuseipdb.com/api/v2/check?ipAddress=2001%3Adb8%3A%3A1&maxAgeInDays=90&verbose=true", true},
		{"other", "192.0.2.1", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.provider+" "+tt.ip, func(t *testing.T) {
			got, ok := threatIntelURL(tt.provider, net.ParseIP(tt.ip))
			if got != tt.want || ok != tt.ok {
				t.Fatalf("threatIntelURL = %q, %v; want %q, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestPermanentBlockTargetError(t *testing.T) {
	tests := []struct {
		action, ip string
		wantKey    string
		wantErr    bool
	}{
		{"block", "203.0.113.9", "", false},
		{"block", "2001:db8::1", "", false},
		{"block", "192.168.1.10", "settings.advanced.errors.reserved_ip", true},
		{"block", "127.0.0.1", "settings.advanced.errors.reserved_ip", true},
		{"block", "203.0.113.0/24", "settings.advanced.errors.cidr_not_supported", true},
		{"unblock", "203.0.113.0/24", "settings.advanced.errors.cidr_not_supported", true},
		{"unblock", "10.0.0.1", "", false},
		{"block", "not-an-ip", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.action+" "+tt.ip, func(t *testing.T) {
			err := permanentBlockTargetError(tt.action, tt.ip)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantKey != "" {
				if got := buildErrorResponse(err, "")["messageKey"]; got != tt.wantKey {
					t.Fatalf("messageKey = %v, want %s", got, tt.wantKey)
				}
			}
		})
	}
}
