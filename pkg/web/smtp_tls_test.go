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

package web

import "testing"

func TestSMTPTLSMode(t *testing.T) {
	tests := []struct {
		name        string
		port        int
		useTLS      bool
		implicitTLS bool
		startTLS    bool
	}{
		{name: "port 25 plain", port: 25, useTLS: false, implicitTLS: false, startTLS: false},
		{name: "port 25 starttls", port: 25, useTLS: true, implicitTLS: false, startTLS: true},
		{name: "port 465 implicit tls", port: 465, useTLS: true, implicitTLS: true, startTLS: false},
		{name: "port 465 implicit tls without useTLS flag", port: 465, useTLS: false, implicitTLS: true, startTLS: false},
		{name: "port 587 starttls", port: 587, useTLS: true, implicitTLS: false, startTLS: true},
		{name: "port 2525 starttls", port: 2525, useTLS: true, implicitTLS: false, startTLS: true},
		{name: "port 8025 starttls mailrise", port: 8025, useTLS: true, implicitTLS: false, startTLS: true},
		{name: "port 8025 plain", port: 8025, useTLS: false, implicitTLS: false, startTLS: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			implicitTLS, startTLS := smtpTLSMode(tt.port, tt.useTLS)
			if implicitTLS != tt.implicitTLS {
				t.Fatalf("implicitTLS=%v want %v", implicitTLS, tt.implicitTLS)
			}
			if startTLS != tt.startTLS {
				t.Fatalf("startTLS=%v want %v", startTLS, tt.startTLS)
			}
		})
	}
}
