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

func TestClassifyCallbackSecret(t *testing.T) {
	tests := []struct {
		name     string
		provided string
		expected string
		want     callbackSecretClass
	}{
		{"empty expected", "x", "", callbackSecretNotConfigured},
		{"missing header", "", "secret", callbackSecretMissingHeader},
		{"valid", "secret", "secret", callbackSecretOK},
		{"wrong secret", "a", "b", callbackSecretMismatch},
		{"length leak safe wrong", "secret", "secreT", callbackSecretMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyCallbackSecret(tt.provided, tt.expected); got != tt.want {
				t.Errorf("classifyCallbackSecret(%q, %q) = %v, want %v", tt.provided, tt.expected, got, tt.want)
			}
		})
	}
}
