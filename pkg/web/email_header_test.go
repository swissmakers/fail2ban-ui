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
	"mime"
	"strings"
	"testing"
)

func TestSanitizeEmailHeaderStripsCRLF(t *testing.T) {
	t.Parallel()
	in := "sshd\r\nBcc: attacker@evil.com"
	got := sanitizeEmailHeader(in)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("sanitizeEmailHeader left CR/LF in %q", got)
	}
	if got != "sshdBcc: attacker@evil.com" {
		t.Fatalf("sanitizeEmailHeader = %q", got)
	}
}

func TestSubjectEncodingNeutralizesInjection(t *testing.T) {
	t.Parallel()
	// A malicious jail/hostname value containing CRLF must not introduce new
	// header lines once RFC 2047-encoded.
	subject := "[Fail2Ban] sshd: banned 1.2.3.4\r\nBcc: attacker@evil.com"
	encoded := mime.QEncoding.Encode("UTF-8", subject)
	if strings.ContainsAny(encoded, "\r\n") {
		t.Fatalf("encoded subject still contains CR/LF: %q", encoded)
	}

	// A plain ASCII subject should remain human-readable (unchanged).
	plain := "[Fail2Ban] sshd: banned 1.2.3.4 from host"
	if got := mime.QEncoding.Encode("UTF-8", plain); got != plain {
		t.Fatalf("plain subject was altered: got %q want %q", got, plain)
	}
}
