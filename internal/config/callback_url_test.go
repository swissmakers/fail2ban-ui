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

package config

import (
	"testing"

	"github.com/swissmakers/fail2ban-ui/internal/shared"
)

func TestDefaultCallbackPortChangeKeepsBasePath(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("CALLBACK_URL", "")
	shared.SetBasePath("/dev/")
	t.Cleanup(func() { shared.SetBasePath("") })
	original := GetSettings()
	t.Cleanup(func() { _, _ = UpdateSettings(original) })
	settings := original
	settings.Port = 8080
	settings.CallbackURL = "http://127.0.0.1:8080/dev"
	if _, err := UpdateSettings(settings); err != nil {
		t.Fatal(err)
	}
	settings = GetSettings()
	settings.Port = 8181
	updated, err := UpdateSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	if updated.CallbackURL != "http://127.0.0.1:8181/dev" {
		t.Fatalf("stale default callback URL: %q", updated.CallbackURL)
	}
	if isDefaultLoopbackCallbackURL("http://127.0.0.1:8181/custom-proxy") {
		t.Fatal("explicit proxy path must not be rewritten")
	}
}
