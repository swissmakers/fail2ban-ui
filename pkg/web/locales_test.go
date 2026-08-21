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
	"io/fs"
	"sort"
	"strings"
	"testing"
)

func loadLocaleKeys(t *testing.T, name string) map[string]struct{} {
	t.Helper()
	data, err := fs.ReadFile(LocalesFS, name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	keys := make(map[string]struct{}, len(m))
	for k := range m {
		keys[k] = struct{}{}
	}
	return keys
}

// Every locale must carry exactly the same key set as en.json, so no language
// silently falls back to English for individual strings.
func TestLocaleKeySetsMatchEnglish(t *testing.T) {
	entries, err := fs.Glob(LocalesFS, "*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected multiple locale files, found %v", entries)
	}
	ref := loadLocaleKeys(t, "en.json")
	for _, name := range entries {
		if name == "en.json" {
			continue
		}
		keys := loadLocaleKeys(t, name)
		var missing, extra []string
		for k := range ref {
			if _, ok := keys[k]; !ok {
				missing = append(missing, k)
			}
		}
		for k := range keys {
			if _, ok := ref[k]; !ok {
				extra = append(extra, k)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		if len(missing) > 0 {
			t.Errorf("%s is missing %d keys present in en.json:\n  %s", name, len(missing), strings.Join(missing, "\n  "))
		}
		if len(extra) > 0 {
			t.Errorf("%s has %d keys not present in en.json:\n  %s", name, len(extra), strings.Join(extra, "\n  "))
		}
	}
}
