// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2025 Swissmakers GmbH (https://swissmakers.ch)
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

import (
	"html/template"
	"testing"
)

func TestEmbeddedTemplatesIndexName(t *testing.T) {
	tmpl, err := template.ParseFS(embeddedTemplates, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tp := range tmpl.Templates() {
		names = append(names, tp.Name())
	}
	ok := false
	for _, n := range names {
		if n == "index.html" {
			ok = true
			break
		}
	}
	if !ok {
		t.Fatalf("template index.html not found; templates: %v", names)
	}
}
