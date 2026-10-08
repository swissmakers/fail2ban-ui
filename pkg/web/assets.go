// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2025 Swissmakers GmbH (https://swissmakers.ch)
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
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/version"
)

//go:embed templates/*
var embeddedTemplates embed.FS

//go:embed all:static
var embeddedStatic embed.FS

//go:embed locales/*.json
var embeddedLocales embed.FS

// LocalesFS is the embedded UI translations
var LocalesFS fs.FS

func init() {
	sub, err := fs.Sub(embeddedLocales, "locales")
	if err != nil {
		panic("web: locales embed: " + err.Error())
	}
	LocalesFS = sub
}

// Cache-busting token for asset URLs: stable across restarts, new whenever an embedded asset changes.
var assetVersion = sync.OnceValue(func() string {
	return version.Version + "-" + contentHash(embeddedStatic, embeddedLocales)
})

// Hashes every file path and body in walk order; the first 8 hex characters are plenty for cache busting.
func contentHash(trees ...fs.FS) string {
	sum := sha256.New()
	for _, tree := range trees {
		_ = fs.WalkDir(tree, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := fs.ReadFile(tree, p)
			if err != nil {
				return err
			}
			sum.Write([]byte(p))
			sum.Write([]byte{0})
			sum.Write(data)
			return nil
		})
	}
	return hex.EncodeToString(sum.Sum(nil))[:8]
}

// Registers HTML templates and /static and /locales handlers using data embedded at compile time.
func MountEmbeddedAssets(r *gin.Engine) error {
	tmpl, err := template.ParseFS(embeddedTemplates, "templates/*.html")
	if err != nil {
		return fmt.Errorf("parse HTML templates: %w", err)
	}
	r.SetHTMLTemplate(tmpl)

	staticRoot, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		return fmt.Errorf("static subdirectory: %w", err)
	}
	r.StaticFS("/static", http.FS(staticRoot))
	r.StaticFS("/locales", http.FS(LocalesFS))
	return nil
}
