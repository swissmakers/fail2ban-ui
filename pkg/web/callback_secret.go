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

import (
	"crypto/subtle"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
)

type callbackSecretClass int

const (
	callbackSecretOK callbackSecretClass = iota
	callbackSecretNotConfigured
	callbackSecretMissingHeader
	callbackSecretMismatch
)

// Compares the provided secret to the configured callback secret.
func classifyCallbackSecret(providedSecret, expectedSecret string) callbackSecretClass {
	if expectedSecret == "" {
		return callbackSecretNotConfigured
	}
	if providedSecret == "" {
		return callbackSecretMissingHeader
	}
	if subtle.ConstantTimeCompare([]byte(providedSecret), []byte(expectedSecret)) != 1 {
		return callbackSecretMismatch
	}
	return callbackSecretOK
}

// Validates X-Callback-Secret. On failure it writes JSON and returns false.
func validateCallbackSecret(c *gin.Context) bool {
	settings := config.GetSettings()
	switch classifyCallbackSecret(c.GetHeader("X-Callback-Secret"), settings.CallbackSecret) {
	case callbackSecretNotConfigured:
		log.Printf("⚠️ Callback secret not configured, rejecting request from %s", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Callback secret not configured"})
		return false
	case callbackSecretMissingHeader:
		log.Printf("⚠️ Missing X-Callback-Secret header in request from %s", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing X-Callback-Secret header"})
		return false
	case callbackSecretMismatch:
		log.Printf("⚠️ Invalid callback secret in request from %s", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid callback secret"})
		return false
	default:
		return true
	}
}

// Validates X-Callback-Secret without side effects (for agent connectivity tests).
func CallbackPingHandler(c *gin.Context) {
	if !validateCallbackSecret(c) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
