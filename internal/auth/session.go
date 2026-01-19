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

package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	sessionCookieName = "fail2ban_ui_session"
	sessionKeyLength  = 32 // AES-256
)

// Session represents a user session
type Session struct {
	UserID    string    `json:"userID"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expiresAt"`
}

var sessionSecret []byte

// InitializeSessionSecret initializes the session encryption secret
func InitializeSessionSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("session secret cannot be empty")
	}

	// Decode base64 secret or use directly if not base64
	decoded, err := base64.URLEncoding.DecodeString(secret)
	if err != nil {
		// Not base64, use as-is (but ensure it's 32 bytes for AES-256)
		if len(secret) < sessionKeyLength {
			return fmt.Errorf("session secret must be at least %d bytes", sessionKeyLength)
		}
		// Use first 32 bytes
		sessionSecret = []byte(secret[:sessionKeyLength])
	} else {
		if len(decoded) < sessionKeyLength {
			return fmt.Errorf("decoded session secret must be at least %d bytes", sessionKeyLength)
		}
		sessionSecret = decoded[:sessionKeyLength]
	}

	return nil
}

// CreateSession creates a new encrypted session cookie
func CreateSession(w http.ResponseWriter, r *http.Request, userInfo *UserInfo, maxAge int) error {
	session := &Session{
		UserID:    userInfo.ID,
		Email:     userInfo.Email,
		Name:      userInfo.Name,
		Username:  userInfo.Username,
		ExpiresAt: time.Now().Add(time.Duration(maxAge) * time.Second),
	}

	// Serialize session to JSON
	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	// Encrypt session data
	encrypted, err := encrypt(sessionData)
	if err != nil {
		return fmt.Errorf("failed to encrypt session: %w", err)
	}

	// Determine if we're using HTTPS
	isSecure := r != nil && (r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https")

	// Create secure cookie
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    encrypted,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   isSecure, // Only secure over HTTPS
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)
	return nil
}

// GetSession retrieves and validates a session from the cookie
func GetSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("no session cookie: %w", err)
	}

	// Decrypt session data
	decrypted, err := decrypt(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session: %w", err)
	}

	// Deserialize session
	var session Session
	if err := json.Unmarshal(decrypted, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

	return &session, nil
}

// DeleteSession clears the session cookie
func DeleteSession(w http.ResponseWriter, r *http.Request) {
	// Determine if we're using HTTPS
	isSecure := r != nil && (r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https")

	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecure, // Only secure over HTTPS
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

// encrypt encrypts data using AES-GCM
func encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(sessionSecret)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts data using AES-GCM
func decrypt(ciphertext string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sessionSecret)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
