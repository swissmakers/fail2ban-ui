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
	"io"
	"log"
	"os"
	"sync"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// ConsoleLogWriter is a multi-writer that writes to both the original log output
// and broadcasts to WebSocket clients when console output is enabled
type ConsoleLogWriter struct {
	originalWriter io.Writer
	hub            *Hub
	mu             sync.RWMutex
	enabled        bool
}

// NewConsoleLogWriter creates a new console log writer
func NewConsoleLogWriter(hub *Hub, originalWriter io.Writer) *ConsoleLogWriter {
	return &ConsoleLogWriter{
		originalWriter: originalWriter,
		hub:            hub,
		enabled:        false,
	}
}

// SetEnabled enables or disables console output broadcasting
func (c *ConsoleLogWriter) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
}

// Write implements io.Writer interface
func (c *ConsoleLogWriter) Write(p []byte) (n int, err error) {
	// Always write to original writer
	n, err = c.originalWriter.Write(p)
	
	// Broadcast to WebSocket if enabled
	c.mu.RLock()
	enabled := c.enabled
	c.mu.RUnlock()
	
	if enabled && c.hub != nil {
		// Remove trailing newline for cleaner display
		message := string(p)
		if len(message) > 0 && message[len(message)-1] == '\n' {
			message = message[:len(message)-1]
		}
		if len(message) > 0 {
			c.hub.BroadcastConsoleLog(message)
		}
	}
	
	return n, err
}

var globalConsoleLogWriter *ConsoleLogWriter
var consoleLogWriterOnce sync.Once

// SetupConsoleLogWriter sets up the console log writer and replaces the standard log output
// This captures all log.Printf, log.Println, etc. output
func SetupConsoleLogWriter(hub *Hub) {
	consoleLogWriterOnce.Do(func() {
		// Create a multi-writer that writes to both original stdout and our console writer
		globalConsoleLogWriter = NewConsoleLogWriter(hub, os.Stdout)
		
		// Replace log output - this captures all log.Printf, log.Println, etc.
		log.SetOutput(globalConsoleLogWriter)
	})
}

// UpdateConsoleLogEnabled updates the enabled state based on settings
func UpdateConsoleLogEnabled() {
	if globalConsoleLogWriter != nil {
		settings := config.GetSettings()
		globalConsoleLogWriter.SetEnabled(settings.ConsoleOutput)
	}
}

// SetConsoleLogEnabled directly sets the enabled state
func SetConsoleLogEnabled(enabled bool) {
	if globalConsoleLogWriter != nil {
		globalConsoleLogWriter.SetEnabled(enabled)
	}
}
