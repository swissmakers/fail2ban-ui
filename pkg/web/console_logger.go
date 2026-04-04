// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the PolyForm Shield License 1.0.0.
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://polyformproject.org/licenses/shield/1.0.0/
//
//     or in the LICENSE file in this repository.
//
// Required Notice: Copyright Swissmakers GmbH (https://swissmakers.ch)

package web

import (
	"io"
	"log"
	"os"
	"sync"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// =========================================================================
//  Console log writer that mirrors log output to the WebSocket hub
//  so the browser can display server logs in real time.
// =========================================================================

type ConsoleLogWriter struct {
	originalWriter io.Writer
	hub            *Hub
	mu             sync.RWMutex
	enabled        bool
}

func NewConsoleLogWriter(hub *Hub, originalWriter io.Writer) *ConsoleLogWriter {
	return &ConsoleLogWriter{
		originalWriter: originalWriter,
		hub:            hub,
		enabled:        false,
	}
}

func (c *ConsoleLogWriter) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
}

// Write sends bytes to the original writer and, when enabled,
// broadcasts the trimmed line to WebSocket clients.
func (c *ConsoleLogWriter) Write(p []byte) (n int, err error) {
	n, err = c.originalWriter.Write(p)

	c.mu.RLock()
	enabled := c.enabled
	c.mu.RUnlock()

	if enabled && c.hub != nil {
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

// =========================================================================
//  Global Setup
// =========================================================================

var globalConsoleLogWriter *ConsoleLogWriter
var consoleLogWriterOnce sync.Once

func SetupConsoleLogWriter(hub *Hub) {
	consoleLogWriterOnce.Do(func() {
		globalConsoleLogWriter = NewConsoleLogWriter(hub, os.Stdout)
		log.SetOutput(globalConsoleLogWriter)
	})
}

func UpdateConsoleLogEnabled() {
	if globalConsoleLogWriter != nil {
		settings := config.GetSettings()
		globalConsoleLogWriter.SetEnabled(settings.ConsoleOutput)
	}
}

func SetConsoleLogEnabled(enabled bool) {
	if globalConsoleLogWriter != nil {
		globalConsoleLogWriter.SetEnabled(enabled)
	}
}
