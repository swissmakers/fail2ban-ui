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
// distributed under the License is distributed on "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
	"github.com/swissmakers/fail2ban-ui/internal/storage"
)

// =========================================================================
//  Types and Constants
// =========================================================================

type Client struct {
	hub            *Hub
	conn           *websocket.Conn
	send           chan []byte
	canReadConsole bool
}

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

const (
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = (pongWait * 9) / 10
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     checkWSOrigin,
}

// =========================================================================
//	WebSocket Origin Validation
// =========================================================================

// Checks the origin of the WebSocket connection to prevent cross-origin hijacking.
func checkWSOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		log.Printf("WebSocket rejected: malformed Origin header %q", origin)
		return false
	}
	reqHost := r.Host
	if reqHost == "" {
		reqHost = r.URL.Host
	}
	originHost := u.Host
	if !strings.Contains(originHost, ":") && strings.Contains(reqHost, ":") {
		if u.Scheme == "https" {
			originHost += ":443"
		} else {
			originHost += ":80"
		}
	}
	if !strings.EqualFold(originHost, reqHost) {
		log.Printf("WebSocket rejected: origin %q does not match host %q", origin, reqHost)
		return false
	}
	return true
}

// =========================================================================
//  Fail2ban-UI WebSocket Hub
// =========================================================================

// Broadcasts the console log message to all connected admin clients.
func (h *Hub) BroadcastConsoleLog(message string) {
	logMsg := map[string]interface{}{
		"type":    "console_log",
		"message": message,
		"time":    time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(logMsg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling console log: %v\n", err)
		return
	}

	select {
	case h.broadcast <- data:
	default:
		fmt.Fprintln(os.Stderr, "Broadcast channel full, dropping console log")
	}
}

// Pushes a transient toast notification to all connected clients.
func (h *Hub) BroadcastToast(level, message string) {
	toastMsg := map[string]interface{}{
		"type":    "toast",
		"level":   level,
		"message": message,
		"time":    time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(toastMsg)
	if err != nil {
		log.Printf("Error marshaling toast: %v", err)
		return
	}

	select {
	case h.broadcast <- data:
	default:
		log.Printf("Broadcast channel full, dropping toast")
	}
}

// Pushes health state transition -> carries no error text because every viewer receives it
func (h *Hub) BroadcastServerHealth(serverID string, health fail2ban.ServerHealth) {
	data, err := json.Marshal(map[string]any{
		"type": "server_health",
		"data": map[string]any{"serverId": serverID, "state": health.State, "checkedAt": health.CheckedAt},
	})
	if err != nil {
		log.Printf("Error marshaling server health: %v", err)
		return
	}
	select {
	case h.broadcast <- data:
	default:
		log.Printf("Broadcast channel full, dropping server health")
	}
}

// Creates new Hub instance.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Runs the Hub.
func (h *Hub) Run() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("WebSocket client connected. Total clients: %d", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			log.Printf("WebSocket client disconnected. Total clients: %d", len(h.clients))

		case message := <-h.broadcast:
			h.deliver(message)

		case <-ticker.C:
			h.sendHeartbeat()
		}
	}
}

// Event readers must not receive admin console traffic on the shared socket.
func (h *Hub) deliver(message []byte) {
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(message, &envelope); err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	publicMessage := message
	if envelope.Type == "operation" {
		var event struct {
			Type string          `json:"type"`
			Data publicOperation `json:"data"`
		}
		if json.Unmarshal(message, &event) == nil {
			event.Data = redactOperation(event.Data, false)
			if encoded, err := json.Marshal(event); err == nil {
				publicMessage = encoded
			}
		}
	}
	for client := range h.clients {
		if envelope.Type == "console_log" && !client.canReadConsole {
			continue
		}
		payload := message
		if !client.canReadConsole {
			payload = publicMessage
		}
		select {
		case client.send <- payload:
		default:
			close(client.send)
			delete(h.clients, client)
		}
	}
}

func (h *Hub) sendHeartbeat() {
	message := map[string]interface{}{
		"type":   "heartbeat",
		"time":   time.Now().UTC().Unix(),
		"status": "healthy",
	}
	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshaling heartbeat: %v", err)
		return
	}

	h.mu.Lock()
	for client := range h.clients {
		select {
		case client.send <- data:
		default:
			close(client.send)
			delete(h.clients, client)
		}
	}
	h.mu.Unlock()
}

// =========================================================================
//  Broadcast Ban/Unban Events
// =========================================================================

func (h *Hub) broadcastEvent(msgType string, event storage.BanEventRecord) {
	message := map[string]interface{}{
		"type": msgType,
		"data": event,
	}
	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshaling %s: %v", msgType, err)
		return
	}

	select {
	case h.broadcast <- data:
	default:
		log.Printf("Broadcast channel full, dropping %s", msgType)
	}
}

func (h *Hub) BroadcastBanEvent(event storage.BanEventRecord) {
	h.broadcastEvent("ban_event", event)
}

func (h *Hub) BroadcastBanEventUpdate(event storage.BanEventRecord) {
	h.broadcastEvent("ban_event_update", event)
}

func (h *Hub) BroadcastUnbanEvent(event storage.BanEventRecord) {
	h.broadcastEvent("unban_event", event)
}

// =========================================================================
//  WebSocket Helper Functions
// =========================================================================

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// Returns the Gin handler that upgrades a request to a WebSocket client of hub
func WebSocketHandler(hub *Hub) gin.HandlerFunc {
	return func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Printf("WebSocket upgrade error: %v", err)
			return
		}
		client := &Client{
			hub:            hub,
			conn:           conn,
			send:           make(chan []byte, 256),
			canReadConsole: userHasAdminAccess(c),
		}
		client.hub.register <- client
		go client.writePump()
		go client.readPump()
	}
}
