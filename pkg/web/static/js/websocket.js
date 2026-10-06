// WebSocket manager for real-time updates in Fail2ban UI.
"use strict";

// =========================================================================
//  WebSocket Manager
// =========================================================================

class WebSocketManager {
  constructor() {
    this.ws = null;
    this.state = 'connecting';
    this.listeners = {};
    this.reconnectAttempts = 0;
    this.reconnectDelay = 1000;
    this.maxReconnectDelay = 30000;
    this.reconnectTimer = null;
    this.stopped = false;
    this.isConnecting = false;
    this.isConnected = false;
    this.lastBanEventId = null;
    this.connectedAt = null;
    this.lastHeartbeatAt = null;
    this.messageCount = 0;
    this.totalReconnects = 0;
    this.initialConnection = true;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    this.wsUrl = protocol + '//' + window.location.host + appPath('/api/ws');
  }

  on(type, callback) {
    (this.listeners[type] = this.listeners[type] || []).push(callback);
  }

  emit(type, payload) {
    (this.listeners[type] || []).forEach(function(callback) {
      try {
        callback(payload);
      } catch (err) {
        console.error('Error in WebSocket ' + type + ' listener:', err);
      }
    });
  }

  connect() {
    if (this.stopped || this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
      return;
    }

    this.isConnecting = true;
    this.updateStatus('connecting');

    try {
      this.ws = new WebSocket(this.wsUrl);

      this.ws.onopen = () => {
        this.isConnecting = false;
        this.isConnected = true;
        this.connectedAt = new Date();
        this.reconnectAttempts = 0;
        this.updateStatus('connected');
        if (!this.initialConnection) {
          this.totalReconnects++;
          this.emit('reconnected');
        }
        this.initialConnection = false;
      };

      this.ws.onmessage = (event) => {
        // WebSocket may send multiple JSON messages separated by newlines
        // Split by newlines and parse each message separately
        event.data.split('\n').forEach((line) => {
          if (!line.trim()) {
            return;
          }
          try {
            const message = JSON.parse(line);
            this.messageCount++;
            this.handleMessage(message);
          } catch (err) {
            console.error('Error parsing WebSocket message:', err, 'Raw:', line);
          }
        });
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        this.updateStatus('error');
      };

      this.ws.onclose = () => {
        this.isConnecting = false;
        this.isConnected = false;
        if (this.stopped) {
          return;
        }
        this.updateStatus('disconnected');
        probeSession();
        this.scheduleReconnect();
      };
    } catch (error) {
      console.error('Error creating WebSocket connection:', error);
      this.isConnecting = false;
      this.updateStatus('error');
      this.scheduleReconnect();
    }
  }

  scheduleReconnect() {
    this.reconnectAttempts++;
    const delay = Math.min(this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1), this.maxReconnectDelay);
    this.updateStatus('reconnecting');
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  handleMessage(message) {
    switch (message.type) {
      case 'ban_event':
      case 'unban_event':
        this.handleBanEvent(message.data);
        break;
      case 'ban_event_update':
        this.emit('ban_event_update', message.data);
        break;
      case 'server_health':
        this.emit('server_health', message.data);
        break;
      case 'heartbeat':
        this.lastHeartbeatAt = new Date();
        break;
      case 'console_log':
        this.emit('console_log', message);
        break;
      case 'toast':
        if (message.message) {
          showToast(message.message, message.level || 'info');
        }
        break;
    }
  }

  handleBanEvent(eventData) {
    // Check if we've already processed this event (prevent duplicates)
    if (eventData.id && this.lastBanEventId !== null && eventData.id <= this.lastBanEventId) {
      return;
    }
    if (eventData.id) {
      this.lastBanEventId = eventData.id;
    }
    this.emit('ban_event', eventData);
  }

  updateStatus(state) {
    this.state = state;
    this.emit('status', state);
  }

  // Stops for good; used when the session ends.
  disconnect() {
    this.stopped = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.isConnected = false;
    this.isConnecting = false;
    this.updateStatus('disconnected');
  }

  formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) {
      const mins = Math.floor(seconds / 60);
      const secs = seconds % 60;
      return `${mins}m ${secs}s`;
    }
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${mins}m`;
  }

  getConnectionInfo() {
    if (!this.isConnected || !this.connectedAt) {
      return null;
    }
    
    const now = new Date();
    const duration = Math.floor((now - this.connectedAt) / 1000);
    const lastHeartbeat = this.lastHeartbeatAt
      ? Math.floor((now - this.lastHeartbeatAt) / 1000)
      : null;
    const heartbeatStr = lastHeartbeat !== null
      ? (lastHeartbeat < 60
        ? t('header.websocket.heartbeat.seconds_ago', '{seconds}s ago').replace('{seconds}', String(lastHeartbeat))
        : t('header.websocket.heartbeat.minutes_ago', '{minutes}m ago').replace('{minutes}', String(Math.floor(lastHeartbeat / 60))))
      : t('header.websocket.heartbeat.never', 'Never');

    return {
      duration: this.formatDuration(duration),
      lastHeartbeat: heartbeatStr,
      url: this.wsUrl,
      messages: this.messageCount,
      reconnects: this.totalReconnects,
      secure: this.wsUrl.startsWith('wss:')
    };
  }
}

// =========================================================================
//  Global Instance of WebSocketManager (created in initializeApp)
// =========================================================================

var wsManager = null;
