// WebSocket Manager for Fail2ban UI
// Handles real-time communication with the backend

"use strict";

class WebSocketManager {
  constructor() {
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = Infinity;
    this.reconnectDelay = 1000; // Start with 1 second
    this.maxReconnectDelay = 30000; // Max 30 seconds
    this.isConnecting = false;
    this.isConnected = false;
    this.lastBanEventId = null;
    this.statusCallbacks = [];
    this.banEventCallbacks = [];
    
    // Connection metrics for tooltip
    this.connectedAt = null;
    this.lastHeartbeatAt = null;
    this.messageCount = 0;
    this.totalReconnects = 0;
    this.initialConnection = true;
    
    // Get WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    this.wsUrl = `${protocol}//${host}/api/ws`;
    
    this.connect();
  }

  connect() {
    if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
      return;
    }

    this.isConnecting = true;
    this.updateStatus('connecting', 'Connecting...');

    try {
      this.ws = new WebSocket(this.wsUrl);

      this.ws.onopen = () => {
        this.isConnecting = false;
        this.isConnected = true;
        this.connectedAt = new Date();
        if (!this.initialConnection) {
          this.totalReconnects++;
        }
        this.initialConnection = false;
        this.reconnectAttempts = 0;
        this.reconnectDelay = 1000;
        this.updateStatus('connected', 'Connected');
        console.log('WebSocket connected');
      };

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.messageCount++;
          this.handleMessage(message);
        } catch (err) {
          console.error('Error parsing WebSocket message:', err);
        }
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        this.updateStatus('error', 'Connection error');
      };

      this.ws.onclose = () => {
        this.isConnecting = false;
        this.isConnected = false;
        this.updateStatus('disconnected', 'Disconnected');
        console.log('WebSocket disconnected');
        
        // Attempt to reconnect
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
          this.scheduleReconnect();
        }
      };
    } catch (error) {
      console.error('Error creating WebSocket connection:', error);
      this.isConnecting = false;
      this.updateStatus('error', 'Connection failed');
      this.scheduleReconnect();
    }
  }

  scheduleReconnect() {
    this.reconnectAttempts++;
    const delay = Math.min(this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1), this.maxReconnectDelay);
    
    this.updateStatus('reconnecting', 'Reconnecting...');
    
    setTimeout(() => {
      this.connect();
    }, delay);
  }

  handleMessage(message) {
    switch (message.type) {
      case 'ban_event':
        this.handleBanEvent(message.data);
        break;
      case 'unban_event':
        this.handleBanEvent(message.data); // Use same handler for unban events
        break;
      case 'heartbeat':
        this.handleHeartbeat(message);
        break;
      default:
        console.log('Unknown message type:', message.type);
    }
  }

  handleBanEvent(eventData) {
    // Check if we've already processed this event (prevent duplicates)
    // Only check if event has an ID and we have a lastBanEventId
    if (eventData.id && this.lastBanEventId !== null && eventData.id <= this.lastBanEventId) {
      console.log('Skipping duplicate ban event:', eventData.id);
      return;
    }

    // Update lastBanEventId if event has an ID
    if (eventData.id) {
      if (this.lastBanEventId === null || eventData.id > this.lastBanEventId) {
        this.lastBanEventId = eventData.id;
      }
    }

    console.log('Processing ban event:', eventData);

    // Notify all registered callbacks
    this.banEventCallbacks.forEach(callback => {
      try {
        callback(eventData);
      } catch (err) {
        console.error('Error in ban event callback:', err);
      }
    });
  }

  handleHeartbeat(message) {
    // Update status to show backend is healthy
    this.lastHeartbeatAt = new Date();
    if (this.isConnected) {
      this.updateStatus('connected', 'Connected');
    }
  }

  updateStatus(state, text) {
    this.statusCallbacks.forEach(callback => {
      try {
        callback(state, text);
      } catch (err) {
        console.error('Error in status callback:', err);
      }
    });
  }

  onStatusChange(callback) {
    this.statusCallbacks.push(callback);
  }

  onBanEvent(callback) {
    this.banEventCallbacks.push(callback);
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.isConnected = false;
    this.isConnecting = false;
  }

  getConnectionState() {
    if (!this.ws) {
      return 'disconnected';
    }
    
    switch (this.ws.readyState) {
      case WebSocket.CONNECTING:
        return 'connecting';
      case WebSocket.OPEN:
        return 'connected';
      case WebSocket.CLOSING:
        return 'disconnecting';
      case WebSocket.CLOSED:
        return 'disconnected';
      default:
        return 'unknown';
    }
  }

  isHealthy() {
    return this.isConnected && this.ws && this.ws.readyState === WebSocket.OPEN;
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
    const durationStr = this.formatDuration(duration);
    
    const lastHeartbeat = this.lastHeartbeatAt 
      ? Math.floor((now - this.lastHeartbeatAt) / 1000)
      : null;
    const heartbeatStr = lastHeartbeat !== null 
      ? (lastHeartbeat < 60 ? `${lastHeartbeat}s ago` : `${Math.floor(lastHeartbeat / 60)}m ago`)
      : 'Never';
    
    const protocol = this.wsUrl.startsWith('wss:') ? 'WSS (Secure)' : 'WS';
    
    return {
      duration: durationStr,
      lastHeartbeat: heartbeatStr,
      url: this.wsUrl,
      messages: this.messageCount,
      reconnects: this.totalReconnects,
      protocol: protocol
    };
  }
}

// Create global instance - initialize immediately
var wsManager = null;

// Initialize WebSocket manager
if (typeof window !== 'undefined') {
  // Initialize immediately if DOM is already loaded, otherwise wait
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      if (!wsManager) {
        wsManager = new WebSocketManager();
      }
    });
  } else {
    wsManager = new WebSocketManager();
  }
}

