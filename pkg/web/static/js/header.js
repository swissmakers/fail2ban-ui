// Header components: Clock and Backend Status Indicator
"use strict";

// =========================================================================
//  Global Variables
// =========================================================================

var clockInterval = null;
var statusUpdateCallback = null;
var headerStatusState = 'connecting';
var headerStatusText = '';
var wsTooltipRefreshContent = null;
var wsTooltipElement = null;

function getWebSocketStatusText(state, fallbackText) {
  switch (state) {
    case 'connected':
      return t('header.websocket.status.connected', 'Connected');
    case 'connecting':
      return t('header.websocket.status.connecting', 'Connecting...');
    case 'reconnecting':
      return t('header.websocket.status.reconnecting', 'Reconnecting...');
    case 'disconnected':
      return t('header.websocket.status.disconnected', 'Disconnected');
    case 'disconnecting':
      return t('header.websocket.status.disconnecting', 'Disconnecting...');
    case 'error':
      return t('header.websocket.status.error', 'Connection error');
    default:
      return fallbackText || t('header.websocket.status.unknown', 'Unknown');
  }
}

function getWebSocketProtocolLabel(protocol) {
  if (protocol === 'WSS (Secure)') {
    return t('header.websocket.tooltip.protocol_wss_secure', 'WSS (Secure)');
  }
  if (protocol === 'WS') {
    return t('header.websocket.tooltip.protocol_ws', 'WS');
  }
  return protocol || '';
}

// =========================================================================
//  Clock
// =========================================================================

function initClock() {
  function updateClock() {
    var now = new Date();
    var hours = String(now.getHours()).padStart(2, '0');
    var minutes = String(now.getMinutes()).padStart(2, '0');
    var seconds = String(now.getSeconds()).padStart(2, '0');
    var timeString = hours + ':' + minutes + ':' + seconds;
    
    var clockElement = document.getElementById('clockTime');
    if (clockElement) {
      clockElement.textContent = timeString;
    }
  }
  updateClock();
  if (clockInterval) {
    clearInterval(clockInterval);
  }
  clockInterval = setInterval(updateClock, 1000);
}

// =========================================================================
//  Status Indicator
// =========================================================================

function initStatusIndicator() {
  updateStatusIndicator('connecting');
  function registerStatusCallback() {
    if (typeof wsManager !== 'undefined' && wsManager) {
      wsManager.onStatusChange(function(state, text) {
        updateStatusIndicator(state, text);
      });
      var currentState = wsManager.getConnectionState();
      var currentText = getWebSocketStatusText('connecting');
      if (currentState === 'connected' && wsManager.isConnected) {
        currentText = getWebSocketStatusText('connected');
      } else if (currentState === 'connecting') {
        currentText = getWebSocketStatusText('connecting');
      } else if (currentState === 'disconnected') {
        currentText = getWebSocketStatusText('disconnected');
      } else if (currentState === 'disconnecting') {
        currentText = getWebSocketStatusText('disconnecting');
      }
      updateStatusIndicator(currentState, currentText);
      return true;
    }
    return false;
  }
  if (!registerStatusCallback()) {
    var checkInterval = setInterval(function() {
      if (registerStatusCallback()) {
        clearInterval(checkInterval);
      }
    }, 100);
    setTimeout(function() {
      clearInterval(checkInterval);
    }, 5000);
  }
}

function updateStatusIndicator(state, text) {
  var statusDot = document.getElementById('statusDot');
  var statusText = document.getElementById('statusText');
  if (!statusDot || !statusText) {
    return;
  }
  headerStatusState = state || 'unknown';
  headerStatusText = text || '';
  statusDot.classList.remove('bg-green-500', 'bg-yellow-500', 'bg-red-500', 'bg-gray-400');
  var statusLabel = getWebSocketStatusText(state, text);
  switch (state) {
    case 'connected':
      statusDot.classList.add('bg-green-500');
      statusText.textContent = statusLabel;
      break;
    case 'connecting':
    case 'reconnecting':
      statusDot.classList.add('bg-yellow-500');
      statusText.textContent = statusLabel;
      break;
    case 'disconnected':
    case 'error':
      statusDot.classList.add('bg-red-500');
      statusText.textContent = statusLabel;
      break;
    default:
      statusDot.classList.add('bg-gray-400');
      statusText.textContent = statusLabel;
  }
}

function refreshHeaderTranslations() {
  var state = headerStatusState || 'unknown';
  if (typeof wsManager !== 'undefined' && wsManager && typeof wsManager.getConnectionState === 'function') {
    state = wsManager.getConnectionState();
  }
  updateStatusIndicator(state, headerStatusText);
  if (wsTooltipElement && wsTooltipElement.style.display !== 'none' && typeof wsTooltipRefreshContent === 'function') {
    wsTooltipRefreshContent();
  }
}

// =========================================================================
//  WebSocket Tooltip
// =========================================================================

function createWebSocketTooltip() {
  const tooltip = document.createElement('div');
  tooltip.id = 'wsTooltip';
  tooltip.className = 'fixed z-50 px-3 py-2 bg-gray-900 text-white text-xs rounded shadow-lg pointer-events-none opacity-0 transition-opacity duration-200';
  tooltip.style.display = 'none';
  tooltip.style.minWidth = '200px';
  document.body.appendChild(tooltip);
  wsTooltipElement = tooltip;
  const statusEl = document.getElementById('backendStatus');
  if (!statusEl) {
    return;
  }
  let tooltipUpdateInterval = null;
  function updateTooltipContent() {
    if (!wsManager || !wsManager.isConnected) {
      return;
    }
    const info = wsManager.getConnectionInfo();
    if (!info) {
      return;
    }
    tooltip.innerHTML = `
      <div class="font-semibold mb-2 text-green-400 border-b border-gray-700 pb-1">${t('header.websocket.tooltip.title', 'WebSocket Connection')}</div>
      <div class="space-y-1">
        <div class="flex justify-between">
          <span class="text-gray-400">${t('header.websocket.tooltip.duration', 'Duration:')}</span>
          <span class="text-green-400 font-medium">${info.duration}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-gray-400">${t('header.websocket.tooltip.last_heartbeat', 'Last Heartbeat:')}</span>
          <span class="text-blue-400 font-medium">${info.lastHeartbeat}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-gray-400">${t('header.websocket.tooltip.messages', 'Messages:')}</span>
          <span class="text-yellow-400 font-medium">${info.messages}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-gray-400">${t('header.websocket.tooltip.reconnects', 'Reconnects:')}</span>
          <span class="text-orange-400 font-medium">${info.reconnects}</span>
        </div>
        <div class="mt-2 pt-2 border-t border-gray-700">
          <div class="text-gray-400 text-xs">${getWebSocketProtocolLabel(info.protocol)}</div>
          <div class="text-gray-500 text-xs mt-1 break-all">${info.url}</div>
        </div>
      </div>
    `;
  }
  wsTooltipRefreshContent = updateTooltipContent;
  function showTooltip(e) {
    if (!wsManager || !wsManager.isConnected) {
      return;
    }
    updateTooltipContent();
    const rect = statusEl.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    let left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);
    let top = rect.bottom + 8;
    if (left < 8) left = 8;
    if (left + tooltipRect.width > window.innerWidth - 8) {
      left = window.innerWidth - tooltipRect.width - 8;
    }
    if (top + tooltipRect.height > window.innerHeight - 8) {
      top = rect.top - tooltipRect.height - 8;
    }
    tooltip.style.left = left + 'px';
    tooltip.style.top = top + 'px';
    tooltip.style.display = 'block';
    setTimeout(() => {
      tooltip.style.opacity = '1';
    }, 10);
    if (tooltipUpdateInterval) {
      clearInterval(tooltipUpdateInterval);
    }
    tooltipUpdateInterval = setInterval(updateTooltipContent, 1000);
  }
  function hideTooltip() {
    tooltip.style.opacity = '0';
    setTimeout(() => {
      tooltip.style.display = 'none';
    }, 200);
    if (tooltipUpdateInterval) {
      clearInterval(tooltipUpdateInterval);
      tooltipUpdateInterval = null;
    }
  }
  statusEl.addEventListener('mouseenter', showTooltip);
  statusEl.addEventListener('mouseleave', hideTooltip);
  if (typeof wsManager !== 'undefined' && wsManager) {
    wsManager.onStatusChange(function(state, text) {
      if (state !== 'connected') {
        hideTooltip();
      }
    });
  } else {
    var checkInterval = setInterval(function() {
      if (typeof wsManager !== 'undefined' && wsManager) {
        wsManager.onStatusChange(function(state, text) {
          if (state !== 'connected') {
            hideTooltip();
          }
        });
        clearInterval(checkInterval);
      }
    }, 100);
  }
}

// =========================================================================
//  Initialization
// =========================================================================

function initHeader() {
  initClock();
  initStatusIndicator();
  createWebSocketTooltip();
}

if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', function() {
    if (clockInterval) {
      clearInterval(clockInterval);
    }
  });
}
