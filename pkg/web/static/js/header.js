// Header components: Clock and Backend Status Indicator
"use strict";

var clockInterval = null;
var statusUpdateCallback = null;

// Initialize clock
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
  
  // Update immediately
  updateClock();
  
  // Update every second
  if (clockInterval) {
    clearInterval(clockInterval);
  }
  clockInterval = setInterval(updateClock, 1000);
}

// Update status indicator
function updateStatusIndicator(state, text) {
  var statusDot = document.getElementById('statusDot');
  var statusText = document.getElementById('statusText');
  
  if (!statusDot || !statusText) {
    return;
  }
  
  // Remove all color classes
  statusDot.classList.remove('bg-green-500', 'bg-yellow-500', 'bg-red-500', 'bg-gray-400');
  
  // Set color and text based on state
  switch (state) {
    case 'connected':
      statusDot.classList.add('bg-green-500');
      statusText.textContent = text || 'Connected';
      break;
    case 'connecting':
    case 'reconnecting':
      statusDot.classList.add('bg-yellow-500');
      statusText.textContent = text || 'Connecting...';
      break;
    case 'disconnected':
    case 'error':
      statusDot.classList.add('bg-red-500');
      statusText.textContent = text || 'Disconnected';
      break;
    default:
      statusDot.classList.add('bg-gray-400');
      statusText.textContent = text || 'Unknown';
  }
}

// Initialize status indicator
function initStatusIndicator() {
  // Set initial state
  updateStatusIndicator('connecting', 'Connecting...');
  
  // Register callback with WebSocket manager when available
  function registerStatusCallback() {
    if (typeof wsManager !== 'undefined' && wsManager) {
      // Register callback for future status changes
      wsManager.onStatusChange(function(state, text) {
        updateStatusIndicator(state, text);
      });
      
      // Immediately update status based on current connection state
      // This handles the case where connection was established before callback registration
      var currentState = wsManager.getConnectionState();
      var currentText = 'Connecting...';
      
      if (currentState === 'connected' && wsManager.isConnected) {
        currentText = 'Connected';
      } else if (currentState === 'connecting') {
        currentText = 'Connecting...';
      } else if (currentState === 'disconnected') {
        currentText = 'Disconnected';
      } else if (currentState === 'disconnecting') {
        currentText = 'Disconnecting...';
      }
      
      updateStatusIndicator(currentState, currentText);
      return true;
    }
    return false;
  }
  
  if (!registerStatusCallback()) {
    // Wait for WebSocket manager to be available
    var checkInterval = setInterval(function() {
      if (registerStatusCallback()) {
        clearInterval(checkInterval);
      }
    }, 100);
    
    // Stop checking after 5 seconds to avoid infinite loop
    setTimeout(function() {
      clearInterval(checkInterval);
    }, 5000);
  }
}

// Create and manage WebSocket tooltip
function createWebSocketTooltip() {
  // Create tooltip element
  const tooltip = document.createElement('div');
  tooltip.id = 'wsTooltip';
  tooltip.className = 'fixed z-50 px-3 py-2 bg-gray-900 text-white text-xs rounded shadow-lg pointer-events-none opacity-0 transition-opacity duration-200';
  tooltip.style.display = 'none';
  tooltip.style.minWidth = '200px';
  document.body.appendChild(tooltip);
  
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
      <div class="font-semibold mb-2 text-green-400 border-b border-gray-700 pb-1">WebSocket Connection</div>
      <div class="space-y-1">
        <div class="flex justify-between">
          <span class="text-gray-400">Duration:</span>
          <span class="text-green-400 font-medium">${info.duration}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-gray-400">Last Heartbeat:</span>
          <span class="text-blue-400 font-medium">${info.lastHeartbeat}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-gray-400">Messages:</span>
          <span class="text-yellow-400 font-medium">${info.messages}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-gray-400">Reconnects:</span>
          <span class="text-orange-400 font-medium">${info.reconnects}</span>
        </div>
        <div class="mt-2 pt-2 border-t border-gray-700">
          <div class="text-gray-400 text-xs">${info.protocol}</div>
          <div class="text-gray-500 text-xs mt-1 break-all">${info.url}</div>
        </div>
      </div>
    `;
  }
  
  function showTooltip(e) {
    if (!wsManager || !wsManager.isConnected) {
      return;
    }
    
    updateTooltipContent();
    const rect = statusEl.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    
    // Position tooltip below the status element, centered
    let left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);
    let top = rect.bottom + 8;
    
    // Adjust if tooltip would go off screen
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
    
    // Update tooltip content every second while visible
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
  
  // Also hide tooltip when status changes to disconnected
  if (typeof wsManager !== 'undefined' && wsManager) {
    wsManager.onStatusChange(function(state, text) {
      if (state !== 'connected') {
        hideTooltip();
      }
    });
  } else {
    // Wait for WebSocket manager to be available
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

// Initialize all header components
function initHeader() {
  initClock();
  initStatusIndicator();
  createWebSocketTooltip();
}

// Cleanup on page unload
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', function() {
    if (clockInterval) {
      clearInterval(clockInterval);
    }
  });
}
