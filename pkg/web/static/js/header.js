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
  if (typeof wsManager !== 'undefined' && wsManager) {
    wsManager.onStatusChange(function(state, text) {
      updateStatusIndicator(state, text);
    });
  } else {
    // Wait for WebSocket manager to be available
    var checkInterval = setInterval(function() {
      if (typeof wsManager !== 'undefined' && wsManager) {
        wsManager.onStatusChange(function(state, text) {
          updateStatusIndicator(state, text);
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
}

// Cleanup on page unload
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', function() {
    if (clockInterval) {
      clearInterval(clockInterval);
    }
  });
}
