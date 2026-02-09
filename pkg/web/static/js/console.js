// Console Output Handler for Fail2ban UI
"use strict";

let consoleOutputContainer = null;
let consoleOutputElement = null;
let maxConsoleLines = 1000; // Maximum number of lines to keep in console
let wasConsoleEnabledOnLoad = false; // Track if console was enabled when page loaded

function initConsoleOutput() {
  consoleOutputContainer = document.getElementById('consoleOutputContainer');
  consoleOutputElement = document.getElementById('consoleOutputWindow');
  
  if (!consoleOutputContainer || !consoleOutputElement) {
    return;
  }

  // Register WebSocket callback for console logs
  if (typeof wsManager !== 'undefined' && wsManager) {
    wsManager.onConsoleLog(function(message, timestamp) {
      appendConsoleLog(message, timestamp);
    });
  } else {
    // Wait for WebSocket manager to be available
    const wsCheckInterval = setInterval(function() {
      if (typeof wsManager !== 'undefined' && wsManager) {
        wsManager.onConsoleLog(function(message, timestamp) {
          appendConsoleLog(message, timestamp);
        });
        clearInterval(wsCheckInterval);
      }
    }, 100);
    
    // Stop checking after 5 seconds
    setTimeout(function() {
      clearInterval(wsCheckInterval);
    }, 5000);
  }
}

function toggleConsoleOutput(userClicked) {
  const checkbox = document.getElementById('consoleOutput');
  const container = document.getElementById('consoleOutputContainer');
  
  if (!checkbox || !container) {
    return;
  }
  
  if (checkbox.checked) {
    container.classList.remove('hidden');
    // Initialize console if not already done
    if (!consoleOutputElement) {
      initConsoleOutput();
    } else {
      // Re-register WebSocket callback in case it wasn't registered before
      if (typeof wsManager !== 'undefined' && wsManager) {
        // Remove any existing callbacks and re-register
        if (!wsManager.consoleLogCallbacks) {
          wsManager.consoleLogCallbacks = [];
        }
        // Check if callback already exists
        let callbackExists = false;
        for (let i = 0; i < wsManager.consoleLogCallbacks.length; i++) {
          if (wsManager.consoleLogCallbacks[i].toString().includes('appendConsoleLog')) {
            callbackExists = true;
            break;
          }
        }
        if (!callbackExists) {
          wsManager.onConsoleLog(function(message, timestamp) {
            appendConsoleLog(message, timestamp);
          });
        }
      }
    }
    
    // Show save hint only if user just clicked to enable (not on page load)
    const consoleEl = document.getElementById('consoleOutputWindow');
    if (consoleEl && userClicked && !wasConsoleEnabledOnLoad) {
      // Clear initial placeholder message
      const placeholder = consoleEl.querySelector('.text-gray-500');
      if (placeholder && placeholder.textContent === 'Console output will appear here...') {
        placeholder.remove();
      }
      
      // Show save hint message
      const hintDiv = document.createElement('div');
      hintDiv.className = 'text-yellow-400 italic text-center py-4';
      hintDiv.id = 'consoleSaveHint';
      const hintText = typeof t !== 'undefined' ? t('settings.console.save_hint', 'Please save your settings first before logs will be displayed here.') : 'Please save your settings first before logs will be displayed here.';
      hintDiv.textContent = hintText;
      consoleEl.appendChild(hintDiv);
    } else if (consoleEl) {
      // Just clear initial placeholder if it exists
      const placeholder = consoleEl.querySelector('.text-gray-500');
      if (placeholder && placeholder.textContent === 'Console output will appear here...') {
        placeholder.remove();
      }
    }
  } else {
    container.classList.add('hidden');
  }
}

function appendConsoleLog(message, timestamp) {
  if (!consoleOutputElement) {
    consoleOutputElement = document.getElementById('consoleOutputWindow');
  }
  
  if (!consoleOutputElement) {
    return;
  }
  
  // Remove initial placeholder message
  const placeholder = consoleOutputElement.querySelector('.text-gray-500');
  if (placeholder && placeholder.textContent === 'Console output will appear here...') {
    placeholder.remove();
  }
  
  // Remove save hint when first log arrives
  const saveHint = document.getElementById('consoleSaveHint');
  if (saveHint) {
    saveHint.remove();
  }
  
  // Create log line
  const logLine = document.createElement('div');
  logLine.className = 'text-green-400 leading-relaxed';
  
  // Format timestamp if provided
  let timeStr = '';
  if (timestamp) {
    try {
      const date = new Date(timestamp);
      timeStr = '<span class="text-gray-500">[' + date.toLocaleTimeString() + ']</span> ';
    } catch (e) {
      // Ignore timestamp parsing errors
    }
  }
  
  // Escape HTML to prevent XSS (but preserve timestamp HTML)
  let escapedMessage = message;
  if (typeof escapeHtml === 'function') {
    escapedMessage = escapeHtml(escapedMessage);
  } else {
    // Fallback HTML escaping
    escapedMessage = escapedMessage
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
  
  // Color code different log levels using precise patterns to avoid
  // false positives from SSH flags (e.g. "-o LogLevel=ERROR") or
  // substrings like "stderr".
  let logClass = 'text-green-400';
  if (/❌/.test(message) || /\b(?:error|fatal)\s*:/i.test(message) || /\bfailed\s+to\b/i.test(message)) {
    logClass = 'text-red-400';
  } else if (/⚠️/.test(message) || /\b(?:warning|warn)\s*:/i.test(message)) {
    logClass = 'text-yellow-400';
  } else if (/✅/.test(message) || /\b(?:info|debug)\s*:/i.test(message) || /\bsuccessfully\b/i.test(message)) {
    logClass = 'text-blue-400';
  }
  
  logLine.className = logClass + ' leading-relaxed';
  logLine.innerHTML = timeStr + escapedMessage;
  
  // Add to console
  consoleOutputElement.appendChild(logLine);
  
  // Limit number of lines
  const lines = consoleOutputElement.children;
  if (lines.length > maxConsoleLines) {
    consoleOutputElement.removeChild(lines[0]);
  }
  
  // Auto-scroll to bottom
  consoleOutputElement.scrollTop = consoleOutputElement.scrollHeight;
}

function clearConsole() {
  if (!consoleOutputElement) {
    consoleOutputElement = document.getElementById('consoleOutputWindow');
  }
  
  if (consoleOutputElement) {
    consoleOutputElement.textContent = '';
    // Note: wasConsoleEnabledOnLoad remains true, so hint won't show again after clear
  }
}

// Initialize on page load
if (typeof window !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      // Check if console output is already enabled on page load
      const checkbox = document.getElementById('consoleOutput');
      if (checkbox && checkbox.checked) {
        wasConsoleEnabledOnLoad = true; // Mark that it was enabled on load
        toggleConsoleOutput(false); // false = not a user click
      }
      initConsoleOutput();
    });
  } else {
    // Check if console output is already enabled on page load
    const checkbox = document.getElementById('consoleOutput');
    if (checkbox && checkbox.checked) {
      wasConsoleEnabledOnLoad = true; // Mark that it was enabled on load
      toggleConsoleOutput(false); // false = not a user click
    }
    initConsoleOutput();
  }
}
