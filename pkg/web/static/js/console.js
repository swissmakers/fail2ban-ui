// Console output handler (websocket log stream and rendering).
"use strict";

// =========================================================================
//  Global Variables
// =========================================================================

let consoleOutputContainer = null;
let consoleOutputElement = null;
let maxConsoleLines = 1000;
let wasConsoleEnabledOnLoad = false;

// =========================================================================
//  Initialization
// =========================================================================

// Initialize the console output container and connect to the websocket
function initConsoleOutput() {
  consoleOutputContainer = document.getElementById('consoleOutputContainer');
  consoleOutputElement = document.getElementById('consoleOutputWindow');

  if (!consoleOutputContainer || !consoleOutputElement) {
    return;
  }
  if (typeof wsManager !== 'undefined' && wsManager) {
    wsManager.onConsoleLog(function(message, timestamp) {
      appendConsoleLog(message, timestamp);
    });
  } else {
    // Wait for websocket manager to be available
    const wsCheckInterval = setInterval(function() {
      if (typeof wsManager !== 'undefined' && wsManager) {
        wsManager.onConsoleLog(function(message, timestamp) {
          appendConsoleLog(message, timestamp);
        });
        clearInterval(wsCheckInterval);
      }
    }, 100);
    // Timeout after 5 seconds if websocket manager is not available
    setTimeout(function() {
      clearInterval(wsCheckInterval);
    }, 5000);
  }
}

// Toggle the console output container
function toggleConsoleOutput(userClicked) {
  const checkbox = document.getElementById('consoleOutput');
  const container = document.getElementById('consoleOutputContainer');

  if (!checkbox || !container) {
    return;
  }

  if (checkbox.checked) {
    // Show the console output container
    container.classList.remove('hidden');
    if (!consoleOutputElement) {
      initConsoleOutput();
    } else {
      if (typeof wsManager !== 'undefined' && wsManager) {
        if (!wsManager.consoleLogCallbacks) {
          wsManager.consoleLogCallbacks = [];
        }
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

    const consoleEl = document.getElementById('consoleOutputWindow');
   // Show save hint only if user just clicked to enable (not on page load)
    if (consoleEl && userClicked && !wasConsoleEnabledOnLoad) {
      const placeholder = consoleEl.querySelector('.text-gray-500');
      if (placeholder && placeholder.textContent === 'Console output will appear here...') {
        placeholder.remove();
      }
      const hintDiv = document.createElement('div');
      hintDiv.className = 'text-yellow-400 italic text-center py-4';
      hintDiv.id = 'consoleSaveHint';
      const hintText = typeof t !== 'undefined' ? t('settings.console.save_hint', 'Please save your settings first before logs will be displayed here.') : 'Please save your settings first before logs will be displayed here.';
      hintDiv.textContent = hintText;
      consoleEl.appendChild(hintDiv);
    } else if (consoleEl) {
      const placeholder = consoleEl.querySelector('.text-gray-500');
      // Remove placeholder if it exists
      if (placeholder && placeholder.textContent === 'Console output will appear here...') {
        placeholder.remove();
      }
    }
  } else {
    // Hide the console output container
    container.classList.add('hidden');
  }
}

// Auto-start console if enabled on load
if (typeof window !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      const checkbox = document.getElementById('consoleOutput');
      if (checkbox && checkbox.checked) {
        wasConsoleEnabledOnLoad = true;
        toggleConsoleOutput(false);
      }
      initConsoleOutput();
    });
  } else {
    const checkbox = document.getElementById('consoleOutput');
    if (checkbox && checkbox.checked) {
      wasConsoleEnabledOnLoad = true;
      toggleConsoleOutput(false);
    }
    initConsoleOutput();
  }
}

// =========================================================================
//  Log Rendering / Core Functionality
// =========================================================================

function appendConsoleLog(message, timestamp) {
  if (!consoleOutputElement) {
    consoleOutputElement = document.getElementById('consoleOutputWindow');
  }
  if (!consoleOutputElement) {
    return;
  }
  // Remove placeholder if it exists
  const placeholder = consoleOutputElement.querySelector('.text-gray-500');
  if (placeholder && placeholder.textContent === 'Console output will appear here...') {
    placeholder.remove();
  }
  // Remove save hint if it exists
  const saveHint = document.getElementById('consoleSaveHint');
  if (saveHint) {
    saveHint.remove();
  }
  // Create new log line element with timestamp
  const logLine = document.createElement('div');
  logLine.className = 'text-green-400 leading-relaxed';
  let timeStr = '';
  if (timestamp) {
    try {
      const date = new Date(timestamp);
      timeStr = '<span class="text-gray-500">[' + date.toLocaleTimeString() + ']</span> ';
    } catch (e) {}
  }

  // Escape message to prevent XSS
  let escapedMessage = message;
  if (typeof escapeHtml === 'function') {
    escapedMessage = escapeHtml(escapedMessage);
  } else {
    escapedMessage = escapedMessage
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
  
  // Set different colors for different log levels using patterns below.
  // Default is green.
  let logClass = 'text-green-400';
  var isConfigDump = /SSH command output\b/.test(message) && /Fail2Ban-UI Managed Configuration|jail\.local|action_mwlg/.test(message);
  if (!isConfigDump) {
    if (/❌/.test(message) || /\b(?:error|fatal)\s*:/i.test(message) || /\bfailed\s+to\b/i.test(message)) {
      logClass = 'text-red-400';
    } else if (/⚠️/.test(message) || /\b(?:warning|warn)\s*:/i.test(message)) {
      logClass = 'text-yellow-400';
    } else if (/✅/.test(message) || /\b(?:info|debug)\s*:/i.test(message) || /\bsuccessfully\b/i.test(message)) {
      logClass = 'text-blue-400';
    }
  }
  logLine.className = logClass + ' leading-relaxed';

  // Build complete log line with timestamp and message
  logLine.innerHTML = timeStr + escapedMessage;
  // Add log line to console
  consoleOutputElement.appendChild(logLine);

  const lines = consoleOutputElement.children;
  if (lines.length > maxConsoleLines) {
    consoleOutputElement.removeChild(lines[0]);
  }
  consoleOutputElement.scrollTop = consoleOutputElement.scrollHeight;
}

// Clear the console
function clearConsole() {
  if (!consoleOutputElement) {
    consoleOutputElement = document.getElementById('consoleOutputWindow');
  }
  if (consoleOutputElement) {
    consoleOutputElement.textContent = '';
  }
}
