// Console output handler (websocket log stream and rendering).
"use strict";

// =========================================================================
//  Global Variables
// =========================================================================

let consoleOutputElement = null;
const maxConsoleLines = 1000;
let wasConsoleEnabledOnLoad = false;

// =========================================================================
//  Initialization
// =========================================================================

// Initialize the console output container and connect to the websocket
function initConsoleOutput() {
  consoleOutputElement = document.getElementById('consoleOutputWindow');
  wsManager.on('console_log', function(message) {
    appendConsoleLog(message.message, message.time);
  });
}

function removeConsolePlaceholder() {
  const placeholder = document.getElementById('consolePlaceholder');
  if (placeholder) {
    placeholder.remove();
  }
}

// Toggle the console output container
function toggleConsoleOutput(userClicked) {
  const checkbox = document.getElementById('consoleOutput');
  const container = document.getElementById('consoleOutputContainer');

  if (!checkbox || !container) {
    return;
  }
  container.classList.toggle('hidden', !checkbox.checked);
  if (!checkbox.checked || !consoleOutputElement) {
    return;
  }
  // Remove placeholder if it exists
  removeConsolePlaceholder();
  // Logs only stream after the setting is saved, so say so when it was just switched on.
  if (userClicked && !wasConsoleEnabledOnLoad && !document.getElementById('consoleSaveHint')) {
    const hintDiv = document.createElement('div');
    hintDiv.className = 'text-yellow-400 italic text-center py-4';
    hintDiv.id = 'consoleSaveHint';
    hintDiv.textContent = t('settings.console.save_hint', 'Please save your settings first before logs will be displayed here.');
    consoleOutputElement.appendChild(hintDiv);
  }
}

// =========================================================================
//  Log Rendering / Core Functionality
// =========================================================================

function appendConsoleLog(message, timestamp) {
  if (!consoleOutputElement) {
    return;
  }
  // Remove placeholder if it exists
  removeConsolePlaceholder();
  // Remove save hint if it exists
  const saveHint = document.getElementById('consoleSaveHint');
  if (saveHint) {
    saveHint.remove();
  }
  // Create new log line element with timestamp
  const logLine = document.createElement('div');
  let timeStr = '';
  if (timestamp) {
    const date = new Date(timestamp);
    if (!isNaN(date.getTime())) {
      timeStr = '<span class="text-gray-500">[' + escapeHtml(date.toLocaleTimeString()) + ']</span> ';
    }
  }

  // Set different colors for different log levels using patterns below.
  // Default is green.
  let logClass = 'text-green-400';
  var isConfigDump = /SSH command output\b/.test(message) && /Fail2Ban-UI Managed Configuration|jail\.local|action_mwlg/.test(message);
  if (!isConfigDump) {
    if (/\b(?:error|fatal)\s*:/i.test(message) || /\bfailed\s+to\b/i.test(message)) {
      logClass = 'text-red-400';
    } else if (/\b(?:warning|warn)\s*:/i.test(message)) {
      logClass = 'text-yellow-400';
    } else if (/\b(?:info|debug)\s*:/i.test(message) || /\bsuccessfully\b/i.test(message)) {
      logClass = 'text-blue-400';
    }
  }
  logLine.className = logClass + ' leading-relaxed';
  // Build complete log line with timestamp and message
  // Escape message to prevent XSS (core.js always loads before this file)
  logLine.innerHTML = timeStr + escapeHtml(message);
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
  if (consoleOutputElement) {
    consoleOutputElement.textContent = '';
  }
}
