// Header components: Clock and Backend Status Indicator
"use strict";

// =========================================================================
//  Global Variables
// =========================================================================

var clockInterval = null;
var wsTooltipRefreshContent = null;
var wsTooltipElement = null;

function headerStatusHasProblem() {
  var health = aggregateServerHealth(serversCache);
  return !wsManager || wsManager.state !== 'connected' || health.down > 0 || health.degraded > 0 || health.busy > 0;
}

function openHeaderServerProblems() {
  if (hasAccess('admin') && headerStatusHasProblem()) {
    openServerManager();
  }
}

function renderHeaderServerProblems() {
  if (!hasAccess('admin')) return '';
  return serversCache.filter(function(server) {
    return server.enabled && server.health && ['down', 'degraded', 'busy'].indexOf(server.health.state) !== -1;
  }).map(function(server) {
    var badge = serverHealthBadge(server.health);
    var reason = server.health.error || '';
    if (serverHasSSHHostKeyError(server)) {
      badge.label = t('servers.health.state.connection_blocked', 'Connection blocked');
      reason = t('servers.card.host_key_error', 'SSH host key changed') + '. '
        + t('servers.card.host_key_blocked', 'Connection blocked. Verify the new fingerprint on the server before accepting it.');
    } else if (server.health.state === 'busy') {
      reason = t('operations.health_busy', 'Fail2Ban is applying a change. Status updates will resume when it finishes.');
    } else if (!reason && server.health.fail2banOk === false) {
      reason = t('servers.health.fail2ban_down', 'Fail2ban is not responding on this server.');
    } else if (!reason && server.health.callbackOk === false) {
      reason = t('servers.health.callback_down', 'The server cannot reach the callback URL; ban events are not recorded.');
    }
    return '<div class="mt-2 pt-2 border-t border-gray-700">'
      + '<div class="font-semibold">' + escapeHtml(server.name || server.id) + ': ' + escapeHtml(badge.label) + '</div>'
      + (reason ? '<div class="mt-1 break-words">' + escapeHtml(reason) + '</div>' : '') + '</div>';
  }).join('');
}

function getWebSocketStatusText(state) {
  switch (state) {
    case 'connected':
      return t('header.websocket.status.connected', 'Connected');
    case 'connecting':
      return t('header.websocket.status.connecting', 'Connecting...');
    case 'reconnecting':
      return t('header.websocket.status.reconnecting', 'Reconnecting...');
    case 'disconnected':
      return t('header.websocket.status.disconnected', 'Disconnected');
    case 'error':
      return t('header.websocket.status.error', 'Connection error');
    default:
      return t('header.websocket.status.unknown', 'Unknown');
  }
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

// While the WebSocket is up the dot reports server health; otherwise the connection state.
function updateStatusIndicator() {
  var statusDot = document.getElementById('statusDot');
  var statusText = document.getElementById('statusText');
  if (!statusDot || !statusText) {
    return;
  }
  var state = wsManager ? wsManager.state : 'connecting';
  var dotClass = 'bg-gray-400';
  var label = getWebSocketStatusText(state);
  if (state === 'connected') {
    var health = aggregateServerHealth(serversCache);
    dotClass = 'bg-green-500';
    if (health.down) {
      dotClass = 'bg-red-500';
      label = t('header.health.servers_down', '{count} server(s) down').replace('{count}', String(health.down));
    } else if (health.degraded) {
      dotClass = 'bg-yellow-500';
      label = t('header.health.servers_degraded', '{count} server(s) degraded').replace('{count}', String(health.degraded));
    } else if (health.busy) {
      dotClass = 'bg-yellow-500';
      label = t('header.health.servers_busy', '{count} server(s) busy').replace('{count}', String(health.busy));
    }
  } else if (state === 'connecting' || state === 'reconnecting') {
    dotClass = 'bg-yellow-500';
  } else if (state === 'disconnected' || state === 'error') {
    dotClass = 'bg-red-500';
  }
  statusDot.classList.remove('bg-green-500', 'bg-yellow-500', 'bg-red-500', 'bg-gray-400');
  statusDot.classList.add(dotClass);
  statusText.textContent = label;
  var statusEl = document.getElementById('backendStatus');
  if (statusEl) {
    var actionable = hasAccess('admin') && headerStatusHasProblem();
    statusEl.setAttribute('role', actionable ? 'button' : 'status');
    statusEl.tabIndex = actionable ? 0 : -1;
    statusEl.classList.toggle('cursor-pointer', actionable);
  }
}

function refreshHeaderTranslations() {
  updateStatusIndicator();
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
  let tooltipUpdateInterval = null;
  function updateTooltipContent() {
    const info = wsManager && wsManager.getConnectionInfo();
    if (!info) {
      tooltip.innerHTML = '<div>' + escapeHtml(getWebSocketStatusText(wsManager ? wsManager.state : 'connecting')) + '</div>' + renderHeaderServerProblems();
      return;
    }
    const protocol = info.secure
      ? t('header.websocket.tooltip.protocol_wss_secure', 'WSS (Secure)')
      : t('header.websocket.tooltip.protocol_ws', 'WS');
    tooltip.innerHTML = `
      <div class="font-semibold mb-2 text-green-400 border-b border-gray-700 pb-1">${escapeHtml(t('header.websocket.tooltip.title', 'WebSocket Connection'))}</div>
      <div class="space-y-1">
        <div class="flex justify-between">
          <span class="text-gray-400">${escapeHtml(t('header.websocket.tooltip.duration', 'Duration:'))}</span>
          <span class="text-green-400 font-medium">${escapeHtml(info.duration)}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-gray-400">${escapeHtml(t('header.websocket.tooltip.last_heartbeat', 'Last Heartbeat:'))}</span>
          <span class="text-blue-400 font-medium">${escapeHtml(info.lastHeartbeat)}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-gray-400">${escapeHtml(t('header.websocket.tooltip.messages', 'Messages:'))}</span>
          <span class="text-yellow-400 font-medium">${info.messages}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-gray-400">${escapeHtml(t('header.websocket.tooltip.reconnects', 'Reconnects:'))}</span>
          <span class="text-orange-400 font-medium">${info.reconnects}</span>
        </div>
        <div class="mt-2 pt-2 border-t border-gray-700">
          <div class="text-gray-400 text-xs">${escapeHtml(protocol)}</div>
          <div class="text-gray-500 text-xs mt-1 break-all">${escapeHtml(info.url)}</div>
        </div>
      </div>
    ` + renderHeaderServerProblems();
  }
  wsTooltipRefreshContent = updateTooltipContent;
  function showTooltip() {
    updateTooltipContent();
    tooltip.style.display = 'block';
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
  if (statusEl) {
    statusEl.addEventListener('mouseenter', showTooltip);
    statusEl.addEventListener('mouseleave', hideTooltip);
    statusEl.addEventListener('focus', showTooltip);
    statusEl.addEventListener('blur', hideTooltip);
    statusEl.addEventListener('click', function() {
      hideTooltip();
      openHeaderServerProblems();
    });
    statusEl.addEventListener('keydown', function(event) {
      if (hasAccess('admin') && headerStatusHasProblem() && (event.key === 'Enter' || event.key === ' ')) {
        event.preventDefault();
        hideTooltip();
        openHeaderServerProblems();
      }
    });
  }
  return hideTooltip;
}

// =========================================================================
//  Initialization
// =========================================================================

function initHeader() {
  initClock();
  var hideTooltip = createWebSocketTooltip();
  wsManager.on('status', function(state) {
    updateStatusIndicator();
    if (state !== 'connected') {
      hideTooltip();
    }
  });
  updateStatusIndicator();
}

if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', function() {
    if (clockInterval) {
      clearInterval(clockInterval);
    }
  });
}
