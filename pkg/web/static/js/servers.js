// Server management javascript functions for Fail2ban UI
"use strict";

// =========================================================================
//  "Selected server persistence" for the browser server-dropdown
// =========================================================================

var SELECTED_SERVER_KEY = 'fail2ban-ui.selectedServerId';

function getStoredServerId() {
  try {
    return window.localStorage.getItem(SELECTED_SERVER_KEY) || null;
  } catch (e) {
    return null;
  }
}

function setStoredServerId(id) {
  try {
    if (id) {
      window.localStorage.setItem(SELECTED_SERVER_KEY, id);
    } else {
      window.localStorage.removeItem(SELECTED_SERVER_KEY);
    }
  } catch (e) {
  }
}

function clearStoredServerId() {
  try {
    window.localStorage.removeItem(SELECTED_SERVER_KEY);
  } catch (e) {
  }
}

// =========================================================================
//  Server data loading
// =========================================================================

var serversLoadPromise = null;

function loadServers() {
  if (serversLoadPromise) return serversLoadPromise;
  serversLoadPromise = fetch(appPath('/api/servers'))
    .then(readJsonResponse)
    .then(function(data) {
      serversCache = (data && data.servers) || [];
      var enabledServers = serversCache.filter(function(s) { return s.enabled; });
      if (!enabledServers.length) {
        currentServerId = null;
        currentServer = null;
      } else {
        var desired = currentServerId;
        if (!desired) {
          var stored = getStoredServerId();
          if (stored) {
            if (enabledServers.some(function(s) { return s.id === stored; })) {
              desired = stored;
            } else {
              clearStoredServerId();
            }
          }
        }
        var selected = desired ? enabledServers.find(function(s) { return s.id === desired; }) : null;
        if (!selected) {
          var def = enabledServers.find(function(s) { return s.isDefault; });
          selected = def || enabledServers[0];
        }
        currentServer = selected;
        currentServerId = selected ? selected.id : null;
      }
      renderServerState();
    })
    .catch(function(err) {
      console.error('Error loading servers:', err);
      // A failed background refresh keeps the last known servers and selection.
      if (serversCache.length) {
        return;
      }
      currentServerId = null;
      currentServer = null;
      renderServerState();
    }).finally(function() { serversLoadPromise = null; });
  return serversLoadPromise;
}

// Reloads the server list and every view that depends on it.
function reloadServerViews() {
  return loadServers().then(function() {
    renderServerManagerList();
    return refreshData({ silent: true });
  });
}

function renderServerState() {
  renderServerSelector();
  renderServerSubtitle();
  updateRestartBanner();
  updateStatusIndicator();
  if (typeof renderOperations === 'function') renderOperations();
}

function isServerManagerOpen() {
  var modal = document.getElementById('serverManagerModal');
  return !!modal && !modal.classList.contains('hidden');
}

// =========================================================================
//  Server health
// =========================================================================

var SERVER_HEALTH_STYLES = {
  ok: { dotClass: 'bg-green-500', textClass: 'text-green-600', key: 'servers.health.state.ok', fallback: 'Healthy' },
  degraded: { dotClass: 'bg-yellow-500', textClass: 'text-yellow-600', key: 'servers.health.state.degraded', fallback: 'Degraded' },
  busy: { dotClass: 'bg-yellow-500', textClass: 'text-yellow-600', key: 'servers.health.state.busy', fallback: 'Busy applying changes' },
  down: { dotClass: 'bg-red-500', textClass: 'text-red-600', key: 'servers.health.state.down', fallback: 'Down' },
  unknown: { dotClass: 'bg-gray-400', textClass: 'text-gray-500', key: 'servers.health.state.unknown', fallback: 'Unknown' }
};
var SERVER_HEALTH_REFRESH_DELAY_MS = 2000;
var serverHealthRefreshTimer = null;

// Display attributes for a health object; null when the server reports none (disabled).
function serverHealthBadge(health) {
  if (!health) {
    return null;
  }
  var state = Object.prototype.hasOwnProperty.call(SERVER_HEALTH_STYLES, health.state) ? health.state : 'unknown';
  var style = SERVER_HEALTH_STYLES[state];
  return { state: state, dotClass: style.dotClass, textClass: style.textClass, label: t(style.key, style.fallback) };
}

// Worst state over enabled servers; unknown only when none has been checked yet.
function aggregateServerHealth(servers) {
  var result = { state: 'unknown', down: 0, degraded: 0, busy: 0 };
  var checked = 0;
  (servers || []).forEach(function(server) {
    if (!server || !server.enabled || !server.health) {
      return;
    }
    var state = server.health.state;
    if (state === 'down') {
      result.down++;
    } else if (state === 'degraded') {
      result.degraded++;
    } else if (state === 'busy') {
      result.busy++;
    } else if (state !== 'ok') {
      return;
    }
    checked++;
  });
  if (result.down) {
    result.state = 'down';
  } else if (result.degraded) {
    result.state = 'degraded';
  } else if (result.busy) {
    result.state = 'busy';
  } else if (checked) {
    result.state = 'ok';
  }
  return result;
}

// Patches a server_health WS message into the cached list; returns the server or null.
function applyServerHealthUpdate(servers, msg) {
  if (!msg || !msg.serverId) {
    return null;
  }
  var server = (servers || []).find(function(s) { return s && s.id === msg.serverId; });
  if (!server) {
    return null;
  }
  server.health = Object.assign({}, server.health, { state: msg.state, checkedAt: msg.checkedAt });
  return server;
}

function serverHealthDot(badge) {
  if (!badge) {
    return '';
  }
  return '<span class="inline-block w-2 h-2 rounded-full flex-shrink-0 ' + badge.dotClass + '"'
    + ' title="' + escapeHtml(badge.label) + '" aria-label="' + escapeHtml(badge.label) + '"></span>';
}

function handleServerHealthMessage(msg) {
  if (!applyServerHealthUpdate(serversCache, msg)) {
    return;
  }
  renderServerState();
  if (isServerManagerOpen()) {
    renderServerManagerList();
  }
  // Only admins get the detail fields (errors, sync state) the message does not carry.
  if (hasAccess('admin')) {
    clearTimeout(serverHealthRefreshTimer);
    serverHealthRefreshTimer = setTimeout(refreshServerHealth, SERVER_HEALTH_REFRESH_DELAY_MS);
  }
}

function refreshServerHealth() {
  return loadServers().then(function() {
    if (isServerManagerOpen()) {
      renderServerManagerList();
    }
  });
}

// =========================================================================
//  Views rendering
// =========================================================================

function renderServerSelector() {
  var container = document.getElementById('serverSelectorContainer');
  if (!container) return;
  var enabledServers = sortServersForDisplay(serversCache.filter(function(s) { return s.enabled; }));
  if (!enabledServers.length) {
    container.innerHTML = '<div class="text-sm text-red-500" data-i18n="servers.selector.empty">No servers configured</div>';
    updateTranslations();
    return;
  }

  var options = enabledServers.map(function(server) {
    var label = server.name || server.id;
    if (server.type) {
      label += ' (' + server.type.toUpperCase() + ')';
    }
    var badge = serverHealthBadge(server.health);
    if (badge && (badge.state === 'down' || badge.state === 'degraded')) {
      label += ' - ' + badge.label;
    }
    return '<option value="' + escapeHtml(server.id) + '">' + escapeHtml(label) + '</option>';
  }).join('');

  container.innerHTML = ''
    + '<div class="flex flex-col">'
    + '  <label for="serverSelect" class="text-xs text-gray-500 mb-1" data-i18n="servers.selector.label">Active Server</label>'
    + '  <div class="flex items-center gap-2">'
    + '    <select id="serverSelect" class="border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">'
    +        options
    + '    </select>'
    + '  </div>'
    + '</div>';

  var select = document.getElementById('serverSelect');
  if (select) {
    select.value = currentServerId || '';
    select.addEventListener('change', function(e) {
      setCurrentServer(e.target.value);
    });
  }
  updateTranslations();
}

function renderServerSubtitle() {
  var subtitle = document.getElementById('currentServerSubtitle');
  if (!subtitle) return;
  if (!currentServer) {
    subtitle.textContent = t('servers.selector.none', 'No server configured. Please add a Fail2ban server.');
    subtitle.classList.add('text-red-500');
    return;
  }
  subtitle.classList.remove('text-red-500');
  var parts = [];
  parts.push(currentServer.name || currentServer.id);
  parts.push(currentServer.type ? currentServer.type.toUpperCase() : 'LOCAL');
  if (currentServer.host) {
    var host = currentServer.host;
    if (currentServer.port) {
      host += ':' + currentServer.port;
    }
    parts.push(host);
  } else if (currentServer.hostname) {
    parts.push(currentServer.hostname);
  }
  subtitle.textContent = parts.join(' - ');
}

function serverHasSSHHostKeyError(server) {
  if (!server) return false;
  var health = server.health || {};
  if (server.hostKeyError || isSSHHostKeyError(health.error) || isSSHHostKeyError(server.disabledReason)) return true;
  var sync = server.configSync;
  if (!sync || !sync.pending || !isSSHHostKeyError(sync.error)) return false;
  // A failed sync keeps its last error while retrying. A newer successful SSH
  // check proves that accepting the key has already restored the connection.
  var connectionRecovered = (health.transportOk === true || health.fail2banOk === true)
    && Date.parse(health.checkedAt) > Date.parse(sync.lastAttempt);
  return !connectionRecovered;
}

// Keep the actionable cause visible and the full SSH output available on demand.
function renderServerHostKeyDetails(server, detailsOpen) {
  var html = '<div class="mt-2 text-xs text-red-600">'
    + '<p class="font-semibold">' + escapeHtml(t('servers.card.host_key_error', 'SSH host key changed')) + '</p>'
    + '<p class="mt-1">' + escapeHtml(t('servers.card.host_key_blocked', 'Connection blocked. Verify the new fingerprint on the server before accepting it.')) + '</p>';
  if (server.hostKeyFingerprint) {
    html += '<p class="mt-2 text-gray-500">' + escapeHtml(t('servers.card.host_key_fingerprint', 'New fingerprint')) + '</p>'
      + '<code class="block mt-1 px-2 py-1 bg-red-50 rounded select-all break-all">' + escapeHtml(server.hostKeyFingerprint) + '</code>';
  }
  var diagnostic = server.health && server.health.error
    || server.configSync && server.configSync.error
    || server.disabledReason
    || typeof server.hostKeyError === 'string' && server.hostKeyError;
  if (diagnostic) {
    html += '<details class="mt-2 min-w-0 text-gray-500" data-server-diagnostics="' + escapeHtml(server.id || '') + '"' + (detailsOpen ? ' open' : '') + '>'
      + '<summary class="cursor-pointer">' + escapeHtml(t('servers.card.connection_details', 'Connection details')) + '</summary>'
      + '<pre class="mt-2 max-h-40 max-w-full overflow-y-auto whitespace-pre-wrap break-all text-xs">' + escapeHtml(diagnostic) + '</pre>'
      + '</details>';
  }
  return html + '</div>';
}

// Status and connection details for the server manager card.
function renderServerHealthDetails(server, detailsOpen) {
  var html = '';
  var health = server.health;
  var hostKeyBlocked = serverHasSSHHostKeyError(server);
  var badge = serverHealthBadge(health);
  if (badge) {
    if (hostKeyBlocked) {
      badge = { dotClass: 'bg-red-500', textClass: 'text-red-600', label: t('servers.health.state.connection_blocked', 'Connection blocked') };
    }
    var checked = formatDateTime(health.checkedAt);
    html += '<p class="mt-1 text-xs flex flex-wrap items-center gap-2">' + serverHealthDot(badge)
      + '<span class="font-semibold ' + badge.textClass + '">' + escapeHtml(badge.label) + '</span>'
      + (checked ? '<span class="text-gray-500">' + escapeHtml(t('servers.health.checked_at', 'Last checked')) + ': ' + escapeHtml(checked) + '</span>' : '')
      + '</p>';
    if (health.error && !hostKeyBlocked) {
      html += '<p class="mt-1 text-xs text-red-600 break-words">' + escapeHtml(health.error) + '</p>';
    }
    if (health.fail2banOk === false && health.state !== 'busy' && !hostKeyBlocked) {
      html += '<p class="mt-1 text-xs text-red-600">' + escapeHtml(t('servers.health.fail2ban_down', 'Fail2ban is not responding on this server.')) + '</p>';
    }
    if (health.callbackOk === false && !hostKeyBlocked) {
      html += '<p class="mt-1 text-xs text-yellow-600">' + escapeHtml(t('servers.health.callback_down', 'The server cannot reach the callback URL; ban events are not recorded.')) + '</p>';
    }
  }
  if (hostKeyBlocked) {
    html += renderServerHostKeyDetails(server, detailsOpen);
  }
  var sync = server.configSync;
  if (sync && sync.pending && !hostKeyBlocked) {
    var syncError = isSSHHostKeyError(sync.error) ? '' : sync.error;
    html += '<p class="mt-1 text-xs text-yellow-600 break-words">'
      + escapeHtml(t('servers.card.sync_pending', 'Configuration pending; automatic retry enabled'))
      + (syncError ? ': ' + escapeHtml(syncError) : '') + '</p>';
  }
  var applied = sync ? formatDateTime(sync.lastApplied) : '';
  if (applied) {
    html += '<p class="mt-1 text-xs text-gray-500">' + escapeHtml(t('servers.health.last_applied', 'Configuration last applied')) + ': ' + escapeHtml(applied) + '</p>';
  }
  return html;
}

function renderServerManagerList() {
  var list = document.getElementById('serverManagerList');
  var emptyState = document.getElementById('serverManagerListEmpty');
  if (!list || !emptyState) return;

  // Move the existing form out before replacing cards so unsaved values survive.
  var editor = document.getElementById('serverManagerEditor');
  var home = document.getElementById('serverManagerEditorHome');
  var editorFocus = editor ? captureFocusState(editor) : null;
  var editorScroll = captureServerManagerScroll();
  if (editor && home && editor.parentNode !== home) home.appendChild(editor);
  var editingId = document.getElementById('serverId');
  if (editingId && editingId.value && !serversCache.some(function(server) { return server.id === editingId.value; })) {
    showServerManagerInfoView();
    editorFocus = null;
  }

  if (!serversCache.length) {
    list.innerHTML = '';
    emptyState.classList.remove('hidden');
    positionServerManagerEditor(editorFocus, editorScroll);
    updateTranslations();
    return;
  }

  emptyState.classList.add('hidden');

  var expandedDetails = new Set();
  list.querySelectorAll('details[data-server-diagnostics][open]').forEach(function(details) {
    expandedDetails.add(details.getAttribute('data-server-diagnostics'));
  });
  var html = sortServersForDisplay(serversCache).map(function(server) {
    var statusBadge = server.enabled
      ? '<span class="ml-2 text-xs font-semibold text-green-600" data-i18n="servers.badge.enabled">Enabled</span>'
      : '<span class="ml-2 text-xs font-semibold text-gray-500" data-i18n="servers.badge.disabled">Disabled</span>';
    var defaultBadge = server.isDefault
      ? '<span class="ml-2 text-xs font-semibold text-blue-600" data-i18n="servers.badge.default">Default</span>'
      : '';
    var restartBadge = server.restartNeeded
      ? '<span class="ml-2 text-xs font-semibold text-yellow-600" data-i18n="servers.badge.restart_needed">Restart required</span>'
      : '';
    var descriptor = [];
    if (server.type) {
      descriptor.push(server.type.toUpperCase());
    }
    if (server.host) {
      var endpoint = server.host;
      if (server.port) {
        endpoint += ':' + server.port;
      }
      descriptor.push(endpoint);
    } else if (server.hostname) {
      descriptor.push(server.hostname);
    }
    var meta = descriptor.join(' - ');
    var tags = (server.tags || []).length
      ? '<div class="mt-2 text-xs text-gray-500 break-words">' + escapeHtml(server.tags.join(', ')) + '</div>'
      : '';
    var localDetails = '';
    if ((server.type || '').toLowerCase() === 'local') {
      var socketPath = server.socketPath || '/var/run/fail2ban/fail2ban.sock';
      var configPath = server.configPath || '/etc/fail2ban';
      localDetails = ''
        + '<div class="mt-1 text-xs text-gray-500">'
        + escapeHtml(t('servers.card.socket_path', 'Socket path')) + ': '
        + '<code class="px-1 py-0.5 bg-gray-100 rounded break-all">' + escapeHtml(socketPath) + '</code>'
        + '</div>'
        + '<div class="mt-1 text-xs text-gray-500">'
        + escapeHtml(t('servers.card.config_path', 'Configuration path')) + ': '
        + '<code class="px-1 py-0.5 bg-gray-100 rounded break-all">' + escapeHtml(configPath) + '</code>'
        + '</div>';
    }
    return ''
      + '<div class="border border-gray-200 p-4 min-w-0 bg-gray-50">'
      + '  <div class="flex flex-col gap-3 min-w-0">'
      + '    <div class="min-w-0">'
      + '      <p class="font-semibold text-gray-800 flex flex-wrap items-center"><span class="min-w-0 break-all">' + escapeHtml(server.name || server.id) + '</span>' + defaultBadge + statusBadge + restartBadge + '</p>'
      + '      <p class="text-sm text-gray-500 break-all">' + escapeHtml(meta || server.id) + '</p>'
      + '      <p class="mt-1 text-xs text-gray-500">'
      + '<span data-i18n="servers.card.server_id">Server-ID</span>: '
      + '<code class="px-1 py-0.5 bg-gray-100 rounded select-all break-all">' + escapeHtml(server.id || '') + '</code>'
      + '</p>'
      + (!server.enabled && server.disabledReason && !isSSHHostKeyError(server.disabledReason)
        ? '<p class="mt-1 text-xs text-red-600 break-words">'
          + escapeHtml(t('servers.card.disabled_reason', 'Disabled reason')) + ': '
          + escapeHtml(server.disabledReason)
          + '</p>'
        : '')
      +        localDetails
      +        renderServerHealthDetails(server, expandedDetails.has(server.id))
      +        tags
      + '    </div>'
      + '    <div class="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-gray-200 pt-3">'
      + '      <button class="text-sm text-blue-600 hover:text-blue-800" onclick="editServer(\'' + escapeHtml(server.id) + '\')" data-i18n="servers.actions.edit">Edit</button>'
      + '      <button class="text-sm text-blue-600 hover:text-blue-800" onclick="setServerEnabled(\'' + escapeHtml(server.id) + '\',' + (server.enabled ? 'false' : 'true') + ')" data-i18n="' + (server.enabled ? 'servers.actions.disable' : 'servers.actions.enable') + '">' + (server.enabled ? 'Disable' : 'Enable') + '</button>'
      + (server.enabled ? (server.type === 'local'
        ? '<button class="text-sm text-blue-600 hover:text-blue-800" onclick="restartFail2banServer(\'' + escapeHtml(server.id) + '\')" data-i18n="servers.actions.reload" data-i18n-title="servers.actions.reload_tooltip" title="' + escapeHtml(t('servers.actions.reload_tooltip', 'For local connectors, only a configuration reload is possible via the socket connection. The container cannot restart the Fail2ban service using systemctl. To perform a full restart, run \'systemctl restart fail2ban\' directly on the host system.')) + '">Reload Fail2ban</button>'
        : '<button class="text-sm text-blue-600 hover:text-blue-800" onclick="restartFail2banServer(\'' + escapeHtml(server.id) + '\')" data-i18n="servers.actions.restart">Restart Fail2ban</button>') : '')
      + (server.hostKeyError && server.hostKeyFingerprint
        ? '<button class="text-sm font-semibold text-red-600 hover:text-red-800" onclick="acceptHostKey(\'' + escapeHtml(server.id) + '\')" data-i18n="servers.actions.accept_hostkey">Accept new host key</button>'
        : '')
      + '      <button class="text-sm text-blue-600 hover:text-blue-800" onclick="testServerConnection(\'' + escapeHtml(server.id) + '\')" data-i18n="servers.actions.test">Test connection</button>'
      + '    </div>'
      + '  </div>'
      + '</div>'
      + '<div class="min-w-0" data-server-editor-slot="' + escapeHtml(server.id) + '"></div>';
  }).join('');

  list.innerHTML = html;
  positionServerManagerEditor(editorFocus, editorScroll);
  updateTranslations();
}

var serverEditorRevision = 0;
var serverEditorMobileQuery = null;

function captureServerManagerScroll() {
  return ['serverManagerModal', 'serverManagerList'].map(function(id) {
    var element = document.getElementById(id);
    return element && { element: element, top: element.scrollTop, left: element.scrollLeft };
  }).filter(Boolean);
}

function positionServerManagerEditor(savedFocus, savedScroll) {
  var editor = document.getElementById('serverManagerEditor');
  var home = document.getElementById('serverManagerEditorHome');
  if (!editor || !home) return;
  var scroll = savedScroll || captureServerManagerScroll();
  if (!serverEditorMobileQuery && typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
    serverEditorMobileQuery = window.matchMedia('(max-width: 1023px)');
    var onLayoutChange = function() { positionServerManagerEditor(); };
    if (serverEditorMobileQuery.addEventListener) serverEditorMobileQuery.addEventListener('change', onLayoutChange);
    else if (serverEditorMobileQuery.addListener) serverEditorMobileQuery.addListener(onLayoutChange);
  }
  var input = document.getElementById('serverId');
  var editingId = input && input.value;
  var isSaved = !!editingId && serversCache.some(function(server) { return server.id === editingId; });
  var formView = document.getElementById('serverFormView');
  var isEditing = isSaved && formView && !formView.classList.contains('hidden');
  var destination = home;
  if (isEditing && serverEditorMobileQuery && serverEditorMobileQuery.matches) {
    var list = document.getElementById('serverManagerList');
    if (list) {
      var slots = list.querySelectorAll('[data-server-editor-slot]');
      for (var i = 0; i < slots.length; i++) {
        if (slots[i].getAttribute('data-server-editor-slot') === editingId) {
          destination = slots[i];
          break;
        }
      }
    }
  }
  var focus = savedFocus || captureFocusState(editor);
  home.classList.toggle('hidden', destination !== home);
  if (editor.parentNode !== destination) destination.appendChild(editor);
  var deleteButton = document.getElementById('serverDeleteButton');
  if (deleteButton) {
    deleteButton.classList.toggle('hidden', !isEditing);
    deleteButton.disabled = !isEditing;
  }
  if (formView && !formView.classList.contains('hidden')) restoreFocusState(focus);
  scroll.forEach(function(state) {
    state.element.scrollTop = state.top;
    state.element.scrollLeft = state.left;
  });
}

function showServerManagerInfoView() {
  serverEditorRevision++;
  var editingId = document.getElementById('serverId');
  if (editingId) editingId.value = '';
  var info = document.getElementById('serverManagerInfoView');
  var formView = document.getElementById('serverFormView');
  if (info) info.classList.remove('hidden');
  if (formView) formView.classList.add('hidden');
  positionServerManagerEditor();
}

function showServerFormView() {
  var info = document.getElementById('serverManagerInfoView');
  var formView = document.getElementById('serverFormView');
  if (info) info.classList.add('hidden');
  if (formView) formView.classList.remove('hidden');
  positionServerManagerEditor();
}

function setCurrentServer(serverId) {
  if (!serverId) {
    currentServerId = null;
    currentServer = null;
  } else {
    var next = serversCache.find(function(s) { return s.id === serverId && s.enabled; });
    currentServer = next || null;
    currentServerId = currentServer ? currentServer.id : null;
  }
  // We remember the manual choice so it can be autoselected after page reload
  if (currentServerId) {
    setStoredServerId(currentServerId);
  } else {
    clearStoredServerId();
  }
  jailBannedState = {};
  latestSummary = typeof summariesByServer !== 'undefined' && summariesByServer[currentServerId] || null;
  latestSummaryServerId = currentServerId;
  latestSummaryError = latestSummary && latestSummary.staleReason || null;
  latestServerInsights = null;
  renderServerState();
  renderDashboard();
  refreshData({ silent: true });
}

// =========================================================================
//  Server manager form actions
// =========================================================================

function resetServerForm() {
  serverEditorRevision++;
  document.getElementById('serverId').value = '';
  document.getElementById('serverName').value = '';
  document.getElementById('serverType').value = 'local';
  document.getElementById('serverHost').value = '';
  document.getElementById('serverPort').value = '';
  document.getElementById('serverSocket').value = '/var/run/fail2ban/fail2ban.sock';
  document.getElementById('serverConfigPath').value = '';
  document.getElementById('serverHostname').value = '';
  document.getElementById('serverSSHUser').value = '';
  document.getElementById('serverSSHKey').value = '';
  document.getElementById('serverAgentUrl').value = '';
  document.getElementById('serverAgentSecret').value = '';
  document.getElementById('serverTags').value = '';
  document.getElementById('serverDefault').checked = false;
  document.getElementById('serverEnabled').checked = false;
  document.getElementById('serverReverseTunnel').checked = false;
  document.getElementById('serverTunnelPort').value = '';
  onReverseTunnelToggle();
  populateSSHKeySelect(sshKeysCache || [], '');
  onServerTypeChange('local');
  showServerFormView();
}

function editServer(serverId) {
  var server = serversCache.find(function(s) { return s.id === serverId; });
  if (!server) return;
  serverEditorRevision++;
  document.getElementById('serverId').value = server.id || '';
  document.getElementById('serverName').value = server.name || '';
  document.getElementById('serverType').value = server.type || 'local';
  document.getElementById('serverHost').value = server.host || '';
  document.getElementById('serverPort').value = server.port || '';
  document.getElementById('serverSocket').value = server.socketPath || '/var/run/fail2ban/fail2ban.sock';
  document.getElementById('serverConfigPath').value = server.configPath || '/etc/fail2ban';
  document.getElementById('serverHostname').value = server.hostname || '';
  document.getElementById('serverSSHUser').value = server.sshUser || '';
  document.getElementById('serverSSHKey').value = server.sshKeyPath || '';
  document.getElementById('serverAgentUrl').value = server.agentUrl || '';
  document.getElementById('serverAgentSecret').value = server.agentSecret || '';
  document.getElementById('serverTags').value = (server.tags || []).join(',');
  document.getElementById('serverDefault').checked = !!server.isDefault;
  document.getElementById('serverEnabled').checked = !!server.enabled;
  document.getElementById('serverReverseTunnel').checked = !!server.reverseTunnelEnabled;
  document.getElementById('serverTunnelPort').value = server.tunnelPort || '';
  onReverseTunnelToggle();
  onServerTypeChange(server.type || 'local');
  showServerFormView();
  var editor = document.getElementById('serverManagerEditor');
  if (editor && serverEditorMobileQuery && serverEditorMobileQuery.matches && typeof editor.scrollIntoView === 'function') {
    editor.scrollIntoView({ block: 'start' });
  }
}

function onReverseTunnelToggle() {
  var group = document.getElementById('serverTunnelPortGroup');
  if (!group) return;
  if (document.getElementById('serverReverseTunnel').checked) {
    group.classList.remove('hidden');
  } else {
    group.classList.add('hidden');
  }
}

function onServerTypeChange(type) {
  serverEditorRevision++;
  document.querySelectorAll('[data-server-fields]').forEach(function(el) {
    var values = (el.getAttribute('data-server-fields') || '').split(/\s+/);
    if (values.indexOf(type) !== -1) {
      el.classList.remove('hidden');
    } else {
      el.classList.add('hidden');
    }
  });
  var enabledToggle = document.getElementById('serverEnabled');
  if (!enabledToggle) return;
  var isEditing = !!document.getElementById('serverId').value;
  updateLocalConnectorGuidance(type, isEditing);
  if (!isEditing) {
    enabledToggle.checked = type !== 'local';
  }
  if (type === 'ssh') {
    var portInput = document.getElementById('serverPort');
    if (!isEditing && portInput && !portInput.value.trim()) {
      portInput.value = '22';
    }
    var revision = serverEditorRevision;
    var selectedKey = document.getElementById('serverSSHKey').value;
    loadSSHKeys().then(function(keys) {
      if (revision === serverEditorRevision && document.getElementById('serverType').value === 'ssh'
          && document.getElementById('serverSSHKey').value === selectedKey) {
        populateSSHKeySelect(keys, selectedKey);
      }
    });
  } else if (!isEditing && type === 'agent') {
    var sshPortInput = document.getElementById('serverPort');
    if (sshPortInput) {
      sshPortInput.value = '';
    }
  } else if (!isEditing) {
    populateSSHKeySelect([], '');
  }
}

function normalizeAgentUrlInput(raw) {
  var val = (raw || '').trim();
  if (!val) return '';
  if (val.indexOf('://') !== -1) {
    return val;
  }
  try {
    var parsed = new URL('http://' + val);
    if (!parsed.port) {
      parsed.port = '9700';
    }
    return parsed.toString();
  } catch (e) {
    return val;
  }
}

function normalizePathForCompare(value) {
  var trimmed = (value || '').trim();
  if (!trimmed) return '';
  return trimmed.replace(/\/+$/, '') || '/';
}

function normalizeNameForCompare(value) {
  return (value || '').trim().toLowerCase();
}

function getOtherLocalServers(currentId) {
  return (serversCache || []).filter(function(server) {
    return (server.type || '').toLowerCase() === 'local' && server.id !== currentId;
  });
}

function updateLocalConnectorGuidance(type, isEditing) {
  var configPathGroup = document.getElementById('serverConfigPathGroup');
  var configPathInput = document.getElementById('serverConfigPath');
  var currentId = document.getElementById('serverId').value;
  var otherLocalCount = getOtherLocalServers(currentId).length;
  var showConfigPath = type === 'local' && (isEditing || otherLocalCount > 0);

  if (configPathGroup) {
    configPathGroup.classList.toggle('hidden', !showConfigPath);
  }
  if (configPathInput && !showConfigPath && !configPathInput.value.trim()) {
    configPathInput.value = '/etc/fail2ban';
  }
}

function submitServerForm(event) {
  event.preventDefault();
  var editingId = document.getElementById('serverId').value || '';
  var payload = {
    id: editingId || undefined,
    name: document.getElementById('serverName').value.trim(),
    type: document.getElementById('serverType').value,
    host: document.getElementById('serverHost').value.trim(),
    port: document.getElementById('serverPort').value ? parseInt(document.getElementById('serverPort').value, 10) : undefined,
    socketPath: document.getElementById('serverSocket').value.trim(),
    configPath: document.getElementById('serverConfigPath').value.trim(),
    hostname: document.getElementById('serverHostname').value.trim(),
    sshUser: document.getElementById('serverSSHUser').value.trim(),
    sshKeyPath: document.getElementById('serverSSHKey').value.trim(),
    agentUrl: document.getElementById('serverAgentUrl').value.trim(),
    agentSecret: document.getElementById('serverAgentSecret').value.trim(),
    tags: document.getElementById('serverTags').value
      ? document.getElementById('serverTags').value.split(',').map(function(tag) { return tag.trim(); }).filter(Boolean)
      : [],
    enabled: document.getElementById('serverEnabled').checked,
    reverseTunnelEnabled: document.getElementById('serverReverseTunnel').checked,
    tunnelPort: document.getElementById('serverTunnelPort').value ? parseInt(document.getElementById('serverTunnelPort').value, 10) : 0
  };
  if (payload.type === 'ssh' && payload.tunnelPort && (payload.tunnelPort < 1024 || payload.tunnelPort > 65535)) {
    showToast(t('servers.validation.tunnel_port_range', 'Tunnel port must be between 1024 and 65535.'), 'error');
    return;
  }
  var nameKey = normalizeNameForCompare(payload.name);
  if (!nameKey) {
    showToast(t('servers.validation.name_required', 'Server name is required.'), 'error');
    return;
  }
  var duplicateName = (serversCache || []).some(function(server) {
    return server.id !== editingId && normalizeNameForCompare(server.name || '') === nameKey;
  });
  if (duplicateName) {
    showToast(t('servers.validation.duplicate_name', 'A server with this name already exists.'), 'error');
    return;
  }

  if (payload.type === 'local') {
    var socketKey = normalizePathForCompare(payload.socketPath || '/var/run/fail2ban/fail2ban.sock');
    var configKey = normalizePathForCompare(payload.configPath || '/etc/fail2ban');
    var localConflicts = getOtherLocalServers(editingId);
    var socketConflict = localConflicts.some(function(server) {
      return normalizePathForCompare(server.socketPath || '/var/run/fail2ban/fail2ban.sock') === socketKey;
    });
    if (socketConflict) {
      showToast(t('servers.validation.duplicate_socket', 'A local connector with this socket path already exists.'), 'error');
      return;
    }
    var configConflict = localConflicts.some(function(server) {
      return normalizePathForCompare(server.configPath || '/etc/fail2ban') === configKey;
    });
    if (configConflict) {
      showToast(t('servers.validation.duplicate_config_path', 'A local connector with this configuration path already exists.'), 'error');
      return;
    }
  }

  showLoading(true);
  if (!payload.socketPath) delete payload.socketPath;
  if (!payload.configPath) delete payload.configPath;
  if (!payload.hostname) delete payload.hostname;
  if (!payload.agentUrl) delete payload.agentUrl;
  if (!payload.agentSecret) delete payload.agentSecret;
  if (!payload.sshUser) delete payload.sshUser;
  if (!payload.sshKeyPath) delete payload.sshKeyPath;
  if (document.getElementById('serverDefault').checked) {
    payload.isDefault = true;
  }

  if (payload.type !== 'local' && payload.type !== 'ssh') {
    delete payload.socketPath;
  }
  if (payload.type !== 'local') {
    delete payload.configPath;
  }
  if (payload.type !== 'ssh') {
    delete payload.sshUser;
    delete payload.sshKeyPath;
    delete payload.reverseTunnelEnabled;
    delete payload.tunnelPort;
  }
  if (payload.type !== 'agent') {
    delete payload.agentUrl;
    delete payload.agentSecret;
  } else {
    payload.agentUrl = normalizeAgentUrlInput(payload.agentUrl);
    if (!payload.agentUrl || !payload.agentSecret) {
      showToast(t('servers.validation.agent_required', 'Agent URL and Agent Secret are required for API Agent servers.'), 'error');
      showLoading(false);
      return;
    }
    delete payload.host;
    delete payload.port;
  }

  fetch(appPath('/api/servers'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        showToast(formatApiError(data, 'servers.toast.save_error', 'Error saving server'), 'error');
        return;
      }
      showToast(t('servers.form.success', 'Server saved successfully.'), 'success');
      showServerResponseWarnings(data);
      var saved = data.server || {};
      currentServerId = saved.id || currentServerId;
      return reloadServerViews().then(showServerManagerInfoView);
    })
    .catch(function(err) {
      showToast(t('servers.toast.save_error', 'Error saving server') + ': ' + err.message, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

// Shows the optional warnings a server save/test response may carry.
function showServerResponseWarnings(data) {
  var hostKeyBlocked = data.hostKeyError || isSSHHostKeyError(data.actionFileWarning);
  if (data.jailLocalWarning) {
    showToast(t('servers.jail_local_warning', 'Warning: jail.local is not managed by Fail2ban-UI. Move each jail into its own file under jail.d/ and delete jail.local so Fail2ban-UI can recreate it (hit once save on the settings page to write the file). See docs for permissions.'), 'warning', 12000);
  }
  if (data.actionFileWarning && !isSSHHostKeyError(data.actionFileWarning)) {
    showToast(data.actionFileWarning, 'warning', 12000);
  }
  if (hostKeyBlocked) {
    showToast(t('servers.errors.host_key_changed', 'The SSH host key of this server has changed. Verify the new fingerprint before accepting it.'), 'warning', 12000);
  }
}

function populateSSHKeySelect(keys, selected) {
  var select = document.getElementById('serverSSHKeySelect');
  if (!select) return;
  var options = '<option value="" data-i18n="servers.form.select_key_placeholder">Manual entry</option>';
  var selectedInList = false;
  if (keys && keys.length) {
    keys.forEach(function(key) {
      var safe = escapeHtml(key);
      if (selected && key === selected) {
        selectedInList = true;
      }
      options += '<option value="' + safe + '">' + safe + '</option>';
    });
  } else {
    options += '<option value="" disabled data-i18n="servers.form.no_keys">No SSH keys found; enter path manually</option>';
  }
  if (selected && !selectedInList) {
    var safeSelected = escapeHtml(selected);
    options += '<option value="' + safeSelected + '">' + safeSelected + '</option>';
  }
  select.innerHTML = options;
  if (selected) {
    select.value = selected;
  } else {
    select.value = '';
  }
  updateTranslations();
  syncSSHKeyPathReadonly();
  initSSHKeySelectHandler();
}

// SSH key path input is readonly when a key is selected, editable for manual entry.
function syncSSHKeyPathReadonly() {
  var select = document.getElementById('serverSSHKeySelect');
  var input = document.getElementById('serverSSHKey');
  if (!select || !input) return;
  if (select.value) {
    input.readOnly = true;
    input.classList.add('bg-gray-100', 'text-gray-500');
  } else {
    input.readOnly = false;
    input.classList.remove('bg-gray-100', 'text-gray-500');
  }
}

var _sshKeySelectHandlerBound = false;
function initSSHKeySelectHandler() {
  if (_sshKeySelectHandlerBound) return;
  var select = document.getElementById('serverSSHKeySelect');
  if (!select) return;
  _sshKeySelectHandlerBound = true;
  select.addEventListener('change', function() {
    var input = document.getElementById('serverSSHKey');
    if (!input) return;
    if (select.value) {
      input.value = select.value;
    }
    syncSSHKeyPathReadonly();
  });
}

function loadSSHKeys() {
  if (sshKeysCache !== null) {
    return Promise.resolve(sshKeysCache);
  }
  return fetch(appPath('/api/ssh/keys'))
    .then(function(res) { return res.json(); })
    .then(function(data) {
      sshKeysCache = data.keys || [];
      return sshKeysCache;
    })
    .catch(function(err) {
      console.error('Error loading SSH keys:', err);
      sshKeysCache = [];
      return sshKeysCache;
    });
}

// =========================================================================
//  Server Actions
// =========================================================================

function setServerEnabled(serverId, enabled) {
  var server = serversCache.find(function(s) { return s.id === serverId; });
  if (!server) {
    return;
  }
  var payload = Object.assign({}, server, { enabled: enabled });
  showLoading(true);
  fetch(appPath('/api/servers'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        showToast(formatApiError(data, 'servers.toast.save_error', 'Error saving server'), 'error');
        return;
      }
      if (!enabled) {
        if (getStoredServerId() === serverId) {
          clearStoredServerId();
        }
        if (currentServerId === serverId) {
          currentServerId = null;
          currentServer = null;
        }
      }
      showServerResponseWarnings(data);
      return reloadServerViews();
    })
    .catch(function(err) {
      showToast(t('servers.toast.save_error', 'Error saving server') + ': ' + err.message, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

function testServerConnection(serverId) {
  if (!serverId) return;
  showLoading(true);
  return fetch(appPath('/api/servers/' + encodeURIComponent(serverId) + '/test'), {
    method: 'POST'
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        if (data.hostKeyError || data.messageKey === 'servers.errors.host_key_changed' || isSSHHostKeyError(data.error)) {
          showToast(t('servers.errors.host_key_changed', 'The SSH host key of this server has changed. Verify the new fingerprint before accepting it.'), 'warning', 12000);
          return refreshServerHealth();
        }
        showToast(formatApiError(data, 'servers.actions.test_failure', 'Connection failed'), 'error');
        return;
      }
      showToast(apiMessage(data, 'servers.actions.test_success', 'Connection successful'), 'success');
      showServerResponseWarnings(data);
    })
    .catch(function(err) {
      showToast(t('servers.actions.test_failure', 'Connection failed') + ': ' + err.message, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

function acceptHostKey(serverId) {
  var server = serversCache.find(function(s) { return s.id === serverId; });
  if (!server || !server.hostKeyFingerprint) {
    showToast(t('servers.actions.accept_hostkey_failed', 'Failed to accept the new host key'), 'error');
    return;
  }
  var prompt = t('servers.confirm.accept_hostkey',
    'Only accept this host key if you have verified the fingerprint on the server (ssh-keygen -lf /etc/ssh/ssh_host_*.pub). Accept and trust this new SSH host key?');
  if (!confirm(prompt + '\n\n' + server.hostKeyFingerprint)) return;
  showLoading(true);
  fetch(appPath('/api/servers/' + encodeURIComponent(serverId) + '/hostkey/accept'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fingerprint: server.hostKeyFingerprint })
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        showToast(formatApiError(data, 'servers.actions.accept_hostkey_failed', 'Failed to accept the new host key'), 'error');
        return loadServers().then(function() { renderServerManagerList(); });
      }
      return reloadServerViews().then(function() {
        showToast(t('servers.actions.accept_hostkey_success', 'New host key accepted and stored'), 'success');
      });
    })
    .catch(function(err) {
      showToast(t('servers.actions.accept_hostkey_failed', 'Failed to accept the new host key') + ': ' + err.message, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

function deleteServer(serverId) {
  if (!serverId || !serversCache.some(function(server) { return server.id === serverId; })) return;
  if (!confirm(t('servers.actions.delete_confirm', 'Delete this server entry?'))) return;
  showLoading(true);
  return fetch(appPath('/api/servers/' + encodeURIComponent(serverId)), { method: 'DELETE' })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        showToast(formatApiError(data, 'servers.toast.delete_error', 'Error deleting server'), 'error');
        return;
      }
      if (getStoredServerId() === serverId) {
        clearStoredServerId();
      }
      if (currentServerId === serverId) {
        currentServerId = null;
        currentServer = null;
      }
      var editingId = document.getElementById('serverId');
      if (editingId && editingId.value === serverId) showServerManagerInfoView();
      return reloadServerViews().then(function() {
        showToast(t('servers.actions.delete_success', 'Server removed'), 'success');
      });
    })
    .catch(function(err) {
      showToast(t('servers.toast.delete_error', 'Error deleting server') + ': ' + err.message, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

function restartFail2banServer(serverId) {
  if (!serverId) {
    showToast(t('servers.toast.none_selected', 'No server selected'), 'error');
    return;
  }
  var server = serversCache.find(function(s) { return s.id === serverId; });
  var isLocal = server && server.type === 'local';
  var confirmMsg = isLocal
    ? t('servers.confirm.reload_local', 'Reload Fail2ban configuration on this server now? This will reload the configuration without restarting the service.')
    : t('servers.confirm.restart_remote', 'Keep in mind that while fail2ban is restarting, logs are not being parsed and no IP addresses are blocked. Restart fail2ban on this server now? This will take some time.');
  if (!confirm(confirmMsg)) return;
  fetch(appPath('/api/fail2ban/restart?serverId=' + encodeURIComponent(serverId)), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  })
    .then(readJsonResponse)
    .then(function(data) {
      if (data.error) {
        showToast(formatApiError(data, 'servers.toast.restart_failed', 'Failed to restart Fail2ban'), 'error');
        return;
      }
      var mode = data.mode || 'restart';
      var key, fallback;
      if (mode === 'reload') {
        key = 'restart_banner.reload_success';
        fallback = 'Fail2ban configuration reloaded successfully';
      } else {
        key = 'restart_banner.restart_success';
        fallback = 'Fail2ban service restarted and passed health check';
      }
      return loadServers().then(function() {
        if (!data.operationId) showToast(t(key, fallback), 'success');
        return refreshData({ silent: true });
      });
    })
    .catch(function(err) {
      if (!err.operation) showToast(t('servers.toast.restart_failed', 'Failed to restart Fail2ban') + ': ' + err.message, 'error');
    });
}
