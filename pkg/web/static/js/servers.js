// Server management functions for Fail2ban UI
"use strict";

function loadServers() {
  return fetch('/api/servers')
    .then(function(res) { return res.json(); })
    .then(function(data) {
      serversCache = data.servers || [];
      var enabledServers = serversCache.filter(function(s) { return s.enabled; });
      if (!enabledServers.length) {
        currentServerId = null;
        currentServer = null;
      } else {
        var desired = currentServerId;
        var selected = desired ? enabledServers.find(function(s) { return s.id === desired; }) : null;
        if (!selected) {
          var def = enabledServers.find(function(s) { return s.isDefault; });
          selected = def || enabledServers[0];
        }
        currentServer = selected;
        currentServerId = selected ? selected.id : null;
      }
      renderServerSelector();
      renderServerSubtitle();
      updateRestartBanner();
    })
    .catch(function(err) {
      console.error('Error loading servers:', err);
      serversCache = [];
      currentServerId = null;
      currentServer = null;
      renderServerSelector();
      renderServerSubtitle();
      updateRestartBanner();
    });
}

function renderServerSelector() {
  var container = document.getElementById('serverSelectorContainer');
  if (!container) return;
  var enabledServers = serversCache.filter(function(s) { return s.enabled; });
  if (!serversCache.length) {
    container.innerHTML = '<div class="text-sm text-red-500" data-i18n="servers.selector.empty">No servers configured</div>';
    if (typeof updateTranslations === 'function') {
      updateTranslations();
    }
    return;
  }
  if (!enabledServers.length) {
    container.innerHTML = '<div class="text-sm text-red-500" data-i18n="servers.selector.empty">No servers configured</div>';
    if (typeof updateTranslations === 'function') {
      updateTranslations();
    }
    return;
  }

  var options = enabledServers.map(function(server) {
    var label = escapeHtml(server.name || server.id);
    var type = server.type ? (' (' + server.type.toUpperCase() + ')') : '';
    return '<option value="' + escapeHtml(server.id) + '">' + label + type + '</option>';
  }).join('');

  container.innerHTML = ''
    + '<div class="flex flex-col">'
    + '  <label for="serverSelect" class="text-xs text-gray-500 mb-1" data-i18n="servers.selector.label">Active Server</label>'
    + '  <select id="serverSelect" class="border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">'
    +        options
    + '  </select>'
    + '</div>';

  var select = document.getElementById('serverSelect');
  if (select) {
    select.value = currentServerId || '';
    select.addEventListener('change', function(e) {
      setCurrentServer(e.target.value);
    });
  }
  if (typeof updateTranslations === 'function') {
    updateTranslations();
  }
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
  subtitle.textContent = parts.join(' • ');
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
  renderServerSelector();
  renderServerSubtitle();
  updateRestartBanner();
  refreshData();
}

function openServerManager(serverId) {
  showLoading(true);
  loadServers()
    .then(function() {
      if (serverId) {
        editServer(serverId);
      } else {
        resetServerForm();
      }
      renderServerManagerList();
      openModal('serverManagerModal');
    })
    .finally(function() {
      showLoading(false);
    });
}

function renderServerManagerList() {
  var list = document.getElementById('serverManagerList');
  var emptyState = document.getElementById('serverManagerListEmpty');
  if (!list || !emptyState) return;

  if (!serversCache.length) {
    list.innerHTML = '';
    emptyState.classList.remove('hidden');
    if (typeof updateTranslations === 'function') updateTranslations();
    return;
  }

  emptyState.classList.add('hidden');

  var html = serversCache.map(function(server) {
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
    var meta = descriptor.join(' • ');
    var tags = (server.tags || []).length
      ? '<div class="mt-2 text-xs text-gray-500">' + escapeHtml(server.tags.join(', ')) + '</div>'
      : '';
    return ''
      + '<div class="border border-gray-200 rounded-lg p-4 overflow-x-auto bg-gray-50">'
      + '  <div class="flex items-center justify-between">'
      + '    <div>'
      + '      <p class="font-semibold text-gray-800 flex items-center">' + escapeHtml(server.name || server.id) + defaultBadge + statusBadge + restartBadge + '</p>'
      + '      <p class="text-sm text-gray-500">' + escapeHtml(meta || server.id) + '</p>'
      +        tags
      + '    </div>'
      + '    <div class="flex flex-col gap-2">'
      + '      <button class="text-sm text-blue-600 hover:text-blue-800" onclick="editServer(\'' + escapeHtml(server.id) + '\')" data-i18n="servers.actions.edit">Edit</button>'
      + (server.isDefault ? '' : '<button class="text-sm text-blue-600 hover:text-blue-800" onclick="makeDefaultServer(\'' + escapeHtml(server.id) + '\')" data-i18n="servers.actions.set_default">Set default</button>')
      + '      <button class="text-sm text-blue-600 hover:text-blue-800" onclick="setServerEnabled(\'' + escapeHtml(server.id) + '\',' + (server.enabled ? 'false' : 'true') + ')" data-i18n="' + (server.enabled ? 'servers.actions.disable' : 'servers.actions.enable') + '">' + (server.enabled ? 'Disable' : 'Enable') + '</button>'
      + (server.enabled ? (server.type === 'local' 
        ? '<button class="text-sm text-blue-600 hover:text-blue-800 relative group" onclick="restartFail2banServer(\'' + escapeHtml(server.id) + '\')" data-i18n="servers.actions.reload" title="" data-i18n-title="servers.actions.reload_tooltip">Reload Fail2ban</button>'
        : '<button class="text-sm text-blue-600 hover:text-blue-800" onclick="restartFail2banServer(\'' + escapeHtml(server.id) + '\')" data-i18n="servers.actions.restart">Restart Fail2ban</button>') : '')
      + '      <button class="text-sm text-blue-600 hover:text-blue-800" onclick="testServerConnection(\'' + escapeHtml(server.id) + '\')" data-i18n="servers.actions.test">Test connection</button>'
      + '      <button class="text-sm text-red-600 hover:text-red-800" onclick="deleteServer(\'' + escapeHtml(server.id) + '\')" data-i18n="servers.actions.delete">Delete</button>'
      + '    </div>'
      + '  </div>'
      + '</div>';
  }).join('');

  list.innerHTML = html;
  if (typeof updateTranslations === 'function') {
    updateTranslations();
    // Set tooltip text for reload buttons after translations are updated
    setTimeout(function() {
      serversCache.forEach(function(server) {
        if (server.enabled && server.type === 'local') {
          var buttons = list.querySelectorAll('button[data-i18n="servers.actions.reload"]');
          buttons.forEach(function(btn) {
            var tooltipText = t('servers.actions.reload_tooltip', 'For local connectors, only a configuration reload is possible via the socket connection. The container cannot restart the Fail2ban service using systemctl. To perform a full restart, run \'systemctl restart fail2ban\' directly on the host system.');
            btn.setAttribute('title', tooltipText);
          });
        }
      });
    }, 100);
  }
}

function resetServerForm() {
  document.getElementById('serverId').value = '';
  document.getElementById('serverName').value = '';
  document.getElementById('serverType').value = 'local';
  document.getElementById('serverHost').value = '';
  document.getElementById('serverPort').value = '22';
  document.getElementById('serverSocket').value = '/var/run/fail2ban/fail2ban.sock';
  document.getElementById('serverLogPath').value = '/var/log/fail2ban.log';
  document.getElementById('serverHostname').value = '';
  document.getElementById('serverSSHUser').value = '';
  document.getElementById('serverSSHKey').value = '';
  document.getElementById('serverAgentUrl').value = '';
  document.getElementById('serverAgentSecret').value = '';
  document.getElementById('serverTags').value = '';
  document.getElementById('serverDefault').checked = false;
  document.getElementById('serverEnabled').checked = false;
  populateSSHKeySelect(sshKeysCache || [], '');
  onServerTypeChange('local');
}

function editServer(serverId) {
  var server = serversCache.find(function(s) { return s.id === serverId; });
  if (!server) return;
  document.getElementById('serverId').value = server.id || '';
  document.getElementById('serverName').value = server.name || '';
  document.getElementById('serverType').value = server.type || 'local';
  document.getElementById('serverHost').value = server.host || '';
  document.getElementById('serverPort').value = server.port || '';
  document.getElementById('serverSocket').value = server.socketPath || '/var/run/fail2ban/fail2ban.sock';
  document.getElementById('serverLogPath').value = server.logPath || '/var/log/fail2ban.log';
  document.getElementById('serverHostname').value = server.hostname || '';
  document.getElementById('serverSSHUser').value = server.sshUser || '';
  document.getElementById('serverSSHKey').value = server.sshKeyPath || '';
  document.getElementById('serverAgentUrl').value = server.agentUrl || '';
  document.getElementById('serverAgentSecret').value = server.agentSecret || '';
  document.getElementById('serverTags').value = (server.tags || []).join(',');
  document.getElementById('serverDefault').checked = !!server.isDefault;
  document.getElementById('serverEnabled').checked = !!server.enabled;
  onServerTypeChange(server.type || 'local');
  if ((server.type || 'local') === 'ssh') {
    loadSSHKeys().then(function(keys) {
      populateSSHKeySelect(keys, server.sshKeyPath || '');
    });
  }
}

function onServerTypeChange(type) {
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
  if (isEditing) {
    return;
  }
  if (type === 'local') {
    enabledToggle.checked = false;
  } else {
    enabledToggle.checked = true;
  }
  if (type === 'ssh') {
    loadSSHKeys().then(function(keys) {
      if (!isEditing) {
        populateSSHKeySelect(keys, '');
      }
    });
  } else {
    populateSSHKeySelect([], '');
  }
}

function submitServerForm(event) {
  event.preventDefault();
  showLoading(true);

  var payload = {
    id: document.getElementById('serverId').value || undefined,
    name: document.getElementById('serverName').value.trim(),
    type: document.getElementById('serverType').value,
    host: document.getElementById('serverHost').value.trim(),
    port: document.getElementById('serverPort').value ? parseInt(document.getElementById('serverPort').value, 10) : undefined,
    socketPath: document.getElementById('serverSocket').value.trim(),
    logPath: document.getElementById('serverLogPath').value.trim(),
    hostname: document.getElementById('serverHostname').value.trim(),
    sshUser: document.getElementById('serverSSHUser').value.trim(),
    sshKeyPath: document.getElementById('serverSSHKey').value.trim(),
    agentUrl: document.getElementById('serverAgentUrl').value.trim(),
    agentSecret: document.getElementById('serverAgentSecret').value.trim(),
    tags: document.getElementById('serverTags').value
      ? document.getElementById('serverTags').value.split(',').map(function(tag) { return tag.trim(); }).filter(Boolean)
      : [],
    enabled: document.getElementById('serverEnabled').checked
  };
  if (!payload.socketPath) delete payload.socketPath;
  if (!payload.logPath) delete payload.logPath;
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
    delete payload.logPath;
  }
  if (payload.type !== 'ssh') {
    delete payload.sshUser;
    delete payload.sshKeyPath;
  }
  if (payload.type !== 'agent') {
    delete payload.agentUrl;
    delete payload.agentSecret;
  }

  fetch('/api/servers', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        showToast('Error saving server: ' + (data.error || 'Unknown error'), 'error');
        return;
      }
      showToast(t('servers.form.success', 'Server saved successfully.'), 'success');
      var saved = data.server || {};
      currentServerId = saved.id || currentServerId;
      return loadServers().then(function() {
        renderServerManagerList();
        renderServerSelector();
        renderServerSubtitle();
        if (currentServerId) {
          currentServer = serversCache.find(function(s) { return s.id === currentServerId; }) || currentServer;
        }
        return refreshData({ silent: true });
      });
    })
    .catch(function(err) {
      showToast('Error saving server: ' + err, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
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
  if (typeof updateTranslations === 'function') {
    updateTranslations();
  }
}

function loadSSHKeys() {
  if (sshKeysCache !== null) {
    populateSSHKeySelect(sshKeysCache, document.getElementById('serverSSHKey').value);
    return Promise.resolve(sshKeysCache);
  }
  return fetch('/api/ssh/keys')
    .then(function(res) { return res.json(); })
    .then(function(data) {
      sshKeysCache = data.keys || [];
      populateSSHKeySelect(sshKeysCache, document.getElementById('serverSSHKey').value);
      return sshKeysCache;
    })
    .catch(function(err) {
      console.error('Error loading SSH keys:', err);
      sshKeysCache = [];
      populateSSHKeySelect(sshKeysCache, document.getElementById('serverSSHKey').value);
      return sshKeysCache;
    });
}

function setServerEnabled(serverId, enabled) {
  var server = serversCache.find(function(s) { return s.id === serverId; });
  if (!server) {
    return;
  }
  var payload = Object.assign({}, server, { enabled: enabled });
  showLoading(true);
  fetch('/api/servers', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        showToast('Error saving server: ' + (data.error || 'Unknown error'), 'error');
        return;
      }
      if (!enabled && currentServerId === serverId) {
        currentServerId = null;
        currentServer = null;
      }
      return loadServers().then(function() {
        renderServerManagerList();
        renderServerSelector();
        renderServerSubtitle();
        return refreshData({ silent: true });
      });
    })
    .catch(function(err) {
      showToast('Error saving server: ' + err, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

function testServerConnection(serverId) {
  if (!serverId) return;
  showLoading(true);
  fetch('/api/servers/' + encodeURIComponent(serverId) + '/test', {
    method: 'POST'
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        showToast(t(data.messageKey || 'servers.actions.test_failure', data.error), 'error');
        return;
      }
      showToast(t(data.messageKey || 'servers.actions.test_success', data.message || 'Connection successful'), 'success');
    })
    .catch(function(err) {
      showToast(t('servers.actions.test_failure', 'Connection failed') + ': ' + err, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

function deleteServer(serverId) {
  if (!confirm(t('servers.actions.delete_confirm', 'Delete this server entry?'))) return;
  showLoading(true);
  fetch('/api/servers/' + encodeURIComponent(serverId), { method: 'DELETE' })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        showToast('Error deleting server: ' + (data.error || 'Unknown error'), 'error');
        return;
      }
      if (currentServerId === serverId) {
        currentServerId = null;
        currentServer = null;
      }
      return loadServers().then(function() {
        renderServerManagerList();
        renderServerSelector();
        renderServerSubtitle();
        return refreshData({ silent: true });
      }).then(function() {
        showToast(t('servers.actions.delete_success', 'Server removed'), 'success');
      });
    })
    .catch(function(err) {
      showToast('Error deleting server: ' + err, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

function makeDefaultServer(serverId) {
  showLoading(true);
  fetch('/api/servers/' + encodeURIComponent(serverId) + '/default', { method: 'POST' })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        showToast('Error setting default server: ' + (data.error || 'Unknown error'), 'error');
        return;
      }
      currentServerId = data.server ? data.server.id : serverId;
      return loadServers().then(function() {
        renderServerManagerList();
        renderServerSelector();
        renderServerSubtitle();
        return refreshData({ silent: true });
      }).then(function() {
        showToast(t('servers.actions.set_default_success', 'Server set as default'), 'success');
      });
    })
    .catch(function(err) {
      showToast('Error setting default server: ' + err, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

function restartFail2banServer(serverId) {
  if (!serverId) {
    showToast("No server selected", 'error');
    return;
  }
  var server = serversCache.find(function(s) { return s.id === serverId; });
  var isLocal = server && server.type === 'local';
  var confirmMsg = isLocal
    ? "Reload Fail2ban configuration on this server now? This will reload the configuration without restarting the service."
    : "Keep in mind that while fail2ban is restarting, logs are not being parsed and no IP addresses are blocked. Restart fail2ban on this server now? This will take some time.";
  if (!confirm(confirmMsg)) return;
  showLoading(true);
  fetch('/api/fail2ban/restart?serverId=' + encodeURIComponent(serverId), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        showToast("Failed to restart Fail2ban: " + data.error, 'error');
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
        updateRestartBanner();
        showToast(t(key, fallback), 'success');
        return refreshData({ silent: true });
      });
    })
    .catch(function(err) {
      showToast("Failed to restart Fail2ban: " + err, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

function restartFail2ban() {
  if (!confirm("Keep in mind that while fail2ban is restarting, logs are not being parsed and no IP addresses are blocked. Restart fail2ban now? This will take some time.")) return;
  restartFail2banServer(currentServerId);
}

