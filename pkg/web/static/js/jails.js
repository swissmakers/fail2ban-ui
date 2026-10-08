// Jail management functions for Fail2ban UI
"use strict";

// =========================================================================
//  Jail creation
// =========================================================================

function createJail() {
  var actionServerId = currentServerId;
  const jailName = document.getElementById('newJailName').value.trim();
  const content = document.getElementById('newJailContent').value.trim();

  if (!jailName) {
    showToast(t('jails.toast.name_required', 'Jail name is required'), 'error');
    return;
  }
  fetch(withServerParam('/api/jails'), {
    method: 'POST',
    headers: serverHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      jailName: jailName,
      content: content
    })
  })
    .then(function(res) {
      if (res.status === 202 && currentServerId === actionServerId) closeModal('createJailModal');
      return readJsonResponse(res);
    })
    .then(function(data) {
      if (!data.operationId) showToast(apiMessage(data, 'jails.toast.create_success', 'Jail created successfully'), 'success');
      if (currentServerId === actionServerId) openManageJailsModal({ silent: true });
    })
    .catch(function(err) {
      console.error('Error creating jail:', err);
      if (!err.operation) showToast(t('jails.toast.create_error', 'Error creating jail') + ': ' + (err.message || err), 'error');
    });
}

// =========================================================================
//  Jail configuration saving
// =========================================================================  

function saveJailConfig() {
  if (!currentJailForConfig) return;
  var actionServerId = currentServerId;
  var actionJail = currentJailForConfig;

  var filterConfig = document.getElementById('filterConfigTextarea').value;
  var jailConfig = document.getElementById('jailConfigTextarea').value;
  var url = '/api/jails/' + encodeURIComponent(currentJailForConfig) + '/config';
  fetch(withServerParam(url), {
    method: 'POST',
    headers: serverHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ filter: filterConfig, jail: jailConfig }),
  })
    .then(function(res) {
      if (res.status === 202 && currentServerId === actionServerId && currentJailForConfig === actionJail) closeModal('jailConfigModal');
      return readJsonResponse(res);
    })
    .then(function(data) {
      data = data || {};
      if (data.warning) {
        var warnMsg = t('filter_debug.save_reload_warning', 'Config saved, but fail2ban reload failed') + ': ' + data.warning;
        if (data.jailAutoDisabled && data.jailName) {
          warnMsg = t('filter_debug.jail_auto_disabled', "Jail '%s' was automatically disabled.").replace('%s', data.jailName) + ' ' + warnMsg;
          var toggleId = 'toggle-' + data.jailName.replace(/[^a-zA-Z0-9]/g, '_');
          var cb = document.getElementById(toggleId);
          if (cb && currentServerId === actionServerId) cb.checked = false;
        }
        if (!data.operationId) showToast(warnMsg, 'warning', 12000);
      } else if (!data.operationId) {
        showToast(t('filter_debug.save_success', 'Filter and jail config saved and reloaded'), 'success');
      }
      if (data.jailAutoDisabled && currentServerId === actionServerId) {
        return refreshData({ silent: true, summaryOnly: true });
      }
    })
    .catch(function(err) {
      console.error('Error saving config:', err);
      if (!err.operation) showToast(t('jails.toast.save_config_error', 'Error saving config') + ': ' + err.message, 'error');
    });
}

function updateJailConfigFromFilter() {
  const filterSelect = document.getElementById('newJailFilter');
  const jailNameInput = document.getElementById('newJailName');
  const contentTextarea = document.getElementById('newJailContent');

  if (!filterSelect || !contentTextarea) return;
  const selectedFilter = filterSelect.value;

  if (!selectedFilter) {
    return;
  }
  if (jailNameInput && !jailNameInput.value.trim()) {
    jailNameInput.value = selectedFilter;
  }

  const jailName = (jailNameInput && jailNameInput.value.trim()) || selectedFilter;
  const config = `[${jailName}]
enabled = false
filter = ${selectedFilter}
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600`;

  contentTextarea.value = config;
}

// =========================================================================
//  Jail toggle enable/disable state of single jails
// =========================================================================

// Only tracks the short submission window until the durable operation is known.
var pendingJailChanges = Object.create(null);

function updateJailChangeProgress() {
  var local = pendingJailChanges[currentServerId] || {};
  var active = typeof activeServerOperations === 'function' ? activeServerOperations(currentServerId) : [];
  document.querySelectorAll('#jailsList input[type="checkbox"]').forEach(function(control) {
    var name = control.getAttribute('data-jail-name');
    if (!name) return;
    var requested = local[name];
    active.forEach(function(operation) {
      if (operation.desiredStates && Object.prototype.hasOwnProperty.call(operation.desiredStates, name)) {
        requested = { enabled: operation.desiredStates[name] };
      }
    });
    control.disabled = !!requested;
    if (requested) control.checked = requested.enabled;
    var note = document.getElementById('jail-state-' + name.replace(/[^a-zA-Z0-9]/g, '_'));
    if (!note) return;
    note.textContent = requested ? (requested.enabled
      ? t('jails.manage.enabling', 'Enabling…')
      : t('jails.manage.disabling', 'Disabling…')) : '';
    note.classList.toggle('hidden', !requested);
  });
}

function saveManageJailsSingle(checkbox) {
  var serverId = currentServerId;
  var item = checkbox.closest('div.flex.items-center.justify-between');
  var nameSpan = item && item.querySelector('span.text-sm.font-medium');
  var jailName = checkbox.getAttribute('data-jail-name') || (nameSpan && nameSpan.textContent.trim());
  if (!jailName) return;
  var pending = pendingJailChanges[serverId] = pendingJailChanges[serverId] || {};
  if (pending[jailName]) return;
  var isEnabled = checkbox.checked;
  var updatedJails = {};
  updatedJails[jailName] = isEnabled;
  var url = withServerParam('/api/jails/manage');
  var headers = serverHeaders({ 'Content-Type': 'application/json' });
  pending[jailName] = { jail: jailName, enabled: isEnabled, started: Date.now() };
  updateJailChangeProgress();
  return fetch(url, { method: 'POST', headers: headers, body: JSON.stringify(updatedJails) })
    .then(readJsonResponse)
    .then(function(data) {
      data = data || {};
      if (data.error) {
        var error = new Error(data.error);
        error.data = data;
        throw error;
      }
      var disabledJails = Array.isArray(data.disabledJails) ? data.disabledJails : [];
      checkbox.checked = disabledJails.indexOf(jailName) === -1 && isEnabled;
      checkbox.setAttribute('data-confirmed-enabled', String(checkbox.checked));
      if (!data.operationId) {
        if (data.warning) showToast(data.warning, 'warning', 12000);
        if (disabledJails.length) {
          showToast(t('jails.manage.offender_disabled', "Your change was applied. Unrelated jail '{jail}' has a broken configuration and was automatically disabled.").replace('{jail}', disabledJails.join("', '")), 'warning', 15000);
        } else {
          showToast(apiMessage(data, isEnabled ? 'jails.toast.enabled_success' : 'jails.toast.disabled_success', 'Jail {jail} ' + (isEnabled ? 'enabled' : 'disabled') + ' successfully').replace('{jail}', jailName), 'success');
        }
      }
      return loadServers().then(function() {
        if (currentServerId === serverId) return refreshData({ silent: true, summaryOnly: true });
      });
    })
    .catch(function(err) {
      var data = err.data || {};
      var autoDisabled = data.autoDisabled && Array.isArray(data.enabledJails) && data.enabledJails.indexOf(jailName) !== -1;
      checkbox.checked = autoDisabled ? false : !isEnabled;
      if (!err.operation) showToast(t('jails.toast.save_settings_error', 'Error saving jail settings') + ': ' + (err.message || String(err)), autoDisabled ? 'warning' : 'error', 15000);
      if (typeof refreshOperations === 'function') refreshOperations();
      // Reconcile the original server, not whichever one the user selected
      // while the request was running.
      return fetch(url, { headers: headers }).then(readJsonResponse).then(function(actual) {
        var jail = actual && Array.isArray(actual.jails) && actual.jails.find(function(j) { return j.jailName === jailName; });
        if (jail) checkbox.checked = jail.enabled;
      }).catch(function() { });
    })
    .finally(function() {
      delete pending[jailName];
      if (!Object.keys(pending).length) delete pendingJailChanges[serverId];
      updateJailChangeProgress();
    });
}

// =========================================================================
//  Jail deletion
// =========================================================================

function deleteJail(jailName) {
  var actionServerId = currentServerId;
  if (!confirm(t('jails.confirm.delete', 'Are you sure you want to delete the jail "{name}"? This action cannot be undone.').replace('{name}', jailName))) {
    return;
  }
  fetch(withServerParam('/api/jails/' + encodeURIComponent(jailName)), {
    method: 'DELETE',
    headers: serverHeaders()
  })
    .then(readJsonResponse)
    .then(function(data) {
      if (!data.operationId) showToast(apiMessage(data, 'jails.toast.delete_success', 'Jail deleted successfully'), 'success');
      if (currentServerId === actionServerId) {
        openManageJailsModal({ silent: true });
        refreshData({ silent: true, summaryOnly: true });
      }
    })
    .catch(function(err) {
      console.error('Error deleting jail:', err);
      if (!err.operation) showToast(t('jails.toast.delete_error', 'Error deleting jail') + ': ' + (err.message || err), 'error');
    });
}

// =========================================================================
//  Logpath Helpers
// =========================================================================

// Supported fail2ban logpath formats: space-separated / multi-line
function extractLogpathFromConfig(configText) {
  if (!configText) return '';
  var logpaths = [];
  var lines = configText.split('\n');
  var inLogpathLine = false;
  var currentLogpath = '';

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (line.startsWith('#')) {
      continue;
    }
    var logpathMatch = line.match(/^logpath\s*=\s*(.+)$/i);
    if (logpathMatch && logpathMatch[1]) {
      // Trim whitespace and remove quotes if present
      currentLogpath = logpathMatch[1].trim();
      currentLogpath = currentLogpath.replace(/^["']|["']$/g, '');
      inLogpathLine = true;
    } else if (inLogpathLine) {

      if (line !== '' && !line.includes('=')) {
        currentLogpath += ' ' + line.trim();
      } else {
        if (currentLogpath) {
          var paths = currentLogpath.split(/\s+/).filter(function(p) { return p.length > 0; });
          logpaths = logpaths.concat(paths);
          currentLogpath = '';
        }
        inLogpathLine = false;
      }
    } else if (inLogpathLine && line === '') {
      if (currentLogpath) {
        var paths = currentLogpath.split(/\s+/).filter(function(p) { return p.length > 0; });
        logpaths = logpaths.concat(paths);
        currentLogpath = '';
      }
      inLogpathLine = false;
    }
  }

  if (currentLogpath) {
    var paths = currentLogpath.split(/\s+/).filter(function(p) { return p.length > 0; });
    logpaths = logpaths.concat(paths);
  }
  return logpaths.join('\n');
}

function updateLogpathButtonVisibility() {
  var jailTextArea = document.getElementById('jailConfigTextarea');
  var jailConfig = jailTextArea ? jailTextArea.value : '';
  var hasLogpath = /logpath\s*=/i.test(jailConfig);
  var testSection = document.getElementById('testLogpathSection');
  var localServerHint = document.getElementById('localServerLogpathHint');

  if (hasLogpath && testSection) {
    testSection.classList.remove('hidden');
    if (localServerHint && currentServer && currentServer.type === 'local') {
      localServerHint.classList.remove('hidden');
    } else if (localServerHint) {
      localServerHint.classList.add('hidden');
    }
  } else if (testSection) {
    testSection.classList.add('hidden');
    document.getElementById('logpathResults').classList.add('hidden');
    if (localServerHint) {
      localServerHint.classList.add('hidden');
    }
  }
}

function testLogpath() {
  if (!currentJailForConfig) return;

  var jailTextArea = document.getElementById('jailConfigTextarea');
  var jailConfig = jailTextArea ? jailTextArea.value : '';
  var logpath = extractLogpathFromConfig(jailConfig);

  if (!logpath) {
    showToast(t('jails.logpath_test.no_logpath', 'No logpath found in jail configuration. Please add a logpath line (e.g., logpath = /var/log/example.log)'), 'warning');
    return;
  }
  var resultsDiv = document.getElementById('logpathResults');
  resultsDiv.textContent = t('jails.logpath_test.testing', 'Testing logpath...');
  resultsDiv.classList.remove('hidden');
  resultsDiv.classList.remove('text-red-600', 'text-yellow-600');
  showLoading(true);
  var url = '/api/jails/' + encodeURIComponent(currentJailForConfig) + '/logpath/test';
  fetch(withServerParam(url), {
    method: 'POST',
    headers: serverHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ logpath: logpath })
  })
    .then(readJsonResponse)
    .then(function(data) {
      showLoading(false);
      data = data || {};
      var results = data.results || [];
      var isLocalServer = data.is_local_server || false;
      var output = '';

      if (results.length === 0) {
        output = '<div class="text-yellow-600">' + t('jails.logpath_test.no_entries', 'No logpath entries found.') + '</div>';
        resultsDiv.innerHTML = output;
        resultsDiv.classList.add('text-yellow-600');
        return;
      }

      results.forEach(function(result, idx) {
        var logpath = result.logpath || '';
        var resolvedPath = result.resolved_path || '';
        var found = result.found || false;
        var files = result.files || [];
        var error = result.error || '';
        var inaccessible = result.inaccessible || false;
        var message = result.message || '';

        if (idx > 0) {
          output += '<div class="my-4 border-t border-gray-300 pt-4"></div>';
        }

        output += '<div class="mb-3">';
        output += '<div class="font-semibold text-gray-800 mb-1">' + t('jails.logpath_test.entry', 'Logpath {num}:').replace('{num}', idx + 1) + '</div>';
        output += '<div class="ml-4 text-sm text-gray-600 font-mono">' + escapeHtml(logpath) + '</div>';

        if (resolvedPath && resolvedPath !== logpath) {
          output += '<div class="ml-4 text-xs text-gray-500 mt-1">' + t('jails.logpath_test.resolved', 'Resolved:') + ' <span class="font-mono">' + escapeHtml(resolvedPath) + '</span></div>';
        }
        output += '</div>';
        output += '<div class="ml-4 mb-2">';
        output += '<div class="flex items-center gap-2">';
        if (isLocalServer) {
          output += '<span class="font-medium text-sm">' + t('jails.logpath_test.in_container', 'In fail2ban-ui Container:') + '</span>';
        } else {
          output += '<span class="font-medium text-sm">' + t('jails.logpath_test.on_remote', 'On Remote Server:') + '</span>';
        }
        if (error) {
          output += '<span class="text-red-600 font-bold">&#10007;</span>';
          output += '<span class="text-red-600 text-sm">' + t('common.error', 'Error') + ': ' + escapeHtml(error) + '</span>';
        } else if (found) {
          output += '<span class="text-green-600 font-bold">&#10003;</span>';
          output += '<span class="text-green-600 text-sm">'
            + t('jails.logpath_test.found_files', 'Found {count} file(s)').replace('{count}', files.length)
            + '</span>';
        } else if (inaccessible) {
          output += '<span class="text-yellow-600 font-bold">&#9888;</span>';
          output += '<span class="text-yellow-600 text-sm">'
            + escapeHtml(t('jails.logpath_test.inaccessible', message || 'Cannot verify: the connector cannot read the log directory. Check its directory permissions. Fail2Ban must validate the configuration before the jail can be enabled.'))
            + '</span>';
        } else {
          output += '<span class="text-red-600 font-bold">&#10007;</span>';
          if (isLocalServer) {
            output += '<span class="text-red-600 text-sm">' + t('jails.logpath_test.not_found_container', 'Not found (logs may not be mounted to container)') + '</span>';
          } else {
            output += '<span class="text-red-600 text-sm">' + t('jails.logpath_test.not_found', 'Not found') + '</span>';
          }
        }
        output += '</div>';
        if (files.length > 0) {
          output += '<div class="ml-6 mt-1 text-xs text-gray-600">';
          files.forEach(function(file) {
            output += '<div class="font-mono">  - ' + escapeHtml(file) + '</div>';
          });
          output += '</div>';
        }
        output += '</div>';
      });

      var allFound = results.every(function(r) { return r.found; });
      var anyFound = results.some(function(r) { return r.found; });
      var anyHardFail = results.some(function(r) { return !r.found && !r.inaccessible; });

      if (allFound) {
        resultsDiv.classList.remove('text-red-600', 'text-yellow-600');
      } else if (!anyHardFail) {
        resultsDiv.classList.remove('text-red-600');
        resultsDiv.classList.add('text-yellow-600');
      } else if (anyFound) {
        resultsDiv.classList.remove('text-red-600');
        resultsDiv.classList.add('text-yellow-600');
      } else {
        resultsDiv.classList.remove('text-yellow-600');
        resultsDiv.classList.add('text-red-600');
      }

      resultsDiv.innerHTML = output;

      setTimeout(function() {
        resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }, 100);
    })
    .catch(function(err) {
      showLoading(false);
      resultsDiv.textContent = t('common.error', 'Error') + ': ' + err.message;
      resultsDiv.classList.add('text-red-600');
      setTimeout(function() {
        resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }, 100);
    });
}

// =========================================================================
//  Extension interference workaround
// =========================================================================

function preventExtensionInterference(element) {
  if (!element) return;
  try {
    // Ensure control property exists to prevent "Cannot read properties of undefined" errors
    if (!element.control) {
      Object.defineProperty(element, 'control', {
        value: {
          type: element.type || 'textarea',
          name: element.name || 'filter-config-editor',
          form: null,
          autocomplete: 'off'
        },
        writable: false,
        enumerable: false,
        configurable: true
      });
    }
    Object.seal(element.control);
  } catch (e) { }
}
