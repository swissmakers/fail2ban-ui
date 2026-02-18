// Jail management functions for Fail2ban UI
"use strict";

// =========================================================================
//  Jail creation
// =========================================================================

function createJail() {
  const jailName = document.getElementById('newJailName').value.trim();
  const content = document.getElementById('newJailContent').value.trim();

  if (!jailName) {
    showToast('Jail name is required', 'error');
    return;
  }
  showLoading(true);
  fetch(withServerParam('/api/jails'), {
    method: 'POST',
    headers: serverHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      jailName: jailName,
      content: content
    })
  })
    .then(function(res) {
      if (!res.ok) {
        return res.json().then(function(data) {
          throw new Error(data.error || 'Server returned ' + res.status);
        });
      }
      return res.json();
    })
    .then(function(data) {
      if (data.error) {
        showToast('Error creating jail: ' + data.error, 'error');
        return;
      }
      closeModal('createJailModal');
      showToast(data.message || 'Jail created successfully', 'success');
      openManageJailsModal();
    })
    .catch(function(err) {
      console.error('Error creating jail:', err);
      showToast('Error creating jail: ' + (err.message || err), 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

// =========================================================================
//  Jail configuration saving
// =========================================================================  

function saveJailConfig() {
  if (!currentJailForConfig) return;
  showLoading(true);

  var filterConfig = document.getElementById('filterConfigTextarea').value;
  var jailConfig = document.getElementById('jailConfigTextarea').value;
  var url = '/api/jails/' + encodeURIComponent(currentJailForConfig) + '/config';
  fetch(withServerParam(url), {
    method: 'POST',
    headers: serverHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ filter: filterConfig, jail: jailConfig }),
  })
    .then(function(res) {
      if (!res.ok) {
        return res.json().then(function(data) {
          throw new Error(data.error || 'Server returned ' + res.status);
        });
      }
      return res.json();
    })
    .then(function(data) {
      if (data.error) {
        showToast("Error saving config: " + data.error, 'error');
        return;
      }
      closeModal('jailConfigModal');
      if (data.warning) {
        var warnMsg = t('filter_debug.save_reload_warning', 'Config saved, but fail2ban reload failed') + ': ' + data.warning;
        if (data.jailAutoDisabled && data.jailName) {
          warnMsg = (typeof t === 'function' ? t('filter_debug.jail_auto_disabled', "Jail '%s' was automatically disabled.").replace('%s', data.jailName) : "Jail '" + data.jailName + "' was automatically disabled.") + ' ' + warnMsg;
          var toggleId = 'toggle-' + data.jailName.replace(/[^a-zA-Z0-9]/g, '_');
          var cb = document.getElementById(toggleId);
          if (cb) cb.checked = false;
        }
        showToast(warnMsg, 'warning', 12000);
      } else {
        showToast(t('filter_debug.save_success', 'Filter and jail config saved and reloaded'), 'success');
      }
      return refreshData({ silent: true });
    })
    .catch(function(err) {
      console.error("Error saving config:", err);
      showToast("Error saving config: " + err.message, 'error');
    })
    .finally(function() {
      showLoading(false);
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

function saveManageJailsSingle(checkbox) {
  const item = checkbox.closest('div.flex.items-center.justify-between');
  if (!item) {
    console.error('Could not find parent container for checkbox');
    return;
  }

  const nameSpan = item.querySelector('span.text-sm.font-medium');
  if (!nameSpan) {
    console.error('Could not find jail name span');
    return;
  }

  const jailName = nameSpan.textContent.trim();
  if (!jailName) {
    console.error('Jail name is empty');
    return;
  }

  const isEnabled = checkbox.checked;
  const updatedJails = {};
  updatedJails[jailName] = isEnabled;

  console.log('Saving jail state:', jailName, 'enabled:', isEnabled, 'payload:', updatedJails);

  fetch(withServerParam('/api/jails/manage'), {
    method: 'POST',
    headers: serverHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(updatedJails),
  })
    .then(function(res) {
      if (!res.ok) {
        return res.json().then(function(data) {
          throw new Error(data.error || 'Server returned ' + res.status);
        });
      }
      return res.json();
    })
    .then(function(data) {
      if (data.error) {
        var errorMsg = data.error;
        var toastType = 'error';
        // If jails were auto-disabled, check if this jail was one of them
        var wasAutoDisabled = data.autoDisabled && data.enabledJails && Array.isArray(data.enabledJails) && data.enabledJails.indexOf(jailName) !== -1;

        if (wasAutoDisabled) {
          checkbox.checked = false;
          toastType = 'warning';
        } else {
          // Revert checkbox state if error occurs
          checkbox.checked = !isEnabled;
        }
        showToast(errorMsg, toastType, wasAutoDisabled ? 15000 : undefined);

        // Reload the jail list to reflect the actual state
        return fetch(withServerParam('/api/jails/manage'), {
          headers: serverHeaders()
        }).then(function(res) { return res.json(); })
        .then(function(data) {
          if (data.jails && data.jails.length) {
            const jail = data.jails.find(function(j) { return j.jailName === jailName; });
            if (jail) {
              checkbox.checked = jail.enabled;
            }
          }
          loadServers().then(function() {
            updateRestartBanner();
            return refreshData({ silent: true });
          });
        });
      }

      if (data.warning) {
        showToast(data.warning, 'warning');
      }

      console.log('Jail state saved successfully:', data);
      showToast(data.message || ('Jail ' + jailName + ' ' + (isEnabled ? 'enabled' : 'disabled') + ' successfully'), 'success');
      return fetch(withServerParam('/api/jails/manage'), {
        headers: serverHeaders()
      }).then(function(res) { return res.json(); })
      .then(function(data) {
        if (data.jails && data.jails.length) {
          const jail = data.jails.find(function(j) { return j.jailName === jailName; });
          if (jail) {
            checkbox.checked = jail.enabled;
          }
        }
        loadServers().then(function() {
          updateRestartBanner();
          return refreshData({ silent: true });
        });
      });
    })
    .catch(function(err) {
      console.error('Error saving jail settings:', err);
      showToast("Error saving jail settings: " + (err.message || err), 'error');
      checkbox.checked = !isEnabled;
    });
}

// =========================================================================
//  Jail deletion
// =========================================================================

function deleteJail(jailName) {
  if (!confirm('Are you sure you want to delete the jail "' + escapeHtml(jailName) + '"? This action cannot be undone.')) {
    return;
  }
  showLoading(true);
  fetch(withServerParam('/api/jails/' + encodeURIComponent(jailName)), {
    method: 'DELETE',
    headers: serverHeaders()
  })
    .then(function(res) {
      if (!res.ok) {
        return res.json().then(function(data) {
          throw new Error(data.error || 'Server returned ' + res.status);
        });
      }
      return res.json();
    })
    .then(function(data) {
      if (data.error) {
        showToast('Error deleting jail: ' + data.error, 'error');
        return;
      }
      showToast(data.message || 'Jail deleted successfully', 'success');
      openManageJailsModal();
      refreshData({ silent: true });
    })
    .catch(function(err) {
      console.error('Error deleting jail:', err);
      showToast('Error deleting jail: ' + (err.message || err), 'error');
    })
    .finally(function() {
      showLoading(false);
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
    // Check if the line starts with logpath =
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
    showToast('No logpath found in jail configuration. Please add a logpath line (e.g., logpath = /var/log/example.log)', 'warning');
    return;
  }
  var resultsDiv = document.getElementById('logpathResults');
  resultsDiv.textContent = 'Testing logpath...';
  resultsDiv.classList.remove('hidden');
  resultsDiv.classList.remove('text-red-600', 'text-yellow-600');
  showLoading(true);
  var url = '/api/jails/' + encodeURIComponent(currentJailForConfig) + '/logpath/test';
  fetch(withServerParam(url), {
    method: 'POST',
    headers: serverHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ logpath: logpath })
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      showLoading(false);
      if (data.error) {
        resultsDiv.textContent = 'Error: ' + data.error;
        resultsDiv.classList.add('text-red-600');
        setTimeout(function() {
          resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
        return;
      }
      var originalLogpath = data.original_logpath || '';
      var results = data.results || [];
      var isLocalServer = data.is_local_server || false;
      var output = '';

      if (results.length === 0) {
        output = '<div class="text-yellow-600">No logpath entries found.</div>';
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

        if (idx > 0) {
          output += '<div class="my-4 border-t border-gray-300 pt-4"></div>';
        }

        output += '<div class="mb-3">';
        output += '<div class="font-semibold text-gray-800 mb-1">Logpath ' + (idx + 1) + ':</div>';
        output += '<div class="ml-4 text-sm text-gray-600 font-mono">' + escapeHtml(logpath) + '</div>';

        if (resolvedPath && resolvedPath !== logpath) {
          output += '<div class="ml-4 text-xs text-gray-500 mt-1">Resolved: <span class="font-mono">' + escapeHtml(resolvedPath) + '</span></div>';
        }
        output += '</div>';
        output += '<div class="ml-4 mb-2">';
        output += '<div class="flex items-center gap-2">';
        if (isLocalServer) {
          output += '<span class="font-medium text-sm">In fail2ban-ui Container:</span>';
        } else {
          output += '<span class="font-medium text-sm">On Remote Server:</span>';
        }
        if (error) {
          output += '<span class="text-red-600 font-bold">✗</span>';
          output += '<span class="text-red-600 text-sm">Error: ' + escapeHtml(error) + '</span>';
        } else if (found) {
          output += '<span class="text-green-600 font-bold">✓</span>';
          output += '<span class="text-green-600 text-sm">Found ' + files.length + ' file(s)</span>';
        } else {
          output += '<span class="text-red-600 font-bold">✗</span>';
          if (isLocalServer) {
            output += '<span class="text-red-600 text-sm">Not found (logs may not be mounted to container)</span>';
          } else {
            output += '<span class="text-red-600 text-sm">Not found</span>';
          }
        }
        output += '</div>';
        if (files.length > 0) {
          output += '<div class="ml-6 mt-1 text-xs text-gray-600">';
          files.forEach(function(file) {
            output += '<div class="font-mono">  • ' + escapeHtml(file) + '</div>';
          });
          output += '</div>';
        }
        output += '</div>';
      });

      var allFound = results.every(function(r) { return r.found; });
      var anyFound = results.some(function(r) { return r.found; });

      if (allFound) {
        resultsDiv.classList.remove('text-red-600', 'text-yellow-600');
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
      resultsDiv.textContent = 'Error: ' + err;
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
