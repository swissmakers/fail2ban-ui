// Jail management functions for Fail2ban UI
"use strict";

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
    // Prevent extensions from adding their own properties
    Object.seal(element.control);
  } catch (e) {
    // Silently ignore errors
  }
}

function openJailConfigModal(jailName) {
  currentJailForConfig = jailName;
  var filterTextArea = document.getElementById('filterConfigTextarea');
  var jailTextArea = document.getElementById('jailConfigTextarea');
  filterTextArea.value = '';
  jailTextArea.value = '';

  // Prevent browser extensions from interfering
  preventExtensionInterference(filterTextArea);
  preventExtensionInterference(jailTextArea);

  document.getElementById('modalJailName').textContent = jailName;

  // Hide test logpath section initially
  document.getElementById('testLogpathSection').classList.add('hidden');
  document.getElementById('logpathResults').classList.add('hidden');

  showLoading(true);
  var url = '/api/jails/' + encodeURIComponent(jailName) + '/config';
  fetch(withServerParam(url), {
    headers: serverHeaders()
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        showToast("Error loading config: " + data.error, 'error');
        return;
      }
      filterTextArea.value = data.filter || '';
      jailTextArea.value = data.jailConfig || '';
      
      // Display file paths if available
      var filterFilePathEl = document.getElementById('filterFilePath');
      var jailFilePathEl = document.getElementById('jailFilePath');
      if (filterFilePathEl && data.filterFilePath) {
        filterFilePathEl.textContent = data.filterFilePath;
        filterFilePathEl.style.display = 'block';
      } else if (filterFilePathEl) {
        filterFilePathEl.style.display = 'none';
      }
      if (jailFilePathEl && data.jailFilePath) {
        jailFilePathEl.textContent = data.jailFilePath;
        jailFilePathEl.style.display = 'block';
      } else if (jailFilePathEl) {
        jailFilePathEl.style.display = 'none';
      }

      // Check if logpath is set in jail config and show test button
      updateLogpathButtonVisibility();
      
      // Add listener to update button visibility when jail config changes
      jailTextArea.addEventListener('input', updateLogpathButtonVisibility);
      
      // Prevent extension interference before opening modal
      preventExtensionInterference(filterTextArea);
      preventExtensionInterference(jailTextArea);
      openModal('jailConfigModal');
      
      // Setup syntax highlighting for both textareas after modal is visible
      setTimeout(function() {
        preventExtensionInterference(filterTextArea);
        preventExtensionInterference(jailTextArea);
      }, 200);
    })
    .catch(function(err) {
      showToast("Error: " + err, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

function updateLogpathButtonVisibility() {
  var jailTextArea = document.getElementById('jailConfigTextarea');
  var jailConfig = jailTextArea ? jailTextArea.value : '';
  var hasLogpath = /logpath\s*=/i.test(jailConfig);
  var testSection = document.getElementById('testLogpathSection');
  if (hasLogpath && testSection) {
    testSection.classList.remove('hidden');
  } else if (testSection) {
    testSection.classList.add('hidden');
    document.getElementById('logpathResults').classList.add('hidden');
  }
}

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
      showToast(t('filter_debug.save_success', 'Filter and jail config saved and reloaded'), 'success');
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

// Extract logpath from jail config text
function extractLogpathFromConfig(configText) {
  if (!configText) return '';
  
  // Match logpath = value (handles various formats)
  var logpathMatch = configText.match(/^logpath\s*=\s*(.+)$/im);
  if (logpathMatch && logpathMatch[1]) {
    // Trim whitespace and remove quotes if present
    var logpath = logpathMatch[1].trim();
    // Remove surrounding quotes
    logpath = logpath.replace(/^["']|["']$/g, '');
    return logpath;
  }
  return '';
}

function testLogpath() {
  if (!currentJailForConfig) return;
  
  // Extract logpath from the textarea
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
        // Auto-scroll to results
        setTimeout(function() {
          resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
        return;
      }
      
      var originalLogpath = data.original_logpath || '';
      var resolvedLogpath = data.resolved_logpath || '';
      var files = data.files || [];
      
      // Build output message with better formatting
      var output = '';
      
      // Show original logpath
      if (originalLogpath) {
        output += 'Logpath:\n  ' + originalLogpath + '\n\n';
      }
      
      // Show resolved logpath if different from original
      if (resolvedLogpath && resolvedLogpath !== originalLogpath) {
        output += 'Resolved logpath:\n  ' + resolvedLogpath + '\n\n';
      } else if (resolvedLogpath) {
        //output += 'Logpath:\n  ' + resolvedLogpath + '\n\n';
      }
      
      // Show files found with better formatting
      if (files.length === 0) {
        output += 'No files found matching the logpath pattern.';
        resultsDiv.classList.remove('text-red-600');
        resultsDiv.classList.add('text-yellow-600');
      } else {
        output += 'Found ' + files.length + ' file(s):\n\n';
        files.forEach(function(file, index) {
          output += '  ' + (index + 1) + '. ' + file + '\n';
        });
        resultsDiv.classList.remove('text-red-600', 'text-yellow-600');
      }
      
      // Use textContent for plain text, but we could also use innerHTML for better formatting
      resultsDiv.textContent = output;
      
      // Auto-scroll to results
      setTimeout(function() {
        resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }, 100);
    })
    .catch(function(err) {
      showLoading(false);
      resultsDiv.textContent = 'Error: ' + err;
      resultsDiv.classList.add('text-red-600');
      // Auto-scroll to results
      setTimeout(function() {
        resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }, 100);
    });
}

function openManageJailsModal() {
  if (!currentServerId) {
    showToast(t('servers.selector.none', 'Please add and select a Fail2ban server first.'), 'info');
    return;
  }
  showLoading(true);
  fetch(withServerParam('/api/jails/manage'), {
    headers: serverHeaders()
  })
    .then(res => res.json())
    .then(data => {
      if (!data.jails || !data.jails.length) {
        showToast("No jails found for this server.", 'info');
        return;
      }

      const html = data.jails.map(jail => {
        const isEnabled = jail.enabled ? 'checked' : '';
        const escapedJailName = escapeHtml(jail.jailName);
        // Escape single quotes for JavaScript string
        const jsEscapedJailName = jail.jailName.replace(/'/g, "\\'");
        return ''
          + '<div class="flex items-center justify-between gap-3 p-3 bg-gray-50">'
          + '  <span class="text-sm font-medium flex-1 text-gray-900">' + escapedJailName + '</span>'
          + '  <div class="flex items-center gap-3">'
          + '    <button'
          + '      type="button"'
          + '      onclick="openJailConfigModal(\'' + jsEscapedJailName + '\')"'
          + '      class="text-xs px-3 py-1.5 bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors whitespace-nowrap"'
          + '      data-i18n="modal.filter_config_edit"'
          + '      title="' + escapeHtml(t('modal.filter_config_edit', 'Edit Filter / Jail')) + '"'
          + '    >'
          + escapeHtml(t('modal.filter_config_edit', 'Edit Filter / Jail'))
          + '    </button>'
          + '    <button'
          + '      type="button"'
          + '      onclick="deleteJail(\'' + jsEscapedJailName + '\')"'
          + '      class="text-xs px-3 py-1.5 bg-red-500 text-white rounded hover:bg-red-600 transition-colors whitespace-nowrap"'
          + '      title="' + escapeHtml(t('modal.delete_jail', 'Delete Jail')) + '"'
          + '    >'
          + '      <i class="fas fa-trash"></i>'
          + '    </button>'
          + '    <label class="inline-flex relative items-center cursor-pointer">'
          + '      <input'
          + '        type="checkbox"'
          + '        id="toggle-' + jail.jailName.replace(/[^a-zA-Z0-9]/g, '_') + '"'
          + '        class="sr-only peer"'
          + isEnabled
          + '      />'
          + '      <div'
          + '        class="w-11 h-6 bg-gray-200 rounded-full peer-focus:ring-4 peer-focus:ring-blue-300 peer-checked:bg-blue-600 transition-colors"'
          + '      ></div>'
          + '      <span'
          + '        class="absolute left-1 top-1/2 -translate-y-1/2 bg-white w-4 h-4 rounded-full transition-transform peer-checked:translate-x-5"'
          + '      ></span>'
          + '    </label>'
          + '  </div>'
          + '</div>';
      }).join('');

      document.getElementById('jailsList').innerHTML = html;
      
      // Add auto-save on checkbox change with debouncing
      let saveTimeout;
      document.querySelectorAll('#jailsList input[type="checkbox"]').forEach(function(checkbox) {
        checkbox.addEventListener('change', function() {
          // Clear any pending save
          if (saveTimeout) {
            clearTimeout(saveTimeout);
          }
          
          // Debounce save by 300ms
          saveTimeout = setTimeout(function() {
            saveManageJailsSingle(checkbox);
          }, 300);
        });
      });
      
      openModal('manageJailsModal');
    })
    .catch(err => showToast("Error fetching jails: " + err, 'error'))
    .finally(() => showLoading(false));
}

function saveManageJailsSingle(checkbox) {
  // Find the parent container div
  const item = checkbox.closest('div.flex.items-center.justify-between');
  if (!item) {
    console.error('Could not find parent container for checkbox');
    return;
  }
  
  // Get jail name from the span - it's the first span with text-sm font-medium class
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

  // Send updated state to the API endpoint /api/jails/manage.
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
      // Check if there was an error (including auto-disabled jails)
      if (data.error) {
        var errorMsg = data.error;
        var toastType = 'error';
        
        // If jails were auto-disabled, check if this jail was one of them
        var wasAutoDisabled = data.autoDisabled && data.enabledJails && Array.isArray(data.enabledJails) && data.enabledJails.indexOf(jailName) !== -1;
        
        if (wasAutoDisabled) {
          checkbox.checked = false;
          toastType = 'warning';
          // Use the message if available, otherwise use the error
          errorMsg = data.message || errorMsg;
        } else {
          // Revert checkbox state on error
          checkbox.checked = !isEnabled;
        }
        
        showToast(errorMsg, toastType);
        
        // Still reload the jail list to reflect the actual state
        return fetch(withServerParam('/api/jails/manage'), {
          headers: serverHeaders()
        }).then(function(res) { return res.json(); })
        .then(function(data) {
          if (data.jails && data.jails.length) {
            // Update the checkbox state based on server response
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
      
      // Check for warning (legacy support)
      if (data.warning) {
        showToast(data.warning, 'warning');
      }
      
      console.log('Jail state saved successfully:', data);
      // Show success toast
      showToast(data.message || ('Jail ' + jailName + ' ' + (isEnabled ? 'enabled' : 'disabled') + ' successfully'), 'success');
      // Reload the jail list to reflect the actual state
      return fetch(withServerParam('/api/jails/manage'), {
        headers: serverHeaders()
      }).then(function(res) { return res.json(); })
      .then(function(data) {
        if (data.jails && data.jails.length) {
          // Update the checkbox state based on server response
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
      // Revert checkbox state on error
      checkbox.checked = !isEnabled;
    });
}

function openCreateJailModal() {
  document.getElementById('newJailName').value = '';
  document.getElementById('newJailContent').value = '';
  const filterSelect = document.getElementById('newJailFilter');
  if (filterSelect) {
    filterSelect.value = '';
  }
  
  // Load filters into dropdown
  showLoading(true);
  fetch(withServerParam('/api/filters'), {
    headers: serverHeaders()
  })
    .then(res => res.json())
    .then(data => {
      if (filterSelect) {
        filterSelect.innerHTML = '<option value="">-- Select a filter --</option>';
        if (data.filters && data.filters.length > 0) {
          data.filters.forEach(filter => {
            const opt = document.createElement('option');
            opt.value = filter;
            opt.textContent = filter;
            filterSelect.appendChild(opt);
          });
        }
      }
      openModal('createJailModal');
    })
    .catch(err => {
      console.error('Error loading filters:', err);
      openModal('createJailModal');
    })
    .finally(() => showLoading(false));
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
  
  // Auto-fill jail name if empty
  if (jailNameInput && !jailNameInput.value.trim()) {
    jailNameInput.value = selectedFilter;
  }
  
  // Auto-populate jail config
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
      // Reload the manage jails modal
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
      // Reload the manage jails modal
      openManageJailsModal();
      // Refresh dashboard
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

