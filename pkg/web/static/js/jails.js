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

function testLogpath() {
  if (!currentJailForConfig) return;
  
  var resultsDiv = document.getElementById('logpathResults');
  resultsDiv.textContent = 'Testing logpath...';
  resultsDiv.classList.remove('hidden');
  resultsDiv.classList.remove('text-red-600', 'text-yellow-600');
  
  showLoading(true);
  var url = '/api/jails/' + encodeURIComponent(currentJailForConfig) + '/logpath/test';
  fetch(withServerParam(url), {
    method: 'POST',
    headers: serverHeaders({ 'Content-Type': 'application/json' }),
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      showLoading(false);
      if (data.error) {
        resultsDiv.textContent = 'Error: ' + data.error;
        resultsDiv.classList.add('text-red-600');
        return;
      }
      
      var files = data.files || [];
      if (files.length === 0) {
        resultsDiv.textContent = 'No files found for logpath: ' + (data.logpath || 'N/A');
        resultsDiv.classList.remove('text-red-600');
        resultsDiv.classList.add('text-yellow-600');
      } else {
        resultsDiv.textContent = 'Found ' + files.length + ' file(s):\n' + files.join('\n');
        resultsDiv.classList.remove('text-red-600', 'text-yellow-600');
      }
    })
    .catch(function(err) {
      showLoading(false);
      resultsDiv.textContent = 'Error: ' + err;
      resultsDiv.classList.add('text-red-600');
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
          + '  <span class="text-sm font-medium flex-1">' + escapedJailName + '</span>'
          + '  <div class="flex items-center gap-3">'
          + '    <button'
          + '      type="button"'
          + '      onclick="openJailConfigModal(\'' + jsEscapedJailName + '\')"'
          + '      class="text-xs px-3 py-1.5 bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors whitespace-nowrap"'
          + '      data-i18n="modal.filter_config_edit"'
          + '      title="' + escapeHtml(t('modal.filter_config_edit', 'Edit Filter')) + '"'
          + '    >'
          + escapeHtml(t('modal.filter_config_edit', 'Edit Filter'))
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
          + '        class="absolute left-1 top-1 bg-white w-4 h-4 rounded-full transition-transform peer-checked:translate-x-5"'
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
      if (data.error) {
        showToast("Error saving jail settings: " + data.error, 'error');
        // Revert checkbox state on error
        checkbox.checked = !isEnabled;
        return;
      }
      console.log('Jail state saved successfully:', data);
      // Show success toast
      showToast('Jail ' + jailName + ' ' + (isEnabled ? 'enabled' : 'disabled') + ' successfully', 'success');
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

