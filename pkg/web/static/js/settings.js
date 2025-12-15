// Settings page functions for Fail2ban UI
"use strict";

// Handle GeoIP provider change
function onGeoIPProviderChange(provider) {
  const dbPathContainer = document.getElementById('geoipDatabasePathContainer');
  if (dbPathContainer) {
    if (provider === 'maxmind') {
      dbPathContainer.style.display = 'block';
    } else {
      dbPathContainer.style.display = 'none';
    }
  }
}

function loadSettings() {
  showLoading(true);
  fetch('/api/settings')
    .then(res => res.json())
    .then(data => {
      document.getElementById('languageSelect').value = data.language || 'en';
      
      // Handle PORT environment variable
      const uiPortInput = document.getElementById('uiPort');
      const portEnvHint = document.getElementById('portEnvHint');
      const portEnvValue = document.getElementById('portEnvValue');
      const portRestartHint = document.getElementById('portRestartHint');
      
      if (data.portEnvSet) {
        // PORT env is set - make field readonly and show hint
        uiPortInput.value = data.port || data.portFromEnv || 8080;
        uiPortInput.readOnly = true;
        uiPortInput.classList.add('bg-gray-100', 'cursor-not-allowed');
        portEnvValue.textContent = data.portFromEnv || data.port || 8080;
        portEnvHint.style.display = 'block';
        portRestartHint.style.display = 'none';
      } else {
        // PORT env not set - allow editing
        uiPortInput.value = data.port || 8080;
        uiPortInput.readOnly = false;
        uiPortInput.classList.remove('bg-gray-100', 'cursor-not-allowed');
        portEnvHint.style.display = 'none';
        portRestartHint.style.display = 'block';
      }
      
      document.getElementById('debugMode').checked = data.debug || false;
      
      // Set callback URL and add auto-update listener for port changes
      const callbackURLInput = document.getElementById('callbackURL');
      callbackURLInput.value = data.callbackUrl || '';
      
      // Auto-update callback URL when port changes (if using default localhost pattern)
      function updateCallbackURLIfDefault() {
        const currentPort = parseInt(uiPortInput.value, 10) || 8080;
        const currentCallbackURL = callbackURLInput.value.trim();
        // Check if callback URL matches default localhost pattern
        const defaultPattern = /^http:\/\/127\.0\.0\.1:\d+$/;
        if (currentCallbackURL === '' || defaultPattern.test(currentCallbackURL)) {
          callbackURLInput.value = 'http://127.0.0.1:' + currentPort;
        }
      }
      
      // Add listener to port input to auto-update callback URL
      uiPortInput.addEventListener('input', updateCallbackURLIfDefault);

      document.getElementById('destEmail').value = data.destemail || '';

      const select = document.getElementById('alertCountries');
      for (let i = 0; i < select.options.length; i++) {
        select.options[i].selected = false;
      }
      if (!data.alertCountries || data.alertCountries.length === 0) {
        select.options[0].selected = true;
      } else {
        for (let i = 0; i < select.options.length; i++) {
          let val = select.options[i].value;
          if (data.alertCountries.includes(val)) {
            select.options[i].selected = true;
          }
        }
      }
      $('#alertCountries').trigger('change');
      
      // Check and apply LOTR theme
      checkAndApplyLOTRTheme(data.alertCountries || []);

      if (data.smtp) {
        document.getElementById('smtpHost').value = data.smtp.host || '';
        document.getElementById('smtpPort').value = data.smtp.port || 587;
        document.getElementById('smtpUsername').value = data.smtp.username || '';
        document.getElementById('smtpPassword').value = data.smtp.password || '';
        document.getElementById('smtpFrom').value = data.smtp.from || '';
        document.getElementById('smtpUseTLS').checked = data.smtp.useTLS || false;
      }

      document.getElementById('bantimeIncrement').checked = data.bantimeIncrement || false;
      document.getElementById('defaultJailEnable').checked = data.defaultJailEnable || false;
      
      // GeoIP settings
      const geoipProvider = data.geoipProvider || 'builtin';
      document.getElementById('geoipProvider').value = geoipProvider;
      onGeoIPProviderChange(geoipProvider);
      document.getElementById('geoipDatabasePath').value = data.geoipDatabasePath || '/usr/share/GeoIP/GeoLite2-Country.mmdb';
      document.getElementById('maxLogLines').value = data.maxLogLines || 50;
      document.getElementById('banTime').value = data.bantime || '';
      document.getElementById('findTime').value = data.findtime || '';
      document.getElementById('maxRetry').value = data.maxretry || '';
      // Load IgnoreIPs as array
      const ignoreIPs = data.ignoreips || [];
      renderIgnoreIPsTags(ignoreIPs);
      
      // Load banaction settings
      document.getElementById('banaction').value = data.banaction || 'iptables-multiport';
      document.getElementById('banactionAllports').value = data.banactionAllports || 'iptables-allports';

      applyAdvancedActionsSettings(data.advancedActions || {});
      loadPermanentBlockLog();
    })
    .catch(err => {
      showToast('Error loading settings: ' + err, 'error');
    })
    .finally(() => showLoading(false));
}

function saveSettings(event) {
  event.preventDefault();
  
  // Validate all fields before submitting
  if (!validateAllSettings()) {
    showToast('Please fix validation errors before saving', 'error');
    return;
  }
  
  showLoading(true);
  
  const smtpSettings = {
    host: document.getElementById('smtpHost').value.trim(),
    port: parseInt(document.getElementById('smtpPort').value, 10) || 587,
    username: document.getElementById('smtpUsername').value.trim(),
    password: document.getElementById('smtpPassword').value.trim(),
    from: document.getElementById('smtpFrom').value.trim(),
    useTLS: document.getElementById('smtpUseTLS').checked,
  };

  const selectedCountries = Array.from(document.getElementById('alertCountries').selectedOptions).map(opt => opt.value);

  // Auto-update callback URL if using default localhost pattern and port changed
  const callbackURLInput = document.getElementById('callbackURL');
  let callbackUrl = callbackURLInput.value.trim();
  const currentPort = parseInt(document.getElementById('uiPort').value, 10) || 8080;
  const defaultPattern = /^http:\/\/127\.0\.0\.1:\d+$/;
  if (callbackUrl === '' || defaultPattern.test(callbackUrl)) {
    callbackUrl = 'http://127.0.0.1:' + currentPort;
  }
  
  const settingsData = {
    language: document.getElementById('languageSelect').value,
    port: currentPort,
    debug: document.getElementById('debugMode').checked,
    destemail: document.getElementById('destEmail').value.trim(),
    callbackUrl: callbackUrl,
    alertCountries: selectedCountries.length > 0 ? selectedCountries : ["ALL"],
    bantimeIncrement: document.getElementById('bantimeIncrement').checked,
    defaultJailEnable: document.getElementById('defaultJailEnable').checked,
    bantime: document.getElementById('banTime').value.trim(),
    findtime: document.getElementById('findTime').value.trim(),
    maxretry: parseInt(document.getElementById('maxRetry').value, 10) || 3,
    ignoreips: getIgnoreIPsArray(),
    banaction: document.getElementById('banaction').value,
    banactionAllports: document.getElementById('banactionAllports').value,
    geoipProvider: document.getElementById('geoipProvider').value || 'builtin',
    geoipDatabasePath: document.getElementById('geoipDatabasePath').value || '/usr/share/GeoIP/GeoLite2-Country.mmdb',
    maxLogLines: parseInt(document.getElementById('maxLogLines').value, 10) || 50,
    smtp: smtpSettings,
    advancedActions: collectAdvancedActionsSettings()
  };

  fetch('/api/settings', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(settingsData),
  })
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        showToast('Error saving settings: ' + (data.error + (data.details || '')), 'error');
      } else {
        var selectedLang = $('#languageSelect').val();
        loadTranslations(selectedLang);
        console.log("Settings saved successfully. Restart needed? " + (data.restartNeeded || false));
        
        // Check and apply LOTR theme after saving
        const selectedCountries = Array.from(document.getElementById('alertCountries').selectedOptions).map(opt => opt.value);
        checkAndApplyLOTRTheme(selectedCountries.length > 0 ? selectedCountries : ["ALL"]);
        
        if (data.restartNeeded) {
          showToast(t('settings.save_success', 'Settings saved. Fail2ban restart required.'), 'info');
          loadServers().then(function() {
            updateRestartBanner();
          });
        } else {
          showToast(t('settings.save_success', 'Settings saved and fail2ban reloaded'), 'success');
        }
      }
    })
    .catch(err => showToast('Error saving settings: ' + err, 'error'))
    .finally(() => showLoading(false));
}

function sendTestEmail() {
  showLoading(true);

  fetch('/api/settings/test-email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  })
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        showToast('Error sending test email: ' + data.error, 'error');
      } else {
        showToast('Test email sent successfully!', 'success');
      }
    })
    .catch(error => showToast('Error sending test email: ' + error, 'error'))
    .finally(() => showLoading(false));
}

function applyAdvancedActionsSettings(cfg) {
  cfg = cfg || {};
  document.getElementById('advancedActionsEnabled').checked = !!cfg.enabled;
  document.getElementById('advancedThreshold').value = cfg.threshold || 5;
  const integrationSelect = document.getElementById('advancedIntegrationSelect');
  integrationSelect.value = cfg.integration || '';

  const mk = cfg.mikrotik || {};
  document.getElementById('mikrotikHost').value = mk.host || '';
  document.getElementById('mikrotikPort').value = mk.port || 22;
  document.getElementById('mikrotikUsername').value = mk.username || '';
  document.getElementById('mikrotikPassword').value = mk.password || '';
  document.getElementById('mikrotikSSHKey').value = mk.sshKeyPath || '';
  document.getElementById('mikrotikList').value = mk.addressList || 'fail2ban-permanent';

  const pf = cfg.pfSense || {};
  document.getElementById('pfSenseBaseURL').value = pf.baseUrl || '';
  document.getElementById('pfSenseToken').value = pf.apiToken || '';
  document.getElementById('pfSenseSecret').value = pf.apiSecret || '';
  document.getElementById('pfSenseAlias').value = pf.alias || '';
  document.getElementById('pfSenseSkipTLS').checked = !!pf.skipTLSVerify;

  updateAdvancedIntegrationFields();
}

function collectAdvancedActionsSettings() {
  return {
    enabled: document.getElementById('advancedActionsEnabled').checked,
    threshold: parseInt(document.getElementById('advancedThreshold').value, 10) || 5,
    integration: document.getElementById('advancedIntegrationSelect').value,
    mikrotik: {
      host: document.getElementById('mikrotikHost').value.trim(),
      port: parseInt(document.getElementById('mikrotikPort').value, 10) || 22,
      username: document.getElementById('mikrotikUsername').value.trim(),
      password: document.getElementById('mikrotikPassword').value,
      sshKeyPath: document.getElementById('mikrotikSSHKey').value.trim(),
      addressList: document.getElementById('mikrotikList').value.trim() || 'fail2ban-permanent',
    },
    pfSense: {
      baseUrl: document.getElementById('pfSenseBaseURL').value.trim(),
      apiToken: document.getElementById('pfSenseToken').value.trim(),
      apiSecret: document.getElementById('pfSenseSecret').value.trim(),
      alias: document.getElementById('pfSenseAlias').value.trim(),
      skipTLSVerify: document.getElementById('pfSenseSkipTLS').checked,
    }
  };
}

function updateAdvancedIntegrationFields() {
  const selected = document.getElementById('advancedIntegrationSelect').value;
  document.getElementById('advancedMikrotikFields').classList.toggle('hidden', selected !== 'mikrotik');
  document.getElementById('advancedPfSenseFields').classList.toggle('hidden', selected !== 'pfsense');
}

function loadPermanentBlockLog() {
  fetch('/api/advanced-actions/blocks')
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        showToast('Error loading permanent block log: ' + data.error, 'error');
        return;
      }
      renderPermanentBlockLog(data.blocks || []);
    })
    .catch(err => {
      showToast('Error loading permanent block log: ' + err, 'error');
    });
}

function renderPermanentBlockLog(blocks) {
  const container = document.getElementById('permanentBlockLog');
  if (!container) return;
  if (!blocks.length) {
    container.innerHTML = '<p class="text-sm text-gray-500 p-4" data-i18n="settings.advanced.log_empty">No permanent blocks recorded yet.</p>';
    if (typeof updateTranslations === 'function') updateTranslations();
    return;
  }
  let rows = blocks.map(block => {
    const statusClass = block.status === 'blocked'
      ? 'text-green-600'
      : (block.status === 'unblocked' ? 'text-gray-500' : 'text-red-600');
    const message = block.message ? escapeHtml(block.message) : '';
    return ''
      + '<tr class="border-t">'
      + '  <td class="px-3 py-2 font-mono text-sm">' + escapeHtml(block.ip) + '</td>'
      + '  <td class="px-3 py-2 text-sm">' + escapeHtml(block.integration) + '</td>'
      + '  <td class="px-3 py-2 text-sm ' + statusClass + '">' + escapeHtml(block.status) + '</td>'
      + '  <td class="px-3 py-2 text-sm">' + (message || '&nbsp;') + '</td>'
      + '  <td class="px-3 py-2 text-xs text-gray-500">' + escapeHtml(block.serverId || '') + '</td>'
      + '  <td class="px-3 py-2 text-xs text-gray-500">' + (block.updatedAt ? new Date(block.updatedAt).toLocaleString() : '') + '</td>'
      + '  <td class="px-3 py-2 text-right">'
      + '    <button type="button" class="text-sm text-blue-600 hover:text-blue-800" onclick="advancedUnblockIP(\'' + escapeHtml(block.ip) + '\', event)" data-i18n="settings.advanced.unblock_btn">Remove</button>'
      + '  </td>'
      + '</tr>';
  }).join('');
  container.innerHTML = ''
    + '<table class="min-w-full text-sm">'
    + '  <thead class="bg-gray-50 text-left">'
    + '    <tr>'
    + '      <th class="px-3 py-2" data-i18n="settings.advanced.log_ip">IP</th>'
    + '      <th class="px-3 py-2" data-i18n="settings.advanced.log_integration">Integration</th>'
    + '      <th class="px-3 py-2" data-i18n="settings.advanced.log_status">Status</th>'
    + '      <th class="px-3 py-2" data-i18n="settings.advanced.log_message">Message</th>'
    + '      <th class="px-3 py-2" data-i18n="settings.advanced.log_server">Server</th>'
    + '      <th class="px-3 py-2" data-i18n="settings.advanced.log_updated">Updated</th>'
    + '      <th class="px-3 py-2 text-right" data-i18n="settings.advanced.log_actions">Actions</th>'
    + '    </tr>'
    + '  </thead>'
    + '  <tbody>' + rows + '</tbody>'
    + '</table>';
  if (typeof updateTranslations === 'function') updateTranslations();
}

function refreshPermanentBlockLog() {
  loadPermanentBlockLog();
}

function openAdvancedTestModal() {
  populateAdvancedTestServers();
  document.getElementById('advancedTestIP').value = '';
  document.getElementById('advancedTestServer').value = '';
  openModal('advancedTestModal');
}

function populateAdvancedTestServers() {
  const select = document.getElementById('advancedTestServer');
  if (!select) return;
  const value = select.value;
  select.innerHTML = '';
  const baseOption = document.createElement('option');
  baseOption.value = '';
  baseOption.textContent = t('settings.advanced.test_server_none', 'Use global integration settings');
  select.appendChild(baseOption);
  serversCache.forEach(server => {
    const opt = document.createElement('option');
    opt.value = server.id;
    opt.textContent = server.name || server.id;
    select.appendChild(opt);
  });
  select.value = value;
}

function submitAdvancedTest(action) {
  const ipValue = document.getElementById('advancedTestIP').value.trim();
  if (!ipValue) {
    showToast('Please enter an IP address.', 'info');
    return;
  }
  const serverId = document.getElementById('advancedTestServer').value;
  showLoading(true);
  fetch('/api/advanced-actions/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: action, ip: ipValue, serverId: serverId })
  })
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        showToast('Advanced action failed: ' + data.error, 'error');
      } else {
        // Check if this is an info message (e.g., IP already blocked)
        const toastType = data.info ? 'info' : 'success';
        showToast(data.message || 'Action completed', toastType);
        loadPermanentBlockLog();
      }
    })
    .catch(err => showToast('Advanced action failed: ' + err, 'error'))
    .finally(() => {
      showLoading(false);
      closeModal('advancedTestModal');
    });
}

function advancedUnblockIP(ip, event) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  if (!ip) return;
  fetch('/api/advanced-actions/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'unblock', ip: ip })
  })
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        showToast('Failed to remove IP: ' + data.error, 'error');
      } else {
        showToast(data.message || 'IP removed', 'success');
        loadPermanentBlockLog();
      }
    })
    .catch(err => showToast('Failed to remove IP: ' + err, 'error'));
}

// Initialize advanced integration select listener
const advancedIntegrationSelect = document.getElementById('advancedIntegrationSelect');
if (advancedIntegrationSelect) {
  advancedIntegrationSelect.addEventListener('change', updateAdvancedIntegrationFields);
}

