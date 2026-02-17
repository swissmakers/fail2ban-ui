// App bootstrap and initialization.
"use strict";

// =========================================================================
//  Bootstrap
// =========================================================================

window.addEventListener('DOMContentLoaded', function() {
  showLoading(true);
  if (typeof checkAuthStatus === 'function') {
    checkAuthStatus().then(function(authStatus) {
      if (!authStatus.enabled || authStatus.authenticated) {
        initializeApp();
      } else {
        showLoading(false);
      }
    }).catch(function(err) {
      console.error('Auth check failed:', err);
      initializeApp();
    });
  } else {
    initializeApp();
  }
});

// =========================================================================
//  App Initialization
// =========================================================================

function initializeApp() {
  if (document.getElementById('external-ip')) {
    displayExternalIP();
  }
  if (typeof initHeader === 'function') {
    initHeader();
  }

  // Initialize WebSocket connection and register ban event handler
  function registerBanEventHandler() {
    if (typeof wsManager !== 'undefined' && wsManager) {
      wsManager.onBanEvent(function(event) {
        if (typeof addBanEventFromWebSocket === 'function') {
          addBanEventFromWebSocket(event);
        }
      });
      return true;
    }
    return false;
  }

  if (!registerBanEventHandler()) {
    var wsCheckInterval = setInterval(function() {
      if (registerBanEventHandler()) {
        clearInterval(wsCheckInterval);
      }
    }, 100);
    setTimeout(function() {
      clearInterval(wsCheckInterval);
    }, 5000);
  }

  fetch('/api/settings')
    .then(res => res.json())
    .then(data => {
      const alertCountries = data.alertCountries || [];
      if (typeof checkAndApplyLOTRTheme === 'function') {
        checkAndApplyLOTRTheme(alertCountries);
      }
      if (typeof currentSettings === 'undefined') {
        window.currentSettings = {};
      }
      window.currentSettings.alertCountries = alertCountries;
    })
    .catch(err => {
      console.warn('Could not check LOTR on load:', err);
    });

  // Check for updates and display version badge in the footer
  var versionContainer = document.getElementById('version-badge-container');
  if (versionContainer && versionContainer.getAttribute('data-update-check') === 'true') {
    fetch('/api/version')
      .then(function(res) { return res.json(); })
      .then(function(data) {
        if (!data.update_check_enabled || versionContainer.innerHTML) return;
        var latestLabel = typeof t === 'function' ? t('footer.latest', 'Latest') : 'Latest';
        var updateHint = (typeof t === 'function' && translations && translations['footer.update_available'])
          ? translations['footer.update_available'].replace('{version}', data.latest_version || '')
          : ('Update available: v' + (data.latest_version || ''));
        if (data.update_available && data.latest_version) {
          versionContainer.innerHTML = '<a href="https://github.com/swissmakers/fail2ban-ui/releases" target="_blank" rel="noopener" class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-800 hover:bg-amber-200" title="' + updateHint + '">' + updateHint + '</a>';
        } else {
          versionContainer.innerHTML = '<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800" title="' + latestLabel + '">' + latestLabel + '</span>';
        }
      })
      .catch(function() { });
  }

  // Load servers and translations, then render the dashboard and initialize tooltips and search
  Promise.all([
    loadServers(),
    getTranslationsSettingsOnPageload()
  ])
    .then(function() {
      updateRestartBanner();
      if (typeof refreshData === 'function') {
        return refreshData({ silent: true });
      }
    })
    .catch(function(err) {
      console.error('Initialization error:', err);
      latestSummaryError = err ? err.toString() : 'failed to initialize';
      if (typeof renderDashboard === 'function') {
        renderDashboard();
      }
    })
    .finally(function() {
      initializeTooltips();
      initializeSearch();
      showLoading(false);
    });

  // jQuery-dependent setup (Select2 for alert countries)
  $(document).ready(function() {
    $('#alertCountries').select2({
      placeholder: 'Select countries..',
      allowClear: true,
      width: '100%'
    });

    // When "ALL" is selected, deselect other countries and vice versa
    $('#alertCountries').on('select2:select', function(e) {
      var selectedValue = e.params.data.id;
      var currentValues = $('#alertCountries').val() || [];
      if (selectedValue === 'ALL') {
        if (currentValues.length > 1) {
          $('#alertCountries').val(['ALL']).trigger('change');
        }
      } else {
        if (currentValues.indexOf('ALL') !== -1) {
          var newValues = currentValues.filter(function(value) {
            return value !== 'ALL';
          });
          $('#alertCountries').val(newValues).trigger('change');
        }
      }
      setTimeout(function() {
        const selectedCountries = $('#alertCountries').val() || [];
        if (typeof checkAndApplyLOTRTheme === 'function') {
          checkAndApplyLOTRTheme(selectedCountries);
        }
      }, 100);
    });

    $('#alertCountries').on('select2:unselect', function(e) {
      setTimeout(function() {
        const selectedCountries = $('#alertCountries').val() || [];
        if (typeof checkAndApplyLOTRTheme === 'function') {
          checkAndApplyLOTRTheme(selectedCountries);
        }
      }, 100);
    });

    var sshKeySelect = document.getElementById('serverSSHKeySelect');
    if (sshKeySelect) {
      sshKeySelect.addEventListener('change', function(e) {
        if (e.target.value) {
          document.getElementById('serverSSHKey').value = e.target.value;
        }
      });
    }

    if (typeof setupIgnoreIPsInput === 'function') {
      setupIgnoreIPsInput();
    }

    if (typeof setupFormValidation === 'function') {
      setupFormValidation();
    }

    const advancedIntegrationSelect = document.getElementById('advancedIntegrationSelect');
    if (advancedIntegrationSelect && typeof updateAdvancedIntegrationFields === 'function') {
      advancedIntegrationSelect.addEventListener('change', updateAdvancedIntegrationFields);
    }
  });
}
