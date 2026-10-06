// App bootstrap and initialization.
"use strict";

// =========================================================================
//  Bootstrap
// =========================================================================

window.addEventListener('DOMContentLoaded', function() {
  initThemeManager();
  showLoading(true);
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
});

// =========================================================================
//  App Initialization
// =========================================================================

function initializeApp() {
  displayExternalIP();
  bindExternalIPSearch();

  wsManager = new WebSocketManager();
  initHeader();
  initConsoleOutput();
  wsManager.on('ban_event', addBanEventFromWebSocket);
  wsManager.on('ban_event_update', updateBanEventFromWebSocket);
  wsManager.on('server_health', handleServerHealthMessage);
  wsManager.on('reconnected', refreshServerHealth);
  wsManager.connect();
  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible') {
      refreshServerHealth();
    }
  });

  getSettings()
    .then(function(data) {
      checkAndApplyLOTRTheme((data && data.alertCountries) || []);
    })
    .catch(function(err) {
      console.warn('Could not check LOTR on load:', err);
    });

  var versionContainer = document.getElementById('version-badge-container');
  if (versionContainer && versionContainer.getAttribute('data-update-check') === 'true') {
    fetch(appPath('/api/version'))
      .then(readJsonResponse)
      .then(function(data) {
        if (!data || !data.update_check_enabled || versionContainer.innerHTML) return;
        var safeLabel = escapeHtml(t('footer.latest', 'Latest'));
        if (data.update_available && data.latest_version) {
          var safeHint = escapeHtml(t('footer.update_available', 'Update available: v{version}').replace('{version}', data.latest_version));
          versionContainer.innerHTML = '<a href="https://github.com/swissmakers/fail2ban-ui/releases" target="_blank" rel="noopener" class="theme-badge-warning inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-800 hover:bg-amber-200" title="' + safeHint + '">' + safeHint + '</a>';
        } else {
          versionContainer.innerHTML = '<span class="theme-badge-success inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800" title="' + safeLabel + '">' + safeLabel + '</span>';
        }
      })
      .catch(function() { });
  }

  var translationsLoaded = getTranslationsSettingsOnPageload();
  translationsLoaded.then(initAlertCountriesSelect);
  setupIgnoreIPsInput();
  setupFormValidation();

  Promise.all([loadServers(), translationsLoaded])
    .then(function() {
      return refreshData({ silent: true });
    })
    .catch(function(err) {
      console.error('Initialization error:', err);
      latestSummaryError = err ? String(err.message || err) : t('common.unknown_error', 'Unknown error');
      renderDashboard();
    })
    .finally(function() {
      showLoading(false);
    });
}

// jQuery-dependent setup (Select2 for alert countries)
// Select2 takes its placeholder once, so it is created after the translations are in.
function initAlertCountriesSelect() {
  $('#alertCountries').select2({
    placeholder: t('settings.alert_countries_placeholder', 'Select countries...'),
    allowClear: true,
    width: '100%'
  });

  // When "ALL" is selected, deselect other countries and vice versa
  $('#alertCountries').on('select2:select', function(e) {
    var selectedValue = e.params.data.id;
    var currentValues = $('#alertCountries').val() || [];
    var hLTR = currentValues.indexOf('LOTR') !== -1;
    if (selectedValue === 'ALL') {
      if (currentValues.length > 1) {
        if (hLTR) {
          $('#alertCountries').val(['ALL', 'LOTR']).trigger('change');
        } else {
          $('#alertCountries').val(['ALL']).trigger('change');
        }
      }
    } else {
      if (currentValues.indexOf('ALL') !== -1) {
        if (selectedValue === 'LOTR') {
          $('#alertCountries').val(['ALL', 'LOTR']).trigger('change');
        } else {
          var newValues = currentValues.filter(function(value) {
            return value !== 'ALL';
          });
          $('#alertCountries').val(newValues).trigger('change');
        }
      }
    }
    setTimeout(function() {
      checkAndApplyLOTRTheme($('#alertCountries').val() || []);
    }, 100);
  });

  $('#alertCountries').on('select2:unselect', function() {
    setTimeout(function() {
      checkAndApplyLOTRTheme($('#alertCountries').val() || []);
    }, 100);
  });
}
