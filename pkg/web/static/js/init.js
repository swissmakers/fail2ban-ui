// Initialization code for Fail2ban UI
"use strict";

window.addEventListener('DOMContentLoaded', function() {
  showLoading(true);
  displayExternalIP();
  
  // Check LOTR mode on page load to apply immediately
  fetch('/api/settings')
    .then(res => res.json())
    .then(data => {
      const alertCountries = data.alertCountries || [];
      if (typeof checkAndApplyLOTRTheme === 'function') {
        checkAndApplyLOTRTheme(alertCountries);
      }
      // Store in global for later use
      if (typeof currentSettings === 'undefined') {
        window.currentSettings = {};
      }
      window.currentSettings.alertCountries = alertCountries;
    })
    .catch(err => {
      console.warn('Could not check LOTR on load:', err);
    });
  
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
      initializeTooltips(); // Initialize tooltips after fetching and rendering
      initializeSearch();
      showLoading(false);
    });
  
  // Setup Select2 for alert countries
  $(document).ready(function() {
    $('#alertCountries').select2({
      placeholder: 'Select countries..',
      allowClear: true,
      width: '100%'
    });

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
      // Check LOTR mode after selection change
      setTimeout(function() {
        const selectedCountries = $('#alertCountries').val() || [];
        if (typeof checkAndApplyLOTRTheme === 'function') {
          checkAndApplyLOTRTheme(selectedCountries);
        }
      }, 100);
    });
    
    $('#alertCountries').on('select2:unselect', function(e) {
      // Check LOTR mode after deselection
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
    
    // Setup IgnoreIPs tag input
    if (typeof setupIgnoreIPsInput === 'function') {
      setupIgnoreIPsInput();
    }
    
    // Setup form validation
    if (typeof setupFormValidation === 'function') {
      setupFormValidation();
    }
    
    // Setup advanced integration fields
    const advancedIntegrationSelect = document.getElementById('advancedIntegrationSelect');
    if (advancedIntegrationSelect && typeof updateAdvancedIntegrationFields === 'function') {
      advancedIntegrationSelect.addEventListener('change', updateAdvancedIntegrationFields);
    }
  });
});

