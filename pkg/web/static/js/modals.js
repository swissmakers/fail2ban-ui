// Modal management for Fail2ban UI
"use strict";

// =========================================================================
//  Modal Lifecycle
// =========================================================================

function updateBodyScrollLock() {
  if (openModalCount > 0) {
    document.body.classList.add('modal-open');
  } else {
    document.body.classList.remove('modal-open');
  }
}

function closeModal(modalId) {
  var modal = document.getElementById(modalId);
  if (!modal || modal.classList.contains('hidden')) {
    return;
  }
  if (modalId === 'banInsightsModal' && typeof destroyInsightsGlobe === 'function') {
    destroyInsightsGlobe();
  }
  modal.classList.add('hidden');
  openModalCount = Math.max(0, openModalCount - 1);
  updateBodyScrollLock();
}

function openModal(modalId) {
  var modal = document.getElementById(modalId);
  if (!modal || !modal.classList.contains('hidden')) {
    updateBodyScrollLock();
    return;
  }
  modal.classList.remove('hidden');
  openModalCount += 1;
  updateBodyScrollLock();
}

// =========================================================================
//  Whois and Logs Modal
// =========================================================================

// Whois modal
function openWhoisModal(eventIndex) {
  if (!latestBanEvents || !latestBanEvents[eventIndex]) {
    showToast("Event not found", 'error');
    return;
  }
  var event = latestBanEvents[eventIndex];
  if (!event.whois || !event.whois.trim()) {
    showToast("No whois data available for this event", 'info');
    return;
  }
  document.getElementById('whoisModalIP').textContent = event.ip || 'N/A';
  var contentEl = document.getElementById('whoisModalContent');
  contentEl.textContent = event.whois;
  openModal('whoisModal');
}

// Logs modal
function openLogsModal(eventIndex) {
  if (!latestBanEvents || !latestBanEvents[eventIndex]) {
    showToast("Event not found", 'error');
    return;
  }
  var event = latestBanEvents[eventIndex];
  if (!event.logs || !event.logs.trim()) {
    showToast("No logs data available for this event", 'info');
    return;
  }
  document.getElementById('logsModalIP').textContent = event.ip || 'N/A';
  document.getElementById('logsModalJail').textContent = event.jail || 'N/A';
  var logs = event.logs;
  var ip = event.ip || '';
  var logLines = logs.split('\n');
  var suspiciousIndices = [];
  for (var i = 0; i < logLines.length; i++) {
    if (isSuspiciousLogLine(logLines[i], ip)) {
      suspiciousIndices.push(i);
    }
  }
  var contentEl = document.getElementById('logsModalContent');
  if (suspiciousIndices.length) {
    var highlightMap = {};
    suspiciousIndices.forEach(function(idx) { highlightMap[idx] = true; });
    var html = '';
    for (var j = 0; j < logLines.length; j++) {
      var safeLine = escapeHtml(logLines[j] || '');
      if (highlightMap[j]) {
        html += '<span style="display: block; background-color: #d97706; color: #fef3c7; padding: 0.25rem 0.5rem; margin: 0.125rem 0; border-radius: 0.25rem;">' + safeLine + '</span>';
      } else {
        html += safeLine + '\n';
      }
    }
    contentEl.innerHTML = html;
  } else {
    contentEl.textContent = logs;
  }
  openModal('logsModal');
}

// =========================================================================
//  Ban Insights Modal
// =========================================================================

function openBanInsightsModal() {
  var countriesContainer = document.getElementById('countryStatsContainer');
  var recurringContainer = document.getElementById('recurringIPsContainer');
  var summaryContainer = document.getElementById('insightsSummary');

  var totals = (latestBanInsights && latestBanInsights.totals) || { overall: 0, today: 0, week: 0 };
  if (summaryContainer) {
    var summaryCards = [
      {
        label: t('logs.overview.total_events', 'Total stored events'),
        value: formatNumber(totals.overall || 0),
        sub: t('logs.modal.total_overall_note', 'Lifetime bans recorded')
      },
      {
        label: t('logs.overview.total_today', 'Today'),
        value: formatNumber(totals.today || 0),
        sub: t('logs.modal.total_today_note', 'Last 24 hours')
      },
      {
        label: t('logs.overview.total_week', 'Last 7 days'),
        value: formatNumber(totals.week || 0),
        sub: t('logs.modal.total_week_note', 'Weekly activity')
      }
    ];
    summaryContainer.innerHTML = summaryCards.map(function(card) {
      return ''
        + '<div class="border border-gray-200 rounded-lg p-4 bg-gray-50">'
        + '  <p class="text-xs uppercase tracking-wide text-gray-500">' + escapeHtml(card.label) + '</p>'
        + '  <p class="text-3xl font-semibold text-gray-900 mt-1">' + escapeHtml(card.value) + '</p>'
        + '  <p class="text-xs text-gray-500 mt-1">' + escapeHtml(card.sub) + '</p>'
        + '</div>';
    }).join('');
  }
  var countries = (latestBanInsights && latestBanInsights.countries) || [];
  if (!countries.length) {
    countriesContainer.innerHTML = '<p class="text-sm text-gray-500" data-i18n="logs.modal.insights_countries_empty">No bans recorded for this period.</p>';
  } else {
    var totalCountries = countries.reduce(function(sum, stat) {
      return sum + (stat.count || 0);
    }, 0) || 1;
    var countryHTML = countries.map(function(stat) {
      var label = stat.country || t('logs.overview.country_unknown', 'Unknown');
      var percent = Math.round(((stat.count || 0) / totalCountries) * 100);
      percent = Math.min(Math.max(percent, 3), 100);
      return ''
        + '<div class="space-y-2">'
        + '  <div class="flex items-center justify-between text-sm font-medium text-gray-800">'
        + '    <span>' + escapeHtml(label) + '</span>'
        + '    <span>' + formatNumber(stat.count || 0) + '</span>'
        + '  </div>'
        + '  <div class="w-full bg-gray-200 rounded-full h-2">'
        + '    <div class="h-2 rounded-full bg-gradient-to-r from-blue-500 to-indigo-600" style="width:' + percent + '%;"></div>'
        + '  </div>'
        + '</div>';
    }).join('');
    countriesContainer.innerHTML = countryHTML;
  }
  var recurring = (latestBanInsights && latestBanInsights.recurring) || [];
  if (!recurring.length) {
    recurringContainer.innerHTML = '<p class="text-sm text-gray-500" data-i18n="logs.modal.insights_recurring_empty">No recurring IPs detected.</p>';
  } else {
    var recurringHTML = recurring.map(function(stat) {
      var countryLabel = stat.country || t('logs.overview.country_unknown', 'Unknown');
      var lastSeenLabel = stat.lastSeen ? formatDateTime(stat.lastSeen) : '—';
      return ''
        + '<div class="rounded-lg bg-white border border-gray-200 shadow-sm p-4">'
        + '  <div class="flex items-center justify-between">'
        + '    <div>'
        + '      <p class="font-mono text-base text-gray-900">' + escapeHtml(stat.ip || '—') + '</p>'
        + '      <p class="text-xs text-gray-500 mt-1">' + escapeHtml(countryLabel) + '</p>'
        + '    </div>'
        + '    <span class="inline-flex items-center rounded-full bg-amber-100 px-3 py-1 text-xs font-semibold text-amber-700">' + formatNumber(stat.count || 0) + '×</span>'
        + '  </div>'
        + '  <div class="mt-3 flex justify-between text-xs text-gray-500">'
        + '    <span>' + t('logs.overview.last_seen', 'Last seen') + '</span>'
        + '    <span>' + escapeHtml(lastSeenLabel) + '</span>'
        + '  </div>'
        + '</div>';
    }).join('');
    recurringContainer.innerHTML = recurringHTML;
  }
  if (typeof updateTranslations === 'function') {
    updateTranslations();
  }
  openModal('banInsightsModal');
  if (typeof renderInsightsGlobe === 'function') {
    setTimeout(renderInsightsGlobe, 150);
  }
}

// =========================================================================
//  Server Manager Modal
// =========================================================================

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

// =========================================================================
//  Manage Jails Modal
// =========================================================================

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

      let saveTimeout;
      document.querySelectorAll('#jailsList input[type="checkbox"]').forEach(function(checkbox) {
        checkbox.addEventListener('change', function() {
          if (saveTimeout) {
            clearTimeout(saveTimeout);
          }
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

// =========================================================================
//  Create Jail Modal
// =========================================================================

function openCreateJailModal() {
  document.getElementById('newJailName').value = '';
  document.getElementById('newJailContent').value = '';
  const filterSelect = document.getElementById('newJailFilter');
  if (filterSelect) {
    filterSelect.value = '';
  }
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

// =========================================================================
//  Create Filter Modal
// =========================================================================

function openCreateFilterModal() {
  document.getElementById('newFilterName').value = '';
  document.getElementById('newFilterContent').value = '';
  openModal('createFilterModal');
}

// =========================================================================
//  Jail / Filter Config Editor Modal
// =========================================================================

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

      // Update logpath button visibility
      updateLogpathButtonVisibility();
      
      // Show hint for local servers
      var localServerHint = document.getElementById('localServerLogpathHint');
      if (localServerHint && currentServer && currentServer.type === 'local') {
        localServerHint.classList.remove('hidden');
      } else if (localServerHint) {
        localServerHint.classList.add('hidden');
      }

      jailTextArea.addEventListener('input', updateLogpathButtonVisibility);

      preventExtensionInterference(filterTextArea);
      preventExtensionInterference(jailTextArea);
      openModal('jailConfigModal');

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
