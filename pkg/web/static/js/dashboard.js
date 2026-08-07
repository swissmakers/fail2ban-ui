"use strict";
// Dashboard data fetching and rendering.

var threatIntelProvider = 'none';
var dashboardRenderScheduled = false;

// life-saver if it should somehow happen that a race or function wants to render multible times.
function scheduleRender() {
  if (dashboardRenderScheduled) {
    return;
  }
  dashboardRenderScheduled = true;
  var raf = (typeof requestAnimationFrame === 'function')
    ? requestAnimationFrame
    : function(cb) { setTimeout(cb, 0); };
  raf(function() {
    dashboardRenderScheduled = false;
    renderDashboard();
  });
}

// =========================================================================
//  Data Fetching
// =========================================================================

function refreshData(options) {
  options = options || {};
  var enabledServers = serversCache.filter(function(s) { return s.enabled; });
  var summaryPromise;
  if (!serversCache.length || !enabledServers.length || !currentServerId) {
    latestSummary = null;
    latestSummaryError = null;
    summaryPromise = Promise.resolve();
  } else {
    summaryPromise = fetchSummaryData();
  }
  if (!options.silent) {
    showLoading(true);
  }

  if (!options.summaryOnly) {
    banEventsLoading = true;
    Promise.all([
      fetchBanStatisticsData(),
      fetchBanEventsData(),
      fetchBanInsightsData(),
      fetchBanEventCountries()
    ])
      .catch(function(err) {
        console.error('Error loading ban events/insights:', err);
      })
      .finally(function() {
        banEventsLoading = false;
        scheduleRender();
      });
  }

  return Promise.all(options.summaryOnly ? [summaryPromise] : [
    summaryPromise,
    fetchThreatIntelProviderData()
  ])
    .then(function() {
      scheduleRender();
    })
    .catch(function(err) {
      console.error('Error refreshing data:', err);
      latestSummaryError = err ? err.toString() : 'Unknown error';
      scheduleRender();
    })
    .finally(function() {
      if (!options.silent) {
        showLoading(false);
      }
    });
}

function fetchThreatIntelProviderData() {
  return fetch(appPath('/api/settings'))
    .then(function(res) { return res.json(); })
    .then(function(data) {
      var provider = data && data.threatIntel && data.threatIntel.provider
        ? String(data.threatIntel.provider).toLowerCase()
        : 'none';
      threatIntelProvider = provider;
    })
    .catch(function() {
      threatIntelProvider = 'none';
    });
}

function fetchBanStatisticsData() {
  return fetch(appPath('/api/events/bans/stats'))
    .then(function(res) { return res.json(); })
    .then(function(data) {
      latestBanStats = data && data.counts ? data.counts : {};
    })
    .catch(function(err) {
      console.error('Error fetching ban statistics:', err);
      latestBanStats = latestBanStats || {};
    });
}

function fetchSummaryData() {
  return fetch(withServerParam('/api/summary'))
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data && !data.error) {
        latestSummary = data;
        latestSummaryServerId = data.serverId || currentServerId || null;
        latestSummaryError = null;
        jailLocalWarning = !!data.jailLocalWarning;
      } else {
        latestSummary = null;
        latestSummaryServerId = null;
        latestSummaryError = formatApiError(data, 'dashboard.errors.summary_failed', 'Failed to load summary from server.');
        jailLocalWarning = false;
      }
    })
    .catch(function(err) {
      latestSummary = null;
      latestSummaryServerId = null;
      latestSummaryError = err ? err.toString() : 'Unknown error';
      jailLocalWarning = false;
    });
}

// -------------------------------------------------------------------------
//  Banned IP overview table (flat, server-paginated/sorted)
// -------------------------------------------------------------------------
function summaryMatchesCurrentServer() {
  if (!latestSummaryServerId || !currentServerId) {
    return true;
  }
  return latestSummaryServerId === currentServerId;
}

function isActiveBannedTableToken(token) {
  return !token || token === bannedTableRequestToken;
}

function setBannedTableLoading(active) {
  bannedTableLoading = !!active;
  var section = document.getElementById('bannedTableSection');
  var tbody = document.getElementById('bannedTableBody');
  if (section) {
    section.classList.toggle('opacity-60', bannedTableLoading);
  }
  if (tbody) {
    tbody.classList.toggle('pointer-events-none', bannedTableLoading);
    tbody.setAttribute('aria-busy', bannedTableLoading ? 'true' : 'false');
  }
}

function buildBannedTableQuery() {
  var params = [
    'sort=' + encodeURIComponent(bannedPagingSort || 'banTime'),
    'order=' + encodeURIComponent(bannedPagingOrder || 'desc'),
    'page=' + encodeURIComponent(bannedPagingPage || 1),
    'pageSize=' + encodeURIComponent(bannedPagingPageSize || 10)
  ];
  var query = (bannedIPsFilterText || '').trim();
  if (query) {
    params.push('q=' + encodeURIComponent(query));
  }
  return withServerParam('/api/banned?' + params.join('&'));
}

function fetchBannedTable() {
  if (!summaryMatchesCurrentServer()) {
    return Promise.resolve();
  }
  bannedTableRequestToken += 1;
  var token = bannedTableRequestToken;
  setBannedTableLoading(true);
  return fetch(buildBannedTableQuery())
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (!isActiveBannedTableToken(token)) {
        return;
      }
      var state = {
        rows: Array.isArray(data && data.rows) ? data.rows : [],
        total: typeof data.total === 'number' ? data.total : 0,
        page: data.page || 1,
        pageSize: data.pageSize || bannedPagingPageSize,
        hasMore: data.hasMore === true,
        error: data && data.error ? formatApiError(data, '', '') : null
      };
      bannedTableState = state;
      renderBannedTable();
    })
    .catch(function(err) {
      if (!isActiveBannedTableToken(token)) {
        return;
      }
      bannedTableState = {
        rows: [],
        total: 0,
        page: 1,
        pageSize: bannedPagingPageSize,
        hasMore: false,
        error: err ? String(err) : 'Unknown error'
      };
      renderBannedTable();
    })
    .finally(function() {
      if (!isActiveBannedTableToken(token)) {
        return;
      }
      setBannedTableLoading(false);
    });
}

function ensureBannedTableLoaded() {
  if (!bannedTableState) {
    fetchBannedTable();
    return;
  }
  renderBannedTable();
}

// Re-fetches the banned overview table from the backend (debounced for search).
function scheduleBannedIPsRefetch() {
  if (bannedIPsFilterDebounce) {
    clearTimeout(bannedIPsFilterDebounce);
  }
  bannedIPsFilterDebounce = setTimeout(function() {
    bannedIPsFilterDebounce = null;
    bannedPagingPage = 1;
    bannedTableState = null;
    fetchBannedTable();
  }, 300);
}

function fetchBanInsightsData() {
  var sevenDaysAgo = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000)).toISOString();
  var sinceQuery = '?since=' + encodeURIComponent(sevenDaysAgo);
  var globalPromise = fetch(appPath('/api/events/bans/insights' + sinceQuery))
    .then(function(res) { return res.json(); })
    .then(function(data) {
      latestBanInsights = normalizeInsights(data);
    })
    .catch(function(err) {
      console.error('Error fetching ban insights:', err);
      if (!latestBanInsights) {
        latestBanInsights = normalizeInsights(null);
      }
    });
  var serverPromise;
  if (currentServerId) {
    serverPromise = fetch(withServerParam('/api/events/bans/insights' + sinceQuery))
      .then(function(res) { return res.json(); })
      .then(function(data) {
        latestServerInsights = normalizeInsights(data);
      })
      .catch(function(err) {
        console.error('Error fetching server-specific ban insights:', err);
        latestServerInsights = null;
      });
  } else {
    latestServerInsights = null;
    serverPromise = Promise.resolve();
  }
  return Promise.all([globalPromise, serverPromise]);
}

function fetchBanEventsData(options) {
  options = options || {};
  var append = options.append === true;
  var offset = append ? Math.min(latestBanEvents.length, BAN_EVENTS_MAX_LOADED) : 0;
  if (append && offset >= BAN_EVENTS_MAX_LOADED) {
    return Promise.resolve();
  }
  var url = buildBanEventsQuery(offset, append);
  return fetch(url)
    .then(function(res) { return res.json(); })
    .then(function(data) {
      var events = data && data.events ? data.events : [];
      if (append) {
        latestBanEvents = latestBanEvents.concat(events);
      } else {
        latestBanEvents = events;
      }
      banEventsHasMore = data.hasMore === true;
      if (offset === 0 && typeof data.total === 'number') {
        banEventsTotal = data.total;
      }
      if (!append && latestBanEvents.length > 0 && wsManager) {
        wsManager.lastBanEventId = latestBanEvents[0].id;
      }
    })
    .catch(function(err) {
      console.error('Error fetching ban events:', err);
      if (!append) {
        latestBanEvents = latestBanEvents || [];
        banEventsTotal = null;
        banEventsHasMore = false;
      }
    });
}

// =========================================================================
//  Triggers Ban / Unban Actions from the dashboard
// =========================================================================

// Sends request to ban an IP in a jail.
function banIP(jail, ip) {
  const confirmMsg = isLOTRModeActive
    ? 'Banish ' + ip + ' from the realm in ' + jail + '?'
    : t('dashboard.ban.confirm', 'Block IP {ip} in jail {jail}?').replace('{ip}', ip).replace('{jail}', jail);
  if (!confirm(confirmMsg)) {
    return;
  }
  showLoading(true);
  var url = '/api/jails/' + encodeURIComponent(jail) + '/ban/' + encodeURIComponent(ip);
  fetch(withServerParam(url), {
    method: 'POST',
    headers: serverHeaders()
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      showLoading(false);
      if (data.error) {
        showToast(formatApiError(data, 'dashboard.toast.block_error', 'Error blocking IP'), 'error');
        return;
      }
      showToast(t('dashboard.manual_block.success', 'IP blocked successfully'), 'success');
      refreshAfterManualAction(jail);
    })
    .catch(function(err) {
      showLoading(false);
      showToast(t('common.error', 'Error') + ': ' + err, 'error');
    });
}

// Refreshes the sections affected by a manual ban/unban
function refreshAfterManualAction(jail) {
  return Promise.all([
    fetchSummaryData(),
    fetchBannedTable(),
    fetchBanEventsData()
  ]).then(function() {
    lastDashboardRefreshAt = Date.now();
    updateSummaryCountersFromLatestSummary();
    renderLogOverviewSection();
    scheduleRender();
  }).catch(function(err) {
    console.error('Error refreshing after manual action:', err);
  });
}

// Sends request to unban an IP from a jail.
function unbanIP(jail, ip) {
  const confirmMsg = isLOTRModeActive
    ? 'Restore ' + ip + ' to the realm from ' + jail + '?'
    : t('dashboard.unban.confirm', 'Unban IP {ip} from jail {jail}?')
      .replace('{ip}', ip)
      .replace('{jail}', jail);
  if (!confirm(confirmMsg)) {
    return;
  }
  showLoading(true);
  var url = '/api/jails/' + encodeURIComponent(jail) + '/unban/' + encodeURIComponent(ip);
  fetch(withServerParam(url), {
    method: 'POST',
    headers: serverHeaders()
  })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      showLoading(false);
      if (data.error) {
        showToast(formatApiError(data, 'dashboard.toast.unban_error', 'Error unbanning IP'), 'error');
        return;
      }
      refreshAfterManualAction(jail);
    })
    .catch(function(err) {
      showLoading(false);
      showToast(t('common.error', 'Error') + ': ' + err, 'error');
    });
}

// =========================================================================
//  Main Dashboard Rendering Function
// =========================================================================

function renderDashboard() {
  var container = document.getElementById('dashboard');
  if (!container) return;
  var focusState = captureFocusState(container);
  var enabledServers = serversCache.filter(function(s) { return s.enabled; });
  if (!serversCache.length) {
    container.innerHTML = ''
      + '<div class="bg-yellow-100 border-l-4 border-yellow-400 text-yellow-700 p-4 rounded mb-4" role="alert">'
      + '  <p class="font-semibold" data-i18n="dashboard.no_servers_title">No Fail2ban servers configured</p>'
      + '  <p class="text-sm mt-1" data-i18n="dashboard.no_servers_body">Add a server to start monitoring and controlling Fail2ban instances.</p>'
      + '</div>';
    if (typeof updateTranslations === 'function') updateTranslations();
    restoreFocusState(focusState);
    return;
  }
  if (!enabledServers.length) {
    container.innerHTML = ''
      + '<div class="bg-yellow-100 border-l-4 border-yellow-400 text-yellow-700 p-4 rounded mb-4" role="alert">'
      + '  <p class="font-semibold" data-i18n="dashboard.no_enabled_servers_title">No active connectors</p>'
      + '  <p class="text-sm mt-1" data-i18n="dashboard.no_enabled_servers_body">Enable the local connector or register a remote Fail2ban server to see live data.</p>'
      + '</div>';
    if (typeof updateTranslations === 'function') updateTranslations();
    restoreFocusState(focusState);
    return;
  }
  var summary = latestSummary;
  var html = '';
  // Persistent warning banner when jail.local is not managed by Fail2ban-UI
  if (jailLocalWarning) {
    html += ''
      + '<div class="bg-red-100 border-l-4 border-red-500 text-red-800 px-4 py-3 rounded mb-4 flex items-start gap-3" role="alert">'
      + '  <svg class="w-5 h-5 mt-0.5 flex-shrink-0 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">'
      + '    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>'
      + '  </svg>'
      + '  <div>'
      + '    <p class="font-semibold" data-i18n="dashboard.jail_local_warning_title">jail.local not managed by Fail2ban-UI</p>'
      + '    <p class="text-sm mt-1" data-i18n="dashboard.jail_local_warning_body">The file /etc/fail2ban/jail.local on the selected server exists but is not managed by Fail2ban-UI. The callback action (ui-custom-action) is missing, which means ban/unban events will not be recorded and no email alerts will be sent. To fix this, move each jail section from jail.local into its own file under /etc/fail2ban/jail.d/ (use jailname.conf to keep a default or jailname.local to override an existing .conf). Then delete jail.local so Fail2ban-UI can create its own managed version. Ensure Fail2ban-UI has write permissions to /etc/fail2ban/  -  see the documentation for details.</p>'
      + '  </div>'
      + '</div>';
  }
  if (latestSummaryError) {
    html += ''
      + '<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4">'
      + escapeHtml(latestSummaryError)
      + '</div>';
  }
  if (!summary) {
    html += ''
      + '<div class="bg-white rounded-lg shadow p-6 mb-6">'
      + '  <p class="text-gray-500" data-i18n="dashboard.loading_summary">Loading summary data...</p>'
      + '</div>';
  } else {
    var totalBanned = summary.jails ? summary.jails.reduce(function(sum, j) { return sum + (j.totalBanned || 0); }, 0) : 0;
    var newLastHour = summary.jails ? summary.jails.reduce(function(sum, j) { return sum + (j.newInLastHour || 0); }, 0) : 0;
    var recurringWeekCount = recurringIPsLastWeekCount();
    html += ''
      + '<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">'
      + renderStatCard({ variant: 'card', labelKey: 'dashboard.cards.active_jails', label: 'Active Jails', id: 'summaryActiveJails', value: summary.jails ? summary.jails.length : 0 })
      + renderStatCard({ variant: 'card', labelKey: 'dashboard.cards.total_banned', label: 'Total Banned IPs', id: 'summaryTotalBanned', value: totalBanned })
      + renderStatCard({ variant: 'card', labelKey: 'dashboard.cards.new_last_hour', label: 'New Last Hour', id: 'summaryNewLastHour', value: newLastHour })
      + renderStatCard({ variant: 'card', labelKey: 'dashboard.cards.recurring_week', label: 'Recurring IPs', id: 'summaryRecurringWeek', value: recurringWeekCount, subKey: 'dashboard.cards.recurring_hint', sub: 'Keep an eye on repeated offenders across all servers.' })
      + '</div>'
      + '<div class="bg-white rounded-lg shadow p-6 mb-6">'
      + '  <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">'
      + '    <div>'
      + '      <h3 class="text-lg font-medium text-gray-900 mb-2" data-i18n="dashboard.overview">Overview active Jails and Blocks</h3>'
      + '      <p class="text-sm text-gray-500" data-i18n="dashboard.overview_hint">Use the search to filter banned IPs and click a jail to edit its configuration.</p>'
      + '      <p class="text-sm text-gray-500 mt-1" data-i18n="dashboard.overview_detail">Sort by jail, IP address or ban time, search for an IP, and page through the results below.</p>'
      + '    </div>'
      + '    <div>'
      + '      <label for="ipSearch" class="block text-sm font-medium text-gray-700 mb-2" data-i18n="dashboard.search_label">Search Banned IPs</label>'
      + '      <input type="text" id="ipSearch" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" data-i18n-placeholder="dashboard.search_placeholder" placeholder="Enter IP address to search" value="' + escapeHtml(bannedIPsFilterText) + '" oninput="filterIPs()">'
      + '    </div>'
      + '  </div>';
    if (!summary.jails || summary.jails.length === 0) {
      html += '<p class="text-gray-500 mt-4" data-i18n="dashboard.no_jails">No jails found.</p>';
    } else {
      // Table 1: per-jail summary counts.
      html += ''
        + '<div class="overflow-x-auto mt-4">'
        + '  <table class="min-w-full divide-y divide-gray-200 text-sm sm:text-base" id="jailsTable">'
        + '    <thead class="bg-gray-50">'
        + '      <tr>'
        + '        <th class="px-2 py-1 sm:px-4 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="dashboard.table.jail">Jail</th>'
        + '        <th class="px-2 py-1 sm:px-4 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="dashboard.table.current_banned">Currently Banned</th>'
        + '        <th class="px-2 py-1 sm:px-4 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="dashboard.table.new_last_hour">New Last Hour</th>'
        + '      </tr>'
        + '    </thead>'
        + '    <tbody class="bg-white divide-y divide-gray-200">';
      summary.jails.forEach(function(jail) {
        var jailName = jail.jailName || '';
        html += ''
          + '<tr class="hover:bg-gray-50">'
          + '  <td class="px-2 py-1 sm:px-4 sm:py-3 whitespace-normal break-words">'
          + '    <a href="#" onclick="openJailConfigModal(\'' + escapeHtml(jailName) + '\')" class="text-blue-600 hover:text-blue-800">'
          +        escapeHtml(jailName)
          + '    </a>'
          + '  </td>'
          + '  <td class="px-2 py-1 sm:px-4 sm:py-3 whitespace-normal break-words">' + (jail.totalBanned || 0) + '</td>'
          + '  <td class="px-2 py-1 sm:px-4 sm:py-3 whitespace-normal break-words">' + (jail.newInLastHour || 0) + '</td>'
          + '</tr>';
      });
      html += '    </tbody></table>';
      html += '</div>';
      // Table 2: flat currently banned IPs (server-paginated/sorted).
      html += '<div id="bannedTableSection" class="mt-6">' + renderBannedTableLoadingMarkup() + '</div>';
      html += '</div>';
    }
  }
  if (summary && summary.jails && summary.jails.length > 0) {
    var enabledJails = summary.jails.filter(function(j) { return j.enabled !== false; });
    if (enabledJails.length > 0) {
      html += ''
        + '<div class="bg-white rounded-lg shadow p-6 mb-6">'
        + '  <div class="cursor-pointer hover:bg-gray-50 -m-6 p-6 rounded-lg transition-colors" onclick="toggleManualBlockSection()">'
        + '    <div class="flex items-center justify-between">'
        + '      <div class="flex-1">'
        + '        <h3 class="text-lg font-medium text-gray-900 mb-2" data-i18n="dashboard.manual_block.title">Manual Block IP</h3>'
        + '        <p class="text-sm text-gray-500" data-i18n="dashboard.manual_block.subtitle">Manually block an IP address in a specific jail.</p>'
        + '        <p class="text-xs text-gray-400 mt-1" data-i18n="dashboard.manual_block.expand_hint">Click to expand and block an IP address</p>'
        + '      </div>'
        + '      <div class="ml-4">'
        + '        <i id="manualBlockToggleIcon" class="fas fa-chevron-down text-gray-400 transition-transform"></i>'
        + '      </div>'
        + '    </div>'
        + '  </div>'
        + '  <div id="manualBlockFormContainer" class="hidden" style="margin-top: 35px;">'
        + '    <form id="manualBlockForm" onsubmit="return false;">'
        + '      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">'
        + '        <div>'
        + '          <label for="blockJailSelect" class="block text-sm font-medium text-gray-700 mb-2" data-i18n="dashboard.manual_block.jail_label">Select Jail</label>'
        + '          <select id="blockJailSelect" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" required>'
        + '            <option value="" data-i18n="dashboard.manual_block.jail_placeholder">Choose a jail...</option>';

      enabledJails.forEach(function(jail) {
        html += '            <option value="' + escapeHtml(jail.jailName) + '">' + escapeHtml(jail.jailName) + '</option>';
      });
      html += ''
        + '          </select>'
        + '        </div>'
        + '        <div>'
        + '          <label for="blockIPInput" class="block text-sm font-medium text-gray-700 mb-2" data-i18n="dashboard.manual_block.ip_label">IP Address</label>'
        + '          <input type="text" id="blockIPInput" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" data-i18n-placeholder="dashboard.manual_block.ip_placeholder" placeholder="e.g., 88.76.21.123" pattern="^([0-9]{1,3}\\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$" required>'
        + '        </div>'
        + '        <div class="flex items-end">'
        + '          <button type="button" onclick="handleManualBlock()" class="w-full bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700 transition-colors flex items-center justify-center gap-2">'
        + '            <i class="fas fa-ban"></i>'
        + '            <span data-i18n="dashboard.manual_block.button">Block IP</span>'
        + '          </button>'
        + '        </div>'
        + '      </div>'
        + '    </form>'
        + '  </div>'
        + '</div>';
    }
  }
  html += '<div id="logOverview">' + renderLogOverviewContent() + '</div>';
  container.innerHTML = html;
  restoreFocusState(focusState);
  const extIpEl = document.getElementById('external-ip');
  if (extIpEl) {
    extIpEl.addEventListener('click', function() {
      const ip = extIpEl.textContent.trim();
      const searchInput = document.getElementById('ipSearch');
      if (searchInput) {
        searchInput.value = ip;
        filterIPs();
        searchInput.focus();
        searchInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });
  }
  initializeSearch();
  if (typeof updateTranslations === 'function') {
    updateTranslations();
  }
  if (isLOTRModeActive) {
    updateDashboardLOTRTerminology(true);
  }
  if (summary && summary.jails && summary.jails.length > 0) {
    ensureBannedTableLoaded();
  }
}

// =========================================================================
//  Rendering the colapsable "Banned IPs per jail" section
// =========================================================================

function bannedSortIcon(field) {
  if (bannedPagingSort !== field) {
    return ' <span class="text-gray-300">\u2195</span>';
  }
  return bannedPagingOrder === 'desc'
    ? ' <span class="text-blue-600">\u25BE</span>'
    : ' <span class="text-blue-600">\u25B4</span>';
}

function changeBannedSort(field) {
  if (bannedPagingSort === field) {
    bannedPagingOrder = (bannedPagingOrder === 'desc') ? 'asc' : 'desc';
  } else {
    bannedPagingSort = field;
    bannedPagingOrder = (field === 'banTime') ? 'desc' : 'asc';
  }
  bannedPagingPage = 1;
  bannedTableState = null;
  fetchBannedTable();
}

function setBannedPageSize(size) {
  var s = parseInt(size, 10);
  if (!s || s < 1) {
    s = 10;
  }
  if (s === bannedPagingPageSize) {
    return;
  }
  bannedPagingPageSize = s;
  bannedPagingPage = 1;
  bannedTableState = null;
  fetchBannedTable();
}

function goBannedPage(delta) {
  var next = (bannedPagingPage || 1) + delta;
  if (next < 1) {
    return;
  }
  var maxPage = bannedTableState
    ? Math.max(1, Math.ceil(bannedTableState.total / (bannedTableState.pageSize || bannedPagingPageSize)))
    : 1;
  if (next > maxPage) {
    return;
  }
  bannedPagingPage = next;
  fetchBannedTable();
}

function formatBanTime(iso) {
  if (!iso) {
    return '';
  }
  var d = new Date(iso);
  if (isNaN(d.getTime())) {
    return '';
  }
  return d.toLocaleString();
}

function renderBannedIPLabel(row, query) {
  var encodedIp = encodeURIComponent(row.ip);
  var safeIp = escapeHtml(row.ip);
  var ipText = query ? highlightQueryMatch(row.ip, query) : safeIp;
  if (isThreatIntelEnabled()) {
    return '<span class="text-blue-600 hover:text-blue-800 cursor-pointer decoration-dotted"'
      + '    data-ip-value="' + encodedIp + '" role="button" tabindex="0"'
      + '    onclick="openThreatIntelModal(decodeURIComponent(this.getAttribute(\'data-ip-value\')))"'
      + '    onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();openThreatIntelModal(decodeURIComponent(this.getAttribute(\'data-ip-value\')));}">' + ipText + '</span>';
  }
  return '<span data-ip-value="' + encodedIp + '">' + ipText + '</span>';
}

function renderBannedTable() {
  var section = document.getElementById('bannedTableSection');
  if (!section) {
    return;
  }
  var focusState = captureFocusState(section);
  var state = bannedTableState;
  var query = (bannedIPsFilterText || '').trim();
  var html = ''
    + '<div class="flex items-center justify-between mb-3">'
    + '  <h4 class="text-base font-semibold text-gray-900" data-i18n="dashboard.current_banned_title">Currently banned IPs</h4>'
    + '</div>';

  if (!state) {
    section.innerHTML = html + renderBannedTableLoadingMarkup();
    restoreFocusState(focusState);
    if (typeof updateTranslations === 'function') updateTranslations();
    return;
  }
  if (state.error) {
    section.innerHTML = html + '<p class="text-red-600">' + escapeHtml(state.error) + '</p>';
    restoreFocusState(focusState);
    if (typeof updateTranslations === 'function') updateTranslations();
    return;
  }
  if (state.rows.length === 0) {
    section.innerHTML = html + '<p class="text-gray-500">'
      + (query
          ? t('dashboard.banned.no_matches', 'No matching IPs')
          : t('dashboard.no_banned_ips', 'No banned IPs'))
      + '</p>';
    restoreFocusState(focusState);
    if (typeof updateTranslations === 'function') updateTranslations();
    return;
  }

  function sortTh(field, labelKey, label) {
    return '<th class="px-2 py-1 sm:px-4 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer select-none" onclick="changeBannedSort(\'' + field + '\')">'
      + '<span data-i18n="' + labelKey + '">' + label + '</span>' + bannedSortIcon(field)
      + '</th>';
  }

  html += '<div class="overflow-x-auto">'
    + '  <table class="min-w-full divide-y divide-gray-200 text-sm sm:text-base" id="bannedTable">'
    + '    <thead class="bg-gray-50">'
    + '      <tr>'
    + '        ' + sortTh('jail', 'dashboard.table.jail', 'Jail')
    + '        ' + sortTh('ip', 'dashboard.table.ip_address', 'IP Address')
    + '        ' + sortTh('banTime', 'dashboard.table.ban_time', 'Ban Time')
    + '        <th class="px-2 py-1 sm:px-4 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="dashboard.table.actions">Actions</th>'
    + '      </tr>'
    + '    </thead>'
    + '    <tbody id="bannedTableBody" class="bg-white divide-y divide-gray-200 transition-opacity duration-150">';

  state.rows.forEach(function(row) {
    var jailName = row.jail || '';
    var banTimeText = formatBanTime(row.banTime);
    var banTimeCell;
    if (row.banTime && banTimeText) {
      banTimeCell = '<span>' + escapeHtml(banTimeText) + '</span>';
    } else {
      var hint = t('dashboard.ban_time_missing_hint', 'No recorded ban event for this IP');
      banTimeCell = '<span title="' + escapeHtml(hint) + '" class="text-gray-400 cursor-help border-b border-dotted border-gray-300">\u2014</span>';
    }
    html += ''
      + '<tr class="hover:bg-gray-50">'
      + '  <td class="px-2 py-1 sm:px-4 sm:py-3 whitespace-normal break-words">'
      + '    <a href="#" onclick="openJailConfigModal(\'' + escapeHtml(jailName) + '\')" class="text-blue-600 hover:text-blue-800">'
      +        escapeHtml(jailName)
      + '    </a>'
      + '  </td>'
      + '  <td class="px-2 py-1 sm:px-4 sm:py-3 whitespace-normal break-words">' + renderBannedIPLabel(row, query) + '</td>'
      + '  <td class="px-2 py-1 sm:px-4 sm:py-3 whitespace-normal break-words">' + banTimeCell + '</td>'
      + '  <td class="px-2 py-1 sm:px-4 sm:py-3 whitespace-nowrap">'
      + '    <button class="bg-yellow-500 text-white px-3 py-1 rounded text-sm hover:bg-yellow-600 transition-colors"'
      + '      onclick="unbanIP(\'' + escapeHtml(jailName) + '\', \'' + escapeHtml(row.ip) + '\')">'
      + '      <span data-i18n="dashboard.unban">Unban</span>'
      + '    </button>'
      + '  </td>'
      + '</tr>';
  });

  html += '    </tbody></table>';
  html += '</div>';
  html += renderBannedPaginationMarkup();
  section.innerHTML = html;
  restoreFocusState(focusState);
  if (typeof updateTranslations === 'function') {
    updateTranslations();
  }
  if (isLOTRModeActive) {
    updateDashboardLOTRTerminology(true);
  }
}

function renderBannedPaginationMarkup() {
  var state = bannedTableState || {};
  var total = state.total || 0;
  var pageSize = state.pageSize || bannedPagingPageSize;
  var page = state.page || bannedPagingPage || 1;
  var maxPage = Math.max(1, Math.ceil(total / pageSize));
  var from = total === 0 ? 0 : ((page - 1) * pageSize) + 1;
  var to = Math.min(page * pageSize, total);
  var pageOpts = (typeof BANNED_TABLE_PAGE_SIZE_OPTIONS !== 'undefined' && BANNED_TABLE_PAGE_SIZE_OPTIONS.length)
    ? BANNED_TABLE_PAGE_SIZE_OPTIONS : [5, 10, 25, 100];
  var sizeSelect = '<select onchange="setBannedPageSize(this.value)" class="border border-gray-300 rounded-md px-2 py-1 text-sm">'
    + pageOpts.map(function(s) {
      return '<option value="' + s + '"' + (s === pageSize ? ' selected' : '') + '>' + s + '</option>';
    }).join('')
    + '</select>';
  return ''
    + '<div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mt-3 text-sm text-gray-600">'
    + '  <div class="flex items-center gap-2">'
    + '    <span data-i18n="dashboard.pagination.rows_per_page">Rows per page:</span>'
    + '    ' + sizeSelect
    + '    <span class="ml-2">' + from + '\u2013' + to + ' ' + t('dashboard.pagination.of', 'of') + ' ' + total + '</span>'
    + '  </div>'
    + '  <div class="flex items-center gap-2">'
    + '    <button type="button" class="px-3 py-1 rounded border border-gray-300 hover:bg-gray-50 disabled:opacity-40"'
    + '      onclick="goBannedPage(-1)"' + (page <= 1 ? ' disabled' : '') + ' data-i18n="dashboard.pagination.prev">Prev</button>'
    + '    <span class="px-2">' + t('dashboard.pagination.page', 'Page') + ' ' + page + ' / ' + maxPage + '</span>'
    + '    <button type="button" class="px-3 py-1 rounded border border-gray-300 hover:bg-gray-50 disabled:opacity-40"'
    + '      onclick="goBannedPage(1)"' + (page >= maxPage ? ' disabled' : '') + ' data-i18n="dashboard.pagination.next">Next</button>'
    + '  </div>'
    + '</div>';
}

function renderBannedTableLoadingMarkup() {
  return '<div class="flex items-center gap-2 text-gray-500 text-sm">'
    + '  <span data-i18n="dashboard.banned.loading">Loading banned IPs...</span>'
    + '</div>';
}

// =========================================================================
//  Internal Log Overview Section Functions
// =========================================================================

function renderLogOverviewContent() {
  var html = ''
    + '<div class="bg-white rounded-lg shadow p-6 mb-6">'
    + '  <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between mb-4">'
    + '    <div>'
    + '      <h3 class="text-lg font-medium text-gray-900" data-i18n="logs.overview.title">Internal Log Overview</h3>'
    + '      <p class="text-sm text-gray-500" data-i18n="logs.overview.subtitle">Events stored by Fail2ban-UI across all connectors.</p>'
    + '    </div>'
    + '    <button class="text-sm text-blue-600 hover:text-blue-800" onclick="refreshData()" data-i18n="logs.overview.refresh">Refresh data</button>'
    + '  </div>';
  var statsKeys = Object.keys(latestBanStats || {});
  statsKeys.sort(function(a, b) {
    return (latestBanStats[b] || 0) - (latestBanStats[a] || 0);
  });
  var totalStored = totalStoredBans();
  var todayCount = totalBansToday();
  var weekCount = totalBansWeek();
  if (statsKeys.length > 0 || totalStored > 0) {
    html += ''
      + '<div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">'
      + '  <div class="border border-gray-200 rounded-lg p-4 flex flex-col gap-4 bg-gray-50">'
      + '    <div class="flex items-start justify-between gap-4">'
      + '      <div>'
      + '        <p class="text-sm text-gray-500" data-i18n="logs.overview.total_events">Total stored events</p>'
      + '        <p class="text-2xl font-semibold text-gray-800">' + totalStored + '</p>'
      + '      </div>'
      + '      <button type="button" class="inline-flex items-center px-3 py-1 text-sm rounded border border-blue-200 text-blue-600 hover:bg-blue-50" onclick="openBanInsightsModal()" data-i18n="logs.overview.open_insights">Open insights</button>'
      + '    </div>'
      + '    <div class="grid grid-cols-2 gap-4 text-sm">'
      + '      <div>'
      + '        <p class="text-gray-500" data-i18n="logs.overview.total_today">Today</p>'
      + '        <p class="text-lg font-semibold text-gray-900">' + todayCount + '</p>'
      + '      </div>'
      + '      <div>'
      + '        <p class="text-gray-500" data-i18n="logs.overview.total_week">Last 7 days</p>'
      + '        <p class="text-lg font-semibold text-gray-900">' + weekCount + '</p>'
      + '      </div>'
      + '    </div>'
      + '  </div>'
      + '  <div class="border border-gray-200 rounded-lg p-4 overflow-x-auto bg-gray-50">'
      + '    <p class="text-sm text-gray-500 mb-2" data-i18n="logs.overview.per_server">Events per server</p>'
      + '    <table class="min-w-full text-sm">'
      + '      <thead>'
      + '        <tr class="text-left text-xs text-gray-500 uppercase tracking-wider">'
      + '          <th class="pr-4" data-i18n="logs.table.server">Server</th>'
      + '          <th data-i18n="logs.table.count">Count</th>'
      + '        </tr>'
      + '      </thead>'
      + '      <tbody>';
    if (!statsKeys.length) {
      html += '<tr><td colspan="2" class="py-2 text-sm text-gray-500" data-i18n="logs.overview.per_server_empty">No per-server data available yet.</td></tr>';
    } else {
      statsKeys.forEach(function(serverId) {
        var count = latestBanStats[serverId] || 0;
        var server = serversCache.find(function(s) { return s.id === serverId; });
        html += ''
          + '        <tr>'
          + '          <td class="pr-4 py-1">' + escapeHtml(server ? server.name : serverId) + '</td>'
          + '          <td class="py-1">' + count + '</td>'
          + '        </tr>';
      });
    }
    html += '      </tbody></table></div></div>';
  }
  html += '<div class="flex items-center justify-between mb-3">'
      + '<h4 class="text-md font-semibold text-gray-800" data-i18n="logs.overview.recent_events_title">Recent stored events</h4>'
      + '<button type="button" class="px-3 py-1.5 text-xs rounded border border-red-300 text-red-600 hover:bg-red-50" onclick="clearStoredBanEvents()" data-i18n="logs.overview.clear_events">Clear</button>'
      + '</div>';
  var countries = getBanEventCountries();
  var recurringMap = getRecurringIPMap();
  var searchQuery = (banEventsFilterText || '').trim();
  var totalLabel = banEventsTotal != null ? banEventsTotal : ' - ';
  if (searchQuery && banEventsTotal != null && banEventsTotal > BAN_EVENTS_SEARCH_COUNT_CAP) {
    totalLabel = BAN_EVENTS_SEARCH_COUNT_CAP + '+';
  }
  html += ''
    + '<div class="flex flex-col sm:flex-row gap-3 mb-4">'
    + '  <div class="flex-1">'
    + '    <label for="recentEventsSearch" class="block text-sm font-medium text-gray-700 mb-1" data-i18n="logs.search.label">Search events</label>'
    + '    <input type="text" id="recentEventsSearch" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="' + t('logs.search.placeholder', 'Search IP, jail or server') + '" value="' + escapeHtml(banEventsFilterText) + '" oninput="updateBanEventsSearch(this.value)">'
    + '  </div>'
    + '  <div class="w-full sm:w-48">'
    + '    <label for="recentEventsServer" class="block text-sm font-medium text-gray-700 mb-1" data-i18n="logs.search.server_label">Server</label>'
    + '    <select id="recentEventsServer" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" onchange="updateBanEventsServer(this.value)">'
    + '      <option value="all"' + (banEventsFilterServer === 'all' ? ' selected' : '') + ' data-i18n="logs.search.server_all">All servers</option>';
  serversCache.filter(function(server) { return server.enabled; }).forEach(function(server) {
    var selected = banEventsFilterServer === server.id ? ' selected' : '';
    html += '<option value="' + escapeHtml(server.id) + '"' + selected + '>' + escapeHtml(server.name || server.id) + '</option>';
  });
  html += '    </select>'
    + '  </div>'
    + '  <div class="w-full sm:w-48">'
    + '    <label for="recentEventsCountry" class="block text-sm font-medium text-gray-700 mb-1" data-i18n="logs.search.country_label">Country</label>'
    + '    <select id="recentEventsCountry" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" onchange="updateBanEventsCountry(this.value)">'
    + '      <option value="all"' + (banEventsFilterCountry === 'all' ? ' selected' : '') + ' data-i18n="logs.search.country_all">All countries</option>';
    countries.forEach(function(country) {
    var value = (country || '').trim();
    var optionValue = value ? value.toLowerCase() : '__unknown__';
    var label = value || t('logs.search.country_unknown', 'Unknown');
    var selected = banEventsFilterCountry.toLowerCase() === optionValue ? ' selected' : '';
    html += '<option value="' + optionValue + '"' + selected + '>' + escapeHtml(label) + '</option>';
  });
  html += '    </select>'
    + '  </div>'
    + '</div>'
    + '<p class="text-xs text-gray-500 mb-3">' + t('logs.overview.recent_count_label', 'Events shown') + ': ' + latestBanEvents.length + ' / ' + totalLabel
    + (banEventsLoading ? ' <span class="inline-block h-3 w-3 align-middle border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></span>' : '')
    + '</p>'
    + '<div class="overflow-x-auto' + (banEventsLoading && latestBanEvents.length ? ' opacity-60' : '') + '"' + (banEventsLoading ? ' aria-busy="true"' : '') + '>'
    + '  <table class="min-w-full divide-y divide-gray-200 text-sm">'
    + '    <thead class="bg-gray-50">'
    + '      <tr>'
    + '        <th class="px-2 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="logs.table.time">Time</th>'
    + '        <th class="px-2 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="logs.table.server">Server</th>'
    + '        <th class="hidden sm:table-cell px-2 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="logs.table.jail">Jail</th>'
    + '        <th class="px-2 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="logs.table.ip">IP</th>'
    + '        <th class="hidden md:table-cell px-2 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="logs.table.country">Country</th>'
    + '        <th class="px-2 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="logs.table.actions">Actions</th>'
    + '      </tr>'
    + '    </thead>'
    + '    <tbody class="bg-white divide-y divide-gray-200">';
  if (!latestBanEvents.length && banEventsLoading) {
    html += '<tr><td colspan="6" class="px-2 py-6 text-center text-gray-500">'
      + '<span class="inline-block h-5 w-5 align-middle border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></span> '
      + '<span class="align-middle" data-i18n="loading">Loading...</span>'
      + '</td></tr>';
  } else if (!latestBanEvents.length) {
    var hasFilter = (banEventsFilterText || '').trim().length > 0 || ((banEventsFilterCountry || 'all').trim() !== 'all');
    var emptyMsgKey = hasFilter ? 'logs.overview.recent_filtered_empty' : 'logs.overview.recent_empty';
    html += '<tr><td colspan="6" class="px-2 py-4 text-center text-gray-500" data-i18n="' + emptyMsgKey + '"></td></tr>';
  } else {
    latestBanEvents.forEach(function(event, index) {
      var hasWhois = !!event.hasWhois || (event.whois && event.whois.trim().length > 0);
      var hasLogs = !!event.hasLogs || (event.logs && event.logs.trim().length > 0);
      var serverValue = event.serverName || event.serverId || '';
      var jailValue = event.jail || '';
      var ipValue = event.ip || '';
      var serverCell = highlightQueryMatch(serverValue, searchQuery);
      var jailCell = highlightQueryMatch(jailValue, searchQuery);
      var ipCell = highlightQueryMatch(ipValue, searchQuery);
      var ipCellInteractive = renderThreatIntelIPTrigger(ipValue, ipCell);
      if (event.ip && recurringMap[event.ip]) {
        ipCellInteractive += ' <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-800">' + t('logs.badge.recurring', 'Recurring') + '</span>';
      }
      var eventType = event.eventType || 'ban';
      var eventTypeBadge = '';
      if (eventType === 'unban') {
        eventTypeBadge = ' <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">' + t('logs.badge.unbanned', 'Unbanned') + '</span>';
      } else {
        eventTypeBadge = ' <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">' + t('logs.badge.banned', 'Banned') + '</span>';
      }
      html += ''
        + '      <tr class="hover:bg-gray-50">'
        + '        <td class="px-2 py-2 whitespace-nowrap">' + escapeHtml(formatDateTime(event.occurredAt || event.createdAt)) + '</td>'
        + '        <td class="px-2 py-2 whitespace-nowrap">' + serverCell + '</td>'
        + '        <td class="hidden sm:table-cell px-2 py-2 whitespace-nowrap">' + jailCell + '</td>'
        + '        <td class="px-2 py-2 whitespace-nowrap">' + ipCellInteractive + eventTypeBadge + '</td>'
        + '        <td class="hidden md:table-cell px-2 py-2 whitespace-nowrap">' + escapeHtml(event.country || ' - ') + '</td>'
        + '        <td class="px-2 py-2 whitespace-nowrap">'
        + '          <div class="flex gap-2">'
        + (hasWhois ? '            <button onclick="openWhoisModal(' + index + ')" class="px-2 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700" data-i18n="logs.actions.whois">Whois</button>' : '            <button disabled class="px-2 py-1 text-xs bg-gray-300 text-gray-500 rounded cursor-not-allowed" data-i18n="logs.actions.whois">Whois</button>')
        + (hasLogs ? '            <button onclick="openLogsModal(' + index + ')" class="px-2 py-1 text-xs bg-green-600 text-white rounded hover:bg-green-700" data-i18n="logs.actions.logs">Logs</button>' : '            <button disabled class="px-2 py-1 text-xs bg-gray-300 text-gray-500 rounded cursor-not-allowed" data-i18n="logs.actions.logs">Logs</button>')
        + '          </div>'
        + '        </td>'
        + '      </tr>';
    });
  }
  html += '    </tbody></table></div>';
  if (banEventsHasMore && latestBanEvents.length > 0 && latestBanEvents.length < BAN_EVENTS_MAX_LOADED) {
    var loadMoreLabel = typeof t === 'function' ? t('logs.overview.load_more', 'Load more') : 'Load more';
    var loadingMoreLabel = typeof t === 'function' ? t('logs.overview.loading_more', 'loading..') : 'loading..';
    var buttonDisabled = isBanEventsLoadingMore ? ' disabled aria-busy="true"' : '';
    var buttonClass = 'px-4 py-2 text-sm font-medium border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500';
    buttonClass += isBanEventsLoadingMore
      ? ' text-gray-500 bg-gray-100 border-gray-200 cursor-not-allowed'
      : ' text-blue-600 bg-blue-50 border-blue-200 hover:bg-blue-100';
    var buttonContent = isBanEventsLoadingMore
      ? '<span class="inline-flex items-center gap-2"><span class="inline-block h-3 w-3 border-2 border-gray-400 border-t-transparent rounded-full animate-spin"></span>' + escapeHtml(loadingMoreLabel) + '</span>'
      : escapeHtml(loadMoreLabel);
    html += '<div class="mt-3 text-center">'
      + '<button type="button" class="' + buttonClass + '" onclick="loadMoreBanEvents()"' + buttonDisabled + '>' + buttonContent + '</button>'
      + '</div>';
  }
  html += '</div>';
  return html;
}

function renderThreatIntelIPTrigger(ipValue, labelHTML) {
  if (!ipValue || !isThreatIntelEnabled()) {
    return labelHTML || '';
  }
  var encodedIp = encodeURIComponent(ipValue);
  return ''
    + '<button type="button" class="text-blue-600 hover:text-blue-800 decoration-dotted"'
    + ' data-ip-value="' + encodedIp + '"'
    + ' onclick="openThreatIntelModal(decodeURIComponent(this.getAttribute(\'data-ip-value\')))">'
    + (labelHTML || escapeHtml(ipValue))
    + '</button>';
}

function isThreatIntelEnabled() {
  return threatIntelProvider === 'alienvault' || threatIntelProvider === 'abuseipdb';
}

// =========================================================================
//  Search and Filtering Functions
// =========================================================================

function updateBanEventsSearch(value) {
  banEventsFilterText = value || '';
  scheduleBanEventsRefetch();
}

function refetchBanEvents() {
  banEventsLoading = true;
  renderLogOverviewSection();
  return fetchBanEventsData().finally(function() {
    banEventsLoading = false;
    renderLogOverviewSection();
  });
}

function updateBanEventsCountry(value) {
  banEventsFilterCountry = value || 'all';
  refetchBanEvents();
}

function updateBanEventsServer(value) {
  banEventsFilterServer = value || 'all';
  refetchBanEvents();
}

function loadMoreBanEvents() {
  if (latestBanEvents.length >= BAN_EVENTS_MAX_LOADED || !banEventsHasMore || isBanEventsLoadingMore) {
    return;
  }
  isBanEventsLoadingMore = true;
  renderLogOverviewSection();
  fetchBanEventsData({ append: true }).finally(function() {
    isBanEventsLoadingMore = false;
    renderLogOverviewSection();
  });
}

function updateBannedIPsSearch(value) {
  var nextValue = value || '';
  if (nextValue === bannedIPsFilterText) {
    return;
  }
  bannedIPsFilterText = nextValue;
  scheduleBannedIPsRefetch();
}

function clearStoredBanEvents() {
  var msg = t('logs.overview.clear_events_confirm',
    'This will permanently delete all stored ban events. Statistics, insights, and the event history will be reset to zero.\n\nThis action cannot be undone. Continue?');
  if (!confirm(msg)) return;
  fetch(appPath('/api/events/bans'), { method: 'DELETE', headers: serverHeaders() })
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data.error) {
        showToast(data.error, 'error');
        return;
      }
      showToast(t('logs.overview.clear_events_success', 'All stored ban events cleared.'), 'success');
      latestBanEvents = [];
      latestBanStats = {};
      latestBanInsights = null;
      banEventsTotal = 0;
      banEventsHasMore = false;
      if (typeof resetInsightsTimeline === 'function') {
        resetInsightsTimeline();
      }
      renderLogOverviewSection();
    })
    .catch(function(err) { showToast(String(err), 'error'); });
}

function filterIPs() {
  var input = document.getElementById('ipSearch');
  updateBannedIPsSearch(input ? input.value : '');
}

// =========================================================================
//  Helper Functions
// =========================================================================

function toggleBannedList(hiddenId, buttonId) {
  var hidden = document.getElementById(hiddenId);
  var button = document.getElementById(buttonId);
  if (!hidden || !button) {
    return;
  }
  var isHidden = hidden.classList.contains("hidden");
  if (isHidden) {
    hidden.classList.remove("hidden");
    button.textContent = button.getAttribute("data-less-label") || button.textContent;
    button.setAttribute("data-expanded", "true");
  } else {
    hidden.classList.add("hidden");
    button.textContent = button.getAttribute("data-more-label") || button.textContent;
    button.setAttribute("data-expanded", "false");
  }
}

function toggleManualBlockSection() {
  var container = document.getElementById('manualBlockFormContainer');
  var icon = document.getElementById('manualBlockToggleIcon');
  if (!container || !icon) {
    return;
  }
  var isHidden = container.classList.contains("hidden");
  if (isHidden) {
    container.classList.remove("hidden");
    icon.classList.remove("fa-chevron-down");
    icon.classList.add("fa-chevron-up");
  } else {
    container.classList.add("hidden");
    icon.classList.remove("fa-chevron-up");
    icon.classList.add("fa-chevron-down");
  }
}

function handleManualBlock() {
  var jailSelect = document.getElementById('blockJailSelect');
  var ipInput = document.getElementById('blockIPInput');
  if (!jailSelect || !ipInput) {
    return;
  }
  var jail = jailSelect.value;
  var ip = ipInput.value.trim();
  if (!jail) {
    showToast(t('dashboard.manual_block.jail_required', 'Please select a jail'), 'error');
    jailSelect.focus();
    return;
  }
  if (!ip) {
    showToast(t('dashboard.manual_block.ip_required', 'Please enter an IP address'), 'error');
    ipInput.focus();
    return;
  }
  // IPv4 / IPv6 validation
  var ipv4Pattern = /^([0-9]{1,3}\.){3}[0-9]{1,3}$/;
  var ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  if (!ipv4Pattern.test(ip) && !ipv6Pattern.test(ip)) {
    showToast(t('dashboard.manual_block.invalid_ip', 'Please enter a valid IP address'), 'error');
    ipInput.focus();
    return;
  }
  banIP(jail, ip);
  ipInput.value = '';
  jailSelect.value = '';
}

function renderLogOverviewSection() {
  var target = document.getElementById('logOverview');
  if (!target) return;
  var focusState = captureFocusState(target);
  target.innerHTML = renderLogOverviewContent();
  restoreFocusState(focusState);
  if (typeof updateTranslations === 'function') {
    updateTranslations();
  }
}

function updateSummaryCountersFromLatestSummary() {
  if (!latestSummary || !Array.isArray(latestSummary.jails)) {
    return;
  }
  var totalBanned = latestSummary.jails.reduce(function(sum, j) { return sum + (j.totalBanned || 0); }, 0);
  var newLastHour = latestSummary.jails.reduce(function(sum, j) { return sum + (j.newInLastHour || 0); }, 0);
  var activeJails = latestSummary.jails.length;
  var recurringWeek = recurringIPsLastWeekCount();

  var activeNode = document.getElementById('summaryActiveJails');
  var totalNode = document.getElementById('summaryTotalBanned');
  var newNode = document.getElementById('summaryNewLastHour');
  var recurringNode = document.getElementById('summaryRecurringWeek');
  if (activeNode) activeNode.textContent = String(activeJails);
  if (totalNode) totalNode.textContent = String(totalBanned);
  if (newNode) newNode.textContent = String(newLastHour);
  if (recurringNode) recurringNode.textContent = String(recurringWeek);
}

function buildBanEventsQuery(offset, append) {
  var params = [
    'limit=' + BAN_EVENTS_PAGE_SIZE,
    'offset=' + (append ? Math.min(latestBanEvents.length, BAN_EVENTS_MAX_LOADED) : 0)
  ];
  var search = (banEventsFilterText || '').trim();
  if (search) {
    params.push('search=' + encodeURIComponent(search));
  }
  var country = (banEventsFilterCountry || 'all').trim();
  if (country && country !== 'all') {
    params.push('country=' + encodeURIComponent(country));
  }
  if (banEventsFilterServer && banEventsFilterServer !== 'all') {
    params.push('serverId=' + encodeURIComponent(banEventsFilterServer));
  }
  return appPath('/api/events/bans?' + params.join('&'));
}

var DASHBOARD_REFRESH_MIN_INTERVAL_MS = 10000;
var dashboardRefreshTimer = null;
var lastDashboardRefreshAt = 0;

function scheduleDashboardRefresh() {
  if (dashboardRefreshTimer) {
    return;
  }
  var elapsed = Date.now() - lastDashboardRefreshAt;
  var delay = Math.max(DASHBOARD_REFRESH_MIN_INTERVAL_MS - elapsed, 0);
  dashboardRefreshTimer = setTimeout(function() {
    dashboardRefreshTimer = null;
    refreshDashboardData();
  }, delay);
}

// Completes a live-added row once the async whois/GeoIP enrichment finished:
// fills in country and enables the whois button without a page reload.
function updateBanEventFromWebSocket(event) {
  if (!event || !event.id) {
    return;
  }
  var updated = false;
  latestBanEvents.forEach(function(existing) {
    if (existing.id !== event.id) {
      return;
    }
    existing.country = event.country || existing.country;
    existing.hasWhois = !!event.hasWhois || !!existing.hasWhois;
    existing.hasLogs = !!event.hasLogs || !!existing.hasLogs;
    updated = true;
  });
  if (updated) {
    renderLogOverviewSection();
  }
}

function refreshBannedTableLive() {
  // Throttle live WebSocket-triggered refreshes of the banned IP overview table.
  if (bannedTableLastRefreshAt && (Date.now() - bannedTableLastRefreshAt < 3000)) {
    return;
  }
  bannedTableLastRefreshAt = Date.now();
  fetchBannedTable();
}

var bannedTableLastRefreshAt = 0;

function addBanEventFromWebSocket(event) {
  var matchesCurrentServer = !!(event && event.serverId && currentServerId && event.serverId === currentServerId);
  if (matchesCurrentServer) {
    refreshBannedTableLive();
  }
  // Server-filtered view must not receive live rows from other servers.
  if (banEventsFilterServer !== 'all' && event && event.serverId !== banEventsFilterServer) {
    if (typeof showBanEventToast === 'function') {
      showBanEventToast(event);
    }
    scheduleDashboardRefresh();
    return;
  }
  var hasSearch = (banEventsFilterText || '').trim().length > 0;
  if (hasSearch) {
    if (typeof showBanEventToast === 'function') {
      showBanEventToast(event);
    }
    scheduleDashboardRefresh();
    return;
  }
  var exists = false;
  if (event.id) {
    exists = latestBanEvents.some(function(e) { return e.id === event.id; });
  } else {
    exists = latestBanEvents.some(function(e) {
      return e.ip === event.ip && e.jail === event.jail && e.eventType === event.eventType && e.occurredAt === event.occurredAt;
    });
  }
  if (!exists) {
    if (!event.eventType) {
      event.eventType = 'ban';
    }
    console.log('Adding new event from WebSocket:', event);
    latestBanEvents.unshift(event);
    if (latestBanEvents.length > BAN_EVENTS_MAX_LOADED) {
      latestBanEvents = latestBanEvents.slice(0, BAN_EVENTS_MAX_LOADED);
    }
    if (typeof showBanEventToast === 'function') {
      showBanEventToast(event);
    }
    scheduleDashboardRefresh();
  } else {
    console.log('Skipping duplicate event:', event);
  }
}

function refreshDashboardData() {
  lastDashboardRefreshAt = Date.now();
  var enabledServers = serversCache.filter(function(s) { return s.enabled; });
  var summaryPromise;
  if (serversCache.length && enabledServers.length && currentServerId) {
    summaryPromise = fetchSummaryData();
  } else {
    summaryPromise = Promise.resolve();
  }
  Promise.all([
    summaryPromise,
    fetchBanStatisticsData(),
    fetchBanInsightsData(),
    fetchBanEventCountries()
  ]).then(function() {
    if ((bannedIPsFilterText || '').trim()) {
      updateSummaryCountersFromLatestSummary();
      fetchBannedTable();
      return;
    }
    renderDashboard();
  }).catch(function(err) {
    console.error('Error refreshing dashboard data:', err);
    if ((bannedIPsFilterText || '').trim()) {
      fetchBannedTable();
      return;
    }
    renderDashboard();
  });
}

function insightsTotals() {
  var totals = (latestBanInsights && latestBanInsights.totals) || {};
  var overall = (typeof totals.overall === 'number') ? totals.overall : null;
  if (overall === null) {
    overall = latestBanStats ? Object.keys(latestBanStats).reduce(function(sum, key) {
      return sum + (latestBanStats[key] || 0);
    }, 0) : 0;
  }
  return {
    overall: overall,
    today: (typeof totals.today === 'number') ? totals.today : 0,
    week: (typeof totals.week === 'number') ? totals.week : 0
  };
}

function totalStoredBans() {
  return insightsTotals().overall;
}

function totalBansToday() {
  return insightsTotals().today;
}

function totalBansWeek() {
  return insightsTotals().week;
}

function recurringIPsLastWeekCount() {
  var source = latestServerInsights || latestBanInsights;
  if (!source || !Array.isArray(source.recurring)) {
    return 0;
  }
  return source.recurring.length;
}

// Loads the full country list from the backend so the dropdown offers every
// known country regardless of the currently applied filters.
function fetchBanEventCountries() {
  return fetch(appPath('/api/events/bans/countries'))
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data && Array.isArray(data.countries)) {
        banEventsCountryOptions = data.countries;
      }
    })
    .catch(function(err) {
      console.error('Error fetching event countries:', err);
    });
}

function getBanEventCountries() {
  if (Array.isArray(banEventsCountryOptions)) {
    return banEventsCountryOptions;
  }
  // Fallback until the backend list has loaded
  var countries = {};
  latestBanEvents.forEach(function(event) {
    var country = (event.country || '').trim();
    var key = country.toLowerCase();
    if (!countries[key]) {
      countries[key] = country;
    }
  });
  var keys = Object.keys(countries);
  keys.sort();
  return keys.map(function(key) {
    return countries[key];
  });
}

function scheduleBanEventsRefetch() {
  if (banEventsFilterDebounce) {
    clearTimeout(banEventsFilterDebounce);
  }
  banEventsFilterDebounce = setTimeout(function() {
    banEventsFilterDebounce = null;
    refetchBanEvents();
  }, 300);
}

function getRecurringIPMap() {
  var map = {};
  if (latestBanInsights && Array.isArray(latestBanInsights.recurring)) {
    latestBanInsights.recurring.forEach(function(stat) {
      if (stat && stat.ip) {
        map[stat.ip] = stat;
      }
    });
  }
  return map;
}
