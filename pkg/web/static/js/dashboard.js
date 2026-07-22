"use strict";
// Dashboard data fetching and rendering.

var threatIntelProvider = 'none';

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

  // Slower sections load independently and don't hold up the page.
  banEventsLoading = true;
  Promise.all([
    fetchBanStatisticsData(),
    fetchBanEventsData(),
    fetchBanInsightsData()
  ])
    .catch(function(err) {
      console.error('Error loading ban events/insights:', err);
    })
    .finally(function() {
      banEventsLoading = false;
      renderDashboard();
    });

  return Promise.all([
    summaryPromise,
    fetchThreatIntelProviderData()
  ])
    .then(function() {
      renderDashboard();
    })
    .catch(function(err) {
      console.error('Error refreshing data:', err);
      latestSummaryError = err ? err.toString() : 'Unknown error';
      renderDashboard();
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

function normalizeJailBannedState(summary) {
  var nextState = {};
  var existing = jailBannedState || {};
  var jails = summary && Array.isArray(summary.jails) ? summary.jails : [];
  jails.forEach(function(jail) {
    var jailName = jail && jail.jailName ? String(jail.jailName) : '';
    if (!jailName) {
      return;
    }
    if (existing[jailName]) {
      nextState[jailName] = existing[jailName];
      return;
    }
    nextState[jailName] = {
      ips: [],
      total: 0,
      hasMore: false,
      loading: false,
      loadedQuery: null,
      error: null
    };
  });
  jailBannedState = nextState;
}

function getJailBannedState(jailName) {
  if (!jailBannedState[jailName]) {
    jailBannedState[jailName] = {
      ips: [],
      total: 0,
      hasMore: false,
      loading: false,
      loadedQuery: null,
      error: null
    };
  }
  return jailBannedState[jailName];
}

function buildJailBannedQuery(jailName, offset, limit) {
  var cappedLimit = Math.min(Math.max(limit || JAIL_BANNED_PAGE_SIZE, 1), JAIL_BANNED_MAX_LIMIT);
  var params = [
    'limit=' + encodeURIComponent(cappedLimit),
    'offset=' + encodeURIComponent(Math.max(offset || 0, 0))
  ];
  var query = (bannedIPsFilterText || '').trim();
  if (query) {
    params.push('q=' + encodeURIComponent(query));
  }
  var path = '/api/jails/' + encodeURIComponent(jailName) + '/banned?' + params.join('&');
  return withServerParam(path);
}

function isActiveBannedSearchToken(token) {
  return !token || token === bannedSearchRequestToken;
}

function setJailsSearchLoadingState(active) {
  isBannedSearchLoading = !!active;
  var wrapper = document.getElementById('jailsTableBody');
  if (!wrapper) {
    return;
  }
  wrapper.classList.toggle('opacity-60', isBannedSearchLoading);
  wrapper.classList.toggle('pointer-events-none', isBannedSearchLoading);
  wrapper.setAttribute('aria-busy', isBannedSearchLoading ? 'true' : 'false');
}

function updateSearchLoadingCounter(delta) {
  bannedSearchPendingCount += delta;
  if (bannedSearchPendingCount < 0) {
    bannedSearchPendingCount = 0;
  }
  setJailsSearchLoadingState(bannedSearchPendingCount > 0);
}

function summaryMatchesCurrentServer() {
  if (!latestSummaryServerId || !currentServerId) {
    return true;
  }
  return latestSummaryServerId === currentServerId;
}

function fetchJailBannedIPs(jailName, options) {
  if (!summaryMatchesCurrentServer()) {
    return Promise.resolve();
  }
  options = options || {};
  var append = options.append === true;
  var searchToken = options.searchToken || null;
  var skipCellRender = options.skipCellRender === true;
  var state = getJailBannedState(jailName);
  var activeQuery = (bannedIPsFilterText || '').trim();
  if (state.loading) {
    return Promise.resolve();
  }
  state.loading = true;
  state.error = null;
  var offset = append ? state.ips.length : 0;
  var url = buildJailBannedQuery(jailName, offset, JAIL_BANNED_PAGE_SIZE);
  return fetch(url)
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (!isActiveBannedSearchToken(searchToken)) {
        return;
      }
      var ips = Array.isArray(data && data.bannedIPs) ? data.bannedIPs : [];
      if (append) {
        state.ips = state.ips.concat(ips);
      } else {
        state.ips = ips;
      }
      state.total = typeof data.total === 'number' ? data.total : state.ips.length;
      state.hasMore = data && data.hasMore === true;
      state.loadedQuery = activeQuery;
      state.error = data && data.error ? formatApiError(data, '', '') : null;
    })
    .catch(function(err) {
      if (!isActiveBannedSearchToken(searchToken)) {
        return;
      }
      state.error = err ? String(err) : 'Unknown error';
      if (!append) {
        state.ips = [];
      }
      state.hasMore = false;
      state.loadedQuery = activeQuery;
    })
    .finally(function() {
      if (!isActiveBannedSearchToken(searchToken)) {
        return;
      }
      state.loading = false;
      if (!skipCellRender) {
        renderJailBannedCell(jailName);
      }
    });
}

function loadInitialJailBannedPages(summary) {
  if (!summaryMatchesCurrentServer()) {
    return;
  }
  var jails = summary && Array.isArray(summary.jails) ? summary.jails : [];
  jails.forEach(function(jail) {
    var jailName = jail && jail.jailName ? String(jail.jailName) : '';
    if (!jailName) {
      return;
    }
    var state = getJailBannedState(jailName);
    var activeQuery = (bannedIPsFilterText || '').trim();
    if (state.loading) {
      applyJailRowVisibility(jailName);
      return;
    }
    if (state.loadedQuery === activeQuery && state.ips.length > 0) {
      applyJailRowVisibility(jailName);
      return;
    }
    if (state.loadedQuery === activeQuery && state.total === 0 && !state.error) {
      applyJailRowVisibility(jailName);
      return;
    }
    fetchJailBannedIPs(jailName, { append: false });
  });
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
    fetchJailBannedIPs(jail, { append: false }),
    fetchBanEventsData()
  ]).then(function() {
    if ((bannedIPsFilterText || '').trim()) {
      updateSummaryCountersFromLatestSummary();
      updateJailRowCountersFromSummary(jail);
      renderJailBannedCell(jail);
      renderLogOverviewSection();
    } else {
      renderDashboard();
    }
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

// Rendering the upper part of the dashboard.
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
      + '    <p class="text-sm mt-1" data-i18n="dashboard.jail_local_warning_body">The file /etc/fail2ban/jail.local on the selected server exists but is not managed by Fail2ban-UI. The callback action (ui-custom-action) is missing, which means ban/unban events will not be recorded and no email alerts will be sent. To fix this, move each jail section from jail.local into its own file under /etc/fail2ban/jail.d/ (use jailname.conf to keep a default or jailname.local to override an existing .conf). Then delete jail.local so Fail2ban-UI can create its own managed version. Ensure Fail2ban-UI has write permissions to /etc/fail2ban/ — see the documentation for details.</p>'
      + '  </div>'
      + '</div>';
  }
  if (latestSummaryError) {
    html += ''
      + '<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4">'
      + escapeHtml(latestSummaryError)
      + '</div>';
  }
  // If there is no summary data, we show a loading message
  if (!summary) {
    html += ''
      + '<div class="bg-white rounded-lg shadow p-6 mb-6">'
      + '  <p class="text-gray-500" data-i18n="dashboard.loading_summary">Loading summary data…</p>'
      + '</div>';
  } else {
    // If there is "summary data", we render the complete upper part of the dashboard here.
    var totalBanned = summary.jails ? summary.jails.reduce(function(sum, j) { return sum + (j.totalBanned || 0); }, 0) : 0;
    var newLastHour = summary.jails ? summary.jails.reduce(function(sum, j) { return sum + (j.newInLastHour || 0); }, 0) : 0;
    var recurringWeekCount = recurringIPsLastWeekCount();
    html += ''
      + '<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">'
      + '  <div class="bg-white rounded-lg shadow p-4">'
      + '    <p class="text-sm text-gray-500" data-i18n="dashboard.cards.active_jails">Active Jails</p>'
      + '    <p id="summaryActiveJails" class="text-2xl font-semibold text-gray-800">' + (summary.jails ? summary.jails.length : 0) + '</p>'
      + '  </div>'
      + '  <div class="bg-white rounded-lg shadow p-4">'
      + '    <p class="text-sm text-gray-500" data-i18n="dashboard.cards.total_banned">Total Banned IPs</p>'
      + '    <p id="summaryTotalBanned" class="text-2xl font-semibold text-gray-800">' + totalBanned + '</p>'
      + '  </div>'
      + '  <div class="bg-white rounded-lg shadow p-4">'
      + '    <p class="text-sm text-gray-500" data-i18n="dashboard.cards.new_last_hour">New Last Hour</p>'
      + '    <p id="summaryNewLastHour" class="text-2xl font-semibold text-gray-800">' + newLastHour + '</p>'
      + '  </div>'
      + '  <div class="bg-white rounded-lg shadow p-4">'
      + '    <p class="text-sm text-gray-500" data-i18n="dashboard.cards.recurring_week">Recurring IPs</p>'
      + '    <p id="summaryRecurringWeek" class="text-2xl font-semibold text-gray-800">' + recurringWeekCount + '</p>'
      + '    <p class="text-xs text-gray-500 mt-1" data-i18n="dashboard.cards.recurring_hint">Keep an eye on repeated offenders across all servers.</p>'
      + '  </div>'
      + '</div>'
      + '<div class="bg-white rounded-lg shadow p-6 mb-6">'
      + '  <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">'
      + '    <div>'
      + '      <h3 class="text-lg font-medium text-gray-900 mb-2" data-i18n="dashboard.overview">Overview active Jails and Blocks</h3>'
      + '      <p class="text-sm text-gray-500" data-i18n="dashboard.overview_hint">Use the search to filter banned IPs and click a jail to edit its configuration.</p>'
      + '      <p class="text-sm text-gray-500 mt-1" data-i18n="dashboard.overview_detail">Collapse or expand long lists to quickly focus on impacted services.</p>'
      + '    </div>'
      + '    <div>'
      + '      <label for="ipSearch" class="block text-sm font-medium text-gray-700 mb-2" data-i18n="dashboard.search_label">Search Banned IPs</label>'
      + '      <input type="text" id="ipSearch" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" data-i18n-placeholder="dashboard.search_placeholder" placeholder="Enter IP address to search" value="' + escapeHtml(bannedIPsFilterText) + '" oninput="filterIPs()">'
      + '    </div>'
      + '  </div>';
    if (!summary.jails || summary.jails.length === 0) {
      html += '<p class="text-gray-500 mt-4" data-i18n="dashboard.no_jails">No jails found.</p>';
    } else {
      html += ''
        + '<div id="jailsTableWrapper" class="overflow-x-auto mt-4">'
        + '  <table class="min-w-full divide-y divide-gray-200 text-sm sm:text-base" id="jailsTable">'
        + '    <thead class="bg-gray-50">'
        + '      <tr>'
        + '        <th class="px-2 py-1 sm:px-6 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="dashboard.table.jail">Jail</th>'
        + '        <th class="hidden sm:table-cell px-2 py-1 sm:px-6 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="dashboard.table.total_banned">Total Banned</th>'
        + '        <th class="hidden sm:table-cell px-2 py-1 sm:px-6 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="dashboard.table.new_last_hour">New Last Hour</th>'
        + '        <th class="px-2 py-1 sm:px-6 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="dashboard.table.banned_ips">Banned IPs</th>'
        + '      </tr>'
        + '    </thead>'
        + '    <tbody id="jailsTableBody" class="bg-white divide-y divide-gray-200 transition-opacity duration-150">';
      summary.jails.forEach(function(jail) {
        var jailName = jail.jailName || '';
        var rowId = slugifyId(jailName, 'jail-row');
        var cellId = slugifyId(jailName, 'banned-cell');
        var totalId = slugifyId(jailName, 'total-banned');
        var newLastHourId = slugifyId(jailName, 'new-last-hour');
        var bannedHTML = renderBannedIPs(jailName);
        html += ''
          + '<tr class="jail-row hover:bg-gray-50" id="' + rowId + '">'
          + '  <td class="px-2 py-1 sm:px-6 sm:py-4 whitespace-normal break-words">'
          + '    <a href="#" onclick="openJailConfigModal(\'' + escapeHtml(jailName) + '\')" class="text-blue-600 hover:text-blue-800">'
          +        escapeHtml(jailName)
          + '    </a>'
          + '  </td>'
          + '  <td id="' + totalId + '" class="hidden sm:table-cell px-2 py-1 sm:px-6 sm:py-4 whitespace-normal break-words">' + (jail.totalBanned || 0) + '</td>'
          + '  <td id="' + newLastHourId + '" class="hidden sm:table-cell px-2 py-1 sm:px-6 sm:py-4 whitespace-normal break-words">' + (jail.newInLastHour || 0) + '</td>'
          + '  <td class="px-2 py-1 sm:px-6 sm:py-4 whitespace-normal break-words" id="' + cellId + '">' + bannedHTML + '</td>'
          + '</tr>';
      });

      html += '    </tbody></table>';
      html += '</div>';
    }
    html += '</div>';
  }
  if (summary && summary.jails && summary.jails.length > 0) {
    var enabledJails = summary.jails.filter(function(j) { return j.enabled !== false; });
    if (enabledJails.length > 0) {
      // Rendering the manual ban-block from the dashboard here
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
      // Rendering the end of the manual ban-block form after fill in the enabled jails
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
  setJailsSearchLoadingState(isBannedSearchLoading);
  if (summary && summary.jails && summary.jails.length > 0) {
    normalizeJailBannedState(summary);
    applyAllJailRowVisibility();
    loadInitialJailBannedPages(summary);
  }
}

// =========================================================================
//  Rendering the colapsable "Banned IPs per jail" section
// =========================================================================

function renderBannedIPs(jailName) {
  var state = getJailBannedState(jailName);
  var query = (bannedIPsFilterText || '').trim();
  var content = '<div class="space-y-2">';
  if (state.loading && (!state.ips || state.ips.length === 0)) {
    return content + '<em class="text-gray-500">' + t('dashboard.banned.loading', 'Loading banned IPs...') + '</em></div>';
  }
  if (state.error) {
    return content + '<em class="text-red-600">' + escapeHtml(state.error) + '</em></div>';
  }
  if (!state.ips || state.ips.length === 0) {
    if (query) {
      return content + '<em class="text-gray-500">' + t('dashboard.banned.no_matches', 'No matching IPs') + '</em></div>';
    }
    return content + '<em class="text-gray-500" data-i18n="dashboard.no_banned_ips">No banned IPs</em></div>';
  }
  function bannedIpRow(ip) {
    var safeIp = escapeHtml(ip);
    var encodedIp = encodeURIComponent(ip);
    var ipLabel = '';
    var ipText = query ? highlightQueryMatch(ip, query) : safeIp;
    if (isThreatIntelEnabled()) {
      ipLabel = ''
        + '<span class="text-sm text-blue-600 hover:text-blue-800 cursor-pointer decoration-dotted"'
        + '    data-ip-value="' + encodedIp + '"'
        + '    role="button" tabindex="0"'
        + '    onclick="openThreatIntelModal(decodeURIComponent(this.getAttribute(\'data-ip-value\')))"'
        + '    onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();openThreatIntelModal(decodeURIComponent(this.getAttribute(\'data-ip-value\')));}">' + ipText + '</span>';
    } else {
      ipLabel = '<span class="text-sm" data-ip-value="' + encodedIp + '">' + ipText + '</span>';
    }
    return ''
      + '<div class="flex items-center justify-between banned-ip-item" data-ip="' + safeIp + '">'
      + ipLabel
      + '  <button class="bg-yellow-500 text-white px-3 py-1 rounded text-sm hover:bg-yellow-600 transition-colors"'
      + '    onclick="unbanIP(\'' + escapeHtml(jailName) + '\', \'' + escapeHtml(ip) + '\')">'
      + '    <span data-i18n="dashboard.unban">Unban</span>'
      + '  </button>'
      + '</div>';
  }
  state.ips.forEach(function(ip) {
    content += bannedIpRow(ip);
  });
  if (state.hasMore) {
    var loadMoreLabel = t('dashboard.banned.show_more', 'Show more');
    content += ''
      + '<button type="button" class="text-xs font-semibold text-blue-600 hover:text-blue-800 banned-ip-toggle"'
      + ' onclick="loadMoreJailBannedIPs(\'' + escapeHtml(jailName) + '\')">'
      + escapeHtml(loadMoreLabel)
      + '</button>';
  }
  content += '</div>';
  return content;
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
  var totalLabel = banEventsTotal != null ? banEventsTotal : '—';
  // Rendering the search and filter options for the recent stored events
  html += ''
    + '<div class="flex flex-col sm:flex-row gap-3 mb-4">'
    + '  <div class="flex-1">'
    + '    <label for="recentEventsSearch" class="block text-sm font-medium text-gray-700 mb-1" data-i18n="logs.search.label">Search events</label>'
    + '    <input type="text" id="recentEventsSearch" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="' + t('logs.search.placeholder', 'Search IP, jail or server') + '" value="' + escapeHtml(banEventsFilterText) + '" oninput="updateBanEventsSearch(this.value)">'
    + '  </div>'
    + '  <div class="w-full sm:w-48">'
    + '    <label for="recentEventsCountry" class="block text-sm font-medium text-gray-700 mb-1" data-i18n="logs.search.country_label">Country</label>'
    + '    <select id="recentEventsCountry" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" onchange="updateBanEventsCountry(this.value)">'
    + '      <option value="all"' + (banEventsFilterCountry === 'all' ? ' selected' : '') + ' data-i18n="logs.search.country_all">All countries</option>';
    // Create list of countries for the filter options
    countries.forEach(function(country) {
    var value = (country || '').trim();
    var optionValue = value ? value.toLowerCase() : '__unknown__';
    var label = value || t('logs.search.country_unknown', 'Unknown');
    var selected = banEventsFilterCountry.toLowerCase() === optionValue ? ' selected' : '';
    html += '<option value="' + optionValue + '"' + selected + '>' + escapeHtml(label) + '</option>';
  });
  // Render the missing part of the select and create table header for the recent stored events
  html += '    </select>'
    + '  </div>'
    + '</div>'
    + '<p class="text-xs text-gray-500 mb-3">' + t('logs.overview.recent_count_label', 'Events shown') + ': ' + latestBanEvents.length + ' / ' + totalLabel + '</p>'
    + '<div class="overflow-x-auto">'
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
      + '<span class="align-middle" data-i18n="loading">Loading…</span>'
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
        + '        <td class="hidden md:table-cell px-2 py-2 whitespace-nowrap">' + escapeHtml(event.country || '—') + '</td>'
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

function updateBanEventsCountry(value) {
  banEventsFilterCountry = value || 'all';
  fetchBanEventsData().then(function() {
    renderLogOverviewSection();
  });
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

function scheduleBannedIPsRefetch() {
  if (bannedIPsFilterDebounce) {
    clearTimeout(bannedIPsFilterDebounce);
  }
  bannedIPsFilterDebounce = setTimeout(function() {
    bannedIPsFilterDebounce = null;
    bannedSearchRequestToken += 1;
    var token = bannedSearchRequestToken;
    bannedSearchPendingCount = 0;
    var jailNames = Object.keys(jailBannedState || {});
    if (jailNames.length === 0) {
      setJailsSearchLoadingState(false);
      return;
    }
    jailNames.forEach(function(jailName) {
      var state = jailBannedState[jailName];
      state.loading = false;
      state.ips = [];
      state.total = 0;
      state.hasMore = false;
      state.loadedQuery = null;
      state.error = null;
      renderJailBannedCell(jailName);
      updateSearchLoadingCounter(1);
      fetchJailBannedIPs(jailName, { append: false, searchToken: token, skipCellRender: true })
        .finally(function() {
          if (!isActiveBannedSearchToken(token)) {
            return;
          }
          renderJailBannedCell(jailName);
          updateSearchLoadingCounter(-1);
        });
    });
  }, 300);
}

function loadMoreJailBannedIPs(jailName) {
  var state = getJailBannedState(jailName);
  if (state.loading || !state.hasMore) {
    return;
  }
  fetchJailBannedIPs(jailName, { append: true });
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
      renderLogOverviewSection();
    })
    .catch(function(err) { showToast(String(err), 'error'); });
}

// Filtering function for the banned IPs for the dashboard.
function filterIPs() {
  var input = document.getElementById('ipSearch');
  updateBannedIPsSearch(input ? input.value : '');
}

// =========================================================================
//  Helper Functions
// =========================================================================

// Helper function to toggle the banned list section for the dashboard.
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

// Helper function to toggle the manual block section for the dashboard.
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

// This handles manual block actions and calls the banIP function.
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

// Helper function to add the "Internal Log Overview" content to the dashboard.
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

function renderJailBannedCell(jailName) {
  var cellId = slugifyId(jailName || 'jail', 'banned-cell');
  var rowId = slugifyId(jailName || 'jail', 'jail-row');
  var cell = document.getElementById(cellId);
  var row = document.getElementById(rowId);
  if (!cell || !row) {
    return;
  }
  var state = getJailBannedState(jailName);
  cell.innerHTML = renderBannedIPs(jailName);
  applyJailRowVisibility(jailName);
  if (typeof updateTranslations === 'function') {
    updateTranslations();
  }
  if (isLOTRModeActive) {
    updateDashboardLOTRTerminology(true);
  }
}

function applyJailRowVisibility(jailName) {
  var rowId = slugifyId(jailName || 'jail', 'jail-row');
  var row = document.getElementById(rowId);
  if (!row) {
    return;
  }
  var query = (bannedIPsFilterText || '').trim();
  if (!query) {
    row.style.display = '';
    return;
  }
  var state = getJailBannedState(jailName);
  row.style.display = (state.loading || state.total > 0) ? '' : 'none';
}

function applyAllJailRowVisibility() {
  Object.keys(jailBannedState || {}).forEach(function(jailName) {
    applyJailRowVisibility(jailName);
  });
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

function updateJailRowCountersFromSummary(jailName) {
  if (!latestSummary || !Array.isArray(latestSummary.jails) || !jailName) {
    return;
  }
  var jail = latestSummary.jails.find(function(item) {
    return item && item.jailName === jailName;
  });
  if (!jail) {
    return;
  }
  var totalNode = document.getElementById(slugifyId(jailName, 'total-banned'));
  var newNode = document.getElementById(slugifyId(jailName, 'new-last-hour'));
  if (totalNode) totalNode.textContent = String(jail.totalBanned || 0);
  if (newNode) newNode.textContent = String(jail.newInLastHour || 0);
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
  if (currentServerId) {
    params.push('serverId=' + encodeURIComponent(currentServerId));
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

// Helper function to add a new ban event from the WebSocket to the dashboard.
function addBanEventFromWebSocket(event) {
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

// Helper function to refresh the dashboard data by fetching the summary and ban insights.
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
    fetchBanInsightsData()
  ]).then(function() {
    if ((bannedIPsFilterText || '').trim()) {
      updateSummaryCountersFromLatestSummary();
      Object.keys(jailBannedState || {}).forEach(function(jailName) {
        updateJailRowCountersFromSummary(jailName);
        renderJailBannedCell(jailName);
      });
      applyAllJailRowVisibility();
      return;
    }
    renderDashboard();
  }).catch(function(err) {
    console.error('Error refreshing dashboard data:', err);
    if ((bannedIPsFilterText || '').trim()) {
      applyAllJailRowVisibility();
      return;
    }
    renderDashboard();
  });
}

// Helper functions to query the total number of banned IPs
function totalStoredBans() {
  if (latestBanInsights && latestBanInsights.totals && typeof latestBanInsights.totals.overall === 'number') {
    return latestBanInsights.totals.overall;
  }
  if (!latestBanStats) return 0;
  return Object.keys(latestBanStats).reduce(function(sum, key) {
    return sum + (latestBanStats[key] || 0);
  }, 0);
}

// Helper functions to query the total number of banned IPs of today.
function totalBansToday() {
  if (latestBanInsights && latestBanInsights.totals && typeof latestBanInsights.totals.today === 'number') {
    return latestBanInsights.totals.today;
  }
  return 0;
}

// Helper functions to query the total number of banned IPs of last week.
function totalBansWeek() {
  if (latestBanInsights && latestBanInsights.totals && typeof latestBanInsights.totals.week === 'number') {
    return latestBanInsights.totals.week;
  }
  return 0;
}

// Helper functions to query the total number of recurring IPs of last week.
function recurringIPsLastWeekCount() {
  var source = latestServerInsights || latestBanInsights;
  if (!source || !Array.isArray(source.recurring)) {
    return 0;
  }
  return source.recurring.length;
}

// Helper functions to query the countries of the banned IPs.
function getBanEventCountries() {
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

// Helper functions to schedule the refetch of the banned events.
function scheduleBanEventsRefetch() {
  if (banEventsFilterDebounce) {
    clearTimeout(banEventsFilterDebounce);
  }
  banEventsFilterDebounce = setTimeout(function() {
    banEventsFilterDebounce = null;
    fetchBanEventsData().then(function() {
      renderLogOverviewSection();
    });
  }, 300);
}

// Helper functions to query the recurring IPs of the banned IPs.
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
