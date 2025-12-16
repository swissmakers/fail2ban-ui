// Dashboard rendering and data fetching functions for Fail2ban UI
"use strict";

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

  return Promise.all([
    summaryPromise,
    fetchBanStatisticsData(),
    fetchBanEventsData(),
    fetchBanInsightsData()
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

function fetchSummaryData() {
  return fetch(withServerParam('/api/summary'))
    .then(function(res) { return res.json(); })
    .then(function(data) {
      if (data && !data.error) {
        latestSummary = data;
        latestSummaryError = null;
      } else {
        latestSummary = null;
        latestSummaryError = data && data.error ? data.error : t('dashboard.errors.summary_failed', 'Failed to load summary from server.');
      }
    })
    .catch(function(err) {
      latestSummary = null;
      latestSummaryError = err ? err.toString() : 'Unknown error';
    });
}

function fetchBanStatisticsData() {
  return fetch('/api/events/bans/stats')
    .then(function(res) { return res.json(); })
    .then(function(data) {
      latestBanStats = data && data.counts ? data.counts : {};
    })
    .catch(function(err) {
      console.error('Error fetching ban statistics:', err);
      latestBanStats = latestBanStats || {};
    });
}

function fetchBanEventsData() {
  return fetch('/api/events/bans?limit=200')
    .then(function(res) { return res.json(); })
    .then(function(data) {
      latestBanEvents = data && data.events ? data.events : [];
      // Track the last event ID to prevent duplicates from WebSocket
      if (latestBanEvents.length > 0 && wsManager) {
        wsManager.lastBanEventId = latestBanEvents[0].id;
      }
    })
    .catch(function(err) {
      console.error('Error fetching ban events:', err);
      latestBanEvents = latestBanEvents || [];
    });
}

// Add new ban or unban event from WebSocket
function addBanEventFromWebSocket(event) {
  // Check if event already exists (prevent duplicates)
  // Only check by ID if both events have IDs
  var exists = false;
  if (event.id) {
    exists = latestBanEvents.some(function(e) {
      return e.id === event.id;
    });
  } else {
    // If no ID, check by IP, jail, eventType, and occurredAt timestamp
    exists = latestBanEvents.some(function(e) {
      return e.ip === event.ip && 
             e.jail === event.jail && 
             e.eventType === event.eventType &&
             e.occurredAt === event.occurredAt;
    });
  }
  
  if (!exists) {
    // Ensure eventType is set (default to 'ban' for backward compatibility)
    if (!event.eventType) {
      event.eventType = 'ban';
    }
    console.log('Adding new event from WebSocket:', event);
    
    // Prepend to the beginning of the array
    latestBanEvents.unshift(event);
    // Keep only the last 200 events
    if (latestBanEvents.length > 200) {
      latestBanEvents = latestBanEvents.slice(0, 200);
    }
    
    // Show toast notification first
    if (typeof showBanEventToast === 'function') {
      showBanEventToast(event);
    }
    
    // Refresh dashboard data (summary, stats, insights) and re-render
    refreshDashboardData();
  } else {
    console.log('Skipping duplicate event:', event);
  }
}

// Refresh dashboard data when new ban event arrives via WebSocket
function refreshDashboardData() {
  // Refresh ban statistics and insights in the background
  // Also refresh summary if we have a server selected
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
    // Re-render the dashboard to show updated stats
    renderDashboard();
  }).catch(function(err) {
    console.error('Error refreshing dashboard data:', err);
    // Still re-render even if refresh fails
    renderDashboard();
  });
}

function fetchBanInsightsData() {
  var sevenDaysAgo = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000)).toISOString();
  var sinceQuery = '?since=' + encodeURIComponent(sevenDaysAgo);
  var globalPromise = fetch('/api/events/bans/insights' + sinceQuery)
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

function totalStoredBans() {
  if (latestBanInsights && latestBanInsights.totals && typeof latestBanInsights.totals.overall === 'number') {
    return latestBanInsights.totals.overall;
  }
  if (!latestBanStats) return 0;
  return Object.keys(latestBanStats).reduce(function(sum, key) {
    return sum + (latestBanStats[key] || 0);
  }, 0);
}

function totalBansToday() {
  if (latestBanInsights && latestBanInsights.totals && typeof latestBanInsights.totals.today === 'number') {
    return latestBanInsights.totals.today;
  }
  return 0;
}

function totalBansWeek() {
  if (latestBanInsights && latestBanInsights.totals && typeof latestBanInsights.totals.week === 'number') {
    return latestBanInsights.totals.week;
  }
  return 0;
}

function recurringIPsLastWeekCount() {
  var source = latestServerInsights || latestBanInsights;
  if (!source || !Array.isArray(source.recurring)) {
    return 0;
  }
  return source.recurring.length;
}

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

function getFilteredBanEvents() {
  var text = (banEventsFilterText || '').toLowerCase();
  var countryFilter = (banEventsFilterCountry || '').toLowerCase();

  return latestBanEvents.filter(function(event) {
    var matchesCountry = !countryFilter || countryFilter === 'all';
    if (!matchesCountry) {
      var eventCountryValue = (event.country || '').toLowerCase();
      if (!eventCountryValue) {
        eventCountryValue = '__unknown__';
      }
      matchesCountry = eventCountryValue === countryFilter;
    }

    if (!text) {
      return matchesCountry;
    }

    var haystack = [
      event.ip,
      event.jail,
      event.serverName,
      event.hostname,
      event.country
    ].map(function(value) {
      return (value || '').toLowerCase();
    });

    var matchesText = haystack.some(function(value) {
      return value.indexOf(text) !== -1;
    });

    return matchesCountry && matchesText;
  });
}

function scheduleLogOverviewRender() {
  if (banEventsFilterDebounce) {
    clearTimeout(banEventsFilterDebounce);
  }
  banEventsFilterDebounce = setTimeout(function() {
    renderLogOverviewSection();
    banEventsFilterDebounce = null;
  }, 100);
}

function updateBanEventsSearch(value) {
  banEventsFilterText = value || '';
  scheduleLogOverviewRender();
}

function updateBanEventsCountry(value) {
  banEventsFilterCountry = value || 'all';
  scheduleLogOverviewRender();
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

function renderBannedIPs(jailName, ips) {
  if (!ips || ips.length === 0) {
    return '<em class="text-gray-500" data-i18n="dashboard.no_banned_ips">No banned IPs</em>';
  }
  var listId = slugifyId(jailName || 'jail', 'banned-list');
  var hiddenId = listId + '-hidden';
  var toggleId = listId + '-toggle';
  var maxVisible = 5;
  var visible = ips.slice(0, maxVisible);
  var hidden = ips.slice(maxVisible);
  var content = '<div class="space-y-2">';

  function bannedIpRow(ip) {
    var safeIp = escapeHtml(ip);
    var encodedIp = encodeURIComponent(ip);
    return ''
      + '<div class="flex items-center justify-between banned-ip-item" data-ip="' + safeIp + '">'
      + '  <span class="text-sm" data-ip-value="' + encodedIp + '">' + safeIp + '</span>'
      + '  <button class="bg-yellow-500 text-white px-3 py-1 rounded text-sm hover:bg-yellow-600 transition-colors"'
      + '    onclick="unbanIP(\'' + escapeHtml(jailName) + '\', \'' + escapeHtml(ip) + '\')">'
      + '    <span data-i18n="dashboard.unban">Unban</span>'
      + '  </button>'
      + '</div>';
  }

  visible.forEach(function(ip) {
    content += bannedIpRow(ip);
  });

  if (hidden.length) {
    content += '<div class="space-y-2 mt-2 hidden banned-ip-hidden" id="' + hiddenId + '" data-initially-hidden="true">';
    hidden.forEach(function(ip) {
      content += bannedIpRow(ip);
    });
    content += '</div>';

    var moreLabel = t('dashboard.banned.show_more', 'Show more') + ' +' + hidden.length;
    var lessLabel = t('dashboard.banned.show_less', 'Hide extra');
    content += ''
      + '<button type="button" class="text-xs font-semibold text-blue-600 hover:text-blue-800 banned-ip-toggle"'
      + ' id="' + toggleId + '"'
      + ' data-target="' + hiddenId + '"'
      + ' data-more-label="' + escapeHtml(moreLabel) + '"'
      + ' data-less-label="' + escapeHtml(lessLabel) + '"'
      + ' data-expanded="false"'
      + ' onclick="toggleBannedList(\'' + hiddenId + '\', \'' + toggleId + '\')">'
      + escapeHtml(moreLabel)
      + '</button>';
  }

  content += '</div>';
  return content;
}

function filterIPs() {
  const input = document.getElementById("ipSearch");
  if (!input) {
    return;
  }
  const query = input.value.trim();
  const rows = document.querySelectorAll("#jailsTable .jail-row");

  rows.forEach(row => {
    const hiddenSections = row.querySelectorAll(".banned-ip-hidden");
    const toggleButtons = row.querySelectorAll(".banned-ip-toggle");

    if (query === "") {
      hiddenSections.forEach(section => {
        if (section.getAttribute("data-initially-hidden") === "true") {
          section.classList.add("hidden");
        }
      });
      toggleButtons.forEach(button => {
        const moreLabel = button.getAttribute("data-more-label");
        if (moreLabel) {
          button.textContent = moreLabel;
        }
        button.setAttribute("data-expanded", "false");
      });
    } else {
      hiddenSections.forEach(section => section.classList.remove("hidden"));
      toggleButtons.forEach(button => {
        const lessLabel = button.getAttribute("data-less-label");
        if (lessLabel) {
          button.textContent = lessLabel;
        }
        button.setAttribute("data-expanded", "true");
      });
    }

    const ipItems = row.querySelectorAll(".banned-ip-item");
    let rowHasMatch = false;

    ipItems.forEach(item => {
      const span = item.querySelector("span.text-sm");
      if (!span) return;

      const storedValue = span.getAttribute("data-ip-value");
      const originalIP = storedValue ? decodeURIComponent(storedValue) : span.textContent.trim();

      if (query === "") {
        item.style.display = "";
        span.textContent = originalIP;
        rowHasMatch = true;
      } else if (originalIP.indexOf(query) !== -1) {
        item.style.display = "";
        span.innerHTML = highlightQueryMatch(originalIP, query);
        rowHasMatch = true;
      } else {
        item.style.display = "none";
      }
    });

    row.style.display = rowHasMatch ? "" : "none";
  });
}

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

function unbanIP(jail, ip) {
  const confirmMsg = isLOTRModeActive 
    ? 'Restore ' + ip + ' to the realm from ' + jail + '?'
    : 'Unban IP ' + ip + ' from jail ' + jail + '?';
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
      if (data.error) {
        showToast("Error unbanning IP: " + data.error, 'error');
      }
      // Don't show success toast here - the WebSocket unban event will show a proper toast
      return refreshData({ silent: true });
    })
    .catch(function(err) {
      showToast("Error: " + err, 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

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

  if (latestSummaryError) {
    html += ''
      + '<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4">'
      + escapeHtml(latestSummaryError)
      + '</div>';
  }

  if (!summary) {
    html += ''
      + '<div class="bg-white rounded-lg shadow p-6 mb-6">'
      + '  <p class="text-gray-500" data-i18n="dashboard.loading_summary">Loading summary data…</p>'
      + '</div>';
  } else {
    var totalBanned = summary.jails ? summary.jails.reduce(function(sum, j) { return sum + (j.totalBanned || 0); }, 0) : 0;
    var newLastHour = summary.jails ? summary.jails.reduce(function(sum, j) { return sum + (j.newInLastHour || 0); }, 0) : 0;
    var recurringWeekCount = recurringIPsLastWeekCount();

    html += ''
      + '<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">'
      + '  <div class="bg-white rounded-lg shadow p-4">'
      + '    <p class="text-sm text-gray-500" data-i18n="dashboard.cards.active_jails">Active Jails</p>'
      + '    <p class="text-2xl font-semibold text-gray-800">' + (summary.jails ? summary.jails.length : 0) + '</p>'
      + '  </div>'
      + '  <div class="bg-white rounded-lg shadow p-4">'
      + '    <p class="text-sm text-gray-500" data-i18n="dashboard.cards.total_banned">Total Banned IPs</p>'
      + '    <p class="text-2xl font-semibold text-gray-800">' + totalBanned + '</p>'
      + '  </div>'
      + '  <div class="bg-white rounded-lg shadow p-4">'
      + '    <p class="text-sm text-gray-500" data-i18n="dashboard.cards.new_last_hour">New Last Hour</p>'
      + '    <p class="text-2xl font-semibold text-gray-800">' + newLastHour + '</p>'
      + '  </div>'
      + '  <div class="bg-white rounded-lg shadow p-4">'
      + '    <p class="text-sm text-gray-500" data-i18n="dashboard.cards.recurring_week">Recurring IPs (7 days)</p>'
      + '    <p class="text-2xl font-semibold text-gray-800">' + recurringWeekCount + '</p>'
      + '    <p class="text-xs text-gray-500 mt-1" data-i18n="dashboard.cards.recurring_hint">Keep an eye on repeated offenders across all servers.</p>'
      + '  </div>'
      + '</div>';

    html += ''
      + '<div class="bg-white rounded-lg shadow p-6 mb-6">'
      + '  <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">'
      + '    <div>'
      + '      <h3 class="text-lg font-medium text-gray-900 mb-2" data-i18n="dashboard.overview">Overview active Jails and Blocks</h3>'
      + '      <p class="text-sm text-gray-500" data-i18n="dashboard.overview_hint">Use the search to filter banned IPs and click a jail to edit its configuration.</p>'
      + '      <p class="text-sm text-gray-500 mt-1" data-i18n="dashboard.overview_detail">Collapse or expand long lists to quickly focus on impacted services.</p>'
      + '    </div>'
      + '    <div>'
      + '      <label for="ipSearch" class="block text-sm font-medium text-gray-700 mb-2" data-i18n="dashboard.search_label">Search Banned IPs</label>'
      + '      <input type="text" id="ipSearch" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" data-i18n-placeholder="dashboard.search_placeholder" placeholder="Enter IP address to search" onkeyup="filterIPs()" pattern="[0-9.]*">'
      + '    </div>'
      + '  </div>';

    if (!summary.jails || summary.jails.length === 0) {
      html += '<p class="text-gray-500 mt-4" data-i18n="dashboard.no_jails">No jails found.</p>';
    } else {
      html += ''
        + '<div class="overflow-x-auto mt-4">'
        + '  <table class="min-w-full divide-y divide-gray-200 text-sm sm:text-base" id="jailsTable">'
        + '    <thead class="bg-gray-50">'
        + '      <tr>'
        + '        <th class="px-2 py-1 sm:px-6 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="dashboard.table.jail">Jail</th>'
        + '        <th class="hidden sm:table-cell px-2 py-1 sm:px-6 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="dashboard.table.total_banned">Total Banned</th>'
        + '        <th class="hidden sm:table-cell px-2 py-1 sm:px-6 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="dashboard.table.new_last_hour">New Last Hour</th>'
        + '        <th class="px-2 py-1 sm:px-6 sm:py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" data-i18n="dashboard.table.banned_ips">Banned IPs</th>'
        + '      </tr>'
        + '    </thead>'
        + '    <tbody class="bg-white divide-y divide-gray-200">';

      summary.jails.forEach(function(jail) {
        var bannedHTML = renderBannedIPs(jail.jailName, jail.bannedIPs || []);
        html += ''
          + '<tr class="jail-row hover:bg-gray-50">'
          + '  <td class="px-2 py-1 sm:px-6 sm:py-4 whitespace-normal break-words">'
          + '    <a href="#" onclick="openJailConfigModal(\'' + escapeHtml(jail.jailName) + '\')" class="text-blue-600 hover:text-blue-800">'
          +        escapeHtml(jail.jailName)
          + '    </a>'
          + '  </td>'
          + '  <td class="hidden sm:table-cell px-2 py-1 sm:px-6 sm:py-4 whitespace-normal break-words">' + (jail.totalBanned || 0) + '</td>'
          + '  <td class="hidden sm:table-cell px-2 py-1 sm:px-6 sm:py-4 whitespace-normal break-words">' + (jail.newInLastHour || 0) + '</td>'
          + '  <td class="px-2 py-1 sm:px-6 sm:py-4 whitespace-normal break-words">' + bannedHTML + '</td>'
          + '</tr>';
      });

      html += '    </tbody></table>';
      html += '</div>';
    }

    html += '</div>'; // close overview card
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

  filterIPs();
  initializeSearch();
  if (typeof updateTranslations === 'function') {
    updateTranslations();
  }
  // Update LOTR terminology if active
  if (isLOTRModeActive) {
    updateDashboardLOTRTerminology(true);
  }
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

  if (statsKeys.length === 0 && totalStored === 0) {
    html += '<p class="text-gray-500" data-i18n="logs.overview.empty">No ban events recorded yet.</p>';
  } else {
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

  html += '<h4 class="text-md font-semibold text-gray-800 mb-3" data-i18n="logs.overview.recent_events_title">Recent stored events</h4>';

  if (!latestBanEvents.length) {
    html += '<p class="text-gray-500" data-i18n="logs.overview.recent_empty">No stored events found.</p>';
  } else {
    var countries = getBanEventCountries();
    var filteredEvents = getFilteredBanEvents();
    var recurringMap = getRecurringIPMap();
    var searchQuery = (banEventsFilterText || '').trim();

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

    countries.forEach(function(country) {
      var value = (country || '').trim();
      var optionValue = value ? value.toLowerCase() : '__unknown__';
      var label = value || t('logs.search.country_unknown', 'Unknown');
      var selected = banEventsFilterCountry.toLowerCase() === optionValue ? ' selected' : '';
      html += '<option value="' + optionValue + '"' + selected + '>' + escapeHtml(label) + '</option>';
    });

    html += '    </select>'
      + '  </div>'
      + '</div>';

    html += '<p class="text-xs text-gray-500 mb-3">' + t('logs.overview.recent_count_label', 'Events shown') + ': ' + filteredEvents.length + ' / ' + latestBanEvents.length + '</p>';

    if (!filteredEvents.length) {
      html += '<p class="text-gray-500" data-i18n="logs.overview.recent_filtered_empty">No stored events match the current filters.</p>';
    } else {
    html += ''
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
    filteredEvents.forEach(function(event) {
      var index = latestBanEvents.indexOf(event);
      var hasWhois = event.whois && event.whois.trim().length > 0;
      var hasLogs = event.logs && event.logs.trim().length > 0;
      var serverValue = event.serverName || event.serverId || '';
      var jailValue = event.jail || '';
      var ipValue = event.ip || '';
      var serverCell = highlightQueryMatch(serverValue, searchQuery);
      var jailCell = highlightQueryMatch(jailValue, searchQuery);
      var ipCell = highlightQueryMatch(ipValue, searchQuery);
      if (event.ip && recurringMap[event.ip]) {
        ipCell += ' <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-800">' + t('logs.badge.recurring', 'Recurring') + '</span>';
      }
      var eventType = event.eventType || 'ban';
      var eventTypeBadge = '';
      if (eventType === 'unban') {
        eventTypeBadge = ' <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">Unban</span>';
      } else {
        eventTypeBadge = ' <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">Ban</span>';
      }
      html += ''
        + '      <tr class="hover:bg-gray-50">'
        + '        <td class="px-2 py-2 whitespace-nowrap">' + escapeHtml(formatDateTime(event.occurredAt || event.createdAt)) + '</td>'
        + '        <td class="px-2 py-2 whitespace-nowrap">' + serverCell + '</td>'
        + '        <td class="hidden sm:table-cell px-2 py-2 whitespace-nowrap">' + jailCell + '</td>'
        + '        <td class="px-2 py-2 whitespace-nowrap">' + ipCell + eventTypeBadge + '</td>'
        + '        <td class="hidden md:table-cell px-2 py-2 whitespace-nowrap">' + escapeHtml(event.country || '—') + '</td>'
        + '        <td class="px-2 py-2 whitespace-nowrap">'
        + '          <div class="flex gap-2">'
        + (hasWhois ? '            <button onclick="openWhoisModal(' + index + ')" class="px-2 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700" data-i18n="logs.actions.whois">Whois</button>' : '            <button disabled class="px-2 py-1 text-xs bg-gray-300 text-gray-500 rounded cursor-not-allowed" data-i18n="logs.actions.whois">Whois</button>')
        + (hasLogs ? '            <button onclick="openLogsModal(' + index + ')" class="px-2 py-1 text-xs bg-green-600 text-white rounded hover:bg-green-700" data-i18n="logs.actions.logs">Logs</button>' : '            <button disabled class="px-2 py-1 text-xs bg-gray-300 text-gray-500 rounded cursor-not-allowed" data-i18n="logs.actions.logs">Logs</button>')
        + '          </div>'
        + '        </td>'
        + '      </tr>';
    });
    html += '    </tbody></table></div>';
    }
  }

  html += '</div>';
  return html;
}
