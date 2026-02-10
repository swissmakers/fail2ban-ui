// Modal management functions for Fail2ban UI
"use strict";

function updateBodyScrollLock() {
  if (openModalCount > 0) {
    document.body.classList.add('modal-open');
  } else {
    document.body.classList.remove('modal-open');
  }
}

// Close modal
function closeModal(modalId) {
  var modal = document.getElementById(modalId);
  if (!modal || modal.classList.contains('hidden')) {
    return;
  }
  modal.classList.add('hidden');
  openModalCount = Math.max(0, openModalCount - 1);
  updateBodyScrollLock();
}

// Open modal
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

  // Determine which lines are suspicious (bad requests)
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
    // No suspicious lines detected; show raw logs without highlighting
    contentEl.textContent = logs;
  }

  openModal('logsModal');
}

function isSuspiciousLogLine(line, ip) {
  if (!line) {
    return false;
  }

  var containsIP = ip && line.indexOf(ip) !== -1;
  var lowered = line.toLowerCase();

  // Detect HTTP status codes (>= 300 considered problematic)
  var statusMatch = line.match(/"[^"]*"\s+(\d{3})\b/);
  if (!statusMatch) {
    statusMatch = line.match(/\s(\d{3})\s+(?:\d+|-)/);
  }
  var statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
  var hasBadStatus = !isNaN(statusCode) && statusCode >= 300;

  // Detect common attack indicators in URLs/payloads
  var indicators = [
    '../',
    '%2e%2e',
    '%252e%252e',
    '%24%7b',
    '${',
    '/etc/passwd',
    'select%20',
    'union%20',
    'cmd=',
    'wget',
    'curl ',
    'nslookup',
    '/xmlrpc.php',
    '/wp-admin',
    '/cgi-bin',
    'content-length: 0'
  ];
  var hasIndicator = indicators.some(function(ind) {
    return lowered.indexOf(ind) !== -1;
  });

  if (containsIP) {
    return hasBadStatus || hasIndicator;
  }
  return (hasBadStatus || hasIndicator) && !ip;
}

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
}

