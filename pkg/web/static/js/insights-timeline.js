// Ban Insights timeline: Kibana-style ban/unban time-series with drill-down,
// incident compare, IP export and bulk permanent blocking.
"use strict";

// =========================================================================
//  State
// =========================================================================

var insightsTimeline = {
  chart: null,
  resizeObserver: null,
  // Current window. anchoredToNow keeps until=now on refetch (live view).
  range: { since: null, until: null, anchoredToNow: true, presetHours: 8 },
  rangeStack: [],
  buckets: [],            // [{ts, bans, unbans}] (ts = bucket start, ms)
  bucketSeconds: 0,
  events: { items: [], total: null, hasMore: false, loading: false, expanded: {} },
  incidents: { A: null, B: null }, // {since, until, ips, truncated, loading}
  suggestions: [],
  pendingBlockIPs: [],
  fetchToken: 0,
  eventsToken: 0,
  wsRegistered: false,
  wsPending: 0,
  wsLastRefetch: 0,
  wsRefetchTimer: null,
  active: false
};

var TIMELINE_MAX_RANGE_HOURS = 366 * 24;
var TIMELINE_WS_REFETCH_MIN_MS = 10000;
var TIMELINE_UNIT_HOURS = { hours: 1, days: 24, weeks: 168, months: 720 };

// =========================================================================
//  Lifecycle
// =========================================================================

function initInsightsTimeline() {
  if (typeof echarts === 'undefined') return;
  var container = document.getElementById('insightsTimelineChart');
  if (!container) return;

  insightsTimeline.active = true;

  if (!insightsTimeline.range.since) {
    timelineSetAnchoredRange(insightsTimeline.range.presetHours);
  } else if (insightsTimeline.range.anchoredToNow) {
    timelineSetAnchoredRange(insightsTimeline.range.presetHours);
  }

  if (!insightsTimeline.chart) {
    insightsTimeline.chart = echarts.init(container);
    insightsTimeline.chart.on('brushEnd', onTimelineBrushEnd);
    insightsTimeline.resizeObserver = new ResizeObserver(function() {
      if (insightsTimeline.chart) {
        insightsTimeline.chart.resize();
      }
    });
    insightsTimeline.resizeObserver.observe(container);
  }

  if (!insightsTimeline.wsRegistered && typeof wsManager !== 'undefined' && wsManager) {
    wsManager.onBanEvent(handleTimelineLiveEvent);
    insightsTimeline.wsRegistered = true;
  }

  renderTimelineRangePicker();
  renderIncidentCompare();
  fetchTimelineData();
}

function destroyInsightsTimeline() {
  insightsTimeline.active = false;
  if (insightsTimeline.resizeObserver) {
    insightsTimeline.resizeObserver.disconnect();
    insightsTimeline.resizeObserver = null;
  }
  if (insightsTimeline.chart) {
    insightsTimeline.chart.dispose();
    insightsTimeline.chart = null;
  }
  if (insightsTimeline.wsRefetchTimer) {
    clearTimeout(insightsTimeline.wsRefetchTimer);
    insightsTimeline.wsRefetchTimer = null;
  }
  insightsTimeline.wsPending = 0;
  // Pinned incidents survive close/reopen on purpose; cleared via resetInsightsTimeline().
}

// Full reset (used when all stored events are cleared).
function resetInsightsTimeline() {
  insightsTimeline.range = { since: null, until: null, anchoredToNow: true, presetHours: 8 };
  insightsTimeline.rangeStack = [];
  insightsTimeline.buckets = [];
  insightsTimeline.events = { items: [], total: null, hasMore: false, loading: false, expanded: {} };
  insightsTimeline.incidents = { A: null, B: null };
  insightsTimeline.suggestions = [];
  insightsTimeline.pendingBlockIPs = [];
  if (insightsTimeline.active) {
    timelineSetAnchoredRange(8);
    renderTimelineRangePicker();
    renderIncidentCompare();
    fetchTimelineData();
  }
}

// =========================================================================
//  Range handling
// =========================================================================

function timelineSetAnchoredRange(hours) {
  var now = new Date();
  insightsTimeline.range = {
    since: new Date(now.getTime() - hours * 3600 * 1000),
    until: now,
    anchoredToNow: true,
    presetHours: hours
  };
}

function setTimelinePreset(hours) {
  timelineSetAnchoredRange(hours);
  insightsTimeline.rangeStack = [];
  insightsTimeline.wsPending = 0;
  renderTimelineRangePicker();
  fetchTimelineData();
}

function applyCustomTimelineRange() {
  var amountEl = document.getElementById('timelineCustomAmount');
  var unitEl = document.getElementById('timelineCustomUnit');
  if (!amountEl || !unitEl) return;
  var amount = parseInt(amountEl.value, 10);
  var unitHours = TIMELINE_UNIT_HOURS[unitEl.value] || 1;
  var hours = amount * unitHours;
  if (!isFinite(hours) || hours < 1 || hours > TIMELINE_MAX_RANGE_HOURS) {
    showToast(t('logs.timeline.custom_invalid', 'Enter a valid range (1 hour to 12 months).'), 'error');
    return;
  }
  setTimelinePreset(hours);
}

function timelineJumpToLive() {
  setTimelinePreset(insightsTimeline.range.presetHours || 8);
}

function zoomIntoRange(since, until) {
  insightsTimeline.rangeStack.push({
    since: insightsTimeline.range.since,
    until: insightsTimeline.range.until,
    anchoredToNow: insightsTimeline.range.anchoredToNow,
    presetHours: insightsTimeline.range.presetHours
  });
  insightsTimeline.range = {
    since: since,
    until: until,
    anchoredToNow: false,
    presetHours: insightsTimeline.range.presetHours
  };
  renderTimelineRangePicker();
  fetchTimelineData();
}

function timelineBack() {
  var prev = insightsTimeline.rangeStack.pop();
  if (!prev) return;
  if (prev.anchoredToNow) {
    timelineSetAnchoredRange(prev.presetHours);
  } else {
    insightsTimeline.range = prev;
  }
  renderTimelineRangePicker();
  fetchTimelineData();
}

function renderTimelineRangePicker() {
  var range = insightsTimeline.range;
  var buttons = document.querySelectorAll('#timelinePresets .timeline-preset');
  for (var i = 0; i < buttons.length; i++) {
    var btn = buttons[i];
    var isActive = range.anchoredToNow && Number(btn.getAttribute('data-hours')) === range.presetHours;
    btn.className = 'timeline-preset px-3 py-1 text-xs rounded border ' + (isActive
      ? 'bg-blue-600 text-white border-blue-600'
      : 'border-blue-200 text-blue-600 hover:bg-blue-50');
  }
  var backBtn = document.getElementById('timelineBackBtn');
  if (backBtn) {
    backBtn.classList.toggle('hidden', insightsTimeline.rangeStack.length === 0);
  }
  var label = document.getElementById('timelineRangeLabel');
  if (label && range.since && range.until) {
    label.textContent = formatDateTime(range.since) + ' – ' + formatDateTime(range.until);
  }
  var chip = document.getElementById('timelineLiveChip');
  if (chip && insightsTimeline.wsPending === 0) {
    chip.classList.add('hidden');
  }
}

// =========================================================================
//  Data fetching
// =========================================================================

function fetchTimelineData() {
  var range = insightsTimeline.range;
  if (!range.since || !range.until) return;
  if (range.anchoredToNow) {
    range.until = new Date();
    range.since = new Date(range.until.getTime() - range.presetHours * 3600 * 1000);
  }

  var token = ++insightsTimeline.fetchToken;
  var query = '?since=' + encodeURIComponent(range.since.toISOString())
    + '&until=' + encodeURIComponent(range.until.toISOString());

  fetch(appPath('/api/events/bans/timeline' + query))
    .then(function(res) {
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    })
    .then(function(data) {
      if (token !== insightsTimeline.fetchToken || !insightsTimeline.active) return;
      insightsTimeline.bucketSeconds = data.bucketSeconds || 0;
      insightsTimeline.buckets = (data.buckets || []).map(function(b) {
        return { ts: new Date(b.start).getTime(), bans: b.bans || 0, unbans: b.unbans || 0 };
      });
      insightsTimeline.wsPending = 0;
      renderTimelineRangePicker();
      renderTimelineChart();
    })
    .catch(function(err) {
      console.error('Error fetching ban timeline:', err);
      if (token === insightsTimeline.fetchToken && insightsTimeline.active) {
        showToast(t('logs.timeline.loading_error', 'Error loading timeline data'), 'error');
      }
    });

  fetchTimelineEvents({ reset: true });
}

function fetchTimelineEvents(options) {
  options = options || {};
  var state = insightsTimeline.events;
  var range = insightsTimeline.range;
  if (!range.since || !range.until) return;

  var offset = options.reset ? 0 : state.items.length;
  var token = ++insightsTimeline.eventsToken;
  state.loading = true;

  var query = '?since=' + encodeURIComponent(range.since.toISOString())
    + '&until=' + encodeURIComponent(range.until.toISOString())
    + '&limit=50&offset=' + offset;

  fetch(appPath('/api/events/bans' + query))
    .then(function(res) {
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    })
    .then(function(data) {
      if (token !== insightsTimeline.eventsToken || !insightsTimeline.active) return;
      var events = (data && data.events) || [];
      if (options.reset) {
        state.items = events;
        state.expanded = {};
        state.total = (typeof data.total === 'number') ? data.total : null;
      } else {
        state.items = state.items.concat(events);
      }
      state.hasMore = data.hasMore === true;
      state.loading = false;
      renderTimelineEventList();
    })
    .catch(function(err) {
      console.error('Error fetching timeline events:', err);
      if (token === insightsTimeline.eventsToken) {
        state.loading = false;
      }
    });
}

// =========================================================================
//  Chart
// =========================================================================

function timelineIsDarkTheme() {
  return document.documentElement.getAttribute('data-theme') === 'dark'
    && !(document.body && document.body.classList.contains('lotr-mode'));
}

function timelineBucketLabel(ts) {
  var date = new Date(ts);
  var pad = function(n) { return String(n).padStart(2, '0'); };
  if (insightsTimeline.bucketSeconds >= 86400) {
    return date.getFullYear() + '.' + pad(date.getMonth() + 1) + '.' + pad(date.getDate());
  }
  var rangeMs = insightsTimeline.range.until - insightsTimeline.range.since;
  if (rangeMs > 24 * 3600 * 1000) {
    return pad(date.getMonth() + 1) + '.' + pad(date.getDate()) + ' ' + pad(date.getHours()) + ':' + pad(date.getMinutes());
  }
  return pad(date.getHours()) + ':' + pad(date.getMinutes());
}

function timelineTooltipFormatter(params) {
  if (!params || !params.length) return '';
  var idx = params[0].dataIndex;
  var bucket = insightsTimeline.buckets[idx];
  if (!bucket) return '';
  var end = bucket.ts + insightsTimeline.bucketSeconds * 1000;
  var html = '<div style="font-size:12px;">'
    + '<div style="margin-bottom:4px;font-weight:600;">'
    + escapeHtml(formatDateTime(new Date(bucket.ts))) + ' – ' + escapeHtml(formatDateTime(new Date(end)))
    + '</div>';
  for (var i = 0; i < params.length; i++) {
    html += '<div>' + params[i].marker + ' ' + escapeHtml(params[i].seriesName) + ': <b>'
      + formatNumber(params[i].value) + '</b></div>';
  }
  html += '</div>';
  return html;
}

function buildTimelineOption(isDark) {
  var textColor = isDark ? '#94a3b8' : '#6b7280';
  var lineColor = isDark ? '#334155' : '#e5e7eb';
  var surface = isDark ? '#1f2937' : '#f9fafb';
  var banColor = isDark ? '#ef4444' : '#dc2626';
  var unbanColor = '#0d9488'; // teal: distinguishable from red for color-blind users
  var bansLabel = t('logs.timeline.series_bans', 'Bans');
  var unbansLabel = t('logs.timeline.series_unbans', 'Unbans');
  var buckets = insightsTimeline.buckets;

  return {
    animation: false,
    grid: { left: 48, right: 16, top: 32, bottom: 28 },
    legend: {
      top: 0,
      right: 0,
      icon: 'roundRect',
      textStyle: { color: textColor },
      data: [bansLabel, unbansLabel]
    },
    xAxis: {
      type: 'category',
      data: buckets.map(function(b) { return timelineBucketLabel(b.ts); }),
      axisLabel: { color: textColor, hideOverlap: true },
      axisLine: { lineStyle: { color: lineColor } },
      axisTick: { alignWithLabel: true },
      splitLine: { show: false }
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: textColor },
      splitLine: { lineStyle: { color: lineColor } }
    },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: isDark ? '#0f172a' : '#ffffff',
      borderColor: lineColor,
      textStyle: { color: isDark ? '#e2e8f0' : '#111827' },
      formatter: timelineTooltipFormatter
    },
    brush: {
      xAxisIndex: 0,
      brushType: 'lineX',
      brushMode: 'single',
      transformable: false,
      throttleType: 'debounce',
      throttleDelay: 100,
      brushStyle: { color: 'rgba(59,130,246,0.15)', borderColor: 'rgba(59,130,246,0.6)' },
      outOfBrush: { colorAlpha: 0.35 }
    },
    toolbox: { show: false, feature: { brush: { type: ['lineX'] } } },
    series: [
      {
        name: bansLabel,
        type: 'bar',
        stack: 'events',
        barCategoryGap: '20%',
        itemStyle: { color: banColor, borderColor: surface, borderWidth: 1 },
        data: buckets.map(function(b) { return b.bans; })
      },
      {
        name: unbansLabel,
        type: 'bar',
        stack: 'events',
        itemStyle: { color: unbanColor, borderColor: surface, borderWidth: 1, borderRadius: [2, 2, 0, 0] },
        data: buckets.map(function(b) { return b.unbans; })
      }
    ]
  };
}

function renderTimelineChart() {
  var chart = insightsTimeline.chart;
  if (!chart) return;
  chart.setOption(buildTimelineOption(timelineIsDarkTheme()), { notMerge: true });
  // Arm the brush cursor so drag-select works without a toolbox click.
  chart.dispatchAction({
    type: 'takeGlobalCursor',
    key: 'brush',
    brushOption: { brushType: 'lineX', brushMode: 'single' }
  });
}

function onTimelineBrushEnd(params) {
  if (!params || !params.areas || !params.areas.length) return;
  var coordRange = params.areas[0].coordRange;
  if (!coordRange || coordRange.length !== 2) return;
  var buckets = insightsTimeline.buckets;
  if (!buckets.length) return;

  var startIdx = Math.max(0, Math.floor(coordRange[0]));
  var endIdx = Math.min(buckets.length - 1, Math.ceil(coordRange[1]));
  if (endIdx < startIdx) return;
  // Ignore selections narrower than one bucket (accidental clicks).
  if (startIdx === endIdx && coordRange[1] - coordRange[0] < 0.5) {
    insightsTimeline.chart.dispatchAction({ type: 'brush', areas: [] });
    return;
  }

  var since = new Date(buckets[startIdx].ts);
  var until = new Date(buckets[endIdx].ts + insightsTimeline.bucketSeconds * 1000);
  insightsTimeline.chart.dispatchAction({ type: 'brush', areas: [] });
  zoomIntoRange(since, until);
}

// =========================================================================
//  Event detail list
// =========================================================================

function renderTimelineEventList() {
  var container = document.getElementById('timelineEventList');
  var moreContainer = document.getElementById('timelineEventListMore');
  var countEl = document.getElementById('timelineEventCount');
  if (!container) return;

  var state = insightsTimeline.events;
  if (countEl) {
    countEl.textContent = (state.total !== null)
      ? formatNumber(state.total) + ' ' + t('logs.timeline.events_total_suffix', 'events')
      : '';
  }

  if (!state.items.length) {
    container.innerHTML = '<p class="text-sm text-gray-400 text-center py-6">'
      + escapeHtml(t('logs.timeline.empty', 'No events in this time range.')) + '</p>';
    if (moreContainer) moreContainer.innerHTML = '';
    return;
  }

  var html = '';
  for (var i = 0; i < state.items.length; i++) {
    var event = state.items[i];
    var isUnban = (event.eventType || 'ban') === 'unban';
    var typeBadge = isUnban
      ? '<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">' + t('logs.badge.unbanned', 'Unbanned') + '</span>'
      : '<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">' + t('logs.badge.banned', 'Banned') + '</span>';
    var expanded = !!state.expanded[event.id];
    var country = (typeof countryLabel === 'function') ? countryLabel(event.country) : (event.country || '');

    html += '<div class="border border-gray-200 rounded-md bg-white">'
      + '<button type="button" class="w-full flex flex-wrap items-center gap-2 px-3 py-2 text-left text-sm hover:bg-gray-50" onclick="toggleTimelineEventDetail(' + event.id + ')">'
      + '<svg class="h-4 w-4 text-gray-400 transition-transform' + (expanded ? ' rotate-90' : '') + '" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>'
      + '<span class="text-xs text-gray-500 whitespace-nowrap">' + escapeHtml(formatDateTime(event.occurredAt || event.createdAt)) + '</span>'
      + '<span class="font-mono text-gray-900">' + escapeHtml(event.ip || '') + '</span>'
      + typeBadge
      + '<span class="text-xs text-gray-500">' + escapeHtml(event.jail || '') + '</span>'
      + '<span class="text-xs text-gray-400">' + escapeHtml(event.serverName || event.serverId || '') + '</span>'
      + '<span class="text-xs text-gray-400 ml-auto">' + escapeHtml(country) + '</span>'
      + '</button>';
    if (expanded) {
      html += '<div id="timelineEventDetail-' + event.id + '" class="border-t border-gray-200 px-3 py-2">'
        + renderTimelineEventDetailContent(event)
        + '</div>';
    }
    html += '</div>';
  }
  container.innerHTML = html;

  if (moreContainer) {
    if (state.hasMore && state.items.length < 1000) {
      moreContainer.innerHTML = '<button type="button" class="px-3 py-1 text-xs rounded border border-blue-200 text-blue-600 hover:bg-blue-50" onclick="fetchTimelineEvents()">'
        + escapeHtml(t('logs.overview.load_more', 'Load more')) + '</button>';
    } else {
      moreContainer.innerHTML = '';
    }
  }
}

function renderTimelineEventDetailContent(event) {
  var html = '<div class="text-xs text-gray-600 mb-2">'
    + '<span class="font-semibold">' + escapeHtml(t('logs.timeline.events_reason', 'Why blocked')) + ':</span> '
    + escapeHtml(t('logs.table.jail', 'Jail')) + ' <span class="font-mono">' + escapeHtml(event.jail || '?') + '</span>';
  if (event.failures) {
    html += ', ' + escapeHtml(t('logs.timeline.events_failures', 'failures')) + ': <span class="font-mono">' + escapeHtml(event.failures) + '</span>';
  }
  html += '</div>';

  if (!event._detailLoaded) {
    return html + '<p class="text-xs text-gray-400">' + escapeHtml(t('loading', 'Loading...')) + '</p>';
  }
  if (event.logs && event.logs.trim()) {
    var logsHtml;
    if (typeof buildHighlightedLogsHtml === 'function') {
      logsHtml = buildHighlightedLogsHtml(event.logs, event.ip || '').html;
    } else {
      logsHtml = escapeHtml(event.logs);
    }
    html += '<pre class="text-xs bg-gray-900 text-gray-100 rounded-md p-3 overflow-x-auto whitespace-pre-wrap max-h-64 overflow-y-auto">' + logsHtml + '</pre>';
  } else {
    html += '<p class="text-xs text-gray-400">' + escapeHtml(t('logs.timeline.events_no_logs', 'No matched log lines stored for this event.')) + '</p>';
  }
  return html;
}

function toggleTimelineEventDetail(eventId) {
  var state = insightsTimeline.events;
  var event = null;
  for (var i = 0; i < state.items.length; i++) {
    if (state.items[i].id === eventId) { event = state.items[i]; break; }
  }
  if (!event) return;

  if (state.expanded[eventId]) {
    delete state.expanded[eventId];
    renderTimelineEventList();
    return;
  }
  state.expanded[eventId] = true;
  renderTimelineEventList();

  if (!event._detailLoaded && typeof ensureBanEventDetail === 'function') {
    ensureBanEventDetail(event)
      .then(function() {
        if (insightsTimeline.events.expanded[eventId]) {
          renderTimelineEventList();
        }
      })
      .catch(function(err) {
        console.error('Error loading event detail:', err);
      });
  }
}

// =========================================================================
//  Incident compare
// =========================================================================

function fetchRangeIPs(since, until) {
  var query = '?since=' + encodeURIComponent(since.toISOString())
    + '&until=' + encodeURIComponent(until.toISOString());
  return fetch(appPath('/api/events/bans/ips' + query))
    .then(function(res) {
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    });
}

function pinIncident(slot) {
  var range = insightsTimeline.range;
  if (!range.since || !range.until) return;

  var incident = {
    since: new Date(range.since.getTime()),
    until: new Date(range.until.getTime()),
    ips: [],
    truncated: false,
    loading: true
  };
  insightsTimeline.incidents[slot] = incident;
  renderIncidentCompare();

  fetchRangeIPs(incident.since, incident.until)
    .then(function(data) {
      if (insightsTimeline.incidents[slot] !== incident) return;
      incident.ips = data.ips || [];
      incident.truncated = data.truncated === true;
      incident.loading = false;
      renderIncidentCompare();
    })
    .catch(function(err) {
      console.error('Error fetching incident IPs:', err);
      if (insightsTimeline.incidents[slot] === incident) {
        incident.loading = false;
        incident.error = true;
        renderIncidentCompare();
      }
    });

  if (slot === 'A') {
    fetchTimelineSuggestions(incident);
  }
}

function clearIncident(slot) {
  insightsTimeline.incidents[slot] = null;
  if (slot === 'A') {
    insightsTimeline.suggestions = [];
  }
  renderIncidentCompare();
}

function computeIncidentOverlap() {
  var a = insightsTimeline.incidents.A;
  var b = insightsTimeline.incidents.B;
  if (!a || !b || a.loading || b.loading) return null;
  var mapB = {};
  for (var i = 0; i < b.ips.length; i++) {
    mapB[b.ips[i].ip] = b.ips[i];
  }
  var overlap = [];
  for (var j = 0; j < a.ips.length; j++) {
    var statA = a.ips[j];
    var statB = mapB[statA.ip];
    if (statB) {
      overlap.push({
        ip: statA.ip,
        country: statA.country || statB.country || '',
        countA: statA.count,
        countB: statB.count,
        firstSeen: statA.firstSeen < statB.firstSeen ? statA.firstSeen : statB.firstSeen,
        lastSeen: statA.lastSeen > statB.lastSeen ? statA.lastSeen : statB.lastSeen
      });
    }
  }
  return overlap;
}

function fetchTimelineSuggestions(incident) {
  var query = '?since=' + encodeURIComponent(incident.since.toISOString())
    + '&until=' + encodeURIComponent(incident.until.toISOString());
  fetch(appPath('/api/events/bans/ips/activity' + query))
    .then(function(res) {
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    })
    .then(function(data) {
      if (insightsTimeline.incidents.A !== incident) return;
      insightsTimeline.suggestions = data.periods || [];
      renderIncidentCompare();
    })
    .catch(function(err) {
      console.error('Error fetching similar periods:', err);
    });
}

function applySuggestedPeriod(index) {
  var period = insightsTimeline.suggestions[index];
  if (!period) return;
  var since = new Date(period.day + 'T00:00:00Z');
  if (isNaN(since.getTime())) return;
  var until = new Date(since.getTime() + 24 * 3600 * 1000);
  zoomIntoRange(since, until);
}

function renderIncidentCompare() {
  var panel = document.getElementById('timelineCompare');
  var chipsEl = document.getElementById('timelineIncidentChips');
  var overlapEl = document.getElementById('timelineOverlapPanel');
  var suggestionsEl = document.getElementById('timelineSuggestions');
  if (!panel || !chipsEl || !overlapEl || !suggestionsEl) return;

  var a = insightsTimeline.incidents.A;
  var b = insightsTimeline.incidents.B;
  if (!a && !b) {
    panel.classList.add('hidden');
    return;
  }
  panel.classList.remove('hidden');

  var chipsHtml = '';
  ['A', 'B'].forEach(function(slot) {
    var incident = insightsTimeline.incidents[slot];
    var slotLabel = t('logs.timeline.compare_incident_' + slot.toLowerCase(), 'Incident ' + slot);
    if (incident) {
      var detail = incident.loading
        ? t('loading', 'Loading...')
        : formatNumber(incident.ips.length) + ' IPs' + (incident.truncated ? ' (max)' : '');
      chipsHtml += '<span class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-100 text-blue-800 text-xs">'
        + '<b>' + escapeHtml(slotLabel) + '</b> '
        + escapeHtml(formatDateTime(incident.since) + ' – ' + formatDateTime(incident.until))
        + ' · ' + escapeHtml(detail)
        + '<button type="button" class="text-blue-500 hover:text-blue-800" onclick="clearIncident(\'' + slot + '\')" title="' + escapeHtml(t('logs.timeline.compare_clear', 'Clear')) + '">&times;</button>'
        + '</span>';
    } else {
      chipsHtml += '<span class="inline-flex items-center px-3 py-1 rounded-full bg-gray-100 text-gray-400 text-xs">'
        + escapeHtml(slotLabel) + ' – ' + escapeHtml(t('logs.timeline.compare_unpinned', 'not pinned'))
        + '</span>';
    }
  });
  chipsEl.innerHTML = chipsHtml;

  var overlap = computeIncidentOverlap();
  if (overlap === null) {
    overlapEl.innerHTML = (a && b)
      ? '<p class="text-xs text-gray-400">' + escapeHtml(t('loading', 'Loading...')) + '</p>'
      : '<p class="text-xs text-gray-400">' + escapeHtml(t('logs.timeline.compare_pin_hint', 'Pin two incidents to compare their IPs.')) + '</p>';
  } else if (!overlap.length) {
    overlapEl.innerHTML = '<p class="text-xs text-gray-500">' + escapeHtml(t('logs.timeline.compare_overlap_empty', 'No overlapping IPs between the two incidents.')) + '</p>';
  } else {
    var html = '<div class="flex flex-wrap items-center justify-between gap-2 mb-2">'
      + '<span class="text-sm font-medium text-gray-800">'
      + escapeHtml(t('logs.timeline.compare_overlap', 'IPs present in both incidents')) + ': ' + formatNumber(overlap.length)
      + '</span>'
      + '<span class="flex gap-2">'
      + '<button type="button" class="px-3 py-1 text-xs rounded border border-gray-300 text-gray-600 hover:bg-gray-100" onclick="exportTimelineIPs(\'csv\', \'overlap\')">' + escapeHtml(t('logs.timeline.export_csv', 'Export CSV')) + '</button>'
      + '<button type="button" class="px-3 py-1 text-xs rounded border border-gray-300 text-gray-600 hover:bg-gray-100" onclick="exportTimelineIPs(\'json\', \'overlap\')">' + escapeHtml(t('logs.timeline.export_json', 'Export JSON')) + '</button>'
      + '<button type="button" data-min-access="admin" class="px-3 py-1 text-xs rounded border border-red-200 text-red-600 hover:bg-red-50" onclick="openBulkBlockConfirm(\'overlap\')">' + escapeHtml(t('logs.timeline.block_all', 'Block all via firewall')) + '</button>'
      + '</span></div>'
      + '<div class="max-h-48 overflow-y-auto border border-gray-200 rounded-md divide-y divide-gray-100 bg-white">';
    for (var i = 0; i < overlap.length; i++) {
      var entry = overlap[i];
      var country = (typeof countryLabel === 'function') ? countryLabel(entry.country) : (entry.country || '');
      html += '<div class="flex items-center gap-3 px-3 py-1.5 text-xs">'
        + '<span class="font-mono text-gray-900">' + escapeHtml(entry.ip) + '</span>'
        + '<span class="text-gray-500">' + escapeHtml(country) + '</span>'
        + '<span class="ml-auto text-gray-400">A: ' + formatNumber(entry.countA) + ' · B: ' + formatNumber(entry.countB) + '</span>'
        + '</div>';
    }
    html += '</div>';
    overlapEl.innerHTML = html;
  }

  var suggestions = insightsTimeline.suggestions;
  if (a && suggestions.length) {
    var sHtml = '<p class="text-xs font-medium text-gray-700 mb-1">' + escapeHtml(t('logs.timeline.suggestions_title', 'Similar past periods')) + '</p>'
      + '<div class="flex flex-wrap gap-2">';
    for (var s = 0; s < suggestions.length; s++) {
      sHtml += '<button type="button" class="px-2 py-1 text-xs rounded border border-amber-200 bg-amber-50 text-amber-800 hover:bg-amber-100" onclick="applySuggestedPeriod(' + s + ')">'
        + escapeHtml(suggestions[s].day) + ' · ' + formatNumber(suggestions[s].overlap) + ' IPs'
        + '</button>';
    }
    sHtml += '</div>';
    suggestionsEl.innerHTML = sHtml;
  } else if (a) {
    suggestionsEl.innerHTML = '<p class="text-xs text-gray-400">' + escapeHtml(t('logs.timeline.suggestions_empty', 'No similar periods found.')) + '</p>';
  } else {
    suggestionsEl.innerHTML = '';
  }

  if (typeof applyAuthorizationUI === 'function') {
    applyAuthorizationUI();
  }
}

// =========================================================================
//  Export
// =========================================================================

function timelineCsvField(value) {
  var s = String(value === null || value === undefined ? '' : value);
  if (/^[=+\-@\t\r]/.test(s)) {
    s = "'" + s; // CSV formula-injection guard
  }
  return '"' + s.replace(/"/g, '""') + '"';
}

function timelineSanitizeFilename(s) {
  return String(s).replace(/[^0-9A-Za-z._-]+/g, '-');
}

function timelineDownloadBlob(content, mimeType, filename) {
  var blob = new Blob([content], { type: mimeType });
  var url = URL.createObjectURL(blob);
  var link = document.createElement('a');
  link.href = url;
  link.download = timelineSanitizeFilename(filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// Resolves the IP list for a scope: 'overlap' uses the compare result,
// 'range' fetches the aggregate for the currently visible window.
function resolveTimelineIPs(scope) {
  if (scope === 'overlap') {
    var overlap = computeIncidentOverlap();
    return Promise.resolve(overlap || []);
  }
  var range = insightsTimeline.range;
  if (!range.since || !range.until) return Promise.resolve([]);
  return fetchRangeIPs(range.since, range.until).then(function(data) {
    return data.ips || [];
  });
}

function exportTimelineIPs(format, scope) {
  scope = scope || 'range';
  resolveTimelineIPs(scope)
    .then(function(ips) {
      if (!ips.length) {
        showToast(t('logs.timeline.export_empty', 'No IPs to export for this selection.'), 'info');
        return;
      }
      var range = insightsTimeline.range;
      var a = insightsTimeline.incidents.A;
      var b = insightsTimeline.incidents.B;
      var stamp = (scope === 'overlap' && a && b)
        ? a.since.toISOString() + '_' + b.since.toISOString()
        : range.since.toISOString() + '_' + range.until.toISOString();

      if (format === 'json') {
        var payload = { scope: scope, exportedAt: new Date().toISOString(), ips: ips };
        if (scope === 'overlap' && a && b) {
          payload.rangeA = { since: a.since.toISOString(), until: a.until.toISOString() };
          payload.rangeB = { since: b.since.toISOString(), until: b.until.toISOString() };
        } else {
          payload.range = { since: range.since.toISOString(), until: range.until.toISOString() };
        }
        timelineDownloadBlob(JSON.stringify(payload, null, 2), 'application/json', 'fail2ban-ips_' + stamp + '.json');
        return;
      }

      var lines = [];
      if (scope === 'overlap') {
        lines.push(['ip', 'country', 'count_a', 'count_b', 'first_seen', 'last_seen'].map(timelineCsvField).join(','));
        ips.forEach(function(entry) {
          lines.push([entry.ip, entry.country, entry.countA, entry.countB, entry.firstSeen, entry.lastSeen].map(timelineCsvField).join(','));
        });
      } else {
        lines.push(['ip', 'country', 'ban_count', 'first_seen', 'last_seen', 'jails'].map(timelineCsvField).join(','));
        ips.forEach(function(entry) {
          lines.push([entry.ip, entry.country, entry.count, entry.firstSeen, entry.lastSeen, entry.jails].map(timelineCsvField).join(','));
        });
      }
      timelineDownloadBlob(lines.join('\r\n') + '\r\n', 'text/csv;charset=utf-8', 'fail2ban-ips_' + stamp + '.csv');
    })
    .catch(function(err) {
      console.error('Error exporting IPs:', err);
      showToast(t('logs.timeline.export_error', 'Error exporting IP list'), 'error');
    });
}

// =========================================================================
//  Bulk permanent block
// =========================================================================

function openBulkBlockConfirm(scope) {
  if (typeof hasAccess === 'function' && !hasAccess('admin')) return;
  resolveTimelineIPs(scope || 'range')
    .then(function(ips) {
      var addresses = ips.map(function(entry) { return entry.ip; }).filter(Boolean);
      if (!addresses.length) {
        showToast(t('logs.timeline.export_empty', 'No IPs to export for this selection.'), 'info');
        return;
      }
      if (addresses.length > 500) {
        addresses = addresses.slice(0, 500);
        showToast(t('logs.timeline.block_capped', 'List capped at 500 IPs per request.'), 'info');
      }
      insightsTimeline.pendingBlockIPs = addresses;

      var textEl = document.getElementById('bulkBlockConfirmText');
      if (textEl) {
        textEl.textContent = t('logs.timeline.block_confirm_body', 'This will permanently block {count} IP addresses on the configured firewall integration. Review the list below.')
          .replace('{count}', formatNumber(addresses.length));
      }
      var listEl = document.getElementById('bulkBlockIPList');
      if (listEl) {
        listEl.innerHTML = addresses.map(function(ip) {
          return '<div>' + escapeHtml(ip) + '</div>';
        }).join('');
      }
      var btn = document.getElementById('bulkBlockConfirmBtn');
      if (btn) {
        btn.disabled = false;
        btn.textContent = t('logs.timeline.block_confirm_button', 'Block {count} IPs').replace('{count}', formatNumber(addresses.length));
      }
      openModal('bulkBlockConfirmModal');
    })
    .catch(function(err) {
      console.error('Error preparing bulk block:', err);
      showToast(t('logs.timeline.block_error', 'Error submitting block request'), 'error');
    });
}

function confirmBulkBlock() {
  var ips = insightsTimeline.pendingBlockIPs;
  if (!ips || !ips.length) return;
  var btn = document.getElementById('bulkBlockConfirmBtn');
  if (btn) {
    btn.disabled = true;
    btn.textContent = t('loading', 'Loading...');
  }

  fetch(appPath('/api/advanced-actions/blocks'), {
    method: 'POST',
    headers: Object.assign({ 'Content-Type': 'application/json' }, (typeof serverHeaders === 'function' ? serverHeaders() : {})),
    body: JSON.stringify({ ips: ips })
  })
    .then(function(res) {
      return res.json().then(function(data) { return { ok: res.ok, data: data }; });
    })
    .then(function(result) {
      closeModal('bulkBlockConfirmModal');
      if (!result.ok) {
        var errMsg = (result.data && result.data.error) || 'HTTP error';
        showToast(t('logs.timeline.block_error', 'Error submitting block request') + ': ' + errMsg, 'error');
        return;
      }
      var summary = (result.data && result.data.summary) || {};
      var msg = t('logs.timeline.block_success', '{count} IPs submitted for blocking.')
        .replace('{count}', formatNumber(summary.blocked || 0));
      var extras = [];
      if (summary.alreadyBlocked) extras.push(summary.alreadyBlocked + ' ' + t('logs.timeline.block_already', 'already blocked'));
      if (summary.skipped) extras.push(summary.skipped + ' ' + t('logs.timeline.block_skipped', 'skipped'));
      if (summary.failed) extras.push(summary.failed + ' ' + t('logs.timeline.block_failed', 'failed'));
      if (summary.aborted) extras.push(summary.aborted + ' ' + t('logs.timeline.block_aborted', 'aborted'));
      if (extras.length) msg += ' (' + extras.join(', ') + ')';
      showToast(msg, summary.failed || summary.aborted ? 'warning' : 'success');
    })
    .catch(function(err) {
      console.error('Error bulk blocking:', err);
      showToast(t('logs.timeline.block_error', 'Error submitting block request'), 'error');
    })
    .finally(function() {
      insightsTimeline.pendingBlockIPs = [];
      if (btn) btn.disabled = false;
    });
}

// =========================================================================
//  Live updates (websocket)
// =========================================================================

function handleTimelineLiveEvent() {
  if (!insightsTimeline.active) return;
  insightsTimeline.wsPending += 1;

  var chip = document.getElementById('timelineLiveChip');
  if (chip) {
    chip.textContent = t('logs.timeline.live_new_events', '{count} new events - refresh')
      .replace('{count}', formatNumber(insightsTimeline.wsPending));
    chip.classList.remove('hidden');
  }

  // Only a live (anchored-to-now) window auto-refreshes; in a drilled-down past
  // range the chip alone signals new data and clicking it jumps back to live.
  if (!insightsTimeline.range.anchoredToNow) return;
  if (insightsTimeline.wsRefetchTimer) return;

  var elapsed = Date.now() - insightsTimeline.wsLastRefetch;
  var delay = Math.max(TIMELINE_WS_REFETCH_MIN_MS - elapsed, 500);
  insightsTimeline.wsRefetchTimer = setTimeout(function() {
    insightsTimeline.wsRefetchTimer = null;
    insightsTimeline.wsLastRefetch = Date.now();
    if (insightsTimeline.active && insightsTimeline.range.anchoredToNow) {
      fetchTimelineData();
    }
  }, delay);
}
