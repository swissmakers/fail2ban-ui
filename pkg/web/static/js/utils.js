// Shared utilities for Fail2ban UI.
"use strict";

// =========================================================================
//  Data Normalization
// =========================================================================

function normalizeInsights(data) {
  var normalized = data && typeof data === 'object' ? data : {};
  if (!normalized.totals || typeof normalized.totals !== 'object') {
    normalized.totals = { overall: 0, today: 0, week: 0 };
  } else {
    normalized.totals.overall = typeof normalized.totals.overall === 'number' ? normalized.totals.overall : 0;
    normalized.totals.today = typeof normalized.totals.today === 'number' ? normalized.totals.today : 0;
    normalized.totals.week = typeof normalized.totals.week === 'number' ? normalized.totals.week : 0;
  }
  if (!Array.isArray(normalized.countries)) {
    normalized.countries = [];
  }
  if (!Array.isArray(normalized.recurring)) {
    normalized.recurring = [];
  }
  return normalized;
}

function t(key, fallback) {
  if (translations && Object.prototype.hasOwnProperty.call(translations, key) && translations[key]) {
    return translations[key];
  }
  return fallback !== undefined ? fallback : key;
}

// =========================================================================
//  Focus Management
// =========================================================================

function captureFocusState(container) {
  var active = document.activeElement;
  if (!active || !container || !container.contains(active)) {
    return null;
  }
  var state = { id: active.id || null };
  if (!state.id) {
    return null;
  }
  try {
    if (typeof active.selectionStart === 'number' && typeof active.selectionEnd === 'number') {
      state.selectionStart = active.selectionStart;
      state.selectionEnd = active.selectionEnd;
    }
  } catch (err) {}
  return state;
}

function restoreFocusState(state) {
  if (!state || !state.id) {
    return;
  }
  var next = document.getElementById(state.id);
  if (!next) {
    return;
  }
  if (typeof next.focus === 'function') {
    try {
      next.focus({ preventScroll: true });
    } catch (err) {
      next.focus();
    }
  }
  try {
    if (typeof state.selectionStart === 'number' && typeof state.selectionEnd === 'number' && typeof next.setSelectionRange === 'function') {
      next.setSelectionRange(state.selectionStart, state.selectionEnd);
    }
  } catch (err) {}
}

// =========================================================================
//  String Helpers
// =========================================================================

function highlightQueryMatch(value, query) {
  var text = value || '';
  if (!query) {
    return escapeHtml(text);
  }
  var escapedPattern = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (!escapedPattern) {
    return escapeHtml(text);
  }
  var regex = new RegExp(escapedPattern, "gi");
  var highlighted = text.replace(regex, function(match) {
    return "%%MARK_START%%" + match + "%%MARK_END%%";
  });
  return escapeHtml(highlighted)
    .replace(/%%MARK_START%%/g, "<mark>")
    .replace(/%%MARK_END%%/g, "</mark>");
}

function slugifyId(value, prefix) {
  var input = (value || '').toString();
  var base = input.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  var hash = 0;
  for (var i = 0; i < input.length; i++) {
    hash = ((hash << 5) - hash) + input.charCodeAt(i);
    hash |= 0;
  }
  hash = Math.abs(hash);
  base = base.replace(/^-+|-+$/g, '');
  if (!base) {
    base = 'item';
  }
  return (prefix || 'id') + '-' + base + '-' + hash;
}

// =========================================================================
//  Log Analysis Helper
// =========================================================================

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
  });  if (containsIP) {
    return hasBadStatus || hasIndicator;
  }
  return (hasBadStatus || hasIndicator) && !ip;
}
