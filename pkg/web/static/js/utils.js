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

// Sets translated text and keeps data-i18n in sync so updateTranslations does not revert it.
function setI18nText(el, key, fallback) {
  el.setAttribute('data-i18n', key);
  el.textContent = t(key, fallback);
}

// messageKey wins, then the server's text, then the caller's fallback.
function apiMessage(data, fallbackKey, fallbackText) {
  var text = data ? (data.error || data.message || '') : '';
  if (data && data.messageKey) {
    return t(data.messageKey, text || t(fallbackKey, fallbackText));
  }
  return text ? String(text) : t(fallbackKey, fallbackText);
}

// Resolves with the parsed body (null when not JSON); rejects non-2xx with a translated message.
function readJsonResponse(res) {
  return res.json()
    .catch(function() { return null; })
    .then(function(data) {
      if (res.ok) {
        return data;
      }
      var err = new Error(apiMessage(data, '', '') || t('common.http_error', 'Server returned {status}').replace('{status}', String(res.status)));
      err.status = res.status;
      err.data = data;
      throw err;
    });
}

function formatApiError(data, fallbackKey, fallbackText) {
  var shortMessage = '';
  if (data && data.messageKey) {
    shortMessage = t(data.messageKey, fallbackText || fallbackKey || '');
  } else if (fallbackKey) {
    shortMessage = t(fallbackKey, fallbackText || fallbackKey);
  } else if (fallbackText) {
    shortMessage = fallbackText;
  }

  if (!shortMessage && data && data.message) {
    shortMessage = String(data.message);
  }

  var detail = data && data.error ? String(data.error).trim() : '';
  if (detail) {
    if (!shortMessage || detail === shortMessage) {
      return detail;
    }
    return shortMessage + ': ' + detail;
  }

  if (shortMessage) {
    return shortMessage;
  }

  return t('common.unknown_error', 'Unknown error');
}

// Shows or hides a collapsed list and swaps the toggle label (data-more-label / data-less-label).
function toggleHiddenList(hiddenId, buttonId) {
  var hidden = document.getElementById(hiddenId);
  var button = document.getElementById(buttonId);
  if (!hidden || !button) {
    return;
  }
  var expand = hidden.classList.contains('hidden');
  hidden.classList.toggle('hidden', !expand);
  button.textContent = button.getAttribute(expand ? 'data-less-label' : 'data-more-label') || button.textContent;
  button.setAttribute('data-expanded', expand ? 'true' : 'false');
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
  var statusMatch = line.match(/"(?:status|code|statusCode)"\s*:\s*(\d{3})\b/i) ||
    line.match(/"[^"]*"\s+(\d{3})\b/) ||
    line.match(/\s(\d{3})\s+(?:\d+|-)/);
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

// Builds escaped log HTML with suspicious lines wrapped in .logs-highlighted-line.
// Returns {html, highlighted} so callers can fall back to plain text.
function buildHighlightedLogsHtml(logs, ip) {
  var logLines = (logs || '').split('\n');
  var html = '';
  var highlighted = false;
  for (var i = 0; i < logLines.length; i++) {
    var safeLine = escapeHtml(logLines[i] || '');
    if (isSuspiciousLogLine(logLines[i], ip)) {
      highlighted = true;
      html += '<span class="logs-highlighted-line">' + safeLine + '</span>';
    } else {
      html += safeLine + '\n';
    }
  }
  return { html: html, highlighted: highlighted };
}

// =========================================================================
//  Display Helpers
// =========================================================================

function countryLabel(country) {
  return country || t('logs.overview.country_unknown', 'Unknown');
}

function sortServersForDisplay(servers) {
  return (servers || []).slice().sort(function (a, b) {
    var an = a.name || a.id || '';
    var bn = b.name || b.id || '';
    return an.localeCompare(bn, undefined, { numeric: true, sensitivity: 'base' });
  });
}
