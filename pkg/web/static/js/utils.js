// Utility functions for Fail2ban UI
"use strict";

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
  } catch (err) {
    // Ignore selection errors for elements that do not support it.
  }
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
  } catch (err) {
    // Element may not support setSelectionRange; ignore.
  }
}

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

