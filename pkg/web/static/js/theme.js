"use strict";

var themeMediaQuery = null;

function isAutoDarkEnabled() {
  return document.documentElement.getAttribute('data-auto-dark') === 'true';
}

function getSystemTheme() {
  if (!isAutoDarkEnabled()) {
    return 'light';
  }
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    return 'dark';
  }
  return 'light';
}

function applyTheme(theme) {
  var resolvedTheme = theme === 'dark' ? 'dark' : 'light';
  var root = document.documentElement;

  root.setAttribute('data-theme', resolvedTheme);
  syncFavicons(resolvedTheme);
}

function syncFavicons(theme) {
  var icons = window.__appIcons;
  if (!icons) return;
  var href = theme === 'dark' ? icons.dark : icons.light;
  if (!href) return;
  var favicon = document.getElementById('appFavicon');
  var appleTouchIcon = document.getElementById('appAppleTouchIcon');
  if (favicon) { favicon.setAttribute('href', href); }
  if (appleTouchIcon) { appleTouchIcon.setAttribute('href', href); }
}

function syncSystemTheme() {
  if (document.body && document.body.classList.contains('lotr-mode')) {
    return;
  }
  applyTheme(getSystemTheme());
}

function initThemeManager() {
  syncSystemTheme();
  if (!isAutoDarkEnabled()) {
    return;
  }
  if (!window.matchMedia || themeMediaQuery) {
    return;
  }

  themeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
  if (typeof themeMediaQuery.addEventListener === 'function') {
    themeMediaQuery.addEventListener('change', syncSystemTheme);
  }
}

window.initThemeManager = initThemeManager;
window.syncSystemTheme = syncSystemTheme;
