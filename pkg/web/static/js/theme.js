"use strict";

var THEME_STORAGE_KEY = 'fail2ban-ui-theme';
var THEME_CHOICES = ['system', 'light', 'dark'];
var themeMediaQuery = null;

// The Appearance choice is kept per browser. Without a stored choice the UI follows the device.
function getThemePreference() {
  try {
    var stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (THEME_CHOICES.indexOf(stored) !== -1) {
      return stored;
    }
  } catch (e) { }
  return 'system';
}

function setThemePreference(preference) {
  if (THEME_CHOICES.indexOf(preference) === -1) {
    return;
  }
  try {
    if (preference === 'system') {
      window.localStorage.removeItem(THEME_STORAGE_KEY);
    } else {
      window.localStorage.setItem(THEME_STORAGE_KEY, preference);
    }
  } catch (e) { }
  syncSystemTheme();
}

function systemPrefersDark() {
  return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
}

function resolveTheme(preference, systemDark, lotrActive) {
  if (lotrActive || preference === 'dark') {
    return 'dark';
  }
  if (preference === 'light') {
    return 'light';
  }
  return systemDark ? 'dark' : 'light';
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

function updateThemeControl(preference) {
  var buttons = document.querySelectorAll('[data-theme-choice]');
  for (var i = 0; i < buttons.length; i++) {
    var active = buttons[i].getAttribute('data-theme-choice') === preference;
    buttons[i].setAttribute('aria-checked', active ? 'true' : 'false');
  }
}

function syncSystemTheme() {
  var preference = getThemePreference();
  var lotrActive = !!(document.body && document.body.classList.contains('lotr-mode'));
  applyTheme(resolveTheme(preference, systemPrefersDark(), lotrActive));
  updateThemeControl(preference);
}

function initThemeManager() {
  syncSystemTheme();
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
window.setThemePreference = setThemePreference;
