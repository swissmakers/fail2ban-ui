// LOTR Mode functions for Fail2ban UI
"use strict";

// Keys rendered with LOTR wording while the mode is active.
var LOTR_KEY_OVERRIDES = {
  'page.title': 'lotr.page_title',
  'dashboard.cards.total_banned': 'lotr.threats_banished',
  'dashboard.table.banned_ips': 'lotr.threats_banished',
  'dashboard.search_label': 'lotr.search_banished',
  'dashboard.manage_servers': 'lotr.manage_realms',
  'dashboard.unban': 'lotr.restore_to_realm',
  'dashboard.ban.confirm': 'lotr.confirm_ban',
  'dashboard.unban.confirm': 'lotr.confirm_unban'
};

function lotrI18nKey(key) {
  return isLOTRModeActive && Object.prototype.hasOwnProperty.call(LOTR_KEY_OVERRIDES, key) ? LOTR_KEY_OVERRIDES[key] : key;
}

function isLOTRMode(alertCountries) {
  if (!alertCountries || !Array.isArray(alertCountries)) {
    return false;
  }
  return alertCountries.includes('LOTR');
}

// =========================================================================
//  Theme Application
// =========================================================================

function applyLOTRTheme(active) {
  const body = document.body;
  const lotrCSS = document.getElementById('lotr-css');
  if (active) {
    if (lotrCSS) {
      lotrCSS.disabled = false;
    }
    body.classList.add('lotr-mode');
    isLOTRModeActive = true;
  } else {
    body.classList.remove('lotr-mode');
    if (lotrCSS) {
      lotrCSS.disabled = true;
    }
    isLOTRModeActive = false;
  }
  if (typeof syncSystemTheme === 'function') {
    syncSystemTheme();
  }
  void body.offsetHeight;
}

function checkAndApplyLOTRTheme(alertCountries) {
  const shouldBeActive = isLOTRMode(alertCountries);
  if (shouldBeActive === isLOTRModeActive) {
    return;
  }
  applyLOTRTheme(shouldBeActive);
  if (shouldBeActive) {
    addLOTRDecorations();
  } else {
    removeLOTRDecorations();
  }
  updateTranslations();
}

function addLOTRDecorations() {
  const settingsSection = document.getElementById('settingsSection');
  if (settingsSection && !settingsSection.querySelector('.lotr-divider')) {
    const divider = document.createElement('div');
    divider.className = 'lotr-divider';
    divider.style.marginTop = '20px';
    divider.style.marginBottom = '20px';
    const firstChild = Array.from(settingsSection.childNodes).find(
      node => node.nodeType === Node.ELEMENT_NODE
    );
    if (firstChild && firstChild.parentNode === settingsSection) {
      settingsSection.insertBefore(divider, firstChild);
    } else if (settingsSection.firstChild) {
      settingsSection.insertBefore(divider, settingsSection.firstChild);
    } else {
      settingsSection.appendChild(divider);
    }
  }
}

function removeLOTRDecorations() {
  const dividers = document.querySelectorAll('.lotr-divider');
  dividers.forEach(div => div.remove());
}
