// LOTR Mode functions for Fail2ban UI
"use strict";

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
    console.log('🎭 LOTR Mode Activated - Welcome to Middle-earth!');
  } else {
    body.classList.remove('lotr-mode');
    if (lotrCSS) {
      lotrCSS.disabled = true;
    }
    isLOTRModeActive = false;
    console.log('🎭 LOTR Mode Deactivated');
  }
  void body.offsetHeight;
}

function checkAndApplyLOTRTheme(alertCountries) {
  const shouldBeActive = isLOTRMode(alertCountries);
  if (shouldBeActive !== isLOTRModeActive) {
    applyLOTRTheme(shouldBeActive);
    updateLOTRTerminology(shouldBeActive);
  }
}

function updateLOTRTerminology(active) {
  if (active) {
    const navTitle = document.querySelector('nav .text-xl');
    if (navTitle) {
      navTitle.textContent = 'Middle-earth Security';
    }
    const pageTitle = document.querySelector('title');
    if (pageTitle) {
      pageTitle.textContent = 'Middle-earth Security Realm';
    }
    updateDashboardLOTRTerminology(true);
    addLOTRDecorations();
  } else {
    const navTitle = document.querySelector('nav .text-xl');
    if (navTitle) {
      navTitle.textContent = 'Fail2ban UI';
    }
    const pageTitle = document.querySelector('title');
    if (pageTitle && pageTitle.hasAttribute('data-i18n')) {
      const i18nKey = pageTitle.getAttribute('data-i18n');
      pageTitle.textContent = t(i18nKey, 'Fail2ban UI Dashboard');
    }
    updateDashboardLOTRTerminology(false);
    removeLOTRDecorations();
  }
}

function updateDashboardLOTRTerminology(active) {
  const elements = document.querySelectorAll('[data-i18n]');
  elements.forEach(el => {
    const i18nKey = el.getAttribute('data-i18n');
    if (active) {
      if (i18nKey === 'dashboard.cards.total_banned') {
        el.textContent = t('lotr.threats_banished', 'Threats Banished');
      } else if (i18nKey === 'dashboard.table.banned_ips') {
        el.textContent = t('lotr.threats_banished', 'Threats Banished');
      } else if (i18nKey === 'dashboard.search_label') {
        el.textContent = t('lotr.threats_banished', 'Search Banished Threats');
      } else if (i18nKey === 'dashboard.manage_servers') {
        el.textContent = t('lotr.realms_protected', 'Manage Realms');
      }
    } else {
      if (i18nKey) {
        el.textContent = t(i18nKey, el.textContent);
      }
    }
  });
  const unbanButtons = document.querySelectorAll('button, a');
  unbanButtons.forEach(btn => {
    if (btn.textContent && btn.textContent.includes('Unban')) {
      if (active) {
        btn.textContent = btn.textContent.replace(/Unban/gi, t('lotr.banished', 'Restore to Realm'));
      } else {
        btn.textContent = btn.textContent.replace(/Restore to Realm/gi, t('dashboard.unban', 'Unban'));
      }
    }
  });
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
