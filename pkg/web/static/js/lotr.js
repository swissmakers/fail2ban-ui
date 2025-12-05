// LOTR Mode functions for Fail2ban UI
"use strict";

function isLOTRMode(alertCountries) {
  if (!alertCountries || !Array.isArray(alertCountries)) {
    return false;
  }
  return alertCountries.includes('LOTR');
}

function applyLOTRTheme(active) {
  const body = document.body;
  const lotrCSS = document.getElementById('lotr-css');
  
  if (active) {
    // Enable CSS first
    if (lotrCSS) {
      lotrCSS.disabled = false;
    }
    // Then add class to body
    body.classList.add('lotr-mode');
    isLOTRModeActive = true;
    console.log('🎭 LOTR Mode Activated - Welcome to Middle-earth!');
  } else {
    // Remove class first
    body.classList.remove('lotr-mode');
    // Then disable CSS
    if (lotrCSS) {
      lotrCSS.disabled = true;
    }
    isLOTRModeActive = false;
    console.log('🎭 LOTR Mode Deactivated');
  }
  
  // Force a reflow to ensure styles are applied
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
    // Update navigation title
    const navTitle = document.querySelector('nav .text-xl');
    if (navTitle) {
      navTitle.textContent = 'Middle-earth Security';
    }
    
    // Update page title
    const pageTitle = document.querySelector('title');
    if (pageTitle) {
      pageTitle.textContent = 'Middle-earth Security Realm';
    }
    
    // Update dashboard terminology
    updateDashboardLOTRTerminology(true);
    
    // Add decorative elements
    addLOTRDecorations();
  } else {
    // Restore original text
    const navTitle = document.querySelector('nav .text-xl');
    if (navTitle) {
      navTitle.textContent = 'Fail2ban UI';
    }
    
    const pageTitle = document.querySelector('title');
    if (pageTitle && pageTitle.hasAttribute('data-i18n')) {
      const i18nKey = pageTitle.getAttribute('data-i18n');
      pageTitle.textContent = t(i18nKey, 'Fail2ban UI Dashboard');
    }
    
    // Restore dashboard terminology
    updateDashboardLOTRTerminology(false);
    
    // Remove decorative elements
    removeLOTRDecorations();
  }
}

function updateDashboardLOTRTerminology(active) {
  // Update text elements that use data-i18n
  const elements = document.querySelectorAll('[data-i18n]');
  elements.forEach(el => {
    const i18nKey = el.getAttribute('data-i18n');
    if (active) {
      // Check for LOTR-specific translations
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
      // Restore original translations
      if (i18nKey) {
        el.textContent = t(i18nKey, el.textContent);
      }
    }
  });
  
  // Update "Unban" buttons
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
  // Add decorative divider to settings section if not already present
  const settingsSection = document.getElementById('settingsSection');
  if (settingsSection && !settingsSection.querySelector('.lotr-divider')) {
    const divider = document.createElement('div');
    divider.className = 'lotr-divider';
    divider.style.marginTop = '20px';
    divider.style.marginBottom = '20px';
    
    // Find the first child element (not text node) to insert before
    const firstChild = Array.from(settingsSection.childNodes).find(
      node => node.nodeType === Node.ELEMENT_NODE
    );
    
    if (firstChild && firstChild.parentNode === settingsSection) {
      settingsSection.insertBefore(divider, firstChild);
    } else if (settingsSection.firstChild) {
      // Fallback: append if insertBefore fails
      settingsSection.insertBefore(divider, settingsSection.firstChild);
    } else {
      // Last resort: append to end
      settingsSection.appendChild(divider);
    }
  }
}

function removeLOTRDecorations() {
  const dividers = document.querySelectorAll('.lotr-divider');
  dividers.forEach(div => div.remove());
}

