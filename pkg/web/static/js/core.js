// Core UI utilities: loading overlay, toasts, formatting, search, and navigation.
"use strict";

// =========================================================================
//  Loading Overlay
// =========================================================================

function showLoading(show) {
  var overlay = document.getElementById('loading-overlay');
  if (overlay) {
    if (show) {
      overlay.style.setProperty('display', 'flex', 'important');
      setTimeout(() => overlay.classList.add('show'), 10);
    } else {
      overlay.classList.remove('show');
      setTimeout(() => overlay.style.setProperty('display', 'none', 'important'), 400);
    }
  }
}

// =========================================================================
//  Toast Notifications
// =========================================================================

function showToast(message, type, duration) {
  var container = document.getElementById('toast-container');
  if (!container || !message) return;
  
  // Show ban/unban events as their own styled toast
  if (typeof message === 'object' && message.type === 'ban_event') {
    showBanEventToast(message.data || message);
    return;
  }
  
  var toast = document.createElement('div');
  var variant = type || 'info';
  toast.className = 'toast toast-' + variant;

  var wrapper = document.createElement('div');
  wrapper.className = 'flex items-start';

  var textSpan = document.createElement('span');
  textSpan.className = 'flex-1';
  textSpan.textContent = message;

  var closeBtn = document.createElement('button');
  closeBtn.className = 'flex-shrink-0 ml-2 mt-0.5 opacity-60 hover:opacity-100 focus:outline-none';
  closeBtn.setAttribute('aria-label', 'Close');
  closeBtn.innerHTML = '<i class="fas fa-times text-sm"></i>';

  wrapper.appendChild(textSpan);
  wrapper.appendChild(closeBtn);
  toast.appendChild(wrapper);

  closeBtn.addEventListener('click', function(e) {
    e.stopPropagation();
    clearTimeout(autoRemoveTimer);
    toast.classList.remove('show');
    setTimeout(function() { toast.remove(); }, 300);
  });

  container.appendChild(toast);
  requestAnimationFrame(function() {
    toast.classList.add('show');
  });
  var autoRemoveTimer = setTimeout(function() {
    toast.classList.remove('show');
    setTimeout(function() {
      toast.remove();
    }, 300);
  }, duration || 5000);
}

// One function for both ban and unban events
function showBanEventToast(event) {
  var container = document.getElementById('toast-container');
  if (!container || !event) return;
  
  var isUnban = event.eventType === 'unban';
  var toast = document.createElement('div');
  toast.className = isUnban ? 'toast toast-unban-event' : 'toast toast-ban-event';
  
  var ip = event.ip || 'Unknown IP';
  var jail = event.jail || 'Unknown Jail';
  var server = event.serverName || event.serverId || 'Unknown Server';
  var country = event.country || 'UNKNOWN';
  
  var title = isUnban ? t('toast.unban.title', 'IP unblocked') : t('toast.ban.title', 'New block occurred');
  var action = isUnban ? t('toast.unban.action', 'unblocked from') : t('toast.ban.action', 'banned in');
  var icon = isUnban ? 'fas fa-check-circle text-green-400' : 'fas fa-shield-alt text-red-500';
  
  toast.innerHTML = ''
    + '<div class="flex items-start gap-3">'
    + '  <div class="flex-shrink-0 mt-1">'
    + '    <i class="' + icon + '"></i>'
    + '  </div>'
    + '  <div class="flex-1 min-w-0">'
    + '    <div class="font-semibold text-sm">' + title + '</div>'
    + '    <div class="text-sm mt-1">'
    + '      <span class="font-mono font-semibold">' + escapeHtml(ip) + '</span>'
    + '      <span> ' + action + ' </span>'
    + '      <span class="font-semibold">' + escapeHtml(jail) + '</span>'
    + '    </div>'
    + '    <div class="text-xs text-gray-400 mt-1">'
    + '      ' + escapeHtml(server) + ' • ' + escapeHtml(country)
    + '    </div>'
    + '  </div>'
    + '  <button class="flex-shrink-0 ml-2 mt-0.5 text-gray-400 hover:text-white focus:outline-none" aria-label="Close">'
    + '    <i class="fas fa-times text-sm"></i>'
    + '  </button>'
    + '</div>';

  var closeBtn = toast.querySelector('button');
  closeBtn.addEventListener('click', function(e) {
    e.stopPropagation();
    clearTimeout(autoRemoveTimer);
    toast.classList.remove('show');
    setTimeout(function() { toast.remove(); }, 300);
  });

  // Click on toast body scrolls to ban events table
  toast.addEventListener('click', function() {
    var logSection = document.getElementById('logOverviewSection');
    if (logSection) {
      logSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
  
  toast.style.cursor = 'pointer';
  container.appendChild(toast);
  
  requestAnimationFrame(function() {
    toast.classList.add('show');
  });
  
  var autoRemoveTimer = setTimeout(function() {
    toast.classList.remove('show');
    setTimeout(function() {
      toast.remove();
    }, 300);
  }, 5000);
}

// =========================================================================
//  Formatting Helpers
// =========================================================================

// Escape HTML special characters to prevent XSS
function escapeHtml(value) {
  if (value === undefined || value === null) return '';
  return String(value).replace(/[&<>"']/g, function(match) {
    switch (match) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      default: return '&#39;';
    }
  });
}

// Format numbers in a human-readable way (1,000,000)
function formatNumber(value) {
  var num = Number(value);
  if (!isFinite(num)) {
    return '0';
  }
  try {
    return num.toLocaleString();
  } catch (e) {
    return String(num);
  }
}

// Format date and time in a human-readable way (YYYY.MM.DD, HH:MM:SS)
function formatDateTime(value) {
  if (!value) return '';
  var date = new Date(value);
  if (isNaN(date.getTime())) {
    return value;
  }
  var year = date.getFullYear();
  var month = String(date.getMonth() + 1).padStart(2, '0');
  var day = String(date.getDate()).padStart(2, '0');
  var hours = String(date.getHours()).padStart(2, '0');
  var minutes = String(date.getMinutes()).padStart(2, '0');
  var seconds = String(date.getSeconds()).padStart(2, '0');
  return year + '.' + month + '.' + day + ', ' + hours + ':' + minutes + ':' + seconds;
}

// =========================================================================
//  External IP
// =========================================================================

// Try multiple providers until one returns a valid IP
function displayExternalIP() {
  const target = document.getElementById('external-ip');
  if (!target) return;

  const providers = [
    { url: 'https://api.ipify.org?format=json', extract: data => data.ip },
    { url: 'https://ipapi.co/json/', extract: data => data && (data.ip || data.ip_address) },
    { url: 'https://ipv4.jsonip.com/', extract: data => data.ip }
  ];

  const tryProvider = (index) => {
    if (index >= providers.length) {
      target.textContent = 'Unavailable';
      return;
    }
    const provider = providers[index];
    fetch(provider.url, { headers: { 'Accept': 'application/json' } })
      .then(res => {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      })
      .then(data => {
        const ip = provider.extract(data);
        if (ip) {
          target.textContent = ip;
        } else {
          throw new Error('Missing IP');
        }
      })
      .catch(() => {
        tryProvider(index + 1);
      });
  };

  tryProvider(0);
}

// =========================================================================
//  UI Initialization
// =========================================================================

function initializeTooltips() {
  const tooltips = document.querySelectorAll('[data-tooltip]');
  tooltips.forEach(el => {
    el.addEventListener('mouseenter', () => {
      const tooltip = document.createElement('div');
      tooltip.className = 'absolute z-10 bg-gray-800 text-white text-xs rounded py-1 px-2 whitespace-nowrap';
      tooltip.textContent = el.getAttribute('data-tooltip');
      tooltip.style.top = (el.offsetTop - 30) + 'px';
      tooltip.style.left = (el.offsetLeft + (el.offsetWidth / 2) - (tooltip.offsetWidth / 2)) + 'px';
      tooltip.id = 'tooltip-' + Date.now();
      document.body.appendChild(tooltip);
      el.setAttribute('data-tooltip-id', tooltip.id);
    });
    
    el.addEventListener('mouseleave', () => {
      const tooltipId = el.getAttribute('data-tooltip-id');
      if (tooltipId) {
        const tooltip = document.getElementById(tooltipId);
        if (tooltip) tooltip.remove();
        el.removeAttribute('data-tooltip-id');
      }
    });
  });
}

// Restrict the IP search input to digits and dots only
function initializeSearch() {
  const ipSearch = document.getElementById("ipSearch");
  if (ipSearch) {
    ipSearch.addEventListener("keypress", function(event) {
      const char = String.fromCharCode(event.which);
      if (!/[0-9.]/.test(char)) {
        event.preventDefault();
      }
    });
  }
}

// =========================================================================
//  Navigation
// =========================================================================

function updateRestartBanner() {
  var banner = document.getElementById('restartBanner');
  if (!banner) return;
  // Don't show restart banner for local connectors; they only reload, not restart
  if (currentServer && currentServer.restartNeeded && currentServer.type !== 'local') {
    banner.style.display = 'block';
  } else {
    banner.style.display = 'none';
  }
}

function showSection(sectionId) {
  // hide all sections
  document.getElementById('dashboardSection').classList.add('hidden');
  document.getElementById('filterSection').classList.add('hidden');
  document.getElementById('settingsSection').classList.add('hidden');

  // show the requested section
  document.getElementById(sectionId).classList.remove('hidden');

  // If it's filterSection, load filters
  if (sectionId === 'filterSection') {
    if (typeof showFilterSection === 'function') {
      showFilterSection();
    }
  }
  // If it's settingsSection, load settings
  if (sectionId === 'settingsSection') {
    if (typeof loadSettings === 'function') {
      loadSettings();
    }
  }
  // Close navbar on mobile when clicking a menu item
  document.getElementById('mobileMenu').classList.add('hidden');
}

function toggleMobileMenu() {
  const menu = document.getElementById('mobileMenu');
  menu.classList.toggle('hidden');
}
