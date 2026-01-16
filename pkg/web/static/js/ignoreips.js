// Ignore IPs tag management functions for Fail2ban UI
"use strict";

function renderIgnoreIPsTags(ips) {
  const container = document.getElementById('ignoreIPsTags');
  if (!container) return;
  container.innerHTML = '';
  if (ips && ips.length > 0) {
    ips.forEach(function(ip) {
      if (ip && ip.trim()) {
        addIgnoreIPTag(ip.trim());
      }
    });
  }
}

function addIgnoreIPTag(ip) {
  if (!ip || !ip.trim()) return;
  
  const trimmedIP = ip.trim();
  
  // Validate IP before adding - isValidIP is in validation.js
  if (typeof isValidIP === 'function' && !isValidIP(trimmedIP)) {
    if (typeof showToast === 'function') {
      showToast('Invalid IP address, CIDR, or hostname: ' + trimmedIP, 'error');
    }
    return;
  }
  
  const container = document.getElementById('ignoreIPsTags');
  if (!container) return;
  
  const existingTags = Array.from(container.querySelectorAll('.ignore-ip-tag')).map(tag => tag.dataset.ip);
  if (existingTags.includes(trimmedIP)) {
    return; // Already exists
  }
  
  const tag = document.createElement('span');
  tag.className = 'ignore-ip-tag inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800';
  tag.dataset.ip = trimmedIP;
  const escapedIP = escapeHtml(trimmedIP);
  tag.innerHTML = escapedIP + ' <button type="button" class="ml-1 text-blue-600 hover:text-blue-800 focus:outline-none" onclick="removeIgnoreIPTag(\'' + escapedIP.replace(/'/g, "\\'") + '\')">×</button>';
  container.appendChild(tag);
  
  // Clear input
  const input = document.getElementById('ignoreIPInput');
  if (input) input.value = '';
}

function removeIgnoreIPTag(ip) {
  const container = document.getElementById('ignoreIPsTags');
  if (!container) return;
  const escapedIP = escapeHtml(ip);
  const tag = container.querySelector('.ignore-ip-tag[data-ip="' + escapedIP.replace(/"/g, '&quot;') + '"]');
  if (tag) {
    tag.remove();
  }
}

function getIgnoreIPsArray() {
  const container = document.getElementById('ignoreIPsTags');
  if (!container) return [];
  const tags = container.querySelectorAll('.ignore-ip-tag');
  return Array.from(tags).map(tag => tag.dataset.ip).filter(ip => ip && ip.trim());
}

function setupIgnoreIPsInput() {
  const input = document.getElementById('ignoreIPInput');
  if (!input) return;
  
  // Allow spaces for space-separated lists, but validate on paste/enter/blur
  let lastValue = '';
  input.addEventListener('input', function(e) {
    // Allow spaces for space-separated lists
    // Allow: 0-9, a-z, A-Z, :, ., /, -, _, space (for space-separated lists)
    let value = this.value;
    // Remove any characters that aren't valid for IPs/hostnames or spaces
    const filtered = value.replace(/[^0-9a-zA-Z:.\/\-\_\s]/g, '');
    if (value !== filtered) {
      this.value = filtered;
    }
    lastValue = filtered;
  });
  
  input.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      const value = input.value.trim();
      if (value) {
        // Support space or comma separated IPs
        const ips = value.split(/[,\s]+/).filter(ip => ip.trim());
        ips.forEach(ip => addIgnoreIPTag(ip.trim()));
      }
    }
  });
  
  input.addEventListener('blur', function(e) {
    const value = input.value.trim();
    if (value) {
      const ips = value.split(/[,\s]+/).filter(ip => ip.trim());
      ips.forEach(ip => addIgnoreIPTag(ip.trim()));
    }
  });
  
  // Handle paste events to automatically process space-separated lists
  input.addEventListener('paste', function(e) {
    // Allow default paste behavior first
    setTimeout(() => {
      const value = input.value.trim();
      if (value) {
        // Check if pasted content contains spaces (likely a space-separated list)
        if (value.includes(' ') || value.includes(',')) {
          const ips = value.split(/[,\s]+/).filter(ip => ip.trim());
          ips.forEach(ip => addIgnoreIPTag(ip.trim()));
          input.value = ''; // Clear input after processing
        }
      }
    }, 0);
  });
}

