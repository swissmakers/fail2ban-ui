// Validation for Fail2ban UI settings and forms.

// =========================================================================
//  Field Validators
// =========================================================================

function validateTimeFormat(value) {
  if (!value || !value.trim()) return { valid: true };
  if (!/^\d+([smhdwy]|mo)$/i.test(value.trim())) {
    return {
      valid: false,
      message: t('settings.validation.time_format', 'Invalid time format. Use: 1m = 1 minute, 1h = 1 hour, 1d = 1 day, 1w = 1 week, 1mo = 1 month, 1y = 1 year')
    };
  }
  return { valid: true };
}

function validateMaxRetry(value) {
  if (!value || value.trim() === '') return { valid: true };
  const num = parseInt(value, 10);
  if (isNaN(num) || num < 1) {
    return {
      valid: false,
      message: t('settings.validation.max_retry', 'Max retry must be a positive integer (minimum 1)')
    };
  }
  return { valid: true };
}

function validateEmail(value) {
  if (!value || !value.trim()) return { valid: true };
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const emails = value.split(',').map(s => s.trim()).filter(s => s);
  for (const email of emails) {
    if (!emailPattern.test(email)) {
      return {
        valid: false,
        message: t('settings.validation.email_format', 'Invalid email format') + ': ' + email
      };
    }
  }
  return { valid: true };
}

// Validates a single DNS label without backtracking-prone regular expressions.
function isValidHostnameLabel(label) {
  if (label.length < 1 || label.length > 63) return false;
  if (label[0] === '-' || label[label.length - 1] === '-') return false;
  for (let i = 0; i < label.length; i++) {
    const c = label[i];
    const isAlnum = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    if (!isAlnum && c !== '-') return false;
  }
  return true;
}

// Linear-time hostname validation (avoids ReDoS from nested quantifiers).
function isValidHostname(host) {
  if (!host || host.length > 253) return false;
  const labels = host.split('.');
  for (let i = 0; i < labels.length; i++) {
    if (!isValidHostnameLabel(labels[i])) return false;
  }
  return true;
}

function isValidIPv4(value) {
  const octets = value.split('.');
  if (octets.length !== 4) return false;
  return octets.every(function(octet) {
    return /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255;
  });
}

function isValidIPv6(value) {
  const gap = value.indexOf('::');
  if (gap !== -1 && value.indexOf('::', gap + 1) !== -1) return false;
  const halves = gap === -1 ? [value] : [value.slice(0, gap), value.slice(gap + 2)];
  let groups = 0;
  for (let h = 0; h < halves.length; h++) {
    if (halves[h] === '') continue;
    const parts = halves[h].split(':');
    for (let i = 0; i < parts.length; i++) {
      const isLast = h === halves.length - 1 && i === parts.length - 1;
      if (isLast && parts[i].indexOf('.') !== -1) {
        if (!isValidIPv4(parts[i])) return false;
        groups += 2;
      } else if (/^[0-9a-fA-F]{1,4}$/.test(parts[i])) {
        groups += 1;
      } else {
        return false;
      }
    }
  }
  return gap === -1 ? groups === 8 : groups <= 7;
}

// IPv4 or IPv6 address; with allowCidr also a network prefix (e.g. 10.0.0.0/8).
function isValidIP(value, allowCidr) {
  if (typeof value !== 'string') return false;
  let addr = value.trim();
  if (!addr) return false;
  let prefix = null;
  const slash = addr.indexOf('/');
  if (slash !== -1) {
    if (!allowCidr) return false;
    prefix = addr.slice(slash + 1);
    addr = addr.slice(0, slash);
    if (!/^(0|[1-9]\d{0,2})$/.test(prefix)) return false;
  }
  // IPv4 with optional CIDR
  if (isValidIPv4(addr)) {
    return prefix === null || Number(prefix) <= 32;
  }
  // IPv6 with optional CIDR
  if (isValidIPv6(addr)) {
    return prefix === null || Number(prefix) <= 128;
  }
  return false;
}

// ignoreip entry: IP, CIDR or hostname; an all-digit last label is a malformed IP, not a host.
function isValidIgnoreEntry(value) {
  if (typeof value !== 'string') return false;
  const entry = value.trim();
  if (isValidIP(entry, true)) return true;
  if (!isValidHostname(entry)) return false;
  return !/^\d+$/.test(entry.split('.').pop());
}

function validateIgnoreIPs() {
  const ignoreIPs = getIgnoreIPsArray();
  const invalidIPs = [];

  for (let i = 0; i < ignoreIPs.length; i++) {
    const ip = ignoreIPs[i];
    if (!isValidIgnoreEntry(ip)) {
      invalidIPs.push(ip);
    }
  }

  if (invalidIPs.length > 0) {
    return {
      valid: false,
      message: t('settings.validation.ignore_ips', 'Invalid IP addresses, CIDR notation, or hostnames') + ': ' + invalidIPs.join(', ')
    };
  }
  return { valid: true };
}

// =========================================================================
//  Error Display
// =========================================================================

function showFieldError(fieldId, message) {
  const errorElement = document.getElementById(fieldId + 'Error');
  const inputElement = document.getElementById(fieldId);
  if (errorElement) {
    errorElement.textContent = message;
    errorElement.classList.remove('hidden');
  }
  if (inputElement) {
    inputElement.classList.add('border-red-500');
    inputElement.classList.remove('border-gray-300');
  }
}

function clearFieldError(fieldId) {
  const errorElement = document.getElementById(fieldId + 'Error');
  const inputElement = document.getElementById(fieldId);
  if (errorElement) {
    errorElement.classList.add('hidden');
    errorElement.textContent = '';
  }
  if (inputElement) {
    inputElement.classList.remove('border-red-500');
    inputElement.classList.add('border-gray-300');
  }
}

// =========================================================================
//  Form Validation
// =========================================================================

function validateAllSettings() {
  let isValid = true;
  const banTime = document.getElementById('banTime');
  if (banTime) {
    const banTimeValidation = validateTimeFormat(banTime.value);
    if (!banTimeValidation.valid) {
      showFieldError('banTime', banTimeValidation.message);
      isValid = false;
    } else {
      clearFieldError('banTime');
    }
  }

  const findTime = document.getElementById('findTime');
  if (findTime) {
    const findTimeValidation = validateTimeFormat(findTime.value);
    if (!findTimeValidation.valid) {
      showFieldError('findTime', findTimeValidation.message);
      isValid = false;
    } else {
      clearFieldError('findTime');
    }
  }

  const maxRetry = document.getElementById('maxRetry');
  if (maxRetry) {
    const maxRetryValidation = validateMaxRetry(maxRetry.value);
    if (!maxRetryValidation.valid) {
      showFieldError('maxRetry', maxRetryValidation.message);
      isValid = false;
    } else {
      clearFieldError('maxRetry');
    }
  }

  const destEmail = document.getElementById('destEmail');
  if (destEmail) {
    const emailValidation = validateEmail(destEmail.value);
    if (!emailValidation.valid) {
      showFieldError('destEmail', emailValidation.message);
      isValid = false;
    } else {
      clearFieldError('destEmail');
    }
  }

  const ignoreIPsValidation = validateIgnoreIPs();
  if (!ignoreIPsValidation.valid) {
    const errorContainer = document.getElementById('ignoreIPsError');
    if (errorContainer) {
      errorContainer.textContent = ignoreIPsValidation.message;
      errorContainer.classList.remove('hidden');
    }
    if (typeof showToast === 'function') {
      showToast(ignoreIPsValidation.message, 'error');
    }
    isValid = false;
  } else {
    const errorContainer = document.getElementById('ignoreIPsError');
    if (errorContainer) {
      errorContainer.classList.add('hidden');
      errorContainer.textContent = '';
    }
  }

  const threatIntelProviderEl = document.getElementById('threatIntelProvider');
  if (threatIntelProviderEl) {
    const provider = threatIntelProviderEl.value;
    const alienKeyEl = document.getElementById('threatIntelAlienVaultApiKey');
    const abuseKeyEl = document.getElementById('threatIntelAbuseIpDbApiKey');
    if (provider === 'alienvault') {
      if (!alienKeyEl || !alienKeyEl.value.trim()) {
        showFieldError('threatIntelAlienVaultApiKey', t('settings.validation.alienvault_key_required', 'AlienVault API key is required'));
        isValid = false;
      } else {
        clearFieldError('threatIntelAlienVaultApiKey');
      }
      clearFieldError('threatIntelAbuseIpDbApiKey');
    } else if (provider === 'abuseipdb') {
      if (!abuseKeyEl || !abuseKeyEl.value.trim()) {
        showFieldError('threatIntelAbuseIpDbApiKey', t('settings.validation.abuseipdb_key_required', 'AbuseIPDB API key is required'));
        isValid = false;
      } else {
        clearFieldError('threatIntelAbuseIpDbApiKey');
      }
      clearFieldError('threatIntelAlienVaultApiKey');
    } else {
      clearFieldError('threatIntelAlienVaultApiKey');
      clearFieldError('threatIntelAbuseIpDbApiKey');
    }
  }
  return isValid;
}

function setupFormValidation() {
  const banTimeInput = document.getElementById('banTime');
  const findTimeInput = document.getElementById('findTime');
  const maxRetryInput = document.getElementById('maxRetry');
  const destEmailInput = document.getElementById('destEmail');
  
  if (banTimeInput) {
    banTimeInput.addEventListener('blur', function() {
      const validation = validateTimeFormat(this.value);
      if (!validation.valid) {
        showFieldError('banTime', validation.message);
      } else {
        clearFieldError('banTime');
      }
    });
  }

  if (findTimeInput) {
    findTimeInput.addEventListener('blur', function() {
      const validation = validateTimeFormat(this.value);
      if (!validation.valid) {
        showFieldError('findTime', validation.message);
      } else {
        clearFieldError('findTime');
      }
    });
  }

  if (maxRetryInput) {
    maxRetryInput.addEventListener('blur', function() {
      const validation = validateMaxRetry(this.value);
      if (!validation.valid) {
        showFieldError('maxRetry', validation.message);
      } else {
        clearFieldError('maxRetry');
      }
    });
  }

  if (destEmailInput) {
    destEmailInput.addEventListener('blur', function() {
      const validation = validateEmail(this.value);
      if (!validation.valid) {
        showFieldError('destEmail', validation.message);
      } else {
        clearFieldError('destEmail');
      }
    });
  }
}
