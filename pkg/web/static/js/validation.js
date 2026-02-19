// Validation for Fail2ban UI settings and forms.

// =========================================================================
//  Field Validators
// =========================================================================

function validateTimeFormat(value, fieldName) {
  if (!value || !value.trim()) return { valid: true };
  const timePattern = /^\d+([smhdwy]|mo)$/i;
  if (!timePattern.test(value.trim())) {
    return { 
      valid: false, 
      message: 'Invalid time format. Use format: 1m = 1 minute, 1h = 1 hour, 1d = 1 day, 1w = 1 week, 1mo = 1 month, 1y = 1 year'
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
      message: 'Max retry must be a positive integer (minimum 1)' 
    };
  }
  return { valid: true };
}

function validateEmail(value) {
  if (!value || !value.trim()) return { valid: true };
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(value.trim())) {
    return { 
      valid: false, 
      message: 'Invalid email format' 
    };
  }
  return { valid: true };
}

function isValidIP(ip) {
  if (!ip || !ip.trim()) return false;
  ip = ip.trim();
  // fail2ban accepts hostnames in addition to IPs
  const hostnamePattern = /^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?)*$/;
  // IPv4 with optional CIDR
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  // IPv6 with optional CIDR
  const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(\/\d{1,3})?$/;
  const ipv6CompressedPattern = /^::([0-9a-fA-F]{0,4}:){0,6}[0-9a-fA-F]{0,4}(\/\d{1,3})?$/;
  const ipv6FullPattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\/\d{1,3})?$/;

  if (ipv4Pattern.test(ip)) {
    const parts = ip.split('/');
    const octets = parts[0].split('.');
    for (let octet of octets) {
      const num = parseInt(octet, 10);
      if (num < 0 || num > 255) return false;
    }
    if (parts.length > 1) {
      const cidr = parseInt(parts[1], 10);
      if (cidr < 0 || cidr > 32) return false;
    }
    return true;
  }
  if (ipv6Pattern.test(ip) || ipv6CompressedPattern.test(ip) || ipv6FullPattern.test(ip)) {
    if (ip.includes('/')) {
      const parts = ip.split('/');
      const cidr = parseInt(parts[1], 10);
      if (cidr < 0 || cidr > 128) return false;
    }
    return true;
  }
  if (hostnamePattern.test(ip)) {
    return true;
  }
  return false;
}

function validateIgnoreIPs() {
  if (typeof getIgnoreIPsArray !== 'function') {
    console.error('getIgnoreIPsArray function not found');
    return { valid: true };
  }
  const ignoreIPs = getIgnoreIPsArray();
  const invalidIPs = [];

  for (let i = 0; i < ignoreIPs.length; i++) {
    const ip = ignoreIPs[i];
    if (!isValidIP(ip)) {
      invalidIPs.push(ip);
    }
  }

  if (invalidIPs.length > 0) {
    return {
      valid: false,
      message: 'Invalid IP addresses, CIDR notation, or hostnames: ' + invalidIPs.join(', ')
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
    const banTimeValidation = validateTimeFormat(banTime.value, 'bantime');
    if (!banTimeValidation.valid) {
      showFieldError('banTime', banTimeValidation.message);
      isValid = false;
    } else {
      clearFieldError('banTime');
    }
  }

  const findTime = document.getElementById('findTime');
  if (findTime) {
    const findTimeValidation = validateTimeFormat(findTime.value, 'findtime');
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
  return isValid;
}

function setupFormValidation() {
  const banTimeInput = document.getElementById('banTime');
  const findTimeInput = document.getElementById('findTime');
  const maxRetryInput = document.getElementById('maxRetry');
  const destEmailInput = document.getElementById('destEmail');
  
  if (banTimeInput) {
    banTimeInput.addEventListener('blur', function() {
      const validation = validateTimeFormat(this.value, 'bantime');
      if (!validation.valid) {
        showFieldError('banTime', validation.message);
      } else {
        clearFieldError('banTime');
      }
    });
  }

  if (findTimeInput) {
    findTimeInput.addEventListener('blur', function() {
      const validation = validateTimeFormat(this.value, 'findtime');
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
