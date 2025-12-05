// Validation functions for Fail2ban UI

function validateTimeFormat(value, fieldName) {
  if (!value || !value.trim()) return { valid: true }; // Empty is OK
  const timePattern = /^\d+[smhdwmy]$/i;
  if (!timePattern.test(value.trim())) {
    return { 
      valid: false, 
      message: 'Invalid time format. Use format like: 1h, 30m, 2d, 1w, 1m, 1y' 
    };
  }
  return { valid: true };
}

function validateMaxRetry(value) {
  if (!value || value.trim() === '') return { valid: true }; // Empty is OK
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
  if (!value || !value.trim()) return { valid: true }; // Empty is OK
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(value.trim())) {
    return { 
      valid: false, 
      message: 'Invalid email format' 
    };
  }
  return { valid: true };
}

// Validate IP address (IPv4, IPv6, CIDR, or hostname)
function isValidIP(ip) {
  if (!ip || !ip.trim()) return false;
  ip = ip.trim();
  
  // Allow hostnames (fail2ban supports DNS hostnames)
  // Basic hostname validation: alphanumeric, dots, hyphens
  const hostnamePattern = /^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?)*$/;
  
  // IPv4 with optional CIDR
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  
  // IPv6 with optional CIDR (simplified - allows various IPv6 formats)
  const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(\/\d{1,3})?$/;
  const ipv6CompressedPattern = /^::([0-9a-fA-F]{0,4}:){0,6}[0-9a-fA-F]{0,4}(\/\d{1,3})?$/;
  const ipv6FullPattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(\/\d{1,3})?$/;
  
  // Check IPv4
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
  
  // Check IPv6
  if (ipv6Pattern.test(ip) || ipv6CompressedPattern.test(ip) || ipv6FullPattern.test(ip)) {
    if (ip.includes('/')) {
      const parts = ip.split('/');
      const cidr = parseInt(parts[1], 10);
      if (cidr < 0 || cidr > 128) return false;
    }
    return true;
  }
  
  // Check hostname
  if (hostnamePattern.test(ip)) {
    return true;
  }
  
  return false;
}

function validateIgnoreIPs() {
  if (typeof getIgnoreIPsArray !== 'function') {
    console.error('getIgnoreIPsArray function not found');
    return { valid: true }; // Skip validation if function not available
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

function validateAllSettings() {
  let isValid = true;
  
  // Validate bantime
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
  
  // Validate findtime
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
  
  // Validate max retry
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
  
  // Validate email
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
  
  // Validate IgnoreIPs
  const ignoreIPsValidation = validateIgnoreIPs();
  if (!ignoreIPsValidation.valid) {
    // Show error for ignoreIPs field
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

// Setup validation on blur for all fields
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

