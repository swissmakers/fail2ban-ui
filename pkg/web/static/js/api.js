// API helper functions for Fail2ban UI

// Add server parameter to URL
function withServerParam(url) {
  if (!currentServerId) {
    return url;
  }
  return url + (url.indexOf('?') === -1 ? '?' : '&') + 'serverId=' + encodeURIComponent(currentServerId);
}

// Get server headers for API requests
function serverHeaders(headers) {
  headers = headers || {};
  if (currentServerId) {
    headers['X-F2B-Server'] = currentServerId;
  }
  return headers;
}

// Auth-aware fetch wrapper that handles 401/403 responses
function authFetch(url, options) {
  options = options || {};
  // Ensure Accept header for API requests
  if (!options.headers) {
    options.headers = {};
  }
  if (!options.headers['Accept']) {
    options.headers['Accept'] = 'application/json';
  }
  
  return fetch(url, options).then(function(response) {
    // Handle authentication errors
    if (response.status === 401 || response.status === 403) {
      if (typeof handleAuthError === 'function') {
        handleAuthError(response);
      }
      // Return a rejected promise to stop the chain
      return Promise.reject(new Error('Authentication required'));
    }
    return response;
  });
}

