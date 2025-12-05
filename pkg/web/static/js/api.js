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

