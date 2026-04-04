// API helpers for Fail2ban UI.
"use strict";

// =========================================================================
//  Base path (set from index.html when BASE_PATH env is set)
// =========================================================================

function appPath(path) {
  var b = typeof window.__BASE_PATH__ === 'string' ? window.__BASE_PATH__ : '';
  if (!path) {
    return b || '/';
  }
  if (path.charAt(0) !== '/') {
    path = '/' + path;
  }
  if (!b) {
    return path;
  }
  return b + path;
}

// =========================================================================
//  Server-Scoped Requests
// =========================================================================

// Adds the server ID to the URL if a server is selected.
function withServerParam(url) {
  url = appPath(url);
  if (!currentServerId) {
    return url;
  }
  return url + (url.indexOf('?') === -1 ? '?' : '&') + 'serverId=' + encodeURIComponent(currentServerId);
}

// Adds the server ID to the headers if a server is selected.
function serverHeaders(headers) {
  headers = headers || {};
  if (currentServerId) {
    headers['X-F2B-Server'] = currentServerId;
  }
  return headers;
}
