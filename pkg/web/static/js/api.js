// API helpers for Fail2ban UI.
"use strict";

// =========================================================================
//  Server-Scoped Requests
// =========================================================================

// Adds the server ID to the URL if a server is selected.
function withServerParam(url) {
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
