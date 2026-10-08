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

// Cache-busted URL for an embedded asset; the version comes from <html data-asset-version>.
function assetUrl(path) {
  var version = document.documentElement.getAttribute('data-asset-version') || '';
  return appPath(path) + (version ? '?v=' + encodeURIComponent(version) : '');
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

// =========================================================================
//  Session Expiry
// =========================================================================

// Only a 401 from our own API means the session is gone; other origins and non-API paths are ignored.
function isSessionExpiredResponse(status, url) {
  if (status !== 401 || !url) {
    return false;
  }
  var parsed;
  try {
    parsed = new URL(url, window.location.href);
  } catch (e) {
    return false;
  }
  return parsed.origin === window.location.origin && parsed.pathname.indexOf(appPath('/api/')) === 0;
}

if (typeof window.fetch === 'function') {
  var nativeFetch = window.fetch.bind(window);
  window.fetch = function(input, init) {
    init = init || {};
    var controller, timer;
    var url = typeof input === 'string' ? input : (input && input.url);
    var ownAPI = false;
    try {
      var parsed = new URL(url, window.location.href);
      ownAPI = parsed.origin === window.location.origin && parsed.pathname.indexOf(appPath('/api/')) === 0;
    } catch (ignore) { }
    if (ownAPI && ['POST', 'PUT', 'DELETE', 'PATCH'].indexOf(String(init.method || '').toUpperCase()) !== -1 && typeof Headers !== 'undefined') {
      var headers = new Headers(init.headers || {});
      if (!headers.has('Idempotency-Key')) {
        headers.set('Idempotency-Key', typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + '-' + Math.random().toString(36).slice(2));
      }
      init = Object.assign({}, init, { headers: headers });
    }
    // These deadlines bound HTTP requests, never the background operation.
    if (ownAPI && !init.signal && typeof AbortController !== 'undefined') {
      controller = new AbortController();
      init = Object.assign({}, init, { signal: controller.signal });
      timer = setTimeout(function() { controller.abort(); }, 15000);
    }
    return nativeFetch(input, init).then(function(res) {
      var url = res.url || (typeof input === 'string' ? input : (input && input.url));
      if (isSessionExpiredResponse(res.status, url)) {
        handleSessionExpired();
      }
      return res;
    }).catch(function(err) {
      if (controller && controller.signal.aborted) {
        throw new Error(t('operations.request_timeout', 'The request timed out. A change already submitted may still be running.'));
      }
      throw err;
    }).finally(function() {
      if (timer) clearTimeout(timer);
    });
  };
}

// =========================================================================
//  Shared Settings
// =========================================================================

// Always fetches fresh: settings are never cached client-side (owner decision 2026-07-25).
function getSettings() {
  return fetch(appPath('/api/settings')).then(readJsonResponse);
}

// =========================================================================
//  Lazy Script Loading
// =========================================================================

var scriptLoads = {};

// Loads a script once; a failed load is forgotten so the next call retries.
function loadScriptOnce(url) {
  if (scriptLoads[url]) {
    return scriptLoads[url];
  }
  scriptLoads[url] = new Promise(function(resolve, reject) {
    var script = document.createElement('script');
    script.src = url;
    script.async = true;
    script.onload = function() { resolve(); };
    script.onerror = function() {
      script.remove();
      delete scriptLoads[url];
      reject(new Error('Failed to load ' + url));
    };
    document.head.appendChild(script);
  });
  return scriptLoads[url];
}
