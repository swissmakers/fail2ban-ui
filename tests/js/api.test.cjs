'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const filename = path.join(__dirname, '../../pkg/web/static/js/api.js');
const source = fs.readFileSync(filename, 'utf8');

function createHarness({ basePath = '', version = 'v1.2.3-abc', fetchStatus = 200 } = {}) {
  const appended = [];
  const expired = [];
  const window = {
    __BASE_PATH__: basePath,
    location: new URL('https://ui.example.com/'),
    fetch: async (input) => ({ status: fetchStatus, url: new URL(input, 'https://ui.example.com/').href })
  };
  const context = vm.createContext({
    URL,
    window,
    currentServerId: null,
    handleSessionExpired: () => expired.push(true),
    document: {
      documentElement: { getAttribute: name => (name === 'data-asset-version' ? version : null) },
      createElement: () => ({ removed: false, remove() { this.removed = true; } }),
      head: { appendChild: el => appended.push(el) }
    }
  });
  vm.runInContext(source, context, { filename });
  return { context, window, appended, expired };
}

const sessionCases = [
  ['same-origin API 401', 401, 'https://ui.example.com/api/summary', '', true],
  ['relative API 401', 401, '/api/servers', '', true],
  ['API 401 under base path', 401, 'https://ui.example.com/f2b/api/settings', '/f2b', true],
  ['API path outside the base path', 401, 'https://ui.example.com/api/settings', '/f2b', false],
  ['API 403 is an authorization error, not expiry', 403, '/api/settings', '', false],
  ['API 500', 500, '/api/settings', '', false],
  ['auth status 401', 401, '/auth/status', '', false],
  ['other origin 401', 401, 'https://ip.swissmakers.ch/api/ip', '', false],
  ['path merely starting with api', 401, '/apiary', '', false],
  ['missing url', 401, '', '', false]
];

for (const [name, status, url, basePath, expected] of sessionCases) {
  test('isSessionExpiredResponse: ' + name, () => {
    const { context } = createHarness({ basePath });
    assert.equal(context.isSessionExpiredResponse(status, url), expected);
  });
}

test('fetch wrapper reports an expired session once per 401 API response', async () => {
  const h = createHarness({ fetchStatus: 401 });
  const res = await h.window.fetch('/api/summary');
  assert.equal(res.status, 401);
  assert.equal(h.expired.length, 1);
  await h.window.fetch('/auth/status');
  assert.equal(h.expired.length, 1);
});

test('fetch wrapper ignores successful responses', async () => {
  const h = createHarness({ fetchStatus: 200 });
  await h.window.fetch('/api/summary');
  assert.equal(h.expired.length, 0);
});

const assetCases = [
  ['version and no base path', '', 'v1.2.3-abc', '/static/vendor/echarts/echarts.min.js', '/static/vendor/echarts/echarts.min.js?v=v1.2.3-abc'],
  ['version is URL-encoded', '', '1.0 beta', '/locales/en.json', '/locales/en.json?v=1.0%20beta'],
  ['base path prefix', '/f2b', '7', '/locales/de.json', '/f2b/locales/de.json?v=7'],
  ['missing leading slash', '', '7', 'static/images/earth-dark.jpg', '/static/images/earth-dark.jpg?v=7'],
  ['no version attribute', '', null, '/locales/en.json', '/locales/en.json']
];

for (const [name, basePath, version, input, expected] of assetCases) {
  test('assetUrl: ' + name, () => {
    const { context } = createHarness({ basePath, version });
    assert.equal(context.assetUrl(input), expected);
  });
}

test('loadScriptOnce appends one script and shares the promise', async () => {
  const h = createHarness();
  const first = h.context.loadScriptOnce('/static/vendor/a.js');
  const second = h.context.loadScriptOnce('/static/vendor/a.js');
  assert.equal(first, second);
  assert.equal(h.appended.length, 1);
  assert.equal(h.appended[0].src, '/static/vendor/a.js');
  h.appended[0].onload();
  await first;
  await h.context.loadScriptOnce('/static/vendor/a.js');
  assert.equal(h.appended.length, 1);
});

test('loadScriptOnce forgets a failed load so the next call retries', async () => {
  const h = createHarness();
  const failed = h.context.loadScriptOnce('/static/vendor/b.js');
  h.appended[0].onerror();
  await assert.rejects(failed, /Failed to load \/static\/vendor\/b\.js/);
  assert.equal(h.appended[0].removed, true);
  const retry = h.context.loadScriptOnce('/static/vendor/b.js');
  assert.notEqual(retry, failed);
  assert.equal(h.appended.length, 2);
  h.appended[1].onload();
  await retry;
});

test('loadScriptOnce keeps separate entries per URL', () => {
  const h = createHarness();
  h.context.loadScriptOnce('/static/vendor/a.js');
  h.context.loadScriptOnce('/static/vendor/b.js');
  assert.deepEqual(h.appended.map(el => el.src), ['/static/vendor/a.js', '/static/vendor/b.js']);
});

test('API request deadlines abort the HTTP wait without retrying a mutation', async () => {
  let timeout, calls = 0, captured;
  const window = {
    __BASE_PATH__: '', location: new URL('https://ui.example.com/'),
    fetch: (url, options) => {
      calls++;
      captured = options;
      return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(new Error('aborted'))));
    }
  };
  const context = vm.createContext({
    URL, Headers, AbortController, window, crypto: { randomUUID: () => 'request-id-1' },
    setTimeout: (callback, delay) => { assert.equal(delay, 15000); timeout = callback; return 1; }, clearTimeout() {},
    t: (key, fallback) => fallback, handleSessionExpired() {}, currentServerId: null
  });
  vm.runInContext(source, context, { filename });
  const pending = window.fetch('/api/jails/manage', { method: 'POST', body: '{"sshd":false}' });
  const rejected = assert.rejects(pending, /A change already submitted may still be running/);
  assert.equal(captured.headers.get('Idempotency-Key'), 'request-id-1');
  timeout();
  await rejected;
  assert.equal(calls, 1, 'the UI must never automatically replay an uncertain mutation');
});

test('an explicit idempotency key is preserved', async () => {
  let captured;
  const window = { __BASE_PATH__: '', location: new URL('https://ui.example.com/'), fetch: async (url, init) => { captured = init; return { status: 202 }; } };
  const context = vm.createContext({ URL, Headers, window, currentServerId: null, handleSessionExpired() {} });
  vm.runInContext(source, context, { filename });
  await window.fetch('/api/jails/manage', { method: 'POST', headers: { 'Idempotency-Key': 'retry-same-intent' } });
  assert.equal(captured.headers.get('Idempotency-Key'), 'retry-same-intent');
});
