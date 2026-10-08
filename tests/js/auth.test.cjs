'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function harness(skipLoginPage = false) {
  const calls = [];
  const context = vm.createContext({
    window: { location: { href: '/dev/' } },
    document: {
      body: { getAttribute: name => name === 'data-skip-login-page' ? String(skipLoginPage) : null },
      getElementById: () => null,
      querySelector: () => null,
      querySelectorAll: () => [],
      addEventListener() {}
    },
    appPath: value => '/dev' + value,
    stopOperations: () => calls.push('stop operations'),
    wsManager: { disconnect: () => calls.push('disconnect websocket') },
    showLoading: value => calls.push('loading ' + value)
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../../pkg/web/static/js/auth.js'), 'utf8'), context);
  vm.runInContext('authEnabled = true; isAuthenticated = true;', context);
  return { context, calls };
}

for (const skipLoginPage of [false, true]) {
  test('session expiry stops operation notices and polling before ' + (skipLoginPage ? 'redirecting' : 'showing login'), () => {
    const h = harness(skipLoginPage);
    h.context.handleSessionExpired();
    assert.deepEqual(h.calls, ['stop operations', 'disconnect websocket', 'loading false']);
    assert.equal(vm.runInContext('isAuthenticated', h.context), false);
    assert.equal(h.context.window.location.href, skipLoginPage ? '/dev/auth/login' : '/dev/');
    h.context.handleSessionExpired();
    assert.equal(h.calls.length, 3, 'repeat unauthorized responses must not repeat session teardown');
  });
}

test('session-expiry handler does not stop an application with authentication disabled', () => {
  const h = harness();
  vm.runInContext('authEnabled = false;', h.context);
  h.context.handleSessionExpired();
  assert.deepEqual(h.calls, []);
});
