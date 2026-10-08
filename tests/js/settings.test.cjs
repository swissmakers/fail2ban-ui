'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function harness(body, status = 200) {
  const toasts = [], loading = [], requests = [];
  let serverRefreshes = 0;
  const fields = {};
  const context = vm.createContext({
    console: { warn() {} }, translations: {},
    document: { getElementById(id) {
      return fields[id] || (fields[id] = {
        value: id === 'smtpPort' ? '25' : '', checked: false, selectedOptions: [], addEventListener() {}
      });
    } },
    $: () => ({ val: () => 'en' }),
    validateAllSettings: () => true,
    getIgnoreIPsArray: () => [],
    loadTranslations() {}, checkAndApplyLOTRTheme() {},
    showLoading: value => loading.push(value),
    showToast: (message, type, duration) => toasts.push({ message, type, duration }),
    appPath: value => value,
    fetch: async (url, options) => {
      requests.push({ url, options });
      return { ok: status < 400, status, json: async () => body };
    },
    loadServers: async () => { serverRefreshes++; }
  });
  for (const file of ['utils.js', 'settings.js']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../../pkg/web/static/js', file), 'utf8'), context);
  }
  return { context, toasts, loading, requests, serverRefreshes: () => serverRefreshes };
}

for (const [name, flags] of [
  ['sync queued', { syncPending: true, restartNeeded: false }],
  ['files written while reload is still running', { syncPending: false, restartNeeded: true }],
  ['servers at different sync phases', { syncPending: true, restartNeeded: true }],
  ['no sync outstanding', { syncPending: false, restartNeeded: false }]
]) {
  test('saving settings confirms persistence without claiming a sync outcome: ' + name, async () => {
    const h = harness(flags);
    await h.context.saveSettings({ preventDefault() {} });
    assert.equal(h.requests[0].url, '/api/settings');
    assert.equal(h.requests[0].options.method, 'POST');
    assert.deepEqual(h.toasts, [{ message: 'Settings saved', type: 'success', duration: 3000 }]);
    assert.equal(h.serverRefreshes(), 1);
    assert.deepEqual(h.loading, [true, false]);
  });
}

test('actual settings warnings stay visible without an additional success toast', async () => {
  const h = harness({ syncPending: true, warnings: ['Unable to queue sync for server A'] });
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(h.toasts.length, 1);
  assert.equal(h.toasts[0].type, 'warning');
  assert.match(h.toasts[0].message, /Unable to queue sync for server A/);
  assert.equal(h.serverRefreshes(), 1);
});

test('a rejected settings update shows its error and does not report success', async () => {
  const h = harness({ error: 'Could not save settings' }, 500);
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(h.toasts.length, 1);
  assert.equal(h.toasts[0].type, 'error');
  assert.match(h.toasts[0].message, /Could not save settings/);
  assert.equal(h.serverRefreshes(), 0);
  assert.deepEqual(h.loading, [true, false]);
});
