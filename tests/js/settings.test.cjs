'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function harness(body, status = 200, confirmAnswer = true) {
  const toasts = [], loading = [], requests = [], confirms = [];
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
    confirm: message => { confirms.push(message); return confirmAnswer; },
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
  return { context, toasts, loading, requests, confirms, serverRefreshes: () => serverRefreshes };
}

const loadedActions = { banaction: 'nftables-multiport', banactionAllports: 'nftables-allports', chain: 'INPUT' };

function withLoadedActions(h, current) {
  vm.runInContext('loadedJailActionSettings = ' + JSON.stringify(loadedActions), h.context);
  h.context.document.getElementById('banaction').value = current.banaction;
  h.context.document.getElementById('banactionAllports').value = current.banactionAllports;
  h.context.document.getElementById('defaultChain').value = current.chain;
  return h;
}

test('saving settings confirms persistence without claiming a sync outcome', async () => {
  const h = harness({ message: 'Settings updated' });
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(h.requests[0].url, '/api/settings');
  assert.equal(h.requests[0].options.method, 'POST');
  assert.deepEqual(h.toasts, [{ message: 'Settings saved', type: 'success', duration: 3000 }]);
  assert.equal(h.serverRefreshes(), 1);
  assert.deepEqual(h.loading, [true, false]);
});

for (const [name, current, changed] of [
  ['unchanged', loadedActions, false],
  ['banaction', { ...loadedActions, banaction: 'firewallcmd-rich-rules' }, true],
  ['allports', { ...loadedActions, banactionAllports: 'iptables-allports' }, true],
  ['chain', { ...loadedActions, chain: 'FORWARD' }, true]
]) {
  test('jailActionSettingsChanged detects a ' + name + ' change', () => {
    const { context } = harness({});
    assert.equal(context.jailActionSettingsChanged(loadedActions, current), changed);
  });
}

test('jailActionSettingsChanged stays quiet before settings were loaded', () => {
  const { context } = harness({});
  assert.equal(context.jailActionSettingsChanged(null, { ...loadedActions, banaction: 'x' }), false);
});

test('an unchanged ban action saves without asking', async () => {
  const h = withLoadedActions(harness({}), loadedActions);
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(h.confirms.length, 0);
  assert.equal(h.requests.length, 1);
});

test('a changed ban action asks first and saves when confirmed', async () => {
  const h = withLoadedActions(harness({}), { ...loadedActions, banaction: 'nftables-allports' });
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(h.confirms.length, 1);
  assert.equal(JSON.parse(h.requests[0].options.body).banaction, 'nftables-allports');
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(h.confirms.length, 1, 'a saved change must not ask again');
});

test('a cancelled ban action change sends nothing', async () => {
  const h = withLoadedActions(harness({}, 200, false), { ...loadedActions, chain: 'FORWARD' });
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(h.confirms.length, 1);
  assert.equal(h.requests.length, 0);
  assert.deepEqual(h.loading, []);
});

test('actual settings warnings stay visible without an additional success toast', async () => {
  const h = harness({ warnings: ['Unable to queue sync for server A'] });
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
