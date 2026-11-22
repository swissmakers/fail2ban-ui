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

test('a stored ban action the list does not offer asks before it is replaced', async () => {
  const h = harness({});
  const stored = { banaction: 'nftables-multiport[blocktype=drop]', banactionAllports: '', chain: 'f2b-chain' };
  vm.runInContext('loadedJailActionSettings = jailActionSettings(' + JSON.stringify(stored) + ')', h.context);
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(h.confirms.length, 1, 'blank dropdowns would replace the stored action and chain');
});

test('blank ban action fields equal the loaded defaults and do not ask', async () => {
  const h = withLoadedActions(harness({}), { banaction: '', banactionAllports: '', chain: '' });
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(h.confirms.length, 0);
  assert.equal(h.requests.length, 1);
});

test('empty ban action settings mean the defaults', () => {
  const h = harness({});
  const defaults = h.context.jailActionSettings({});
  assert.deepEqual({ ...defaults }, loadedActions);
  assert.equal(h.context.jailActionSettingsChanged(defaults, h.context.jailActionSettings({ banaction: '', chain: 'INPUT' })), false);
});

test('a stored value missing from a dropdown stays selectable', () => {
  const h = harness({});
  const select = h.context.document.getElementById('banaction');
  select.options = [{ value: 'nftables-multiport' }];
  select.appendChild = option => select.options.push(option);
  h.context.document.createElement = () => ({});
  h.context.setSelectValue('banaction', 'nftables-multiport[blocktype=drop]');
  assert.deepEqual(select.options.map(o => o.value), ['nftables-multiport', 'nftables-multiport[blocktype=drop]']);
  assert.equal(select.value, 'nftables-multiport[blocktype=drop]');
  h.context.setSelectValue('banaction', 'nftables-multiport');
  assert.equal(select.options.length, 2, 'a listed value must not be added again');
});

test('the active settings section is the last one above the sticky bar', () => {
  const h = harness({});
  const sections = [{ id: 'a', top: -900 }, { id: 'b', top: 40 }, { id: 'c', top: 700 }];
  assert.equal(h.context.activeSettingsSection(sections, 80), 'b');
  assert.equal(h.context.activeSettingsSection(sections, 20), 'a');
  assert.equal(h.context.activeSettingsSection([{ id: 'a', top: 300 }, { id: 'b', top: 900 }], 80), 'a', 'the first section is active at the top of the page');
  assert.equal(h.context.activeSettingsSection([], 80), '');
});

test('the unsaved hint shows after a change and hides after a successful save', async () => {
  const h = harness({});
  const classes = new Set(['hidden']);
  h.context.document.getElementById('settingsUnsavedHint').classList = {
    toggle: (name, on) => { if (on) classes.add(name); else classes.delete(name); }
  };
  h.context.setSettingsDirty(true);
  assert.equal(classes.has('hidden'), false);
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(classes.has('hidden'), true);
});

test('a failed save keeps the unsaved hint', async () => {
  const h = harness({ error: 'Could not save settings' }, 500);
  const classes = new Set();
  h.context.document.getElementById('settingsUnsavedHint').classList = {
    toggle: (name, on) => { if (on) classes.add(name); else classes.delete(name); }
  };
  h.context.setSettingsDirty(true);
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(classes.has('hidden'), false);
});

test('the threshold is only editable while automatic blocking is on', () => {
  const h = harness({});
  const doc = h.context.document;
  const dimmed = new Set();
  doc.getElementById('advancedThresholdField').classList = {
    toggle: (name, on) => { if (on) dimmed.add(name); else dimmed.delete(name); }
  };
  doc.getElementById('advancedActionsEnabled').checked = false;
  h.context.updateAdvancedActionsState();
  assert.equal(doc.getElementById('advancedThreshold').disabled, true);
  assert.equal(dimmed.has('opacity-50'), true);
  assert.notEqual(doc.getElementById('advancedIntegrationSelect').disabled, true, 'manual blocks still need the integration');
  doc.getElementById('advancedActionsEnabled').checked = true;
  h.context.updateAdvancedActionsState();
  assert.equal(doc.getElementById('advancedThreshold').disabled, false);
  assert.equal(dimmed.has('opacity-50'), false);
});

test('every checkbox in the page template has the same size', () => {
  const html = fs.readFileSync(path.join(__dirname, '../../pkg/web/templates/index.html'), 'utf8');
  const boxes = html.match(/<input type="checkbox"[^>]*>/g);
  assert.ok(boxes.length >= 18);
  for (const box of boxes) {
    assert.match(box, /class="h-4 w-4 shrink-0 rounded border-gray-300 text-blue-600 accent-blue-600[ "]/, box);
  }
});

function withDefaultJailEnable(h, loaded, checked) {
  vm.runInContext('loadedDefaultJailEnable = ' + JSON.stringify(loaded), h.context);
  h.context.document.getElementById('defaultJailEnable').checked = checked;
  return h;
}

test('switching Enable Jails by Default on asks first and saves when confirmed', async () => {
  const h = withDefaultJailEnable(harness({}), false, true);
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(h.confirms.length, 1);
  assert.equal(JSON.parse(h.requests[0].options.body).defaultJailEnable, true);
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(h.confirms.length, 1, 'a saved choice must not ask again');
});

test('a cancelled Enable Jails by Default sends nothing', async () => {
  const h = withDefaultJailEnable(harness({}, 200, false), false, true);
  await h.context.saveSettings({ preventDefault() {} });
  assert.equal(h.confirms.length, 1);
  assert.equal(h.requests.length, 0);
  assert.deepEqual(h.loading, []);
});

test('Enable Jails by Default asks only when it is switched on', () => {
  const h = harness({});
  const cases = [
    [false, true, true],
    [null, true, true],
    [true, true, false],
    [true, false, false],
    [false, false, false]
  ];
  for (const [loaded, current, want] of cases) {
    assert.equal(h.context.defaultJailEnableTurnedOn(loaded, current), want, loaded + '/' + current);
  }
});
