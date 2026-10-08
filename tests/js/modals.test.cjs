'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const filename = path.join(__dirname, '../../pkg/web/static/js/modals.js');
const source = fs.readFileSync(filename, 'utf8');
const utilsFilename = path.join(__dirname, '../../pkg/web/static/js/utils.js');
const utilsSource = fs.readFileSync(utilsFilename, 'utf8');

function createHarness(responses, serverId = 'test-server') {
  const opened = [];
  const toasts = [];
  const loading = [];
  const requests = [];
  const listeners = [];
  const elements = {
    jailsList: { innerHTML: '' },
    newJailName: { value: 'old name' },
    newJailContent: { value: 'old config' },
    newJailFilter: { value: 'old filter', innerHTML: '' }
  };
  const context = vm.createContext({
    currentServerId: serverId,
    translations: {},
    showLoading: active => loading.push(active),
    showToast: (message, type) => toasts.push({ message, type }),
    t: (key, fallback) => fallback,
    withServerParam: url => url,
    serverHeaders: () => ({}),
    escapeHtml: value => String(value).replace(/[&<>"']/g, char => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[char]),
    escapeJs: value => value,
    document: {
      getElementById: id => elements[id],
      querySelectorAll: () => elements.jailsList.innerHTML.includes('<input')
        ? [{ addEventListener: (event, handler) => listeners.push({ event, handler }) }]
        : []
    },
    fetch: async url => {
      requests.push(url);
      const response = responses.shift();
      assert.ok(response, 'unexpected fetch: ' + url);
      return {
        ok: response.status >= 200 && response.status < 300,
        status: response.status,
        json: async () => {
          if (response.jsonError) throw new SyntaxError('invalid JSON');
          return response.body;
        }
      };
    }
  });
  vm.runInContext(utilsSource, context, { filename: utilsFilename });
  vm.runInContext(source, context, { filename });
  context.openModal = id => opened.push(id);
  return { context, elements, opened, toasts, loading, requests, listeners };
}

async function openManage(harness) {
  harness.context.openManageJailsModal();
  await new Promise(setImmediate);
}

for (const jails of [[], null]) {
  test('opens Manage Jails for ' + JSON.stringify(jails), async () => {
    const h = createHarness([{ status: 200, body: { jails } }]);
    await openManage(h);
    assert.deepEqual(h.opened, ['manageJailsModal']);
    assert.match(h.elements.jailsList.innerHTML, /No jails found for this server\./);
    assert.deepEqual(h.toasts, []);
    assert.deepEqual(h.loading, [true, false]);
  });
}

test('can open Create New Jail from an empty server', async () => {
  const h = createHarness([
    { status: 200, body: { jails: null } },
    { status: 200, body: { filters: [] } }
  ]);
  await openManage(h);
  assert.deepEqual(h.opened, ['manageJailsModal']);
  h.context.openCreateJailModal();
  await new Promise(setImmediate);
  assert.deepEqual(h.opened, ['manageJailsModal', 'createJailModal']);
  assert.equal(h.elements.newJailName.value, '');
  assert.equal(h.elements.newJailContent.value, '');
  assert.deepEqual(h.requests, ['/api/jails/manage', '/api/filters']);
});

test('populated lists still render jail controls', async () => {
  const h = createHarness([{ status: 200, body: { jails: [{ jailName: 'sshd', enabled: true }] } }]);
  await openManage(h);
  assert.deepEqual(h.opened, ['manageJailsModal']);
  assert.match(h.elements.jailsList.innerHTML, /sshd/);
  assert.match(h.elements.jailsList.innerHTML, /checked/);
  assert.doesNotMatch(h.elements.jailsList.innerHTML, /No jails found/);
  assert.equal(h.listeners.length, 1);
  assert.equal(h.listeners[0].event, 'change');
});

test('clears previous jail rows when the next list is empty', async () => {
  const h = createHarness([
    { status: 200, body: { jails: [{ jailName: 'sshd', enabled: false }] } },
    { status: 200, body: { jails: [] } }
  ]);
  await openManage(h);
  await openManage(h);
  assert.deepEqual(h.opened, ['manageJailsModal', 'manageJailsModal']);
  assert.doesNotMatch(h.elements.jailsList.innerHTML, /sshd|<input/);
  assert.match(h.elements.jailsList.innerHTML, /No jails found/);
});

for (const response of [
  { status: 500, body: { error: 'SSH connection refused' } },
  { status: 403, body: { error: 'Access denied', jails: [] } },
  { status: 502, jsonError: true },
  { status: 200, body: {} },
  { status: 200, body: null },
  { status: 200, body: { jails: 'unexpected' } }
]) {
  test('reports a load error for ' + JSON.stringify(response), async () => {
    const h = createHarness([response]);
    await openManage(h);
    assert.deepEqual(h.opened, []);
    assert.equal(h.toasts.length, 1);
    assert.equal(h.toasts[0].type, 'error');
    assert.match(h.toasts[0].message, /Error fetching jails/);
    if (response.body && response.body.error) {
      assert.ok(h.toasts[0].message.includes(response.body.error));
    }
    assert.doesNotMatch(h.elements.jailsList.innerHTML, /No jails found/);
    assert.deepEqual(h.loading, [true, false]);
  });
}

test('requires a selected server before requesting jails', async () => {
  const h = createHarness([], '');
  await openManage(h);
  assert.deepEqual(h.requests, []);
  assert.deepEqual(h.opened, []);
  assert.equal(h.toasts[0].type, 'info');
});

test('jail changes start immediately instead of sharing a debounce timer', async () => {
  const h = createHarness([{ status: 200, body: { jails: [{ jailName: 'sshd', enabled: false }] } }]);
  const calls = [];
  h.context.saveManageJailsSingle = checkbox => calls.push(checkbox);
  await openManage(h);
  assert.equal(h.listeners.length, 1);
  h.listeners[0].handler();
  assert.equal(calls.length, 1, 'the toggle must not wait on a timer another toggle can cancel');
});

test('jails still loading are not presented as an empty server', async () => {
  const h = createHarness([{ status: 200, body: { available: false, stale: true, jails: null } }]);
  await openManage(h);
  assert.match(h.elements.jailsList.innerHTML, /Loading jails…/);
  assert.doesNotMatch(h.elements.jailsList.innerHTML, /No jails found|snapshot|Activity/);
});

test('a failed initial jail read explains the connection problem', async () => {
  const h = createHarness([{ status: 200, body: { available: false, stale: true, staleReason: 'refresh_failed', jails: null } }]);
  await openManage(h);
  assert.match(h.elements.jailsList.innerHTML, /Unable to load jails\. Check the server connection\./);
  assert.doesNotMatch(h.elements.jailsList.innerHTML, /Loading jails|No jails found|snapshot|Activity/);
});
