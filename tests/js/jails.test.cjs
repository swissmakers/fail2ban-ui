'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function harness() {
  const requests = [], toasts = [];
  const notes = Object.fromEntries(['first', 'second'].map(name => [name, {
    textContent: '', hidden: true, classList: { toggle(className, hidden) { notes[name].hidden = hidden; } }
  }]));
  const checkbox = name => ({ checked: true, disabled: false, getAttribute: key => key === 'data-jail-name' ? name : null, setAttribute() {}, closest: () => ({ querySelector: () => ({ textContent: name }) }) });
  const first = checkbox('first'), second = checkbox('second');
  const context = vm.createContext({
    currentServerId: 'server-a', translations: {}, console, Date,
    setInterval: () => 1, clearInterval() {},
    document: { getElementById: id => notes[id.replace('jail-state-', '')] || null, querySelectorAll: () => [first, second] },
    fetch: (url, options) => new Promise((resolve, reject) => requests.push({ url, options, resolve: body => resolve({ ok: true, status: 200, json: async () => body }), reject })),
    showToast: (message, type) => toasts.push({ message, type }),
    loadServers: async () => {}, refreshData: async () => {},
    serverHeaders: () => ({ 'X-F2B-Server': context.currentServerId }),
    withServerParam: url => url + '?serverId=' + context.currentServerId
  });
  for (const file of ['utils.js', 'jails.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, '../../pkg/web/static/js', file), 'utf8'), context);
  return { context, first, second, notes, requests, toasts };
}

test('separate jails can queue while the first task is still running', async () => {
  const h = harness();
  const first = h.context.saveManageJailsSingle(h.first);
  assert.equal(h.requests.length, 1);
  assert.equal(h.first.disabled, true);
  assert.equal(h.second.disabled, false);
  assert.equal(h.notes.first.textContent, 'Enabling…');
  assert.equal(h.notes.first.hidden, false);
  assert.equal(h.notes.second.textContent, '');
  assert.equal(h.notes.second.hidden, true);
  const second = h.context.saveManageJailsSingle(h.second);
  assert.equal(h.requests.length, 2);
  assert.equal(h.second.disabled, true);
  h.requests[1].resolve({ message: 'Second done' });
  await second;
  assert.equal(h.first.disabled, true);
  assert.equal(h.second.disabled, false);
  h.requests[0].resolve({ message: 'First done' });
  await first;
  assert.equal(h.first.checked, true);
  assert.equal(h.first.disabled, false);
  assert.equal(h.notes.first.textContent, '');
  assert.equal(h.notes.first.hidden, true);
});

test('restored queued changes show a short row label without locking unrelated jails', () => {
  const h = harness();
  h.context.activeServerOperations = () => [{ state: 'queued', desiredStates: { first: false } }];
  h.context.latestSummary = { serverId: 'server-a', available: true, stale: true, jails: [{ jailName: 'first' }] };
  h.context.updateJailChangeProgress();
  assert.equal(h.first.checked, false);
  assert.equal(h.first.disabled, true);
  assert.equal(h.notes.first.textContent, 'Disabling…');
  assert.equal(h.second.disabled, false);
  assert.equal(h.notes.second.textContent, '');
});

test('failed request restores toggle and releases controls', async () => {
  const h = harness();
  const pending = h.context.saveManageJailsSingle(h.first);
  h.requests[0].reject(new Error('connection lost'));
  await new Promise(setImmediate);
  h.requests[1].resolve({ jails: [{ jailName: 'first', enabled: false }] });
  await pending;
  assert.equal(h.first.checked, false);
  assert.equal(h.second.disabled, false);
  assert.equal(h.toasts[0].type, 'error');
});

test('completed background jail changes do not also create generic success and warning toasts', async () => {
  const h = harness();
  const pending = h.context.saveManageJailsSingle(h.first);
  h.requests[0].resolve({ operationId: 'op-1', warning: 'Unrelated configuration was fixed.', disabledJails: ['first'] });
  await pending;
  assert.equal(h.first.checked, false);
  assert.equal(h.first.disabled, false);
  assert.deepEqual(h.toasts, []);
});

test('failed background changes reconcile the toggle without duplicating the operation error toast', async () => {
  const h = harness();
  const pending = h.context.saveManageJailsSingle(h.first);
  const error = new Error('Invalid configuration');
  error.operation = { id: 'op-1', state: 'failed' };
  h.requests[0].reject(error);
  await new Promise(setImmediate);
  h.requests[1].resolve({ jails: [{ jailName: 'first', enabled: false }] });
  await pending;
  assert.equal(h.first.checked, false);
  assert.equal(h.first.disabled, false);
  assert.deepEqual(h.toasts, []);
});

test('automatic disable rereads the original server after selection changes', async () => {
  const h = harness();
  const pending = h.context.saveManageJailsSingle(h.first);
  h.context.currentServerId = 'server-b';
  h.requests[0].resolve({ error: 'Invalid logpath', autoDisabled: true, enabledJails: ['first'] });
  await new Promise(setImmediate);
  assert.match(h.requests[1].url, /serverId=server-a$/);
  assert.equal(h.requests[1].options.headers['X-F2B-Server'], 'server-a');
  h.requests[1].resolve({ jails: [{ jailName: 'first', enabled: false }] });
  await pending;
  assert.equal(h.first.checked, false);
});
