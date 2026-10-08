'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const jsDir = path.join(__dirname, '../../pkg/web/static/js');
const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const operation = (state = 'queued', extra = {}) => ({ id: 'op-1', serverId: 'a', kind: 'jail.manage', target: 'sshd', state, desiredStates: { sshd: false }, createdAt: '2026-10-06T10:00:00Z', updatedAt: '2026-10-06T10:00:00Z', ...extra });
function harness() {
  const requests = [], timers = [], events = {}, toasts = [];
  function element() {
    return {
      children: [], attrs: {}, markup: '', className: '', style: {}, listeners: {},
      classList: { add() {}, remove() {} },
      addEventListener(name, fn) { this.listeners[name] = fn; },
      querySelector() { return this.button || (this.button = element()); },
      get innerHTML() { return this.markup + this.children.map(child => child.innerHTML).join(''); },
      set innerHTML(value) { this.markup = value; this.children = []; },
      setAttribute(name, value) { this.attrs[name] = value; },
      appendChild(child) { this.children.push(child); child.parent = this; },
      remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); }
    };
  }
  const elements = { 'operation-toasts': element(), 'toast-container': element() };
  elements['toast-container'].appendChild(elements['operation-toasts']);
  const context = vm.createContext({
    console, Date, Set, URL, requestAnimationFrame: fn => fn(), translations: {}, currentServerId: 'a', serversCache: [{ id: 'a', name: 'Server A' }, { id: 'b', name: 'Server B' }],
    document: { getElementById: id => elements[id], querySelectorAll: () => [], createElement: element },
    setTimeout: (fn, delay) => { timers.push({ fn, delay }); return timers.length; }, clearTimeout: id => { if (timers[id - 1]) timers[id - 1].cancelled = true; }, setInterval: () => 1, clearInterval() {},
    fetch: (url, init) => new Promise((resolve, reject) => requests.push({ url, init, resolve: (data, status) => resolve(response(data, status)), reject })),
    appPath: url => url, hasAccess: () => true, loadServers: async () => {}, fetchSummaryData: async () => {}, scheduleRender() {},
    showToast: (...args) => toasts.push(args), wsManager: { on: (event, callback) => { events[event] = callback; } }
  });
  for (const file of ['utils.js', 'core.js', 'operations.js']) vm.runInContext(fs.readFileSync(path.join(jsDir, file), 'utf8'), context, { filename: file });
  return { context, requests, timers, events, elements, toasts };
}

test('202 acceptance never reports success before terminal state, even for a long operation', async () => {
  const h = harness();
  let completed = false;
  const result = h.context.readJsonResponse(response({ operation: operation() }, 202)).then(data => { completed = true; return data; });
  await new Promise(setImmediate);
  assert.equal(completed, false);
  assert.equal(h.elements['operation-toasts'].children.length, 1);
  h.context.receiveOperation(operation('running', { updatedAt: '2026-10-06T10:08:00Z', phase: 'applying' }));
  await new Promise(setImmediate);
  assert.equal(completed, false);
  assert.match(h.elements['operation-toasts'].innerHTML, /Removing existing bans/);
  h.context.receiveOperation(operation('reconciling', { updatedAt: '2026-10-06T10:09:00Z' }));
  await new Promise(setImmediate);
  assert.equal(completed, false);
  h.context.receiveOperation(operation('succeeded', { updatedAt: '2026-10-06T10:10:00Z', result: { message: 'Verified', disabledJails: ['sshd'] } }));
  assert.deepEqual(JSON.parse(JSON.stringify(await result)), { message: 'Verified', disabledJails: ['sshd'] });
});

test('reload restores active tasks and polling completes a task without WebSocket updates', async () => {
  const h = harness();
  h.context.initOperations();
  assert.equal(h.requests[0].url, '/api/operations');
  h.requests[0].resolve({ operations: [operation('running')] });
  await new Promise(setImmediate);
  assert.equal(h.elements['operation-toasts'].children.length, 1);
  assert.match(h.elements['operation-toasts'].innerHTML, /Server A/);
  const completed = h.context.waitForOperation(operation('running'));
  h.context.currentServerId = 'b';
  h.context.refreshOperations();
  // Switching servers never cancels the durable operation.
  assert.equal(h.requests[1].url, '/api/operations');
  h.requests[1].resolve({ operations: [operation('succeeded', { result: { message: 'Done' } })] });
  assert.equal((await completed).message, 'Done');
  assert.equal(h.context.currentServerId, 'b');
});

test('polling failure preserves running state and does not settle the mutation', async () => {
  const h = harness();
  let settled = false;
  const promise = h.context.waitForOperation(operation('running')).then(() => { settled = true; });
  const poll = h.context.refreshOperations();
  h.requests[0].reject(new Error('network disconnected'));
  await poll;
  assert.equal(settled, false);
  assert.equal(h.context.operationsById['op-1'].state, 'running');
  assert.match(h.elements['operation-toasts'].innerHTML, /Connection lost/);
  h.context.receiveOperation(operation('succeeded'));
  await promise;
});

test('failure retains configuration safety result and never resolves a success callback', async () => {
  const h = harness();
  const promise = h.context.waitForOperation(operation());
  const expected = assert.rejects(promise, error => error.message === 'Configuration invalid' && error.data.autoDisabled === true);
  h.context.receiveOperation(operation('failed', { error: 'Configuration invalid', result: { autoDisabled: true, enabledJails: ['sshd'] } }));
  await expected;
});

test('old poll responses and delayed acceptance cannot regress terminal state', async () => {
  const h = harness();
  h.context.receiveOperation(operation('succeeded', { updatedAt: '2026-10-06T10:01:00Z', result: { done: true } }));
  const result = await h.context.waitForOperation(operation('queued'));
  assert.equal(result.done, true);
  assert.equal(h.context.operationsById['op-1'].state, 'succeeded');
  h.context.receiveOperation(operation('running', { updatedAt: '2026-10-06T10:02:00Z' }));
  assert.equal(h.context.operationsById['op-1'].state, 'succeeded');
});

test('a partial operation list is reconciled through the individual endpoint', async () => {
  const h = harness();
  const result = h.context.waitForOperation(operation('running'));
  const poll = h.context.refreshOperations();
  h.requests[0].resolve({ operations: [] });
  await new Promise(setImmediate);
  assert.equal(h.requests[1].url, '/api/operations/op-1');
  h.requests[1].resolve({ operation: operation('succeeded', { result: { verified: true } }) });
  await poll;
  assert.equal((await result).verified, true);
});

test('queued cancellation respects support permissions and cannot cancel a running task', () => {
  const h = harness();
  h.context.hasAccess = level => level === 'support';
  assert.equal(h.context.operationCanCancel(operation('queued', { kind: 'jail.manage' })), false);
  assert.equal(h.context.operationCanCancel(operation('queued', { kind: 'jail.unban' })), true);
  assert.equal(h.context.operationCanCancel(operation('running', { kind: 'jail.unban' })), false);
});

test('operation text is escaped before rendering', () => {
  for (const [target, error, escapedTarget, escapedError] of [
    ['<img src=x>', '<script>unsafe</script>', '&lt;img src=x&gt;', '&lt;script&gt;unsafe&lt;/script&gt;'],
    ['<IMG src=x>', '<SCRIPT>unsafe</SCRIPT>', '&lt;IMG src=x&gt;', '&lt;SCRIPT&gt;unsafe&lt;/SCRIPT&gt;'],
    ['<ImG src="x">', '<ScRiPt type="text/javascript">unsafe</ScRiPt>', '&lt;ImG src=&quot;x&quot;&gt;', '&lt;ScRiPt type=&quot;text/javascript&quot;&gt;unsafe&lt;/ScRiPt&gt;']
  ]) {
    const h = harness();
    h.context.receiveOperation(operation('failed', { target, error }));
    const html = h.elements['operation-toasts'].innerHTML;
    assert.doesNotMatch(html, /<\/?(?:img|script)\b/i);
    assert.ok(html.includes(escapedTarget));
    assert.ok(html.includes(escapedError));
  }
});

test('elapsed time is labelled for active work and omitted for immediate or terminal results', () => {
  const h = harness();
  h.context.Date = class extends Date { static now() { return Date.parse('2026-10-06T10:01:05Z'); } };
  assert.equal(h.context.operationElapsed(operation('queued')), 'Elapsed: 1m 5s');
  assert.equal(h.context.operationElapsed(operation('running', { startedAt: '2026-10-06T10:01:03Z' })), 'Elapsed: 2s');
  assert.equal(h.context.operationElapsed(operation('reconciling')), 'Elapsed: 1m 5s');
  for (const createdAt of ['2026-10-06T10:01:04.900Z', '2026-10-06T10:02:00Z', 'invalid']) {
    assert.equal(h.context.operationElapsed(operation('queued', { createdAt })), '');
  }
  for (const state of ['succeeded', 'failed', 'cancelled']) {
    assert.equal(h.context.operationElapsed(operation(state)), '');
    h.context.receiveOperation(operation(state, { id: state }));
  }
  assert.doesNotMatch(h.elements['operation-toasts'].innerHTML, /data-operation-elapsed|0:00/);
  h.context.translations['operations.elapsed_minutes'] = '{minutes} min {seconds} sec passed';
  assert.equal(h.context.operationElapsed(operation('running')), '1 min 5 sec passed');
});

test('elapsed updates appear as work continues without rebuilding toast controls', () => {
  const h = harness();
  let now = Date.parse('2026-10-06T10:00:00Z');
  h.context.Date = class extends Date { static now() { return now; } };
  const clock = { getAttribute: () => 'op-1' };
  h.context.document.querySelectorAll = () => [clock];
  h.context.receiveOperation(operation('running'));
  assert.equal(clock.hidden, true);
  assert.equal(clock.textContent, '');
  const toast = h.elements['operation-toasts'].children[0];
  Object.defineProperty(toast, 'innerHTML', { set() { assert.fail('clock update replaced toast controls'); } });
  now += 61000;
  h.context.updateOperationElapsed();
  assert.equal(clock.hidden, false);
  assert.equal(clock.textContent, 'Elapsed: 1m 1s');
});

test('SSH trust failures use a concise toast and open server settings without accepting a key', async () => {
  const h = harness();
  let opened = 0;
  h.context.openServerManager = () => { opened++; };
  h.context.initOperations();
  h.requests[0].resolve({ operations: [] });
  await new Promise(setImmediate);
  const error = 'remote fail2ban ping error: ssh host key for localhost has changed (presented SHA256:new) (output: @ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @)';
  const promise = h.context.waitForOperation(operation('running', { kind: 'server.sync', target: '' }));
  const rejected = assert.rejects(promise, err => err.message === error);
  h.context.receiveOperation(operation('failed', { kind: 'server.sync', target: '', error }));
  await rejected;
  assert.match(h.elements['operation-toasts'].innerHTML, /SSH host key changed/);
  assert.match(h.elements['operation-toasts'].innerHTML, /data-operation-servers/);
  assert.doesNotMatch(h.elements['operation-toasts'].innerHTML, /REMOTE HOST IDENTIFICATION|SHA256:new|data-operation-elapsed/);
  h.elements['operation-toasts'].onclick({ target: { closest: selector => selector === '[data-operation-servers]' ? {} : null } });
  assert.equal(opened, 1);
  assert.equal(h.requests.length, 1, 'opening server settings must not send a trust or retry request');
  h.context.hasAccess = () => false;
  h.context.renderOperations();
  assert.doesNotMatch(h.elements['operation-toasts'].innerHTML, /data-operation-servers/);
  h.elements['operation-toasts'].onclick({ target: { closest: selector => selector === '[data-operation-servers]' ? {} : null } });
  assert.equal(opened, 1, 'only admins can open server settings');
});

test('active progress stays visible, then success disappears once after three seconds', () => {
  const h = harness();
  h.context.receiveOperation(operation('running'));
  assert.match(h.elements['operation-toasts'].innerHTML, /Disabling sshd/);
  assert.equal(h.timers.filter(timer => timer.delay === 3000).length, 0);
  h.context.dismissOperationToast('op-1');
  assert.equal(h.elements['operation-toasts'].children.length, 1, 'running progress cannot be dismissed accidentally');
  h.context.receiveOperation(operation('succeeded'));
  assert.match(h.elements['operation-toasts'].innerHTML, /sshd disabled/);
  assert.equal(h.timers.length, 1);
  assert.equal(h.timers[0].delay, 3000);
  h.context.receiveOperation(operation('succeeded'), { history: true });
  assert.equal(h.timers.length, 1, 'polling must not extend the completion toast');
  h.timers[0].fn();
  assert.equal(h.elements['operation-toasts'].children.length, 0);
  h.context.receiveOperation(operation('succeeded'));
  assert.equal(h.elements['operation-toasts'].children.length, 0, 'duplicate events cannot resurrect dismissed results');
});

test('reload restores active progress without replaying completed history', async () => {
  const h = harness();
  const refresh = h.context.refreshOperations();
  h.requests[0].resolve({ operations: [
    operation('succeeded', { id: 'old-success' }),
    operation('failed', { id: 'old-error', error: 'Old error' }),
    operation('running')
  ] });
  await refresh;
  assert.equal(h.elements['operation-toasts'].children.length, 1);
  assert.match(h.elements['operation-toasts'].innerHTML, /Disabling sshd/);
  assert.doesNotMatch(h.elements['operation-toasts'].innerHTML, /Old error/);
});

test('errors and safety warnings remain until dismissed', () => {
  const h = harness();
  h.context.receiveOperation(operation('failed', {
    error: 'Invalid logpath', result: { configurationRestored: true, message: 'Original configuration restored' }
  }));
  h.context.receiveOperation(operation('succeeded', {
    id: 'op-2', result: { disabledJails: ['broken-jail'], warning: 'Review configuration' }
  }));
  assert.equal(h.timers.length, 0);
  assert.match(h.elements['operation-toasts'].innerHTML, /Invalid logpath/);
  assert.match(h.elements['operation-toasts'].innerHTML, /Original configuration restored/);
  assert.match(h.elements['operation-toasts'].innerHTML, /broken-jail/);
  assert.match(h.elements['operation-toasts'].innerHTML, /Review configuration/);
  h.context.dismissOperationToast('op-1');
  assert.equal(h.elements['operation-toasts'].children.length, 1);
});

test('automatic disabling is reflected in the result title and safety warning', () => {
  const h = harness();
  h.context.receiveOperation(operation('succeeded', {
    desiredStates: { sshd: true }, result: { disabledJails: ['sshd'] }
  }));
  assert.match(h.elements['operation-toasts'].innerHTML, /sshd disabled/);
  assert.match(h.elements['operation-toasts'].innerHTML, /automatically disabled/);
  assert.doesNotMatch(h.elements['operation-toasts'].innerHTML, /sshd enabled|Unrelated/);
  h.context.receiveOperation(operation('succeeded', {
    id: 'op-2', kind: 'jail.config', result: { jailAutoDisabled: true, jailName: 'apache', warning: 'Reload failed' }
  }));
  assert.match(h.elements['operation-toasts'].innerHTML, /apache.*automatically disabled/);
  assert.equal(h.timers.length, 0);
});

test('a terminal update received before acceptance still produces one completion toast', async () => {
  const h = harness();
  h.context.receiveOperation(operation('succeeded'), { history: true });
  assert.equal(h.elements['operation-toasts'].children.length, 0);
  const result = await h.context.waitForOperation(operation('queued'));
  assert.equal(result.operationId, 'op-1', 'mutation handlers can suppress duplicate notifications');
  assert.equal(h.elements['operation-toasts'].children.length, 1);
  assert.match(h.elements['operation-toasts'].innerHTML, /sshd disabled/);
  assert.equal(h.timers.filter(timer => timer.delay === 3000).length, 1);
});

test('unchanged polls preserve the toast element and its controls', () => {
  const h = harness();
  h.context.receiveOperation(operation('queued'));
  const original = h.elements['operation-toasts'].children[0];
  Object.defineProperty(original, 'innerHTML', { set() { assert.fail('unchanged polling replaced controls'); } });
  h.context.receiveOperation(operation('queued', { updatedAt: '2026-10-06T10:00:01Z' }), { history: true });
  assert.equal(h.elements['operation-toasts'].children[0], original);
});

test('logout clears progress toasts and completion timers', () => {
  const h = harness();
  h.context.receiveOperation(operation('succeeded'));
  h.context.receiveOperation(operation('running', { id: 'op-2' }));
  h.context.stopOperations();
  assert.equal(h.elements['operation-toasts'].children.length, 0);
  assert.equal(h.timers[0].cancelled, true);
  assert.equal(Object.keys(h.context.operationsById).length, 0);
});

test('late polling and WebSocket updates cannot restore toasts after logout', async () => {
  const h = harness();
  h.context.initOperations();
  const poll = h.context.operationsRefreshPromise;
  h.context.stopOperations();
  h.requests[0].resolve({ operations: [operation('running')] });
  await poll;
  h.events.operation(operation('running'));
  h.events.reconnected();
  assert.equal(h.elements['operation-toasts'].children.length, 0);
  assert.equal(h.requests.length, 1);
  assert.equal(Object.keys(h.context.operationsById).length, 0);
});

test('delayed mutation acceptance cannot restore progress after session expiry', async () => {
  const h = harness();
  h.context.stopOperations();
  await assert.rejects(h.context.readJsonResponse(response({ operation: operation('queued') }, 202)), error => !!error.operation);
  await h.context.refreshOperations();
  assert.equal(h.elements['operation-toasts'].children.length, 0);
  assert.equal(h.requests.length, 0);
});

const unbanOperation = (state, extra = {}) => operation(state, {
  kind: 'jail.unban', target: 'sshd / 192.0.2.1', desiredStates: undefined,
  startedAt: '2026-10-06T10:00:00Z',
  finishedAt: state === 'succeeded' ? '2026-10-06T10:00:02Z' : undefined, ...extra
});
const unbanEvent = extra => ({ id: 101, serverId: 'a', serverName: 'Server A', jail: 'sshd',
  ip: '192.0.2.1', eventType: 'unban', country: 'TH', occurredAt: '2026-10-06T10:00:01Z', ...extra });
const visibleToasts = h => h.elements['operation-toasts'].children.concat(
  h.elements['toast-container'].children.filter(child => child !== h.elements['operation-toasts']));

test('background changes reuse existing toast variants without a separate visual style', () => {
  const h = harness();
  h.context.receiveOperation(operation('running'));
  assert.equal(visibleToasts(h)[0].className, 'toast toast-info show');
  h.context.receiveOperation(operation('succeeded'));
  assert.equal(visibleToasts(h)[0].className, 'toast toast-success show');
  h.context.receiveOperation(operation('failed', { id: 'failed' }));
  assert.equal(visibleToasts(h)[1].className, 'toast toast-error show');
});

test('an unban event updates the existing task toast without completing its pending request', async () => {
  const h = harness();
  let finished = false;
  const pending = h.context.waitForOperation(unbanOperation('running')).then(() => { finished = true; });
  const original = visibleToasts(h)[0];
  h.context.showBanEventToast(unbanEvent());
  await new Promise(setImmediate);
  assert.equal(finished, false);
  assert.equal(visibleToasts(h).length, 1);
  assert.equal(visibleToasts(h)[0], original);
  assert.equal(original.className, 'toast toast-info show');
  h.context.receiveOperation(unbanOperation('succeeded'));
  await pending;
  assert.equal(visibleToasts(h).length, 1);
  assert.equal(original.className, 'toast toast-unban-event show');
  assert.match(original.innerHTML, /IP unblocked/);
  assert.match(original.innerHTML, /192\.0\.2\.1/);
  assert.match(original.innerHTML, /Server A - TH/);
  assert.equal(h.timers.filter(timer => timer.delay === 3000).length, 1);
});

test('a live event arriving before task metadata is combined into one toast', () => {
  const h = harness();
  h.context.showBanEventToast(unbanEvent());
  assert.equal(visibleToasts(h).length, 1);
  h.context.receiveOperation(unbanOperation('running'));
  assert.equal(visibleToasts(h).length, 1);
  assert.equal(h.timers.find(timer => timer.delay === 5000).cancelled, true);
  h.context.receiveOperation(unbanOperation('succeeded'));
  assert.equal(visibleToasts(h).length, 1);
  assert.equal(visibleToasts(h)[0].className, 'toast toast-unban-event show');
  assert.match(visibleToasts(h)[0].innerHTML, /Server A - TH/);
});

test('late completion does not repeat an event toast that already disappeared', () => {
  const h = harness();
  h.context.showBanEventToast(unbanEvent());
  h.timers.find(timer => timer.delay === 5000).fn();
  h.timers.find(timer => timer.delay === 300).fn();
  assert.equal(visibleToasts(h).length, 0);
  h.context.receiveOperation(unbanOperation('succeeded'));
  assert.equal(visibleToasts(h).length, 0);
});

test('verified success uses the normal unban toast even if the live event is missed', () => {
  const h = harness();
  h.context.receiveOperation(unbanOperation('succeeded'));
  const original = visibleToasts(h)[0];
  assert.equal(original.className, 'toast toast-unban-event show');
  assert.match(original.innerHTML, /IP unblocked/);
  h.context.showBanEventToast(unbanEvent());
  assert.equal(visibleToasts(h).length, 1);
  assert.equal(visibleToasts(h)[0], original);
  assert.match(original.innerHTML, /Server A - TH/);
  assert.equal(h.timers.filter(timer => timer.delay === 3000).length, 1);
});

test('a delayed callback or duplicate event cannot replay a dismissed success toast', () => {
  const h = harness();
  h.context.receiveOperation(unbanOperation('succeeded'));
  h.timers.find(timer => timer.delay === 3000).fn();
  h.context.showBanEventToast(unbanEvent());
  h.context.showBanEventToast(unbanEvent());
  assert.equal(visibleToasts(h).length, 0);
});

test('ban operations use the same event toast and normalize IPv6 identities', () => {
  const h = harness();
  const changes = { kind: 'jail.ban', target: 'sshd / 2001:0DB8:0000:0000:0000:0000:0000:0001' };
  h.context.receiveOperation(unbanOperation('running', changes));
  h.context.showBanEventToast(unbanEvent({ ip: '2001:db8::1', eventType: 'ban' }));
  h.context.receiveOperation(unbanOperation('succeeded', changes));
  assert.equal(visibleToasts(h).length, 1);
  assert.equal(visibleToasts(h)[0].className, 'toast toast-ban-event show');
  assert.match(visibleToasts(h)[0].innerHTML, /New block occurred/);
});

test('CIDR requests and canonical daemon addresses share the same toast', () => {
  for (const [requested, actual] of [
    ['192.0.2.1/32', '192.0.2.1'], ['192.0.2.199/24', '192.0.2.0/24'],
    ['2001:0DB8:0000:0000:0000:0000:0000:0001/128', '2001:db8::1'],
    ['2001:db8:1234:5678::1/48', '2001:db8:1234::/48'],
    ['::ffff:192.0.2.1/128', '::ffff:c000:201']
  ]) {
    const h = harness();
    h.context.receiveOperation(unbanOperation('running', { target: 'sshd / ' + requested }));
    h.context.showBanEventToast(unbanEvent({ ip: actual }));
    assert.equal(visibleToasts(h).length, 1, requested);
  }
});

test('a queued change cannot steal the running action callback or an automatic event', () => {
  const h = harness();
  h.context.receiveOperation(unbanOperation('running'));
  h.context.receiveOperation(unbanOperation('queued', {
    id: 'next', startedAt: undefined, createdAt: '2026-10-06T10:00:00.500Z'
  }));
  h.context.showBanEventToast(unbanEvent());
  assert.equal(h.context.operationNotices['op-1'].banEvent.id, 101);
  assert.equal(h.context.operationNotices.next.banEvent, undefined);
  const queued = harness();
  queued.context.receiveOperation(unbanOperation('queued', { startedAt: undefined }));
  queued.context.showBanEventToast(unbanEvent());
  assert.equal(visibleToasts(queued).length, 2);
  queued.context.receiveOperation(unbanOperation('running', { startedAt: '2026-10-06T10:01:00Z' }));
  assert.equal(visibleToasts(queued).length, 2, 'an event before execution must remain independent');
});

test('events for another server, jail, IP, action or time remain independent', () => {
  for (const changes of [
    { serverId: 'b' }, { jail: 'apache' }, { ip: '192.0.2.2' }, { eventType: 'ban' },
    { occurredAt: '2026-10-06T09:59:00Z' }, { occurredAt: '2026-10-06T10:01:00Z' }
  ]) {
    const h = harness();
    h.context.receiveOperation(unbanOperation('succeeded'));
    h.context.showBanEventToast(unbanEvent(changes));
    assert.equal(visibleToasts(h).length, 2, JSON.stringify(changes));
  }
});

test('a distinct subsequent event is not swallowed by an already matched operation', () => {
  const h = harness();
  h.context.receiveOperation(unbanOperation('succeeded'));
  h.context.showBanEventToast(unbanEvent());
  h.context.showBanEventToast(unbanEvent({ id: 102, occurredAt: '2026-10-06T10:00:04Z' }));
  assert.equal(visibleToasts(h).length, 2);
});

test('a live unban followed by an operation failure keeps the error visible', () => {
  const h = harness();
  h.context.receiveOperation(unbanOperation('running'));
  h.context.showBanEventToast(unbanEvent());
  h.context.receiveOperation(unbanOperation('failed', { error: 'Verification failed' }));
  assert.equal(visibleToasts(h).length, 1);
  assert.equal(visibleToasts(h)[0].className, 'toast toast-error show');
  assert.match(visibleToasts(h)[0].innerHTML, /Verification failed/);
  assert.equal(h.timers.filter(timer => timer.delay === 3000).length, 0);
});
