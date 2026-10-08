'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const jsDir = path.join(__dirname, '../../pkg/web/static/js');
const context = vm.createContext({ translations: { 'servers.health.state.down': 'Nicht erreichbar' } });
for (const name of ['utils.js', 'servers.js']) {
  const filename = path.join(jsDir, name);
  vm.runInContext(fs.readFileSync(filename, 'utf8'), context, { filename });
}
const { serverHealthBadge, aggregateServerHealth, applyServerHealthUpdate } = context;
const plain = value => JSON.parse(JSON.stringify(value));

const badgeCases = [
  ['ok', { state: 'ok' }, { state: 'ok', dotClass: 'bg-green-500', textClass: 'text-green-600', label: 'Healthy' }],
  ['degraded', { state: 'degraded' }, { state: 'degraded', dotClass: 'bg-yellow-500', textClass: 'text-yellow-600', label: 'Degraded' }],
  ['down uses the translation', { state: 'down' }, { state: 'down', dotClass: 'bg-red-500', textClass: 'text-red-600', label: 'Nicht erreichbar' }],
  ['unknown', { state: 'unknown' }, { state: 'unknown', dotClass: 'bg-gray-400', textClass: 'text-gray-500', label: 'Unknown' }],
  ['busy', { state: 'busy' }, { state: 'busy', dotClass: 'bg-yellow-500', textClass: 'text-yellow-600', label: 'Busy applying changes' }],
  ['unexpected state renders as unknown', { state: 'exploded' }, { state: 'unknown', dotClass: 'bg-gray-400', textClass: 'text-gray-500', label: 'Unknown' }],
  ['prototype key is not a state', { state: 'toString' }, { state: 'unknown', dotClass: 'bg-gray-400', textClass: 'text-gray-500', label: 'Unknown' }],
  ['missing state', {}, { state: 'unknown', dotClass: 'bg-gray-400', textClass: 'text-gray-500', label: 'Unknown' }]
];

for (const [name, health, expected] of badgeCases) {
  test('serverHealthBadge: ' + name, () => {
    assert.deepEqual(plain(serverHealthBadge(health)), expected);
  });
}

test('serverHealthBadge: no health (disabled server) gives no badge', () => {
  assert.equal(serverHealthBadge(undefined), null);
  assert.equal(serverHealthBadge(null), null);
});

const server = (state, enabled = true) => ({ enabled, health: state === undefined ? undefined : { state } });

const aggregateCases = [
  ['no servers', [], { state: 'unknown', down: 0, degraded: 0, busy: 0 }],
  ['nothing checked yet', [server('unknown'), server('unknown')], { state: 'unknown', down: 0, degraded: 0, busy: 0 }],
  ['all ok', [server('ok'), server('ok')], { state: 'ok', down: 0, degraded: 0, busy: 0 }],
  ['ok beats unknown', [server('ok'), server('unknown')], { state: 'ok', down: 0, degraded: 0, busy: 0 }],
  ['degraded beats ok', [server('ok'), server('degraded')], { state: 'degraded', down: 0, degraded: 1, busy: 0 }],
  ['down beats degraded', [server('degraded'), server('down'), server('down')], { state: 'down', down: 2, degraded: 1, busy: 0 }],
  ['busy is separate from unavailable', [server('ok'), server('busy')], { state: 'busy', down: 0, degraded: 0, busy: 1 }],
  ['failure is not hidden by busy', [server('down'), server('busy')], { state: 'down', down: 1, degraded: 0, busy: 1 }],
  ['disabled servers are ignored', [server('down', false), server('ok')], { state: 'ok', down: 0, degraded: 0, busy: 0 }],
  ['servers without health are ignored', [server(undefined), server('degraded')], { state: 'degraded', down: 0, degraded: 1, busy: 0 }],
  ['null entries are ignored', [null, server('ok')], { state: 'ok', down: 0, degraded: 0, busy: 0 }]
];

for (const [name, servers, expected] of aggregateCases) {
  test('aggregateServerHealth: ' + name, () => {
    assert.deepEqual(plain(aggregateServerHealth(servers)), expected);
  });
}

test('aggregateServerHealth: missing list', () => {
  assert.deepEqual(plain(aggregateServerHealth(undefined)), { state: 'unknown', down: 0, degraded: 0, busy: 0 });
});

test('applyServerHealthUpdate patches state and time, keeps the details', () => {
  const servers = [
    { id: 'a', enabled: true, health: { state: 'ok', checkedAt: 't0', error: 'old', fail2banOk: true } },
    { id: 'b', enabled: true, health: { state: 'ok' } }
  ];
  const patched = applyServerHealthUpdate(servers, { serverId: 'a', state: 'down', checkedAt: 't1' });
  assert.equal(patched, servers[0]);
  assert.deepEqual(plain(servers[0].health), { state: 'down', checkedAt: 't1', error: 'old', fail2banOk: true });
  assert.deepEqual(plain(servers[1].health), { state: 'ok' });
});

test('applyServerHealthUpdate creates health for a server that had none', () => {
  const servers = [{ id: 'a', enabled: true }];
  applyServerHealthUpdate(servers, { serverId: 'a', state: 'ok', checkedAt: 't1' });
  assert.deepEqual(plain(servers[0].health), { state: 'ok', checkedAt: 't1' });
});

for (const [name, msg] of [
  ['unknown server', { serverId: 'zzz', state: 'down' }],
  ['missing server id', { state: 'down' }],
  ['missing message', null]
]) {
  test('applyServerHealthUpdate ignores ' + name, () => {
    const servers = [{ id: 'a', enabled: true, health: { state: 'ok' } }];
    assert.equal(applyServerHealthUpdate(servers, msg), null);
    assert.deepEqual(plain(servers[0].health), { state: 'ok' });
  });
}

function cardHarness(servers, expanded = []) {
  const list = {
    innerHTML: '',
    querySelectorAll: () => expanded.map(id => ({ getAttribute: () => id }))
  };
  const emptyState = { classList: { add() {}, remove() {} } };
  const context = vm.createContext({
    translations: {}, serversCache: servers,
    document: { getElementById: id => ({ serverManagerList: list, serverManagerListEmpty: emptyState }[id]) },
    escapeHtml: value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char])),
    formatDateTime: value => value || '',
    sortServersForDisplay: values => values,
    updateTranslations() {}
  });
  for (const name of ['utils.js', 'servers.js']) {
    vm.runInContext(fs.readFileSync(path.join(jsDir, name), 'utf8'), context);
  }
  return { context, list };
}

const sshHostKeyDiagnostic = 'remote fail2ban ping error: ssh host key for localhost has changed '
  + '(presented SHA256:newkey) (output: @@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! '
  + '</pre><img src=x onerror="bad()"> Host key verification failed.)';

test('changed SSH key has one actionable warning and escaped collapsed diagnostics', () => {
  const h = cardHarness([]);
  const html = h.context.renderServerHealthDetails({
    id: 'ssh', hostKeyError: true, hostKeyFingerprint: 'SHA256:new<key>',
    health: { state: 'down', error: sshHostKeyDiagnostic, fail2banOk: false, callbackOk: false, checkedAt: 'now' },
    configSync: { pending: true, error: sshHostKeyDiagnostic }
  });
  const visible = html.replace(/<details\b[^>]*>[\s\S]*?<\/details>/g, '');
  assert.equal((html.match(/SSH host key changed/g) || []).length, 1);
  assert.match(visible, /Connection blocked/);
  assert.match(visible, /Verify the new fingerprint on the server before accepting it/);
  assert.match(visible, /select-all break-all">SHA256:new&lt;key&gt;/);
  assert.doesNotMatch(visible, /@@@|remote fail2ban|not responding|cannot reach the callback|automatic retry/);
  assert.match(html, /<details[^>]*data-server-diagnostics="ssh">/);
  assert.doesNotMatch(html, /<details[^>]*\bopen\b|<img/);
  assert.match(html, /max-h-40 max-w-full overflow-y-auto whitespace-pre-wrap break-all/);
  assert.match(html, /&lt;\/pre&gt;&lt;img src=x onerror=&quot;bad\(\)&quot;&gt;/);
  assert.equal((html.match(/remote fail2ban ping error/g) || []).length, 1);
});

test('host-key health or sync errors are recognized before host-key metadata is refreshed', () => {
  for (const detail of [
    { health: { state: 'down', error: sshHostKeyDiagnostic, fail2banOk: false } },
    { health: { state: 'down', fail2banOk: false }, configSync: { pending: true, error: sshHostKeyDiagnostic } }
  ]) {
    const h = cardHarness([{ id: 'ssh', type: 'ssh', enabled: true, ...detail }]);
    h.context.renderServerManagerList();
    assert.match(h.list.innerHTML, /SSH host key changed/);
    assert.doesNotMatch(h.list.innerHTML, /Fail2ban is not responding|automatic retry|acceptHostKey\(/);
  }
});

test('unrelated Fail2ban and callback failures remain visible', () => {
  const h = cardHarness([]);
  const html = h.context.renderServerHealthDetails({
    health: { state: 'down', error: 'Connection refused', fail2banOk: false, callbackOk: false },
    configSync: { pending: true, error: 'Write failed' }
  });
  assert.match(html, /Connection refused/);
  assert.match(html, /Fail2ban is not responding/);
  assert.match(html, /cannot reach the callback URL/);
  assert.match(html, /automatic retry enabled: Write failed/);
  assert.doesNotMatch(html, /SSH host key changed/);
});

test('a newer successful connection supersedes an old host-key error while configuration retries', () => {
  const h = cardHarness([]);
  const server = {
    health: { state: 'ok', transportOk: true, fail2banOk: true, checkedAt: '2026-10-08T12:00:10Z' },
    configSync: { pending: true, lastAttempt: '2026-10-08T12:00:00Z', error: sshHostKeyDiagnostic }
  };
  assert.equal(h.context.serverHasSSHHostKeyError(server), false);
  const html = h.context.renderServerHealthDetails(server);
  assert.match(html, /Healthy/);
  assert.match(html, /Configuration pending/);
  assert.doesNotMatch(html, /Connection blocked|SSH host key changed|@@@|REMOTE HOST/);
  server.health = { ...server.health, state: 'busy', fail2banOk: false };
  assert.equal(h.context.serverHasSSHHostKeyError(server), false, 'a successful transport check also proves SSH trust was restored');
  server.health.checkedAt = '2026-10-08T11:59:59Z';
  assert.equal(h.context.serverHasSSHHostKeyError(server), true, 'older checks cannot dismiss a newer SSH failure');
  server.health.checkedAt = '2026-10-08T12:00:10Z';
  server.hostKeyError = 'changed again';
  assert.equal(h.context.serverHasSSHHostKeyError(server), true, 'a currently recorded key issue still blocks the connection');
});

test('server cards wrap fingerprints and keep all actions accessible without horizontal scrolling', () => {
  const h = cardHarness([{
    id: 'ssh', name: 'Test SSH', type: 'ssh', host: 'localhost', port: 2222, enabled: true,
    hostKeyError: true, hostKeyFingerprint: 'SHA256:' + 'x'.repeat(43),
    health: { state: 'down', error: sshHostKeyDiagnostic }
  }]);
  h.context.renderServerManagerList();
  const html = h.list.innerHTML;
  assert.match(html, /border border-gray-200 p-4 min-w-0 bg-gray-50/);
  assert.match(html, /flex flex-col gap-3 min-w-0/);
  assert.match(html, /flex flex-wrap items-center gap-x-4 gap-y-2/);
  assert.doesNotMatch(html, /overflow-x-auto/);
  for (const action of ['editServer', 'setServerEnabled', 'restartFail2banServer', 'acceptHostKey', 'testServerConnection', 'deleteServer']) {
    assert.match(html, new RegExp('onclick="' + action + '\\('));
  }
  assert.doesNotMatch(html, /makeDefaultServer\(|Set default/);
});

test('an opened diagnostics section remains open during background server refreshes', () => {
  const servers = [{ id: 'ssh', enabled: true, hostKeyError: true, health: { state: 'down', error: sshHostKeyDiagnostic } }];
  const h = cardHarness(servers, ['ssh']);
  h.context.renderServerManagerList();
  assert.match(h.list.innerHTML, /data-server-diagnostics="ssh" open>/);
  const fresh = cardHarness(servers);
  fresh.context.renderServerManagerList();
  assert.doesNotMatch(fresh.list.innerHTML, /data-server-diagnostics="ssh" open>/);
});

test('testing a changed SSH key shows one concise warning and refreshes its server details', async () => {
  const h = cardHarness([]);
  const toasts = [];
  let refreshed = 0;
  h.context.showToast = (...args) => toasts.push(args);
  h.context.showLoading = () => {};
  h.context.appPath = value => value;
  h.context.fetch = async () => ({ json: async () => ({ error: sshHostKeyDiagnostic }) });
  h.context.refreshServerHealth = async () => { refreshed++; };
  await h.context.testServerConnection('ssh');
  assert.equal(toasts.length, 1);
  assert.match(toasts[0][0], /SSH host key.*changed/);
  assert.match(toasts[0][0], /Verify the new fingerprint/);
  assert.doesNotMatch(toasts[0][0], /@@@|output:|remote fail2ban/);
  assert.equal(toasts[0][1], 'warning');
  assert.equal(refreshed, 1);
});

test('server save warnings do not duplicate a host-key failure as an action-file error', () => {
  const h = cardHarness([]);
  const toasts = [];
  h.context.showToast = (...args) => toasts.push(args);
  h.context.showServerResponseWarnings({ hostKeyError: true, actionFileWarning: sshHostKeyDiagnostic });
  assert.equal(toasts.length, 1);
  assert.match(toasts[0][0], /Verify the new fingerprint/);
  assert.doesNotMatch(toasts[0][0], /@@@/);
  toasts.length = 0;
  h.context.showServerResponseWarnings({ actionFileWarning: 'Write permission denied' });
  assert.equal(toasts.length, 1);
  assert.equal(toasts[0][0], 'Write permission denied');
  toasts.length = 0;
  h.context.showServerResponseWarnings({ hostKeyError: true, actionFileWarning: 'Write permission denied' });
  assert.equal(toasts.length, 2);
  assert.equal(toasts[0][0], 'Write permission denied');
});
