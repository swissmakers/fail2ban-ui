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
  ['no servers', [], { state: 'unknown', down: 0, degraded: 0 }],
  ['nothing checked yet', [server('unknown'), server('unknown')], { state: 'unknown', down: 0, degraded: 0 }],
  ['all ok', [server('ok'), server('ok')], { state: 'ok', down: 0, degraded: 0 }],
  ['ok beats unknown', [server('ok'), server('unknown')], { state: 'ok', down: 0, degraded: 0 }],
  ['degraded beats ok', [server('ok'), server('degraded')], { state: 'degraded', down: 0, degraded: 1 }],
  ['down beats degraded', [server('degraded'), server('down'), server('down')], { state: 'down', down: 2, degraded: 1 }],
  ['disabled servers are ignored', [server('down', false), server('ok')], { state: 'ok', down: 0, degraded: 0 }],
  ['servers without health are ignored', [server(undefined), server('degraded')], { state: 'degraded', down: 0, degraded: 1 }],
  ['null entries are ignored', [null, server('ok')], { state: 'ok', down: 0, degraded: 0 }]
];

for (const [name, servers, expected] of aggregateCases) {
  test('aggregateServerHealth: ' + name, () => {
    assert.deepEqual(plain(aggregateServerHealth(servers)), expected);
  });
}

test('aggregateServerHealth: missing list', () => {
  assert.deepEqual(plain(aggregateServerHealth(undefined)), { state: 'unknown', down: 0, degraded: 0 });
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
