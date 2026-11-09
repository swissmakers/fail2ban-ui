'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const filename = path.join(__dirname, '../../pkg/web/static/js/core.js');
const context = vm.createContext({});
vm.runInContext(fs.readFileSync(filename, 'utf8'), context, { filename });
const { escapeJs } = context;

const values = [
  ['double quote', 'a"b'],
  ['single quote', "it's"],
  ['script tag', '</script>'],
  ['backslash', 'x\\y'],
  ['newline', 'l1\nl2'],
  ['html entity', '&quot;'],
  ['line separator', 'a b'],
];

for (const [name, value] of values) {
  test(`escapeJs keeps ${name} inside a single-quoted literal in a double-quoted attribute`, () => {
    const escaped = escapeJs(value);
    assert.ok(!/["<>&\n]/.test(escaped), `escaped value ${escaped} could end the attribute or tag`);
    assert.equal(vm.runInNewContext(`'${escaped}'`), value);
  });
}

const { banToastBurst } = context;
const unblock = (serverId, jail) => ({ serverId, jail, eventType: 'unban' });

test('banToastBurst keeps single toasts up to the threshold, then summarizes', () => {
  const state = {};
  for (let i = 0; i < 3; i++) {
    assert.equal(banToastBurst(state, unblock('local', 'sshd'), 1000 + i).summary, false);
  }
  const burst = banToastBurst(state, unblock('local', 'nginx'), 1003);
  assert.equal(burst.summary, true);
  assert.equal(burst.count, 4);
  assert.deepEqual(Array.from(burst.jails), ['sshd', 'nginx']);
});

test('banToastBurst counts each server and event type on its own', () => {
  const state = {};
  for (let i = 0; i < 3; i++) banToastBurst(state, unblock('local', 'sshd'), i);
  assert.equal(banToastBurst(state, unblock('remote', 'sshd'), 4).summary, false);
  assert.equal(banToastBurst(state, { serverId: 'local', jail: 'sshd', eventType: 'ban' }, 5).summary, false);
  assert.equal(banToastBurst(state, unblock('local', 'sshd'), 6).summary, true);
});

test('banToastBurst stays a summary while events keep coming and resets after a quiet window', () => {
  const state = {};
  for (let i = 0; i < 4; i++) banToastBurst(state, unblock('local', 'sshd'), i);
  assert.equal(banToastBurst(state, unblock('local', 'sshd'), 9000).summary, true);
  assert.equal(banToastBurst(state, unblock('local', 'sshd'), 18000).summary, true, 'a slow trickle must not fall back to single toasts mid-burst');
  const fresh = banToastBurst(state, unblock('local', 'sshd'), 28001);
  assert.equal(fresh.summary, false);
  assert.equal(fresh.count, 1);
});
