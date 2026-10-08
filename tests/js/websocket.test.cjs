'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function harness() {
  class Socket {
    static OPEN = 1;
    constructor() { this.readyState = 0; }
    open() { this.readyState = Socket.OPEN; this.onopen(); }
    close() { this.readyState = 3; this.onclose(); }
    receive(message) { this.onmessage({ data: JSON.stringify(message) }); }
  }
  const context = vm.createContext({
    window: { location: { protocol: 'https:', host: 'example.test' } },
    appPath: value => '/dev' + value,
    WebSocket: Socket,
    probeSession() {},
    setTimeout() { return 1; }, clearTimeout() {}, console
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../../pkg/web/static/js/websocket.js'), 'utf8'), context);
  const manager = vm.runInContext('new WebSocketManager()', context);
  const events = [];
  manager.on('ban_event', event => events.push(event));
  return { manager, events };
}

test('ban and unban events arrive once even when server callbacks are interleaved out of order', () => {
  const { manager, events } = harness();
  const newer = { id: 104, serverId: 'a', eventType: 'ban', ip: '192.0.2.1', jail: 'sshd' };
  const earlier = { id: 102, serverId: 'b', eventType: 'unban', ip: '192.0.2.1', jail: 'sshd' };
  const middle = { id: 103, serverId: 'a', eventType: 'unban', ip: '192.0.2.1', jail: 'sshd' };
  for (const event of [newer, earlier, newer, middle, earlier]) {
    manager.handleMessage({ type: event.eventType === 'unban' ? 'unban_event' : 'ban_event', data: event });
  }
  manager.handleBanEvent({ ...newer, id: '104' });
  assert.deepEqual(events, [newer, earlier, middle]);
});

test('seeding REST events suppresses only those exact IDs, not lower unseen live events', () => {
  const { manager, events } = harness();
  manager.rememberBanEvent({ id: 203 });
  manager.rememberBanEvent({ id: 201 });
  manager.handleBanEvent({ id: 201 });
  manager.handleBanEvent({ id: 202 });
  manager.handleBanEvent({ id: 203 });
  assert.deepEqual(events.map(event => event.id), [202]);
});

test('events without IDs remain visible and missing payloads are ignored', () => {
  const { manager, events } = harness();
  const event = { serverId: 'a', eventType: 'unban', ip: '192.0.2.1', jail: 'sshd' };
  manager.handleBanEvent(event);
  manager.handleBanEvent(event);
  manager.handleBanEvent(null);
  manager.handleBanEvent(undefined);
  assert.deepEqual(events, [event, event]);
});

test('reconnecting retains recent event identities without dropping new lower IDs', () => {
  const { manager, events } = harness();
  manager.connect();
  manager.ws.open();
  manager.ws.receive({ type: 'ban_event', data: { id: 20 } });
  manager.ws.close();
  manager.connect();
  manager.ws.open();
  manager.ws.receive({ type: 'ban_event', data: { id: 20 } });
  manager.ws.receive({ type: 'unban_event', data: { id: 19 } });
  assert.deepEqual(events.map(event => event.id), [20, 19]);
});

test('long-lived dashboards bound remembered IDs while retaining recent duplicate protection', () => {
  const { manager, events } = harness();
  for (let id = 1; id <= 4200; id++) manager.handleBanEvent({ id });
  manager.handleBanEvent({ id: 4199 });
  manager.handleBanEvent({ id: 4200 });
  assert.equal(events.length, 4200);
  assert.equal(manager.seenBanEventIds.size, 4096);
  manager.handleBanEvent({ id: 1 });
  assert.equal(events.length, 4201, 'an evicted ID is no longer retained indefinitely');
  assert.equal(manager.seenBanEventIds.size, 4096);
});
