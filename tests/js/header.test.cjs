'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function harness() {
  let opened = 0;
  let admin = true;
  const elements = Object.fromEntries(['statusDot', 'statusText', 'backendStatus'].map(id => [id, {
    textContent: '', attributes: {}, classes: new Set(),
    setAttribute(name, value) { this.attributes[name] = value; }
  }]));
  for (const el of Object.values(elements)) el.classList = {
    add: name => el.classes.add(name), remove: (...names) => names.forEach(name => el.classes.delete(name)),
    toggle: (name, enabled) => enabled ? el.classes.add(name) : el.classes.delete(name)
  };
  const context = vm.createContext({
    translations: {}, serversCache: [], wsManager: { state: 'connected' },
    hasAccess: level => admin && level === 'admin', openServerManager: () => opened++,
    escapeHtml: value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char])),
    document: { getElementById: id => elements[id] }
  });
  for (const file of ['utils.js', 'servers.js', 'header.js']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../../pkg/web/static/js', file), 'utf8'), context);
  }
  return { context, elements, opened: () => opened, setAdmin: value => { admin = value; } };
}

test('unhealthy header opens server manager only for admins; healthy header stays passive', () => {
  const h = harness();
  h.context.serversCache = [{ id: 'a', enabled: true, health: { state: 'ok' } }];
  h.context.updateStatusIndicator();
  h.context.openHeaderServerProblems();
  assert.equal(h.opened(), 0);
  assert.equal(h.elements.backendStatus.attributes.role, 'status');
  h.context.serversCache[0].health.state = 'down';
  h.context.updateStatusIndicator();
  h.context.openHeaderServerProblems();
  assert.equal(h.opened(), 1);
  assert.equal(h.elements.backendStatus.tabIndex, 0);
  assert.ok(h.elements.statusDot.classes.has('bg-red-500'));
  h.setAdmin(false);
  h.context.updateStatusIndicator();
  h.context.openHeaderServerProblems();
  assert.equal(h.opened(), 1);
  assert.equal(h.elements.backendStatus.tabIndex, -1);
});

test('disconnected websocket opens server manager even without reported server failures', () => {
  const h = harness();
  h.context.wsManager.state = 'disconnected';
  h.context.openHeaderServerProblems();
  assert.equal(h.opened(), 1);
});

test('header tooltip names affected servers and escapes diagnostic text', () => {
  const h = harness();
  h.context.serversCache = [
    { id: 'a', name: '<script>bad</script>', enabled: true, health: { state: 'down', error: '<img src=x>' } },
    { id: 'b', enabled: true, health: { state: 'degraded', callbackOk: false } },
    { id: 'healthy', enabled: true, health: { state: 'ok' } },
    { id: 'disabled', enabled: false, health: { state: 'down' } }
  ];
  const html = h.context.renderHeaderServerProblems();
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /&lt;img src=x&gt;/);
  assert.match(html, /cannot reach the callback URL/);
  assert.doesNotMatch(html, /healthy|disabled|<script>|<img/);
  h.setAdmin(false);
  assert.equal(h.context.renderHeaderServerProblems(), '');
});

test('an active server change is busy rather than a disconnected UI', () => {
  const h = harness();
  h.context.serversCache = [{ id: 'a', name: 'Working server', enabled: true, health: { state: 'busy', fail2banOk: false, error: 'ping timed out' } }];
  h.context.updateStatusIndicator();
  assert.match(h.elements.statusText.textContent, /busy/);
  assert.ok(h.elements.statusDot.classes.has('bg-yellow-500'));
  const tooltip = h.context.renderHeaderServerProblems();
  assert.match(tooltip, /applying a change/);
  assert.doesNotMatch(tooltip, /not responding|ping timed out|Activity/);
});

test('header summarizes SSH trust failures without the raw OpenSSH warning', () => {
  const h = harness();
  h.context.serversCache = [{
    id: 'ssh', name: 'Test SSH', enabled: true,
    health: {
      state: 'down', fail2banOk: false,
      error: 'remote fail2ban ping error: ssh host key for localhost has changed (output: @@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@)'
    }
  }];
  const html = h.context.renderHeaderServerProblems();
  assert.match(html, /Test SSH: Connection blocked/);
  assert.match(html, /SSH host key changed/);
  assert.match(html, /Verify the new fingerprint/);
  assert.doesNotMatch(html, /@@@|ping error|not responding|REMOTE HOST/);
  h.context.serversCache[0].hostKeyError = true;
  h.context.serversCache[0].health.error = '';
  assert.match(h.context.renderHeaderServerProblems(), /SSH host key changed/);
});
