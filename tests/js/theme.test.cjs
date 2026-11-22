'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const filename = path.join(__dirname, '../../pkg/web/static/js/theme.js');

function harness({ systemDark = false, stored = null, lotr = false, storageFails = false } = {}) {
  const store = new Map(stored === null ? [] : [['fail2ban-ui-theme', stored]]);
  const attributes = {};
  const buttons = ['system', 'light', 'dark'].map(choice => {
    const attrs = { 'data-theme-choice': choice };
    return { getAttribute: name => attrs[name], setAttribute: (name, value) => { attrs[name] = value; }, attrs };
  });
  const listeners = [];
  const fail = () => { throw new Error('storage blocked'); };
  const window = {
    localStorage: {
      getItem: storageFails ? fail : key => (store.has(key) ? store.get(key) : null),
      setItem: storageFails ? fail : (key, value) => store.set(key, value),
      removeItem: storageFails ? fail : key => store.delete(key)
    },
    matchMedia: () => ({ matches: systemDark, addEventListener: (name, fn) => listeners.push(fn) })
  };
  const context = vm.createContext({
    window,
    document: {
      documentElement: { setAttribute: (name, value) => { attributes[name] = value; } },
      body: { classList: { contains: name => lotr && name === 'lotr-mode' } },
      getElementById: () => null,
      querySelectorAll: () => buttons
    }
  });
  vm.runInContext(fs.readFileSync(filename, 'utf8'), context, { filename });
  const checked = () => buttons.filter(b => b.attrs['aria-checked'] === 'true').map(b => b.attrs['data-theme-choice']);
  return { context, store, attributes, checked, listeners, setSystemDark: value => { systemDark = value; } };
}

test('resolveTheme follows the device only for the System choice', () => {
  const { context } = harness();
  const cases = [
    ['system', false, false, 'light'],
    ['system', true, false, 'dark'],
    ['light', true, false, 'light'],
    ['dark', false, false, 'dark'],
    ['light', false, true, 'dark'],
    ['system', false, true, 'dark']
  ];
  for (const [preference, systemDark, lotr, want] of cases) {
    assert.equal(context.resolveTheme(preference, systemDark, lotr), want, [preference, systemDark, lotr].join('/'));
  }
});

test('without a stored choice the page follows the device', () => {
  const h = harness({ systemDark: true });
  h.context.initThemeManager();
  assert.equal(h.attributes['data-theme'], 'dark');
  assert.deepEqual(h.checked(), ['system']);
});

test('a stored choice wins over the device setting', () => {
  const h = harness({ systemDark: true, stored: 'light' });
  h.context.initThemeManager();
  assert.equal(h.attributes['data-theme'], 'light');
  assert.deepEqual(h.checked(), ['light']);
});

test('an unknown stored value counts as System', () => {
  const h = harness({ systemDark: false, stored: 'purple' });
  assert.equal(h.context.getThemePreference(), 'system');
});

test('choosing a theme stores it, applies it and marks the button', () => {
  const h = harness({ systemDark: false });
  h.context.setThemePreference('dark');
  assert.equal(h.store.get('fail2ban-ui-theme'), 'dark');
  assert.equal(h.attributes['data-theme'], 'dark');
  assert.deepEqual(h.checked(), ['dark']);
  h.context.setThemePreference('system');
  assert.equal(h.store.has('fail2ban-ui-theme'), false, 'System clears the stored choice');
  assert.equal(h.attributes['data-theme'], 'light');
  h.context.setThemePreference('purple');
  assert.equal(h.store.has('fail2ban-ui-theme'), false, 'an invalid choice must not be stored');
});

test('a device change repaints only while System is chosen', () => {
  const h = harness({ systemDark: false });
  h.context.initThemeManager();
  assert.equal(h.listeners.length, 1);
  h.setSystemDark(true);
  h.listeners[0]();
  assert.equal(h.attributes['data-theme'], 'dark');
  h.context.setThemePreference('light');
  h.listeners[0]();
  assert.equal(h.attributes['data-theme'], 'light');
});

test('LOTR mode stays dark whatever is chosen', () => {
  const h = harness({ systemDark: false, stored: 'light', lotr: true });
  h.context.syncSystemTheme();
  assert.equal(h.attributes['data-theme'], 'dark');
  assert.deepEqual(h.checked(), ['light']);
});

test('blocked browser storage falls back to the device setting', () => {
  const h = harness({ systemDark: true, storageFails: true });
  h.context.setThemePreference('light');
  assert.equal(h.attributes['data-theme'], 'dark');
});
