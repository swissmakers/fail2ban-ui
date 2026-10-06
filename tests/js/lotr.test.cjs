'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const filename = path.join(__dirname, '../../pkg/web/static/js/lotr.js');
const localesDir = path.join(__dirname, '../../pkg/web/locales');
const context = vm.createContext({ isLOTRModeActive: false });
vm.runInContext(fs.readFileSync(filename, 'utf8'), context, { filename });

const cases = [
  ['page.title', 'lotr.page_title'],
  ['dashboard.cards.total_banned', 'lotr.threats_banished'],
  ['dashboard.table.banned_ips', 'lotr.threats_banished'],
  ['dashboard.search_label', 'lotr.search_banished'],
  ['dashboard.manage_servers', 'lotr.manage_realms'],
  ['dashboard.unban', 'lotr.restore_to_realm'],
  ['dashboard.ban.confirm', 'lotr.confirm_ban'],
  ['dashboard.unban.confirm', 'lotr.confirm_unban']
];

for (const [key, lotrKey] of cases) {
  test('lotrI18nKey maps ' + key + ' only in LOTR mode', () => {
    context.isLOTRModeActive = false;
    assert.equal(context.lotrI18nKey(key), key);
    context.isLOTRModeActive = true;
    assert.equal(context.lotrI18nKey(key), lotrKey);
  });
}

test('lotrI18nKey leaves other keys alone in LOTR mode', () => {
  context.isLOTRModeActive = true;
  for (const key of ['dashboard.title', 'toString', '', 'lotr.page_title']) {
    assert.equal(context.lotrI18nKey(key), key);
  }
});

test('every LOTR override target exists in every locale', () => {
  const targets = new Set(Object.values(context.LOTR_KEY_OVERRIDES));
  for (const file of fs.readdirSync(localesDir).filter(f => f.endsWith('.json'))) {
    const locale = JSON.parse(fs.readFileSync(path.join(localesDir, file), 'utf8'));
    for (const key of targets) {
      assert.ok(locale[key], file + ' is missing ' + key);
    }
  }
});

test('LOTR confirm texts keep the {ip} and {jail} placeholders', () => {
  for (const file of fs.readdirSync(localesDir).filter(f => f.endsWith('.json'))) {
    const locale = JSON.parse(fs.readFileSync(path.join(localesDir, file), 'utf8'));
    for (const key of ['lotr.confirm_ban', 'lotr.confirm_unban']) {
      assert.match(locale[key], /\{ip\}/, file + ' ' + key);
      assert.match(locale[key], /\{jail\}/, file + ' ' + key);
    }
  }
});
