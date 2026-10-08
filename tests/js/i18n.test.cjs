'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.join(__dirname, '../..');
const localesDir = path.join(root, 'pkg/web/locales');
const locales = {};
for (const file of fs.readdirSync(localesDir).filter(f => f.endsWith('.json'))) {
  locales[file] = JSON.parse(fs.readFileSync(path.join(localesDir, file), 'utf8'));
}
const en = locales['en.json'];
const enKeys = Object.keys(en);

// Built at runtime ('logs.timeline.compare_incident_' + slot).
const DYNAMIC_PREFIXES = ['logs.timeline.compare_incident_'];

function walk(dir, pick, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (['node_modules', '.git', '_dev', 'vendor'].includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, pick, out);
    else if (pick(entry.name)) out.push(full);
  }
  return out;
}

const uiFiles = walk(path.join(root, 'pkg/web/static/js'), n => n.endsWith('.js'))
  .concat([path.join(root, 'pkg/web/templates/index.html')]);
const goFiles = ['cmd', 'internal', 'pkg'].flatMap(d => walk(path.join(root, d), n => n.endsWith('.go') && !n.endsWith('_test.go')));
const uiSource = uiFiles.map(f => fs.readFileSync(f, 'utf8')).join('\n');
const goSource = goFiles.map(f => fs.readFileSync(f, 'utf8')).join('\n');

const namespaces = new Set(enKeys.filter(k => k.includes('.')).map(k => k.split('.')[0]));
const literals = source => new Set([...source.matchAll(/["'`]([A-Za-z0-9_.-]+)\\?["'`]/g)].map(m => m[1]));
const uiLiterals = literals(uiSource);
const goLiterals = new Set([...goSource.matchAll(/"([A-Za-z0-9_.-]+)"/g)].map(m => m[1]));
const looksLikeKey = value => value.includes('.') && namespaces.has(value.split('.')[0]) && !/\.(js|css|json|html|png|jpg|go|conf|local)$/.test(value);
const isDynamic = value => DYNAMIC_PREFIXES.some(prefix => value.startsWith(prefix));

test('every key literal used by the UI exists in en.json', () => {
  const direct = [...uiSource.matchAll(/(?<![\w.$])(?:t|setI18nText\([^,]+,)\(?\s*['"]([A-Za-z0-9_.-]+)['"]/g)].map(m => m[1]);
  const shaped = [...uiLiterals].filter(looksLikeKey);
  const missing = [...new Set(direct.concat(shaped))].filter(k => !(k in en) && !isDynamic(k)).sort();
  assert.deepEqual(missing, []);
});

test('every key literal used by the Go backend exists in en.json', () => {
  const missing = [...goLiterals].filter(looksLikeKey).filter(k => !(k in en)).sort();
  assert.deepEqual(missing, []);
});

test('every en.json key is referenced', () => {
  const unused = enKeys.filter(k => !uiLiterals.has(k) && !goLiterals.has(k) && !isDynamic(k)).sort();
  assert.deepEqual(unused, []);
});

test('all locales have the same key set as en.json', () => {
  const expected = [...enKeys].sort();
  for (const [file, locale] of Object.entries(locales)) {
    assert.deepEqual(Object.keys(locale).sort(), expected, file);
  }
});

test('all locale values are non-empty strings', () => {
  for (const [file, locale] of Object.entries(locales)) {
    const bad = Object.entries(locale).filter(([, v]) => typeof v !== 'string' || !v.trim()).map(([k]) => k);
    assert.deepEqual(bad, [], file);
  }
});

test('placeholder tokens match en.json in every locale', () => {
  const tokens = value => [...value.matchAll(/\{[a-z_]+\}|%s/g)].map(m => m[0]).sort();
  for (const [file, locale] of Object.entries(locales)) {
    const mismatched = enKeys.filter(k => JSON.stringify(tokens(locale[k] || '')) !== JSON.stringify(tokens(en[k])));
    assert.deepEqual(mismatched, [], file);
  }
});
