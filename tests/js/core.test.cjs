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
