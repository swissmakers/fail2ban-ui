'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const jsDir = path.join(__dirname, '../../pkg/web/static/js');
const context = vm.createContext({ translations: {} });
for (const name of ['utils.js', 'validation.js']) {
  const filename = path.join(jsDir, name);
  vm.runInContext(fs.readFileSync(filename, 'utf8'), context, { filename });
}
const { isValidIP, isValidIgnoreEntry, validateTimeFormat } = context;

const ipCases = [
  ['IPv4', '1.2.3.4', false, true],
  ['IPv4 with surrounding space', ' 1.2.3.4 ', false, true],
  ['IPv4 three octets', '1.2.3', false, false],
  ['IPv4 five octets', '1.2.3.4.5', false, false],
  ['IPv4 octet out of range', '999.999.999.999', false, false],
  ['IPv4 256', '1.2.3.256', false, false],
  ['IPv4 leading zero', '01.2.3.4', false, false],
  ['IPv4 empty octet', '1..3.4', false, false],
  ['IPv4 CIDR rejected without allowCidr', '10.0.0.0/8', false, false],
  ['IPv4 CIDR', '10.0.0.0/8', true, true],
  ['IPv4 CIDR /0', '0.0.0.0/0', true, true],
  ['IPv4 CIDR /32', '1.2.3.4/32', true, true],
  ['IPv4 CIDR /33', '1.2.3.4/33', true, false],
  ['IPv4 CIDR leading zero prefix', '1.2.3.0/024', true, false],
  ['IPv4 CIDR empty prefix', '1.2.3.0/', true, false],
  ['IPv6 unspecified', '::', false, true],
  ['IPv6 loopback', '::1', false, true],
  ['IPv6 compressed', '2001:db8::1', false, true],
  ['IPv6 full form', '2001:0db8:0000:0000:0000:ff00:0042:8329', false, true],
  ['IPv6 trailing gap', '2001:db8::', false, true],
  ['IPv6 mixed case', '2001:DB8::aBc', false, true],
  ['IPv4-mapped IPv6', '::ffff:192.0.2.1', false, true],
  ['IPv6 with embedded IPv4 full', '1:2:3:4:5:6:1.2.3.4', false, true],
  ['IPv6 colons only', ':::::::', false, false],
  ['IPv6 two gaps', '1::2::3', false, false],
  ['IPv6 group too long', '12345::1', false, false],
  ['IPv6 zone', 'fe80::1%eth0', false, false],
  ['IPv4 before gap', '1.2.3.4::', false, false],
  ['IPv6 seven groups without gap', '1:2:3:4:5:6:7', false, false],
  ['IPv6 nine groups', '1:2:3:4:5:6:7:8:9', false, false],
  ['IPv6 gap with eight groups', '1:2:3:4::5:6:7:8', false, false],
  ['IPv6 leading single colon', ':1::2', false, false],
  ['IPv6 non-hex', '2001:db8::g', false, false],
  ['IPv6 invalid embedded IPv4', '::ffff:1.2.3.999', false, false],
  ['IPv6 CIDR', '2001:db8::/32', true, true],
  ['IPv6 CIDR /128', '::1/128', true, true],
  ['IPv6 CIDR /129', '2001:db8::/129', true, false],
  ['hostname is not an IP', 'example.com', true, false],
  ['empty', '', true, false],
  ['non-string', null, true, false]
];

for (const [name, value, allowCidr, expected] of ipCases) {
  test('isValidIP: ' + name, () => {
    assert.equal(isValidIP(value, allowCidr), expected);
  });
}

const ignoreCases = [
  ['IPv4', '192.0.2.1', true],
  ['IPv4 CIDR', '192.0.2.0/24', true],
  ['IPv6 CIDR', '2001:db8::/48', true],
  ['hostname', 'mail.example.com', true],
  ['single label host', 'localhost', true],
  ['host with digits in first label', '1password.example.com', true],
  ['malformed IP looks like a host', '1.2.3', false],
  ['out-of-range IP looks like a host', '999.999.999.999', false],
  ['numeric last label', 'host.123', false],
  ['bad CIDR', '1.2.3.4/33', false],
  ['underscore', 'bad_host.example.com', false],
  ['trailing dot', 'example.com.', false],
  ['label starting with dash', '-bad.example.com', false],
  ['empty', '', false]
];

for (const [name, value, expected] of ignoreCases) {
  test('isValidIgnoreEntry: ' + name, () => {
    assert.equal(isValidIgnoreEntry(value), expected);
  });
}

const timeCases = [
  ['empty', '', true],
  ['seconds', '600s', true],
  ['minutes', '10m', true],
  ['hours', '48h', true],
  ['days', '7d', true],
  ['weeks', '5w', true],
  ['months', '1mo', true],
  ['years', '1y', true],
  ['uppercase', '1MO', true],
  ['bare number', '3600', false],
  ['unknown unit', '1x', false],
  ['fraction', '1.5h', false],
  ['negative', '-1h', false],
  ['month typo', '1mon', false]
];

for (const [name, value, expected] of timeCases) {
  test('validateTimeFormat: ' + name, () => {
    const result = validateTimeFormat(value);
    assert.equal(result.valid, expected);
    if (!expected) {
      assert.match(result.message, /1mo = 1 month/);
    }
  });
}
