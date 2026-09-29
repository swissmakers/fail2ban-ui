'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const filename = path.join(__dirname, '../../pkg/web/static/js/utils.js');
const context = vm.createContext({});
vm.runInContext(fs.readFileSync(filename, 'utf8'), context, { filename });
const isSuspiciousLogLine = context.isSuspiciousLogLine;
const ip = '192.0.2.1';

const cases = [
  ['JSON status', '{"ip":"192.0.2.1","status":400}', true],
  ['JSON code', '{"ip":"192.0.2.1","code":401}', true],
  ['JSON statusCode', '{"ip":"192.0.2.1","statusCode":503}', true],
  ['JSON key case and whitespace', '{"ip":"192.0.2.1","STATUSCODE" : 503}', true],
  ['JSON quoted status remains unsupported', '{"ip":"192.0.2.1","status":"400"}', false],
  ['JSON success', '{"ip":"192.0.2.1","status":200}', false],
  ['JSON redirect remains highlighted', '{"ip":"192.0.2.1","status":302}', true],
  ['combined log error', '192.0.2.1 - - [29/Sep/2026:12:00:00 +0200] "GET / HTTP/1.1" 503 17', true],
  ['combined log success', '192.0.2.1 - - [29/Sep/2026:12:00:00 +0200] "GET / HTTP/1.1" 200 17', false],
  ['text fallback error', '192.0.2.1 503 17', true],
  ['text fallback success', '192.0.2.1 200 17', false],
  ['numeric prefix must not hide combined log error', '192.0.2.1 200 42 "GET / HTTP/1.1" 503 17', true],
  ['numeric prefix must not flag combined log success', '192.0.2.1 503 42 "GET / HTTP/1.1" 200 17', false],
  ['message numbers must not hide JSON error', '{"ip":"192.0.2.1","message":"received 200 123 bytes","status":503}', true],
  ['message numbers must not flag JSON success', '{"ip":"192.0.2.1","message":"received 503 123 bytes","status":200}', false],
  ['ordinary SSH log without a status', 'sshd: Accepted publickey for admin from 192.0.2.1 port 12345 ssh2', false],
  ['attack indicator still flags a successful request', '192.0.2.1 "GET /etc/passwd HTTP/1.1" 200 17', true],
  ['empty log', '', false]
];

for (const [name, line, expected] of cases) {
  test(name, () => {
    assert.equal(isSuspiciousLogLine(line, ip), expected);
  });
}

test('only highlights the selected IP when one is supplied', () => {
  const line = '{"ip":"192.0.2.2","message":"received 200 123 bytes","status":503}';
  assert.equal(isSuspiciousLogLine(line, ip), false);
  assert.equal(isSuspiciousLogLine(line, ''), true);
});
