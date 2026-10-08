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

const translated = vm.createContext({
  translations: {
    'jails.errors.already_exists': 'A jail with this name already exists.',
    'jails.toast.create_success': 'Jail created',
    'servers.toast.restart_failed': 'Failed to restart Fail2ban',
    'common.http_error': 'HTTP {status}',
    'common.unknown_error': 'Something went wrong'
  }
});
vm.runInContext(fs.readFileSync(filename, 'utf8'), translated, { filename });

const apiMessageCases = [
  ['messageKey wins over text', { messageKey: 'jails.errors.already_exists', error: 'jail sshd exists' }, 'A jail with this name already exists.'],
  ['untranslated messageKey falls back to the error text', { messageKey: 'missing.key', error: 'raw error' }, 'raw error'],
  ['untranslated messageKey without text uses the fallback', { messageKey: 'missing.key' }, 'Jail created'],
  ['error text', { error: 'boom' }, 'boom'],
  ['message text', { message: 'Created sshd' }, 'Created sshd'],
  ['no data', null, 'Jail created'],
  ['empty object', {}, 'Jail created']
];

for (const [name, data, expected] of apiMessageCases) {
  test('apiMessage: ' + name, () => {
    assert.equal(translated.apiMessage(data, 'jails.toast.create_success', 'Jail created successfully'), expected);
  });
}

const formatApiErrorCases = [
  ['fallback key plus detail', { error: 'exit 1' }, 'Failed to restart Fail2ban: exit 1'],
  ['messageKey plus detail', { messageKey: 'jails.errors.already_exists', error: 'dup' }, 'A jail with this name already exists.: dup'],
  ['detail equal to the short message', { error: 'Failed to restart Fail2ban' }, 'Failed to restart Fail2ban'],
  ['no detail', {}, 'Failed to restart Fail2ban']
];

for (const [name, data, expected] of formatApiErrorCases) {
  test('formatApiError: ' + name, () => {
    assert.equal(translated.formatApiError(data, 'servers.toast.restart_failed', 'Failed'), expected);
  });
}

test('formatApiError: nothing to show uses the translated unknown error', () => {
  assert.equal(translated.formatApiError(null, '', ''), 'Something went wrong');
});

test('SSH host-key diagnostics are recognized without masking other connection failures', () => {
  for (const message of [
    'remote fail2ban ping error: ssh host key for localhost has changed (presented SHA256:new)',
    '@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @',
    'WARNING: POSSIBLE DNS SPOOFING DETECTED!',
    'ssh host key verification failed for localhost',
    'remote host key SHA256:new does not match the approved fingerprint SHA256:old'
  ]) assert.equal(context.isSSHHostKeyError(message), true, message);
  for (const message of [null, '', 'Permission denied (publickey)', 'ssh: connect to host localhost port 2222: Connection refused', 'fail2ban ping timed out']) {
    assert.equal(context.isSSHHostKeyError(message), false, message);
  }
});

function fakeResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => {
      if (body instanceof Error) throw body;
      return body;
    }
  };
}

test('readJsonResponse: 2xx resolves with the body', async () => {
  assert.deepEqual(await translated.readJsonResponse(fakeResponse(200, { jails: [] })), { jails: [] });
});

test('readJsonResponse: 2xx without JSON resolves with null', async () => {
  assert.equal(await translated.readJsonResponse(fakeResponse(204, new SyntaxError('Unexpected end of JSON input'))), null);
});

test('readJsonResponse: 409 rejects with the translated messageKey', async () => {
  const body = { error: 'jail sshd already exists', messageKey: 'jails.errors.already_exists' };
  await assert.rejects(translated.readJsonResponse(fakeResponse(409, body)), (err) => {
    assert.equal(err.message, 'A jail with this name already exists.');
    assert.equal(err.status, 409);
    assert.deepEqual(err.data, body);
    return true;
  });
});

test('readJsonResponse: 500 rejects with the server error text', async () => {
  await assert.rejects(translated.readJsonResponse(fakeResponse(500, { error: 'SSH connection refused' })), (err) => {
    assert.equal(err.message, 'SSH connection refused');
    assert.equal(err.status, 500);
    return true;
  });
});

test('readJsonResponse: non-JSON 502 rejects with the status', async () => {
  await assert.rejects(translated.readJsonResponse(fakeResponse(502, new SyntaxError('Unexpected token <'))), (err) => {
    assert.equal(err.message, 'HTTP 502');
    assert.equal(err.data, null);
    return true;
  });
});
