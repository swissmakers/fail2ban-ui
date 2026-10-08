'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const jsDir = path.join(__dirname, '../../pkg/web/static/js');
function harness() {
  const requests = [], timers = [];
  let renders = 0;
  const context = vm.createContext({
    console, Date,
    setTimeout: (fn, delay) => { timers.push({ fn, delay }); return timers.length; }, clearTimeout() {},
    appPath: url => url, document: { getElementById: () => null },
    fetch: url => new Promise((resolve, reject) => requests.push({ url, reject, resolve: data => resolve({ ok: true, status: 200, json: async () => data }) })),
    escapeHtml: value => String(value), formatDateTime: value => value
  });
  for (const file of ['globals.js', 'utils.js', 'dashboard.js']) vm.runInContext(fs.readFileSync(path.join(jsDir, file), 'utf8'), context, { filename: file });
  context.scheduleRender = () => { renders++; };
  context.currentServerId = 'a';
  return { context, requests, timers, renders: () => renders };
}
const snapshot = (serverId, extra = {}) => ({ serverId, available: true, stale: false, observedAt: '2026-10-06T10:00:00Z', jails: [{ jailName: 'sshd', totalBanned: 123 }], ...extra });

test('multiple refresh triggers share one request for each server', async () => {
  const h = harness();
  const a = h.context.fetchSummaryData();
  const b = h.context.fetchSummaryData();
  assert.equal(a, b);
  assert.equal(h.requests.length, 1);
  h.requests[0].resolve(snapshot('a'));
  await a;
  assert.equal(h.context.latestSummary.jails[0].totalBanned, 123);
});

test('a slow previous server never overwrites the newly selected server', async () => {
  const h = harness();
  const a = h.context.fetchSummaryData();
  h.context.currentServerId = 'b';
  const b = h.context.fetchSummaryData();
  h.requests[1].resolve(snapshot('b', { jails: [{ jailName: 'httpd', totalBanned: 7 }] }));
  await b;
  h.requests[0].resolve(snapshot('a'));
  await a;
  assert.equal(h.context.latestSummary.serverId, 'b');
  assert.equal(h.context.latestSummary.jails[0].totalBanned, 7);
  assert.equal(h.context.summariesByServer.a.jails[0].totalBanned, 123);
});

test('a failed refresh preserves counts and explains the connection problem', async () => {
  const h = harness();
  let pending = h.context.fetchSummaryData();
  h.requests[0].resolve(snapshot('a'));
  await pending;
  pending = h.context.fetchSummaryData();
  h.requests[1].reject(new Error('SSH unavailable'));
  await pending;
  assert.equal(h.context.latestSummary.jails[0].totalBanned, 123);
  assert.equal(h.context.latestSummary.stale, true);
  assert.equal(h.context.latestSummary.observedAt, '2026-10-06T10:00:00Z');
  assert.match(h.context.renderSummaryStatus(h.context.latestSummary), /Server not responding\. Showing the last received data\./);
  assert.doesNotMatch(h.context.renderSummaryStatus(h.context.latestSummary), /snapshot|Last confirmed|Awaiting|SSH unavailable/);
});

test('normal updates and running changes do not add dashboard status banners', () => {
  const h = harness();
  for (const extra of [
    {},
    { stale: true, refreshing: true, staleReason: 'refresh_pending' },
    { stale: true, refreshing: false, staleReason: 'operation_in_progress' },
    { stale: true, staleReason: 'operation_in_progress', refreshError: 'A daemon query timed out' }
  ]) {
    assert.equal(h.context.renderSummaryStatus(snapshot('a', extra)), '');
  }
});

test('no initial snapshot stays unavailable, not an invented zero or empty jail list', async () => {
  const h = harness();
  const pending = h.context.fetchSummaryData();
  h.requests[0].resolve({ serverId: 'a', available: false, stale: true, refreshing: true, staleReason: 'initializing', jails: null });
  await pending;
  assert.equal(h.context.latestSummary.available, false);
  assert.equal(h.context.latestSummary.jails, null);
  assert.equal(h.context.renderSummaryStatus(h.context.latestSummary), '');
  assert.equal(h.context.summaryStatusFailed(h.context.latestSummary), false);
  assert.equal(h.timers.at(-1).delay, 3000);
});

test('a failed initial read is distinguishable from normal loading without duplicate banners', () => {
  const h = harness();
  const unavailable = { serverId: 'a', available: false, stale: true, staleReason: 'refresh_failed', jails: null };
  assert.equal(h.context.summaryStatusFailed(unavailable), true);
  assert.equal(h.context.renderSummaryStatus(unavailable), '');
});

test('a temporary unavailable response retains an earlier confirmed snapshot', async () => {
  const h = harness();
  let pending = h.context.fetchSummaryData();
  h.requests[0].resolve(snapshot('a'));
  await pending;
  pending = h.context.fetchSummaryData();
  h.requests[1].resolve({ serverId: 'a', available: false, stale: true, refreshing: true, jails: null });
  await pending;
  assert.equal(h.context.latestSummary.available, true);
  assert.equal(h.context.latestSummary.jails[0].totalBanned, 123);
  assert.equal(h.context.latestSummary.stale, true);
});

test('a newly confirmed snapshot invalidates expanded IP pages after missed callbacks', async () => {
  const h = harness();
  h.context.latestSummary = snapshot('a');
  h.context.jailBannedState = { sshd: { ips: ['192.0.2.1'] } };
  const pending = h.context.fetchSummaryData();
  h.requests[0].resolve(snapshot('a', { observedAt: '2026-10-06T10:10:00Z', jails: [] }));
  await pending;
  assert.deepEqual(Object.keys(h.context.jailBannedState), []);
});

test('new server data refreshes an open jail manager without repeated requests for unchanged data', () => {
  const h = harness();
  const refreshes = [];
  let hidden = false;
  h.context.document.getElementById = id => id === 'manageJailsModal'
    ? { classList: { contains: () => hidden } } : null;
  h.context.openManageJailsModal = options => refreshes.push(options);
  h.context.latestSummary = { serverId: 'a', available: false, staleReason: 'initializing', jails: null };
  h.context.summariesByServer.a = snapshot('a');
  h.context.applySelectedSummary('a');
  assert.equal(refreshes.length, 1);
  assert.equal(refreshes[0].silent, true);
  h.context.applySelectedSummary('a');
  assert.equal(refreshes.length, 1, 'unchanged summary must not trigger another jail read');
  h.context.summariesByServer.b = snapshot('b');
  h.context.applySelectedSummary('b');
  assert.equal(refreshes.length, 1, 'another server cannot replace the visible jail list');
  hidden = true;
  h.context.summariesByServer.a = snapshot('a', { observedAt: '2026-10-06T10:10:00Z' });
  h.context.applySelectedSummary('a');
  assert.equal(refreshes.length, 1, 'a closed manager needs no background jail read');
});

test('stored event statistics render while the runtime snapshot request is still pending', async () => {
  const h = harness();
  h.context.serversCache = [{ id: 'a', enabled: true }];
  h.context.fetchBanStatisticsData = async () => { h.context.latestBanStats = { a: 10 }; };
  h.context.fetchBanInsightsData = async () => {};
  h.context.fetchBanEventCountries = async () => {};
  let rendered = false;
  h.context.renderDashboard = () => { rendered = true; };
  h.context.refreshDashboardData();
  await new Promise(setImmediate);
  assert.equal(rendered, true);
  assert.equal(h.requests.length, 1);
  h.requests[0].resolve(snapshot('a'));
  await new Promise(setImmediate);
});
