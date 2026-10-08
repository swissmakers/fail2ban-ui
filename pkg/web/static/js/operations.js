// Durable background tasks: HTTP acceptance, WebSocket updates and polling
// all feed the same registry. Reloading a page never owns/cancels a task.
"use strict";

var operationsById = Object.create(null);
var operationWaiters = Object.create(null);
var operationsPollTimer = null;
var operationsClockTimer = null;
var operationsRefreshPromise = null;
var operationsStarted = false;
var operationsGeneration = 0;
var operationNotices = Object.create(null);
var operationsStatusError = '';
var recentBanEventToasts = [];

function operationBanEvent(operation) {
  if (['jail.ban', 'jail.unban'].indexOf(operation.kind) === -1) return null;
  var target = String(operation.target || '').split(' / ');
  if (target.length !== 2) return null;
  var server = (typeof serversCache !== 'undefined' ? serversCache : []).find(function(s) { return s.id === operation.serverId; });
  return { serverId: operation.serverId, serverName: server ? server.name : operation.serverId,
    jail: target[0], ip: target[1], eventType: operation.kind === 'jail.unban' ? 'unban' : 'ban' };
}

function normalizeBanToastIP(value) {
  var ip = String(value || '').toLowerCase();
  var parts = ip.split('/');
  var ipv6 = parts[0].indexOf(':') !== -1;
  var bits = ipv6 ? 128 : 32;
  var prefix = parts.length === 1 ? bits : Number(parts[1]);
  if (parts.length > 2 || !Number.isInteger(prefix) || prefix < 0 || prefix > bits) return ip;
  var address = parts[0];
  try {
    if (ipv6) {
      address = new URL('http://[' + address + ']/').hostname.slice(1, -1);
      var halves = address.split('::');
      var left = halves[0] ? halves[0].split(':') : [];
      var right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
      var groups = left.concat(new Array(8 - left.length - right.length).fill('0'), right);
      address = groups.map(function(group, index) {
        var keep = Math.max(0, Math.min(16, prefix - index * 16));
        return (parseInt(group, 16) & (0xffff << (16 - keep))).toString(16);
      }).join(':');
      address = new URL('http://[' + address + ']/').hostname.slice(1, -1);
    } else {
      var octets = address.split('.');
      if (octets.length !== 4 || octets.some(function(octet) { return !/^\d+$/.test(octet) || Number(octet) > 255; })) return ip;
      address = octets.map(function(octet, index) {
        var keep = Math.max(0, Math.min(8, prefix - index * 8));
        return Number(octet) & (0xff << (8 - keep));
      }).join('.');
    }
  } catch (ignore) {
    return ip;
  }
  return address + (prefix === bits ? '' : '/' + prefix);
}

function banToastIdentity(event) {
  // Match daemon canonicalization, including IPv6 and CIDR host bits.
  return JSON.stringify([event.serverId, event.jail, normalizeBanToastIP(event.ip), event.eventType || 'ban']);
}

function pruneBanEventToasts() {
  var cutoff = Date.now() - 60000;
  recentBanEventToasts = recentBanEventToasts.filter(function(record) { return record.receivedAt >= cutoff; }).slice(-200);
}

function matchingBanEvent(operation, record) {
  var target = operationBanEvent(operation);
  if (!target || ['queued', 'failed', 'cancelled'].indexOf(operation.state) !== -1 ||
      (record.operationId && record.operationId !== operation.id) ||
      banToastIdentity(target) !== banToastIdentity(record.event)) return false;
  var start = Date.parse(operation.startedAt || operation.createdAt);
  var end = Date.parse(operation.finishedAt);
  var occurred = Date.parse(record.event.occurredAt);
  if (!Number.isFinite(occurred)) occurred = record.receivedAt;
  // Match this action's time window, never every future event for the same IP.
  return Number.isFinite(start) && occurred >= start - 1000 && (!Number.isFinite(end) || occurred <= end + 30000);
}

function attachBanEventToast(operation, notice) {
  if (notice.banEvent) return;
  pruneBanEventToasts();
  var record = recentBanEventToasts.find(function(entry) { return matchingBanEvent(operation, entry); });
  if (!record) return;
  record.operationId = operation.id;
  notice.banEvent = record.event;
  if (!operationIsActive(operation) && record.isVisible && !record.isVisible()) notice.dismissed = true;
  if (record.removeToast) record.removeToast();
}

// The event and the operation may arrive in either order. Join their notices,
// but only the verified operation result may finish a pending command.
function handleOperationBanEventToast(event) {
  pruneBanEventToasts();
  var key = event.id ? JSON.stringify([event.serverId, String(event.id)]) :
    event.occurredAt ? banToastIdentity(event) + event.occurredAt : null;
  if (key && recentBanEventToasts.some(function(record) { return record.key === key; })) return true;
  var record = { key: key, event: event, receivedAt: Date.now() };
  recentBanEventToasts.push(record);
  var candidates = Object.values(operationsById).filter(function(operation) {
    return operationNotices[operation.id] && matchingBanEvent(operation, record);
  }).sort(function(a, b) { return String(b.startedAt || b.createdAt).localeCompare(String(a.startedAt || a.createdAt)); });
  var operation = candidates[0];
  if (!operation) return false;
  var notice = operationNotices[operation.id];
  // Each operation consumes at most one event; a later distinct event remains visible.
  if (notice.banEvent) return false;
  record.operationId = operation.id;
  notice.banEvent = event;
  renderOperations();
  return true;
}

function rememberBanEventToast(event, removeToast, isVisible) {
  var record = recentBanEventToasts.find(function(entry) { return entry.event === event; });
  if (record) {
    record.removeToast = removeToast;
    record.isVisible = isVisible;
  }
}

function operationIsActive(operation) {
  return operation && ['queued', 'running', 'reconciling'].indexOf(operation.state) !== -1;
}

function activeServerOperations(serverId) {
  return Object.values(operationsById).filter(function(operation) {
    return operationIsActive(operation) && (!serverId || operation.serverId === serverId);
  }).sort(function(a, b) { return String(a.createdAt).localeCompare(String(b.createdAt)); });
}

function operationStateLabel(state) {
  var labels = {
    queued: t('operations.state.queued', 'Queued'),
    running: t('operations.state.running', 'Running'),
    reconciling: t('operations.state.reconciling', 'Checking result'),
    succeeded: t('operations.state.succeeded', 'Completed'),
    failed: t('operations.state.failed', 'Failed'),
    cancelled: t('operations.state.cancelled', 'Cancelled')
  };
  return labels[state] || String(state || '');
}

function operationKindLabel(kind) {
  var labels = {
    'jail.manage': t('operations.kind.jail_manage', 'Change jail state'),
    'jail.config': t('operations.kind.jail_config', 'Save jail configuration'),
    'jail.create': t('operations.kind.jail_create', 'Create jail'),
    'jail.delete': t('operations.kind.jail_delete', 'Delete jail'),
    'filter.create': t('operations.kind.filter_create', 'Create filter'),
    'filter.delete': t('operations.kind.filter_delete', 'Delete filter'),
    'server.restart': t('operations.kind.server_restart', 'Restart or reload Fail2Ban'),
    'server.sync': t('operations.kind.server_sync', 'Apply shared configuration'),
    'jail.ban': t('operations.kind.jail_ban', 'Ban IP'),
    'jail.unban': t('operations.kind.jail_unban', 'Unban IP')
  };
  return labels[kind] || String(kind || '');
}

function operationElapsed(operation) {
  var start = Date.parse(operation.startedAt || operation.createdAt);
  if (!Number.isFinite(start)) return '';
  var end = operation.finishedAt ? Date.parse(operation.finishedAt) : Date.now();
  var seconds = Math.max(0, Math.floor((end - start) / 1000));
  return Math.floor(seconds / 60) + ':' + String(seconds % 60).padStart(2, '0');
}

function operationCanCancel(operation) {
  return operation.state === 'queued' && (hasAccess('admin') ||
    (hasAccess('support') && ['jail.ban', 'jail.unban'].indexOf(operation.kind) !== -1));
}

function operationToastTitle(operation) {
  var jails = Object.keys(operation.desiredStates || {});
  if (operation.kind === 'jail.manage' && jails.length === 1 &&
      (operationIsActive(operation) || operation.state === 'succeeded')) {
    var enabled = operation.desiredStates[jails[0]];
    var completed = operation.state === 'succeeded';
    if (completed && operationDisabledJails(operation).indexOf(jails[0]) !== -1) enabled = false;
    return (enabled
      ? (completed ? t('operations.toast.enabled', '{jail} enabled') : t('operations.toast.enabling', 'Enabling {jail}…'))
      : (completed ? t('operations.toast.disabled', '{jail} disabled') : t('operations.toast.disabling', 'Disabling {jail}…'))).replace('{jail}', jails[0]);
  }
  return operationKindLabel(operation.kind) + (operation.target ? ': ' + operation.target : '');
}

function operationDisabledJails(operation) {
  var result = operation.result || {};
  var disabled = Array.isArray(result.disabledJails) ? result.disabledJails.slice() : [];
  if (result.jailAutoDisabled && result.jailName) disabled.push(result.jailName);
  if (result.autoDisabled && Array.isArray(result.enabledJails)) disabled = disabled.concat(result.enabledJails);
  return Array.from(new Set(disabled));
}

function operationWarning(operation) {
  var result = operation.result || {};
  var warnings = [];
  if (result.warning) warnings.push(result.warning);
  operationDisabledJails(operation).forEach(function(jail) {
    warnings.push(t('filter_debug.jail_auto_disabled', "Jail '%s' was automatically disabled.").replace('%s', jail));
  });
  return warnings.join(' ');
}

function dismissOperationToast(id) {
  var notice = operationNotices[id];
  if (!notice || operationIsActive(operationsById[id])) return;
  clearTimeout(notice.timer);
  notice.dismissed = true;
  if (notice.element) notice.element.remove();
  notice.element = null;
}

function showOperationNotice(operation) {
  var notice = operationNotices[operation.id];
  if (!notice) notice = operationNotices[operation.id] = { dismissed: false, timer: null, element: null };
  attachBanEventToast(operation, notice);
  // Repeated polls must not restart the three-second completion timer or
  // reopen a dismissed result. Errors and warnings need explicit dismissal.
  if (!notice.dismissed && notice.timer === null && !operationIsActive(operation) &&
      operation.state !== 'failed' && !operationWarning(operation)) {
    notice.timer = setTimeout(function() { dismissOperationToast(operation.id); }, 3000);
  }
}

function updateOperationElapsed() {
  document.querySelectorAll('[data-operation-elapsed]').forEach(function(element) {
    var operation = operationsById[element.getAttribute('data-operation-elapsed')];
    if (operation) element.textContent = operationElapsed(operation);
  });
}

function renderOperations() {
  var list = document.getElementById('operation-toasts');
  if (!list) return;
  Object.keys(operationNotices).forEach(function(id) {
    var notice = operationNotices[id];
    if (notice.dismissed) return;
    var operation = operationsById[id];
    var active = operationIsActive(operation);
    var server = (typeof serversCache !== 'undefined' ? serversCache : []).find(function(s) { return s.id === operation.serverId; });
    var warning = operationWarning(operation);
    var variant = operation.state === 'failed' ? 'error' : warning ? 'warning' : operation.state === 'succeeded' ? 'success' : 'info';
    var icon = active ? 'fas fa-circle-notch fa-spin' : variant === 'error' || variant === 'warning' ? 'fas fa-exclamation-circle' : 'fas fa-check';
    var detail = '';
    if (active && operationsStatusError) {
      detail = operationsStatusError;
    } else if (operation.state === 'queued') {
      detail = t('operations.queue_hint', 'Waiting for earlier changes on this server.');
    } else if (operation.state === 'running' && operation.phase === 'applying' &&
        Object.values(operation.desiredStates || {}).some(function(enabled) { return !enabled; })) {
      detail = t('operations.toast.stopping', 'Removing existing bans. This can take a few minutes.');
    }
    var result = operation.result || {};
    var html = '<div class="flex items-start gap-3">'
      + '<i class="' + icon + ' mt-1" aria-hidden="true"></i>'
      + '<div class="flex-1 min-w-0">'
      + '<div class="text-sm font-semibold break-words">' + escapeHtml(operationToastTitle(operation)) + '</div>'
      + '<div class="text-xs opacity-80 mt-1">' + escapeHtml(server ? server.name : operation.serverId)
      + ' · ' + escapeHtml(operationStateLabel(operation.state))
      + ' <span aria-hidden="true" data-operation-elapsed="' + escapeHtml(id) + '"></span></div>'
      + (detail ? '<p class="text-xs mt-2 break-words">' + escapeHtml(detail) + '</p>' : '')
      + (operation.error ? '<p class="text-xs mt-2 break-words">' + escapeHtml(operation.error) + '</p>' : '')
      + (warning ? '<p class="text-xs mt-2 break-words">' + escapeHtml(warning) + '</p>' : '')
      + (result.configurationRestored ? '<p class="text-xs mt-2 break-words">' + escapeHtml(result.message || t('operations.configuration_restored', 'The original configuration was restored.')) + '</p>' : '')
      + (operationCanCancel(operation) ? '<button type="button" class="mt-2 text-xs underline opacity-80 hover:opacity-100" data-cancel-operation="' + escapeHtml(id) + '">' + escapeHtml(t('operations.cancel_queued', 'Cancel queued task')) + '</button>' : '')
      + '</div>'
      + (!active ? '<button type="button" class="flex-shrink-0 opacity-60 hover:opacity-100" data-dismiss-operation="' + escapeHtml(id) + '" aria-label="' + escapeHtml(t('modal.close', 'Close')) + '"><i class="fas fa-times text-sm" aria-hidden="true"></i></button>' : '')
      + '</div>';
    var banEvent = operationBanEvent(operation);
    if (operation.state === 'succeeded' && !warning && banEvent) {
      variant = banEvent.eventType === 'unban' ? 'unban-event' : 'ban-event';
      html = banEventToastHTML(notice.banEvent || banEvent, id);
    }
    if (!notice.element) {
      notice.element = document.createElement('div');
      notice.element.setAttribute('data-operation-id', id);
      notice.element.setAttribute('role', 'status');
      list.appendChild(notice.element);
    }
    notice.element.className = 'toast toast-' + variant + ' show';
    // Keep controls/focus and live announcements stable across identical polls.
    if (notice.html !== html) {
      notice.element.innerHTML = html;
      notice.html = html;
    }
  });
  updateOperationElapsed();
}

function settleOperation(operation) {
  if (operationIsActive(operation)) return;
  var waiters = operationWaiters[operation.id] || [];
  delete operationWaiters[operation.id];
  waiters.forEach(function(waiter) {
    if (operation.state === 'succeeded') {
      var result = Object.assign({}, operation.result || {});
      Object.defineProperty(result, 'operationId', { value: operation.id });
      waiter.resolve(result);
    } else {
      var error = new Error(operation.error || operation.message || operationStateLabel(operation.state));
      error.data = operation.result;
      error.operation = operation;
      waiter.reject(error);
    }
  });
}

function receiveOperation(operation, options) {
  if (!operationsStarted && operationsGeneration > 0) return;
  if (!operation || !operation.id) return;
  options = options || {};
  var previous = operationsById[operation.id];
  // Poll snapshots can race WebSocket updates; never move a terminal task back
  // to running or replace newer state with an older observation.
  if (previous && ((!operationIsActive(previous) && operationIsActive(operation)) ||
      (previous.updatedAt && operation.updatedAt && Date.parse(previous.updatedAt) > Date.parse(operation.updatedAt)))) return;
  operationsById[operation.id] = operation;
  if (operationIsActive(operation) || !options.history || operationNotices[operation.id]) showOperationNotice(operation);
  settleOperation(operation);
  if (previous && operationIsActive(previous) && !operationIsActive(operation)) {
    if (typeof loadServers === 'function') loadServers();
    if (operation.serverId === currentServerId && typeof fetchSummaryData === 'function') fetchSummaryData().then(scheduleRender);
  }
  if (!options.batch) {
    renderOperations();
    if (typeof updateJailChangeProgress === 'function') updateJailChangeProgress();
    if (typeof updateStatusIndicator === 'function') updateStatusIndicator();
  }
}

function waitForOperation(operation) {
  if (!operationsStarted && operationsGeneration > 0) {
    // A delayed acceptance from the previous session must not restore its UI.
    var error = new Error('Session ended');
    error.operation = operation;
    return Promise.reject(error);
  }
  var promise = new Promise(function(resolve, reject) {
    (operationWaiters[operation.id] = operationWaiters[operation.id] || []).push({ resolve: resolve, reject: reject });
  });
  receiveOperation(operation);
  showOperationNotice(operationsById[operation.id]);
  renderOperations();
  // The operation may already have completed via the WebSocket before its
  // original acceptance response arrived.
  settleOperation(operationsById[operation.id]);
  scheduleOperationsPoll(1000);
  return promise;
}

function scheduleOperationsPoll(delay) {
  if (!operationsStarted) return;
  clearTimeout(operationsPollTimer);
  operationsPollTimer = setTimeout(function() { refreshOperations(); }, delay);
}

function refreshOperations() {
  if (!operationsStarted && operationsGeneration > 0) return Promise.resolve();
  if (operationsRefreshPromise) return operationsRefreshPromise;
  var generation = operationsGeneration;
  operationsRefreshPromise = fetch(appPath('/api/operations'))
    .then(readJsonResponse)
    .then(function(data) {
      if (generation !== operationsGeneration) return;
      if (!data || !Array.isArray(data.operations)) throw new Error(t('common.invalid_response', 'Unexpected response from the server'));
      operationsStatusError = '';
      data.operations.forEach(function(operation) { receiveOperation(operation, { batch: true, history: true }); });
      // Preserve uncompleted tasks if the listing is temporarily partial.
      // Their state must be confirmed through their individual endpoint.
      var returned = new Set(data.operations.map(function(operation) { return operation.id; }));
      return Promise.all(activeServerOperations().filter(function(operation) { return !returned.has(operation.id); }).map(function(operation) {
        return fetch(appPath('/api/operations/' + encodeURIComponent(operation.id))).then(readJsonResponse).then(function(result) {
          if (generation !== operationsGeneration) return;
          if (result && result.operation) receiveOperation(result.operation, { batch: true, history: true });
        });
      }));
    })
    .catch(function(err) {
      if (generation !== operationsGeneration) return;
      operationsStatusError = t('operations.status_unavailable', 'Connection lost. Progress will update when reconnected.');
    })
    .finally(function() {
      if (generation !== operationsGeneration) return;
      operationsRefreshPromise = null;
      renderOperations();
      if (typeof updateJailChangeProgress === 'function') updateJailChangeProgress();
      if (typeof updateStatusIndicator === 'function') updateStatusIndicator();
      scheduleOperationsPoll(activeServerOperations().length ? 3000 : 15000);
      if (activeServerOperations(currentServerId).length && typeof fetchSummaryData === 'function') fetchSummaryData().then(scheduleRender);
    });
  return operationsRefreshPromise;
}

function cancelQueuedOperation(id) {
  var operation = operationsById[id];
  if (!operation || !operationCanCancel(operation)) return;
  var generation = operationsGeneration;
  fetch(appPath('/api/operations/' + encodeURIComponent(id) + '/cancel'), { method: 'POST' })
    .then(readJsonResponse)
    .then(function(data) {
      if (generation !== operationsGeneration) return;
      if (data && data.operation) receiveOperation(data.operation);
      refreshOperations();
    })
    .catch(function(err) {
      if (generation !== operationsGeneration) return;
      showToast(err.message || String(err), 'error');
      refreshOperations();
    });
}

function initOperations() {
  if (operationsStarted) return;
  operationsStarted = true;
  if (typeof summaryPollingEnabled !== 'undefined') summaryPollingEnabled = true;
  var list = document.getElementById('operation-toasts');
  if (list) list.onclick = function(event) {
    var button = event.target.closest('[data-cancel-operation]');
    if (button) cancelQueuedOperation(button.getAttribute('data-cancel-operation'));
    var close = event.target.closest('[data-dismiss-operation]');
    if (close) dismissOperationToast(close.getAttribute('data-dismiss-operation'));
    if (button || close) return;
    var toast = event.target.closest('[data-operation-id]');
    var operation = toast && operationsById[toast.getAttribute('data-operation-id')];
    if (operation && operation.state === 'succeeded' && operationBanEvent(operation)) {
      var logSection = document.getElementById('logOverview');
      if (logSection) logSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };
  var generation = operationsGeneration;
  wsManager.on('operation', function(operation) {
    if (operationsStarted && generation === operationsGeneration) receiveOperation(operation);
  });
  wsManager.on('reconnected', function() {
    if (!operationsStarted || generation !== operationsGeneration) return;
    refreshOperations();
    if (typeof fetchSummaryData === 'function') fetchSummaryData().then(scheduleRender);
  });
  operationsClockTimer = setInterval(updateOperationElapsed, 1000);
  refreshOperations();
}

function stopOperations() {
  operationsStarted = false;
  operationsGeneration++;
  operationsRefreshPromise = null;
  clearTimeout(operationsPollTimer);
  clearInterval(operationsClockTimer);
  if (typeof summaryRefreshTimer !== 'undefined') clearTimeout(summaryRefreshTimer);
  if (typeof summaryPollingEnabled !== 'undefined') summaryPollingEnabled = false;
  Object.values(operationNotices).forEach(function(notice) {
    clearTimeout(notice.timer);
    if (notice.element) notice.element.remove();
  });
  operationNotices = Object.create(null);
  operationsById = Object.create(null);
  operationWaiters = Object.create(null);
  operationsStatusError = '';
  recentBanEventToasts.forEach(function(record) { if (record.removeToast) record.removeToast(); });
  recentBanEventToasts = [];
}
