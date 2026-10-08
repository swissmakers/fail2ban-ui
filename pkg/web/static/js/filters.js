// Filter debug functions for Fail2ban UI
"use strict";

// =========================================================================
//  Filter creation
// =========================================================================

function createFilter() {
  var actionServerId = currentServerId;
  const filterName = document.getElementById('newFilterName').value.trim();
  const content = document.getElementById('newFilterContent').value.trim();

  if (!filterName) {
    showToast(t('filters.toast.name_required', 'Filter name is required'), 'error');
    return;
  }

  fetch(withServerParam('/api/filters'), {
    method: 'POST',
    headers: serverHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      filterName: filterName,
      content: content
    })
  })
    .then(function(res) {
      if (res.status === 202 && currentServerId === actionServerId) closeModal('createFilterModal');
      return readJsonResponse(res);
    })
    .then(function(data) {
      if (!data.operationId) showToast(apiMessage(data, 'filters.toast.create_success', 'Filter created successfully'), 'success');
      if (currentServerId === actionServerId) loadFilters();
    })
    .catch(function(err) {
      console.error('Error creating filter:', err);
      if (!err.operation) showToast(t('filters.toast.create_error', 'Error creating filter') + ': ' + err.message, 'error');
    });
}

// =========================================================================
//  Filter Loading
// =========================================================================

function loadFilters() {
  showLoading(true);
  fetch(withServerParam('/api/filters'), {
    headers: serverHeaders()
  })
    .then(readJsonResponse)
    .then(data => {
      data = data || {};
      const select = document.getElementById('filterSelect');
      const notice = document.getElementById('filterNotice');
      if (notice) {
        if (data.messageKey) {
          notice.classList.remove('hidden');
          notice.textContent = t(data.messageKey, data.message || '');
        } else {
          notice.classList.add('hidden');
          notice.textContent = '';
        }
      }
      select.innerHTML = '';
      const deleteBtn = document.getElementById('deleteFilterBtn');
      if (!data.filters || data.filters.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = t('filter_debug.no_filters', 'No filters found');
        select.appendChild(opt);
        if (deleteBtn) deleteBtn.disabled = true;
      } else {
        data.filters.forEach(f => {
          const opt = document.createElement('option');
          opt.value = f;
          opt.textContent = f;
          select.appendChild(opt);
        });
        if (deleteBtn) deleteBtn.disabled = !select.value;
        if (select.value) {
          loadFilterContent(select.value);
        }
      }
    })
    .catch(err => {
      showToast(t('filters.toast.load_error', 'Error loading filters') + ': ' + err.message, 'error');
    })
    .finally(() => showLoading(false));
}

function loadFilterContent(filterName) {
  const filterContentTextarea = document.getElementById('filterContentTextarea');
  const editBtn = document.getElementById('editFilterContentBtn');
  if (!filterContentTextarea) return;

  showLoading(true);
  fetch(withServerParam('/api/filters/' + encodeURIComponent(filterName) + '/content'), {
    headers: serverHeaders()
  })
    .then(readJsonResponse)
    .then(data => {
      filterContentTextarea.value = (data && data.content) || '';
      setFilterEditMode(false);
      if (editBtn) editBtn.classList.remove('hidden');
    })
    .catch(err => {
      showToast(t('filters.toast.load_content_error', 'Error loading filter content') + ': ' + err.message, 'error');
      resetFilterContentView();
    })
    .finally(() => showLoading(false));
}

// Empty, read-only filter editor without the edit button.
function resetFilterContentView() {
  const filterContentTextarea = document.getElementById('filterContentTextarea');
  const editBtn = document.getElementById('editFilterContentBtn');
  if (filterContentTextarea) {
    filterContentTextarea.value = '';
  }
  setFilterEditMode(false);
  if (editBtn) editBtn.classList.add('hidden');
}

// =========================================================================
//  Filter Editing (on the filter section)
// =========================================================================

// Edits in the filter section are only used for the test run, never saved.
function setFilterEditMode(editable) {
  const filterContentTextarea = document.getElementById('filterContentTextarea');
  const editBtn = document.getElementById('editFilterContentBtn');
  if (filterContentTextarea) {
    filterContentTextarea.readOnly = !editable;
    filterContentTextarea.classList.toggle('bg-gray-50', !editable);
    filterContentTextarea.classList.toggle('bg-white', editable);
  }
  if (editBtn) {
    if (editable) {
      setI18nText(editBtn, 'filter_debug.cancel_edit', 'Cancel');
    } else {
      setI18nText(editBtn, 'filter_debug.edit_filter', 'Edit');
    }
    editBtn.classList.toggle('bg-gray-600', editable);
    editBtn.classList.toggle('hover:bg-gray-700', editable);
    editBtn.classList.toggle('bg-blue-600', !editable);
    editBtn.classList.toggle('hover:bg-blue-700', !editable);
  }
  updateFilterContentHints(editable);
}

function toggleFilterContentEdit() {
  const filterContentTextarea = document.getElementById('filterContentTextarea');
  if (filterContentTextarea) {
    setFilterEditMode(filterContentTextarea.readOnly);
  }
}

function updateFilterContentHints(isEditable) {
  const readonlyHint = document.querySelector('p[data-i18n="filter_debug.filter_content_hint_readonly"]');
  const editableHint = document.getElementById('filterContentHintEditable');
  if (readonlyHint) readonlyHint.classList.toggle('hidden', isEditable);
  if (editableHint) editableHint.classList.toggle('hidden', !isEditable);
}

// =========================================================================
//  Filter deletion
// =========================================================================

function deleteFilter() {
  var actionServerId = currentServerId;
  const filterName = document.getElementById('filterSelect').value;
  if (!filterName) {
    showToast(t('filters.toast.select_delete', 'Please select a filter to delete'), 'info');
    return;
  }

  if (!confirm(t('filters.confirm.delete', 'Are you sure you want to delete the filter "{name}"? This action cannot be undone.').replace('{name}', filterName))) {
    return;
  }
  fetch(withServerParam('/api/filters/' + encodeURIComponent(filterName)), {
    method: 'DELETE',
    headers: serverHeaders()
  })
    .then(readJsonResponse)
    .then(function(data) {
      if (!data.operationId) showToast(apiMessage(data, 'filters.toast.delete_success', 'Filter deleted successfully'), 'success');
      if (currentServerId !== actionServerId) return;
      loadFilters();
      document.getElementById('testResults').innerHTML = '';
      document.getElementById('testResults').classList.add('hidden');
      document.getElementById('logLinesTextarea').value = '';
      resetFilterContentView();
    })
    .catch(function(err) {
      console.error('Error deleting filter:', err);
      if (!err.operation) showToast(t('filters.toast.delete_error', 'Error deleting filter') + ': ' + err.message, 'error');
    });
}

// =========================================================================
//  Filter Testing
// =========================================================================

function testSelectedFilter() {
  const filterName = document.getElementById('filterSelect').value;
  const lines = document.getElementById('logLinesTextarea').value.split('\n').filter(line => line.trim() !== '');
  const filterContentTextarea = document.getElementById('filterContentTextarea');
  
  if (!filterName) {
    showToast(t('filters.toast.select_filter', 'Please select a filter.'), 'info');
    return;
  }
  if (lines.length === 0) {
    showToast(t('filters.toast.enter_log_lines', 'Please enter at least one log line to test.'), 'info');
    return;
  }
  const testResultsEl = document.getElementById('testResults');
  testResultsEl.classList.add('hidden');
  testResultsEl.innerHTML = '';
  showLoading(true);
  const requestBody = {
    filterName: filterName,
    logLines: lines
  };
  if (filterContentTextarea && !filterContentTextarea.readOnly) {
    const filterContent = filterContentTextarea.value.trim();
    if (filterContent) {
      requestBody.filterContent = filterContent;
    }
  }
  fetch(withServerParam('/api/filters/test'), {
    method: 'POST',
    headers: serverHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(requestBody)
  })
    .then(readJsonResponse)
    .then(data => {
      data = data || {};
      renderTestResults(data.output || '', data.filterPath || '');
    })
    .catch(err => {
      showToast(t('filters.toast.test_error', 'Error testing filter') + ': ' + err.message, 'error');
    })
    .finally(() => showLoading(false));
}

function renderTestResults(output, filterPath) {
  const testResultsEl = document.getElementById('testResults');
  let html = '<h5 class="text-lg font-medium text-white mb-4" data-i18n="filter_debug.test_results_title">Test Results</h5>';

  if (filterPath) {
    html += '<div class="mb-3 p-2 bg-gray-800 rounded text-sm">';
    html += '<span class="text-gray-400">' + escapeHtml(t('filter_debug.used_filter', 'Used Filter:')) + '</span> ';
    html += '<span class="text-yellow-300 font-mono">' + escapeHtml(filterPath) + '</span>';
    html += '</div>';
  }
  if (!output || output.trim() === '') {
    html += '<p class="text-gray-400" data-i18n="filter_debug.no_matches">No output received.</p>';
  } else {
    html += '<pre class="text-white whitespace-pre-wrap overflow-x-auto">' + escapeHtml(output) + '</pre>';
  }
  testResultsEl.innerHTML = html;
  testResultsEl.classList.remove('hidden');
  updateTranslations();
}

// =========================================================================
//  Filter Section Init
// =========================================================================

function showFilterSection() {
  const testResultsEl = document.getElementById('testResults');
  testResultsEl.innerHTML = '';
  testResultsEl.classList.add('hidden');
  document.getElementById('logLinesTextarea').value = '';
  resetFilterContentView();
  if (!currentServerId) {
    var notice = document.getElementById('filterNotice');
    if (notice) {
      notice.classList.remove('hidden');
      notice.textContent = t('filter_debug.not_available', 'Filter debug is only available when a Fail2ban server is selected.');
    }
    document.getElementById('filterSelect').innerHTML = '';
    document.getElementById('deleteFilterBtn').disabled = true;
    return;
  }
  loadFilters();
}

const filterSelectElement = document.getElementById('filterSelect');
if (filterSelectElement) {
  filterSelectElement.addEventListener('change', function() {
    document.getElementById('deleteFilterBtn').disabled = !filterSelectElement.value;
    if (filterSelectElement.value) {
      loadFilterContent(filterSelectElement.value);
    } else {
      resetFilterContentView();
    }
  });
}
