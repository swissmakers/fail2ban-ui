// Filter debug functions for Fail2ban UI
"use strict";

// =========================================================================
//  Filter creation
// =========================================================================

function createFilter() {
  const filterName = document.getElementById('newFilterName').value.trim();
  const content = document.getElementById('newFilterContent').value.trim();

  if (!filterName) {
    showToast('Filter name is required', 'error');
    return;
  }

  showLoading(true);
  fetch(withServerParam('/api/filters'), {
    method: 'POST',
    headers: serverHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      filterName: filterName,
      content: content
    })
  })
    .then(function(res) {
      if (!res.ok) {
        return res.json().then(function(data) {
          throw new Error(data.error || 'Server returned ' + res.status);
        });
      }
      return res.json();
    })
    .then(function(data) {
      if (data.error) {
        showToast('Error creating filter: ' + data.error, 'error');
        return;
      }
      closeModal('createFilterModal');
      showToast(data.message || 'Filter created successfully', 'success');
      loadFilters();
    })
    .catch(function(err) {
      console.error('Error creating filter:', err);
      showToast('Error creating filter: ' + (err.message || err), 'error');
    })
    .finally(function() {
      showLoading(false);
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
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        showToast('Error loading filters: ' + data.error, 'error');
        return;
      }
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
        opt.textContent = 'No Filters Found';
        select.appendChild(opt);
        if (deleteBtn) deleteBtn.disabled = true;
      } else {
        data.filters.forEach(f => {
          const opt = document.createElement('option');
          opt.value = f;
          opt.textContent = f;
          select.appendChild(opt);
        });
        if (!select.hasAttribute('data-listener-added')) {
          select.setAttribute('data-listener-added', 'true');
          select.addEventListener('change', function() {
            if (deleteBtn) deleteBtn.disabled = !select.value;
            if (select.value) {
              loadFilterContent(select.value);
            } else {
              const filterContentTextarea = document.getElementById('filterContentTextarea');
              const editBtn = document.getElementById('editFilterContentBtn');
              if (filterContentTextarea) {
                filterContentTextarea.value = '';
                filterContentTextarea.readOnly = true;
                filterContentTextarea.classList.add('bg-gray-50');
                filterContentTextarea.classList.remove('bg-white');
              }
              if (editBtn) editBtn.classList.add('hidden');
              updateFilterContentHints(false);
            }
          });
        }
        if (deleteBtn) deleteBtn.disabled = !select.value;
        if (select.value) {
          loadFilterContent(select.value);
        }
      }
    })
    .catch(err => {
      showToast('Error loading filters: ' + err, 'error');
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
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        showToast('Error loading filter content: ' + data.error, 'error');
        filterContentTextarea.value = '';
        filterContentTextarea.readOnly = true;
        if (editBtn) editBtn.classList.add('hidden');
        updateFilterContentHints(false);
        return;
      }
      filterContentTextarea.value = data.content || '';
      filterContentTextarea.readOnly = true;
      filterContentTextarea.classList.add('bg-gray-50');
      filterContentTextarea.classList.remove('bg-white');
      if (editBtn) editBtn.classList.remove('hidden');
      updateFilterContentHints(false);
    })
    .catch(err => {
      showToast('Error loading filter content: ' + err, 'error');
      filterContentTextarea.value = '';
      filterContentTextarea.readOnly = true;
      if (editBtn) editBtn.classList.add('hidden');
      updateFilterContentHints(false);
    })
    .finally(() => showLoading(false));
}

// =========================================================================
//  Filter Editing (on the filter section)
// =========================================================================

function toggleFilterContentEdit() {
  const filterContentTextarea = document.getElementById('filterContentTextarea');
  const editBtn = document.getElementById('editFilterContentBtn');
  if (!filterContentTextarea) return;
  if (filterContentTextarea.readOnly) {
    filterContentTextarea.readOnly = false;
    filterContentTextarea.classList.remove('bg-gray-50');
    filterContentTextarea.classList.add('bg-white');
    if (editBtn) {
      editBtn.textContent = t('filter_debug.cancel_edit', 'Cancel');
      editBtn.classList.remove('bg-blue-600', 'hover:bg-blue-700');
      editBtn.classList.add('bg-gray-600', 'hover:bg-gray-700');
    }
    updateFilterContentHints(true);
  } else {
    filterContentTextarea.readOnly = true;
    filterContentTextarea.classList.add('bg-gray-50');
    filterContentTextarea.classList.remove('bg-white');
    if (editBtn) {
      editBtn.textContent = t('filter_debug.edit_filter', 'Edit');
      editBtn.classList.remove('bg-gray-600', 'hover:bg-gray-700');
      editBtn.classList.add('bg-blue-600', 'hover:bg-blue-700');
    }
    updateFilterContentHints(false);
  }
}

function updateFilterContentHints(isEditable) {
  const readonlyHint = document.querySelector('p[data-i18n="filter_debug.filter_content_hint_readonly"]');
  const editableHint = document.getElementById('filterContentHintEditable');

  if (isEditable) {
    if (readonlyHint) readonlyHint.classList.add('hidden');
    if (editableHint) editableHint.classList.remove('hidden');
  } else {
    if (readonlyHint) readonlyHint.classList.remove('hidden');
    if (editableHint) editableHint.classList.add('hidden');
  }
  if (typeof updateTranslations === 'function') {
    updateTranslations();
  }
}

// =========================================================================
//  Filter deletion
// =========================================================================

function deleteFilter() {
  const filterName = document.getElementById('filterSelect').value;
  if (!filterName) {
    showToast('Please select a filter to delete', 'info');
    return;
  }

  if (!confirm('Are you sure you want to delete the filter "' + escapeHtml(filterName) + '"? This action cannot be undone.')) {
    return;
  }
  showLoading(true);
  fetch(withServerParam('/api/filters/' + encodeURIComponent(filterName)), {
    method: 'DELETE',
    headers: serverHeaders()
  })
    .then(function(res) {
      if (!res.ok) {
        return res.json().then(function(data) {
          throw new Error(data.error || 'Server returned ' + res.status);
        });
      }
      return res.json();
    })
    .then(function(data) {
      if (data.error) {
        showToast('Error deleting filter: ' + data.error, 'error');
        return;
      }
      showToast(data.message || 'Filter deleted successfully', 'success');
      loadFilters();
      document.getElementById('testResults').innerHTML = '';
      document.getElementById('testResults').classList.add('hidden');
      document.getElementById('logLinesTextarea').value = '';
      const filterContentTextarea = document.getElementById('filterContentTextarea');
      const editBtn = document.getElementById('editFilterContentBtn');
      if (filterContentTextarea) {
        filterContentTextarea.value = '';
        filterContentTextarea.readOnly = true;
        filterContentTextarea.classList.add('bg-gray-50');
        filterContentTextarea.classList.remove('bg-white');
      }
      if (editBtn) editBtn.classList.add('hidden');
      updateFilterContentHints(false);
    })
    .catch(function(err) {
      console.error('Error deleting filter:', err);
      showToast('Error deleting filter: ' + (err.message || err), 'error');
    })
    .finally(function() {
      showLoading(false);
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
    showToast('Please select a filter.', 'info');
    return;
  }
  if (lines.length === 0) {
    showToast('Please enter at least one log line to test.', 'info');
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
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        showToast('Error testing filter: ' + data.error, 'error');
        return;
      }
      renderTestResults(data.output || '', data.filterPath || '');
    })
    .catch(err => {
      showToast('Error testing filter: ' + err, 'error');
    })
    .finally(() => showLoading(false));
}

function renderTestResults(output, filterPath) {
  const testResultsEl = document.getElementById('testResults');
  let html = '<h5 class="text-lg font-medium text-white mb-4" data-i18n="filter_debug.test_results_title">Test Results</h5>';

  if (filterPath) {
    html += '<div class="mb-3 p-2 bg-gray-800 rounded text-sm">';
    html += '<span class="text-gray-400">Used Filter (exact file):</span> ';
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
  if (typeof updateTranslations === 'function') {
    updateTranslations();
  }
}

// =========================================================================
//  Filter Section Init
// =========================================================================

function showFilterSection() {
  const testResultsEl = document.getElementById('testResults');
  const filterContentTextarea = document.getElementById('filterContentTextarea');
  if (!currentServerId) {
    var notice = document.getElementById('filterNotice');
    if (notice) {
      notice.classList.remove('hidden');
      notice.textContent = t('filter_debug.not_available', 'Filter debug is only available when a Fail2ban server is selected.');
    }
    document.getElementById('filterSelect').innerHTML = '';
    document.getElementById('logLinesTextarea').value = '';
    if (filterContentTextarea) {
      filterContentTextarea.value = '';
      filterContentTextarea.readOnly = true;
    }
    testResultsEl.innerHTML = '';
    testResultsEl.classList.add('hidden');
    document.getElementById('deleteFilterBtn').disabled = true;
    return;
  }
  loadFilters();
  testResultsEl.innerHTML = '';
  testResultsEl.classList.add('hidden');
  document.getElementById('logLinesTextarea').value = '';
  const editBtn = document.getElementById('editFilterContentBtn');
  if (filterContentTextarea) {
    filterContentTextarea.value = '';
    filterContentTextarea.readOnly = true;
    filterContentTextarea.classList.add('bg-gray-50');
    filterContentTextarea.classList.remove('bg-white');
  }
  if (editBtn) editBtn.classList.add('hidden');
  updateFilterContentHints(false);
  const filterSelect = document.getElementById('filterSelect');
  const deleteBtn = document.getElementById('deleteFilterBtn');
  if (!filterSelect.hasAttribute('data-listener-added')) {
    filterSelect.setAttribute('data-listener-added', 'true');
    filterSelect.addEventListener('change', function() {
      deleteBtn.disabled = !filterSelect.value;
      if (filterSelect.value) {
        loadFilterContent(filterSelect.value);
      } else {
        const editBtn = document.getElementById('editFilterContentBtn');
        if (filterContentTextarea) {
          filterContentTextarea.value = '';
          filterContentTextarea.readOnly = true;
          filterContentTextarea.classList.add('bg-gray-50');
          filterContentTextarea.classList.remove('bg-white');
        }
        if (editBtn) editBtn.classList.add('hidden');
        updateFilterContentHints(false);
      }
    });
  }
}
