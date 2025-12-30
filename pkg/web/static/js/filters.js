// Filter debug functions for Fail2ban UI
"use strict";

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
        // Add change listener if not already added
        if (!select.hasAttribute('data-listener-added')) {
          select.setAttribute('data-listener-added', 'true');
          select.addEventListener('change', function() {
            if (deleteBtn) deleteBtn.disabled = !select.value;
          });
        }
        if (deleteBtn) deleteBtn.disabled = !select.value;
      }
    })
    .catch(err => {
      showToast('Error loading filters: ' + err, 'error');
    })
    .finally(() => showLoading(false));
}

function testSelectedFilter() {
  const filterName = document.getElementById('filterSelect').value;
  const lines = document.getElementById('logLinesTextarea').value.split('\n').filter(line => line.trim() !== '');
  
  if (!filterName) {
    showToast('Please select a filter.', 'info');
    return;
  }

  if (lines.length === 0) {
    showToast('Please enter at least one log line to test.', 'info');
    return;
  }

  // Hide results initially
  const testResultsEl = document.getElementById('testResults');
  testResultsEl.classList.add('hidden');
  testResultsEl.innerHTML = '';

  showLoading(true);
  fetch(withServerParam('/api/filters/test'), {
    method: 'POST',
    headers: serverHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      filterName: filterName,
      logLines: lines
    })
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
  
  // Show which filter file was used
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

function showFilterSection() {
  const testResultsEl = document.getElementById('testResults');
  if (!currentServerId) {
    var notice = document.getElementById('filterNotice');
    if (notice) {
      notice.classList.remove('hidden');
      notice.textContent = t('filter_debug.not_available', 'Filter debug is only available when a Fail2ban server is selected.');
    }
    document.getElementById('filterSelect').innerHTML = '';
    document.getElementById('logLinesTextarea').value = '';
    testResultsEl.innerHTML = '';
    testResultsEl.classList.add('hidden');
    document.getElementById('deleteFilterBtn').disabled = true;
    return;
  }
  loadFilters();
  testResultsEl.innerHTML = '';
  testResultsEl.classList.add('hidden');
  document.getElementById('logLinesTextarea').value = '';
  // Add change listener to enable/disable delete button
  const filterSelect = document.getElementById('filterSelect');
  const deleteBtn = document.getElementById('deleteFilterBtn');
  filterSelect.addEventListener('change', function() {
    deleteBtn.disabled = !filterSelect.value;
  });
}

function openCreateFilterModal() {
  document.getElementById('newFilterName').value = '';
  document.getElementById('newFilterContent').value = '';
  openModal('createFilterModal');
}

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
      // Reload filters
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
      // Reload filters
      loadFilters();
      // Clear test results
      document.getElementById('testResults').innerHTML = '';
      document.getElementById('testResults').classList.add('hidden');
      document.getElementById('logLinesTextarea').value = '';
    })
    .catch(function(err) {
      console.error('Error deleting filter:', err);
      showToast('Error deleting filter: ' + (err.message || err), 'error');
    })
    .finally(function() {
      showLoading(false);
    });
}

