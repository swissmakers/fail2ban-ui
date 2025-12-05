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
      if (!data.filters || data.filters.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'No Filters Found';
        select.appendChild(opt);
      } else {
        data.filters.forEach(f => {
          const opt = document.createElement('option');
          opt.value = f;
          opt.textContent = f;
          select.appendChild(opt);
        });
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
      renderTestResults(data.output || '');
    })
    .catch(err => {
      showToast('Error testing filter: ' + err, 'error');
    })
    .finally(() => showLoading(false));
}

function renderTestResults(output) {
  const testResultsEl = document.getElementById('testResults');
  let html = '<h5 class="text-lg font-medium text-white mb-4" data-i18n="filter_debug.test_results_title">Test Results</h5>';
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
    return;
  }
  loadFilters();
  testResultsEl.innerHTML = '';
  testResultsEl.classList.add('hidden');
  document.getElementById('logLinesTextarea').value = '';
}

