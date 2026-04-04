"use strict";

function fetchThreatIntelData(ip) {
  return fetch(appPath('/api/threat-intel/' + encodeURIComponent(ip)), { method: 'GET' })
    .then(function(res) {
      if (!res.ok) {
        return res.json()
          .then(function(payload) {
            var apiError = payload && payload.error ? String(payload.error) : '';
            var message = apiError || (t('threat.modal.error_http', 'Threat intelligence request failed') + ' (' + res.status + ')');
            throw new Error(message);
          })
          .catch(function(parseErr) {
            if (parseErr instanceof Error) {
              throw parseErr;
            }
            throw new Error(t('threat.modal.error_http', 'Threat intelligence request failed') + ' (' + res.status + ')');
          });
      }
      return res.json();
    });
}

function renderThreatIntelData(data, selectedIP) {
  var content = document.getElementById('threatIntelContent');
  if (!content) {
    return;
  }
  setThreatIntelContentState();
  var provider = String(data.provider || '').toLowerCase();
  var providerData = data.data || {};
  var html = '';
  if (provider === 'abuseipdb') {
    html = renderAbuseIPDBThreatIntel(providerData, selectedIP);
  } else if (provider === 'alienvault') {
    html = renderAlienVaultThreatIntel(providerData, selectedIP);
  } else {
    html = '<section class="threat-intel-section"><h4>' + escapeHtml(t('threat.modal.provider_unknown', 'Unknown provider')) + '</h4>'
      + '<pre class="threat-intel-raw">' + escapeHtml(JSON.stringify(providerData, null, 2)) + '</pre></section>';
  }
  content.innerHTML = html;
  if (typeof updateTranslations === 'function') {
    updateTranslations();
  }
}

function renderAlienVaultThreatIntel(payload, selectedIP) {
  var pulses = payload && payload.pulse_info && Array.isArray(payload.pulse_info.pulses) ? payload.pulse_info.pulses.slice() : [];
  pulses.sort(function(a, b) { return tiTimestamp(b && b.modified) - tiTimestamp(a && a.modified); });
  var pulseSection = buildThreatIntelCollapsibleEntries(
    pulses.map(function(pulse, idx) {
      return renderOtxPulseItem(pulse, selectedIP, idx);
    }),
    selectedIP,
    'alienvault-pulses'
  );

  var pulseCount = payload && payload.pulse_info ? payload.pulse_info.count : 0;
  var reputation = payload ? payload.reputation : '';
  var riskLabel = tiAlienVaultRiskLabel(reputation, pulseCount);
  var references = payload && payload.pulse_info && Array.isArray(payload.pulse_info.references) ? payload.pulse_info.references : [];
  var validations = Array.isArray(payload && payload.validation) ? payload.validation : [];
  var relatedOther = payload && payload.pulse_info && payload.pulse_info.related && payload.pulse_info.related.other ? payload.pulse_info.related.other : {};
  var relatedIndustries = Array.isArray(relatedOther.industries) ? relatedOther.industries : [];
  var relatedAdversary = Array.isArray(relatedOther.adversary) ? relatedOther.adversary : [];
  var relatedMalware = Array.isArray(relatedOther.malware_families) ? relatedOther.malware_families : [];

  var html = '';
  html += renderThreatIntelHero({
    ip: payload && payload.indicator ? payload.indicator : selectedIP,
    provider: t('threat.provider.alienvault', 'AlienVault OTX'),
    riskLabel: riskLabel,
    riskClass: tiClassForReputation(riskLabel),
    cards: [
      { label: t('threat.metric.pulses', 'Pulses'), value: tiValue(pulseCount) },
      { label: t('threat.metric.country', 'Country'), value: tiValue(payload && (payload.country_name || payload.country_code)) },
      { label: t('threat.field.city', 'City'), value: tiValue(payload && payload.city) },
      { label: t('threat.metric.asn', 'ASN'), value: tiValue(payload && payload.asn) }
    ]
  });

  html += '<section class="threat-intel-section"><h4>' + escapeHtml(t('threat.section.overview', 'Overview')) + '</h4><div class="threat-intel-grid" style="margin-bottom: 0.9rem;">';
  html += threatIntelDetailCard(t('threat.field.continent', 'Continent'), tiValue(payload && payload.continent_code));
  html += threatIntelDetailCard(t('threat.field.latitude', 'Latitude'), tiValue(payload && payload.latitude));
  html += threatIntelDetailCard(t('threat.field.longitude', 'Longitude'), tiValue(payload && payload.longitude));
  html += threatIntelDetailCard(t('threat.field.subdivision', 'Subdivision'), tiValue(payload && payload.subdivision));
  html += '</div>';

  if (validations.length) {
    html += buildThreatIntelCollapsibleEntries(
      validations.map(function(v, idx) {
        var source = t('threat.field.validation_source', 'Source') + ': ' + tiValue(v && v.source);
        var name = t('threat.field.validation_name', 'Rule') + ': ' + tiValue(v && v.name);
        var detail = source + ' | ' + name;
        var msg = tiRichTextBlock(v && v.message, selectedIP + '-otx-validation', idx, 220);
        return '<div class="rounded-md border border-gray-200 bg-white p-2">'
          + '<p class="text-xs font-semibold text-gray-700">' + escapeHtml(detail) + '</p>'
          + msg
          + '</div>';
      }),
      selectedIP,
      'alienvault-validation'
    );
  }
  html += '</section>';

  html += '<section class="threat-intel-section"><h4>' + escapeHtml(t('threat.section.pulses', 'Pulses')) + '</h4>';
  html += pulseSection;
  html += '</section>';

  if (references.length) {
    html += renderThreatIntelLinkSection(
      t('threat.section.references', 'References'),
      references,
      selectedIP,
      'alienvault-references'
    );
  }

  if (relatedIndustries.length || relatedAdversary.length || relatedMalware.length) {
    html += '<section class="threat-intel-section"><h4>' + escapeHtml(t('threat.section.related_context', 'Related context')) + '</h4><div class="threat-intel-grid">';
    html += threatIntelDetailCard(t('threat.field.industries', 'Industries'), tiJoinList(relatedIndustries));
    html += threatIntelDetailCard(t('threat.field.adversary', 'Adversary'), tiJoinList(relatedAdversary));
    html += threatIntelDetailCard(t('threat.field.malware_families', 'Malware families'), tiJoinList(relatedMalware));
    html += '</div></section>';
  }

  return html;
}

function renderAbuseIPDBThreatIntel(payload, selectedIP) {
  var entry = payload && payload.data ? payload.data : {};
  var reports = Array.isArray(entry.reports) ? entry.reports.slice() : [];
  reports.sort(function(a, b) { return tiTimestamp(b && b.reportedAt) - tiTimestamp(a && a.reportedAt); });
  var hostnames = Array.isArray(entry.hostnames) ? entry.hostnames.slice() : [];

  var reportSection = buildThreatIntelCollapsibleEntries(
    reports.map(function(report, idx) {
      return renderAbuseIpDbReportItem(report, selectedIP, idx);
    }),
    selectedIP,
    'abuseipdb-reports'
  );

  var hostnameSection = '';
  if (hostnames.length) {
    hostnameSection = renderThreatIntelStringListSection(
      t('threat.field.hostnames', 'Hostnames'),
      hostnames,
      selectedIP,
      'abuseipdb-hostnames'
    );
  }

  var score = parseInt(entry.abuseConfidenceScore || 0, 10);
  var riskLabel = score >= 75 ? 'malicious' : (score >= 25 ? 'suspicious' : 'low-risk');

  var html = '';
  html += renderThreatIntelHero({
    ip: entry.ipAddress || selectedIP,
    provider: t('threat.provider.abuseipdb', 'AbuseIPDB'),
    riskLabel: riskLabel,
    riskClass: tiClassForReputation(riskLabel),
    cards: [
      { label: t('threat.metric.abuse_confidence', 'Abuse confidence'), value: tiValue(score) + '%' },
      { label: t('threat.metric.total_reports', 'Total reports'), value: tiValue(entry.totalReports) },
      { label: t('threat.metric.distinct_users', 'Distinct users'), value: tiValue(entry.numDistinctUsers) },
      { label: t('threat.field.last_seen', 'Last seen'), value: tiDate(entry.lastReportedAt) }
    ]
  });

  html += '<section class="threat-intel-section"><h4>' + escapeHtml(t('threat.section.overview', 'Overview')) + '</h4><div class="threat-intel-grid">';
  html += threatIntelDetailCard(t('threat.field.country', 'Country'), tiAbuseCountry(entry));
  html += threatIntelDetailCard(t('threat.field.ip_version', 'IP version'), tiValue(entry.ipVersion));
  html += threatIntelDetailCard(t('threat.field.public_ip', 'Public IP'), tiBool(entry.isPublic));
  html += threatIntelDetailCard(t('threat.field.tor', 'Tor exit node'), tiBool(entry.isTor));
  html += threatIntelDetailCard(t('threat.field.isp', 'ISP'), tiValue(entry.isp));
  html += threatIntelDetailCard(t('threat.field.domain', 'Domain'), tiValue(entry.domain));
  html += threatIntelDetailCard(t('threat.field.usage_type', 'Usage type'), tiValue(entry.usageType));
  html += threatIntelDetailCard(t('threat.field.whitelisted', 'Whitelisted'), tiBool(entry.isWhitelisted));
  html += '</div></section>';

  html += hostnameSection;

  html += '<section class="threat-intel-section"><h4>' + escapeHtml(t('threat.section.reports', 'Reports')) + '</h4>';
  html += reportSection;
  html += '</section>';

  return html;
}

function renderThreatIntelHero(opts) {
  var cards = Array.isArray(opts.cards) ? opts.cards : [];
  var html = '';
  html += '<section class="threat-intel-hero ' + escapeHtml(opts.riskClass || '') + '">';
  html += '  <div class="threat-intel-hero-main">';
  html += '    <p class="threat-intel-hero-kicker">' + escapeHtml(t('threat.metric.provider', 'Provider')) + ': ' + escapeHtml(tiValue(opts.provider)) + '</p>';
  html += '    <h4 class="threat-intel-hero-title">' + escapeHtml(tiValue(opts.ip)) + '</h4>';
  html += '    <p class="threat-intel-hero-subtitle">' + escapeHtml(t('threat.metric.risk', 'Risk')) + ': ' + escapeHtml(tiValue(opts.riskLabel)) + '</p>';
  html += '  </div><div class="threat-intel-priority-grid">';
  cards.forEach(function(card) {
    html += threatIntelMetricCard(card.label, card.value, 'threat-intel-card-compact');
  });
  html += '  </div></section>';
  return html;
}

function buildThreatIntelCollapsibleList(items, selectedIP, suffix) {
  var safeItems = Array.isArray(items) ? items : [];
  if (!safeItems.length) {
    return '<p class="text-sm text-gray-500">' + escapeHtml(t('threat.empty.list', 'No data available.')) + '</p>';
  }

  var visible = safeItems.slice(0, 5);
  var hidden = safeItems.slice(5);
  var hiddenId = 'threat-intel-list-hidden-' + suffix + '-' + tiSlug(selectedIP || 'ip');
  var toggleId = 'threat-intel-list-toggle-' + suffix + '-' + tiSlug(selectedIP || 'ip');
  var html = '<div class="threat-intel-list">';

  visible.forEach(function(item) {
    html += threatIntelListRow(item.left, item.right, item.meta);
  });
  html += '</div>';

  if (hidden.length) {
    html += '<div class="threat-intel-list hidden mt-2" style="display:none;" id="' + hiddenId + '" data-initially-hidden="true">';
    hidden.forEach(function(item) {
      html += threatIntelListRow(item.left, item.right, item.meta);
    });
    html += '</div>';
    var moreLabel = t('dashboard.banned.show_more', 'Show more') + ' +' + hidden.length;
    var lessLabel = t('dashboard.banned.show_less', 'Hide extra');
    html += '<button type="button" class="mt-2 text-xs font-semibold text-blue-600 hover:text-blue-800"'
      + ' id="' + toggleId + '"'
      + ' data-more-label="' + escapeHtml(moreLabel) + '"'
      + ' data-less-label="' + escapeHtml(lessLabel) + '"'
      + ' data-expanded="false"'
      + ' onclick="toggleThreatActivityList(\'' + hiddenId + '\', \'' + toggleId + '\')">'
      + escapeHtml(moreLabel)
      + '</button>';
  }
  return html;
}

function buildThreatIntelCollapsibleEntries(entries, selectedIP, suffix, visibleCount) {
  var safeEntries = Array.isArray(entries) ? entries.filter(Boolean) : [];
  if (!safeEntries.length) {
    return '<p class="text-sm text-gray-500">' + escapeHtml(t('threat.empty.list', 'No data available.')) + '</p>';
  }

  var maxVisible = Number.isFinite(visibleCount) && visibleCount > 0 ? visibleCount : 5;
  var visible = safeEntries.slice(0, maxVisible);
  var hidden = safeEntries.slice(maxVisible);
  var hiddenId = 'threat-intel-list-hidden-' + suffix + '-' + tiSlug(selectedIP || 'ip');
  var toggleId = 'threat-intel-list-toggle-' + suffix + '-' + tiSlug(selectedIP || 'ip');
  var html = '<div class="threat-intel-list">';

  visible.forEach(function(entryHtml) {
    html += entryHtml;
  });
  html += '</div>';

  if (hidden.length) {
    html += '<div class="threat-intel-list hidden mt-2" style="display:none;" id="' + hiddenId + '" data-initially-hidden="true">';
    hidden.forEach(function(entryHtml) {
      html += entryHtml;
    });
    html += '</div>';
    var moreLabel = t('dashboard.banned.show_more', 'Show more') + ' +' + hidden.length;
    var lessLabel = t('dashboard.banned.show_less', 'Hide extra');
    html += '<button type="button" class="mt-2 text-xs font-semibold text-blue-600 hover:text-blue-800"'
      + ' id="' + toggleId + '"'
      + ' data-more-label="' + escapeHtml(moreLabel) + '"'
      + ' data-less-label="' + escapeHtml(lessLabel) + '"'
      + ' data-expanded="false"'
      + ' onclick="toggleThreatActivityList(\'' + hiddenId + '\', \'' + toggleId + '\')">'
      + escapeHtml(moreLabel)
      + '</button>';
  }

  return html;
}

function threatIntelListRow(left, right, meta) {
  var html = '<div class="threat-intel-list-row"><span>' + escapeHtml(tiValue(left)) + '</span><strong>' + escapeHtml(tiValue(right)) + '</strong></div>';
  if (meta) {
    html += '<p class="mt-1 text-xs text-gray-500 whitespace-pre-wrap break-words">' + escapeHtml(meta) + '</p>';
  }
  return html;
}

function threatIntelMetricCard(label, value, extraClass) {
  return ''
    + '<div class="threat-intel-card ' + (extraClass || '') + '">'
    + '  <p class="threat-intel-card-label">' + escapeHtml(label) + '</p>'
    + '  <p class="threat-intel-card-value">' + escapeHtml(value) + '</p>'
    + '</div>';
}

function threatIntelDetailCard(label, value) {
  return ''
    + '<div class="threat-intel-card">'
    + '  <p class="threat-intel-card-label">' + escapeHtml(label) + '</p>'
    + '  <p class="threat-intel-card-text">' + escapeHtml(value) + '</p>'
    + '</div>';
}

function renderAbuseIpDbReportItem(report, selectedIP, idx) {
  var categories = Array.isArray(report && report.categories) ? report.categories : [];
  var categoryLabels = categories.map(function(cat) {
    return tiAbuseCategoryLabel(cat);
  });
  var countryName = tiValue(report && report.reporterCountryName);
  var countryCode = tiValue(report && report.reporterCountryCode);
  var reporterId = tiValue(report && report.reporterId);
  var reporterLabel = t('threat.field.reporter', 'Reporter');
  var reporterValue = countryName !== '—'
    ? countryName + ' (' + countryCode + ')'
    : countryCode;
  var metaLine = reporterLabel + ': ' + reporterValue + ' | ' + t('threat.field.reporter_id', 'Reporter ID') + ': ' + reporterId;
  var commentHtml = tiRichTextBlock(report && report.comment, selectedIP + '-abuse-report', idx, 260);
  var html = '<div class="rounded-md border border-gray-200 bg-white p-2">';
  html += '<div class="threat-intel-list-row">';
  html += '  <span>' + escapeHtml(tiDate(report && report.reportedAt)) + '</span>';
  //html += '  <strong>' + escapeHtml(t('threat.field.categories', 'Categories')) + ': ' + escapeHtml(String(categoryLabels.length)) + '</strong>';
  if (categoryLabels.length) {
    html += '<strong>' + escapeHtml(categoryLabels.join(', ')) + '</strong>';
  }
  html += '</div>';
  //if (categoryLabels.length) {
  //  html += '<p class="mt-1 text-xs text-gray-600 whitespace-pre-wrap break-words">' + escapeHtml(categoryLabels.join(', ')) + '</p>';
  //}
  html += '<p class="mt-1 text-xs text-gray-500">' + escapeHtml(metaLine) + '</p>';
  html += commentHtml;
  html += '</div>';
  return html;
}

function renderOtxPulseItem(pulse, selectedIP, idx) {
  var tlp = tiValue(pulse && pulse.TLP).toUpperCase();
  var author = tiValue(pulse && pulse.author && pulse.author.username);
  var subscribers = tiValue(pulse && pulse.subscriber_count);
  var indicators = tiValue(pulse && pulse.indicator_count);
  var tags = Array.isArray(pulse && pulse.tags) ? pulse.tags : [];
  var references = Array.isArray(pulse && pulse.references) ? pulse.references : [];
  var attackIds = Array.isArray(pulse && pulse.attack_ids) ? pulse.attack_ids : [];
  var attackLabels = attackIds.map(function(item) {
    return (item && (item.display_name || item.name || item.id)) || '';
  }).filter(Boolean);
  var descriptionHtml = tiRichTextBlock(pulse && pulse.description, selectedIP + '-otx-pulse', idx, 220);

  var html = '<div class="rounded-md border border-gray-200 bg-white p-2">';
  html += '<div class="threat-intel-list-row">';
  html += '  <span>' + escapeHtml(tiValue(pulse && pulse.name)) + '</span>';
  html += '  <strong>' + escapeHtml(tiDate(pulse && pulse.modified)) + '</strong>';
  html += '</div>';
  html += '<p class="mt-1 text-xs text-gray-500">';
  html += escapeHtml(t('threat.field.tlp', 'TLP')) + ': ' + escapeHtml(tlp);
  html += ' | ' + escapeHtml(t('threat.field.author', 'Author')) + ': ' + escapeHtml(author);
  html += ' | ' + escapeHtml(t('threat.field.subscribers', 'Subscribers')) + ': ' + escapeHtml(subscribers);
  html += ' | ' + escapeHtml(t('threat.field.indicators', 'Indicators')) + ': ' + escapeHtml(indicators);
  html += '</p>';
  if (tags.length) {
    html += '<p class="mt-1 text-xs text-gray-600 whitespace-pre-wrap break-words">';
    html += '<strong>' + escapeHtml(t('threat.field.tags', 'Tags')) + ':</strong> ' + escapeHtml(tags.join(', '));
    html += '</p>';
  }
  if (attackLabels.length) {
    html += '<p class="mt-1 text-xs text-gray-600 whitespace-pre-wrap break-words">';
    html += '<strong>' + escapeHtml(t('threat.section.mitre', 'MITRE techniques')) + ':</strong> ' + escapeHtml(attackLabels.join(', '));
    html += '</p>';
  }
  if (references.length) {
    html += '<p class="mt-1 text-xs text-gray-600">';
    html += '<strong>' + escapeHtml(t('threat.section.references', 'References')) + ':</strong> ' + escapeHtml(String(references.length));
    html += '</p>';
  }
  html += descriptionHtml;
  html += '</div>';
  return html;
}

function renderThreatIntelStringListSection(title, items, selectedIP, suffix) {
  var safeItems = Array.isArray(items) ? items.filter(Boolean) : [];
  if (!safeItems.length) {
    return '';
  }
  var sectionHtml = '<section class="threat-intel-section"><h4>' + escapeHtml(title) + '</h4>';
  sectionHtml += buildThreatIntelCollapsibleEntries(
    safeItems.map(function(item) {
      return '<div class="rounded-md border border-gray-200 bg-white px-3 py-2 text-sm text-gray-800 break-all">' + escapeHtml(item) + '</div>';
    }),
    selectedIP,
    suffix
  );
  sectionHtml += '</section>';
  return sectionHtml;
}

function renderThreatIntelLinkSection(title, links, selectedIP, suffix) {
  var safeLinks = Array.isArray(links) ? links.filter(Boolean) : [];
  if (!safeLinks.length) {
    return '';
  }
  var sectionHtml = '<section class="threat-intel-section"><h4>' + escapeHtml(title) + '</h4>';
  sectionHtml += buildThreatIntelCollapsibleEntries(
    safeLinks.map(function(link) {
      var href = String(link);
      return '<div class="rounded-md border border-gray-200 bg-white px-3 py-2 text-sm break-all">'
        + '<a class="text-blue-600 hover:text-blue-800 underline" href="' + escapeHtml(href) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(href) + '</a>'
        + '</div>';
    }),
    selectedIP,
    suffix
  );
  sectionHtml += '</section>';
  return sectionHtml;
}

function tiRichTextBlock(text, baseId, idx, maxChars) {
  if (!text) {
    return '<p class="mt-1 text-xs text-gray-500">—</p>';
  }
  var value = String(text);
  var threshold = Number.isFinite(maxChars) ? maxChars : 240;
  var escapedFull = escapeHtml(value);
  if (value.length <= threshold) {
    return '<p class="mt-1 text-xs text-gray-600 whitespace-pre-wrap break-words">' + escapedFull + '</p>';
  }
  var shortText = value.slice(0, threshold).replace(/\s+$/g, '') + '...';
  var escapedShort = escapeHtml(shortText);
  var textId = 'threat-intel-rich-text-' + tiSlug(baseId) + '-' + idx;
  var btnId = 'threat-intel-rich-toggle-' + tiSlug(baseId) + '-' + idx;
  var moreLabel = t('dashboard.banned.show_more', 'Show more');
  var lessLabel = t('dashboard.banned.show_less', 'Hide extra');
  return ''
    + '<p id="' + textId + '" class="mt-1 text-xs text-gray-600 whitespace-pre-wrap break-words"'
    + ' data-short="' + escapedShort + '" data-full="' + escapedFull + '" data-expanded="false">' + escapedShort + '</p>'
    + '<button type="button" id="' + btnId + '" class="mt-1 text-xs font-semibold text-blue-600 hover:text-blue-800"'
    + ' data-more-label="' + escapeHtml(moreLabel) + '" data-less-label="' + escapeHtml(lessLabel) + '"'
    + ' onclick="toggleThreatIntelText(\'' + textId + '\', \'' + btnId + '\')">' + escapeHtml(moreLabel) + '</button>';
}

function toggleThreatIntelText(textId, buttonId) {
  var textEl = document.getElementById(textId);
  var button = document.getElementById(buttonId);
  if (!textEl || !button) {
    return;
  }
  var expanded = textEl.getAttribute('data-expanded') === 'true';
  if (expanded) {
    textEl.textContent = textEl.getAttribute('data-short') || '';
    textEl.setAttribute('data-expanded', 'false');
    button.textContent = button.getAttribute('data-more-label') || button.textContent;
  } else {
    textEl.textContent = textEl.getAttribute('data-full') || '';
    textEl.setAttribute('data-expanded', 'true');
    button.textContent = button.getAttribute('data-less-label') || button.textContent;
  }
}

function tiAbuseCategoryLabel(id) {
  var key = String(id);
  var map = {
    "3": "Fraud Orders",
    "4": "DDoS Attack",
    "5": "FTP Brute-Force",
    "6": "Ping of Death",
    "7": "Phishing",
    "8": "Fraud VoIP",
    "9": "Open Proxy",
    "10": "Web Spam",
    "11": "Email Spam",
    "12": "Blog Spam",
    "13": "VPN IP",
    "14": "Port Scan",
    "15": "Hacking",
    "16": "SQL Injection",
    "17": "Spoofing",
    "18": "Brute-Force",
    "19": "Bad Web Bot",
    "20": "Exploited Host",
    "21": "Web App Attack",
    "22": "SSH",
    "23": "IoT Targeted"
  };
  return map[key] || ('Category #' + key);
}

function tiAbuseCountry(entry) {
  if (!entry) {
    return '—';
  }
  var code = tiValue(entry.countryCode);
  var name = tiValue(entry.countryName);
  if (name === '—') {
    return code;
  }
  if (code === '—') {
    return name;
  }
  return name + ' (' + code + ')';
}

function tiJoinList(items) {
  var safe = Array.isArray(items) ? items.filter(Boolean) : [];
  return safe.length ? safe.join(', ') : '—';
}

function tiDate(value) {
  if (!value) {
    return '—';
  }
  if (typeof formatDateTime === 'function') {
    return formatDateTime(value);
  }
  return String(value);
}

function tiValue(value) {
  if (value === null || value === undefined || value === '') {
    return '—';
  }
  return String(value);
}

function tiBool(value) {
  if (value === null || value === undefined) {
    return '—';
  }
  return value ? t('threat.boolean.yes', 'Yes') : t('threat.boolean.no', 'No');
}

function tiClassForReputation(reputation) {
  var value = (reputation || '').toLowerCase();
  if (value === 'malicious') {
    return 'threat-intel-card-danger';
  }
  if (value === 'suspicious') {
    return 'threat-intel-card-danger';
  }
  if (value === 'benign') {
    return 'threat-intel-card-safe';
  }
  if (value === 'low-risk') {
    return 'threat-intel-card-safe';
  }
  return '';
}

function tiAlienVaultRiskLabel(reputation, pulseCount) {
  var rep = parseInt(reputation || 0, 10);
  var pulses = parseInt(pulseCount || 0, 10);
  if (rep < 0 || pulses >= 5) {
    return 'malicious';
  }
  if (pulses > 0) {
    return 'suspicious';
  }
  return 'low-risk';
}

function tiTimestamp(value) {
  var ts = Date.parse(value || '');
  return Number.isFinite(ts) ? ts : 0;
}

function tiSlug(value) {
  return String(value || 'ti').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function toggleThreatActivityList(hiddenId, buttonId) {
  var hidden = document.getElementById(hiddenId);
  var button = document.getElementById(buttonId);
  if (!hidden || !button) {
    return;
  }
  var isHidden = hidden.classList.contains('hidden') || hidden.style.display === 'none';
  if (isHidden) {
    hidden.classList.remove('hidden');
    hidden.style.display = 'flex';
    button.textContent = button.getAttribute('data-less-label') || button.textContent;
    button.setAttribute('data-expanded', 'true');
  } else {
    hidden.classList.add('hidden');
    hidden.style.display = 'none';
    button.textContent = button.getAttribute('data-more-label') || button.textContent;
    button.setAttribute('data-expanded', 'false');
  }
}
