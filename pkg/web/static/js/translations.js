// Translation functions for Fail2ban UI
"use strict";

// Loads translation JSON file for given language (e.g., en, de, etc.)
function loadTranslations(lang) {
  $.getJSON('/locales/' + lang + '.json')
    .done(function(data) {
      translations = data;
      updateTranslations();
    })
    .fail(function() {
      console.error('Failed to load translations for language:', lang);
    });
}

// Updates all elements with data-i18n attribute with corresponding translation.
function updateTranslations() {
  $('[data-i18n]').each(function() {
    var key = $(this).data('i18n');
    if (translations[key]) {
      $(this).text(translations[key]);
    }
  });
  // Updates placeholders.
  $('[data-i18n-placeholder]').each(function() {
    var key = $(this).data('i18n-placeholder');
    if (translations[key]) {
      $(this).attr('placeholder', translations[key]);
    }
  });
}

function getTranslationsSettingsOnPageload() {
  return fetch('/api/settings')
    .then(function(res) { return res.json(); })
    .then(function(data) {
      var lang = data.language || 'en';
      $('#languageSelect').val(lang);
      loadTranslations(lang);
    })
    .catch(function(err) {
      console.error('Error loading initial settings:', err);
      loadTranslations('en');
    });
}

