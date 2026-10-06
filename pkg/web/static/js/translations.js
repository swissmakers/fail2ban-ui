// Translation implementation for Fail2ban UI.
"use strict";

// =========================================================================
//  Translation Engine
// =========================================================================

var I18N_ATTRIBUTES = ['placeholder', 'title', 'aria-label'];

// Always resolves; a missing locale leaves the current strings in place.
function loadTranslations(lang) {
  return Promise.resolve($.getJSON(assetUrl('/locales/' + lang + '.json')))
    .then(function(data) {
      translations = data;
      updateTranslations();
    })
    .catch(function() {
      console.error('Failed to load translations for language:', lang);
    });
}

function updateTranslations() {
  $('[data-i18n]').each(function() {
    var key = lotrI18nKey($(this).attr('data-i18n'));
    if (translations[key]) {
      $(this).text(translations[key]);
    }
  });
  I18N_ATTRIBUTES.forEach(function(attr) {
    $('[data-i18n-' + attr + ']').each(function() {
      var key = lotrI18nKey($(this).attr('data-i18n-' + attr));
      if (translations[key]) {
        $(this).attr(attr, translations[key]);
      }
    });
  });
  refreshHeaderTranslations();
}

function getTranslationsSettingsOnPageload() {
  return getSettings().then(function(data) {
    var lang = (data && data.language) || 'en';
    $('#languageSelect').val(lang);
    return loadTranslations(lang);
  }, function(err) {
    console.error('Error loading initial settings:', err);
    return loadTranslations('en');
  });
}
