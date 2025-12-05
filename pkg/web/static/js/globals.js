// Global variables for Fail2ban UI
"use strict";

var currentJailForConfig = null;
var serversCache = [];
var currentServerId = null;
var currentServer = null;
var latestSummary = null;
var latestSummaryError = null;
var latestBanStats = {};
var latestBanEvents = [];
var latestBanInsights = {
  totals: { overall: 0, today: 0, week: 0 },
  countries: [],
  recurring: []
};
var latestServerInsights = null;
var banEventsFilterText = '';
var banEventsFilterCountry = 'all';
var banEventsFilterDebounce = null;
var translations = {};
var sshKeysCache = null;
var openModalCount = 0;
var isLOTRModeActive = false;
