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
var banEventsTotal = null;
var banEventsHasMore = false;
var latestBanInsights = {
  totals: { overall: 0, today: 0, week: 0 },
  countries: [],
  recurring: []
};
var latestServerInsights = null;
var banEventsFilterText = '';
var banEventsFilterCountry = 'all';
var banEventsFilterDebounce = null;
var BAN_EVENTS_PAGE_SIZE = 50;
var BAN_EVENTS_MAX_LOADED = 1000;
var translations = {};
var sshKeysCache = null;
var openModalCount = 0;
var isLOTRModeActive = false;
