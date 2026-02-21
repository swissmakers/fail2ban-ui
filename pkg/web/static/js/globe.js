// 3D threat globe for Ban Insights modal.
"use strict";

// =========================================================================
//  Country Coordinates (ISO 3166-1 alpha-2 -> lat/lng)
// =========================================================================

var COUNTRY_COORDS = {
  AF:{lat:33.94,lng:67.71},AL:{lat:41.15,lng:20.17},DZ:{lat:28.03,lng:1.66},
  AS:{lat:-14.27,lng:-170.13},AD:{lat:42.55,lng:1.6},AO:{lat:-11.2,lng:17.87},
  AG:{lat:17.06,lng:-61.8},AR:{lat:-38.42,lng:-63.62},AM:{lat:40.07,lng:45.04},
  AU:{lat:-25.27,lng:133.78},AT:{lat:47.52,lng:14.55},AZ:{lat:40.14,lng:47.58},
  BS:{lat:25.03,lng:-77.4},BH:{lat:26.07,lng:50.56},BD:{lat:23.68,lng:90.36},
  BB:{lat:13.19,lng:-59.54},BY:{lat:53.71,lng:27.95},BE:{lat:50.5,lng:4.47},
  BZ:{lat:17.19,lng:-88.5},BJ:{lat:9.31,lng:2.32},BT:{lat:27.51,lng:90.43},
  BO:{lat:-16.29,lng:-63.59},BA:{lat:43.92,lng:17.68},BW:{lat:-22.33,lng:24.68},
  BR:{lat:-14.24,lng:-51.93},BN:{lat:4.54,lng:114.73},BG:{lat:42.73,lng:25.49},
  BF:{lat:12.24,lng:-1.56},BI:{lat:-3.37,lng:29.92},KH:{lat:12.57,lng:104.99},
  CM:{lat:7.37,lng:12.35},CA:{lat:56.13,lng:-106.35},CV:{lat:16.0,lng:-24.01},
  CF:{lat:6.61,lng:20.94},TD:{lat:15.45,lng:18.73},CL:{lat:-35.68,lng:-71.54},
  CN:{lat:35.86,lng:104.2},CO:{lat:4.57,lng:-74.3},KM:{lat:-11.88,lng:43.87},
  CG:{lat:-0.23,lng:15.83},CD:{lat:-4.04,lng:21.76},CR:{lat:9.75,lng:-83.75},
  CI:{lat:7.54,lng:-5.55},HR:{lat:45.1,lng:15.2},CU:{lat:21.52,lng:-77.78},
  CY:{lat:35.13,lng:33.43},CZ:{lat:49.82,lng:15.47},DK:{lat:56.26,lng:9.5},
  DJ:{lat:11.83,lng:42.59},DM:{lat:15.41,lng:-61.37},DO:{lat:18.74,lng:-70.16},
  EC:{lat:-1.83,lng:-78.18},EG:{lat:26.82,lng:30.8},SV:{lat:13.79,lng:-88.9},
  GQ:{lat:1.65,lng:10.27},ER:{lat:15.18,lng:39.78},EE:{lat:58.6,lng:25.01},
  ET:{lat:9.15,lng:40.49},FJ:{lat:-17.71,lng:178.07},FI:{lat:61.92,lng:25.75},
  FR:{lat:46.23,lng:2.21},GA:{lat:-0.8,lng:11.61},GM:{lat:13.44,lng:-15.31},
  GE:{lat:42.32,lng:43.36},DE:{lat:51.17,lng:10.45},GH:{lat:7.95,lng:-1.02},
  GR:{lat:39.07,lng:21.82},GD:{lat:12.12,lng:-61.68},GT:{lat:15.78,lng:-90.23},
  GN:{lat:9.95,lng:-9.7},GW:{lat:11.8,lng:-15.18},GY:{lat:4.86,lng:-58.93},
  HT:{lat:18.97,lng:-72.29},HN:{lat:15.2,lng:-86.24},HU:{lat:47.16,lng:19.5},
  IS:{lat:64.96,lng:-19.02},IN:{lat:20.59,lng:78.96},ID:{lat:-0.79,lng:113.92},
  IR:{lat:32.43,lng:53.69},IQ:{lat:33.22,lng:43.68},IE:{lat:53.41,lng:-8.24},
  IL:{lat:31.05,lng:34.85},IT:{lat:41.87,lng:12.57},JM:{lat:18.11,lng:-77.3},
  JP:{lat:36.2,lng:138.25},JO:{lat:30.59,lng:36.24},KZ:{lat:48.02,lng:66.92},
  KE:{lat:-0.02,lng:37.91},KI:{lat:-3.37,lng:-168.73},KP:{lat:40.34,lng:127.51},
  KR:{lat:35.91,lng:127.77},KW:{lat:29.31,lng:47.48},KG:{lat:41.2,lng:74.77},
  LA:{lat:19.86,lng:102.5},LV:{lat:56.88,lng:24.6},LB:{lat:33.85,lng:35.86},
  LS:{lat:-29.61,lng:28.23},LR:{lat:6.43,lng:-9.43},LY:{lat:26.34,lng:17.23},
  LI:{lat:47.17,lng:9.56},LT:{lat:55.17,lng:23.88},LU:{lat:49.82,lng:6.13},
  MK:{lat:41.51,lng:21.75},MG:{lat:-18.77,lng:46.87},MW:{lat:-13.25,lng:34.3},
  MY:{lat:4.21,lng:101.98},MV:{lat:3.2,lng:73.22},ML:{lat:17.57,lng:-4.0},
  MT:{lat:35.94,lng:14.38},MH:{lat:7.13,lng:171.18},MR:{lat:21.01,lng:-10.94},
  MU:{lat:-20.35,lng:57.55},MX:{lat:23.63,lng:-102.55},FM:{lat:7.43,lng:150.55},
  MD:{lat:47.41,lng:28.37},MC:{lat:43.75,lng:7.41},MN:{lat:46.86,lng:103.85},
  ME:{lat:42.71,lng:19.37},MA:{lat:31.79,lng:-7.09},MZ:{lat:-18.67,lng:35.53},
  MM:{lat:21.91,lng:95.96},NA:{lat:-22.96,lng:18.49},NR:{lat:-0.52,lng:166.93},
  NP:{lat:28.39,lng:84.12},NL:{lat:52.13,lng:5.29},NZ:{lat:-40.9,lng:174.89},
  NI:{lat:12.87,lng:-85.21},NE:{lat:17.61,lng:8.08},NG:{lat:9.08,lng:8.68},
  NO:{lat:60.47,lng:8.47},OM:{lat:21.47,lng:55.98},PK:{lat:30.38,lng:69.35},
  PW:{lat:7.51,lng:134.58},PA:{lat:8.54,lng:-80.78},PG:{lat:-6.31,lng:143.96},
  PY:{lat:-23.44,lng:-58.44},PE:{lat:-9.19,lng:-75.02},PH:{lat:12.88,lng:121.77},
  PL:{lat:51.92,lng:19.15},PT:{lat:39.4,lng:-8.22},QA:{lat:25.35,lng:51.18},
  RO:{lat:45.94,lng:24.97},RU:{lat:61.52,lng:105.32},RW:{lat:-1.94,lng:29.87},
  KN:{lat:17.36,lng:-62.78},LC:{lat:13.91,lng:-60.98},VC:{lat:12.98,lng:-61.29},
  WS:{lat:-13.76,lng:-172.1},SM:{lat:43.94,lng:12.46},ST:{lat:0.19,lng:6.61},
  SA:{lat:23.89,lng:45.08},SN:{lat:14.5,lng:-14.45},RS:{lat:44.02,lng:21.01},
  SC:{lat:-4.68,lng:55.49},SL:{lat:8.46,lng:-11.78},SG:{lat:1.35,lng:103.82},
  SK:{lat:48.67,lng:19.7},SI:{lat:46.15,lng:14.99},SB:{lat:-9.65,lng:160.16},
  SO:{lat:5.15,lng:46.2},ZA:{lat:-30.56,lng:22.94},SS:{lat:6.88,lng:31.31},
  ES:{lat:40.46,lng:-3.75},LK:{lat:7.87,lng:80.77},SD:{lat:12.86,lng:30.22},
  SR:{lat:3.92,lng:-56.03},SZ:{lat:-26.52,lng:31.47},SE:{lat:60.13,lng:18.64},
  CH:{lat:46.82,lng:8.23},SY:{lat:34.8,lng:38.99},TW:{lat:23.7,lng:120.96},
  TJ:{lat:38.86,lng:71.28},TZ:{lat:-6.37,lng:34.89},TH:{lat:15.87,lng:100.99},
  TL:{lat:-8.87,lng:125.73},TG:{lat:8.62,lng:1.21},TO:{lat:-21.18,lng:-175.2},
  TT:{lat:10.69,lng:-61.22},TN:{lat:33.89,lng:9.54},TR:{lat:38.96,lng:35.24},
  TM:{lat:38.97,lng:59.56},TV:{lat:-7.11,lng:177.65},UG:{lat:1.37,lng:32.29},
  UA:{lat:48.38,lng:31.17},AE:{lat:23.42,lng:53.85},GB:{lat:55.38,lng:-3.44},
  US:{lat:37.09,lng:-95.71},UY:{lat:-32.52,lng:-55.77},UZ:{lat:41.38,lng:64.59},
  VU:{lat:-15.38,lng:166.96},VE:{lat:6.42,lng:-66.59},VN:{lat:14.06,lng:108.28},
  YE:{lat:15.55,lng:48.52},ZM:{lat:-13.13,lng:27.85},ZW:{lat:-19.02,lng:29.15},
  PS:{lat:31.95,lng:35.23},HK:{lat:22.4,lng:114.11},XK:{lat:42.6,lng:20.9},
  PR:{lat:18.22,lng:-66.59},RE:{lat:-21.12,lng:55.54},GP:{lat:16.27,lng:-61.55},
  MQ:{lat:14.64,lng:-61.02},GF:{lat:3.93,lng:-53.13},YT:{lat:-12.83,lng:45.17},
  NC:{lat:-20.9,lng:165.62},PF:{lat:-17.68,lng:-149.41},CW:{lat:12.17,lng:-68.98},
  SX:{lat:18.04,lng:-63.05},AW:{lat:12.51,lng:-69.97}
};

// =========================================================================
//  Globe State
// =========================================================================

var _globeInstance = null;
var _globeResizeObserver = null;

// =========================================================================
//  Color Helper
// =========================================================================

// Returns an rgba string interpolating from blue (low) to red (high).
function _threatColor(ratio) {
  var r = Math.round(30 + 225 * ratio);
  var g = Math.round(100 * (1 - ratio));
  var b = Math.round(220 * (1 - ratio));
  return 'rgba(' + r + ',' + g + ',' + b + ',0.9)';
}

// =========================================================================
//  Render
// =========================================================================

function renderInsightsGlobe() {
  if (typeof Globe === 'undefined') return;

  var container = document.getElementById('insightsGlobe');
  if (!container) return;

  destroyInsightsGlobe();

  var countries = (latestBanInsights && latestBanInsights.countries) || [];
  if (!countries.length) {
    var emptyMsg = (translations && translations['logs.modal.threat_map_empty']) || 'No geo data available.';
    container.innerHTML = '<p class="text-sm text-gray-400 text-center py-16">' + escapeHtml(emptyMsg) + '</p>';
    return;
  }

  var maxCount = 1;
  countries.forEach(function(s) {
    if (s.count > maxCount) maxCount = s.count;
  });

  var points = [];
  countries.forEach(function(s) {
    var code = (s.country || '').toUpperCase();
    var coords = COUNTRY_COORDS[code];
    if (!coords) return;
    var ratio = Math.min(s.count / maxCount, 1);
    points.push({
      lat: coords.lat,
      lng: coords.lng,
      alt: 0.06 + 0.7 * ratio,
      radius: 0.4 + 0.6 * ratio,
      color: _threatColor(ratio),
      label: '<div style="padding:6px 10px;background:rgba(15,23,42,0.92);color:#f1f5f9;' +
             'border-radius:6px;font-size:13px;line-height:1.4;pointer-events:none;">' +
             '<b>' + escapeHtml(s.country || '??') + '</b><br>' +
             formatNumber(s.count) + ' ban' + (s.count !== 1 ? 's' : '') + '</div>',
      country: s.country,
      count: s.count
    });
  });

  var width = container.clientWidth || 600;
  var height = container.clientHeight || 420;

  var globe = Globe()
    .width(width)
    .height(height)
    .backgroundColor('rgba(0,0,0,0)')
    .showAtmosphere(true)
    .atmosphereColor('#3b82f6')
    .atmosphereAltitude(0.15)
    .globeImageUrl('/static/images/earth.jpg?v={{.version}}')
    .pointsData(points)
    .pointLat('lat')
    .pointLng('lng')
    .pointAltitude('alt')
    .pointRadius('radius')
    .pointColor('color')
    .pointLabel('label')
    .pointsMerge(false)
    (container);

  globe.pointOfView({ lat: 30, lng: 10, altitude: 2.2 });

  var controls = globe.controls();
  if (controls) {
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.4;
    controls.enableZoom = true;
    controls.minDistance = 120;
    controls.maxDistance = 500;
  }

  _globeInstance = globe;

  _globeResizeObserver = new ResizeObserver(function(entries) {
    for (var i = 0; i < entries.length; i++) {
      var rect = entries[i].contentRect;
      if (_globeInstance && rect.width > 0 && rect.height > 0) {
        _globeInstance.width(rect.width).height(rect.height);
      }
    }
  });
  _globeResizeObserver.observe(container);
}

// =========================================================================
//  Cleanup Globe
// =========================================================================

function destroyInsightsGlobe() {
  if (_globeResizeObserver) {
    _globeResizeObserver.disconnect();
    _globeResizeObserver = null;
  }
  if (_globeInstance) {
    _globeInstance.pauseAnimation();
    _globeInstance._destructor && _globeInstance._destructor();
    _globeInstance = null;
  }
  var container = document.getElementById('insightsGlobe');
  if (container) {
    container.innerHTML = '';
  }
}
