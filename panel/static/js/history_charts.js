// History charts shared by the server page (server_detail.js) and the host page (remote_history.js):
// the scheme-aware ink, the chart builder that refreshes in place, the axes, and the network chart.
// Loaded before either page's script, which call these by name.

// Chart text and grid in the page's colour scheme: the dark scheme's grey ticks are 2.9:1 on the
// light scheme's white card. Read when a chart is built; _r37d_inkCharts repaints the built ones.
function _cmpbInk(){
  var de = document.documentElement;
  var light = !!(de && de.getAttribute && de.getAttribute('data-bs-theme') === 'light');
  return light ? {tick: '#4b5563', grid: 'rgba(0,0,0,.08)', legend: '#1f2937'}
               : {tick: '#8b98a5', grid: 'rgba(255,255,255,.05)', legend: '#c9d1d9'};
}

var _histCharts = {};

var _histTimes = {};

// The 7-day x axis, in the scheme in force when a chart is built (it was taken once, at load).
function _histX(){ return { ticks:{color:_cmpbInk().tick, maxTicksLimit:6, maxRotation:0}, grid:{display:false} }; }

function _histXScale(id){
  var fmtT = function(t){ return t.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}); };
  var fmtD = function(t){ return t.toLocaleDateString([], {month:'short', day:'numeric'}); };
  return { grid:{display:false},
    afterFit: function(scale){
      var prev = null;
      scale.ticks.forEach(function(tk){
        var t = (_histTimes[id] || [])[tk.value]; if(!t) return;
        var d = fmtD(t);
        tk.label = (d === prev) ? fmtT(t) : [fmtT(t), d];
        prev = d;
      });
    },
    ticks:{ color:_cmpbInk().tick, maxTicksLimit:6, maxRotation:0, autoSkip:true,
      callback: function(value){ var t=(_histTimes[id]||[])[value]; return t ? [fmtT(t), fmtD(t)] : ''; } } };
}

// tipLabel (optional): how a hovered point's value reads in the tooltip, for units the axis formats.
function _histChart(id, labels, datasets, yScales, xScale, tipLabel){
  var el = document.getElementById(id); if(!el || typeof Chart==='undefined') return;
  var existing = _histCharts[id];
  if(existing){
    // Live refresh: update the data in place (no destroy/recreate) so the chart doesn't flash and
    // keeps the tooltip/hover state. The dataset structure is stable per chart id. The label too:
    // the caller translates it on every refresh, so a language switch reaches the legend.
    existing.data.labels = labels;
    datasets.forEach(function(ds, i){
      if(existing.data.datasets[i]){ existing.data.datasets[i].data = ds.data; existing.data.datasets[i].label = ds.label; }
      else existing.data.datasets[i] = ds;
    });
    existing.data.datasets.length = datasets.length;
    existing.update('none');
    return;
  }
  var scales = { x:(xScale||_histX()) }; for(var k in yScales){ scales[k]=yScales[k]; }
  _histCharts[id] = new Chart(el.getContext('2d'), {
    type:'line', data:{ labels:labels, datasets:datasets },
    options:{ responsive:true, maintainAspectRatio:false, animation:false,
      interaction:{intersect:false, mode:'index'}, scales:scales,
      plugins:{ legend:{ labels:{color:_cmpbInk().legend, boxWidth:12, boxHeight:12} },
                tooltip: tipLabel ? {callbacks:{label:tipLabel}} : {} } }
  });
}

// A live change of colour scheme (Account "System" following the device, app_shell.js) flips
// data-bs-theme without a reload. Each chart took its ink when it was built, and History refreshes
// in place, so the old scheme's ticks stayed (2.9:1 grey on white, or dark grey on near-black) until
// a reload. Repaint every built chart's ticks, grid lines and legend when the scheme changes.
function _r37d_inkChart(chart){
  if (!chart || !chart.options) return;
  var ink = _cmpbInk(), sc = chart.options.scales || {};
  Object.keys(sc).forEach(function(k){
    var s = sc[k] || {};
    if (s.ticks) s.ticks.color = ink.tick;
    if (s.grid && s.grid.display !== false) s.grid.color = ink.grid;
  });
  var lg = chart.options.plugins && chart.options.plugins.legend;
  if (lg && lg.labels) lg.labels.color = ink.legend;
  chart.update('none');
}
function _r37d_inkCharts(){
  // The server page's live CPU chart; the host page has none.
  if (typeof statsChart !== 'undefined') _r37d_inkChart(statsChart);
  Object.keys(_histCharts).forEach(function(id){ _r37d_inkChart(_histCharts[id]); });
}
var _r37d_inkWatch = typeof MutationObserver !== 'undefined' ? new MutationObserver(_r37d_inkCharts) : null;
if (_r37d_inkWatch && document.documentElement) {
  _r37d_inkWatch.observe(document.documentElement, {attributes: true, attributeFilter: ['data-bs-theme']});
}

// How a point's time reads, per range: every range carries the date so a hovered point is never
// ambiguous about which day it is (the compact date-at-change of the 24h axis is _histXScale). 7d and
// 30d points are hours; 90d points are days, and 6mo and 1y add the year, which their span crosses.
var _histLblFmt = {
  '24h': {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'},
  '7d': {month:'short', day:'numeric', hour:'2-digit'},
  '30d': {month:'short', day:'numeric', hour:'2-digit'},
  '90d': {month:'short', day:'numeric'},
  '6mo': {year:'numeric', month:'short', day:'numeric'},
  '1y': {year:'numeric', month:'short', day:'numeric'}
};
function _histLbl(iso, rng){
  return new Date(iso).toLocaleString([], _histLblFmt[rng] || _histLblFmt['24h']);
}

// The x axis past 24h: each tick is the day, with the hour under it for 7d and the year under it for 6mo
// and 1y. Two short lines, not the tooltip's one long label: "Nov 26, 2025" side by side ran into each
// other at phone width.
var _histTickSub = {'7d': {hour:'2-digit'}, '6mo': {year:'numeric'}, '1y': {year:'numeric'}};
function _histXDays(id, rng){
  var sc = _histX();
  sc.ticks.callback = function(value){
    var t = (_histTimes[id] || [])[value]; if (!t) return '';
    var day = t.toLocaleDateString([], {month:'short', day:'numeric'});
    var sub = _histTickSub[rng];
    return sub ? [day, t.toLocaleString([], sub)] : day;
  };
  return sc;
}

// The x axis for a range: the 24h one puts the date under the time where the day changes; the longer
// ones the day (_histXDays). At phone width four ticks, not six, so the labels never meet.
function _histAxis(id, rng){
  var sc = rng === '24h' ? _histXScale(id) : _histXDays(id, rng);
  var box = document.getElementById(id);
  if (box && box.parentNode && box.parentNode.clientWidth < 420) sc.ticks.maxTicksLimit = 4;
  return sc;
}

// Whether a poll should read range `rng` again for chart set `key`: the 24h and 7d ranges every poll
// (a new sample lands each minute); the hourly ranges every ten minutes, since a point there spans
// hours to a day and a minute's poll would read the same rows again for nothing.
var _histPolled = {};
function _histDue(key, rng, now){
  if (rng !== '24h' && rng !== '7d' && _histPolled[key] !== undefined && now - _histPolled[key] < 600000) return false;
  _histPolled[key] = now;
  return true;
}

// Which "nothing here" line an empty reply shows (prefix: 'hist' on the server page, 'hh' on the host
// page). With `older` (the shortest longer range that has history, from the reply) it says there is
// older history and offers that range as one button, labelled as that range's own button is titled;
// without it, the "nothing recorded yet" line.
function _histOlder(prefix, older){
  var none = document.getElementById(prefix + '-empty-none'), more = document.getElementById(prefix + '-empty-older');
  if (none) none.style.display = older ? 'none' : '';
  if (!more) return;
  more.style.display = older ? '' : 'none';
  var go = more.querySelector('[data-hist-go]');
  if (!older || !go) return;
  go.setAttribute('data-hist-go', older);
  var target = document.querySelector('[' + go.getAttribute('data-hist-go-for') + '="' + older + '"]');
  if (target && target.getAttribute('title')) go.textContent = target.getAttribute('title');
}

// The offered range's button: presses that range's own button, so the toggle, the active state and the
// reload are the ones a direct tap gives.
document.addEventListener('click', function(e){
  var go = e.target.closest && e.target.closest('[data-hist-go]'); if (!go) return;
  var target = document.querySelector('[' + go.getAttribute('data-hist-go-for') + '="' + go.getAttribute('data-hist-go') + '"]');
  if (target) target.click();
});

// A dashed "Peak" line beside an average, for the ranges whose points are hourly rollups (they carry
// cpu_max and the like); none for the 24h and 7d ranges, whose points are single samples.
function _hch_peak(datasets, points, key, color){
  if (!points.length || points[0][key] === undefined) return datasets;
  var peak = Object.assign(_ds(_hch_t('Peak'), points.map(function(p){ return p[key]; }), color, false),
                           {borderDash: [4, 3], borderWidth: 1});
  return datasets.concat([peak]);
}

function _ds(label, data, color, fill){
  return { label:label, data:data, borderColor:color, backgroundColor:color+'22',
           fill:!!fill, tension:.3, pointRadius:0, borderWidth:2, spanGaps:true };  // NOPMD
}

// Gaps, not bridges, in the network lines: a missing rate is a panel restart, a reboot or a long
// silence, and a straight line across it would draw traffic nobody measured.
function _hch_rateDs(label, data, color){ return Object.assign(_ds(label, data, color, false), {spanGaps:false}); }

// A rate in kbit/s as text: kbit/s up to 1000, Mbit/s above it.
function _hch_rate(v){
  if (v === null || v === undefined || Number.isNaN(v)) return '';
  return v >= 1000 ? (v / 1000).toFixed(1) + ' Mbit/s' : Math.round(v) + ' kbit/s';  // i18n-ignore
}

function _hch_t(s){ return window.t ? window.t(s) : s; }

// The network chart: received and sent, in kbit/s (Mbit/s above 1000), from a host series' rx/tx.
function _hch_netChart(id, labels, points, xScale){
  var ink = _cmpbInk();
  // The rate labels on the y axis are wider than a percentage's, so a phone-width chart has room for
  // fewer time labels: four, not six, or the two-line labels the 24h axis draws run into each other.
  var box = document.getElementById(id);
  if (xScale && xScale.ticks && box && box.parentNode && box.parentNode.clientWidth < 420) xScale.ticks.maxTicksLimit = 4;
  _histChart(id, labels, [
    _hch_rateDs(_hch_t('Received'), points.map(function(p){ return p.rx; }), '#58a6ff'),
    _hch_rateDs(_hch_t('Sent'), points.map(function(p){ return p.tx; }), '#d29922')
  ], { y:{ min:0, ticks:{color:ink.tick, maxTicksLimit:5, callback:_hch_rate}, grid:{color:ink.grid} } },
  xScale, function(c){ return c.dataset.label + ': ' + _hch_rate(c.parsed.y); });
}
