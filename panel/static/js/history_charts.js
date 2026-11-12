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
    // keeps the tooltip/hover state. The dataset structure is stable per chart id.
    existing.data.labels = labels;
    datasets.forEach(function(ds, i){
      if(existing.data.datasets[i]) existing.data.datasets[i].data = ds.data;
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

function _histLbl(iso, rng){
  // Tooltip title (per point). Both ranges carry the date so a hovered point is never ambiguous
  // about which day it is; the compact date-at-change lives on the x-axis ticks (_histXScale).
  var d = new Date(iso);
  return rng==='7d' ? d.toLocaleString([], {month:'short', day:'numeric', hour:'2-digit'})
                           : d.toLocaleString([], {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
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
