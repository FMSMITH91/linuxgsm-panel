// The host page's History card: this host's CPU, RAM, disk and network over 24 hours or 7 days, drawn
// with the server page's chart code (history_charts.js). Refreshed every minute while the card is on
// screen, which is how often a sample is recorded.
var _hch_range = '24h';

// The page arrives in the state the route expects (remote_manage.html), so a reply that agrees moves
// nothing. Charts already on screen that the reply empties keep their height (visibility, not
// display) with "No history yet" laid over them; the first samples for a card that had none show the
// chart area, the one change of height, made once, when there is something to show.
function _hch_showEmpty(empty){
  var e = document.getElementById('hh-empty'), c = document.getElementById('hh-charts');
  if (!e || !c) return;
  var shown = c.style.display !== 'none';
  e.style.display = empty ? '' : 'none';
  e.classList.toggle('hh-over', empty && shown);
  c.style.visibility = (empty && shown) ? 'hidden' : '';
  if (!empty) c.style.display = '';
}

function _hch_drawHost(h){
  var L = h.map(function(p){ return _histLbl(p.t, _hch_range); });
  var times = h.map(function(p){ return new Date(p.t); });
  var ink = _cmpbInk();
  var pctY = { y:{ min:0, max:100, ticks:{color:ink.tick, maxTicksLimit:5}, grid:{color:ink.grid} } };
  var xs = function(id){ _histTimes[id] = times; return _hch_range === '7d' ? _histX() : _histXScale(id); };
  _histChart('hh-cpu', L, [ _ds('CPU %', h.map(function(p){ return p.cpu; }), '#58a6ff', true) ], pctY, xs('hh-cpu'));
  _histChart('hh-ram', L, [ _ds('RAM %', h.map(function(p){ return p.ram; }), '#3fb950', true) ], pctY, xs('hh-ram'));
  _histChart('hh-disk', L, [ _ds('Disk %', h.map(function(p){ return p.disk; }), '#d29922', true) ], pctY, xs('hh-disk'));
  _hch_netChart('hh-net', L, h, xs('hh-net'));
}

window.loadHostHistory = function(){
  if (!document.getElementById('hh-card')) return;
  fetch(MOUNT + '/api/remote/' + REMOTE_ID + '/history?range=' + encodeURIComponent(_hch_range))
    .then(function(r){ return r.json(); })
    .then(function(d){
      // An error reply is not "No history yet": what is on screen stays, as after a failed request.
      if (!d || d.error) return;
      var h = d.host || [];
      _hch_showEmpty(!h.length);
      if (h.length) _hch_drawHost(h);
    }).catch(function(){});
};

document.addEventListener('click', function(e){
  var b = e.target.closest && e.target.closest('[data-hh-range]'); if (!b) return;
  var rng = b.getAttribute('data-hh-range'); if (rng === _hch_range) return;
  _hch_range = rng;
  b.parentNode.querySelectorAll('[data-hh-range]').forEach(function(x){ x.classList.toggle('active', x === b); });
  // Rebuilt, not refreshed in place: the x axis differs between the two ranges.
  ['hh-cpu', 'hh-ram', 'hh-disk', 'hh-net'].forEach(function(id){
    if (_histCharts[id]) { try { _histCharts[id].destroy(); } catch (err) { /* already gone */ } delete _histCharts[id]; }
  });
  window.loadHostHistory();
});

window.loadHostHistory();
if (window.pollWhenVisible) {
  pollWhenVisible(function(){
    var c = document.getElementById('hh-card');
    if (c && c.offsetParent !== null) window.loadHostHistory();
  }, 60000);
}
