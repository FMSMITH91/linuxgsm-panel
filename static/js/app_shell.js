// The page shell, on every page: the colour scheme and the "What's new" dialog.
//
// The scheme itself is set before first paint — by the server for a fixed choice, by the inline
// script at the top of base.html for "system". This file only follows changes: the device
// switching between light and dark while "system" is chosen, and the Account page's picker.
(function(){
  'use strict';
  var root = document.documentElement;
  var media = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;

  // The browser bar's colour: the topbar's, per scheme. "system" gets one per device scheme.
  function _cmpbBar(pref){
    document.querySelectorAll('meta[name="theme-color"]').forEach(function(m){ m.remove(); });
    var add = function(colour, query){
      var m = document.createElement('meta');
      m.name = 'theme-color'; m.content = colour;
      if (query) m.media = query;
      document.head.appendChild(m);
    };
    if (pref === 'light') add('#ffffff');
    else if (pref === 'dark') add('#111827');
    else { add('#ffffff', '(prefers-color-scheme: light)'); add('#111827', '(prefers-color-scheme: dark)'); }
  }

  function _cmpbApply(pref){
    var light = pref === 'light' || (pref === 'system' && !!media && media.matches);
    root.setAttribute('data-theme-pref', pref);
    root.setAttribute('data-bs-theme', light ? 'light' : 'dark');
  }

  if (media && media.addEventListener) {
    media.addEventListener('change', function(){
      if (root.getAttribute('data-theme-pref') === 'system') _cmpbApply('system');
    });
  }

  // The Account page's picker: applied at once, then saved to the account so it follows the
  // user to every device. A failed save leaves this page in the new scheme and says so.
  document.addEventListener('change', function(e){
    var el = e.target;
    if (!el || !el.matches || !el.matches('select[data-theme-select]')) return;
    var pref = el.value, url = el.getAttribute('data-theme-url');
    if (['system', 'dark', 'light'].indexOf(pref) < 0 || !url) return;
    _cmpbApply(pref);
    _cmpbBar(pref);
    fetch(url, {method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({theme: pref})})
      .then(function(r){ return r.ok ? r.json() : null; })
      .then(function(d){
        if (!(d && d.success) && window.toast) toast('The theme could not be saved to your account.', 'warning');
      })
      .catch(function(){
        if (window.toast) toast('The theme could not be saved to your account.', 'warning');
      });
  });

  // "What's new" (templates/_whats_new.html): opened once the page is parsed, and recorded as seen
  // however it is closed — the close button, "Got it" or Esc all fire `close`.
  var wn = document.getElementById('whats-new');
  if (wn && typeof wn.showModal === 'function') {
    wn.addEventListener('close', function(){
      var url = wn.getAttribute('data-seen-url');
      if (url) fetch(url, {method: 'POST', cache: 'no-store', keepalive: true}).catch(function(){});
      wn.remove();
    });
    try { wn.showModal(); } catch (_e) { /* already open, or not in the document */ }
  }
})();
