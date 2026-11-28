// Folds that hold settings start open for everyone; each viewer may close one, and it stays how they left it.
//
// A fold opts in with data-fold="<name>" (the same name wherever the same fold appears: one choice per fold, not
// per page). Only a choice the viewer made by clicking its summary is kept, in this browser's localStorage under
// uis.fold.<name>; a choice that matches what the page draws anyway is forgotten, so the page's default rules
// again. A script opening a fold (a link to a setting inside it) is never recorded.
//
// Storage may be refused (a private window, blocked site data): every read and write is in try/catch and the
// page then simply draws its defaults. Loaded at the end of <body>, before the first paint, so a fold the viewer
// closed is closed from the start and nothing below it jumps.
//
// window.restoreFolds(root) does the same for markup put in after load (refreshSection).
(function(){
  'use strict';
  var PREFIX = 'uis.fold.';   // i18n-ignore: a storage key

  function _storeKey(fold){
    var name = fold.getAttribute('data-fold');
    return name ? PREFIX + name : null;
  }
  function _read(k){
    try { return window.localStorage.getItem(k); } catch (e) { return null; }
  }
  function _write(k, value){
    try {
      if (value === null) window.localStorage.removeItem(k);
      else window.localStorage.setItem(k, value);
    } catch (e) { /* storage refused: the choice lasts until the page is left */ }
  }
  // A fold the address names, or one holding what it names, stays open: a link to a setting shows it.
  function _holdsTarget(fold){
    var id = String((window.location && window.location.hash) || '').slice(1);
    if (!id) return false;
    var el = null;
    try { el = document.getElementById(decodeURIComponent(id)); } catch (e) { return false; }
    return !!el && (el === fold || fold.contains(el));
  }
  function restoreFolds(root){
    var folds = (root || document).querySelectorAll('details[data-fold]');
    for (var i = 0; i < folds.length; i++) {
      var fold = folds[i];
      if (!fold.hasAttribute('data-fold-default')) fold.setAttribute('data-fold-default', fold.open ? '1' : '0');
      var k = _storeKey(fold);
      var saved = k ? _read(k) : null;
      if (saved === '0' && !_holdsTarget(fold)) fold.open = false;
      else if (saved === '1') fold.open = true;
    }
  }
  function _remember(fold){
    var k = _storeKey(fold);
    if (!k) return;
    var now = fold.open ? '1' : '0';
    _write(k, now === fold.getAttribute('data-fold-default') ? null : now);
  }
  // The summary's own click (a tap, or Enter/Space on it): the browser toggles the fold after the listeners run.
  document.addEventListener('click', function(e){
    var sum = e.target && e.target.closest ? e.target.closest('summary') : null;
    var fold = sum ? sum.parentNode : null;
    if (!fold || fold.tagName !== 'DETAILS' || !fold.hasAttribute('data-fold')) return;
    if (fold.querySelector('summary') !== sum) return;
    window.setTimeout(function(){ _remember(fold); }, 0);
  });
  window.restoreFolds = restoreFolds;
  restoreFolds(document);
})();
