// Client-side i18n: window.t(s) plus a DOM auto-translator.
// window.I18N / window.LANG are set inline by base.html immediately above this file.
// i18n: hand the active language's catalog to the browser. window.t(s) translates one string
// (falls back to English). We also auto-translate the DOM — every text node and a few attributes
// whose EXACT text is in the catalog get swapped — so both server-rendered and JS-generated
// content are localised without wrapping every string. Anything not in the catalog stays English.
// Own keys only, and only string values. The catalog is an ordinary object, so a bare
// window.I18N[key] also "found" Object.prototype: text reading "constructor" (a player's name, in a
// player list) was replaced with "function Object() { [native code] }", and "__proto__" with
// "[object Object]".
function i18nLookup(key){
  var c = window.I18N;
  if (!c || !Object.prototype.hasOwnProperty.call(c, key)) return undefined;
  return (typeof c[key] === 'string') ? c[key] : undefined;
}
window.t = function(s){ return i18nLookup(s) || s; };
(function(){
  // Every text node + title/placeholder/aria-label whose EXACT (whitespace-collapsed) text is a
  // catalog key gets swapped. Each node's ORIGINAL English is remembered (node.__i18nEn /
  // el.__i18nA_<attr>) the first time it's seen — while it's still English — so window.setLang()
  // can revert and re-apply for a different language LIVE, with no page reload.
  var SKIP = {SCRIPT:1, STYLE:1, TEXTAREA:1, CODE:1, PRE:1, NOSCRIPT:1};
  var ATTRS = ['title', 'placeholder', 'aria-label'];
  var observing = false;
  // The stored English is RE-SEEDED when the current value is neither it nor what this file last
  // wrote (__i18nW / __i18nW_<attr>): that means a script changed it since, and what the script
  // wrote is the new English. Without that, the first value ever seen was the English forever — a
  // tooltip a poll updated stayed in English, and the next setLang() re-walk wrote the translation
  // of the STALE value over it (a badge reading "Reachable" with a "not checked yet" tooltip).
  function tText(node){
    var en = node.__i18nEn, cur = node.nodeValue;
    if (en === undefined || (cur !== en && cur !== node.__i18nW)){ en = node.__i18nEn = cur; }
    var key = en.replace(/\s+/g, ' ').trim();
    if (!key) return;
    var v = i18nLookup(key);
    // keep leading/trailing whitespace (inline layout, e.g. the gap after an icon)
    var out = (v !== undefined) ? en.match(/^\s*/)[0] + v + en.match(/\s*$/)[0] : en;
    node.__i18nW = out;
    if (node.nodeValue !== out) node.nodeValue = out;   // guard: no redundant set => no observer loop
  }
  function tAttr(el, a){
    var cur = el.getAttribute(a); if (cur == null) return;
    var pk = '__i18nA_' + a, wk = '__i18nW_' + a, en = el[pk];
    if (en === undefined || (cur !== en && cur !== el[wk])){ en = el[pk] = cur; }
    var key = en.replace(/\s+/g, ' ').trim(); if (!key) return;
    var v = i18nLookup(key);
    var out = (v !== undefined) ? v : en;
    el[wk] = out;
    if (cur !== out) el.setAttribute(a, out);
  }
  // Is anything ABOVE this node guarded? The recursive walk below stops at a guarded element on
  // the way down, so it never needs to ask — but the observer enters at an ARBITRARY node and
  // knows nothing about its ancestors, which is where the guard was being lost.
  function guardedAbove(node){
    for (var el = node && node.parentNode; el && el.nodeType === 1; el = el.parentNode){
      if (SKIP[el.tagName] || el.hasAttribute('data-no-i18n')) return true;
    }
    return false;
  }
  function walk(node){
    if (!node) return;
    if (node.nodeType === 3){ tText(node); return; }
    if (node.nodeType !== 1) return;
    if (SKIP[node.tagName] || node.hasAttribute('data-no-i18n')) return;
    for (var i = 0; i < ATTRS.length; i++) tAttr(node, ATTRS[i]);
    for (var c = node.firstChild; c; c = c.nextSibling) walk(c);
  }
  function run(root){ try { walk(root || document.body); } catch(e){} }
  function startObserver(){
    if (observing || !document.body) return; observing = true;
    new MutationObserver(function(muts){
      for (var i = 0; i < muts.length; i++){
        var m = muts[i];
        // guardedAbove FIRST. `el.textContent = x` REPLACES the children with a brand-new Text
        // node, so what arrives here is that text node — which has no attributes — and
        // `<span data-no-i18n>` above it was never consulted. Appending an element into a
        // guarded parent had the same hole. Measured before this: a guarded span written with
        // textContent 'Online' displayed 'En línea', indistinguishable from an unguarded one, so
        // every template-side guard of that shape (#tag-list, #game-version, #acct-username,
        // #eu-name) was decorative — and a username called Admin rendered as "Administrador".
        if (m.type === 'characterData'){ if (!guardedAbove(m.target)) walk(m.target); continue; }
        // A script set a title/placeholder/aria-label on an element already in the page. Nothing
        // was listening for that, so the new value was never translated.
        if (m.type === 'attributes'){
          var el = m.target;
          if (!SKIP[el.tagName] && !el.hasAttribute('data-no-i18n') && !guardedAbove(el)) tAttr(el, m.attributeName);
          continue;
        }
        for (var j = 0; j < m.addedNodes.length; j++){
          if (!guardedAbove(m.addedNodes[j])) walk(m.addedNodes[j]);
        }
      }
    }).observe(document.body, {childList:true, subtree:true, characterData:true,
                               attributes:true, attributeFilter:ATTRS});
  }
  // Switch language live: swap the catalog, then re-translate the whole DOM from each node's stored
  // English (so es->fr and any->English both work), and keep new nodes translated via the observer.
  window.setLang = function(lang, catalog){
    window.I18N = catalog || {};
    window.LANG = lang;
    try { document.documentElement.lang = lang; } catch(e){}
    startObserver();
    run(document.body);
  };
  function boot(){
    if (window.LANG !== 'en' && window.I18N){ startObserver(); run(document.body); }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
