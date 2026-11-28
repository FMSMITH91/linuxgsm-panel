// A stored secret on a page: dots until Show is pressed, Copy without showing it, hidden again by itself.
//
// The value stays in this closure: it is not in the page's text, an attribute or a URL until Show is pressed,
// never in the console or browser storage. The dots are a fixed number, so they say nothing of the secret's
// length. A shown value is hidden again after SHOW_MS, and at once when the tab is hidden (OWASP ASVS 5.0,
// V14.2.6: masked in the user interface unless the user specifically views it; V14.3.3: no sensitive data in
// browser storage). A value that must be fetched (audited by the panel) is fetched once, on the first Show or
// Copy, and kept here for both.
(function () {
  'use strict';
  var MASK = '••••••••••••';    // i18n-ignore: twelve dots, whatever the secret's length
  var SHOW_MS = 30000;
  function T(s) { return window.t ? window.t(s) : s; }

  // Call hide() after SHOW_MS or when the tab is hidden, whichever is first; the answer cancels both.
  function hideLater(hide) {
    var timer = null;
    function cancel() {
      if (timer !== null) window.clearTimeout(timer);
      timer = null;
      document.removeEventListener('visibilitychange', onVis);
    }
    function fire() { cancel(); hide(); }
    function onVis() { if (document.hidden) fire(); }
    timer = window.setTimeout(fire, SHOW_MS);
    document.addEventListener('visibilitychange', onVis);
    return cancel;
  }

  function iconButton(icon, label) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn-sm btn-outline-secondary secret-btn';
    b.title = label;
    b.setAttribute('aria-label', label);
    var i = document.createElement('i');
    i.className = 'bi ' + icon;
    i.setAttribute('aria-hidden', 'true');
    b.appendChild(i);
    return b;
  }
  function setIcon(b, icon, label) {
    b.title = label;
    b.setAttribute('aria-label', label);
    if (b.firstChild) b.firstChild.className = 'bi ' + icon;
  }

  function copy(text, label) {
    if (window.copyText) { window.copyText(text, label); return; }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).catch(function () { /* nothing shown */ });
  }

  // opts: {value: the secret} or {fetch: a function answering a promise of it}; onError(message) when a
  // fetch fails. The answer is the field's element; el.secretHide() masks it again.
  window.secretField = function (opts) {
    opts = opts || {};
    var value = typeof opts.value === 'string' ? opts.value : null, cancel = null;
    var wrap = document.createElement('span');
    wrap.className = 'secret-field d-inline-flex flex-wrap align-items-center gap-1';
    var out = document.createElement('code');
    out.className = 'secret-value';
    out.setAttribute('data-no-i18n', '');
    out.textContent = MASK;
    var show = iconButton('bi-eye', T('Show the password'));
    show.setAttribute('aria-pressed', 'false');
    var copyBtn = iconButton('bi-clipboard', T('Copy the password'));
    function get() {
      if (value !== null) return Promise.resolve(value);
      return Promise.resolve(opts.fetch()).then(function (v) { value = String(v == null ? '' : v); return value; });
    }
    function failed(e) { if (opts.onError) opts.onError((e && e.message) || T('Failed')); }
    function hide() {
      if (cancel) cancel();
      cancel = null;
      out.textContent = MASK;
      show.setAttribute('aria-pressed', 'false');
      setIcon(show, 'bi-eye', T('Show the password'));
    }
    show.addEventListener('click', function () {
      if (show.getAttribute('aria-pressed') === 'true') { hide(); return; }
      get().then(function (v) {
        out.textContent = v;
        show.setAttribute('aria-pressed', 'true');
        setIcon(show, 'bi-eye-slash', T('Hide the password'));
        if (cancel) cancel();
        cancel = hideLater(hide);
      }, failed);
    });
    copyBtn.addEventListener('click', function () {
      get().then(function (v) { copy(v, T('Password copied')); }, failed);
    });
    wrap.appendChild(out);
    wrap.appendChild(show);
    wrap.appendChild(copyBtn);
    wrap.secretHide = hide;
    return wrap;
  };
  window.secretHideLater = hideLater;
  window.SECRET_MASK = MASK;
  window.SECRET_SHOW_MS = SHOW_MS;
})();
