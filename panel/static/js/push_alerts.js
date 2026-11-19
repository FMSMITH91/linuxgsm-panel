// Alerts on this device (Web Push): the Account page's card, and the sign-out page's "stop alerts" choice.
//
// The browser is asked for notification permission only when "Turn on alerts" is clicked. The service
// worker (static/push/sw.js) is registered at its own folder's scope, so it controls no page; this file
// waits for it to be active itself (navigator.serviceWorker.ready waits for a worker controlling THIS
// page, which never comes). Every status line is rendered by the template; this only picks one.
// A browser's subscription is matched to the account's devices by the SHA-256 of its endpoint, so the
// page never holds an endpoint the server sent.
(function () {
  'use strict';

  function hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) {
      return ('0' + b.toString(16)).slice(-2);
    }).join('');
  }

  function endpointHash(endpoint) {
    return window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint)).then(hex);
  }

  function keyBytes(b64) {
    var pad = '='.repeat((4 - b64.length % 4) % 4);
    var raw = window.atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'));
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  function sameKey(sub, b64) {
    var have = sub && sub.options && sub.options.applicationServerKey;
    if (!have) return true;   // a browser that does not say: trust the server's answer instead
    var a = new Uint8Array(have), b = keyBytes(b64);
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  function supported() {
    return window.isSecureContext && 'serviceWorker' in navigator && 'PushManager' in window
      && 'Notification' in window;
  }

  function existing(scope) {
    return navigator.serviceWorker.getRegistration(scope)
      .then(function (reg) { return reg ? reg.pushManager.getSubscription() : null; });
  }

  function whenActive(reg) {
    if (reg.active) return Promise.resolve(reg);
    return new Promise(function (resolve, reject) {
      var w = reg.installing || reg.waiting;
      if (!w) { reject(new Error('no worker')); return; }
      w.addEventListener('statechange', function () {
        if (w.state === 'activated') resolve(reg);
        else if (w.state === 'redundant') reject(new Error('worker failed'));
      });
    });
  }

  // Go to a page the server rendered into a data attribute, only if it is on this panel's own origin.
  function goSameSite(path) {
    var u = new URL(path || '/', window.location.href);
    if (u.origin === window.location.origin) window.location.assign(u.href);
  }

  function postJson(url, body) {
    return fetch(url, {method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json'},  // nosemgrep
                       body: JSON.stringify(body || {})})
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (d) { return {status: r.status, d: d || {}}; });
      });
  }

  // ── the Account page's card ────────────────────────────────────────────────────────────────────
  function card(el) {
    var key = el.getAttribute('data-key');
    var scope = el.getAttribute('data-scope');
    var btnOn = document.getElementById('push-enable');
    var btnOff = document.getElementById('push-disable');
    var btnTest = document.getElementById('push-test');
    var known = Array.prototype.map.call(el.querySelectorAll('[data-push-hash]'), function (li) {
      return li.getAttribute('data-push-hash');
    });

    function say(which) {
      el.querySelectorAll('[data-push-msg]').forEach(function (s) {
        s.classList.toggle('d-none', s.getAttribute('data-push-msg') !== which);
      });
    }
    function show(on) {
      btnOn.classList.toggle('d-none', on);
      btnOff.classList.toggle('d-none', !on);
      btnTest.classList.toggle('d-none', !on);
      say(on ? 'on' : 'off');
    }
    function markThisDevice(hash) {
      el.querySelectorAll('[data-push-hash]').forEach(function (li) {
        var badge = li.querySelector('[data-push-this]');
        if (badge) badge.classList.toggle('d-none', li.getAttribute('data-push-hash') !== hash);
      });
    }
    function notice(d, fallbackKind) {
      if (d && d.message && window.toast) window.toast(d.message, d.success ? 'success' : fallbackKind);
    }

    // "Turn on alerts" is shown from the first paint; a browser that cannot take alerts hides it.
    function cannot(which) { btnOn.classList.add('d-none'); say(which); }
    if (!window.isSecureContext) { cannot('insecure'); return; }
    if (!supported()) {
      var ios = /iPad|iPhone|iPod/.test(navigator.userAgent)
        || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
      cannot(ios && !window.navigator.standalone ? 'ios' : 'unsupported');
      return;
    }

    // What this browser holds now. Read when the page is drawn and again whenever it comes back into
    // view or the browser's notification setting changes: alerts turned off in another tab, or
    // notifications blocked or allowed in the browser's settings, would otherwise leave the card saying
    // what was true when the page was drawn. Nothing is read while a button's request is running.
    function read() {
      if (btnOn.disabled || btnOff.disabled) return;
      if (Notification.permission === 'denied') {
        btnOff.classList.add('d-none'); btnTest.classList.add('d-none'); cannot('blocked'); return;
      }
      existing(scope).then(function (sub) {
        if (!sub || !sameKey(sub, key)) { show(false); return null; }
        return endpointHash(sub.endpoint).then(function (h) {
          var mine = known.indexOf(h) >= 0;
          show(mine);
          if (mine) markThisDevice(h);
        });
      }).catch(function () { show(false); });
    }
    read();
    document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'visible') read(); });
    window.addEventListener('pageshow', function (e) { if (e.persisted) read(); });
    if (navigator.permissions && navigator.permissions.query) {
      navigator.permissions.query({name: 'notifications'})
        .then(function (p) { p.addEventListener('change', read); })
        .catch(function () { /* a browser that does not report this permission: the reads above still run */ });
    }

    // Storing the subscription needs a recent sign-in (step_up_required). data-reauth is the answer when
    // the page was drawn; a page left open past the window asks for the password here (stepUpThen),
    // so the refusal does not send the tab away with the browser's half of the subscription left
    // behind. Closing that dialog takes the browser's half back.
    function store(sub) {
      return new Promise(function (resolve) {
        function post() { resolve(postJson(el.getAttribute('data-subscribe-url'), sub.toJSON()).then(function (res) { return stored(sub, res); })); }
        function dropped() { resolve(sub.unsubscribe().then(function () { show(false); btnOn.disabled = false; })); }
        if (window.stepUpThen) window.stepUpThen(post, window.STEP_UP_TOTP === true, dropped); else post();
      });
    }
    function stored(sub, res) {
      if (res.status === 200 && res.d.success) { window.location.reload(); return null; }
      // Not stored: take the browser's half back too, so the card tells the truth.
      return sub.unsubscribe().then(function () {
        if (res.d.error === 'reauth_required') { goSameSite(el.getAttribute('data-reauth-url')); return; }
        notice(res.d, 'danger');
        show(false);
        btnOn.disabled = false;
      });
    }

    btnOn.addEventListener('click', function () {
      if (el.getAttribute('data-reauth') === '1') {
        goSameSite(el.getAttribute('data-reauth-url'));
        return;
      }
      btnOn.disabled = true;
      Notification.requestPermission().then(function (perm) {
        if (perm !== 'granted') { say(perm === 'denied' ? 'blocked' : 'denied'); btnOn.disabled = false; return null; }
        return navigator.serviceWorker.register(el.getAttribute('data-sw'), {scope: scope})
          .then(whenActive)
          .then(function (reg) {
            return reg.pushManager.getSubscription().then(function (old) {
              // A subscription made with an older key would be refused by the push service.
              return (old && !sameKey(old, key)) ? old.unsubscribe().then(function () { return reg; }) : reg;
            });
          })
          .then(function (reg) {
            // A refusal HERE is the browser's push service saying no (Brave switches it off by
            // default), not a passing fault: say what to turn on rather than "try again".
            return reg.pushManager.subscribe({userVisibleOnly: true, applicationServerKey: keyBytes(key)})
              .catch(function (e) { e.pushService = true; throw e; });
          })
          .then(store);
      }).catch(function (e) {
        say(e && e.pushService ? 'pushsvc' : 'failed'); btnOn.classList.remove('d-none'); btnOn.disabled = false;
      });
    });

    btnOff.addEventListener('click', function () {
      btnOff.disabled = true;
      existing(scope).then(function (sub) {
        if (!sub) return null;
        return postJson(el.getAttribute('data-unsubscribe-url'), {endpoint: sub.endpoint})
          .then(function () { return sub.unsubscribe(); });
      }).then(function () { window.location.reload(); }, function () { btnOff.disabled = false; say('failed'); });
    });

    btnTest.addEventListener('click', function () {
      btnTest.disabled = true;
      postJson(el.getAttribute('data-test-url'), {}).then(function (res) {
        notice(res.d, 'warning');
        btnTest.disabled = false;
      }, function () { btnTest.disabled = false; });
    });
  }

  // ── the sign-out page ──────────────────────────────────────────────────────────────────────────
  function signout(form) {
    var hashes = (form.getAttribute('data-hashes') || '').split(',').filter(Boolean);
    var input = document.getElementById('signout-endpoint');
    var stop = document.getElementById('signout-stop');
    if (!hashes.length || !supported()) return;
    existing(form.getAttribute('data-scope')).then(function (sub) {
      if (!sub) return null;
      return endpointHash(sub.endpoint).then(function (h) {
        if (hashes.indexOf(h) < 0) return;
        input.value = sub.endpoint;
        document.getElementById('signout-push').classList.remove('d-none');
      });
    }).catch(function () { return null; });
    form.addEventListener('submit', function () {
      // Alerts kept: the server then clears only the cache and cookies (Clear-Site-Data "storage"
      // would remove the service worker and its subscription), so this page clears the rest of the
      // site's storage.
      if (input.value && !stop.checked) {
        try { window.localStorage.clear(); window.sessionStorage.clear(); } catch (e) { /* private mode */ }
      }
      if (window.ensureCsrfFields) window.ensureCsrfFields(form);
    });
  }

  // ── Telegram: link the account's own chat ────────────────────────────────────────────────────────
  // The link is a button the person taps (an <a>), not a window this script opens: a phone blocks a
  // window opened after a request finishes. Then this page asks every few seconds whether the chat is
  // linked, for as long as the code is good.
  var TG_CHECK_MS = 3000, TG_CHECKS = 200;
  function tgLink(box, push) {
    var btn = document.getElementById('tg-link-btn'), open = document.getElementById('tg-link-open');
    var msg = document.getElementById('tg-link-msg');
    if (!btn) return;
    // The status lines are rendered (and translated) in the card; this only picks which one shows.
    function show(which) {
      box.querySelectorAll('[data-tg-msg]').forEach(function (s) {
        s.classList.toggle('d-none', s.getAttribute('data-tg-msg') !== which);
      });
    }
    function check(left) {
      if (left <= 0) { show('gone'); open.classList.add('d-none'); btn.classList.remove('d-none'); return; }
      postJson(box.getAttribute('data-check-url'), {}).then(function (res) {
        if (res.status === 200 && res.d.linked) { window.location.reload(); return; }
        setTimeout(function () { check(left - 1); }, TG_CHECK_MS);
      }, function () { setTimeout(function () { check(left - 1); }, TG_CHECK_MS); });
    }
    btn.addEventListener('click', function () {
      if (push && push.getAttribute('data-reauth') === '1') { goSameSite(push.getAttribute('data-reauth-url')); return; }
      btn.disabled = true;
      // A page left open past the recent-sign-in window: the password is asked for here first.
      if (window.stepUpThen) window.stepUpThen(link, window.STEP_UP_TOTP === true, function () { btn.disabled = false; });
      else link();
    });
    function link() {
      postJson(box.getAttribute('data-link-url'), {}).then(function (res) {
        btn.disabled = false;
        if (res.d.error === 'reauth_required' && push) { goSameSite(push.getAttribute('data-reauth-url')); return; }
        if (res.status !== 200 || !res.d.success || !/^https:\/\/t\.me\/[A-Za-z0-9_]{5,32}\?start=[A-Za-z0-9_-]{1,64}$/.test(res.d.url || '')) {
          show(''); msg.textContent = res.d.message || ''; return;
        }
        open.href = res.d.url;
        open.classList.remove('d-none');
        btn.classList.add('d-none');
        msg.textContent = '';
        show('wait');
        setTimeout(function () { check(TG_CHECKS); }, TG_CHECK_MS);
      }, function () { btn.disabled = false; });
    }
  }

  var cardEl = document.getElementById('sec-push');
  if (cardEl) card(cardEl);
  var tgEl = document.getElementById('tg-link');
  if (tgEl) tgLink(tgEl, cardEl);
  var formEl = document.getElementById('signout-form');
  if (formEl) signout(formEl);
})();
