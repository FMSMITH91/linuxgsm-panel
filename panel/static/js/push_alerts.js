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
    if (Notification.permission === 'denied') { cannot('blocked'); return; }

    existing(scope).then(function (sub) {
      if (!sub || !sameKey(sub, key)) { show(false); return; }
      return endpointHash(sub.endpoint).then(function (h) {
        var mine = known.indexOf(h) >= 0;
        show(mine);
        if (mine) markThisDevice(h);
      });
    }).catch(function () { show(false); });

    btnOn.addEventListener('click', function () {
      if (el.getAttribute('data-reauth') === '1') {
        window.location.href = el.getAttribute('data-reauth-url');
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
            return reg.pushManager.subscribe({userVisibleOnly: true, applicationServerKey: keyBytes(key)});
          })
          .then(function (sub) {
            return postJson(el.getAttribute('data-subscribe-url'), sub.toJSON()).then(function (res) {
              if (res.status === 200 && res.d.success) { window.location.reload(); return; }
              // Not stored: take the browser's half back too, so the card tells the truth.
              return sub.unsubscribe().then(function () {
                if (res.d.error === 'reauth_required') { window.location.href = el.getAttribute('data-reauth-url'); return; }
                notice(res.d, 'danger');
                show(false);
                btnOn.disabled = false;
              });
            });
          });
      }).catch(function () { say('failed'); btnOn.classList.remove('d-none'); btnOn.disabled = false; });
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
      if (!sub) return;
      return endpointHash(sub.endpoint).then(function (h) {
        if (hashes.indexOf(h) < 0) return;
        input.value = sub.endpoint;
        document.getElementById('signout-push').classList.remove('d-none');
      });
    }).catch(function () { return null; });
    form.addEventListener('submit', function () {
      // Alerts kept: the server then clears only cookies (Clear-Site-Data "storage" would remove the
      // service worker and its subscription), so this page clears the rest of the site's storage.
      if (input.value && !stop.checked) {
        try { window.localStorage.clear(); window.sessionStorage.clear(); } catch (e) { /* private mode */ }
      }
      if (window.ensureCsrfFields) window.ensureCsrfFields(form);
    });
  }

  var cardEl = document.getElementById('sec-push');
  if (cardEl) card(cardEl);
  var formEl = document.getElementById('signout-form');
  if (formEl) signout(formEl);
})();
