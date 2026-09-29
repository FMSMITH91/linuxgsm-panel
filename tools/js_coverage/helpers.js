// In-page helpers for tools/js_coverage/run.py, evaluated into each page it drives.
//
// NOT panel code, and never served by the panel: run.py sends this text over the DevTools protocol
// (Page.addScriptToEvaluateOnNewDocument), so it runs beside the page's scripts without a <script>
// tag, a nonce or a URL. Its own coverage is not collected — run.py keeps only /static/js/*.js.
//
// Everything here drives the page the way a person would: a click on the element, a value typed
// into a field and the event the field would fire. The panel's own handlers do the rest; nothing
// here calls a panel function directly.
(function () {
  if (window.__jscov) return;
  // run.py pauses the page on this listener (an event-listener breakpoint on `navigate`) to take
  // the leaving document's coverage before the navigation starts — see driver.py. The listener
  // itself does nothing; it is what the breakpoint stops on. A same-document change fires it too,
  // and the take there is merely early: nothing is lost by it, and nothing is counted twice.
  if (window.navigation && window.navigation.addEventListener) {
    window.navigation.addEventListener('navigate', function () {});
  }
  var sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };

  function setValue(el, value) {
    var proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype
      : (el.tagName === 'SELECT' ? HTMLSelectElement.prototype : HTMLInputElement.prototype);
    var d = Object.getOwnPropertyDescriptor(proto, 'value');
    if (d && d.set) d.set.call(el, value); else el.value = value;
  }

  function key(target, k, opts) {
    (target || document).dispatchEvent(new KeyboardEvent('keydown', Object.assign(
      {key: k, bubbles: true, cancelable: true}, opts || {})));
  }

  // Type into every field matching `selector`, then clear it again.
  async function typeInto(selector, text) {
    var els = Array.prototype.slice.call(document.querySelectorAll(selector));
    for (var i = 0; i < els.length; i++) {
      setValue(els[i], text);
      els[i].dispatchEvent(new Event('input', {bubbles: true}));
      els[i].dispatchEvent(new KeyboardEvent('keyup', {key: text.slice(-1), bubbles: true}));
      await sleep(150);
      setValue(els[i], '');
      els[i].dispatchEvent(new Event('input', {bubbles: true}));
      els[i].dispatchEvent(new KeyboardEvent('keyup', {key: 'Backspace', bubbles: true}));
    }
    return els.length;
  }

  // ── forms ──────────────────────────────────────────────────────────────────────────────────
  // Every empty field gets a plausible value for its type: the account's own password in a
  // password field, a TEST-NET address in a host field, a free port in a port field.
  var FILL = {email: 'jscov@example.com', url: 'https://example.com/', tel: '1', time: '05:00',
              date: '2026-09-26', color: '#3ba55d', search: 'a'};

  // The value for an empty field, by its type and then its name.
  function fillValue(el, password) {
    var name = (el.name || el.id || '').toLowerCase(), v = FILL[el.type];
    if (el.type === 'password') return password || 'x';
    if (el.type === 'number') return el.min || '1';
    if (/port/.test(name)) return '27020';
    if (/(host|^ip|_ip|address)/.test(name)) return '192.0.2.99';
    return v === undefined ? 'jscov' : v;
  }

  // A field the fill leaves alone: one a person cannot, or does not, type into.
  function notFilled(el) {
    return el.disabled || el.readOnly || el.type === 'hidden' || el.type === 'file';
  }

  function fillField(el, password) {
    if (notFilled(el)) return;
    if (el.tagName === 'SELECT') {
      if (!el.value && el.options.length > 1) setValue(el, el.options[1].value);
      return;
    }
    if (el.type === 'checkbox' || el.type === 'radio' || el.value) return;
    setValue(el, fillValue(el, password));
    el.dispatchEvent(new Event('input', {bubbles: true}));
    el.dispatchEvent(new Event('change', {bubbles: true}));
  }

  function fillForm(f, password) {
    f.querySelectorAll('input, textarea, select').forEach(function (el) { fillField(el, password); });
  }

  // ── controls ───────────────────────────────────────────────────────────────────────────────
  // Everything a person could click, tick or pick that is not a plain link: buttons, the panel's
  // delegated targets (data-tab, data-acc, data-nav, a file row, ...), Bootstrap toggles,
  // checkboxes, selects — and forms, submitted filled in. Deduplicated by what the control IS
  // (its action, label and role), not which row it sits in: forty servers cost one click a kind.
  var CONTROL_SEL = 'button, [role="button"], [data-action], [data-tab], [data-acc], [data-nav], '
    + '[data-mtab-btn], [data-bs-toggle], [data-path], [data-copy], [data-sort], [data-filter], '
    + 'summary, a[href^="#"], input[type="checkbox"], input[type="radio"], select, label.btn, form';

  // A form that deletes or ends something is submitted only in the pass that confirms things:
  // its confirmation, where it has one, is on the button that submits it, which submitting the
  // form directly skips.
  var DESTRUCTIVE = /delete|remove|uninstall|revoke|reset|logout|disable|wipe|restore|reboot/i;

  function csig(el) {
    var a = function (n) { return el.getAttribute(n) || ''; };
    if (el.tagName === 'FORM') {
      return ['FORM', el.id, a('action'), a('data-action'), el.className,
              el.querySelectorAll('input, select, textarea').length].join('|');
    }
    // A plain checkbox or radio is one kind per form: forty permission boxes run one handler.
    if (el.tagName === 'INPUT' && !el.hasAttribute('data-action')) {
      var box = el.closest('form, [id]');
      return [el.tagName, el.type, box ? (box.id || box.getAttribute('action') || '') : '',
              el.className].join('|');
    }
    return [el.tagName, el.type || '', a('data-action'), a('data-on'), a('data-tab'), a('data-acc'),
            a('data-mtab-btn'), a('data-bs-toggle'), a('data-bs-target'), a('data-type'),
            a('data-sort'), a('data-filter'), a('name'), el.id || '',
            (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 30)].join('|');
  }

  // `mainOnly`: leave out the sidebar and top bar, which every page shares — pressing them once,
  // on the first page, is what there is to learn from them. The language picker is left alone:
  // switching language is a pass of its own, and left switched it would change every page after.
  function isPlainLink(el) {
    return el.tagName === 'A' && (el.getAttribute('href') || '').length > 1
      && !el.hasAttribute('data-action') && !el.hasAttribute('data-bs-toggle');
  }

  function isFormLeftOut(el, accept) {
    return el.tagName === 'FORM' && (!el.closest('main')
      || (!accept && DESTRUCTIVE.test(el.getAttribute('action') || '')));
  }

  function leftOut(el, mainOnly, accept) {
    return !!(el.disabled || el.closest('form[action*="logout"]') || el.hasAttribute('data-lang-select')
      || (mainOnly && !el.closest('main')) || isPlainLink(el) || isFormLeftOut(el, accept));
  }

  function controls(skip, mainOnly, accept) {
    var seen = {}, out = [];
    document.querySelectorAll(CONTROL_SEL).forEach(function (el) {
      if (leftOut(el, mainOnly, accept)) return;
      var s = csig(el);
      if (seen[s]) return;
      if (skip && skip.some(function (k) { return s.indexOf(k) >= 0; })) return;
      seen[s] = 1;
      out.push(el);
    });
    return out;
  }

  function submitForm(el, password) {
    fillForm(el, password);
    var btn = el.querySelector('button[type="submit"], input[type="submit"]');
    if (el.requestSubmit) el.requestSubmit(btn || undefined);
    else el.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
    return 'submit';
  }

  function editTextarea(el) {
    setValue(el, el.value + '\n# jscov');
    el.dispatchEvent(new Event('input', {bubbles: true}));
    el.dispatchEvent(new Event('change', {bubbles: true}));
    return 'input';
  }

  // A control that is changed rather than pressed: a select, or an input that is not a button.
  function isField(el) {
    return el.tagName === 'SELECT' || (el.tagName === 'INPUT' && el.type !== 'button'
                                       && el.type !== 'submit');
  }

  function pickNextOption(el) {
    var next = Array.prototype.filter.call(el.options, function (o) {
      return !o.disabled && o.value !== el.value;
    })[0];
    if (next) setValue(el, next.value);
  }

  function changeField(el, on) {
    if (el.tagName === 'SELECT') {
      pickNextOption(el);
    } else if (el.type === 'checkbox' || el.type === 'radio') {
      el.checked = el.type === 'radio' ? true : !el.checked;
    } else if (el.type !== 'file' && !el.value) {
      setValue(el, el.type === 'number' ? (el.min || '1') : 'a');
    }
    el.dispatchEvent(new Event('input', {bubbles: true}));
    el.dispatchEvent(new Event('change', {bubbles: true}));
    if (on === 'keydown') key(el, 'Enter');
    return 'change';
  }

  function submitOwnForm(el, password) {
    var f = el.tagName === 'FORM' ? el : el.closest('form');
    if (f) { fillForm(f, password); f.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true})); }
    return 'submit';
  }

  function fireControl(el, password) {
    var on = el.getAttribute('data-on') || '';
    if (el.tagName === 'FORM') return submitForm(el, password);
    if (el.tagName === 'TEXTAREA') return editTextarea(el);
    if (isField(el)) return changeField(el, on);
    if (on === 'keydown') { key(el, 'Enter'); return on; }
    if (on === 'submit') return submitOwnForm(el, password);
    el.click();
    return 'click';
  }

  // Answer whatever the last step opened: the panel's confirm dialog — OK only when `accept`, and
  // with what it asks to be typed (the account's password, or the name its label quotes), else
  // Cancel — the panel's own overlay dialogs, the command palette, and any Bootstrap modal left
  // open. Pressing a still-disabled OK is not something a person can do, so a dialog whose text
  // did not satisfy it is cancelled.
  // What the confirm dialog asks to be typed: the account's password, or the name its label
  // quotes, in (parentheses) or quotation marks. Neither run can hold its own opening mark, so a
  // label full of them is read once, not once for every mark.
  function confirmAnswer(card, inp, password) {
    if (inp.type === 'password') return password || '';
    var lab = card.querySelector('label[for="cd-input"]');
    var m = lab && /\(([^()]+)\)|[“"']([^“”"']+)[”"']/.exec(lab.textContent);
    return m ? (m[1] || m[2]) : '';
  }

  function settleDialogs(accept, password) {
    var n = 0;
    document.querySelectorAll('[data-cd="ok"]').forEach(function (ok) {
      var card = ok.closest('.card');
      var cancel = card && card.querySelector('[data-cd="cancel"]');
      var inp = card && card.querySelector('#cd-input');
      if (accept && inp && !inp.value) {
        setValue(inp, confirmAnswer(card, inp, password));
        inp.dispatchEvent(new Event('input', {bubbles: true}));
      }
      if (accept && !ok.disabled) ok.click();
      else if (cancel) cancel.click();
      n++;
    });
    // The panel's other dialogs are overlays of their own — who is online before a restart, a
    // ban's scope, a command's output, a full backup's players — and one left open covers the
    // page, so a drop meant for the page lands on it. Each closes on a click on its backdrop;
    // accepting presses its first button that is not a way out.
    Array.prototype.slice.call(document.querySelectorAll('body > div')).forEach(function (ov) {
      if (ov.style.position !== 'fixed' || ov.style.inset !== '0px'
          || ov.querySelector('[data-cd]')) return;
      var go = accept && Array.prototype.filter.call(ov.querySelectorAll('button'), function (b) {
        var what = [b.id, b.getAttribute('data-scope'), b.hasAttribute('data-close') ? 'close' : '',
                    b.textContent].join(' ');
        return !/cancel|close/i.test(what);
      })[0];
      if (go) go.click();
      else ov.dispatchEvent(new MouseEvent('click', {bubbles: true}));
      n++;
    });
    // The command palette covers the page while it is open, so anything aimed at the page after
    // it lands on the palette instead: a file dropped on the file browser went nowhere.
    var palette = document.getElementById('cmdk');
    if (palette && !palette.hidden) {
      key(document, 'Escape');
      n++;
    }
    if (window.bootstrap && bootstrap.Modal) {
      document.querySelectorAll('.modal.show').forEach(function (m) {
        var inst = bootstrap.Modal.getInstance(m);
        if (inst) { inst.hide(); n++; }
      });
    }
    return n;
  }

  // ── for the page flows (flows.py) ─────────────────────────────────────────────────────────
  function q(sel, i) { return document.querySelectorAll(sel)[i || 0] || null; }

  // Click the `i`th match of `sel`; say whether there was one.
  function click(sel, i) {
    var el = q(sel, i);
    if (el) el.click();
    return !!el;
  }

  // Type `text` into the `i`th match of `sel` as a person would: focus, value, input, change.
  function type(sel, text, i) {
    var el = q(sel, i);
    if (!el) return false;
    if (el.focus) el.focus();
    setValue(el, text);
    el.dispatchEvent(new Event('input', {bubbles: true}));
    el.dispatchEvent(new Event('change', {bubbles: true}));
    return true;
  }

  async function waitFor(sel, ms) {
    var end = Date.now() + (ms || 3000);
    while (Date.now() < end) {
      if (q(sel)) return q(sel);
      await sleep(100);
    }
    return null;
  }

  // A point on the `i`th match of `sel` that input sent there would actually reach, scrolled into
  // view first, for input the page cannot be sent from inside it (a real pointer drag, a file
  // dragged in from disk). On screen, and not under anything else: a card taller than the window
  // has its centre below the bottom edge, and a fixed widget (a toast, the install progress
  // corner) can sit over the middle of what is left — a drop there lands on the widget.
  var SPOTS = [[0.5, 0.5], [0.5, 0.3], [0.5, 0.7], [0.3, 0.5], [0.7, 0.5],
               [0.2, 0.2], [0.8, 0.2], [0.2, 0.8], [0.8, 0.8]];
  function centre(sel, i) {
    var el = q(sel, i);
    if (!el) return null;
    // 'instant': the panel's stylesheet asks for smooth scrolling, and the rect read straight
    // after a smooth scroll is where the element was before it.
    el.scrollIntoView({block: 'center', inline: 'center', behavior: 'instant'});
    var r = el.getBoundingClientRect();
    var left = Math.max(r.left, 0), right = Math.min(r.right, window.innerWidth);
    var top = Math.max(r.top, 0), bottom = Math.min(r.bottom, window.innerHeight);
    if (right <= left || bottom <= top) return null;
    for (var k = 0; k < SPOTS.length; k++) {
      var x = left + (right - left) * SPOTS[k][0], y = top + (bottom - top) * SPOTS[k][1];
      var hit = document.elementFromPoint(x, y);
      if (hit && (hit === el || el.contains(hit))) return [x, y];
    }
    return null;
  }

  window.__jscov = {
    sleep: sleep, setValue: setValue, key: key, typeInto: typeInto, fillForm: fillForm,
    settleDialogs: settleDialogs, controls: controls, csig: csig,
    q: q, click: click, type: type, waitFor: waitFor, centre: centre,

    // One step of the walk, in one round trip: answer what the previous step opened, then — if
    // the page is still `path` — fire the first control not in `done` (and, when `only` is given,
    // in `only`). The page changes under every click (a dialog opens, a list re-renders), so the
    // caller keeps what it has fired and asks again rather than indexing a list that has changed.
    step: function (o) {
      var res = {dialogs: settleDialogs(o.accept, o.password), path: location.pathname, sig: null};
      if (location.pathname !== o.path) return res;
      var list = controls(o.skip, o.mainOnly, o.accept);
      for (var i = 0; i < list.length; i++) {
        var s = csig(list[i]);
        if (o.done.indexOf(s) >= 0 || (o.only && o.only.indexOf(s) < 0)) continue;
        res.sig = s;
        res.on = fireControl(list[i], o.password);
        break;
      }
      return res;
    },
  };
})();
