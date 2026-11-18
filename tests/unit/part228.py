"""Part 228 of the unit suite: a page holding an old session's CSRF token renews it by itself.

* An in-page POST (X-Requested-With) refused for a stale token is still a 400 in the viewer's words,
  and its JSON reply carries this session's token (X-CSRF-Renewed, no-store); the same POST sent
  again with that token goes through. panel.js's fetch wrapper does that resend.
* A POST that is not an in-page one (no X-Requested-With) gets no token, and a cross-site POST is
  refused by the Fetch Metadata guard before any token is handed out.
* The wrapper: it resends once only, only on that marker, and only a request it can send twice.

HOW IT RUNS. The refusal through the real CSRF error handler on part12's Flask app (which runs
CSRF off), the cross-site POST through its real routes, and panel.js in node against a stand-in
server. The whole round trip with CSRF on, on the real app, is in tests/smoke/part03.py.
"""
from unit.part01 import check, eq
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_restore_all

_trips228 = len(_P9_TRIPPED)
_XHR228 = {"X-Requested-With": "XMLHttpRequest"}
_URL228 = "/api/account/ui-order/reset"


def _renew228():
    from flask_wtf.csrf import CSRFError, validate_csrf
    hook = _p9.error_handler_spec[None][400].get(CSRFError)
    with _p9.test_request_context("/api/account/ui-order/reset", method="POST", headers=_XHR228):
        resp, code = hook(CSRFError("The CSRF session token is missing."))
        body = resp.get_json() or {}
        token = body.get("csrf_token") or ""
        try:
            validate_csrf(token)
            valid = True
        except Exception:  # noqa: BLE001 - any refusal of the handed-out token is the failure
            valid = False
    eq("csrf renew: an in-page request refused for a stale token is a 400 whose reply carries a token "
       "valid for this session", (code, bool(token), valid), (400, True, True))
    check("csrf renew: ...the refusal still says why in words, is marked X-CSRF-Renewed and is not cached",
          body.get("success") is False and "security token" in (body.get("message") or "")
          and resp.headers.get("X-CSRF-Renewed") == "1" and resp.headers.get("Cache-Control") == "no-store",
          repr((body.get("message"), dict(resp.headers))))


def _not_inpage228():
    from flask_wtf.csrf import CSRFError
    hook = _p9.error_handler_spec[None][400].get(CSRFError)
    with _p9.test_request_context(_URL228, method="POST", headers={"Accept": "application/json"}):
        presp, pcode = hook(CSRFError("The CSRF token is missing."))
        plain = presp.get_json() or {}
    cross = _p9_client(P9_ADMIN).post(_URL228, headers={"X-CSRFToken": "x", "Sec-Fetch-Site": "cross-site",
                                                        **_XHR228})
    check("csrf renew: a request that is not an in-page one gets no token, and a cross-site one is refused "
          "(Fetch Metadata) before any is handed out",
          pcode == 400 and "csrf_token" not in plain and not presp.headers.get("X-CSRF-Renewed")
          and cross.status_code == 403 and "csrf_token" not in (cross.get_json(silent=True) or {}),
          repr((pcode, plain, cross.status_code)))


# panel.js loaded in node with a stand-in server that refuses with a renewed token: once (the resend
# goes through), or every time (one resend, then the refusal), and a stream body (never resent).
_WRAP_JS228 = r"""
const vm = require('vm'), fs = require('fs');
const src = fs.readFileSync(%(path)s, 'utf8');
const inputs = [{value: 'old'}, {value: 'old'}];
const noop = () => {};
const el = new Proxy(function(){}, {get: (t, k) => k === Symbol.toPrimitive ? () => '' : el, apply: () => el});
const document = {addEventListener: noop, removeEventListener: noop, querySelectorAll: (q) => q.includes('csrf_token') ? inputs : [],
  querySelector: () => null, getElementById: () => null, createElement: () => el, body: el, documentElement: el, hidden: false, cookie: ''};
const calls = [];
let refuse = %(mode)s === 'always' ? Infinity : 1;
function stubFetch(input, init) {
  calls.push({tok: init.headers.get('X-CSRFToken'), body: init.body});
  if (refuse-- > 0) {
    return Promise.resolve(new Response(JSON.stringify({success: false, message: 'expired', csrf_token: 'NEW'}),
      {status: 400, headers: {'X-CSRF-Renewed': '1', 'Content-Type': 'application/json'}}));
  }
  return Promise.resolve(new Response('{"success":true}', {status: 200}));
}
const window = {fetch: stubFetch, CSRF: 'old', addEventListener: noop, location: {pathname: '/x', search: ''}, MOUNT: ''};
window.window = window;
const ctx = vm.createContext(Object.assign(window, {document, Headers, Response, FormData, URLSearchParams, URL, Promise, setTimeout, clearTimeout, console,
  navigator: {userAgent: 'node'}, localStorage: {getItem: () => null, setItem: noop}, sessionStorage: {getItem: () => null, setItem: noop},
  location: window.location, history: {replaceState: noop},
  MutationObserver: function(){ this.observe = noop; }, matchMedia: () => ({matches: false, addEventListener: noop})}));
try { vm.runInContext(src, ctx); } catch (e) { console.log('load error:', e.message); }
(async () => {
  const fd = new FormData(); fd.set('csrf_token', 'old');
  const r = await ctx.fetch('/api/x', {method: 'POST', body: fd});
  console.log(JSON.stringify({status: r.status, calls: calls.map(c => c.tok), formTok: fd.get('csrf_token'),
    CSRF: ctx.CSRF, inputs: inputs.map(i => i.value)}));
  calls.length = 0;
  const stream = new ReadableStream({start(c){ c.close(); }});
  refuse = 1;
  const r2 = await ctx.fetch('/api/x', {method: 'POST', body: stream, duplex: 'half'});
  console.log(JSON.stringify({streamStatus: r2.status, streamCalls: calls.length}));
})();
"""


def _wrap_run228(mode):
    import json as _json228
    import os
    import subprocess as _sp228  # nosec B404 - node on this part's own fixed program
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    prog = _WRAP_JS228 % {"path": _json228.dumps(os.path.join(root, "panel", "static", "js", "panel.js")),
                          "mode": _json228.dumps(mode)}
    r = _sp228.run(["node", "-"], input=prog, capture_output=True, text=True, timeout=60,  # nosec B603 B607
                   check=False)
    return [ln for ln in r.stdout.splitlines() if ln.startswith("{")], r.stderr[-300:]


def _wrapper228():
    once, err1 = _wrap_run228("once")
    always, err2 = _wrap_run228("always")
    check("csrf renew: panel.js resends a refused request once with the renewed token, which it puts in "
          "window.CSRF, every form field and the request's own form data; the resend goes through",
          once[:1] == ['{"status":200,"calls":["old","NEW"],"formTok":"NEW","CSRF":"NEW","inputs":["NEW","NEW"]}'],
          repr((once, err1)))
    check("csrf renew: ...refused again, it does not resend a second time (the refusal is shown), and a "
          "stream body, which reads once, is never resent",
          always[:1] == ['{"status":400,"calls":["old","NEW"],"formTok":"NEW","CSRF":"NEW","inputs":["NEW","NEW"]}']
          and once[1:2] == ['{"streamStatus":400,"streamCalls":1}'], repr((always, once, err2)))


_p9_arm(who="part228")
try:
    _renew228()
    _not_inpage228()
finally:
    _p9_restore_all()
_wrapper228()
check("csrf renew: nothing in this part reached a real transport (part12's tripwire)",
      len(_P9_TRIPPED) == _trips228)
