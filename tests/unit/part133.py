"""Part 133 of the unit suite: the host page's Network and Security tabs with less scrolling (ui-dense).

1. "Could not load top offenders." The Security tab's cards showed that one line for every way a read can
   fail before its answer is read — the connection dropping, an error page from the panel or the proxy
   in front of it, a sign-in page — and named none of them. Each card now says which it was, and the
   top-ips routes answer JSON even when reading their auto-block settings raises (that escaped as an
   HTML 500, which the card could only call "Could not load").

HOW IT RUNS. Routes on part12's app with its transport tripwire armed and every host call stubbed, as
part131 does; the tab's readers in node on a DOM of their own. Nothing reaches a host or data/.
"""
import json as _json133
import os

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9_arm, _p9_client, _p9_patch, _p9_restore_all)
from unit.part47 import _cut47, _node47
from panel.routes import host_local as _hl133
from panel.routes import remote_security as _rs133

_TRIP133_START = len(_P9_TRIPPED)


def _read133(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _uid_raises():
    raise OSError("database is locked")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Top offenders: an answer the card can read, and a failure it can name
# ════════════════════════════════════════════════════════════════════════════════════════════════
_uid_top = {}
try:
    _p9_arm(who="part133")
    _p9_patch(_hl133, "_autoblock_hosts", _uid_raises)
    _p9_patch(_rs133, "_autoblock_hosts", _uid_raises)
    for _k133, _url133 in (("panel", "/api/panel/security/top-ips"),
                           ("remote", "/api/remote/%d/security/top-ips" % P9_HOST)):
        _r133 = _p9_client(P9_ADMIN).get(_url133)
        _uid_top[_k133] = (_r133.status_code, _r133.mimetype, _r133.get_json(silent=True))
finally:
    _p9_restore_all()

for _k133 in ("panel", "remote"):
    _s133, _m133, _j133 = _uid_top.get(_k133, (None, None, None))
    check("top offenders (%s host): reading the auto-block settings raised, and the route still answers "
          "JSON saying the read failed, with no setting the card would repaint from a guess" % _k133,
          _s133 == 200 and _m133 == "application/json" and isinstance(_j133, dict)
          and bool(_j133.get("error")) and _j133.get("ips") == []
          and not {"autoblock", "threshold", "whitelist"} & set(_j133), repr(_uid_top.get(_k133)))

_RM133 = _read133("static", "js", "remote_manage.js")


def _uid_cut(head):
    return _cut47(_RM133, head) if head in _RM133 else "/* MISSING %s */" % head


_UID_SRC = "\n".join(_uid_cut(h) for h in (
    "function secBase(", "function _uidReadJson(", "var _UID_WHY", "function _uidFailHtml(",
    "function loadSecurityTopIps(", "function renderWhitelist(", "function loadSecurityBans(",
    "function loadSecurityEvents("))
_UID_PROG = r"""
const SRC = %s;
const els = {};
global.document = { getElementById(id) { return els[id] || (els[id] = {id, innerHTML: '', value: '', checked: false}); } };
global.window = global; global.IS_LOCAL = true; global.MOUNT = '/lgsm'; global.REMOTE_ID = 1;
global.escapeHtml = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;');
global.t = s => s; global.tfHtml = (s, v) => s.replace(/\{(\w+)\}/g, (m, k) => String(v[k]));
global._da = () => '';
(0, eval)(SRC);
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };
const json = body => Promise.resolve({ok: true, status: 200, headers: {get: () => 'application/json'},
                                      json: () => Promise.resolve(body)});
const page = status => Promise.resolve({ok: status < 400, status, headers: {get: () => 'text/html; charset=utf-8'},
                                        json: () => Promise.reject(new SyntaxError('Unexpected token <'))});
const CASES = {
  net: () => Promise.reject(new TypeError('Failed to fetch')),
  bad_gateway: () => page(502),
  sign_in: () => page(200),
  good: () => json({autoblock: true, threshold: 30, whitelist: [], ips: [{ip: 'offender-a', attempts: 9, bans: 1, jails: ['sshd']}]}),
};
(async () => {
  const out = {};
  for (const k in CASES) {
    for (const id in els) delete els[id];
    global.fetch = CASES[k];
    loadSecurityTopIps(); loadSecurityBans(); loadSecurityEvents(); await settle();
    out[k] = {top: els['sec-top'].innerHTML, bans: els['sec-bans'].innerHTML, events: els['sec-events'].innerHTML,
              wl: els['sec-wl-list'] ? els['sec-wl-list'].innerHTML : null,
              tog: els['sec-autoblock'] ? els['sec-autoblock'].checked : null};
  }
  console.log(JSON.stringify(out));
})();
""" % _json133.dumps(_UID_SRC)
_uid_out = _node47(_UID_PROG)
_UID_NAME = "top offenders card: a read with no answer says the panel did not answer, not just \"could not load\""
if _uid_out is None:
    skip(_UID_NAME, "node is not installed here")
else:
    _n133 = _uid_out.get("net", {})
    check(_UID_NAME + " (the connection dropped: the panel restarting, a proxy giving up)",
          "Could not load top offenders." in _n133.get("top", "") and "did not answer" in _n133.get("top", ""),
          repr(_uid_out))
    _g133 = _uid_out.get("bad_gateway", {})
    check("top offenders card: an error page in place of the answer names its HTTP status (a 502 from the "
          "proxy in front of the panel)", "HTTP 502" in _g133.get("top", ""), repr(_uid_out))
    _p133 = _uid_out.get("sign_in", {})
    check("top offenders card: a 200 that is a web page (a sign-in or proxy page) says so and to reload, "
          "and paints none of the card's controls from it",
          "web page" in _p133.get("top", "") and _p133.get("wl") in (None, "") and _p133.get("tog") in (None, False),
          repr(_uid_out))
    check("security tab: the bans and events cards name the same failures (the whole class, not one card)",
          all("did not answer" in _n133.get(k, "") and "HTTP 502" in _g133.get(k, "") for k in ("bans", "events")),
          repr(_uid_out))
    _ok133 = _uid_out.get("good", {})
    check("top offenders card: a good answer still paints the table, the whitelist and the Auto-block switch",
          "offender-a" in _ok133.get("top", "") and "Nothing whitelisted" in (_ok133.get("wl") or "")
          and _ok133.get("tog") is True, repr(_uid_out))

check("ui-dense: rendering and reading reached no real transport",
      len(_P9_TRIPPED) == _TRIP133_START, repr(_P9_TRIPPED[_TRIP133_START:]))
