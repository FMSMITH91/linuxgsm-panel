"""Part 133 of the unit suite: the host page's Network and Security tabs with less scrolling (ui-dense).

1. "Could not load top offenders." The Security tab's cards showed that one line for every way a read can
   fail before its answer is read — the connection dropping, an error page from the panel or the proxy
   in front of it, a sign-in page — and named none of them. Each card now says which it was, and the
   top-ips routes answer JSON even when reading their auto-block settings raises (that escaped as an
   HTML 500, which the card could only call "Could not load").
2. Less scrolling on the Network tab: no UFW Status card with an empty body (its badge is on the Firewall
   heading, its read's note a line under it); Open a Port and Restrict a Port are one "Add a rule" card
   with a switch, one kind of rule shown at a time; the game ports are one line each; Connection & SSH's
   explanations open from their label lines, while every lock-out warning stays in view beside the
   button it warns about.
3. Less scrolling on the Security tab: Blocked IPs and the fail2ban bans side by side on a desktop; Top
   offenders' four paragraphs behind "How auto-block works", its controls in view; the offenders and the
   events capped (10 and 5) behind "Show all"; Raw logs collapsed until wanted, opened by a jail's
   "view log" or a link to it.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed and every host call stubbed, as
part131 does; the tab's readers in node on a DOM of their own. Nothing reaches a host or data/.
"""
import json as _json133
import os
import re as _re133
from html.parser import HTMLParser as _HTMLParser133

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9_arm, _p9_client, _p9_patch, _p9_restore_all)
from unit.part47 import _cut47, _node47
from unit.part131 import _P131, _pages131
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
    "function secBase(", "function _uidReadJson(", "var _UID_WHY", "function _uidFailHtml(", "function _uidCapped(",
    "function loadSecurityTopIps(", "function renderWhitelist(", "function loadSecurityBans(",
    "function loadSecurityEvents("))
_UID_PROG = r"""
const SRC = %s;
const els = {};
global.document = { getElementById(id) {
  return els[id] || (els[id] = {id, innerHTML: '', value: '', checked: false}); } };
global.window = global; global.IS_LOCAL = true; global.MOUNT = '/lgsm'; global.REMOTE_ID = 1;
global.escapeHtml = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;');
global.t = s => s; global.tfHtml = (s, v) => s.replace(/\{(\w+)\}/g, (m, k) => String(v[k]));
global._da = () => '';
(0, eval)(SRC);
const cnt = (id, re) => (els[id].innerHTML.match(re) || []).length;
const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };
const json = body => Promise.resolve({ok: true, status: 200, headers: {get: () => 'application/json'},
                                      json: () => Promise.resolve(body)});
const page = status => Promise.resolve({ok: status < 400, status, headers: {get: () => 'text/html; charset=utf-8'},
                                        json: () => Promise.reject(new SyntaxError('Unexpected token <'))});
const CASES = {
  net: () => Promise.reject(new TypeError('Failed to fetch')),
  bad_gateway: () => page(502),
  sign_in: () => page(200),
  good: () => json({autoblock: true, threshold: 30, whitelist: [], installed: true, jails: [],
                    ips: Array.from({length: 12}, (_, i) => ({ip: i ? 'offender-' + i : 'offender-a',
                                                             attempts: 20 - i, bans: 0, jails: ['sshd']})),
                    events: Array.from({length: 15}, (_, i) => ({time: '', action: 'login_failed', user: 'u' + i,
                                                                 detail: '', ip: 'ev-' + i}))}),
};
(async () => {
  const out = {};
  for (const k in CASES) {
    for (const id in els) delete els[id];
    global.fetch = CASES[k];
    loadSecurityTopIps(); loadSecurityBans(); loadSecurityEvents(); await settle();
    out[k] = {top: els['sec-top'].innerHTML,
              rows: [cnt('sec-top', /<tr>/g), cnt('sec-top', /<tr hidden>/g),
                     cnt('sec-events', /<tr>/g), cnt('sec-events', /<tr hidden>/g)],
              bans: els['sec-bans'].innerHTML, events: els['sec-events'].innerHTML,
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
    # [shown offender rows (+1 header), hidden, shown event rows (+1 header), hidden]
    check("security tab: 12 offenders show their first 10 and 15 events their latest 5, each with a \"Show "
          "all\" for the rest (drawn hidden, not dropped)",
          _ok133.get("rows") == [11, 2, 6, 10] and "Show all 12" in _ok133.get("top", "")
          and "Show all 15" in _ok133.get("events", ""), repr(_ok133.get("rows")))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2-3. The tabs' layout: what is folded, what stays in view, and every control still on its tab
# ════════════════════════════════════════════════════════════════════════════════════════════════
_VOID133 = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
            "track", "wbr"}


class _Fold133(_HTMLParser133):
    """Where each id and each text sits: folded, in a summary, in a card.

    Folded is inside a closed <details> body; a summary is the label line, always in view. Also each
    id's attributes.
    """

    def __init__(self):
        super().__init__()
        self.stack = []
        self.ids = {}
        self.texts = []
        self.attrs = {}

    def _state(self):
        """(folded, in a summary, in a card) where the parser is now."""
        folded = summary = card = False
        for k, (tag, a) in enumerate(self.stack):
            # Inside a closed <details>, and not in its own <summary> (its first child, always shown).
            if tag == "details" and a.get("open") is None and self.stack[k + 1:k + 2] != [] \
                    and self.stack[k + 1][0] != "summary":
                folded = True
            if tag == "summary":
                summary = True
            if "card" in (a.get("class") or "").split():
                card = True
        return folded, summary, card

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag not in _VOID133:
            self.stack.append((tag, a))
        st = self._state()
        if a.get("id"):
            self.ids[a["id"]] = st
            self.attrs[a["id"]] = a
        if tag in _VOID133 and a.get("id"):
            self.ids[a["id"]] = st

    def handle_endtag(self, tag):
        for k in range(len(self.stack) - 1, -1, -1):
            if self.stack[k][0] == tag:
                del self.stack[k:]
                return

    def handle_data(self, data):
        t = " ".join(data.split())
        if t:
            self.texts.append((t, self._state()))


def _fold133(page):
    p = _Fold133()
    p.feed(_pages131.get(page, (0, ""))[1])
    return p


_F133 = {k: _fold133(k) for k in ("local", "remote")}


def _text_state133(page, needle):
    """(folded, in a summary, in a card) of the first text node containing `needle`, or None."""
    return next((st for t, st in _F133[page].texts if needle in t), None)


for _pg133 in ("local", "remote"):
    _ids133 = _F133[_pg133].ids
    _html133 = _pages131.get(_pg133, (0, ""))[1]
    check("network tab (%s host page): no UFW Status card — the badge is on the Firewall heading and the read's "
          "note a line under it, outside any card" % _pg133,
          "UFW Status" not in _html133 and _ids133.get("ufw-badge", (1, 1, 1))[2] is False
          and _ids133.get("ufw-status-note", (1, 1, 1))[2] is False
          and _html133.find('id="sec-firewall"') < _html133.find('id="ufw-badge"')
          < _html133.find("</h2>", _html133.find('id="sec-firewall"')),
          repr((_ids133.get("ufw-badge"), _ids133.get("ufw-status-note"))))
    _a133 = _F133[_pg133].attrs
    _modes133 = {m: _a133.get("fw-mode-" + m, {}) for m in ("open", "src", "limit")}
    _panels133 = dict(_re133.findall(r'<div data-fw-mode="(\w+)"( hidden)?>', _html133))
    check("network tab (%s host page): Add a rule's switch — Open checked and its form the one shown, One source "
          "and Rate-limit hidden, each radio calling fwAddMode on change" % _pg133,
          all(_modes133[m].get("data-action") == "fwAddMode" and _modes133[m].get("data-on") == "change"
              and _modes133[m].get("data-args") == '["%s"]' % m for m in _modes133)
          and "checked" in _modes133["open"] and "checked" not in _modes133["src"]
          and _panels133 == {"open": "", "src": " hidden", "limit": " hidden"}, repr((_modes133, _panels133)))
    _order133 = [_html133.find('id="%s"' % i) for i in ("fw-add", "new-port", "port-result", "src-cidr",
                                                        "limit-port", "restrict-result")]
    check("network tab (%s host page): every field and result line of the two old cards is in Add a rule, in "
          "the switch's order" % _pg133, -1 not in _order133 and _order133 == sorted(_order133), repr(_order133))
    # What a setting is FOR folds; what an action RISKS does not.
    _warn133 = [st for t, st in _F133[_pg133].texts
                if "lock yourself out" in t or "you'd lock yourself out" in t or "Lockout-safe" in t
                or "lockout-safe" in t or "Funnel is on" in t or "While UFW is inactive" in t
                or "Blocking an IP denies it on every port" in t]
    check("network/security tabs (%s host page): every lock-out warning, the SSH port move's safety note, the "
          "inactive-firewall note and what a block does stay in view (never folded into an explanation)" % _pg133,
          bool(_warn133) and not any(st[0] for st in _warn133), repr(_warn133))
    _expl133 = ["keeps working regardless",
                "Entries marked Auto are managed by the rolling auto-block",
                "Because that count is cumulative", "Reachable only over Tailscale?"]
    _expl_st133 = {e: _text_state133(_pg133, e) for e in _expl133}
    if _pg133 == "local":
        for _e133 in ("SSH into this host over your tailnet", "Keeps the panel reachable over the tailnet in UFW."):
            _expl_st133[_e133] = _text_state133(_pg133, _e133)
    check("network/security tabs (%s host page): the long explanations are folded behind their label lines"
          % _pg133, all(st is not None and st[0] for st in _expl_st133.values()), repr(_expl_st133))
    _labels133 = {i: _ids133.get(i) for i in ("ssh-mode",) + (("ts-ssh-badge",) if _pg133 == "local" else ())}
    check("network tab (%s host page): the label lines that open them still show their live state (Currently:, "
          "the Tailscale SSH badge) — in the summary, in view" % _pg133,
          all(st is not None and st[1] and not st[0] for st in _labels133.values()), repr(_labels133))
    _sec133 = _P131[_pg133] if _pg133 in _P131 else None
    check("security tab (%s host page): Blocked IPs and the bans are one side-by-side pair, Top offenders' "
          "threshold and whitelist in view under a folded \"How auto-block works\", and Raw logs a closed "
          "card on the tab" % _pg133,
          _html133.find('<div class="uid-pair">') < _html133.find('id="fw-blocks"') < _html133.find('id="sec-bans"')
          and _html133.find('<div class="uid-pair">') >= 0
          and _ids133.get("sec-threshold", (1,))[0] is False and _ids133.get("sec-autoblock", (1,))[0] is False
          and _text_state133(_pg133, "How auto-block works") is not None
          and "open" not in _a133.get("sec-rawlogs-card", {"open": ""})
          and _sec133 is not None and _sec133.where.get("sec-rawlogs-card") == "security"
          and _sec133.where.get("sec-log") == "security", repr(_a133.get("sec-rawlogs-card")))
    _net133 = _P131[_pg133].actions.get("network", set()) if _pg133 in _P131 else set()
    check("network tab (%s host page): the switch's action is a control on the Network tab" % _pg133,
          "fwAddMode" in _net133, repr(sorted(_net133)))

_FWP133 = _read133("templates", "_firewall_panel.html")
_games133 = _pages131.get("remote", (0, ""))[1]
_LI133 = '<li class="list-group-item d-flex align-items-center gap-2 py-1">'
check("network tab: the game ports are one line each — name, port, Open all ports — not a table of three lines "
      "a game (the remote page, whose host has games)",
      _LI133 in _FWP133 and "<th>Server</th>" not in _FWP133
      and _games133.count('data-action="syncPorts"') >= 1
      and _games133.count('data-action="syncPorts"') == _games133.count(_LI133),
      repr(_games133.count('data-action="syncPorts"')))

_CSS133 = _read133("static", "css", "panel.css")
_pair133 = _re133.search(r"@media \(width >= 992px\)\{\s*\.uid-pair\{([^}]*)\}", _CSS133)
check("security tab: the pair is two columns from 992px (range notation), one above the other below it",
      _pair133 is not None and "grid-template-columns:1fr 1fr" in _pair133.group(1), "")

# The switch, the "Show all" and the folds' openers, in node.
_FW133 = _read133("static", "js", "remote_firewall.js")
_FOLD_PROG133 = r"""
const SRC = %s;
const mk = (attrs) => ({attrs, hidden: !!attrs.hidden, open: false,
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }});
const panels = ['open', 'src', 'limit'].map(m => mk({'data-fw-mode': m, hidden: m !== 'open'}));
const rows = [mk({}), mk({hidden: true}), mk({hidden: true})];
const details = mk({}); const logEl = {textContent: '', closest: s => s === 'details' ? details : null,
  setAttribute() {}, removeAttribute() {}, scrollIntoView() {}};
const btn = {removed: 0, remove() { this.removed++; },
  parentElement: {querySelectorAll: s => s === 'tr[hidden]' ? rows.filter(r => r.hidden) : []}};
global.document = { querySelectorAll: s => s === '#fw-add [data-fw-mode]' ? panels : [],
  getElementById: id => id === 'sec-log' ? logEl : null };
global.window = global; global.t = s => s; global.tf = s => s; global.IS_LOCAL = true; global.MOUNT = '';
global.fetch = () => new Promise(() => {});
(0, eval)(SRC);
const out = {};
fwAddMode('limit'); out.limit = panels.map(p => p.hidden);
fwAddMode('src'); out.src = panels.map(p => p.hidden);
uidShowAll(btn); out.shown = rows.map(r => r.hidden); out.removed = btn.removed;
loadSecurityLog('ssh'); out.logOpen = details.open;
console.log(JSON.stringify(out));
""" % _json133.dumps("\n".join(
    [_cut47(_FW133, "function fwAddMode(") if "function fwAddMode(" in _FW133 else "",
     _uid_cut("function uidShowAll("), _uid_cut("function secBase("),
     _uid_cut("function _r21cLogNote("), _uid_cut("function loadSecurityLog(")]))
_fo133 = _node47(_FOLD_PROG133)
if _fo133 is None:
    skip("network tab: Add a rule's switch shows one kind of rule at a time", "node is not installed here")
else:
    check("network tab: Add a rule's switch shows the chosen kind's form and hides the others (nothing cleared)",
          _fo133.get("limit") == [True, True, False] and _fo133.get("src") == [True, False, True], repr(_fo133))
    check("security tab: \"Show all\" shows every row it held back, and goes",
          _fo133.get("shown") == [False, False, False] and _fo133.get("removed") == 1, repr(_fo133))
    check("security tab: a jail's \"view log\" opens the collapsed Raw logs card it writes into",
          _fo133.get("logOpen") is True, repr(_fo133))
_RMH133 = _uid_cut("function openHash(")
check("host page: a link to a card inside a collapsed one (#sec-rawlogs) opens it before scrolling there",
      "el.closest('details')" in _RMH133 and "fold.open = true" in _RMH133
      and _RMH133.find("fold.open = true") < _RMH133.find("el.scrollIntoView()"), _RMH133[:200])

check("ui-dense: rendering and reading reached no real transport",
      len(_P9_TRIPPED) == _TRIP133_START, repr(_P9_TRIPPED[_TRIP133_START:]))
