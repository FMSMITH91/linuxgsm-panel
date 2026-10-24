"""Part 131 of the unit suite: the host page's Network tab (ui-network-tab).

The firewall was a card on Host Controls that only linked to a page of its own, and Connection & SSH
was that tab's last card. Both are on a Network tab now, the firewall's cards rendered there from the
same partial (_firewall_panel.html) and script (remote_firewall.js) as the standalone page, which
still answers its old URL. Held here:

* REACHABILITY, not presence: every control that moved, and every one that stayed on Host Controls,
  is inside the tab it should be in AND that tab's button is in the page's nav, on the panel host's
  page and on a remote's. A later edit that drops a control, or leaves it under a tab nobody can
  open, fails by name. Every control of the standalone page's cards is on the tab too.
* The tab's firewall cards say "Loading…" and claim no count until read (the page makes no
  firewall read while it loads), and remote_firewall.js is loaded wherever the tab is.
* No link on the host page or the Remote Servers list still points at the old page; the SSH port
  card and the Security tab link into the tab, the palette finds the panel host's firewall.
* remote_manage.js's tab script, in node: #network and a #card inside it open the tab, the first
  opening reads the firewall once (after DOMContentLoaded when the page is still parsing, since
  remote_firewall.js loads after it), and the active pill is scrolled into the phone-width bar.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed and every host call stubbed,
as part103 does; the tab script in node on a DOM of its own. Nothing reaches a host or data/.
"""
import json as _json131
import os
from html.parser import HTMLParser as _HTMLParser131

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9_arm, _p9_client, _p9_patch, _p9_restore_all,
                         _p9_rv)
from unit.part47 import _cut47, _node47
from panel.ops import system_ops as _so131
from panel.ops import tailscale_integration as _ts131
from panel.ops.ssh_manager import _core as _smc131

_TRIP131_START = len(_P9_TRIPPED)


def _read131(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


_VOID131 = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
            "track", "wbr"}


class _Tabs131(_HTMLParser131):
    """Which data-mtab section each id and each data-action sits in, and the nav's tab buttons."""

    def __init__(self):
        super().__init__()
        self.stack = []            # (tag, the data-mtab in force inside it)
        self.where = {}            # id -> data-mtab (None outside every section)
        self.actions = {}          # data-mtab -> set of data-action names
        self.hrefs = []            # (href, data-mtab)
        self.buttons = set()
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        tab = a.get("data-mtab") or (self.stack[-1][1] if self.stack else None)
        if a.get("id"):
            self.where[a["id"]] = tab
        if a.get("data-action"):
            self.actions.setdefault(tab, set()).add(a["data-action"])
        if a.get("href") is not None:
            self.hrefs.append((a["href"], tab))
        if a.get("data-mtab-btn"):
            self.buttons.add(a["data-mtab-btn"])
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        if tag not in _VOID131:
            self.stack.append((tag, tab))

    def handle_endtag(self, tag):
        # Pop back to the matching open tag: a stray end tag (none expected) cannot unwind the rest.
        for k in range(len(self.stack) - 1, -1, -1):
            if self.stack[k][0] == tag:
                del self.stack[k:]
                return


def _parse131(html):
    p = _Tabs131()
    p.feed(html)
    return p


# The controls each tab must hold, on every host page (a superadmin's view).
_NETWORK131 = ("sec-firewall", "network-jump", "fw-rules", "fw-blocks", "ufw-badge", "ufw-status-note",
               "rules-list", "rules-count", "blocks-list", "blocks-count", "blocks-inactive-note",
               "new-port", "new-proto", "new-comment", "port-result", "src-cidr", "src-port", "src-proto",
               "limit-port", "limit-proto", "restrict-result", "block-ip", "block-result",
               "conn-ssh-card", "sec-connection", "ssh-mode", "ssh-msg", "ssh-port-now", "ssh-port-input",
               "ssh-bind-input", "ssh-port-msg")
_NETWORK_LOCAL131 = ("ts-ssh-badge", "panel-bind-select", "panel-bind-custom", "panel-port-input",
                     "panel-port-msg", "panel-port-change-msg")
_NETWORK_REMOTE131 = ("conn-method", "migrate-msg", "hostkey-msg")
_CONTROLS131 = ("os-updates", "sec-osupdates", "btn-install-updates", "update-info", "sec-terminal",
                "sec-power", "power-state", "disc-scan-btn", "disc-result")
_NET_ACTIONS131 = {"refreshFirewall", "openPort", "allowFromSource", "removeAllowFromSource", "limitPort",
                   "unlimitPort", "blockIp", "sshMode", "changeSshPort"}
_NET_ACTIONS_LOCAL131 = {"changePanelBinding", "onBindSelect", "ufwAllowTailscale"}
_NET_ACTIONS_REMOTE131 = {"retrustHostKey", "switchToTailscale"}

_STATUS131 = {"has_sudo": True, "ufw": {"enabled": True, "rules": []},
              "tailscale_ssh": {"enabled": False, "running": True}, "tailscale_ssh_allowed": False,
              "tailscale_interface": "tailscale0", "tailscale_ufw_allowed": False, "updates": {},
              "uptime": ""}
_GROUP131 = {"is_block": False, "is_iface": False, "port_num": "27015", "proto_label": "BOTH",
             "comment": "game", "action": "ALLOW", "scope": "Any address", "family_label": "IPv4",
             "protected": False, "nums": [2], "warn": False, "key": "27015|both|any"}
_ADDR131 = "203.0.113.50"   # NOSONAR(S1313) - a documentation address in a stand-in firewall row; never dialled
_BLOCK131 = {"is_block": True, "block_ip": _ADDR131, "comment": "panel-block", "family_label": "IPv4",
             "nums": [1], "key": "block|" + _ADDR131}
_UFW131 = {"installed": True, "enabled": True, "rules": [], "groups": [_GROUP131, _BLOCK131]}

_pages131 = {}
try:
    _p9_arm(who="part131")
    _p9_patch(_so131, "get_server_status", lambda *a, **k: _STATUS131)
    _p9_patch(_ts131, "panel_funnel_facts", lambda cfg: {})
    _p9_patch(_smc131, "run_privileged", lambda *a, **k: ("", "", 1))
    _p9_patch(_smc131, "run_command", lambda *a, **k: ("", "", 1))
    _p9_patch(_p9_rv, "remote_ufw_status", lambda remote: _UFW131)
    for _k131, _url131 in (("local", "/server-management"), ("remote", "/remote/%d/manage" % P9_HOST),
                           ("firewall", "/remote/%d/firewall" % P9_HOST)):
        _r131 = _p9_client(P9_ADMIN).get(_url131)
        _pages131[_k131] = (_r131.status_code, _r131.get_data(as_text=True))
finally:
    _p9_restore_all()

check("network tab: every host page renders (the panel host's, a remote's and the standalone firewall page)",
      len(_pages131) == 3 and all(st == 200 for st, _h in _pages131.values()),
      repr({k: v[0] for k, v in _pages131.items()}))
_P131 = {k: _parse131(h) for k, (_st, h) in _pages131.items()}


def _misplaced131(page, tab, ids):
    """The ids of `ids` that are not inside section `tab` of `page`, or not reachable (no tab button)."""
    p = _P131.get(page)
    if p is None:
        return ["<no page>"]
    if tab not in p.buttons:
        return ["<no %s tab button>" % tab]
    return [i for i in ids if p.where.get(i, "<absent>") != tab]


for _page131, _extra131, _acts131 in (("local", _NETWORK_LOCAL131, _NET_ACTIONS_LOCAL131),
                                      ("remote", _NETWORK_REMOTE131, _NET_ACTIONS_REMOTE131)):
    _bad131 = _misplaced131(_page131, "network", _NETWORK131 + _extra131)
    check("network tab (%s host page): the firewall's cards and Connection & SSH are on the Network tab, "
          "and the tab is offered in the nav" % _page131, not _bad131,
          repr({i: _P131[_page131].where.get(i, "<absent>") for i in _bad131} if _page131 in _P131 else _bad131))
    _have131 = _P131[_page131].actions.get("network", set()) if _page131 in _P131 else set()
    check("network tab (%s host page): every firewall and SSH action is a control on that tab"
          % _page131, (_NET_ACTIONS131 | _acts131) <= _have131,
          repr(sorted((_NET_ACTIONS131 | _acts131) - _have131)))
    _bad131 = _misplaced131(_page131, "controls", _CONTROLS131)
    check("network tab (%s host page): OS Updates, Terminal, Power and Existing servers stay on Host "
          "Controls" % _page131, not _bad131,
          repr({i: _P131[_page131].where.get(i, "<absent>") for i in _bad131} if _page131 in _P131 else _bad131))
    _btns131 = sorted(_P131[_page131].buttons) if _page131 in _P131 else []
    check("network tab (%s host page): the five tabs are offered" % _page131,
          _btns131 == ["controls", "maintenance", "network", "overview", "security"], repr(_btns131))
    _src131 = [s for s in (_P131[_page131].scripts if _page131 in _P131 else []) if "remote_firewall.js" in s]
    check("network tab (%s host page): remote_firewall.js is loaded, whose functions the tab's controls "
          "and its rule rows (deleteGroup, unblockIp) call" % _page131, len(_src131) == 1, repr(_src131))

# Every control of the standalone page's cards is on the tab. Its rows' deleteGroup/unblockIp come from
# its server-side read; on the tab the script draws them (remote_firewall.js, checked above).
_fwp131 = _P131.get("firewall")
_PARTIAL131 = _read131("templates", "_firewall_panel.html")
# The cards' own actions: the page's chrome (sidebar, palette, 2FA nag) carries others.
_fw_actions131 = {a for a in (set().union(*_fwp131.actions.values()) if _fwp131 else set())
                  if 'data-action="%s"' % a in _PARTIAL131}
_fw_ids131 = {i for i in (_fwp131.where if _fwp131 else {})
              if 'id="%s"' % i in _PARTIAL131 and i not in ("rules-body", "blocks-body")}
_net131 = _P131["remote"].actions.get("network", set()) if "remote" in _P131 else set()
check("network tab: the standalone Firewall page still renders its read (a rule row and a block row, "
      "with their delete and unblock)", {"deleteGroup", "unblockIp", "openPort", "blockIp"} <= _fw_actions131,
      repr(sorted(_fw_actions131)))
check("network tab: every control of the standalone Firewall page's cards is on the Network tab too",
      (_fw_actions131 - {"deleteGroup", "unblockIp"}) <= _net131 and len(_fw_ids131) > 15
      and not [i for i in _fw_ids131 if _P131["remote"].where.get(i) != "network"],
      repr((sorted(_fw_actions131 - _net131), sorted(i for i in _fw_ids131
                                                     if _P131["remote"].where.get(i) != "network"))))


def _net_text131(page):
    """The Network tab's firewall section of a rendered page, as text."""
    html = _pages131.get(page, (0, ""))[1]
    i = html.find('id="network-firewall"')
    j = html.find('id="conn-ssh-card"', i)
    return html[i:j] if i >= 0 and j > i else ""


for _page131 in ("local", "remote"):
    _t131 = _net_text131(_page131)
    check("network tab (%s host page): the firewall cards wait for their read — Checking… and Loading…, no "
          "count and no empty-state claim about a firewall nothing read" % _page131,
          "Checking…" in _t131 and _t131.count("Loading…") >= 3
          and 'id="rules-count">&mdash;' in _t131 and 'id="blocks-count">&mdash;' in _t131
          and "No firewall rules yet." not in _t131 and "No IPs are blocked." not in _t131
          and "not installed" not in _t131.partition('id="ufw-status-note"')[2].partition("</div>")[0],
          _t131[:300])

_links131 = {k: [h for h, _tab in _P131[k].hrefs if "/firewall" in h] for k in ("local", "remote") if k in _P131}
check("network tab: nothing on the host pages links to the old Firewall page",
      len(_links131) == 2 and not any(_links131.values()), repr(_links131))
# The Remote Servers list, as its template writes the button (the page needs more than part12's app
# serves): it opens the host's Network tab, and nothing there names the old page's endpoint.
_MR131 = _read131("templates", "manage_remotes.html")
check("network tab: the Remote Servers list's Firewall button opens the host's Network tab",
      "url_for('remote_manage', remote_id=remote.id) }}#network\" class=\"btn btn-outline-info btn-sm\" "
      "title=\"Open or close firewall ports\"" in _MR131 and "url_for('remote_firewall'" not in _MR131, "")
for _page131 in ("local", "remote"):
    _in131 = {(h, tab) for h, tab in (_P131[_page131].hrefs if _page131 in _P131 else [])
              if h in ("#sec-firewall", "#fw-rules", "#fw-blocks", "#sec-connection")}
    check("network tab (%s host page): the SSH port card and the jump line link into the tab, and the "
          "Security tab to its Blocked IPs" % _page131,
          {("#sec-firewall", "network"), ("#fw-rules", "network"), ("#fw-blocks", "network"),
           ("#sec-connection", "network"), ("#fw-blocks", "security")} <= _in131, repr(sorted(_in131)))
_pw131 = [h for h, tab in (_P131["local"].hrefs if "local" in _P131 else []) if h.endswith("/settings#sec-reboots")]
check("network tab: the Power card links a superadmin to the Settings page's Host reboots",
      len(_pw131) == 1 and _P131["local"].where.get("sec-power") == "controls", repr(_pw131))

_PAL131 = _read131("static", "js", "palette.js")
check("network tab: the command palette finds the panel host's firewall and Connection & SSH (its host rows "
      "expand over remote hosts only)",
      "page: '/server-management', hash: 'sec-firewall'" in _PAL131
      and "page: '/server-management', hash: 'sec-connection'" in _PAL131, "")

_CAT131 = {}
for _lang131 in ("es", "fr"):
    for _f131 in sorted(os.listdir(os.path.join(_root, "translations", _lang131))):
        if _f131.endswith(".json"):
            _CAT131.setdefault(_lang131, {}).update(_json131.loads(_read131("translations", _lang131, _f131)))
_NEW131 = ("Network", "Jump to:", "Network tab sections", "Go to the firewall rules", "Firewall — panel host",
           "Connection & SSH — panel host",
           "Lockout-safe: the current binding stays in place as a fallback, and the firewall and fail2ban are "
           "updated to the new port. Once you've confirmed you can reach SSH on {port}, close the old port in "
           "the firewall rules on the Network tab.")
check("network tab: its new words are in the es and fr catalogs",
      all(k in _CAT131.get(lang, {}) for lang in ("es", "fr") for k in _NEW131),
      repr([(lang, k) for lang in ("es", "fr") for k in _NEW131 if k not in _CAT131.get(lang, {})]))

check("network tab: rendering the pages reached no real transport",
      len(_P9_TRIPPED) == _TRIP131_START, repr(_P9_TRIPPED[_TRIP131_START:]))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# remote_manage.js's tab script, in node
# ════════════════════════════════════════════════════════════════════════════════════════════════
_RM131 = _read131("static", "js", "remote_manage.js")
_HEAD131 = "(function(){\n  var nav = document.getElementById('mtab-nav'); if(!nav) return;"
_IIFE131 = (_cut47(_RM131, _HEAD131) + ")();") if _HEAD131 in _RM131 else "/* MISSING the tab script */"
_PROG131 = r"""
const SRC = %s;
const TABS = [['overview', 16, 135], ['controls', 135, 285], ['network', 285, 396],
              ['maintenance', 396, 540], ['security', 540, 650]];
function el(attrs, rect) {
  return { attrs, style: {}, cls: new Set(), _sec: null,
    classList: { toggle(c, on) { on ? this._o.cls.add(c) : this._o.cls.delete(c); } },
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
    getBoundingClientRect() { return rect || {left: 0, right: 10}; },
    scrollIntoView() { state.scrolled.push(this.attrs.id); },
    closest(sel) { return sel === '[data-mtab]' ? this._sec : (sel === '[data-mtab-btn]' ? this : null); } };
}
let state;
function run(ready, hash, fwEarly) {
  const secs = TABS.map(t => el({'data-mtab': t[0]}));
  const btns = TABS.map(t => el({'data-mtab-btn': t[0]}, {left: t[1], right: t[2]}));
  btns.forEach(b => { b.classList._o = b; }); secs.forEach(s => { s.classList._o = s; });
  const card = el({id: 'sec-connection'}); card._sec = secs[2];
  state = {reads: 0, scrolled: [], dcl: [], click: null, btns};
  const nav = { scrollLeft: 0, querySelectorAll() { return btns; },
    querySelector(sel) { const m = /data-mtab-btn="(\w+)"/.exec(sel);
      return m ? btns.find(b => b.attrs['data-mtab-btn'] === m[1]) || null : null; },
    addEventListener(e, f) { state.click = f; }, getBoundingClientRect() { return {left: 16, right: 359}; } };
  state.nav = nav;
  global.document = { readyState: ready,
    getElementById(id) { return id === 'mtab-nav' ? nav : (id === 'sec-connection' ? card : null); },
    querySelectorAll(sel) { return sel === '[data-mtab]' ? secs : []; },
    addEventListener(e, f) { if (e === 'DOMContentLoaded') state.dcl.push(f); } };
  global.location = {hash, search: ''};
  global.history = {replaceState(a, b, u) { location.hash = u; }};
  global.window = global; global.addEventListener = () => {};
  delete global.refreshFirewall; delete global.loadSecurity;
  const fw = () => { state.reads++; };
  if (fwEarly) global.refreshFirewall = fw;
  (0, eval)(SRC);
  if (!fwEarly) global.refreshFirewall = fw;   // remote_firewall.js, loaded after this file
  return state;
}
const active = s => s.btns.filter(b => b.cls.has('active')).map(b => b.attrs['data-mtab-btn']);
const click = (s, t) => s.click({target: s.btns.find(b => b.attrs['data-mtab-btn'] === t)});
const out = {};
let s = run('loading', '#network', false);
out.loading = {before: s.reads, active: active(s), scroll: s.nav.scrollLeft};
s.dcl.forEach(f => f()); out.loading.after = s.reads;
s = run('complete', '#overview', true);
out.click = {start: s.reads, scroll: s.nav.scrollLeft};
click(s, 'network'); out.click.first = s.reads; out.click.active = active(s); out.click.hash = location.hash;
click(s, 'overview'); click(s, 'network'); out.click.again = s.reads;
s = run('complete', '#sec-connection', true);
out.card = {reads: s.reads, active: active(s), scrolled: s.scrolled};
console.log(JSON.stringify(out));
""" % _json131.dumps(_IIFE131)
_out131 = _node47(_PROG131)
_name131 = "network tab script: #network opens the tab and reads the firewall once the page has loaded"
if _out131 is None:
    skip(_name131, "node is not installed here")
else:
    _l131 = _out131.get("loading", {})
    check(_name131 + " (a deep link arrives while the page is still parsing, before remote_firewall.js "
          "exists: the read waits for DOMContentLoaded rather than being lost)",
          _l131.get("active") == ["network"] and _l131.get("before") == 0 and _l131.get("after") == 1,
          repr(_out131))
    check("network tab script: the active pill is scrolled into the phone-width tab bar (Network sat past "
          "its right edge), and a pill already in view leaves the bar where it is",
          _l131.get("scroll", 0) > 0 and _out131.get("click", {}).get("scroll") == 0, repr(_out131))
    _c131 = _out131.get("click", {})
    check("network tab script: opening the tab by its pill reads the firewall the first time only, and "
          "puts #network in the address", _c131.get("start") == 0 and _c131.get("first") == 1
          and _c131.get("again") == 1 and _c131.get("active") == ["network"] and _c131.get("hash") == "#network",
          repr(_out131))
    _d131 = _out131.get("card", {})
    check("network tab script: a link to a card on the tab (#sec-connection) opens the tab, scrolls to the "
          "card and reads the firewall", _d131.get("active") == ["network"] and _d131.get("reads") == 1
          and _d131.get("scrolled") == ["sec-connection"], repr(_out131))
