"""Part 134 of the unit suite: less scrolling (ui-scroll).

The owner, on a phone and a wide desktop: "go through all the pages and find any pages that you have to
scroll... and if you have to scroll a lot then try and fix it". Files & Config was eight phone screens,
Notifications six, the Maintenance backups list grew a screen per few servers, and every page opened with
three alerts half a phone screen tall. Sections now sit behind tabs and folds. Held here:

* REACHABILITY, not presence: every control on Files & Config is inside the section its tab opens, every
  section has its tab and every tab its section, on a superadmin's page, a file manager's (no Backups) and
  a failed install's (no Files or Mods). A control left in a section nobody can open fails by name.
* The section script, in node: a #hash opens its section, an unknown or absent one opens Config, a click
  puts the section in the address.
* Alerts on Files & Config: only the services in use are open; the rest are one "Add a service" tap away
  and keep their fields (saveAlerts still reads them).
* Notifications: every field the save route reads is still in the form; the command-bot folds open by
  themselves when the bot is in use.
* The server page: the console first by DEFAULT, a saved order still wins; the eight maintenance commands
  are the same actions in a menu, each keeping its confirmation.
* The page alerts: one line each, every action still there (2FA's three buttons, the reboot banner's two,
  each host's updates link and the dismiss).
* The Maintenance backups list: each server's backups folded behind a count, the schedule and "Back up
  now" outside the fold, an open list kept open across a refresh.
* Account sessions: three shown and "Show all N", this device never hidden. Audit filters folded on a
  phone only, and open while a filter is in use. The moved Settings cards, the folded help on Global Bans,
  Custom Commands and Tailscale: every control still rendered.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed and every host call stubbed; the
page scripts in node on small DOMs of their own. Nothing reaches a host or data/.
"""
import json as _json134
import os
import re as _re134
from html.parser import HTMLParser as _HTMLParser134

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch,
                         _p9_restore_all, _p9_set)
from unit.part47 import _cut47, _node47
from panel.db.models import GameServer as _GS134, User as _User134, db as _db134
from panel.ops.ssh_manager import _core as _smc134
from panel.routes import server_detail as _sd134
from panel.services import notifications as _nt134

_TRIP134_START = len(_P9_TRIPPED)


def _read134(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


_VOID134 = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
            "track", "wbr"}


class _Page134(_HTMLParser134):
    """Where each id, data-action and form field sits: its section, the <details> it is folded in."""

    def __init__(self):
        super().__init__()
        self.stack = []        # (tag, section in force, inside a closed <details>, inside an open one)
        self.where = {}        # id -> section (data-sfsub) or None
        self.folded = {}       # id -> True when inside a <details> that is not open
        self.actions = {}      # data-action -> [section, ...]
        self.names = set()     # form field names
        self.buttons = []      # data-sfsub-btn values, in order
        self.sections = []     # data-sfsub values, in order
        self.attrs = {}        # id -> attrs

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        top = self.stack[-1] if self.stack else (None, None, False)
        sec = a.get("data-sfsub") or top[1]
        closed = top[2] or (tag == "details" and "open" not in a)
        self._tabs(a)
        self._record(tag, a, sec, closed)
        if tag not in _VOID134:
            self.stack.append((tag, sec, closed))

    def _tabs(self, a):
        """The section and tab-button lists, in document order."""
        if a.get("data-sfsub"):
            self.sections.append(a["data-sfsub"])
        if a.get("data-sfsub-btn"):
            self.buttons.append(a["data-sfsub-btn"])

    def _record(self, tag, a, sec, closed):
        """Where this element's id, action and field name sit."""
        if a.get("id"):
            self.where[a["id"]] = sec
            self.folded[a["id"]] = closed
            self.attrs[a["id"]] = a
        if a.get("data-action"):
            self.actions.setdefault(a["data-action"], []).append(sec)
        if a.get("name") and tag in ("input", "select", "textarea"):
            self.names.add(a["name"])

    def handle_endtag(self, tag):
        for k in range(len(self.stack) - 1, -1, -1):
            if self.stack[k][0] == tag:
                del self.stack[k:]
                return


def _parse134(html):
    p = _Page134()
    p.feed(html or "")
    return p


def _get134(uid, url):
    r = _p9_client(uid).get(url)
    return r.status_code, r.get_data(as_text=True)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Files & Config: every control inside the section its tab opens
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SECTIONS134 = {
    "config": ("cfg-tabs", "cfg-form", "cfg-groups", "game-cfg", "cfg-raw"),
    "files": ("file-browser", "file-list", "breadcrumb", "upload-input", "upload-dir-input", "editor"),
    "backups": ("backup-card", "bk-interval", "bk-keep", "bk-now", "bk-rows"),
    "schedule": ("cron-card", "cron-form", "cron-sched", "cron-cmd", "cron-submit", "cron-cancel",
                 "cron-help", "cron-presets", "cron-explain", "cron-desc", "cron-msg", "cron-tbody"),
    "alerts": ("alerts-card", "alerts-body", "alerts-msg"),
    "mods": ("mods-card", "mods-list", "mods-body"),
}
_ACTIONS134 = {"saveConfig": "config", "saveGameCfg": "config", "saveRaw": "config",
               "doUpload": "files", "saveBkSchedule": "backups", "backupNow": "backups",
               "saveCron": "schedule", "cancelCronEdit": "schedule", "saveAlerts": "alerts",
               "testAlert": "alerts", "loadMods": "mods"}
_files134 = {}
_FILE_USER134 = None
try:
    from unit.part12 import P9_FILES as _FILE_USER134   # a file manager on host 1, not a superadmin
except ImportError:
    _FILE_USER134 = None
try:
    _p9_arm(who="part134")
    _p9_patch(_smc134, "run_command", lambda *a, **k: ("", "", 1))
    _files134["admin"] = _get134(P9_ADMIN, "/server/%d/files" % P9_GS)
    if _FILE_USER134 is not None:
        _files134["files"] = _get134(_FILE_USER134, "/server/%d/files" % P9_GS)
    with _p9.app_context():
        _was134 = _db134.session.get(_GS134, P9_GS).status
    _p9_set(P9_GS, status="failed")
    _files134["failed"] = _get134(P9_ADMIN, "/server/%d/files" % P9_GS)
    _p9_set(P9_GS, status=_was134)
finally:
    _p9_restore_all()

check("files & config: the page renders for a superadmin, a file manager and a failed install",
      [v[0] for v in _files134.values()] == [200] * len(_files134) and len(_files134) >= 2,
      repr({k: v[0] for k, v in _files134.items()}))
_FP134 = {k: _parse134(h) for k, (_s, h) in _files134.items()}


def _sf_misplaced134(page, want):
    """Controls of the sections `want` that are not in their section, and sections with no tab."""
    p = _FP134.get(page)
    if p is None:
        return ["<no page>"]
    bad = ["<no %s tab>" % s for s in want if s not in p.buttons]
    for sec in want:
        bad += ["%s in %s" % (i, p.where.get(i, "<absent>")) for i in _SECTIONS134[sec]
                if p.where.get(i, "<absent>") != sec]
    for act, sec in _ACTIONS134.items():
        if sec in want and sec not in p.actions.get(act, []):
            bad.append("action %s in %s" % (act, p.actions.get(act)))
    return bad


_bad134 = _sf_misplaced134("admin", list(_SECTIONS134))
check("files & config (superadmin): every control is inside the section its tab opens, and all six "
      "sections have a tab", not _bad134, repr(_bad134))
_a134 = _FP134.get("admin")
check("files & config: the tabs and the sections are the same six, in the same order (no tab opening "
      "nothing, no section no tab opens)",
      _a134 is not None and _a134.buttons == _a134.sections
      == ["config", "files", "backups", "schedule", "alerts", "mods"],
      repr((_a134.buttons, _a134.sections) if _a134 else None))
_first134 = {m.group(1): "display:none" in m.group(0)
             for m in _re134.finditer(r'<div [^>]*data-sfsub="([a-z]+)"[^>]*>', _files134.get("admin", (0, ""))[1])}
check("files & config: Config shows from the first paint and every other section is hidden until opened "
      "(no section shifts the page in after load)",
      _first134 == {"config": False, "files": True, "backups": True, "schedule": True, "alerts": True,
                    "mods": True}, repr(_first134))
if "files" in _FP134:
    _f134 = _FP134["files"]
    check("files & config (a file manager): no Backups tab and no Backups card (a superadmin's), the "
          "other five reachable",
          "backups" not in _f134.buttons and "backup-card" not in _f134.where
          and not _sf_misplaced134("files", ["config", "files", "schedule", "alerts", "mods"]),
          repr((_f134.buttons, _sf_misplaced134("files", ["config", "files", "schedule", "alerts", "mods"]))))
else:
    skip("files & config (a file manager): no Backups tab", "part12 exports no file-manager user")
_x134 = _FP134.get("failed")
check("files & config (a failed install): only Config, Schedule and Alerts, each reachable; no Files, "
      "Backups or Mods tab for game files that never downloaded",
      _x134 is not None and _x134.buttons == ["config", "schedule", "alerts"]
      and not _sf_misplaced134("failed", ["config", "schedule", "alerts"]),
      repr((_x134.buttons, _sf_misplaced134("failed", ["config", "schedule", "alerts"])) if _x134 else None))
check("files & config: the cron help (quick picks and field legend) is folded, the schedule's own "
      "message line is not",
      _a134 is not None and _a134.folded.get("cron-presets") is True and _a134.folded.get("cron-msg") is False
      and _a134.folded.get("cron-sched") is False,
      repr({i: _a134.folded.get(i) for i in ("cron-presets", "cron-msg", "cron-sched")} if _a134 else None))

# ── the section script, in node ─────────────────────────────────────────────────────────────────
_SF134 = _read134("static", "js", "server_files.js")
_SFDOM134 = r"""
function El(attrs){ this.attrs = attrs; this.style = {display: attrs.hidden ? 'none' : ''};
  const cl = new Set(attrs.active ? ['active'] : []);
  this.classList = {toggle: (c, on) => on ? cl.add(c) : cl.delete(c), contains: c => cl.has(c)}; }
El.prototype.getAttribute = function(k){ return this.attrs[k] === undefined ? null : this.attrs[k]; };
El.prototype.setAttribute = function(k, v){ this.attrs[k] = String(v); };
const NAMES = %s;
const secs = NAMES.map((n, i) => new El({'data-sfsub': n, hidden: i > 0}));
const btns = NAMES.map((n, i) => new El({'data-sfsub-btn': n, active: i === 0}));
global.history = {replaceState: (a, b, h) => { global.location.hash = h; }};
global.location = {hash: ''};
global.document = {querySelectorAll: s => s === '[data-sfsub]' ? secs : s === '[data-sfsub-btn]' ? btns : []};
const shown = () => secs.filter(e => e.style.display !== 'none').map(e => e.attrs['data-sfsub']);
const active = () => btns.filter(b => b.classList.contains('active')).map(b => b.attrs['data-sfsub-btn']);
"""
_PROG134 = (_SFDOM134 % _json134.dumps(["config", "files", "schedule", "alerts"])
            + _cut47(_SF134, "function _uis_sfSections(") + "\n" + _cut47(_SF134, "function _uis_sfShow(") + "\n"
            + "const out = {};\n"
            + "_uis_sfShow('schedule'); out.click = [shown(), active(), location.hash];\n"
            + "location.hash = '#alerts'; _uis_sfShow('alerts', true); out.hash = [shown(), location.hash];\n"
            + "_uis_sfShow('backups'); out.absent = [shown(), active(), location.hash];\n"
            + "_uis_sfShow('nonsense'); out.junk = shown();\n"
            + "console.log(JSON.stringify(out));\n")
_o134 = _node47(_PROG134)
_n134 = "files & config section script: a tab shows its section alone and puts it in the address"
if _o134 is None:
    skip(_n134, "node is not installed here")
else:
    check(_n134, _o134.get("click") == [["schedule"], ["schedule"], "#schedule"], repr(_o134))
    check("files & config section script: a #hash link (hashchange) opens that section and leaves the "
          "address as linked", _o134.get("hash") == [["alerts"], "#alerts"], repr(_o134))
    check("files & config section script: a section this page does not have (#backups for a file manager, "
          "or junk) opens Config rather than an empty page",
          _o134.get("absent") == [["config"], ["config"], "#config"] and _o134.get("junk") == ["config"],
          repr(_o134))
_init134 = _SF134[_SF134.find("(function(){\n  var nav = document.getElementById('sfsub-nav')"):]
check("files & config section script: the page reads its #hash on load and follows hashchange (a link "
      "into a section of this same page opens it)",
      "addEventListener('hashchange'" in _init134[:900] and "location.hash" in _init134[:900],
      _init134[:300])

# ── Alerts: only the services in use are open ───────────────────────────────────────────────────
_ALDOM134 = r"""
global.MOUNT = ''; global.serverId = 1; global.window = global;
global.escapeHtml = s => String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
function esc(s){ return escapeHtml(s); } var escA = esc;
const els = {'alerts-body': {style: {}, innerHTML: ''}, 'alerts-loading': {style: {}, innerHTML: ''}};
global.document = {getElementById: id => els[id] || null};
const D = {providers: [
  {toggle: 'discordalert', label: 'Discord', fields: [{key: 'discordwebhook', label: 'Webhook'}]},
  {toggle: 'emailalert', label: 'Email', fields: [{key: 'email', label: 'Address'}]},
  {toggle: 'slackalert', label: 'Slack', fields: [{key: 'slackwebhook', label: 'Webhook'}]}],
  values: {discordalert: 'on', discordwebhook: 'https://x', email: 'a@example.com', slackalert: 'off'}};
global.fetch = () => Promise.resolve({json: () => Promise.resolve(D)});
"""
_ALPROG134 = (_ALDOM134 + _cut47(_SF134, "function loadAlerts(") + "\n"
              + "(async () => { loadAlerts(); for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r));\n"
              + "  console.log(JSON.stringify({html: els['alerts-body'].innerHTML})); })();\n")
_al134 = _node47(_ALPROG134)
_aln134 = "files & config alerts: the services in use are open, the others wait behind Add a service"
if _al134 is None:
    skip(_aln134, "node is not installed here")
else:
    _h134 = _al134.get("html", "")
    _boxes134 = {m.group(2): "d-none" in m.group(1)
                 for m in _re134.finditer(r'<div class="([^"]*)" data-uis-alert="(\d+)"', _h134)}
    _adds134 = _re134.findall(r'data-action="_uis_alertAdd" data-args=\'\["@self", (\d+)\]\'', _h134)
    check(_aln134 + " (switched on, or a field filled in, counts as in use)",
          _boxes134 == {"0": False, "1": False, "2": True} and _adds134 == ["2"], repr((_boxes134, _adds134, _h134[:300])))
    check("files & config alerts: a folded service keeps all its fields in the page (saveAlerts reads every "
          "toggle and field, folded or not, and posts only what changed)",
          _h134.count("data-alert-toggle=") == 3 and _h134.count("data-alert-key=") == 3, _h134[:400])
_ADD134 = (r"""
function El(cls){ const s = new Set(cls); this.classList = {remove: c => s.delete(c), has: c => s.has(c)};
  this.removed = false; this.focused = false; }
El.prototype.remove = function(){ this.removed = true; };
El.prototype.querySelector = function(){ return this.input; };
const box = new El(['col-12', 'd-none']); box.input = {focus(){ box.focused = true; }};
const btn = new El([]), none = new El([]), row = new El([]); row.querySelector = () => null;
global.document = {querySelector: s => s === '[data-uis-alert="2"]' ? box : null,
                   getElementById: id => ({'alerts-none': none, 'alerts-add': row})[id] || null};
""" + _cut47(_SF134, "function _uis_alertAdd(") + "\n"
           "_uis_alertAdd(btn, 2);\n"
           "console.log(JSON.stringify({shown: !box.classList.has('d-none'), focused: box.focused, "
           "btnGone: btn.removed, noneGone: none.removed, rowGone: row.removed}));\n")
_ad134 = _node47(_ADD134)
if _ad134 is None:
    skip("files & config alerts: Add a service opens its box", "node is not installed here")
else:
    check("files & config alerts: Add a service opens that service's box, focuses its first field, and "
          "drops its own button (and the empty row once no button is left)",
          _ad134 == {"shown": True, "focused": True, "btnGone": True, "noneGone": True, "rowGone": True},
          repr(_ad134))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Notifications: every field still in the form; the bot folds open when the bot is in use
# ════════════════════════════════════════════════════════════════════════════════════════════════
_ANR134 = _read134("panel", "routes", "admin_notifications.py")
_ANI134 = _ANR134.find("def notifications_save(")
_ANS134 = _ANR134[_ANI134:_ANR134.find("@app.route", _ANI134)]
# The fields notifications_save reads (event_<key> is read for every key in EVENTS, below).
_SAVE_NAMES134 = {n for n in _re134.findall(r'f\.get\("([a-z_]+)"', _ANS134)
                  + _re134.findall(r'_json_str\(f, "([a-z_]+)"', _ANS134) if not n.endswith("_")}
_real_form134 = _nt134.settings_for_form


def _form_with134(**over):
    """settings_for_form with the Telegram/Discord command settings set as given."""
    def fake():
        s = _real_form134()
        for k, v in over.items():
            chan, key = k.split("__")
            s[chan] = dict(s[chan], **{key: v})
        return s
    return fake


_nf134 = {}
try:
    _p9_arm(who="part134")
    _nf134["plain"] = _get134(P9_ADMIN, "/notifications")
    _p9_patch(_nt134, "settings_for_form", _form_with134(telegram__accept_commands=True,
                                                         discord__gateway_problem="no intent"))
    _nf134["inuse"] = _get134(P9_ADMIN, "/notifications")
finally:
    _p9_restore_all()
_NP134 = {k: _parse134(h) for k, (_s, h) in _nf134.items()}
_np134 = _NP134.get("plain")
_form_names134 = _np134.names if _np134 else set()
check("notifications: every field the save route reads is still in the form, folded or not",
      bool(_SAVE_NAMES134) and _SAVE_NAMES134 <= _form_names134 | {"event_" + k for k in _nt134.EVENTS},
      repr(sorted(_SAVE_NAMES134 - _form_names134)))
check("notifications: the setup help and the command bots are folded on a panel that does not use them",
      _np134 is not None and _np134.folded.get("tg-cmd") is True and _np134.folded.get("dc-cmd") is True
      and _np134.folded.get("notifications-discord_bot_token") is True
      and _np134.folded.get("tg-en") is False and _np134.folded.get("notifications-telegram_chat_id") is False,
      repr({i: _np134.folded.get(i) for i in ("tg-cmd", "dc-cmd", "tg-en")} if _np134 else None))
_nu134 = _NP134.get("inuse")
check("notifications: a bot in use (Telegram's switched on; Discord's gateway reporting a problem) has "
      "its fold open from the first paint, so its state and its fault are never behind a tap",
      _nu134 is not None and _nu134.folded.get("tg-cmd") is False and _nu134.folded.get("dc-cmd") is False,
      repr({i: _nu134.folded.get(i) for i in ("tg-cmd", "dc-cmd")} if _nu134 else None))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The server page: console first by default, a saved order kept; maintenance in one menu
# ════════════════════════════════════════════════════════════════════════════════════════════════


def _panels134(html):
    i = html.find('id="detail-console"')
    j = html.find('id="detail-console-hidden"', i) if i >= 0 else -1
    region = html[i:j if j > 0 else html.find("data-mtab=\"history\"", i)]
    return _re134.findall(r'class="card mb-3 panel-movable" data-panel="([a-z_]+)"', region)


_sdp134 = {}
try:
    _p9_arm(who="part134")
    _p9_patch(_sd134, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd134, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch(_smc134, "run_command", lambda *a, **k: ("", "", 1))
    # A server with LinuxGSM's maintenance commands cached (the fixture's has none).
    _real_btns134 = _sd134._server_action_buttons
    _p9_patch(_sd134, "_server_action_buttons", lambda app, gs: (lambda r: (r[0], [
        {"cmd": "monitor", "desc": "Checks the server is running."},
        {"cmd": "validate", "desc": "Validates the game files."},
        {"cmd": "backup", "desc": "Backs the server up."},
        {"cmd": "details", "desc": "Shows server details."}], r[2], r[3]))(_real_btns134(app, gs)))
    with _p9.app_context():
        _u134 = _db134.session.get(_User134, P9_ADMIN)
        _prefs_was134 = _u134.ui_prefs
        _u134.ui_prefs = "{}"
        _db134.session.commit()
    _sdp134["default"] = _get134(P9_ADMIN, "/server/%d" % P9_GS)
    with _p9.app_context():
        _u134 = _db134.session.get(_User134, P9_ADMIN)
        _u134.set_ui_pref("panels", {"detail_console": ["controls", "console", "players"]})
        _db134.session.commit()
    _sdp134["saved"] = _get134(P9_ADMIN, "/server/%d" % P9_GS)
finally:
    with _p9.app_context():
        _u134 = _db134.session.get(_User134, P9_ADMIN)
        _u134.ui_prefs = _prefs_was134
        _db134.session.commit()
    _p9_restore_all()
_def134 = _panels134(_sdp134.get("default", (0, ""))[1])
check("server page: with no saved layout the Live Console is the first panel, before the Connect/stats "
      "panel", _def134[:2] == ["console", "controls"], repr(_def134))
_sav134 = _panels134(_sdp134.get("saved", (0, ""))[1])
check("server page: a saved layout that put the controls first is left as it was saved",
      _sav134[:2] == ["controls", "console"], repr(_sav134))

_SA134 = _read134("templates", "_server_actions.html")
_html134 = _sdp134.get("default", (0, ""))[1]
_mi134 = _html134.find('id="srv-maint-menu"')
_menu134 = _html134[_mi134:_html134.find("</ul>", _mi134)] if _mi134 >= 0 else ""
_maint134 = _re134.findall(r'data-action="serverAction" data-args=\'\["([a-z-]+)", "@self", (true|false), true\]\'',
                           _menu134)
_CONFIRM134 = {"validate", "backup", "force-update", "mods-update", "fastdl"}
check("server bar: the maintenance commands are serverAction items of one dropdown menu, opened by a "
      "Maintenance button",
      bool(_maint134) and 'data-bs-toggle="dropdown"' in _html134[_mi134 - 300:_mi134 + 200]
      and "dropdown-menu" in _menu134, repr(_menu134[:300]))
check("server bar: each maintenance command keeps its confirmation (validate, backup, force-update, "
      "mods-update, fastdl ask first; the read-only ones do not) and its output dialog",
      all((flag == "true") == (cmd in _CONFIRM134) for cmd, flag in _maint134)
      and {"validate", "backup"} <= {c for c, _f in _maint134}, repr(_maint134))
_lead134 = _html134[_html134.rfind('<div class="card mb-3">', 0, _mi134):_mi134]
check("server bar: Start / Stop / Restart stay buttons of their own, outside the menu",
      all('"%s", "@self"' % a in _lead134 for a in ("start", "stop", "restart")), _lead134[-400:])

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The page alerts: one line, every action kept
# ════════════════════════════════════════════════════════════════════════════════════════════════
_BASE134 = _read134("templates", "base.html")
_otp134 = _BASE134[_BASE134.find('id="otp-nag"'):_BASE134.find("js/otp_nag.js")]
check("2FA alert: one compact line (uis-nag) holding Enable 2FA, Not now and Don't remind me, the reason "
      "kept as the sentence's tooltip",
      "uis-nag" in _otp134 and "account_2fa_enable" in _otp134 and 'data-action="hideOtpNag"' in _otp134
      and 'data-action="dismissOtpNagForever"' in _otp134
      and 'title="You have full control of the panel' in _otp134
      and '<div class="small d-none d-sm-block">' not in _otp134, _otp134[:300])
_NG134 = _read134("static", "js", "nags.js")
_RBDOM134 = r"""
function E(tag){ this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.className = '';
  this.style = {}; this._text = ''; }
E.prototype.appendChild = function(c){ this.children.push(c); return c; };
E.prototype.setAttribute = function(k, v){ this.attrs[k] = String(v); };
E.prototype.getAttribute = function(k){ return this.attrs[k] === undefined ? null : this.attrs[k]; };
E.prototype.addEventListener = function(){};
Object.defineProperty(E.prototype, 'textContent', {get(){ return this._text + this.children.map(c => c.textContent).join(''); },
  set(v){ this._text = String(v); this.children = []; }});
function T(s){ this.textContent = s; }
global.document = {createElement: t => new E(t), createTextNode: s => new T(s)};
global.window = global; window.LOCAL_HOST_ID = 7; window.LOCAL_HOST_CTL = true;
global.tfNodes = (s, v) => [v.host, new T(s.replace('{host}', ''))];
const all = (e, acc) => { acc.push(e); (e.children || []).forEach(c => all(c, acc)); return acc; };
"""
_RBPROG134 = (_RBDOM134
              + "".join(_cut47(_NG134, h) + "\n" for h in ("function _rbEl(", "function _rbName(", "function _rbHost(",
                                                          "function _rbButton("))
              + "var _RB_PHASE = {};\n" + _cut47(_NG134, "window.rebootNagRender = function(") + "\n"
              + "const el = new E('div');\n"
              + "rebootNagRender(el, 7, 'the panel host', {required: true, packages: ['linux-image']});\n"
              + "const nodes = all(el, []);\n"
              + "console.log(JSON.stringify({cls: el.className, buttons: nodes.filter(n => n.tagName === 'BUTTON')"
              + ".map(b => b.textContent), text: el.textContent,"
              + " short: nodes.filter(n => /d-sm-none/.test(n.className)).map(n => n.textContent),"
              + " title: nodes.filter(n => n.title).map(n => n.title)}));\n")
_rb134 = _node47(_RBPROG134)
if _rb134 is None:
    skip("reboot alert: one line", "node is not installed here")
else:
    check("reboot alert: one compact line (uis-nag) with both its buttons, Reboot now and Reboot when "
          "empty; the whole sentence from sm up, the host alone on a phone, the packages as a tooltip",
          "uis-nag" in _rb134.get("cls", "") and _rb134.get("buttons") == ["Reboot now", "Reboot when empty"]
          and "needs to reboot to finish applying system updates." in _rb134.get("text", "")
          and _rb134.get("short") == ["the panel host"] and _rb134.get("title") == ["linux-image"],
          repr(_rb134))
_OSPROG134 = (r"""
global.window = global; global.MOUNT = ''; global.OS_NAG = false;
global.escapeHtml = s => String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
global._da = (n, a) => ' data-action="' + n + '" data-args=\'' + JSON.stringify(a) + '\'';
const box = {className: '', innerHTML: ''};
global.document = {getElementById: id => id === 'os-updates-nag' ? box : null};
global.sessionStorage = {getItem: () => null, setItem(){}};
global.fetch = () => Promise.resolve({ok: true, json: () => Promise.resolve({hosts: [
  {id: 1, local: true, name: 'panel', url: '/server-management', count: 12, security: 2},
  {id: 2, local: false, name: 'vps-one', url: '/remote/2/manage', count: 1, security: 0}]})});
""" + _cut47(_NG134, "function _osNagClear(") + "\n" + _cut47(_NG134, "window.osUpdatesNagCheck = function(") + "\n"
              + "(async () => { osUpdatesNagCheck(); for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r));\n"
              + "  console.log(JSON.stringify({html: box.innerHTML})); })();\n")
_os134 = _node47(_OSPROG134)
if _os134 is None:
    skip("updates alert: one line", "node is not installed here")
else:
    _oh134 = _os134.get("html", "")
    check("updates alert: one line (uis-nag) — the heading, then each host's link with its count and "
          "security badge inline, and the dismiss button",
          "uis-nag" in _oh134 and _oh134.count('class="uis-nag-item"') == 2
          and 'href="/server-management#os-updates"' in _oh134 and 'href="/remote/2/manage#os-updates"' in _oh134
          and " 12 " in _oh134 and " <span>security</span>" in _oh134
          and '<i class="bi bi-shield-exclamation d-sm-none"></i>' in _oh134
          and 'data-action="osUpdatesNagDismiss"' in _oh134 and "<div><a" not in _oh134, _oh134[:600])

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The Maintenance backups list: each server's backups folded, its controls outside the fold
# ════════════════════════════════════════════════════════════════════════════════════════════════
_BK134 = _read134("static", "js", "remote_manage_backups.js")
_BKPROG134 = (r"""
global.window = global; global.MOUNT = '';
global.escapeHtml = s => String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
global._da = (n, a) => ' data-action="' + n + '" data-args=\'' + JSON.stringify(a) + '\'';
global.tfHtml = (s, v) => s.replace(/\{(\w+)\}/g, (m, k) => v[k]);
global.bkAgo = () => '1d ago'; global.bkFmtBytes = n => n + ' B'; global.bkGameDisk = () => '';
global.gameSchedule = g => '<div class="sched" id="gsi-' + g.id + '"></div>';
global._r29c_bkFieldIn = () => false;
const fg = {innerHTML: '', querySelectorAll: s => s === 'details[data-uis-gid][open]'
  ? [{getAttribute: () => '5'}] : []};
const D = {games: [
  {id: 4, name: 'a', host: 'h', backups: [{name: 'a-1.tar', size: 1, created: 1}, {name: 'a-2.tar', size: 1, created: 2}]},
  {id: 5, name: 'b', host: 'h', backups: [{name: 'b-1.tar', size: 1, created: 1}]},
  {id: 6, name: 'c', host: 'h', backups: []}]};
""" + "".join(_cut47(_BK134, h) + "\n" for h in ("function bkRenderGames(", "function _uis_bkOpenIds(",
                                                 "function _uis_bkFold(", "function bkGameRows(",
                                                 "function bkGameStatus("))
              + "bkRenderGames(fg, D);\nconsole.log(JSON.stringify({html: fg.innerHTML}));\n")
_bk134 = _node47(_BKPROG134)
if _bk134 is None:
    skip("maintenance backups: folded per server", "node is not installed here")
else:
    _bh134 = _bk134.get("html", "")
    _det134 = {m.group(1): (m.group(2) == " open", m.group(3)) for m in _re134.finditer(
        r'<details class="uis-fold" data-uis-gid="(\d+)"( open)?>(.*?)</details>', _bh134, _re134.S)}
    check("maintenance backups: each server's finished backups sit in a fold labelled with how many there "
          "are and how new the newest is; a server with none has no fold",
          set(_det134) == {"4", "5"} and "2 backups, newest 1d ago" in _det134.get("4", (0, ""))[1]
          and "1 backup, newest 1d ago" in _det134.get("5", (0, ""))[1]
          and "deleteGameBackup" in _det134.get("4", (0, ""))[1] and "no backups yet" in _bh134,
          repr({k: v[0] for k, v in _det134.items()}) + _bh134[:300])
    check("maintenance backups: a list that was open stays open when the card is drawn again, the others "
          "stay folded", _det134.get("5", (False,))[0] is True and _det134.get("4", (True,))[0] is False,
          repr({k: v[0] for k, v in _det134.items()}))
    _outside134 = _re134.sub(r"<details.*?</details>", "", _bh134, flags=_re134.S)
    check("maintenance backups: Back up now and the schedule are outside the fold, one each per server",
          _outside134.count('data-action="backupOneGame"') == 3 and _outside134.count('class="sched"') == 3,
          _outside134[:400])

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. Account sessions: three, then "Show all N"; this device never hidden
# ════════════════════════════════════════════════════════════════════════════════════════════════
_AS134 = _read134("static", "js", "account_sessions.js")
_ASPROG134 = (r"""
function E(tag){ this.tagName = tag; this.children = []; this.attrs = {}; this.style = {}; this.on = {};
  const s = new Set(); this.classList = {add: c => s.add(c), remove: c => s.delete(c), has: c => s.has(c)};
  this._t = ''; this.parent = null; }
E.prototype.appendChild = function(c){ c.parent = this; this.children.push(c); return c; };
E.prototype.setAttribute = function(k, v){ this.attrs[k] = String(v); };
E.prototype.addEventListener = function(ev, fn){ this.on[ev] = fn; };
E.prototype.remove = function(){ const p = this.parent; if (p) p.children = p.children.filter(c => c !== this); };
E.prototype.querySelectorAll = function(sel){ const out = [], walk = e => e.children.forEach(c => {
  if (c.attrs && 'data-uis-more' in c.attrs) out.push(c); walk(c); }); walk(this); return out; };
Object.defineProperty(E.prototype, 'textContent', {get(){ return this._t + this.children.map(c => c.textContent || '').join(''); },
  set(v){ this._t = String(v); this.children = []; }});
const box = new E('div');
global.window = global; global.MOUNT = '';
global.t = s => s; global.tf = (s, v) => s.replace(/\{(\w+)\}/g, (m, k) => v[k]);
global.document = {readyState: 'complete', getElementById: id => id === 'sessions-list' ? box : null,
                   createElement: t => new E(t), addEventListener(){}};
const S = []; for (let i = 0; i < 7; i++) S.push({id: i, device: 'd' + i, ip: '', current: i === 5, last_seen: null});
global.fetch = () => Promise.resolve({json: () => Promise.resolve({sessions: S})});
""" + _AS134[:_AS134.find("// ── Dashboard layout controls")] + r"""
(async () => { for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r));
  const rows = () => box.children.filter(c => c.tagName === 'div');
  const shown = () => rows().filter(r => !r.classList.has('d-none')).map(r => r.children[0].children[0].children[0].textContent);
  const more = box.children.find(c => c.tagName === 'button');
  const out = {shown: shown(), rows: rows().length, more: more && more.textContent};
  if (more) more.on.click();
  out.after = shown().length; out.moreGone = !box.children.find(c => c.tagName === 'button');
  console.log(JSON.stringify(out)); })();
""")
_as134 = _node47(_ASPROG134)
if _as134 is None:
    skip("account sessions: three then Show all", "node is not installed here")
else:
    check("account sessions: the first three and this device are listed, the rest behind \"Show all N "
          "sessions\", which lists every one; every row is built either way",
          _as134.get("shown") == ["d0", "d1", "d2", "d5"] and _as134.get("rows") == 7
          and _as134.get("more") == "Show all 7 sessions" and _as134.get("after") == 7
          and _as134.get("moreGone") is True, repr(_as134))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. The other pages: folded, not removed
# ════════════════════════════════════════════════════════════════════════════════════════════════
_pg134 = {}
try:
    _p9_arm(who="part134")
    _p9_patch(_smc134, "run_command", lambda *a, **k: ("", "", 1))
    for _k134, _url134 in (("logs", "/logs"), ("logsq", "/logs?q=zz"), ("account", "/account"),
                           ("settings", "/settings"), ("bans", "/global-bans"), ("commands", "/commands")):
        _pg134[_k134] = _get134(P9_ADMIN, _url134)
finally:
    _p9_restore_all()
_PG134 = {k: _parse134(h) for k, (_s, h) in _pg134.items()}
check("other pages: Audit Logs, Account, Settings, Global Bans and Custom Commands render",
      all(v[0] == 200 for v in _pg134.values()) and len(_pg134) == 6, repr({k: v[0] for k, v in _pg134.items()}))
_lf134 = _PG134.get("logs")
_lq134 = _PG134.get("logsq")
check("audit logs: the filters are a collapse on a phone only (d-md-block shows them from md up), shut "
      "with no filter in use and open while one is, with a button that opens them",
      _lf134 is not None and _lq134 is not None
      and "collapse d-md-block" in (_lf134.attrs.get("logs-filters", {}).get("class") or "")
      and " show" not in (_lf134.attrs.get("logs-filters", {}).get("class") or "")
      and " show" in (_lq134.attrs.get("logs-filters", {}).get("class") or "")
      and 'data-bs-target="#logs-filters"' in _pg134["logs"][1]
      and {"q", "action", "user", "status"} <= _lf134.names,
      repr((_lf134.attrs.get("logs-filters") if _lf134 else None)))
_ac134 = _PG134.get("account")
check("account: the panel-default buttons, sign-out-everywhere and the API token form are all still on "
      "the page (two of them folded)",
      _ac134 is not None and {"publishDashLayout", "clearDashDefault", "_acctSignOutAll",
                              "resetDashLayout"} <= set(_ac134.actions)
      and "revoke-sessions-form" in _ac134.where and "account-api_password" in _ac134.where,
      repr(sorted(_ac134.actions) if _ac134 else None))
_st134 = _PG134.get("settings")
_SETNAMES134 = {"site_title", "site_domain", "login_tagline", "accent_color", "default_language",
                "session_lifetime_hours", "remember_days", "session_protection", "reboot_wait_max_hours",
                "reboot_restore_no_autostart"}
check("settings: every field the page saved before the columns moved is still in its one form, every "
      "section still has its anchor",
      _st134 is not None and _SETNAMES134 <= _st134.names
      and {"sec-branding", "sec-localization", "sec-security", "sec-reboots"} <= set(_st134.where),
      repr(sorted(_SETNAMES134 - (_st134.names if _st134 else set()))))
_SETTPL134 = _read134("templates", "settings.html")
check("settings: Host reboots sits in the right-hand column under Sessions & Security, Localization in "
      "the left under Branding (the columns were 350px apart)",
      _SETTPL134.find('id="sec-branding"') < _SETTPL134.find('id="sec-localization"')
      < _SETTPL134.find("<!-- Sessions/Security + Host reboots -->") < _SETTPL134.find('id="sec-security"')
      < _SETTPL134.find('id="sec-reboots"'), "order changed")
_bn134 = _PG134.get("bans")
check("global bans: the add form is still there under one sentence, the rest of the explanation folded",
      _bn134 is not None and {"steamid", "player_name", "reason"} <= _bn134.names
      and "that is running when you add it." in _pg134["bans"][1].split("<details", 1)[0],
      repr(sorted(_bn134.names) if _bn134 else None))
_cm134 = _PG134.get("commands")
_cmh134 = _pg134.get("commands", (0, ""))[1]
check("custom commands: every command row keeps its Edit toggle and its Delete form",
      _cm134 is not None and _cmh134.count('data-bs-target="#edit-cmd-') == _cmh134.count('id="edit-cmd-')
      and _cmh134.count("/delete\"") >= _cmh134.count('id="edit-cmd-'), _cmh134[:200])

# The Details tab's Supported Commands: the first six, then the rest folded, none dropped.
_SD134 = _read134("templates", "server_detail.html")
check("server details: Supported Commands shows six rows and folds the rest, every command still rendered",
      "_uis_cmd_rows(all_commands[:6])" in _SD134 and "_uis_cmd_rows(all_commands[6:])" in _SD134
      and "{% for c in all_commands %}" not in _SD134, "the Supported Commands table changed shape")

# The Tailscale page: the explanation and the Serve form fold only when Serve already proxies the panel.
_TS134 = _read134("templates", "tailscale.html")
check("tailscale: Recommended Access folds its explanation and Serve form only when the recommended "
      "method is already in use (method tailscale-serve), and renders them unfolded otherwise",
      "{% set _uis_ts_done = suggestion.method == 'tailscale-serve' %}" in _TS134
      and "{% if _uis_ts_done %}{% call fold('Details') %}{{ _uis_ts_body }}{% endcall %}{% else %}"
      "{{ _uis_ts_body }}{% endif %}" in _TS134 and 'id="serve-form"' in _TS134, "fold changed")


# The Maintenance tab's backup encryption: the why folded, the passphrase box and the warning not.
_RM134 = _read134("templates", "remote_manage.html")
_enc134 = _RM134[_RM134.find('id="bk-enc-box"'):]
_encf134 = _enc134[_enc134.find("{% call fold('Why encrypt?'"):_enc134.find("{% endcall %}")]
check("maintenance: backup encryption folds only its explanation; the status, the passphrase box, both "
      "buttons and the no-reset warning stay on view",
      "one copied backup hands over" in _encf134 and 'id="bk-pass"' not in _encf134
      and 'id="bk-enc-status"' not in _encf134 and "There is no reset" not in _encf134
      and 'id="bk-pass"' in _enc134 and "saveBackupPassphrase" in _enc134, _encf134[:200])

check("part134: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP134_START, repr(_P9_TRIPPED[_TRIP134_START:]))
