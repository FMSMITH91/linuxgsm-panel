"""Part 328 of the unit suite: every Updates row says what it updates, and from which version to which.

1. Game rows (GET /api/updates): the row's title names the kind and the game by LinuxGSM's own name ("Game update:
   PaperMC"); the two builds LinuxGSM printed are two labelled lines, read per family: a Paper build of the same
   Minecraft version says players are not locked out, a new Minecraft version says older clients cannot join, a
   Velocity build names Velocity, vanilla marks a snapshot, Steam shows its branch, a build LinuxGSM could not read is
   said in words. Automatic updates' reason fits a same-version Paper build; its default stays off.
2. The other rows (GET /api/updates): LinuxGSM, the panel, a host's packages, an add-on and a website each carry a
   title and an Installed and an Available line, and an unknown version is words, never "?". A French viewer reads
   them in French.
3. The page (templates/updates.html, js/updates.js, css/panel.css): the title comes first on the row, then the
   name, then the two version lines; a row with nothing else to say has no empty list; the header note wraps inside
   its group beside the buttons instead of being cut.
4. WordPress's Site Health page cache state without a proxy apply: the update-check thread's pass (at boot, then
   every 30 minutes) writes it into each WordPress site whose state this process has not written yet, as the site's
   account, and tries a failed write again on the next pass; a Performance save writes it again even when the state
   is unchanged; the loopback plugin says "not reported yet" for a missing file, not "off".

HOW IT RUNS. part12's app and database; every host call is a stand-in, part12's tripwire is armed.
"""
import os
import re

from flask import g as _g328

from unit.part01 import check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch, _p9_restore_all
from panel.core import config as _cfg328
from panel.core.panel_state import _os_update_seen as _osseen328
from panel.db.models import (GameServer as _GS328, RemoteServer as _Remote328, User as _User328, Website as _Site328,
                             db as _db328)
from panel.ops import system_ops as _so328
from panel.routes import remote_vps as _rv328, websites as _w328
from panel.services import (addons as _ad328, game_updates as _gu328, lgsm_data as _lgd328,
                            lgsm_releases as _lr328, update_versions as _uv328, updates as _u328)

_ROWS328 = {"servers": [], "users": [], "remotes": [], "sites": []}
_OS_ID328 = 990328
_LIST328 = [{"shortname": "pmc", "gameservername": "pmcserver", "gamename": "PaperMC"},
            {"shortname": "vpmc", "gameservername": "vpmcserver", "gamename": "Velocity Proxy MC"},
            {"shortname": "mc", "gameservername": "mcserver", "gamename": "Minecraft"},
            {"shortname": "gmod", "gameservername": "gmodserver", "gamename": "Garrys Mod"}]
_IMAGE328 = "registry.example/p328-php:8.4@sha256:" + "ab" * 26 + "0123456789ab"


def _out328(local, remote, branch=""):
    """What LinuxGSM's check-update prints for a newer build (lgsm/modules/update_*.sh, core_steamcmd.sh)."""
    return ("Checking for update\nUpdate available\n* Local build: %s\n* Remote build: %s\n%s"
            % (local, remote, "* Branch: %s\n" % branch if branch else ""))


def _rows328(uid):
    _g328.pop("_login_user", None)
    d = _p9_client(uid).get("/api/updates").get_json(silent=True) or {}
    return {x["ref"]: x for g in d.get("groups") or [] for x in g["items"]}


def _setup328():
    r = _Remote328(name="p328-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.82")
    _db328.session.add(r)
    su = _User328(username="p328-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db328.session.add(su)
    _db328.session.commit()
    _ROWS328["remotes"].append(r.id)
    _ROWS328["users"].append(su.id)
    return r, su


def _gs328(host, name, game, out, display=""):
    gs = _GS328(name=name, game_type=game, short_name=game + "server", port=27015 + len(_ROWS328["servers"]),
                remote_id=host.id, installed=True, status="offline", game_display=display)
    _db328.session.add(gs)
    _db328.session.commit()
    _ROWS328["servers"].append(gs.id)
    _gu328.note_output(gs.id, out)
    return gs


# ── 1. game rows ──────────────────────────────────────────────────────────────────────────────────
def _s1_games(host, su):
    same = _gs328(host, "p328-paper", "pmc", _out328("26.3-257", "26.3-263"))
    jump = _gs328(host, "p328-paper2", "pmc", _out328("26.3-263", "26.4-12"))
    rows = _rows328(su.id)
    a, b = rows.get("game:%d" % same.id) or {}, rows.get("game:%d" % jump.id) or {}
    eq("game rows (GET /api/updates): a Paper build of the same Minecraft version is titled by LinuxGSM's game name, "
       "its builds labelled as Minecraft version and Paper build, and it says players are not locked out",
       (a.get("title"), a.get("versions"), (a.get("what") or [None])[0]),
       ("Game update: PaperMC", ["Installed: Minecraft 26.3, Paper build 257",
                                 "Available: Minecraft 26.3, Paper build 263"], _uv328.S_PAPER_SAME))
    eq("game rows: a Paper build of a NEW Minecraft version says older clients cannot join (control)",
       (b.get("versions"), (b.get("what") or [None])[0]),
       (["Installed: Minecraft 26.3, Paper build 263", "Available: Minecraft 26.4, Paper build 12"],
        _uv328.S_PAPER_NEW))
    eq("game rows: automatic updates' reason fits a same-version Paper build (nobody is locked out) and stays the "
       "Minecraft release reason across versions; the default is off for both",
       (a.get("auto_why"), a.get("auto"), b.get("auto_why"), b.get("auto")),
       (_uv328.WHY_PAPER_BUILD.replace("{project}", "Paper"), False, _gu328.WHY_MINECRAFT, False))
    _s1_families(host, su)


def _s1_families(host, su):
    velo = _gs328(host, "p328-velo", "vpmc", _out328("3.4.0-SNAPSHOT-500", "3.4.0-SNAPSHOT-512"))
    snap = _gs328(host, "p328-snap", "mc", _out328("25w14a", "25w15a", "snapshot"))
    pre = _gs328(host, "p328-pre", "mc", _out328("0", "1.21.5-pre1", "release"))
    steam = _gs328(host, "p328-gmod", "gmod", _out328("25375524", "25375525", "public"))
    other = _gs328(host, "p328-ts", "ts3", _out328("3.13.6", "3.13.7"), display="My voice server")
    rows = _rows328(su.id)
    got = [rows.get("game:%d" % g.id) or {} for g in (velo, snap, pre, steam, other)]
    eq("game rows: Velocity names its own version and build; a vanilla snapshot and a pre-release are marked as test "
       "versions, and a build LinuxGSM could not read (\"0\") is said in words",
       [g.get("versions") for g in got[:3]] + [(got[0].get("what") or [None])[0]],
       [["Installed: Velocity 3.4.0-SNAPSHOT, build 500", "Available: Velocity 3.4.0-SNAPSHOT, build 512"],
        ["Installed: Minecraft 25w14a (a snapshot: a test version)",
         "Available: Minecraft 25w15a (a snapshot: a test version)"],
        ["Installed: " + _uv328.S_NOT_READ, "Available: Minecraft 1.21.5-pre1 (a pre-release: a test version)"],
        "Same Velocity version: a new build (fixes). Players are not locked out."])
    eq("game rows: Steam's builds with the branch; another updater's own strings, labelled; a game LinuxGSM's list "
       "does not name is titled by the name the panel holds",
       (got[3].get("title"), got[3].get("versions"), got[4].get("title"), got[4].get("versions")),
       ("Game update: Garrys Mod", ["Installed: build 25375524", "Available: build 25375525 (branch public)"],
        "Game update: My voice server", ["Installed: 3.13.6", "Available: 3.13.7"]))
    check("game rows: no row shows a bare \"?\" for a version",
          not any("?" in v for g in got for v in g.get("versions") or []), [g.get("versions") for g in got])


# ── 2. the other rows ─────────────────────────────────────────────────────────────────────────────
def _s2_others(host, su):
    gs = _gs328(host, "p328-lgsm", "gmod", "No output\n")
    _u328.note_lgsm(gs.id, {"release": "v26.5.0", "latest": "v26.6.0", "behind": True})
    # The row's release notes are the panel's held copy: a stand-in, so no re-read of GitHub starts.
    _p9_patch(_lr328, "releases", lambda newest=None: [{"tag": "v26.6.0", "url": _lr328.RELEASES_PAGE + "/tag/v26.6.0",
                                                         "blocks": [], "cut": False}])
    _p9_patch(_so328, "panel_update_cached", lambda: {"update_available": True, "current_version": "",
                                                      "current_sha": "", "remote_version": "2026.11.28",
                                                      "target_sha": "e683c73d0011", "changes": ["A change."]})
    _osseen328[_OS_ID328] = {"packages": [{"name": "openssl", "label": "openssl", "from": "3.0.13-1", "version":
                                           "3.0.13-2"}, {"name": "tzdata", "label": "tzdata"}]}
    _p9_patch(_rv328, "os_update_hosts", lambda user: [{"id": _OS_ID328, "name": "p328-host", "count": 2,
                                                        "security": 1, "url": "/remote/1"}])
    _u328._ADDONS_SEEN[gs.id] = {"rows": {"b3": {"reason": "image", "version": "", "new": "1.12"}}}
    rows = _rows328(su.id)
    lg, pn = rows.get("lgsm:%d" % gs.id) or {}, rows.get("panel") or {}
    osr, ad = rows.get("os:%d" % _OS_ID328) or {}, rows.get("addon:%d:b3" % gs.id) or {}
    eq("other rows (GET /api/updates): LinuxGSM, the panel, a host's packages and an add-on are each titled by their "
       "kind, with Installed and Available lines; an unread version is words",
       (lg.get("title"), lg.get("versions"), pn.get("title"), pn.get("versions"), osr.get("title"), ad.get("title"),
        ad.get("versions")),
       (_uv328.S_TITLE_LGSM, ["Installed: LinuxGSM v26.5.0", "Available: LinuxGSM v26.6.0"], "Panel update",
        ["Installed: not known (the panel could not read its own version)", "Available: 2026.11.28 (e683c73)"],
        "Host system update: packages", "Add-on update: " + _ad328.CATALOG["b3"]["name"],
        ["Installed: not recorded (the panel did not read the running image's version)", "Available: 1.12"]))
    eq("other rows: a host's packages each say their old and new version (apt's), and a package apt gave none for "
       "keeps its name", (osr.get("what") or [None, None])[1], "openssl 3.0.13-1 to 3.0.13-2, tzdata")
    _s2_site(host, su)
    _s2_french(su, gs)


def _s2_site(host, su):
    s = _Site328(remote_id=host.id, name="p328-site", kind="wordpress", state="running", php_version="8.4",
                 proxy_secret=_cfg328.encrypt_secret(os.urandom(16).hex()))
    _db328.session.add(s)
    _db328.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    s.image_digest, s.image_key = "", "files-6"
    _db328.session.commit()
    _ROWS328["sites"].append(s.id)
    _p9_patch(_w328, "current_image", lambda site: _IMAGE328)
    row = _rows328(su.id).get("website:%d" % s.id) or {}
    eq("website row (GET /api/updates): titled by what the site runs, the image it moves to by name and digest, and "
       "an image the panel never recorded said in words",
       (row.get("title"), row.get("versions")),
       ("Website update: WordPress", ["Installed: not recorded (installed before the panel kept it)",
                                      "Available: image p328-php (0123456789ab)"]))


def _s2_french(su, gs):
    user = _db328.session.get(_User328, su.id)
    user.language = "fr"
    _db328.session.commit()
    try:
        row = _rows328(su.id).get("lgsm:%d" % gs.id) or {}
    finally:
        user.language = None
        _db328.session.commit()
    eq("other rows: a French viewer reads the title and both version lines in French",
       (row.get("title"), row.get("versions")),
       ("Mise à jour de LinuxGSM : les scripts qui font tourner le serveur",
        ["Installée : LinuxGSM v26.5.0", "Disponible : LinuxGSM v26.6.0"]))


# ── 3. the page ───────────────────────────────────────────────────────────────────────────────────
_SCN328 = r"""
  for (let i = 0; i < 6; i++) await tick();
  return {text: $('upd-list').textContent, lists: $('upd-list').querySelectorAll('ul').length,
          titles: $('upd-list').querySelectorAll('.upd-title').map(function (e) { return e.textContent; }),
          versions: $('upd-list').querySelectorAll('.upd-versions').map(function (e) { return e.textContent; })};
"""


def _s3_page():
    from unit.part301 import _page301
    from unit.part12 import P9_ADMIN
    from unit.part322 import _node322
    page = _page301("updates.html", P9_ADMIN, allowed=True)
    row = {"kind": "lgsm", "ref": "lgsm:5", "name": "pmcserver", "title": "LinuxGSM update: x", "host": "Panel Server",
           "versions": ["Installed: LinuxGSM v26.5.0", "Available: LinuxGSM v26.6.0"], "what": [], "notes": [],
           "cost": "No restart.", "security": False, "safe": True, "auto": None, "auto_editable": False, "when": "w",
           "when_link": None, "link": "", "action": None}
    got = _node322(page, ["updates.js"], _SCN328, {
        "/api/updates": {"success": True, "count": 1, "groups": [{"key": "lgsm", "title": "LinuxGSM", "items": [row]}],
                         "settings": {}, "history": []}})
    text = got.get("text") or ""
    eq("Updates page (js/updates.js): the row's title comes first, then its name, then the Installed and Available "
       "lines; a row with nothing else to say has no empty list",
       (got.get("titles"), got.get("versions"), [text.find(t) for t in ("LinuxGSM update: x", "pmcserver",
                                                                         "Installed:", "Available:")] ==
        sorted(text.find(t) for t in ("LinuxGSM update: x", "pmcserver", "Installed:", "Available:")),
        got.get("lists"), got.get("error")),
       (["LinuxGSM update: x"], ["Installed: LinuxGSM v26.5.0Available: LinuxGSM v26.6.0"], True, 0, None))
    css = open(os.path.join(os.path.dirname(_cfg328.__file__), "..", "static", "css", "panel.css"),
               encoding="utf-8").read()
    rule = {m.group(1): m.group(2) for m in re.finditer(r"^\.(upd-head-acts|upd-safe-why) \{([^}]*)\}", css, re.M)}
    eq("Updates page header (updates.html, panel.css): the note and the buttons share a group that may shrink, and "
       "the note wraps inside it (min-width 0, any break point) instead of being cut",
       ('class="upd-head-acts' in page and 'class="upd-safe-why' in page,
        "min-width: 0" in rule.get("upd-head-acts", ""),
        "min-width: 0" in rule.get("upd-safe-why", "") and "overflow-wrap: anywhere" in rule.get("upd-safe-why", "")),
       (True, True, True))


# ── 4. Site Health's page cache state ───────────────────────────────────────────────────────────
def _site328(host, name, **kw):
    from panel.db.models import WebsiteDomain
    from panel.core.clock import utcnow
    s = _Site328(remote_id=host.id, name=name, kind="wordpress", state="running", php_version="8.4", enabled=True,
                 proxy_secret=_cfg328.encrypt_secret(os.urandom(16).hex()), **kw)
    _db328.session.add(s)
    _db328.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    _db328.session.add(WebsiteDomain(website_id=s.id, domain="%s.example.org" % name, is_primary=True,
                                     verified_at=utcnow(), dns_state="matching"))
    _db328.session.commit()
    _ROWS328["sites"].append(s.id)
    return s


def _s4_seams(writes, rc):
    from panel.ops.ssh_manager import _core as _smcore
    from panel.routes import _shared as _shared328, websites_view as _wview328
    from panel.ops.ssh_manager import websites as _sw328

    def shell(server, user, sh, timeout=30, stdin_text=None, **k):
        writes.append((user, stdin_text or ""))
        return "", "", rc["rc"]
    _p9_patch(_smcore, "shell_as_game_user", shell)
    _p9_patch(_shared328, "game_account_write_refusal", lambda remote, user, *a, **k: None)
    _p9_patch(_wview328, "proxy_options", lambda: {"cache_build": True})
    _p9_patch(_sw328, "proxy_status", lambda remote, proxy=None: (True, "installed=yes\nactive=active\ncache=yes\n"))
    _p9_patch(_sw328, "php_apply", lambda remote, site: (True, ""))
    return _sw328


def _written328(writes, accounts):
    """{(account, path): text} of the bundles written as `accounts` since the last call."""
    import base64
    out = {}
    for user, stdin in writes:
        for line in stdin.splitlines():
            path, _sep, b64 = line.partition(" ")
            if user in accounts and path.endswith("page-cache"):
                out[(user, path)] = base64.b64decode(b64).decode()
    writes[:] = []
    return out


def _s4_page_cache(host, su):
    from panel.routes import os_updates as _osu328
    from panel.services import websites as _ws328
    writes, rc = [], {"rc": 1}
    sw = _s4_seams(writes, rc)
    on = _site328(host, "p328-wpon", page_cache=True, page_cache_ttl=300)
    off = _site328(host, "p328-wpoff", page_cache=False)
    mine = {on.account, off.account}
    for s in (on, off):
        sw._PAGE_CACHE_NOTED.pop(s.id, None)
    _osu328._web_page_cache_tick(_p9)          # the update-check thread's pass: this write fails on the host
    failed = (_written328(writes, mine), sw.page_cache_noted(on.id))
    rc["rc"] = 0
    _osu328._web_page_cache_tick(_p9)          # its next pass
    second = _written328(writes, mine)
    _osu328._web_page_cache_tick(_p9)
    eq("page cache state (the update-check thread's pass, no proxy apply): a WordPress site this process has not "
       "written gets its state (on with its TTL, off) as its account; a write that failed is tried on the next pass, "
       "and a site already written is not written again",
       (failed, second, _written328(writes, mine)),
       (({(on.account, _ws328.PAGE_CACHE_FILE): "on 300\n", (off.account, _ws328.PAGE_CACHE_FILE): "off\n"}, False),
        {(on.account, _ws328.PAGE_CACHE_FILE): "on 300\n", (off.account, _ws328.PAGE_CACHE_FILE): "off\n"}, {}))
    want = {(on.account, _ws328.PAGE_CACHE_FILE): "on 300\n"}
    _g328.pop("_login_user", None)
    r = _p9_client(su.id).post("/websites/%d/performance" % on.id, json={"opcache": True})
    eq("page cache state: a Performance save (POST /websites/<id>/performance) that re-applies nothing writes it again "
       "though it did not change", (r.status_code, _written328(writes, mine)), (200, want))
    src = open(_osu328.__file__, encoding="utf-8").read()
    loop = src[src.index("def update_check_ticker"):src.index("time.sleep(1800)")]
    check("page cache state: the update-check thread's loop runs the pass on each of its passes (the first 30 s "
          "after boot)", "_web_page_cache_tick(app)" in loop, loop[-400:])
    for s in (on, off):
        s.enabled = False
    _db328.session.commit()
    php = _ws328.loopback_plugin()
    eq("Site Health (the loopback plugin): with no state file yet it says the panel has not reported the page cache, "
       "never \"not enabled\"; a file still says on or off (control)",
       ("if ( ! is_readable( LGSM_PANEL_PAGE_CACHE_FILE ) ) {\n\t\treturn array( null, 0 );" in php,
        "if ( null === $on ) {" in php and "'label'       => 'The panel has not reported the page cache yet'," in php,
        "'status'      => $on ? 'good' : 'recommended'," in php), (True, True, True))


def _cleanup328():
    _db328.session.rollback()
    for model, ids in ((_Site328, _ROWS328["sites"]), (_GS328, _ROWS328["servers"]), (_User328, _ROWS328["users"]),
                       (_Remote328, _ROWS328["remotes"])):
        for i in ids:
            row = _db328.session.get(model, i)
            if row is not None:
                _db328.session.delete(row)
    _db328.session.commit()
    for i in _ROWS328["servers"]:
        _u328.forget_server(i)
        _gu328.forget(i)
        _u328._ADDONS_SEEN.pop(i, None)
    _osseen328.pop(_OS_ID328, None)
    from panel.ops.ssh_manager import websites as _sw328
    for i in _ROWS328["sites"]:
        _sw328._PAGE_CACHE_NOTED.pop(i, None)
    _u328.forget_counts()


def _ran328(step, *args):
    """Run one section: its result, or None when it raised (the traceback kept in _ran328.last)."""
    import traceback
    try:
        return step(*args) or True
    except Exception:
        _ran328.last = traceback.format_exc()[-1500:]
        return None


_ran328.last = ""
_trips328 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part328")
        _p9_patch(_lgd328, "serverlist", lambda allow_fetch=True: _LIST328)
        _p9_patch(_u328, "window_phase", lambda remote, cfg, now=None: "tonight")
        _p9_patch(_so328, "panel_update_cached", lambda: None)
        _host328, _su328 = _setup328()
        check("part328: _s1_games ran to the end", _ran328(_s1_games, _host328, _su328), _ran328.last)
        check("part328: _s2_others ran to the end", _ran328(_s2_others, _host328, _su328), _ran328.last)
        check("part328: _s3_page ran to the end", _ran328(_s3_page), _ran328.last)
        check("part328: _s4_page_cache ran to the end", _ran328(_s4_page_cache, _host328, _su328), _ran328.last)
        eq("part328: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips328:], [])
    finally:
        _p9_restore_all()
        _cleanup328()
