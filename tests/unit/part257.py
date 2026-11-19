"""Part 257 of the unit suite: B3's games and settings, DB-IP's country database, add-on updates, Renovate's pins.

1. The catalog: B3 at its fork commit (with maxminddb hashed in its lock) for cod, coduo, cod2, cod4, codwaw
   and sof2, each with its parser, RCON setting and game log; wet's kept behind B3_WET; the port the game
   really listens on.
   The probe under bash finds SoF2's log, ~/.sof2/base/date.
2. b3.ini: the game log per game, geolocation off / offline / online, the plugins; a settings change
   rewrites only the panel's [plugins] lines and the two keys of plugin_geolocation.ini.
3. DB-IP: the page's link and SHA1, the checks on the file, the Outside services switch, the month's cache.
4. The routes: an offline B3 install gets the database (stdin, base64) and its read-only mount; settings
   and update run in the background with step-up and audit, keep b3.ini's passwords and the operator's
   lines, and an update rebuilds; the row says when an update is available.
5. The card (server_addons.js run whole in node over a small DOM): B3's settings fold, the Update button,
   the settings post, the Remove warning.
6. Renovate: B3's commit (addons.py and the Containerfile) and IW4MAdmin's digest, each matched, daily.
7. The remote form of addon-account-release, under bash: after its rotation, an empty journal re-created
   for a uid that is gone goes, and nothing else.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; every host call is a recorder.
Shells run under bash in a throwaway folder; nothing reaches a host or db-ip.com.
"""
import base64 as _b64m257
import gzip as _gzip257
import json as _json257
import os
import re as _re257
import shutil as _shutil257
import subprocess as _sp257  # nosec B404 - bash and node over this part's own throwaway files
import tempfile as _tf257
import urllib.request as _urlreq257

from unit.part01 import _root, check, eq
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client, _p9_delete_server,
                         _p9_drain, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_threading,
                         _P9Thread)
from panel.core import outside_services as _os257
from panel.core.config import encrypt_secret as _enc257
from panel.db.models import GameDatabase as _GD257, db as _db257
from panel.routes import addons as _ra257, addons_change as _ch257
from panel.security import privileged as _pv257
from panel.services import addons as _ad257, geoip as _geo257

_trips257 = len(_P9_TRIPPED)
_TMP257 = _tf257.mkdtemp(prefix="p257-")
_RC257 = "p257-rcon-" + "value"            # the game's RCON password in these checks
_DBV257 = "Dbv257" + "abcdefghijklmnopq"   # a database's password in these checks
_PIN257 = "1b96587fe567c5ca635e43a4daa59d174b7abe29"
_MONTH257 = "2026-11"


def _read257(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ── 1. the catalog ──────────────────────────────────────────────────────────────────────────────
def _catalog257():
    games = _ad257.CATALOG[_ad257.B3]["games"]
    eq("B3: offered for cod, coduo, cod2, cod4 (CoD4x), codwaw and sof2 with their parsers; not for wet (vanilla "
       "ET), switched off until B3 authorizes its players",
       (games, _ad257.offered("cod4"), _ad257.offered("wet"), _ad257.B3_WET, _ad257.B3_LATER_GAMES[0]),
       ({"cod": "cod", "coduo": "cod", "cod2": "cod2", "cod4": "cod4", "codwaw": "cod5", "sof2": "sof2"},
        ["b3", "iw4madmin"], [], False, ("wet", "et", False)))
    eq("game port: where the game listens, else its config's; ET (its start sets no port) needs to be running",
       [_ad257.game_port("wet", 27970, [27960]), _ad257.game_port("wet", 27970, [])[0],
        _ad257.game_port("cod2", 28960, []), _ad257.game_port("cod2", 28960, [28960, 28961]),
        _ad257.game_port("cod2", 28960, [1, 2]), _ad257.parse_probe("udp= 27960 0 70000 x\n")["udp"]],
       [(27960, ""), None, (28960, ""), (28960, ""), (28960, ""), [27960]])
    eq("B3: SoF2 and ET read rconpassword; their logs are ~/.sof2/base/date and etmain/etserver.log; CoD's games_mp.log",
       ([_ad257.RCON_SETTING[g] for g in ("sof2", "wet", "codwaw")],
        [_ad257.game_log_name(g) for g in ("sof2", "wet", "cod2")]),
       (["rconpassword", "rconpassword", "rcon_password"], ["date", "etserver.log", "games_mp.log"]))
    req, cf = _read257("panel", "addon_images", "b3", "requirements.txt"), _read257("panel", "addon_images", "b3",
                                                                                   "Containerfile")
    m = _re257.search(r"^maxminddb==(\S+) \\\n((?:    --hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)", req, _re257.M)
    eq("B3: built from the fork commit (addons.py and the Containerfile agree), shown as release 2.0.0 with its short "
       "commit, maxminddb in its hashed lock",
       (_ad257.B3_COMMIT, _re257.findall(r"^ARG B3_COMMIT=(\S+)", cf, _re257.M), _ad257.CATALOG["b3"]["version"],
        bool(m), "maxminddb>=2.6" in _read257("panel", "addon_images", "b3", "requirements.in")),
       (_PIN257, [_PIN257], "2.0.0 (1b96587f)", True, True))


def _probe_sof2_257():
    home = os.path.join(_TMP257, "sof2-home")
    for d in ("serverfiles/base", ".sof2/base"):
        os.makedirs(os.path.join(home, d), exist_ok=True)
    with open(os.path.join(home, "serverfiles", "base", "sof2server.cfg"), "w", encoding="utf-8") as fh:
        fh.write('set rconpassword "%s"\nseta g_log "date"\n' % _RC257)
    open(os.path.join(home, ".sof2", "base", "date"), "w").close()
    sh = _ad257.probe_sh(_ad257.B3, "sof2server", 7, "sof2", 0).replace('cd "$HOME"', "cd %s" % home)
    r = _sp257.run(["bash", "-c", sh], capture_output=True, text=True, timeout=30, check=False,  # nosec B603 B607
                   env={"PATH": "/usr/bin:/bin"})
    p = _ad257.parse_probe(r.stdout)
    eq("probe (bash): SoF2's log is found where LinuxGSM's g_log \"date\" puts it, its RCON from serverfiles/base",
       (p["logdir"], _ad257.game_rcon("sof2", p["rcon_lines"])), (".sof2/base", (_RC257, "")))


# ── 2. b3.ini and plugin_geolocation.ini ────────────────────────────────────────────────────────
def _ini257():
    off = _ad257.b3_ini("sof2", 20100, _RC257, "gs1_b3", _DBV257, "off")
    offline = _ad257.b3_ini("codwaw", 28960, _RC257, "gs1_b3", _DBV257, "offline")
    eq("b3.ini: SoF2's game log and parser; geolocation off lists neither geolocation plugin",
       ("game_log: /gamelog/date\n" in off, "parser: sof2\n" in off, "geolocation" in off, "parser: cod5\n" in offline),
       (True, True, False, True))
    eq("b3.ini: geolocation on lists geolocation (with its settings file) before location and what needs it",
       _ad257.b3_ini_plugins(_ad257.b3_ini_apply(offline, "offline", ["afk", "geowelcome"])),
       ["admin", "afk", "geolocation", "location", "geowelcome"])
    mine = offline.replace("[plugins]\n", "[plugins]\n; mine\nmyext: @conf/myext.ini\n") + "\n[custom]\nx: 1\n"
    new = _ad257.b3_ini_apply(mine, "off", ["stats", "geowelcome", "translator"])
    eq("settings: only the panel's [plugins] lines change; the passwords, an operator's plugin and section stay; "
       "geowelcome needs geolocation and translator is never offered",
       (_ad257.b3_ini_plugins(new), "myext: @conf/myext.ini\n" in new, "; mine\n" in new, "[custom]\nx: 1\n" in new,
        "rcon_password: %s\n" % _RC257 in new, _DBV257 in new, "geolocation" in new.split("[plugins]")[1]),
       (["admin", "stats"], True, True, True, True, True, False))
    eq("settings: a b3.ini with no [plugins] section gets one", _ad257.b3_ini_plugins(
        _ad257.b3_ini_apply("[b3]\nparser: cod\n", "off", ["tk"])), ["admin", "tk"])
    geo = _ad257.geolocation_ini("## my note\n[settings]\ngeolocators: ipwho.is, ipapi.co\nmine: 1\n", "offline")
    eq("plugin_geolocation.ini: offline asks only the database in the geoip folder; the operator's lines stay; off "
       "leaves the file as it is",
       (geo, _ad257.geolocation_ini("x\n", "off"), "geolocators: ipwho.is\n" in _ad257.geolocation_ini("", "online")),
       ("## my note\n[settings]\nmmdb_file: /geoip/dbip-country-lite.mmdb\ngeolocators: mmdb\nmine: 1\n", "x\n", True))


# ── 3. DB-IP ────────────────────────────────────────────────────────────────────────────────────
_DB257 = b"\x00" * 64 + _geo257.MMDB_MARKER + b"\xe1\x00metadata"
_GZ257 = _gzip257.compress(_DB257)
_SHA_GZ257 = _geo257.sha1_hex(_GZ257)
_SHA_DB257 = _geo257.sha1_hex(_DB257)
# DB-IP's page as it is laid out (part258 has the full markup): each file's MD5SUM and SHA1SUM, of the
# unpacked file, above its link; the CSV's block first.
_PAGE257 = ('<dl><dt>MD5SUM</dt><dd class="small">%s</dd><dt>SHA1SUM</dt><dd class="small">%s</dd></dl>'
            "<a href='https://download.db-ip.com/free/dbip-country-lite-%s.csv.gz'>CSV</a> ... "
            '<dl><dt>MD5SUM</dt><dd class="small">%s</dd><dt>SHA1SUM</dt><dd class="small">%s</dd></dl>'
            "<a href='https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz'>MMDB</a>"
            % ("c" * 32, "c" * 40, _MONTH257, "a" * 32, _SHA_DB257, _MONTH257))


def _geo_stub257(gets, switch=True, month=_MONTH257):
    asked = []

    def get(url, cap):
        asked.append(url)
        return gets.get(url, (None, "unreachable"))
    _p9_patch(_geo257, "_get", get)
    _p9_patch(_geo257, "CACHE_DIR", __import__("pathlib").Path(_TMP257) / ("geo-%d" % len(os.listdir(_TMP257))))
    _p9_patch(_geo257, "month_now", lambda: month)
    _p9_patch(_os257, "enabled", lambda key: switch if key == _os257.DBIP else True)
    return asked


def _geoip257():
    url = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz" % _MONTH257
    eq("DB-IP: the page gives the MMDB file's link, month and SHA1 (not the CSV's)",
       _geo257.parse_page(_PAGE257), (url, _MONTH257, _SHA_DB257))
    eq("DB-IP: the file is used only when the database matches the SHA1 and is an MMDB file (the .gz's sum is not "
       "the published one)",
       [_geo257.unpack(_GZ257, _SHA_GZ257) is None,
        _geo257.unpack(_GZ257, _SHA_DB257) == _DB257,
        _geo257.unpack(_GZ257, "0" * 40),
        _geo257.unpack(_gzip257.compress(b"x" * 99), _geo257.sha1_hex(_gzip257.compress(b"x" * 99)))],
       [True, True, None, None])
    asked = _geo_stub257({_geo257.PAGE: (_PAGE257.encode(), None), url: (_GZ257, None)})
    first = _geo257.latest()
    again = _geo257.latest()
    eq("DB-IP: downloaded once for the month, then kept (the second ask reaches nothing)",
       (first[1:], first[0] is not None and first[0].read_bytes() == _DB257, again[1:], asked),
       ((_MONTH257, ""), True, (_MONTH257, ""), [_geo257.PAGE, url]))
    asked = _geo_stub257({_geo257.PAGE: (_PAGE257.replace(_SHA_DB257, "1" * 40).encode(), None), url: (_GZ257, None)})
    eq("DB-IP: a file that doesn't match its SHA1 is not kept (the page and the file were both asked for)",
       (_geo257.latest(), asked), ((None, "", _geo257.BAD_FILE), [_geo257.PAGE, url]))
    asked = _geo_stub257({_geo257.PAGE: (_PAGE257.encode(), None)}, switch=False)
    eq("DB-IP: turned off in Outside services, nothing is asked", (_geo257.latest(), asked),
       ((None, "", _geo257.OFF), []))
    redirect, req = _geo257._AllowedRedirect(), _urlreq257.Request(_geo257.PAGE)
    eq("DB-IP: a redirect is followed on db-ip.com's two hosts only, over https",
       [_geo257._allowed(u) for u in ("https://download.db-ip.com/x", "http://db-ip.com/x", "https://evil.example/x",
                                      "https://db-ip.com:8443/x")]
       + [redirect.redirect_request(req, None, 302, "", {}, u) is not None
          for u in ("https://evil.example/x", "https://download.db-ip.com/free/x.gz")],
       [True, False, False, False, False, True])
    check("Outside services: DB-IP has its own switch, which says what it sends and what Off stops",
          any(s["key"] == _os257.DBIP and "no player address" in s["note"] for s in _os257.SERVICES), "")


# ── 4. the routes ───────────────────────────────────────────────────────────────────────────────
_PROBE257 = ("os=24.04\npodman=podman version 4.9.3\nuid=1004\ngid=1005\nlogdir=.callofduty2/main\n"
             "rcon.b64=%s\nports= 21030 21031 21032\n" % _ad257._b64('set rcon_password "%s"' % _RC257))


_WETPROBE257 = ("os=24.04\npodman=podman version 4.9.3\nuid=1004\ngid=1005\nlogdir=serverfiles/etmain\n"
                "rcon.b64=%s\nports= 21040 21041 21042\nudp=%%s\n" % _ad257._b64('set rconpassword "%s"' % _RC257))


def _status257(meta, b3ini=""):
    return _PROBE257 + "installed=1\nmeta.b3=%s\nstate.b3=active\nb3ini.b64=%s\ngeoini.b64=\n" % (
        _ad257._b64(_json257.dumps(meta)), _ad257._b64(b3ini))


def _host257(answer):
    """Recorders for the host calls: [(kind, sh or verb, stdin)]; `answer(sh)` is the shell's stdout."""
    calls = []

    def shell(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
        calls.append(("sh", sh, stdin_text))
        return answer(sh), "", 0
    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch_sm("run_privileged", lambda server, verb, args=(), **_k: calls.append(("verb", verb, list(args)))
                 or ("", "", 0))
    _p9_patch_sm("enrol_game_user", lambda server, user: None)
    _p9_patch(_ra257, "threading", _p9_threading(_P9Thread))
    _p9_patch(_ch257, "threading", _p9_threading(_P9Thread))
    _p9_patch(_ra257, "step_up_needed", lambda: False)
    _p9_patch(_ra257, "game_account_write_refusal", lambda remote, user, reading=False: None)
    return calls


def _geo_file257():
    path = os.path.join(_TMP257, "geo.mmdb")
    with open(path, "wb") as fh:
        fh.write(_DB257)
    _p9_patch(_geo257, "latest", lambda: (__import__("pathlib").Path(path), _MONTH257, ""))
    _p9_patch(_geo257, "month_now", lambda: _MONTH257)


def _answer257(meta, b3ini="", probe=None):
    """The host's stdout for each shell: the change's read, the database push, an install or restart, the probe, a status."""
    def answer(sh):
        if "b3ini.b64" in sh:
            return _status257(meta, b3ini)
        if "GEOIP_PUT" in sh:
            return "GEOIP_PUT\n"
        if "restart lgsm-addon-b3" in sh or "podman build" in sh:
            return "ADDON_INSTALLED\n"
        if "-maxdepth 3 -type f -name" in sh:
            return probe or _PROBE257
        return "os=24.04\npodman=podman version 4.9.3\nmeta.b3=%s\nstate.b3=active\n" % _ad257._b64(_json257.dumps(meta))
    return answer


def _first257(calls, mark):
    """The first recorded shell call holding `mark`, or None."""
    return next((c for c in calls if c[0] == "sh" and mark in c[1]), None)


def _puts257(call):
    """The files an install or change shell writes, {path: text} (from its base64 lines)."""
    return {path: _ad257._unb64(b64) for b64, path in _re257.findall(r"printf %s (\S+) \| base64 -d > (\S+)\.new",
                                                                         call[1] if call else "")}


def _put257(puts, end):
    return next((t for p, t in puts.items() if p.endswith(end)), "")


def _install257(sid, db_id, geolocation, probe=None):
    """POST a B3 install and run it -> (status, push call, install call, its files, all calls)."""
    calls = _host257(_answer257({}, probe=probe))
    _geo_file257()
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/install" % sid,
                                  json={"database_id": db_id, "geolocation": geolocation})
    _p9_drain()
    inst = _first257(calls, "podman build")
    return r.status_code, _first257(calls, "GEOIP_PUT"), inst, _puts257(inst), calls


def _install_offline257(ids):
    code, push, inst, puts, calls = _install257(ids["cod2"], ids["db"], "offline")
    unit, meta = _put257(puts, ".container"), _json257.loads(_put257(puts, "addon.json") or "{}")
    eq("install (offline geolocation): the database goes to the add-on's geoip folder on stdin, mounted read-only; "
       "no relay; plugin_geolocation.ini asks only it; the record says offline, the month and the commit",
       (code, (push or [0, 0, ""])[2] == _b64m257.b64encode(_DB257).decode(),
        "Volume=/home/cod2p257/panel-addons/b3/geoip:/geoip:ro" in unit, "-T,443:" in unit,
        "geolocators: mmdb" in _put257(puts, "plugin_geolocation.ini"), meta.get("geolocation"), meta.get("geoip"),
        meta.get("commit"), None not in (push, inst) and calls.index(push) < calls.index(inst)),
       (202, True, True, False, True, "offline", _MONTH257, _PIN257, True))


def _install_wet257(ids):
    """Vanilla ET: refused while B3_WET is off; switched on, B3 uses the port the game really listens on.

    Its start passes no port, so a stopped server is refused.
    """
    off, _push, _inst, _puts, off_calls = _install257(ids["wet"], ids["wetdb"], "off", probe=_WETPROBE257 % "27960")
    sh_calls = [c for c in off_calls if c[0] == "sh"]
    rows = (_p9_client(P9_ADMIN).get("/api/server/%d/addons" % ids["wet"]).get_json() or {}).get("addons")
    eq("install (ET, switched off): refused as for any game B3 isn't offered for, nothing runs on the host; the "
       "card lists no add-on for it", (off, sh_calls, rows), (404, [], []))
    games = _ad257.CATALOG["b3"]["games"]
    games["wet"] = "et"
    try:
        code, _push, inst, _puts, _calls = _install257(ids["wet"], ids["wetdb"], "off", probe=_WETPROBE257 % "")
        refused = _p9_audit("addon_install").detail
        code2, _push, inst2, puts, _calls = _install257(ids["wet"], ids["wetdb"], "off", probe=_WETPROBE257 % "27960")
    finally:
        games.pop("wet", None)
    unit = _put257(puts, ".container")
    stdin = inst2[2] if inst2 else ""
    eq("install (ET, switched on): stopped, it is refused (its start passes no port, so only a running server says "
       "it); running on 27960 while its config says 27970, B3 and the unit use 27960; its log is etmain/etserver.log",
       (code, inst, "Start the game server first" in refused, code2, ",-U,27960" in unit, "port: 27960\n" in stdin,
        "game_log: /gamelog/etserver.log\n" in stdin, "parser: et\n" in stdin),
       (202, None, True, 202, True, True, True, True))


_B3INI257 = ("[b3]\nparser: cod2\n\n[server]\nrcon_password: %s\n\n[plugins]\nadmin: @conf/conf/plugin_admin.ini\n"
             "myext: @conf/myext.ini\nstats: @conf/conf/plugin_stats.ini\n" % _RC257)


def _meta257(**kw):
    rec = {"kind": "b3", "image": _ad257.CATALOG["b3"]["image"], "version": "x", "commit": _PIN257,
           "geolocation": "off", "plugins": ["stats"], "database": "gs%d_b3" % 0, "port": None}
    rec.update(kw)
    return rec


def _settings_refused257(ids, calls):
    _p9_patch(_ra257, "step_up_needed", lambda: True)
    refused = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/settings" % ids["cod2"],
                                        json={"geolocation": "off", "plugins": ["afk"]}, headers={"Accept": "application/json"})
    _p9_patch(_ra257, "step_up_needed", lambda: False)
    bad = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/settings" % ids["cod2"],
                                    json={"geolocation": "off", "plugins": ["translator"]})
    eq("settings: step-up first, as for install; a plugin the card doesn't offer is refused; nothing runs",
       (refused.status_code, bad.status_code, [c for c in calls if c[0] == "sh"]), (403, 400, []))


def _settings257(ids):
    meta = _meta257(database="gs%d_b3" % ids["cod2"])
    calls = _host257(_answer257(meta, _B3INI257))
    _settings_refused257(ids, calls)
    ok = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/settings" % ids["cod2"],
                                   json={"geolocation": "off", "plugins": ["afk", "tk"]})
    _p9_drain()
    re_ = _first257(calls, "restart lgsm-addon-b3") or ["sh", "podman build " + _RC257, ""]
    stdin = re_[2] or ""
    eq("settings: b3.ini goes back on stdin with only the panel's plugin lines changed (the operator's plugin and the "
       "password kept), no rebuild, a restart watched, audited",
       (ok.status_code, _ad257.b3_ini_plugins(stdin), "myext: @conf/myext.ini" in stdin,
        "rcon_password: %s" % _RC257 in stdin, "/panel-addons/b3/Data/b3.ini.new && mv" in re_[1], "podman build" in re_[1],
        _RC257 in re_[1], _p9_audit("addon_settings").success),
       (202, ["admin", "afk", "tk"], True, True, True, False, False, True))


def _update257(ids):
    old = "localhost/lgsm-addon-b3:b8e98400c51b"
    meta = _meta257(database="gs%d_b3" % ids["cod2"], image=old)
    calls = _host257(_answer257(meta, _B3INI257))
    rows = _p9_client(P9_ADMIN).get("/api/server/%d/addons" % ids["cod2"]).get_json()
    b3 = next(r for r in rows.get("addons") or [] if r["id"] == "b3")
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/update" % ids["cod2"], json={})
    _p9_drain()
    up = [c for c in calls if c[0] == "sh" and "restart lgsm-addon-b3" in c[1]]
    sh = up[0][1] if up else ""
    eq("update: offered when the record's image is older; it rebuilds from the pinned commit, keeps b3.ini's plugins "
       "and password, rewrites the unit, restarts, removes the old image, audited",
       (b3["update"], r.status_code, "B3_COMMIT=%s" % _PIN257 in sh, "podman rmi %s" % old in sh,
        _ad257.b3_ini_plugins((up[0][2] or _B3INI257) if up else ""), _RC257 in sh, _p9_audit("addon_update").success),
       ("image", 202, True, True, ["admin", "stats"], False, True))
    eq("update: none offered once the record matches; an offline B3 is offered next month's country database",
       [_ch257.update_reason("b3", _meta257()), _ch257.update_reason("b3", _meta257(geolocation="offline",
                                                                                     geoip="2026-10"), "2026-11"),
        _ch257.update_reason("b3", _meta257(geolocation="offline", geoip="2026-11"), "2026-11"),
        _ch257.update_reason("iw4madmin", {"image": _ad257.CATALOG["iw4madmin"]["image"]})],
       ["", "geoip", "", ""])


def _fixture257():
    ids = {"cod2": _p9_new_server(P9_HOST, "cod2p257", "cod2", 28965, name="p257-cod2"),
           "wet": _p9_new_server(P9_HOST, "wetp257", "wet", 27970, name="p257-wet")}
    with _p9.app_context():
        for key, db_key in (("cod2", "db"), ("wet", "wetdb")):
            row = _GD257(remote_id=P9_HOST, game_server_id=ids[key], name="gs%d_b3" % ids[key], secret=_enc257(_DBV257))
            _db257.session.add(row)
            _db257.session.commit()
            ids[db_key] = row.id
    return ids


def _drop257(ids):
    with _p9.app_context():
        for key in ("cod2", "wet"):
            _GD257.query.filter_by(game_server_id=ids[key]).delete()
        _db257.session.commit()
    for key in ("cod2", "wet"):
        _p9_delete_server(ids[key])


# ── 5. the card ─────────────────────────────────────────────────────────────────────────────────
_HARNESS257 = r"""'use strict';
const fs = require('fs'), vm = require('vm');
const cfg = JSON.parse(fs.readFileSync(0, 'utf8'));
const posts = [], dialogs = [];
function El(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.className = '';
  this._text = ''; this.style = {}; this.disabled = false; this.id = ''; this.checked = false; this.value = ''; }
El.prototype.appendChild = function (c) { this.children.push(c); return c; };
Object.defineProperty(El.prototype, 'textContent', {
  get() { return this._text + this.children.map(function (c) { return c.textContent; }).join(''); },
  set(v) { this._text = String(v); this.children = []; }});
El.prototype.setAttribute = function (k, v) { this.attrs[k] = String(v); if (k === 'id') this.id = String(v); };
El.prototype.getAttribute = function (k) { return k in this.attrs ? this.attrs[k] : null; };
function walk(e, out) { out.push(e); (e.children || []).forEach(function (c) { if (c instanceof El) walk(c, out); }); return out; }
const fixed = {};
['ad-card', 'ad-list', 'ad-loading', 'ad-runtime', 'ad-msg'].forEach(function (id) { fixed[id] = new El('div'); fixed[id].id = id; });
const all = function () { return walk(fixed['ad-list'], []); };
const document = {
  createElement: function (t) { return new El(t); },
  createTextNode: function (t) { return {textContent: String(t)}; },
  getElementById: function (id) { return fixed[id] || all().filter(function (e) { return e.id === id; })[0] || null; },
  querySelector: function () { return null; },
  querySelectorAll: function (sel) { const m = /^\[data-ad-plugin="([^"]+)"\]$/.exec(sel);
    return m ? all().filter(function (e) { return e.getAttribute('data-ad-plugin') === m[1]; }) : []; },
  addEventListener: function () {}};
const ctx = {document: document, location: {hash: ''}, MOUNT: '', serverId: 7, JSON: JSON, Promise: Promise, Number: Number,
  Array: Array, setInterval: function () { return 0; }, clearInterval: function () {}, Date: Date,
  confirmDialog: function (o) { dialogs.push(o.bodyText); },
  fetch: function (url, opts) {
    if (opts && opts.method === 'POST') posts.push([url, JSON.parse(opts.body)]);
    return Promise.resolve({ok: true, json: function () { return Promise.resolve(opts && opts.method === 'POST'
      ? {success: true, started: true, message: 'ok'} : cfg.data); }}); }};
ctx.window = ctx; ctx.addEventListener = function () {};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(cfg.src, 'utf8'), ctx);
ctx.window.adLoad(true).then(function () {
  const els = all();
  const act = function (n) { return els.filter(function (e) { return e.getAttribute('data-action') === n; }); };
  const geo = els.filter(function (e) { return e.id === 'ad-set-geo-b3'; })[0];
  const boxes = els.filter(function (e) { return e.getAttribute('data-ad-plugin') === 'b3'; });
  const res = {fold: els.some(function (e) { return e.tagName === 'DETAILS'; }), update: act('adUpdate').length,
    plugins: boxes.map(function (b) { return [b.value, b.checked]; }).filter(function (x) { return x[1]; }).map(function (x) { return x[0]; }),
    text: fixed['ad-list'].textContent};
  if (geo) geo.value = 'offline';
  boxes.forEach(function (b) { b.checked = b.value === 'afk' || b.value === 'countryfilter'; });
  ctx.window.adRemove('b3');
  ctx.window.adSettings('b3');
  return new Promise(function (r) { setTimeout(r, 20); }).then(function () {
    res.posts = posts; res.dialogs = dialogs;
    process.stdout.write(JSON.stringify(res));
  });
}).catch(function (e) { process.stdout.write(JSON.stringify({error: String(e && e.stack || e)})); });
"""


def _card257(update, game_note=""):
    node = _shutil257.which("node")
    if not node:
        return {"error": "node is not installed"}
    path = os.path.join(_TMP257, "harness.js")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_HARNESS257)
    row = {"id": "b3", "name": "B3", "version": "x", "installed": True, "state": "active", "legacy": True,
           "needs_database": True, "data_kept": True, "database": "gs7_b3", "geolocation_option": True,
           "geolocation": "offline", "geoip": "2026-11", "credit": _geo257.CREDIT, "plugins": ["stats", "tk"],
           "switchable": list(_ad257.B3_SWITCHABLE), "geo_switchable": list(_ad257.B3_GEO_SWITCHABLE),
           "update": update, "note": game_note}
    cfg = {"src": os.path.join(_root, "panel", "static", "js", "server_addons.js"),
           "data": {"success": True, "addons": [row], "databases": []}}
    r = _sp257.run([node, path], input=_json257.dumps(cfg),  # nosec B603 - node on this part's harness
                   capture_output=True, text=True, timeout=120, check=False)
    try:
        return _json257.loads(r.stdout)
    except ValueError:
        return {"error": (r.stdout + r.stderr)[-800:]}


def _card_checks257():
    got = _card257("image", "On Soldier of Fortune 2, B3 has no private messages.")
    eq("card: an installed B3 has its settings folded, its plugins ticked as set, an Update button when one is "
       "available, the DB-IP credit when offline, and the game's note",
       (got.get("fold"), got.get("update"), got.get("plugins"), _geo257.CREDIT in got.get("text", ""),
        "no private messages" in got.get("text", "")), (True, 1, ["stats", "tk"], True, True))
    eq("card: Apply posts the geolocation and the ticked plugins to the settings route",
       got.get("posts"), [["/api/server/7/addons/b3/settings", {"geolocation": "offline",
                                                                 "plugins": ["afk", "countryfilter"],
                                                                 "own_plugins": False}]])
    check("card: B3's Remove warns that its folder goes (settings and plugin edits) and its database stays",
          any("plugin settings you edited" in d and "database is kept" in d for d in got.get("dialogs") or []),
          repr(got.get("dialogs")))
    eq("card: no Update button when none is available", _card257("").get("update"), 0)
    _src = _read257("panel", "static", "js", "server_addons.js")
    _hook = _src[_src.find("document.addEventListener('click'"):]
    check("card: a visit to the Databases tab makes the card ask again when it is next opened",
          "closest('[data-sfsub-btn=\"databases\"]')) st.loaded = false;" in _hook[:400], _hook[:400])


# ── 6. Renovate ─────────────────────────────────────────────────────────────────────────────────
def _manager_hits257(m):
    """[(file, digest)] a Renovate regex manager matches in the panel's own files (its JS regex read as Python's)."""
    pat = _re257.compile(_re257.sub(r"\(\?<(?=[A-Za-z])", "(?P<", m["matchStrings"][0]))
    paths = [f.strip("/").lstrip("^").rstrip("$").replace("\\.", ".") for f in m.get("managerFilePatterns") or []]
    return [(path, x.groupdict().get("currentDigest")) for path in paths if path.startswith("panel/")
            for x in pat.finditer(_read257(*path.split("/")))]


def _renovate257():
    cfg = _json257.loads(_read257(".github", "renovate.json"))
    found = {}
    for m in cfg.get("customManagers") or []:
        hits = _manager_hits257(m)
        if hits:
            found.setdefault(m.get("datasourceTemplate"), []).extend(hits)
    daily = [r for r in cfg.get("packageRules") or [] if r.get("schedule") == ["* 0-5 * * *"]]
    eq("Renovate: B3's commit in addons.py and the Containerfile (git-refs, master) and IW4MAdmin's digest (docker, "
       "latest), each matched once, checked daily",
       (found, sorted(sum((r.get("matchDepNames") or [] for r in daily), []))),
       ({"git-refs": [("panel/services/addons.py", _PIN257), ("panel/addon_images/b3/Containerfile", _PIN257)],
         "docker": [("panel/services/addons.py", _ad257.IW4MADMIN_IMAGE.split("@")[1])]},
        ["big-brother-bot", "ghcr.io/raidmax/iw4madmin"]))


# ── 7. the remote form of addon-account-release ─────────────────────────────────────────────────
_EMPTY257 = b"LPKSHHRH" + b"\0" * 160
_HELD257 = b"LPKSHHRH" + b"\0" * 144 + (3).to_bytes(8, "little") + b"\0" * 8


def _remote_forget257():
    base = os.path.join(_TMP257, "remote-journal")
    _shutil257.rmtree(base, ignore_errors=True)
    mid = os.path.join(base, "var", "0123456789abcdef0123456789abcdef")
    os.makedirs(mid)
    os.makedirs(os.path.join(base, "run"))
    os.makedirs(os.path.join(base, "proc", "4242"))
    with open(os.path.join(base, "proc", "4242", "status"), "w", encoding="ascii") as fh:
        fh.write("Name:\tx\nUid:\t5004\t5004\t5004\t5004\n")
    for name, body in {"user-5000.journal": _HELD257, "user-5001.journal": _EMPTY257, "user-5002.journal": _HELD257,
                       "user-5003.journal": _EMPTY257, "user-5004.journal": _EMPTY257, "user-999.journal": _EMPTY257,
                       "user-5005@00ab-0000000000000001-0005f3a1b2c3d4e5.journal": _EMPTY257,
                       "user-5006.journal": b""}.items():
        with open(os.path.join(mid, name), "wb") as fh:
            fh.write(body)
    sh = (_pv257._addon_release_remote(["cod4server", "forget"]).replace("/var/log/journal", base + "/var")
          .replace("/run/log/journal", base + "/run").replace("/proc/", base + "/proc/"))
    stubs = ('id() { echo 5000; }; loginctl() { :; }; systemctl() { :; }; timeout() { shift; "$@"; }; '
             'journalctl() { echo "rotate" >> %s/ran; }; getent() { [ "$2" = 5003 ]; }; ' % base)
    r = _sp257.run(["bash", "-c", stubs + sh], capture_output=True, text=True, timeout=30, check=False,  # nosec B603 B607
                   env={"PATH": "/usr/bin:/bin"})
    eq("remote release (bash): after its rotation the empty journal re-created for a uid with no account and no "
       "process goes with the account's own; one holding entries, a live account's, a uid with a process, one "
       "below 1000, an archived one and a file that is not a journal stay",
       (r.stdout.strip().splitlines()[-1:], sorted(os.listdir(mid))),
       (["forgotten=2"], ["user-5002.journal", "user-5003.journal", "user-5004.journal",
                          "user-5005@00ab-0000000000000001-0005f3a1b2c3d4e5.journal", "user-5006.journal",
                          "user-999.journal"]))


try:
    _catalog257()
    _probe_sof2_257()
    _ini257()
    _geoip257()
    _p9_restore_all()
    _card_checks257()
    _renovate257()
    _remote_forget257()
    _ids257 = _fixture257()
    try:
        for _step257 in (_install_offline257, _install_wet257, _settings257, _update257):
            _p9_restore_all()
            _p9_arm(who="part257")
            _step257(_ids257)
    finally:
        _p9_restore_all()
        _drop257(_ids257)
finally:
    _p9_restore_all()
check("part257: no check reached a real host", len(_P9_TRIPPED) == _trips257, repr(_P9_TRIPPED[_trips257:][:4]))
_shutil257.rmtree(_TMP257, ignore_errors=True)
