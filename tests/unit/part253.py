"""Part 253 of the unit suite: add-ons in rootless containers (panel/services/addons.py, routes/addons.py).

1. The verbs: addon-account-prepare and addon-account-release refuse root and the panel's own account
   on both sides; the helper gives a game account only the subordinate id range it lacks, after every
   range in use, then lingering, and refuses an account outside the game group; the remote shell form,
   run under bash with stand-in usermod and loginctl, does the same.
2. The pieces: the RCON line, the log folder (nothing that could break the unit file), the runtime
   check, the unit's hardening lines, the network forwards, and IW4MAdmin's settings.
3. The routes: Manage add-ons on every route; step-up on install and remove; a database of another
   server refused; the install installs Podman when missing, readies the account, writes the settings
   over stdin (no secret on any command line) and is audited; a missing RCON password or log stops it;
   remove releases the account only when no add-on is left; the account guard stops start/stop;
   the log masks the database passwords; uninstall releases lingering before it kills the account.
4. The tab: shown for a game an add-on runs, to a viewer with Manage add-ons only; every new sentence
   in Spanish and French.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; every host call is a recorder.
The helper runs in-process with stand-ins, and the shell form runs under bash in a throwaway folder
with stand-in tools on PATH. Nothing reaches a host, /etc or data/.
"""
import atexit as _atexit253
import json as _json253
import os
import shutil as _shutil253
import subprocess as _sp253  # nosec B404 - bash over the panel's own shell form, in a throwaway dir
import tempfile as _tf253
from types import SimpleNamespace as _NS253

from unit.part01 import check, eq
from unit.part05 import _helper as _h253
from unit.part12 import (P9_ADMIN, P9_HOST, P9_VIEWER, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client,
                         _p9_delete_server, _p9_drain, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all,
                         _p9_threading, _P9Thread)
from panel.core import i18n as _i18n253
from panel.core.config import encrypt_secret as _enc253
from panel.db.models import GameDatabase as _GD253, db as _db253
from panel.routes import addons as _ra253
from panel.routes import manage_servers as _ms253
from panel.security import privileged as _pv253
from panel.services import addons as _ad253

_trips253 = len(_P9_TRIPPED)
_TMP253 = _tf253.mkdtemp(prefix="p253-")
_atexit253.register(_shutil253.rmtree, _TMP253, True)
_RC253 = "p253-rcon-" + "value"          # the game's RCON password in these checks
_DBV253 = "Dbv253" + "abcdefghijklmnopqrstu"   # a database's password in these checks


# ── 1. the verbs ────────────────────────────────────────────────────────────────────────────────
def _refuses253(verb, user):
    try:
        _pv253.check_args(verb, [user])
    except ValueError:
        return True
    return False


def _verbs253():
    panel_user = _pv253.pwd.getpwuid(os.getuid()).pw_name
    for verb in ("addon-account-prepare", "addon-account-release"):
        check("addon verbs: %s refuses root on the panel's side" % verb, _refuses253(verb, "root"))
        try:
            _h253.validate(verb, ["root"])
            helper_refused = False
        except ValueError:
            helper_refused = True
        check("addon verbs: %s refuses root in the helper" % verb, helper_refused)
    if _pv253._is_panel_account(panel_user):
        check("addon verbs: release refuses the panel's own account (it would end a per-user install's boot start)",
              _refuses253("addon-account-release", panel_user))
    eq("addon verbs: release is the helper's own function on both sides (no fixed argv)",
       (_pv253.tool_argv("addon-account-release", ["cod4server"]),
        _h253.VERBS["addon-account-release"][1](["cod4server"]),
        _h253.ACTIONS.get("addon-account-release") is _h253.do_addon_account_release),
       ([], [], True))
    eq("addon verbs: the two copies of the id range agree",
       (_pv253.ADDON_SUBID_COUNT, _pv253.ADDON_SUBID_MIN, _pv253.ADDON_SUBID_LAST),
       (_h253.ADDON_SUBID_COUNT, _h253.ADDON_SUBID_MIN, _h253.ADDON_SUBID_LAST))


def _helper_run253(subuid, subgid, member=True):
    """do_addon_account_prepare with stand-in files and tools: (rc, argv lists run)."""
    files = []
    for name, text in (("subuid", subuid), ("subgid", subgid)):
        path = os.path.join(_TMP253, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        files.append(path)
    ran = []
    saved = {k: getattr(_h253, k) for k in ("SUBID_FILES", "_groups_of", "pwd", "subprocess", "resolve")}
    try:
        _h253.SUBID_FILES = tuple(files)
        _h253._groups_of = lambda u: {_h253.GAME_GROUP} if member else {"users"}
        _h253.pwd = _NS253(getpwnam=lambda n: _NS253(pw_name=n, pw_uid=4321))
        _h253.subprocess = _NS253(run=lambda argv, **k: ran.append(argv) or _NS253(returncode=0, stderr=b""))
        _h253.resolve = lambda prog: prog
        rc = _h253.do_addon_account_prepare(["cod4server"], None)
    finally:
        for k, v in saved.items():
            setattr(_h253, k, v)
    return rc, ran


def _helper_prepare253():
    rc, ran = _helper_run253("alice:100000:65536\ncod4server:165536:65536\n", "alice:100000:65536\n")
    eq("addon-account-prepare: only the missing gid range is added, after every range in use, then lingering",
       (rc, ran), (0, [["usermod", "--add-subgids", "231072-296607", "cod4server"],
                       ["loginctl", "enable-linger", "cod4server"]]))
    rc, ran = _helper_run253("4321:100000:65536\n", "cod4server:100000:65536\n")
    eq("addon-account-prepare: an account holding both ranges (by uid or by name) gets lingering only",
       (rc, ran), (0, [["loginctl", "enable-linger", "cod4server"]]))
    rc, ran = _helper_run253("", "cod4server:200000:100\n")
    eq("addon-account-prepare: a range too small counts as none",
       ran[0], ["usermod", "--add-subuids", "200100-265635", "--add-subgids", "200100-265635", "cod4server"])
    rc, ran = _helper_run253("", "", member=False)
    eq("addon-account-prepare: an account outside the game group is refused and nothing runs", (rc, ran), (1, []))
    rc, ran = _helper_run253("x:4294900000:65536\n", "")
    eq("addon-account-prepare: no range left below the top refuses", (rc, ran), (1, []))


def _remote_form253():
    if _shutil253.which("bash") is None or _shutil253.which("awk") is None:
        check("addon-account-prepare remote form: bash and awk present to run it", False)
        return
    bindir = os.path.join(_TMP253, "bin")
    os.makedirs(bindir, exist_ok=True)
    for tool in ("usermod", "loginctl"):
        path = os.path.join(bindir, tool)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\necho "%s $*"\n' % tool)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(path, 0o700)  # nosec B103 - a stand-in tool in the part's own temp dir
    out = []
    for subuid, subgid in (("alice:100000:65536\nnobody:165536:65536\n", "alice:100000:65536\n"),
                           ("nobody:100000:65536\n", "65534:100000:65536\n")):
        for name, text in (("subuid", subuid), ("subgid", subgid)):
            with open(os.path.join(_TMP253, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        cmd = _pv253.remote_command("addon-account-prepare", ["nobody"])
        cmd = cmd.replace("/etc/subuid", os.path.join(_TMP253, "subuid")).replace(
            "/etc/subgid", os.path.join(_TMP253, "subgid"))
        r = _sp253.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=30,  # nosec B603 B607
                       env={"PATH": bindir + ":/usr/bin:/bin"}, check=False)
        out.append((r.returncode, r.stdout))
    eq("addon-account-prepare remote form: adds only the missing range, after every range, then lingers",
       out[0], (0, "usermod --add-subgids 231072-296607 nobody\nsubids=added\nloginctl enable-linger nobody\nlinger=on\n"))
    eq("addon-account-prepare remote form: both ranges held (gid row by uid): lingering only",
       out[1], (0, "subids=present\nloginctl enable-linger nobody\nlinger=on\n"))


# ── 2. the pieces ─────────────────────────────────────────────────────────────────────────────────
def _pieces253():
    eq("rcon: the last rcon_password line wins, quoted or bare; none is ''",
       [_ad253.rcon_password('set rcon_password "a b"\nseta rcon_password "c"'),
        _ad253.rcon_password("set rcon_password xyz // note"), _ad253.rcon_password("set sv_hostname x"),
        _ad253.rcon_password('set rcon_password ""')], ["c", "xyz", "", ""])
    eq("log dir: only plain words below the home; .., %, spaces and line breaks are refused",
       [_ad253.log_dir("u", "serverfiles/main"), _ad253.log_dir("u", "../x"), _ad253.log_dir("u", "a/%h"),
        _ad253.log_dir("u", "a b"), _ad253.log_dir("u", "a\nPodmanArgs=--privileged"), _ad253.log_dir("u", "")],
       ["/home/u/serverfiles/main", "", "", "", "", ""])
    eq("runtime: Ubuntu 22.04 and Podman 3.4 are refused; 24.04 with 4.9 or no Podman yet passes",
       [bool(_ad253.runtime_refusal("22.04", "")), bool(_ad253.runtime_refusal("24.04", "podman version 3.4.4")),
        _ad253.runtime_refusal("24.04", "podman version 4.9.3"), _ad253.runtime_refusal("26.04", "")],
       [True, True, "", ""])
    eq("network: RCON (UDP) always, the database's port only when it is on this host, the lock first",
       [_ad253.network(28960, 3306, [], False), _ad253.network(28961, None, [], True)],
       ["pasta:-4,-o,127.0.0.1,-U,28960,-T,3306:3306", "pasta:--splice-only,-U,28961"])
    unit = _ad253.quadlet("cod4server", "iw4madmin", "/home/cod4server/serverfiles/main", "pasta:-U,28960", 21007)
    want = ("ReadOnly=true", "DropCapability=all", "NoNewPrivileges=true", "PidsLimit=512", "Pull=never",
            "PublishPort=127.0.0.1:21007:1624", "Volume=/home/cod4server/serverfiles/main:/gamelog:ro",
            "Image=ghcr.io/raidmax/iw4madmin@sha256:", "PodmanArgs=--memory=1g", "WantedBy=default.target")
    eq("unit: the hardening, the pinned image and the loopback-only page are all there",
       [w for w in want if w not in unit], [])
    check("unit: no privileged mode, host network or added capability",
          not any(x in unit for x in ("--privileged", "Network=host", "AddCapability")), unit[:200])
    doc = _json253.loads(_ad253.iw4madmin_settings("cod4", 28960, _RC253))
    srv = doc["Servers"][0]
    eq("IW4MAdmin settings: one server on 127.0.0.1 with the CoD4x parser, the game log, SQLite, no Id",
       (srv["IPAddress"], srv["Port"], srv["Password"], srv["RConParserVersion"], srv["ManualLogPath"],
        doc["DatabaseProvider"], "ConnectionString" in doc, doc["AutoMessagePeriod"] >= 60, "Id" in doc),
       ("127.0.0.1", 28960, _RC253, "CoD4x Parser", "/gamelog/games_mp.log", "sqlite", False, True, False))


# ── 3. the routes ─────────────────────────────────────────────────────────────────────────────────
def _fixture253():
    sid = _p9_new_server(P9_HOST, "cod4server", "cod4", 28960, name="p253-cod4")
    other = _p9_new_server(P9_HOST, "tf2p253", "tf2", 27099, name="p253-tf2")
    with _p9.app_context():
        mine = _GD253(remote_id=P9_HOST, game_server_id=sid, name="gs%d_iw4m" % sid, secret=_enc253(_DBV253))
        theirs = _GD253(remote_id=P9_HOST, game_server_id=other, name="gs%d_data" % other, secret=_enc253("x"))
        _db253.session.add_all([mine, theirs])
        _db253.session.commit()
        return sid, other, mine.id, theirs.id


def _drop253(ids):
    sid, other, mine, theirs = ids
    with _p9.app_context():
        for i in (mine, theirs):
            r = _db253.session.get(_GD253, i)
            if r is not None:
                _db253.session.delete(r)
        _db253.session.commit()
    _p9_delete_server(sid)
    _p9_delete_server(other)


def _host253(probe=None, install_out="ADDON_INSTALLED\n", remove_out="others=0\nADDON_REMOVED\n"):
    """Recorders for the two host calls: [(kind, sh or verb, args or stdin)]."""
    calls = []
    meta = _ad253._b64('{"database": "taken", "port": 21001}')

    def shell(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
        calls.append(("sh", sh, stdin_text))
        if "podman pull" in sh:
            return install_out, "", 0
        if "ADDON_REMOVED" in sh:
            return remove_out, "", 0
        if "games_mp.log" in sh:
            return probe if probe is not None else (
                "os=24.04\npodman=\nlogdir=serverfiles/main\nports= 21009\nrcon.b64=%s\n"
                % _ad253._b64('set rcon_password "%s"' % _RC253)), "", 0
        if "journalctl" in sh:
            return "conn Password=%s\n" % _DBV253, "", 0
        return "os=24.04\npodman=podman version 4.9.3\nmeta.iw4madmin=%s\nstate.iw4madmin=active\n" % meta, "", 0

    def priv(server, verb, args=(), **_kw):
        calls.append(("verb", verb, list(args)))
        return "", "", 0
    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch_sm("run_privileged", priv)
    _p9_patch(_ra253, "threading", _p9_threading(_P9Thread))
    _p9_patch(_ra253, "step_up_needed", lambda: False)
    # A plain game account (the guard's own host read is driven in part19; its refusal below).
    _p9_patch(_ra253, "game_account_write_refusal", lambda remote, user, reading=False: None)
    return calls


def _permission253(ids):
    sid = ids[0]
    _host253()
    v = _p9_client(P9_VIEWER)
    got = [v.get("/api/server/%d/addons" % sid).status_code,
           v.post("/api/server/%d/addons/iw4madmin/install" % sid, json={"database_id": ids[2]}).status_code,
           v.post("/api/server/%d/addons/iw4madmin/remove" % sid).status_code]
    check("routes: a viewer without Manage add-ons is refused on read, install and remove",
          all(c in (403, 404) for c in got), repr(got))
    _p9_patch(_ra253, "step_up_needed", lambda: True)
    a = _p9_client(P9_ADMIN)
    r = [a.post("/api/server/%d/addons/iw4madmin/install" % sid, json={"database_id": ids[2]}),
         a.post("/api/server/%d/addons/iw4madmin/remove" % sid)]
    eq("routes: install and remove ask a stale sign-in to confirm the password (403 reauth_required)",
       [(x.status_code, (x.get_json(silent=True) or {}).get("error")) for x in r],
       [(403, "reauth_required"), (403, "reauth_required")])


def _install_calls253(calls, ok):
    verbs = [c[1] for c in calls if c[0] == "verb"]
    check("install: Podman is installed when missing, then the account is readied",
          verbs[:1] + verbs[-1:] == ["apt-install", "addon-account-prepare"],
          repr((verbs, ok.status_code, _p9_audit("addon_install").detail, [c[1][:80] for c in calls])))
    eq("install: the packages are the fixed list", next((c[2] for c in calls if c[1] == "apt-install"), None),
       ["podman", "uidmap", "passt"])


def _install_stdin253(calls):
    """The settings the install sent on stdin, parsed ({} when it sent none)."""
    inst = [c[2] for c in calls if c[0] == "sh" and "podman pull" in c[1]]
    return _json253.loads(inst[0]) if inst and inst[0] else {}


def _install_secrets253(calls):
    settings = _install_stdin253(calls)
    srv = (settings.get("Servers") or [{}])[0]
    check("install: the settings travel on stdin with the RCON password, and IW4MAdmin's own SQLite database",
          srv.get("Password") == _RC253 and settings.get("DatabaseProvider") == "sqlite", repr(settings)[:200])
    check("install: no secret is on any command line",
          not [c for c in calls if c[0] == "sh" and (_RC253 in c[1] or _DBV253 in c[1])])


def _install253(ids):
    sid = ids[0]
    calls = _host253()
    a = _p9_client(P9_ADMIN)
    ok = a.post("/api/server/%d/addons/iw4madmin/install" % sid, json={})
    _p9_drain()
    _install_calls253(calls, ok)
    _install_secrets253(calls)
    row = _p9_audit("addon_install")
    eq("install: 202, then an audit row that it is installed", (ok.status_code, row.success, row.detail),
       (202, True, "iw4madmin installed"))


def _install_refused253(ids):
    sid = ids[0]
    for probe, want in (("os=24.04\npodman=\nlogdir=serverfiles/main\nports= 21009\n", _ra253._NO_RCON),
                        ("os=24.04\npodman=\nlogdir=\nports= 21009\nrcon.b64=%s\n" % _ad253._b64("set rcon_password x"),
                         _ra253._NO_LOG),
                        ("os=22.04\npodman=\nlogdir=serverfiles/main\nports= 21009\nrcon.b64=%s\n"
                         % _ad253._b64("set rcon_password x"), "Add-ons need Ubuntu 24.04 or newer on the game's host.")):
        calls = _host253(probe=probe)
        _p9_client(P9_ADMIN).post("/api/server/%d/addons/iw4madmin/install" % sid, json={})
        _p9_drain()
        row = _p9_audit("addon_install")
        check("install refused (%s): audited as failed, nothing installed or readied" % want[:40],
              row.success is False and want in row.detail and not [c for c in calls if c[0] == "verb"]
              and not [c for c in calls if c[0] == "sh" and "podman pull" in c[1]], repr((row.detail, calls[-1:])))


def _remove253(ids):
    sid = ids[0]
    for out, released in (("others=0\nADDON_REMOVED\n", True), ("others=1\nADDON_REMOVED\n", False)):
        calls = _host253(remove_out=out)
        r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/iw4madmin/remove" % sid)
        verbs = [c[1] for c in calls if c[0] == "verb"]
        eq("remove (%s): lingering is released only when no add-on is left" % out.split()[0],
           (r.status_code, verbs, _p9_audit("addon_remove").success),
           (200, ["addon-account-release"] if released else [], True))


def _guard_and_logs253(ids):
    sid = ids[0]
    calls = _host253()
    _p9_patch(_ra253, "game_account_write_refusal", lambda remote, user, reading=False: "root-capable")
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/iw4madmin/start" % sid)
    check("start: a root-capable account is refused before anything runs, and audited",
          not calls and _p9_audit("addon_refused").success is False and "root-capable" in r.get_data(as_text=True),
          repr(calls[:1]))
    _p9_restore_all()
    _p9_arm(who="part253")
    _host253()
    log = _p9_client(P9_ADMIN).get("/api/server/%d/addons/iw4madmin/logs" % sid).get_json(silent=True) or {}
    check("logs: the server's database passwords are masked", _DBV253 not in log.get("log", "x")
          and "Password=" in log.get("log", ""), repr(log)[:200])
    st = _p9_client(P9_ADMIN).get("/api/server/%d/addons" % sid).get_json(silent=True) or {}
    a = (st.get("addons") or [{}])[0]
    eq("status: the installed add-on, its state and port, read in one call", (a.get("installed"), a.get("state"), a.get("port")),
       (True, "active", 21001))


def _uninstall253():
    calls = []
    _p9_patch_sm("run_privileged", lambda server, verb, args=(), **k: calls.append(verb) or ("", "", 0))
    _p9_patch(_ms253, "_lgp", _NS253(stop_now=lambda *a, **k: None))
    _p9_patch(_ms253, "time", _NS253(sleep=lambda s: None))
    _ms253._stop_game_processes(_NS253(id=1), "cod4server", "cod4server")
    eq("uninstall: lingering is released (and the manager stopped) before the account's processes are killed", calls,
       ["addon-account-release", "user-kill-processes"])


# ── 4. the tab and its text ───────────────────────────────────────────────────────────────────────
def _tab253(ids):
    _host253()
    page = _p9_client(P9_ADMIN).get("/server/%d/files" % ids[0]).get_data(as_text=True)
    other = _p9_client(P9_ADMIN).get("/server/%d/files" % ids[1]).get_data(as_text=True)
    check("tab: a CoD4 server's Files & Config page has the Add-ons tab and its script; a TF2 server's has not",
          'data-sfsub-btn="addons"' in page and "server_addons.js" in page
          and 'data-sfsub-btn="addons"' not in other, "")


def _said_in_modules253():
    said = set()
    for mod in (_ra253, _ad253):
        for k, v in vars(mod).items():
            if k.startswith("_") and isinstance(v, str) and v[:1].isupper() and v.endswith(".") and " " in v:
                said.add(v)
    return (said | set(_ra253._DONE.values()) | set(_ra253._NOT_DONE.values()) | set(_ad253._FAIL_MARKS.values())
            | set(_ra253._REMOVED.values()))


def _said_in_page253(base):
    import re
    js = open(os.path.join(base, "static", "js", "server_addons.js"), encoding="utf-8").read()
    said = {m.replace("\\'", "'") for m in re.findall(r"T\('((?:[^'\\]|\\.)*)'\)", js)}
    said |= set(re.findall(r"^\s+(?:active|activating|deactivating|inactive|failed|reloading|unknown): '([^']+)'",
                           js, re.M))
    html = open(os.path.join(base, "templates", "_server_addons.html"), encoding="utf-8").read()
    return said | {m.strip() for m in re.findall(r"<li>([^<]+)</li>", html)}


def _text253():
    """Every sentence the routes, the service, the tab's script and its template show, in es and fr."""
    said = _said_in_modules253() | _said_in_page253(os.path.join(os.path.dirname(_ra253.__file__), ".."))
    said.add("Manage a server's add-ons: install, start, stop and remove admin tools that run in containers "
             "beside the game as its account, and read their logs")
    missing = [(lang, x) for lang in ("es", "fr") for x in sorted(said) if x not in _i18n253.catalog(lang)]
    check("text: the check found the add-ons' sentences to look up", len(said) > 50, repr(len(said)))
    eq("text: every new sentence has a Spanish and a French translation", missing[:4], [])


try:
    _verbs253()
    _helper_prepare253()
    _remote_form253()
    _pieces253()
    _ids253 = _fixture253()
    try:
        _p9_arm(who="part253")
        _permission253(_ids253)
        _p9_restore_all()
        _p9_arm(who="part253")
        _install253(_ids253)
        _install_refused253(_ids253)
        _remove253(_ids253)
        _guard_and_logs253(_ids253)
        _p9_restore_all()
        _p9_arm(who="part253")
        _uninstall253()
        _p9_restore_all()
        _p9_arm(who="part253")
        _tab253(_ids253)
    finally:
        _p9_restore_all()
        _drop253(_ids253)
    _text253()
finally:
    _p9_restore_all()
check("part253: no check reached a real host", len(_P9_TRIPPED) == _trips253, repr(_P9_TRIPPED[_trips253:][:4]))
