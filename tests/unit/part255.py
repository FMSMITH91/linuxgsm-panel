"""Part 255 of the unit suite: the add-ons' fix round and B3 (panel/services/addons.py, routes/addons.py).

1. The network lock: every unit's Network= is pasta with the lock first (--splice-only where pasta has
   it, else -4 and -o 127.0.0.1) and forwards only RCON, the local database and the relays; the
   install asks pasta which it has and writes that into the unit it installs.
2. The first start: the install's own shell, run under bash with stand-in podman, systemctl,
   journalctl and sleep, calls an add-on that stops (or restarts) within the settle time a failure,
   stops it and returns its last log lines; the route audits that as failed and shows the lines
   with the RCON password masked.
3. IW4MAdmin: SQLite (no database from the Databases tab), its two first-start plugin questions
   answered in their files, a SIGINT stop, Restart=always.
4. Releasing an account: the helper and the remote shell turn lingering off, stop the user manager
   and clear its failed state.
5. B3: a database of this server is required; the image is built from the pinned commit with
   hashed dependencies; geolocation is off unless chosen, and when chosen goes through relays;
   a database on another machine goes through a relay; CoD1's ~/.callofduty log folder works;
   an RCON password B3's ini can't hold is refused; its log is its own file.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; every host call is a recorder.
The shells run under bash in a throwaway folder with stand-in tools on PATH. Nothing reaches a host.
"""
import atexit as _atexit255
import json as _json255
import os
import re as _re255
import shutil as _shutil255
import socket as _socket255
import subprocess as _sp255  # nosec B404 - bash over the panel's own shell forms, in a throwaway dir
import tempfile as _tf255
from types import SimpleNamespace as _NS255

from unit.part01 import check, eq, skip
from unit.part05 import _helper as _h255
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client, _p9_delete_server,
                         _p9_drain, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_threading,
                         _P9Thread)
from panel.core.config import encrypt_secret as _enc255
from panel.db.models import GameDatabase as _GD255, db as _db255
from panel.routes import addons as _ra255
from panel.security import privileged as _pv255
from panel.services import addons as _ad255

_trips255 = len(_P9_TRIPPED)
_TMP255 = _tf255.mkdtemp(prefix="p255-")
_atexit255.register(_shutil255.rmtree, _TMP255, True)
_RC255 = "p255-rcon-" + "value"            # the game's RCON password in these checks
_DBV255 = "Dbv255" + "abcdefghijklmnopq"   # a database's password in these checks
_PUT255 = _re255.compile(r"printf %s (\S+) \| base64 -d > (\S+)\.new")


def _puts255(sh):
    """The files an install shell writes from base64, {path: text}."""
    return {path: _ad255._unb64(b64) for b64, path in _PUT255.findall(sh)}


def _net_line255(unit):
    return next((x[len("Network="):] for x in unit.splitlines() if x.startswith("Network=")), "")


# ── 1. the network lock ─────────────────────────────────────────────────────────────────────────
def _lock255():
    eq("lock: forwards only RCON, the local database and the relays, after the lock",
       [_ad255.network(28960, 3306, [], True),
        _ad255.network(28961, None, [("db", "127.0.0.1", 3306, 21005, "100.70.1.2:3307"),
                                     ("geo1", "127.0.0.2", 443, 21006, "ipwho.is:443")], False)],
       ["pasta:--splice-only,-U,28960,-T,3306:3306",
        "pasta:-4,-o,127.0.0.1,-U,28961,-T,3306:21005,-T,443:21006"])
    geo = _ad255.relays(_ad255.B3, "100.70.1.2", 3307, True, [21005, 21006, 21007])
    nets = [_ad255.network(28960, None, geo, splice) for splice in (True, False)]
    eq("lock: -T never carries an address, on 26.04 (--splice-only) or 24.04 (pasta's -T takes none)",
       [_re255.findall(r"-T,([^,]+)", n) for n in nets], [["3306:21005", "443:21006"]] * 2)
    p = _ad255.probe_sh(_ad255.IW4MADMIN, "cod4server", 3, "cod4", 1)
    check("lock: the probe asks pasta whether it has --splice-only", "pasta --help" in p and "--splice-only" in p, p[:80])
    eq("lock: the probe's answer is read", [_ad255.parse_probe("splice=1\n")["splice"], _ad255.parse_probe("")["splice"]],
       [True, False])
    for aid in _ad255.ADDON_IDS:
        unit = _ad255.quadlet("u", aid, "/home/u/serverfiles/main", _ad255.network(28960, None, [], False), 21001)
        check("lock: the %s unit has no host network, no added capability and its DNS off" % aid,
              "--dns=none" in unit and not any(x in unit for x in ("Network=host", "AddCapability", "--privileged",
                                                                   "--cap-add")), unit[:120])


# ── 2. the first start (the install's shell, under bash) ───────────────────────────────────────
def _stand_ins255(bindir):
    os.makedirs(bindir, exist_ok=True)
    tools = {
        "podman": ("#!/bin/sh\necho \"podman $*\" >> \"$S255_LOG\"\n"
                   "case \"$1\" in pull|build) [ -e \"$S255_UNIT\" ] && echo unit-before-image >> \"$S255_LOG\";; "
                   "unshare) shift; exec \"$@\";; esac\nexit 0\n"),
        "systemctl": ("#!/bin/sh\necho \"systemctl $*\" >> \"$S255_LOG\"\n"
                      "case \"$*\" in *is-active*) echo \"$S255_STATE\";; *NRestarts*) echo \"$S255_NR\";; "
                      "*--user\\ start*) [ \"$S255_START\" = fail ] && exit 1;; esac\nexit 0\n"),
        "journalctl": ("#!/bin/sh\ncase \"$*\" in *CONTAINER_NAME*) [ -n \"$S255_NOFIELD\" ] && exit 0;; esac\n"
                       "printf 'container died 0123456789abcdef (image=x, name=y)\\nfirst line\\nlast words %s\\n' "
                       "\"$S255_SECRET\"\n"),
        "sleep": "#!/bin/sh\nexit 0\n",
    }
    for name, text in tools.items():
        path = os.path.join(bindir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(path, 0o700)  # nosec B103 - a stand-in tool in the part's own temp dir


def _run_install255(state, restarts, addon=_ad255.IW4MADMIN, start="ok", nofield=""):
    """install_sh under bash with stand-ins: (rc, stdout, the tools' log, files under home)."""
    root = os.path.join(_TMP255, "inst-%s-%s-%s-%s-%s" % (addon, state, restarts, start, nofield))
    run, home, bindir = os.path.join(root, "run"), os.path.join(root, "home"), os.path.join(_TMP255, "bin")
    os.makedirs(run, exist_ok=True)
    _stand_ins255(bindir)
    bus = _socket255.socket(_socket255.AF_UNIX)
    bus.bind(os.path.join(run, "bus"))
    log = os.path.join(root, "tools.log")
    files = _ad255.iw4madmin_files() if addon == _ad255.IW4MADMIN else _ad255.build_files(addon)
    sh = _ad255.install_sh("u255", addon, "[Unit]\n", "{}\n", files)
    sh = sh.replace('"/run/user/$(id -u)"', run).replace("/home/u255", home)
    unit = os.path.join(home, ".config", "containers", "systemd", "lgsm-addon-%s.container" % addon)
    try:
        r = _sp255.run(["bash", "-c", sh], input='{"Servers": []}\n', capture_output=True, text=True,  # nosec B603 B607
                       timeout=60, check=False,
                       env={"PATH": bindir + ":/usr/bin:/bin", "S255_LOG": log, "S255_STATE": state,
                            "S255_NR": str(restarts), "S255_SECRET": _RC255, "S255_UNIT": unit,
                            "S255_START": start, "S255_NOFIELD": nofield})
    finally:
        bus.close()
    tools = open(log, encoding="utf-8").read() if os.path.exists(log) else ""
    return r.returncode, r.stdout, tools, home


def _settle255():
    if _shutil255.which("bash") is None or _shutil255.which("base64") is None:
        check("first start: bash and base64 present to run the install's shell", False)
        return
    rc, out, tools, home = _run_install255("failed", 0)
    ok, said, tail = _ad255.install_outcome(out, rc)
    eq("first start: an add-on that is not running after its start is a failure, stopped, with its last lines",
       [rc, ok, said == _ad255._FAIL_MARKS["ADDON_DIED"], "last words" in tail,
        "--user stop lgsm-addon-iw4madmin.service" in tools], [26, False, True, True, True])
    rc, out, tools, _home = _run_install255("active", 1)
    check("first start: an add-on systemd had to restart within the settle time is a failure too",
          rc == 26 and "ADDON_DIED" in out, repr((rc, out[-120:])))
    rc, out, tools, home = _run_install255("active", 0)
    base = os.path.join(home, "panel-addons", "iw4madmin")
    stats = os.path.join(base, "Configuration", "StatsPluginSettings.json")
    settings = os.path.join(base, "Configuration", "IW4MAdminSettings.json")
    eq("first start: running for the whole settle time is installed, with the settings and plugin answers written",
       [rc, out.strip()[-15:], open(settings, encoding="utf-8").read() if os.path.exists(settings) else "",
        os.path.exists(stats), "podman pull" in tools], [0, "ADDON_INSTALLED", '{"Servers": []}\n', True, True])
    unit = os.path.join(home, ".config", "containers", "systemd", "lgsm-addon-iw4madmin.container")
    eq("first start: the unit is written only once the image is there (a user manager coming up can't start it early)",
       ["unit-before-image" in tools, os.path.exists(unit)], [False, True])
    _first_start_tails255()


def _first_start_tails255():
    rc, out, tools, _home = _run_install255("failed", 0, nofield="1")
    tail = _ad255.install_outcome(out, rc)[2]
    eq("first start: the tail is the add-on's own lines, not Podman's event lines",
       ["last words" in tail, "container died" in tail], [True, False])
    rc, out, tools, _home = _run_install255("active", 0, addon=_ad255.B3, start="fail")
    _ok, said, tail = _ad255.install_outcome(out, rc)
    eq("first start: a B3 that never started (no b3.log yet) is stopped and shows its journal's lines",
       [rc, said == _ad255._FAIL_MARKS["ADDON_START_FAILED"], "last words" in tail,
        "--user stop lgsm-addon-b3.service" in tools, "podman build" in tools, "unit-before-image" in tools],
       [25, True, True, True, True, False])


def _host255(probe, install_out="ADDON_INSTALLED\n", install_rc=0, status="", log_text=""):
    """Recorders for the host calls: [(kind, sh or verb, stdin or args)]."""
    calls = []

    def shell(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
        calls.append(("sh", sh, stdin_text))
        if "podman pull" in sh or "podman build" in sh:
            return install_out, "", install_rc
        if "ADDON_REMOVED" in sh:
            return "others=0\nADDON_REMOVED\n", "", 0
        if "games_mp.log" in sh:
            return probe, "", 0
        if "tail -n" in sh:
            return log_text, "", 0
        return status or "os=24.04\npodman=podman version 4.9.3\n", "", 0

    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch_sm("run_privileged", lambda server, verb, args=(), **_k: calls.append(("verb", verb, list(args)))
                 or ("", "", 0))
    _p9_patch(_ra255, "threading", _p9_threading(_P9Thread))
    _p9_patch(_ra255, "step_up_needed", lambda: False)
    _p9_patch(_ra255, "game_account_write_refusal", lambda remote, user, reading=False: None)
    return calls


def _probe255(logdir="serverfiles/main", rcon_line='set rcon_password "%s"' % _RC255, extra="port=\n",
              ids="uid=1004\ngid=1005\n"):
    return ("os=24.04\npodman=podman version 4.9.3\n%slogdir=%s\nrcon.b64=%s\n%s"
            % (ids, logdir, _ad255._b64(rcon_line), extra))


def _installed255(calls):
    """(the install shell, its stdin, the files it writes) from the recorded calls."""
    inst = [c for c in calls if c[0] == "sh" and ("podman pull" in c[1] or "podman build" in c[1])]
    return (inst[0][1], inst[0][2] or "", _puts255(inst[0][1])) if inst else ("", "", {})


def _unit_of255(puts):
    return next((t for p, t in puts.items() if p.endswith(".container")), "")


def _died_route255(ids):
    sid = ids["cod4"]
    tail = _ad255._b64("FTL Failed to initialize, password %s\n" % _RC255)
    _host255(_probe255(extra="ports= 21003\n"), install_out="ADDON_DIED\ntail.b64=%s\n" % tail, install_rc=26)
    _p9_client(P9_ADMIN).post("/api/server/%d/addons/iw4madmin/install" % sid, json={})
    _p9_drain()
    row = _p9_audit("addon_install")
    check("first start (route): an add-on that died after its start is audited as not installed",
          row.success is False and "stopped again within 30 seconds" in row.detail, repr(row.detail))
    st = _p9_client(P9_ADMIN).get("/api/server/%d/addons" % sid).get_json(silent=True) or {}
    a = (st.get("addons") or [{}])[0]
    check("first start (route): the card shows why and the last log lines, the RCON password masked",
          "stopped again" in a.get("error", "") and "FTL Failed" in a.get("tail", "") and _RC255 not in a.get("tail", "x"),
          repr(a)[:300])


# ── 3. IW4MAdmin ────────────────────────────────────────────────────────────────────────────────
def _iw4m255(ids):
    sid = ids["cod4"]
    for splice, want in (("splice=1\n", "pasta:--splice-only,-U,28960"), ("", "pasta:-4,-o,127.0.0.1,-U,28960")):
        calls = _host255(_probe255(extra="ports= 21003\n" + splice))
        r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/iw4madmin/install" % sid, json={"database_id": 999999})
        _p9_drain()
        sh, stdin, puts = _installed255(calls)
        unit = _unit_of255(puts)
        eq("IW4MAdmin install (%s): the unit's network is the locked one the host's pasta allows"
           % ("splice" if splice else "no splice"), (r.status_code, _net_line255(unit)), (202, want))
    settings = _json255.loads(stdin or "{}")
    stats = _json255.loads(next((t for p, t in puts.items() if p.endswith("StatsPluginSettings.json")), "{}"))
    prof = _json255.loads(next((t for p, t in puts.items() if p.endswith("ProfanityDetermentSettings.json")), "{}"))
    eq("IW4MAdmin install: SQLite and local translations, no database asked; anti-cheat and profanity answered off",
       (settings.get("DatabaseProvider"), settings.get("UseLocalTranslations"), "ConnectionString" in settings,
        stats.get("AnticheatConfiguration"), prof.get("EnableProfanityDeterment")),
       ("sqlite", True, False, {"Enable": False}, False))
    eq("IW4MAdmin unit: stops on SIGINT with time to finish, restarts even after a clean exit, page on 127.0.0.1",
       [x in unit for x in ("--stop-signal=SIGINT", "--stop-timeout=30", "Restart=always",
                            "PublishPort=127.0.0.1:21003:1624")], [True] * 4)
    check("IW4MAdmin install: no secret on any command line", _RC255 not in sh)
    eq("IW4MAdmin unit: its own uid and gid, and a kill is never called a clean stop",
       ["User=1004" in unit.splitlines(), "Group=1005" in unit.splitlines(), "SuccessExitStatus" in unit],
       [True, True, False])
    calls = _host255(_probe255(extra="ports= 21003\n", ids="uid=\ngid=1005\n"))
    _p9_client(P9_ADMIN).post("/api/server/%d/addons/iw4madmin/install" % sid, json={})
    _p9_drain()
    row = _p9_audit("addon_install")
    eq("install: an account whose ids can't be read is refused before anything is installed",
       [row.success, _ra255._NO_IDS in row.detail, bool(_installed255(calls)[0])], [False, True, False])


# ── 4. releasing an account ─────────────────────────────────────────────────────────────────────
def _release_helper255(stop_rc, mode="keep", roots=None):
    ran = []

    def run(argv, **_k):
        ran.append(argv)
        if argv[1:2] == ["stop"] and stop_rc is None:
            raise _h255.subprocess.TimeoutExpired(argv, 1)
        return _NS255(returncode=stop_rc if argv[1:2] == ["stop"] else 0, stderr=b"")
    saved = {k: getattr(_h255, k) for k in ("pwd", "subprocess", "resolve", "JOURNAL_ROOTS", "ADDON_TMP_DIRS")}
    try:
        _h255.JOURNAL_ROOTS = tuple(roots[:2]) if roots else (os.path.join(_TMP255, "nojournal"),)
        _h255.ADDON_TMP_DIRS = (os.path.join(_TMP255, "notmp-%d"),)
        _h255.pwd = _NS255(getpwnam=lambda n: _NS255(pw_name=n, pw_uid=4321))
        _h255.subprocess = _NS255(run=run, TimeoutExpired=saved["subprocess"].TimeoutExpired)
        _h255.resolve = lambda prog: prog
        rc = _h255.do_addon_account_release(["cod4server", mode], None)
    finally:
        for k, v in saved.items():
            setattr(_h255, k, v)
    return rc, ran


def _release255():
    want = [["loginctl", "disable-linger", "cod4server"], ["systemctl", "stop", "user@4321.service"],
            ["systemctl", "reset-failed", "user@4321.service"]]
    eq("release (helper): lingering off, the user manager stopped, its failed state cleared; no journal file, no rotation",
       [_release_helper255(0), _release_helper255(0, "forget")], [(0, want), (0, want)])
    eq("release (helper): a manager that does not stop in time is still cleared", _release_helper255(None), (0, want))
    keep = _fake_journal255("hverb-keep", 4321)
    rc, ran = _release_helper255(0, "keep", keep)
    eq("release (helper verb, keep): the account's journal stays whole and nothing rotates",
       (rc, ran, sorted(_left255(keep[:2]))), (0, want, sorted(_ALL255)))
    gone = _fake_journal255("hverb-forget", 4321)
    rc, ran = _release_helper255(0, "forget", gone)
    eq("release (helper verb, forget): rotated once, then the account's journal files go",
       (rc, ran, sorted(_left255(gone[:2]))), (0, want + [["journalctl", "--rotate"]], sorted(_KEPT255)))
    eq("release: the remove route keeps the journal, an uninstall forgets it (both sides take only keep/forget)",
       [_arity255("keep"), _arity255("forget"), _arity255("keep", "x"), _arity255(), _arity255("purge")],
       [False, False, True, True, True])
    _release_remote255()
    _forget255()


def _arity255(*extra):
    """True when the panel's side refuses addon-account-release with these arguments after the account."""
    try:
        _pv255.check_args("addon-account-release", ["cod4server"] + list(extra))
    except ValueError:
        return True
    return False


def _remote_release_run255(tag, mode, archived_only=False):
    """The remote form under bash, its paths moved into a throwaway tree: (rc, stdout, files left, tools' log)."""
    bindir = os.path.join(_TMP255, "rbin")
    log = os.path.join(_TMP255, "rbin-%s.log" % tag)
    os.makedirs(bindir, exist_ok=True)
    for tool in ("loginctl", "systemctl", "journalctl"):
        path = os.path.join(bindir, tool)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\necho "%s $*"\necho "%s $*" >> "$R255_LOG"\n' % (tool, tool))
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(path, 0o700)  # nosec B103 - a stand-in tool in the part's own temp dir
    uid = _pv255.pwd.getpwnam("nobody").pw_uid
    roots = _fake_journal255(tag, uid, archived_only)
    cmd = _pv255.remote_command("addon-account-release", ["nobody", mode])
    tmp_dirs = ("/tmp/podman-run-", "/tmp/containers-user-")  # nosec B108 - the remote form's paths, redirected below
    for real, fake in (("/var/log/journal", roots[0]), ("/run/log/journal", roots[1]),
                       (tmp_dirs[0], roots[2] + "/podman-run-"), (tmp_dirs[1], roots[2] + "/containers-user-")):
        cmd = cmd.replace(real, fake)
    r = _sp255.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=30,  # nosec B603 B607
                   env={"PATH": bindir + ":/usr/bin:/bin", "R255_LOG": log}, check=False)
    return r.returncode, r.stdout, sorted(_left255(roots)), open(log, encoding="utf-8").read() if os.path.exists(log) else ""


def _release_remote255():
    uid = _pv255.pwd.getpwnam("nobody").pw_uid
    head = ("loginctl disable-linger nobody\nlinger=off\nsystemctl stop user@%d.service\n"
            "systemctl reset-failed user@%d.service\nmanager=stopped\n" % (uid, uid))
    rc, out, left, tools = _remote_release_run255("rkeep", "keep")
    eq("release (remote form, keep): the journal stays whole and nothing rotates (a folder the uid doesn't own stays)",
       (rc, out, left, "--rotate" in tools),
       (0, head + "forgotten=0\n", sorted(_ALL255 + ["podman-run-%d" % uid, "containers-user-%d" % uid]), False))
    rc, out, left, tools = _remote_release_run255("rforget", "forget")
    eq("release (remote form, forget): rotated once (an active file), then the uid's journal files go, nothing else",
       (rc, out, left, tools.count("journalctl --rotate")),
       (0, head + "forgotten=3\n", sorted(_KEPT255 + ["podman-run-%d" % uid, "containers-user-%d" % uid]), 1))
    rc, out, left, tools = _remote_release_run255("rarch", "forget", archived_only=True)
    eq("release (remote form, forget): only archived files left: they go, and nothing rotates",
       (out.endswith("forgotten=1\n"), "--rotate" in tools), (True, False))


# What must survive a forget: another uid's journal (a longer number), the system journal, a link.
_KEPT255 = ["user-%s0.journal", "system.journal", "user-link.journal"]
_ALL255 = []


def _fake_journal255(tag, uid, archived_only=False):
    """Two journal roots and a /tmp stand-in, holding the uid's files and ones that must stay."""
    base = os.path.join(_TMP255, tag)
    roots = [os.path.join(base, "var"), os.path.join(base, "run"), os.path.join(base, "tmp")]
    mid = os.path.join(roots[0], "0123456789abcdef0123456789abcdef")
    os.makedirs(mid, exist_ok=True)
    os.makedirs(os.path.join(roots[1], "fedcba9876543210fedcba9876543210"), exist_ok=True)
    names = ["user-%d@00ab-0000000000000001-0005f3a1b2c3d4e5.journal" % uid, "user-%d0.journal" % uid, "system.journal"]
    for name in names + ([] if archived_only else ["user-%d.journal" % uid]):
        open(os.path.join(mid, name), "w").close()
    if not archived_only:
        open(os.path.join(roots[1], "fedcba9876543210fedcba9876543210", "user-%d.journal" % uid), "w").close()
    os.symlink(os.path.join(mid, "system.journal"), os.path.join(mid, "user-link.journal"))
    for d in ("podman-run-%d" % uid, "containers-user-%d" % uid):
        os.makedirs(os.path.join(roots[2], d, "sub"), exist_ok=True)
    global _KEPT255, _ALL255
    _KEPT255 = [k % uid if "%s" in k else k for k in ("user-%s0.journal", "system.journal", "user-link.journal")]
    _ALL255 = _KEPT255 + names[:1] + ([] if archived_only else ["user-%d.journal" % uid] * 2)
    return roots


def _left255(roots):
    return [n for r in roots for _d, _s, files in os.walk(r) for n in files + _s if n not in ("sub",)
            and not _re255.fullmatch(r"[0-9a-f]{32}", n)]


def _forget_run255(tag, uid, forget, archived_only=False):
    roots = _fake_journal255(tag, uid, archived_only)
    saved = {k: getattr(_h255, k) for k in ("subprocess", "resolve", "JOURNAL_ROOTS", "ADDON_TMP_DIRS")}
    ran = []
    try:
        _h255.subprocess = _NS255(run=lambda argv, **_k: ran.append(argv) or _NS255(returncode=0))
        _h255.resolve = lambda prog: prog
        _h255.JOURNAL_ROOTS = tuple(roots[:2])
        _h255.ADDON_TMP_DIRS = (roots[2] + "/podman-run-%d", roots[2] + "/containers-user-%d")
        got = (_h255._addon_forget_account(uid, forget), _h255._addon_forget_account(999, forget))
    finally:
        for k, v in saved.items():
            setattr(_h255, k, v)
    return got, ran, sorted(_left255(roots))


def _forget255():
    uid = os.getuid()
    if uid < _h255.ADDON_FORGET_MIN_UID:
        skip("release (helper): the uid's journal files and its own /tmp folders go", "runs as a uid below 1000 (root)")
        return
    eq("release (helper, forget): rotated once for the active file, then the uid's journal files and its own /tmp "
       "folders go, nothing else; nothing at all for a uid below 1000",
       _forget_run255("hforget", uid, True), ((5, 0), [["journalctl", "--rotate"]], sorted(_KEPT255)))
    got = _forget_run255("hkeep", uid, False)
    eq("release (helper, keep): only its /tmp folders go; the journal stays whole and nothing rotates",
       got, ((2, 0), [], sorted(_ALL255)))
    got = _forget_run255("harch", uid, True, archived_only=True)
    eq("release (helper, forget): only archived files: they go without a rotation", (got[0], got[1]), ((3, 0), []))


# ── 5. B3 ───────────────────────────────────────────────────────────────────────────────────────
def _b3_refusals255(ids):
    sid = ids["cod"]
    calls = _host255(_probe255(".callofduty/main", 'set rconpassword "%s"' % _RC255))
    a = _p9_client(P9_ADMIN)
    got = [a.post("/api/server/%d/addons/b3/install" % sid, json={}).status_code,
           a.post("/api/server/%d/addons/b3/install" % sid, json={"database_id": ids["theirs"]}).status_code]
    check("B3: no database, or another server's, is refused before anything runs", got == [400, 400] and not calls,
          repr((got, calls[:1])))
    calls = _host255(_probe255(".callofduty/main", 'set rconpassword "ab ;cd"'))
    a.post("/api/server/%d/addons/b3/install" % sid, json={"database_id": ids["mine"]})
    _p9_drain()
    row = _p9_audit("addon_install")
    check("B3: an RCON password its ini would cut is refused, audited, and nothing is installed",
          row.success is False and _ad255._B3_RCON_REFUSAL in row.detail and not _installed255(calls)[0],
          repr(row.detail))


def _b3_install255(ids, geolocation, extra="ports=\n"):
    calls = _host255(_probe255(".callofduty/main", 'set rconpassword "%s"' % _RC255, extra))
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/install" % ids["cod"],
                                  json={"database_id": ids["mine"], "geolocation": geolocation})
    _p9_drain()
    return (r.status_code,) + _installed255(calls)


def _b3_local255(ids):
    code, sh, ini, puts = _b3_install255(ids, False)
    unit = _unit_of255(puts)
    name = "gs%d_b3" % ids["cod"]
    eq("B3 install: its database on this host forwarded at 3306, CoD1's log folder read-only, no page, no relay",
       (code, _net_line255(unit), "Volume=/home/codp255/.callofduty/main:/gamelog:ro" in unit, "PublishPort" in unit,
        [p for p in puts if p.endswith(".socket")]),
       (202, "pasta:-4,-o,127.0.0.1,-U,28960,-T,3306:3306", True, False, []))
    eq("B3 install: b3.ini on stdin with the cod parser, its own database and the RCON password; no geolocation",
       ["parser: cod\n" in ini, "database: mysql://%s:%s@127.0.0.1:3306/%s\n" % (name, _DBV255, name) in ini,
        "rcon_password: %s\n" % _RC255 in ini, "geolocation" in ini, "translator" in ini],
       [True, True, True, False, False])
    eq("B3 install: built from the pinned commit and base, no secret on any command line",
       ["podman build" in sh, "B3_COMMIT=%s" % _ad255.B3_COMMIT in sh, _ad255.B3_BASE in sh, _RC255 in sh,
        _DBV255 in sh, sorted(p.rsplit("/", 2)[-2] + "/" + p.rsplit("/", 1)[-1] for p in puts if "/build/" in p)],
       [True, True, True, False, False, ["build/Containerfile", "build/entrypoint.sh", "build/requirements.txt"]])
    eq("B3 unit: SIGTERM stop (no other signal), restarted even after a clean exit, its built image, never pulled",
       ["--stop-signal" in unit, "Restart=always" in unit, "Image=localhost/lgsm-addon-b3:" + _ad255.B3_COMMIT[:12] in unit,
        "Pull=never" in unit], [False, True, True, True])
    eq("B3 unit: runs as the account's own uid and gid (keep-id plus User=/Group=: the image's USER wins otherwise)",
       [x in unit.splitlines() for x in ("UserNS=keep-id", "User=1004", "Group=1005")], [True, True, True])
    eq("B3 unit: a stop waits 30 s and a kill is not excused (the pinned fork commit exits on its own)",
       ["--stop-timeout=30" in unit, any(x.startswith("SuccessExitStatus=") for x in unit.splitlines())],
       [True, False])


def _b3_geo255(ids):
    code, _sh, ini, puts = _b3_install255(ids, True, "ports= 21010\n")
    unit = _unit_of255(puts)
    services = [t for p, t in sorted(puts.items()) if p.endswith(".service")]
    eq("B3 geolocation on: the plugins listed, each service through its own relay, nothing else reachable",
       [code, "geolocation:\n" in ini, "location: @conf/conf/plugin_location.ini" in ini,
        _net_line255(unit).endswith(",-T,3306:3306,-T,443:21010"),
        "--add-host=ipwho.is:127.0.0.1" in unit, "ipapi.co" in unit, len(services),
        [x.rsplit(" ", 1)[-1].strip() for x in services], "Requires=lgsm-addon-b3-geo1.socket" in unit],
       [202, True, True, True, True, False, 1, ["ipwho.is:443"], True])
    check("B3 geolocation on: the audit says so", "geolocation on" in _audit_started255(), _audit_started255())
    _p9_patch(_ra255, "_db_target", lambda r: ("100.70.1.2", 3307))
    code, _sh, ini, puts = _b3_install255(ids, False, "ports= 21012\n")
    unit = _unit_of255(puts)
    db_relay = next((t for p, t in puts.items() if p.endswith("lgsm-addon-b3-db.service")), "")
    eq("B3 with a database on another machine: a relay on this host to that one address, at 3306 inside",
       ["-T,3306:21012" in _net_line255(unit), "systemd-socket-proxyd --exit-idle-time=5min 100.70.1.2:3307" in db_relay,
        "Requires=lgsm-addon-b3-db.socket" in unit], [True, True, True])


def _waw255(ids):
    sid = ids["waw"]
    calls = _host255(_probe255(".codwaw/main", 'set rconpassword "%s"' % _RC255, "ports= 21004\n"))
    _p9_client(P9_ADMIN).post("/api/server/%d/addons/iw4madmin/install" % sid, json={})
    _p9_drain()
    row = _p9_audit("addon_install")
    eq("World at War (route): only rconpassword set: refused with the rename sentence, nothing installed",
       [row.success, _ad255._RCON_RENAME in row.detail, bool(_installed255(calls)[0])], [False, True, False])
    lines = 'set rconpassword "ignored"\nset rcon_password "%s"\n' % _RC255
    calls = _host255(_probe255(".codwaw/main", lines, "ports= 21004\n"))
    _p9_client(P9_ADMIN).post("/api/server/%d/addons/iw4madmin/install" % sid, json={})
    _p9_drain()
    _sh, stdin, puts = _installed255(calls)
    srv = (_json255.loads(stdin or "{}").get("Servers") or [{}])[0]
    eq("World at War (route): its rcon_password is the one IW4MAdmin gets, with WaW's parser and ~/.codwaw's log",
       [srv.get("Password"), srv.get("RConParserVersion"), "Volume=/home/cwp255/.codwaw/main:/gamelog:ro"
        in _unit_of255(puts)], [_RC255, "Call of Duty 5: World at War Parser", True])


def _audit_started255():
    from panel.db.models import AuditLog
    with _p9.app_context():
        r = AuditLog.query.filter(AuditLog.action == "addon_install", AuditLog.detail.like("%started%")).order_by(
            AuditLog.id.desc()).first()
        return r.detail if r is not None else ""


def _b3_pieces255():
    both = 'set rconpassword "old"\nset rcon_password "new"\n'
    eq("RCON: each game reads only its own setting: CoD1 and UO rconpassword, CoD2, CoD4 and WaW rcon_password",
       [_ad255.game_rcon(g, both) for g in ("cod", "coduo", "cod2", "cod4", "codwaw")],
       [("old", ""), ("old", ""), ("new", ""), ("new", ""), ("new", "")])
    eq("RCON: World at War with only rconpassword set (LinuxGSM's default) is told to rename it; none set says nothing",
       [_ad255.game_rcon("codwaw", 'set rconpassword "x"'), _ad255.game_rcon("codwaw", ""),
        _ad255.game_rcon("cod", 'set rcon_password "x"')],
       [("", _ad255._RCON_RENAME), ("", ""), ("", "")])
    check("RCON: United Offensive's config is read from serverfiles/uo",
          "serverfiles/uo/coduoserver.cfg" in _ad255.probe_sh(_ad255.B3, "coduoserver", 4, "coduo", 0))
    eq("log dir: one leading dot is allowed (~/.callofduty/main), ./ and .. are not",
       [_ad255.log_dir("u", ".callofduty/main"), _ad255.log_dir("u", "./x"), _ad255.log_dir("u", ".callofduty/..")],
       ["/home/u/.callofduty/main", "", ""])
    check("B3 log: its own b3.log comes first", "panel-addons/b3/Data/b3.log" in _ad255.logs_sh("u", _ad255.B3))
    find = _re255.search(r"find (.*?) -maxdepth", _ad255.probe_sh(_ad255.B3, "codserver", 4, "cod", 0))
    eq("log search: serverfiles, ~/.callofduty* (CoD1, UO, CoD2) and ~/.cod* (World at War's ~/.codwaw)",
       find.group(1).split() if find else [], ["serverfiles", ".callofduty*", ".cod*"])
    eq("probe: the account's uid and gid are read, and only plain numbers count",
       [_ad255.parse_probe("uid=1004\ngid=1005\n")["ids"], _ad255.parse_probe("uid=0\ngid=0\n")["ids"],
        _ad255.parse_probe("uid=x\ngid=1\n")["ids"]], [(1004, 1005), None, None])


def _probe_run255():
    """probe_sh for a World at War account under bash, in a throwaway home: what parse_probe reads."""
    home = os.path.join(_TMP255, "probe-home")
    for d in ("serverfiles/main", ".codwaw/main"):
        os.makedirs(os.path.join(home, d), exist_ok=True)
    with open(os.path.join(home, "serverfiles", "main", "cwp255.cfg"), "w", encoding="utf-8") as fh:
        fh.write('set sv_hostname "x"\nset rconpassword "pw-a"\nset rcon_password "pw-b"\nset rcon_passwordx "no"\n')
    open(os.path.join(home, ".codwaw", "main", "games_mp.log"), "w").close()
    sh = _ad255.probe_sh(_ad255.IW4MADMIN, "cwp255", 7, "codwaw", 0).replace('cd "$HOME"', "cd %s" % home)
    r = _sp255.run(["bash", "-c", sh], capture_output=True, text=True, timeout=30, check=False,  # nosec B603 B607
                   env={"PATH": "/usr/bin:/bin"})
    return _ad255.parse_probe(r.stdout)


def _probe_bash255():
    p = _probe_run255()
    eq("probe (bash): finds ~/.codwaw's log, and hands over both RCON lines but no look-alike; WaW takes rcon_password",
       [p["logdir"], _ad255.rcon_password(p["rcon_lines"], "rconpassword"), _ad255.rcon_password(p["rcon_lines"]),
        "rcon_passwordx" in p["rcon_lines"], _ad255.game_rcon("codwaw", p["rcon_lines"])],
       [".codwaw/main", "pw-a", "pw-b", False, ("pw-b", "")])


def _b3_build255():
    here = os.path.join(os.path.dirname(_ad255.__file__), "..", "addon_images", "b3")
    cf = open(os.path.join(here, "Containerfile"), encoding="utf-8").read()
    req = open(os.path.join(here, "requirements.txt"), encoding="utf-8").read()
    eq("B3 build: the Containerfile's defaults are the pinned commit and base the install passes",
       [_ad255.B3_COMMIT in _re255.findall(r"^ARG B3_COMMIT=(\S+)", cf, _re255.M),
        _ad255.B3_BASE in _re255.findall(r"^ARG BASE_IMAGE=(\S+)", cf, _re255.M),
        _re255.findall(r"^FROM (\S+)", cf, _re255.M)], [True, True, ["${BASE_IMAGE}", "${BASE_IMAGE}"]])
    lines = cf.splitlines()
    at = {k: next((i for i, x in enumerate(lines) if x.startswith(k)), -1)
          for k in ("COPY entrypoint.sh", "RUN chmod 0755 /opt/b3/entrypoint.sh", "USER 65534")}
    eq("B3 build: the start script is made readable (the panel writes it 0600, COPY keeps that) before USER",
       [at["COPY entrypoint.sh"] < at["RUN chmod 0755 /opt/b3/entrypoint.sh"] < at["USER 65534"],
        at["COPY entrypoint.sh"] >= 0], [True, True])
    check("B3 build: the checkout must be exactly the pinned commit, and pip installs by hash from wheels only",
          'test "$(git rev-parse HEAD)" = "${B3_COMMIT}"' in cf and "--require-hashes" in cf and "--only-binary :all:" in cf)
    pins = _re255.findall(r"^([A-Za-z0-9_.-]+)==\S+ \\\n((?:\s+--hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)", req, _re255.M)
    lines = [x for x in req.splitlines() if _re255.match(r"^[A-Za-z0-9_.-]+==", x)]
    check("B3 build: every dependency is pinned with at least one hash", len(pins) == len(lines) >= 8,
          repr((len(pins), len(lines))))


def _b3_remove255(ids):
    calls = _host255(_probe255())
    r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/remove" % ids["cod"]).get_json(silent=True) or {}
    r2 = _p9_client(P9_ADMIN).post("/api/server/%d/addons/iw4madmin/remove" % ids["cod4"]).get_json(silent=True) or {}
    eq("remove: B3's database is kept; IW4MAdmin's data goes with it (and says so)",
       (r.get("message"), r2.get("message")), (_ra255._REMOVED[True], _ra255._REMOVED[False]))
    check("remove: the add-on's relays go too", "lgsm-addon-b3-*" in _ad255.remove_sh("u", _ad255.B3))
    eq("remove: the last add-on's release keeps the account's journal (keep, never forget)",
       [c[2] for c in calls if c[0] == "verb" and c[1] == "addon-account-release"],
       [["codp255", "keep"], ["cod4p255", "keep"]])


def _run_remove255(other):
    """remove_sh for B3 under bash with stand-ins, in a throwaway home: (rc, stdout, tools' log, home)."""
    home = os.path.join(_TMP255, "rm-%s" % other)
    for d in ("panel-addons/b3/Data", ".cache/containers/x", ".config/containers/systemd", ".config/systemd/user",
              ".config/containers/podman", ".local/share/containers/storage/overlay", "elsewhere/keep"):
        os.makedirs(os.path.join(home, d), exist_ok=True)
    if not os.path.lexists(os.path.join(home, ".config", "cni")):
        os.symlink(os.path.join(home, "elsewhere"), os.path.join(home, ".config", "cni"))
    if other:
        os.makedirs(os.path.join(home, "panel-addons", "iw4madmin"), exist_ok=True)
    log = os.path.join(home, "tools.log")
    bindir = os.path.join(_TMP255, "bin")
    _stand_ins255(bindir)
    sh = _ad255.remove_sh("u255", _ad255.B3).replace("/home/u255", home)
    r = _sp255.run(["bash", "-c", sh], capture_output=True, text=True, timeout=60, check=False,  # nosec B603 B607
                   env={"PATH": bindir + ":/usr/bin:/bin", "S255_LOG": log, "S255_UNIT": "/nonexistent"})
    return r.returncode, r.stdout, open(log, encoding="utf-8").read() if os.path.exists(log) else "", home


def _purge255():
    rc, out, tools, home = _run_remove255(True)
    eq("remove: with another add-on left, Podman's storage stays",
       [rc, "others=1" in out, "system reset" in tools, os.path.isdir(os.path.join(home, ".cache", "containers"))],
       [0, True, False, True])
    rc, out, tools, home = _run_remove255(False)
    eq("remove: the last add-on takes the account's Podman storage, cache and folders with it; a link is not followed",
       [rc, "others=0" in out, "podman system reset -f" in tools,
        [d for d in (".cache/containers", ".config/containers", ".config/systemd", ".local/share/containers")
         if os.path.exists(os.path.join(home, d))], os.path.isdir(os.path.join(home, "elsewhere", "keep")),
        os.path.islink(os.path.join(home, ".config", "cni"))],
       [0, True, True, [], True, True])


def _b3_logs255(ids):
    _host255(_probe255(), log_text="db mysql://x:%s@127.0.0.1\n" % _DBV255)
    log = _p9_client(P9_ADMIN).get("/api/server/%d/addons/b3/logs" % ids["cod"]).get_json(silent=True) or {}
    check("B3 log: read, with the database password masked", "mysql://x:" in log.get("log", "")
          and _DBV255 not in log.get("log", "x"), repr(log)[:200])


def _fixture255():
    ids = {"cod4": _p9_new_server(P9_HOST, "cod4p255", "cod4", 28960, name="p255-cod4"),
           "cod": _p9_new_server(P9_HOST, "codp255", "cod", 28960, name="p255-cod"),
           "other": _p9_new_server(P9_HOST, "cod2p255", "cod2", 28961, name="p255-cod2"),
           "waw": _p9_new_server(P9_HOST, "cwp255", "codwaw", 28962, name="p255-waw")}
    with _p9.app_context():
        mine = _GD255(remote_id=P9_HOST, game_server_id=ids["cod"], name="gs%d_b3" % ids["cod"], secret=_enc255(_DBV255))
        theirs = _GD255(remote_id=P9_HOST, game_server_id=ids["other"], name="gs%d_x" % ids["other"], secret=_enc255("x"))
        _db255.session.add_all([mine, theirs])
        _db255.session.commit()
        ids.update(mine=mine.id, theirs=theirs.id)
    return ids


def _drop255(ids):
    with _p9.app_context():
        for i in (ids["mine"], ids["theirs"]):
            r = _db255.session.get(_GD255, i)
            if r is not None:
                _db255.session.delete(r)
        _db255.session.commit()
    for k in ("cod4", "cod", "other", "waw"):
        _p9_delete_server(ids[k])


def _routes255(ids):
    for step in (_died_route255, _iw4m255, _waw255, _b3_refusals255, _b3_local255, _b3_geo255, _b3_remove255, _b3_logs255):
        _p9_restore_all()
        _p9_arm(who="part255")
        step(ids)


try:
    _lock255()
    _settle255()
    _release255()
    _b3_pieces255()
    _probe_bash255()
    _b3_build255()
    _purge255()
    _ids255 = _fixture255()
    try:
        _routes255(_ids255)
    finally:
        _p9_restore_all()
        _drop255(_ids255)
finally:
    _p9_restore_all()
check("part255: no check reached a real host", len(_P9_TRIPPED) == _trips255, repr(_P9_TRIPPED[_trips255:][:4]))
