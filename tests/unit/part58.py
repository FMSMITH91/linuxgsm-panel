"""Part 58 of the unit suite: the third 2026-10-11 review's fixes (builder B).

Game files, bots, the debug report, the privileged helper and routes:

* Console player list: the capture reads only what the pane printed after the `status`/`list`
  send (a slow reply is unknown, never the previous table), and a valve reply caught part-way is
  unknown. The capture's start row is worked out in a real bash against a stand-in tmux.
* Persistent bans find the server cfg by the game account's home path, not `~`.
* Bots: `!connect <markdown>` is not echoed back as markdown. The Refresh reason names the file
  that refresh fetches, not an older failure for another distro.
* Debug report: a localized journal prefix does not print sudo's "(command continued)" argv
  tail; the report's reads run in the C locale; pkexec/doas command lines are cut; the Funnel
  findings use the bound port and say nothing about a config.json that was not read.
* Helper: a later rule taking a root grant back is read item by item, with each item's Runas
  (and group Runas that hold root); a file included twice is applied twice. Remote content verbs
  run as the content account.
* Routes: every request flag is a JSON boolean or a 400 ("false" is not yes); the install's GMod
  content step says when it did not happen.

HOW IT RUNS. On part12's Flask app and stubs, as part55 does: host commands run in a REAL bash
over a throwaway home; nothing reaches a transport.
"""
import contextlib as _ctx58
import io as _io58
import os
import pwd as _pwd58
import shutil as _shutil58
import subprocess as _sp58  # nosec B404 - runs bash on the commands this part's code builds
import tarfile as _tar58
import tempfile as _tf58
import time as _time58
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper
from unit.part12 import (_P9_TRIPPED, _p9, _p9_client, _p9_core, _p9_json, _p9_ms, _p9_patch,
                         _p9_restore_all, _p9_sd, _p9_sf, _p9_so, _p9_trip, _p9_ts)
from panel.db.models import GameServer, RemoteServer, User, db
from panel.ops.debug_report import _base as _base58
from panel.ops.debug_report import logs as _logs58
from panel.ops.debug_report import network as _nw58
from panel.ops.ssh_manager import files as _files58
from panel.ops.ssh_manager import game as _game58
from panel.routes import route_helpers as _rh58
from panel.security import auth as _auth58
from panel.security import privileged as _priv58
from panel.services import lgsm_data as _lgd58
from panel.services import monitoring as _mon58
from panel.services.bots import commands as _botcmd58

_TRIP58_START = len(_P9_TRIPPED)
_CAPTURE58, _SEND58 = _game58.capture_console, _p9_core.send_console_command   # before any stub
_USER58 = "r13b58"
_HOME58 = os.path.realpath(_tf58.mkdtemp(prefix="lgsm-unit-p58-home-"))
_BIN58 = os.path.realpath(_tf58.mkdtemp(prefix="lgsm-unit-p58-bin-"))
_TMUX58 = os.path.join(_BIN58, "tmuxdir")       # stands in for /tmp/tmux-<uid> (_bash58)
_mine58 = {"hosts": [], "servers": [], "users": []}


def _bash58(server, user, sh, timeout=30, selfname=None, scope=False):
    """Run shell_as_game_user's command in a real bash.

    /home/<account> points at the throwaway home, and the stand-in tools are first on PATH.
    """
    env = dict(os.environ, PATH=_BIN58 + os.pathsep + os.environ.get("PATH", ""))
    sh = sh.replace("/home/" + _USER58, _HOME58).replace("D=/tmp/tmux-$(id -u)", "D=" + _TMUX58)  # nosec B108 - the text replaced, not a path used
    p = _sp58.run(["bash", "-c", sh],  # nosec B603 B607 - bash on this part's own command
                  capture_output=True, text=True, timeout=60, check=False, env=env)
    return p.stdout, p.stderr, p.returncode


def _tool58(name, body):
    path = os.path.join(_BIN58, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/bash\n" + body)
    os.chmod(path, 0o755)  # nosec B103 - a stand-in tool in this part's own temp dir


def _arm58():
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part58's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_core, "run_command", _p9_trip("run_command"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9_core, "shell_as_game_user", _bash58)


def _setup58():
    with _p9.app_context():
        r = RemoteServer(name="p58-host", host="192.0.2.158", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p58-" + _USER58, short_name=_USER58, game_type="csgo",
                        port=27558, installed=True, status="offline")
        admin = User(username="p58_admin", password_hash=_auth58.hash_password("Str0ng!passw0rd-p58"),
                     display_name="p58 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gs, admin])
        db.session.commit()
        _mine58["hosts"].append(r.id)
        _mine58["servers"].append(gs.id)
        _mine58["users"].append(admin.id)
        return r.id, gs.id, admin.id


def _cleanup58():
    with _p9.app_context():
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine58[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()
    _shutil58.rmtree(_HOME58, ignore_errors=True)
    _shutil58.rmtree(_BIN58, ignore_errors=True)


# ── A04: the player list reads only the reply to its own send ───────────────────────────────────
_OLD58 = ('hostname: p58\nplayers : 1 humans, 0 bots (24 max)\n'
          '# userid name uniqueid connected ping loss state\n'
          '#  2 "Ghost" STEAM_0:1:5 01:02 40 0 active\n')


def _player_reply58():
    sent, since = [], []
    replies = {"pane": ""}
    _p9_patch(_p9_core, "send_console_command", lambda *a, **k: (
        sent.append(k.get("mark")), ("PANE_MARK 1200 17\n", "", 0))[1])
    _p9_patch(_game58, "capture_console", lambda *a, **k: (
        since.append(k.get("since")), (replies["pane"], "", 0))[1])
    _p9_patch(_game58, "time", NS(sleep=lambda s: None))
    replies["pane"] = "status\n"                          # the send landed; no reply printed yet
    slow = _game58.console_player_list(None, _USER58, "gmod", selfname="gmodserver")
    check("players: a `status` whose reply has not been printed yet reads as unknown, not as the "
          "pane's previous table (and the capture starts where the send was typed)",
          slow is None and sent == [True] and since == [(1200, 17)], repr((slow, sent, since)))
    replies["pane"] = ("status\nhostname: p58\nplayers : 3 humans, 0 bots (24 max)\n"
                       "# userid name uniqueid connected ping loss state\n"
                       '#  2 "Ann" STEAM_0:1:5 01:02 40 0 active\n')
    part = _game58.console_player_list(None, _USER58, "gmod", selfname="gmodserver")
    check("players: a valve reply caught part-way (1 row of the 3 its `players :` line counts) "
          "is unknown, not a shorter list", part is None, repr(part))
    replies["pane"] = "status\n" + _OLD58
    whole = _game58.console_player_list(None, _USER58, "gmod", selfname="gmodserver")
    check("players: ...a whole reply still parses (control)",
          [p["name"] for p in whole or []] == ["Ghost"], repr(whole))
    _p9_patch(_p9_core, "send_console_command", lambda *a, **k: ("", "", 0))
    nomark = _game58.console_player_list(None, _USER58, "gmod", selfname="gmodserver")
    check("players: a send that did not say where the pane stood is unknown (no capture to trust)",
          nomark is None, repr(nomark))


def _capture_since58():
    # The stand-in tmux: list one live socket, answer `display -p` from TMUX58_DISPLAY, and print
    # the -S value capture-pane was given.
    os.makedirs(_TMUX58, exist_ok=True)
    sock = os.path.join(_TMUX58, "gmod58srv-zz")
    open(sock, "w").close()
    try:
        _tool58("tmux", 'case " $* " in\n'
                        '  *" has-session "*) exit 0;;\n'
                        '  *" display "*) if [ -n "${TMUX58_DISPLAY+x}" ]; then echo "$TMUX58_DISPLAY"; else\n'
                        '      f="${@: -1}"; f=${f//"#{history_size}"/1200}; echo "${f//"#{cursor_y}"/17}"; fi;;\n'
                        '  *" capture-pane "*) while [ $# -gt 0 ]; do [ "$1" = -S ] && echo "S=$2"; shift; done;;\n'
                        'esac\n')
        got = {}
        for tag, disp in (("grew", "1210 2000"), ("trimmed", "1090 2000"), ("unread", "")):
            os.environ["TMUX58_DISPLAY"] = disp
            out, _e, rc = _CAPTURE58(None, _USER58, selfname="gmod58srv", since=(1200, 17))
            got[tag] = (out.strip(), rc)
        check("capture since the send: the row it marked, counted from the pane's history now "
              "(10 rows scrolled in: -S 7), less tmux's 200-row trim when the history went down "
              "(-S -73), and no capture at all when the pane could not be read",
              got == {"grew": ("S=7", 0), "trimmed": ("S=-73", 0), "unread": ("", 4)}, repr(got))
        os.environ.pop("TMUX58_DISPLAY", None)        # the stand-in now fills tmux's own format
        out, _e, rc = _SEND58(None, _USER58, "status", selfname="gmod58srv", mark=True)
        check("send with mark: prints where the pane stood, in the same round trip as the send",
              rc == 0 and out == "PANE_MARK 1200 17\n", repr((out, rc)))
    finally:
        os.environ.pop("TMUX58_DISPLAY", None)
        os.unlink(sock)
        os.unlink(os.path.join(_BIN58, "tmux"))


def _persistent_bans58():
    cfg = os.path.join(_HOME58, "serverfiles", "csgo", "cfg", "csgoserver.cfg")
    os.makedirs(os.path.dirname(cfg), exist_ok=True)
    with open(cfg, "w", encoding="utf-8") as fh:
        fh.write("hostname x\n")
    _p9_patch(_files58, "lgsm_get_values", lambda *a, **k: {"servercfg": "${selfname}.cfg"})
    ok = _game58.ensure_persistent_bans(None, _USER58, "csgoserver")
    with open(cfg, encoding="utf-8") as fh:
        text = fh.read()
    check("persistent bans: the server cfg is found under the game account's home by its path "
          "(not `~`, which is the caller's HOME where sudo keeps it) and gets the exec line",
          ok is True and "exec banned_user.cfg" in text, repr((ok, text)))


def _console_slots58():
    _p9_patch(_mon58, "sm_game_engine", lambda gt: "valve")
    _p9_patch(_mon58, "_server_max_config", lambda gs: 24)
    _p9_patch(_mon58, "sm_console_status", lambda *a, **k: (None, None))
    gs = NS(remote=None, short_name=_USER58, game_type="gmod", lgsm_name="gmodserver")
    unread = _mon58._server_slots(gs, allow_console=True, primary=(None, None, None))
    _p9_patch(_mon58, "sm_console_status", lambda *a, **k: ([], "x"))
    empty = _mon58._server_slots(gs, allow_console=True, primary=(None, None, None))
    check("player count: a console read that failed is no count, not 0 players; an empty table "
          "is 0 (control)", unread[0] is None and empty[0] == 0, repr((unread, empty)))


# ── live regression from #416: a backup LinuxGSM called failed while its archive is whole ──────
# LinuxGSM v26.3.0 on the owner's host: the FAIL below, then "Backup created" and exit 0, and the
# archive complete (1.2G, the size of the earlier ones). #416's rule took the FAIL text alone as
# proof and deleted that day's archives for two servers.
_SELF58 = "csgoserver"
_BKDIR58 = os.path.join("lgsm", "backup")
_V26FAIL58 = ("[ FAIL ] Backup %s: Problem identifying the previous backup directory for exclusion.\n"
              "BACKUP: FAIL: Problem identifying the previous backup directory for exclusion\n"
              "[  OK  ] Backup %s: Completed: NAME, total size 1.2G\n"
              "PASS: Backup created: NAME, total size 1.2G\n" % (_SELF58, _SELF58))
_OLDBK58 = ["%s-2026-01-0%d-000000.tar.gz" % (_SELF58, d) for d in (1, 2, 3, 4)]


def _tgz58(path, truncate=False):
    """A real .tar.gz at `path` (random bytes, so it does not compress away); cut mid-stream."""
    src = os.path.join(_BIN58, "bksrc")
    os.makedirs(src, exist_ok=True)
    for i in range(4):
        with open(os.path.join(src, "f%d.bin" % i), "wb") as fh:
            fh.write(os.urandom(16384))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _tar58.open(path, "w:gz") as tf:
        tf.add(src, arcname="serverfiles")
    if truncate:
        with open(path, "r+b") as fh:
            fh.truncate(os.path.getsize(path) // 2)


def _backup58(rc, out, truncate=False):
    """run_game_backup over the throwaway home, LinuxGSM standing in: (result, name, listing)."""
    bk = os.path.join(_HOME58, _BKDIR58)
    _shutil58.rmtree(bk, ignore_errors=True)
    for i, n in enumerate(_OLDBK58):
        _tgz58(os.path.join(bk, n))
        os.utime(os.path.join(bk, n), (_time58.time() - 86400 * (10 - i),) * 2)
    name = "%s-%s.tar.gz" % (_SELF58, _time58.strftime("%Y-%m-%d-%H%M%S"))

    def _run(server, user, action, **_k):
        _tgz58(os.path.join(bk, name), truncate)
        return out.replace("NAME", name), "", rc
    _p9_patch(_p9_core, "run_as_game_user", _run)
    # The disk checks before the run are part49's subject; here there is room.
    _p9_patch(_game58.cron, "_ensure_backup_headroom", lambda *a, **k: "")
    _p9_patch(_game58.cron, "backup_disk_info", lambda *a, **k: {"free": 0, "total": 0})
    res = _game58.run_game_backup(NS(id=58), _USER58, _SELF58, keep=3, force=True)
    return res, name, sorted(os.listdir(bk))


def _backup_kept58():
    res, name, ls = _backup58(0, _V26FAIL58)
    check("backup: LinuxGSM's FAIL line with exit 0 and a WHOLE archive keeps the archive (read to "
          "the end first) and is a backup with LinuxGSM's line as a warning",
          res[0] is True and name in ls and "Problem identifying the previous backup" in res[1]
          and "reads to the end" in res[1], repr((res, ls)))
    check("backup: ...and the old backups are pruned to keep=3 as after any backup",
          ls == sorted(_OLDBK58[2:] + [name]), repr(ls))
    res, name, ls = _backup58(1, "[ FAIL ] Backup %s: Starting backup\n" % _SELF58)
    check("backup: a run that exited 1 with a whole archive (a later step failed) keeps it, and "
          "says why", res[0] is False and name in ls and "reads to the end, so it was kept" in res[1],
          repr((res, ls)))


def _backup_removed58():
    res, name, ls = _backup58(0, _V26FAIL58, truncate=True)
    check("backup: the same FAIL lines over an archive cut mid-stream still remove it, and nothing "
          "old is pruned", res[0] is False and name not in ls and all(o in ls for o in _OLDBK58)
          and "Removed the partial archive" in res[1], repr((res, ls)))
    _tool58("timeout", "exit 124\n")         # the archive read runs out of time
    try:
        res, name, ls = _backup58(0, _V26FAIL58, truncate=True)
    finally:
        os.unlink(os.path.join(_BIN58, "timeout"))
    check("backup: an archive whose read timed out is not taken as broken: kept, nothing pruned",
          res[0] is False and name in ls and all(o in ls for o in _OLDBK58)
          and "Removed" not in res[1], repr((res, ls)))


# ── A04: the bots and the Refresh reason ────────────────────────────────────────────────────────
def _connect_echo58():
    with _p9.app_context():
        _gs, err = _botcmd58._find_server("[Session expired](https://evil.example/x)")
    echoed = (err or "").split("'")[1] if (err or "").count("'") >= 2 else None
    check("bots: an unmatched server name is echoed without markdown (no masked link in the "
          "bot's own message)", echoed is not None and not any(c in echoed for c in "[]()/:"),
          repr(err))


def _refresh_reason58():
    saved = dict(_lgd58._last_error)
    try:
        _lgd58._last_error.clear()
        _lgd58._last_error.update({"debian-12.csv": "HTTPError", _lgd58.DEPS: "URLError"})
        reason = _lgd58.status()["reason"]
    finally:
        _lgd58._last_error.clear()
        _lgd58._last_error.update(saved)
    check("lgsm data: the Refresh reason names the package list refresh fetches, not an older "
          "failure for another distro's", reason == "%s: URLError" % _lgd58.DEPS, repr(reason))


# ── A06: what the debug report prints ───────────────────────────────────────────────────────────
def _localized_continued58():
    lines = ["oct. 11 10:00:00 h sudo[1]:      bob : (command continued) -pS3cretPass2",
             "Mär 11 10:00:00 h sudo[1]:      bob : (command continued) -pS3cretPass3",
             "Oct 11 10:00:00 h pkexec[2]: bob: Executing command [USER=root] [TTY=pts/0] "
             "[CWD=/home/bob] [COMMAND=/usr/bin/mysql -u root -pS3cretPass4]",
             "Oct 11 10:00:00 h doas[3]: bob ran command mysql -pS3cretPass5 as root from /home/bob"]
    kept, _v, _s = _logs58._split_priv(lines)
    text = "\n".join(kept)
    check("debug report: a sudo continuation under a localized date prefix is dropped, and a "
          "pkexec / doas command line is kept without its argv",
          len(kept) == 2 and "S3cret" not in text and "pkexec[2]" in text and "doas[3]" in text,
          repr(kept))
    old = {k: os.environ.get(k) for k in ("LANG", "LC_ALL", "LANGUAGE")}
    os.environ.update(LANG="fr_FR.UTF-8", LC_ALL="fr_FR.UTF-8", LANGUAGE="fr")
    try:
        out, _e, _rc = _p9_so._debug_run(["bash", "-c", 'echo "$LC_ALL $LANG ${LANGUAGE-unset}"'])
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    check("debug report: its reads (journalctl among them) run in the C locale, whatever the "
          "service inherited", out.strip() == "C.UTF-8 C.UTF-8 unset", repr(out))


def _funnel_port58():
    ports = []
    _p9_patch(_p9_ts, "shared_funnel_apps", lambda sc, port, use: (ports.append(port), ["other"])[1])
    _p9_patch(_nw58, "_load_cfg", lambda: ({"port": 5000, "tailscale_use_funnel": False}, True))
    ctx = NS(app=NS(config={"BOOT_PORT": 5001}))
    v = {"backend_state": "Running", "serve_services": [], "funnel_enabled": True}
    res = _base58.Result()
    _nw58._tailscale_lines(ctx, res, {}, ("ok", ("ok", v)))
    shared = [f for f in res.findings if "whole :443 listener" in repr(f)]
    check("debug report: the shared-Funnel finding is looked for on the port the panel is bound "
          "to, not config.json's (a restart pending)", ports == [5001] and len(shared) == 1,
          repr((ports, res.findings)))
    _p9_patch(_nw58, "_load_cfg", lambda: ({}, False))
    res = _base58.Result()
    _nw58._tailscale_lines(ctx, res, {}, ("ok", ("ok", v)))
    said = " | ".join(repr(f) for f in res.findings)
    check("debug report: with config.json unreadable, Funnel on is not blamed on a config value "
          "nobody read", "config says off" not in said and "off in the panel's config" not in said
          and "could not be read" in said, said)


def _funnel_facts58():
    seen = []
    _p9_patch(_p9_ts, "get_tailscale_info", lambda *a, **k: NS(serve_config={}, serve_unreadable=False))
    _p9_patch(_p9_ts, "panel_funnelled", lambda sc, port: (seen.append(port), port == 5002)[1])
    _p9_patch(_p9_ts, "shared_funnel_apps", lambda sc, port, use: (seen.append(port), [])[1])
    saved = _p9.config.get("BOOT_PORT")
    _p9.config["BOOT_PORT"] = 5002
    cfg = {"tailscale_setup_done": True, "port": 5000}
    try:
        with _p9.app_context():
            facts = _p9_ts.panel_funnel_facts(cfg)
            maybe = _rh58._r12a_funnel_maybe(cfg)
    finally:
        if saved is None:
            _p9.config.pop("BOOT_PORT", None)
        else:
            _p9.config["BOOT_PORT"] = saved
    check("tailscale: with a port change pending, 'reachable from the internet' asks the bound port "
          "too — the pages' facts and the setup wizard's 'only your devices' test",
          facts["funnelled"] is True and maybe is True and 5000 in seen and 5002 in seen,
          repr((facts, maybe, seen)))


# ── A07: who reaches root, as the helper reads sudoers ──────────────────────────────────────────
def _reach58():
    tmp = _tf58.mkdtemp(prefix="lgsm-unit-p58-sudo-")
    caller = _pwd58.getpwuid(os.getuid()).pw_name
    saved = (_helper.SUDOERS_FILE, _helper.SUDOERS_DIR, _helper._groups_of)
    try:
        main = os.path.join(tmp, "sudoers")
        ddir = os.path.join(tmp, "sudoers.d")
        os.makedirs(ddir)
        _helper.SUDOERS_FILE, _helper.SUDOERS_DIR = main, ddir
        _helper._groups_of = lambda _n: set()

        def reach(main_text, files):
            with open(main, "w", encoding="utf-8") as fh:
                fh.write(main_text.replace("@DDIR@", ddir))
            for n in os.listdir(ddir):
                os.unlink(os.path.join(ddir, n))
            for n, t in files.items():
                with open(os.path.join(ddir, n), "w", encoding="utf-8") as fh:
                    fh.write(t)
            with _ctx58.redirect_stderr(_io58.StringIO()):
                return _helper._caller_reaches_root(caller)

        grant = "%s ALL=(ALL) NOPASSWD: ALL\n" % caller
        inc = "@includedir @DDIR@\n"
        got = {k: reach(grant + (r % caller), {}) for k, r in (
            ("tag mid-list", "%s ALL=(ALL) NOPASSWD: /usr/bin/true, PASSWD: ALL\n"),
            ("second Runas", "%s ALL=(nobody) NOPASSWD: ALL, (root) PASSWD: ALL\n"),
            ("%root", "%s ALL=(%%root) PASSWD: ALL\n"),
            ("%#0", "%s ALL=(%%#0) PASSWD: ALL\n"))}
        got["install.sh layout"] = reach(inc, {"90-cloud": grant, "linuxgsm-panel":
                                               "%s ALL=(root) NOPASSWD: /usr/local/lib/x\n"
                                               "%s ALL=(%%lgsmpanel-games) NOPASSWD: ALL\n"
                                               % (caller, caller)})
        check("helper: a later rule that leaves every root command asking a password takes a "
              "NOPASSWD grant back — a tag mid-list, a second Runas, a Runas group root is in — "
              "while install.sh's own layout does not (control)",
              got == {"tag mid-list": False, "second Runas": False, "%root": False, "%#0": False,
                      "install.sh layout": True}, repr(got))
        twice = reach("@include @DDIR@/zzpw\n" + inc, {"10grant": grant,
                                                      "zzpw": "%s ALL=(ALL) PASSWD: ALL\n" % caller})
        cycle = reach(grant + "@include %s\n" % main, {})
        once = reach(inc, {"10grant": grant})
        check("helper: a file included twice is applied twice, as sudo does (its later PASSWD "
              "wins), and an include cycle is unreadable; one grant is root (control)",
              (twice, cycle, once) == (False, False, True), repr((twice, cycle, once)))
    finally:
        (_helper.SUDOERS_FILE, _helper.SUDOERS_DIR, _helper._groups_of) = saved
        _shutil58.rmtree(tmp, ignore_errors=True)


def _remote_content58():
    mk = _priv58.remote_command("content-dir-create", ["gmodcontent"])
    check("remote content-dir-create: made AS the content account (root's install -d followed a "
          "link at ~/serverfiles and chowned its target)",
          mk.startswith("runuser -u gmodcontent -- mkdir ") and "install" not in mk
          and " && runuser -u gmodcontent -- chmod 700 " in mk, mk)
    # Stand-ins: `id` knows the accounts in ACCOUNTS58, `runuser` runs the command as this process
    # (logging the account) unless the account is in BROKEN58.
    log = os.path.join(_BIN58, "runuser.log")
    _tool58("id", '[ "$1" = -u ] && shift; [ "$1" = -- ] && shift\n'
                  'case " $ACCOUNTS58 " in *" $1 "*) echo 1000;; *) exit 1;; esac\n')
    _tool58("runuser", 'u=$2; shift 3; echo "$u" >> ' + log + '\n'
                       'case " $BROKEN58 " in *" $u "*) exit 1;; esac\nexec "$@"\n')
    os.makedirs(os.path.join(_HOME58, "gm", "serverfiles", "cstrike"), exist_ok=True)
    env = dict(os.environ, PATH=_BIN58 + os.pathsep + os.environ.get("PATH", ""),
               ACCOUNTS58="gm broken", BROKEN58="broken")
    rcs = {}
    for tag, user, game in (("present", "gm", "cstrike"), ("absent", "gm", "tf"),
                            ("no account", "ghost", "cstrike"), ("cannot ask", "broken", "cstrike")):
        sh = _priv58.remote_command("content-game-present", [user, game]).replace(
            "/home/", _HOME58 + "/")
        rcs[tag] = _sp58.run(["bash", "-c", sh], env=env, capture_output=True, check=False).returncode  # nosec B603 B607 - bash on the rendered verb
    asked = []
    if os.path.exists(log):                 # no log at all: nothing was asked as an account
        with open(log, encoding="utf-8") as fh:
            asked = sorted(set(fh.read().split()))
    check("remote content-game-present: asked AS the account — present 0, absent 1, no account 1, "
          "and 2 (unknown) when it cannot be run as the account",
          rcs == {"present": 0, "absent": 1, "no account": 1, "cannot ask": 2}
          and asked == ["broken", "gm"], repr((rcs, asked)))
    sc = _priv58.remote_command("content-scan", ["cstrike"])
    check("remote content-scan: each home looked at as its own account, uid 0 and no-account "
          "entries skipped", 'runuser -u "$u" -- test -d "$d/$g"' in sc and '[ "$i" = 0 ]' in sc
          and "[ -d" not in sc, sc)


# ── A08: request flags, and the GMod content step ───────────────────────────────────────────────
def _said58(resp):
    """A JSON answer's message, or its error (the log-timestamps switch answers with `error`)."""
    body = _p9_json(resp) or {}
    return body.get("message") or body.get("error") or ""


def _flags58(client, rid, sid):
    calls = []
    _p9_patch(_p9_sd, "set_daily_restart", lambda *a, **k: (calls.append(a[5]), (True, ""))[1])
    _p9_patch(_p9_sd, "_host_timezone_cached", lambda remote: None)
    posts = {
        "daily-restart": ("/api/server/%d/daily-restart" % sid, "enabled"),
        "notify-empty": ("/api/server/%d/notify-empty" % sid, "enabled"),
        "panel whitelist": ("/api/panel/security/whitelist", "remove"),
        "panel block": ("/api/panel/security/block", "unblock"),
        "panel autoblock": ("/api/panel/security/autoblock", "enabled"),
        "remote whitelist": ("/api/remote/%d/security/whitelist" % rid, "remove"),
        "remote block": ("/api/remote/%d/security/block" % rid, "unblock"),
        "remote autoblock": ("/api/remote/%d/security/autoblock" % rid, "enabled"),
        "game backup": ("/api/panel/backup/game/%d" % sid, "force"),
        "log timestamps": ("/api/server/%d/log-timestamps" % sid, "enabled"),
    }
    got, said = {}, {}
    for tag, (url, key) in posts.items():
        r = client.post(url, json={"ip": "198.51.100.58", key: "false"})
        got[tag] = r.status_code
        said[tag] = _said58(r)
    check("routes: a switch posted as the string \"false\" is refused (400), not read as yes — "
          "daily restart, notify-empty, whitelist remove, block/unblock, auto-block, backup force, "
          "log timestamps", got == {t: 400 for t in posts} and calls == []
          and all("must be true or false" in m for m in said.values()), repr((got, calls, said)))
    _flags_control58(client, sid, calls)


def _flags_control58(client, sid, calls):
    r1 = client.post("/api/server/%d/daily-restart" % sid, json={"enabled": False})
    r2 = client.post("/api/server/%d/notify-empty" % sid, json={"enabled": True})
    check("routes: ...while a JSON boolean still works (control)",
          r1.status_code == 200 and calls == [False] and r2.status_code == 200
          and _p9_json(r2).get("enabled") is True, repr((r1.status_code, r2.status_code, calls)))


def _content_note58():
    finished = []
    job = NS(short_name="gm58", lgsm_name="gmodserver", game_type="gmod",
             content_games=["cstrike"], p=lambda *a, **k: None,
             finish=lambda msg, warn=False: finished.append((msg, warn)))
    for name in ("_configure_server", "_open_game_ports", "_seed_scpsl_port_config",
                 "_enable_autostart", "_reopen_runtime_ports"):
        _p9_patch(_p9_ms, name, lambda *a, **k: (None, None))
    _p9_patch(_p9_ms, "_start_and_verify", lambda *a, **k: (True, 0, ""))
    audits = []
    _p9_patch(_p9_ms, "log_action", lambda *a, **k: audits.append(k.get("detail")))
    _p9_sf._claim_gmod_content_host(-58)          # a Content-card job is running on this host
    try:
        _p9_ms._configure_and_start(job, NS(name="p58-host", id=-58), NS(name="gm58", port=27058))
    finally:
        _p9_sf._release_gmod_content_host(-58)
    check("gmod install: a content step skipped (another content job on the host) is said in the "
          "install's last word, as a warning, and in its audit entry",
          len(finished) == 1 and finished[0][1] is True and "Content card" in finished[0][0]
          and audits and "gmod content" in (audits[-1] or ""), repr((finished, audits)))


try:
    _arm58()
    _R58, _S58, _ADMIN58 = _setup58()
    _A58 = _p9_client(_ADMIN58)
    _player_reply58()
    _capture_since58()
    _persistent_bans58()
    _console_slots58()
    _backup_kept58()
    _backup_removed58()
    _connect_echo58()
    _refresh_reason58()
    _localized_continued58()
    _funnel_port58()
    _funnel_facts58()
    _reach58()
    _remote_content58()
    _flags58(_A58, _R58, _S58)
    _content_note58()
finally:
    _p9_restore_all()
    _cleanup58()

check("part58: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP58_START, repr(_P9_TRIPPED[_TRIP58_START:][:6]))
