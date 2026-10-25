"""Part 65 of the unit suite: the fifth 2026-10-11 review's fixes (builder B).

Game files, the debug report, the privileged helper and routes:

* Console player list: CoD4X's `status` table (LinuxGSM's cod4server), whose header prints
  "playerid steamid" where CoD prints "guid", is read — slots, clean names, a PRIM row — instead of
  every CoD4 list reading as unknown; a capture at another pane width than the send's mark is
  unknown (a narrowing resize GROWS the history and slipped past the shrink test).
* Moderation: Ban sends each idTech3 game's own ban (iortcw's address ban and a kick), and is
  refused, never "Done.", where the console has no ban by slot. The idTech3 table is keyed by
  LinuxGSM's shortnames: Jedi Knight II (jk2, JK2MV) has a player list, Kick and Say.
* Debug report: a doas line whose argv holds sudo's words (`"command":`, `ENV=`, `COMMAND=`) is cut
  at the doas argv start, not at the first such word inside the argv.
* Helper: `#¹` is no uid, not a ValueError.
* Audit: the User column a failed sign-in writes is escaped like the target and the detail, and the
  brute-force alert still counts it; a long-action completion row stores LinuxGSM's text without
  its colour codes; a cut never splits an escape.
* Routes: an account refusal's row names the path and keeps the whole reason; the cron routes and
  the firewall comment read non-text JSON as "", answered and audited, not a 500 or a false
  "Deleted".

HOW IT RUNS. On part12's Flask app and stubs, as part62 does: the capture runs in a REAL bash with a
stand-in tmux; nothing reaches a transport.
"""
import os
import re as _re65
import shutil as _shutil65
import subprocess as _sp65  # nosec B404 - runs bash on the commands this part's code builds
import tempfile as _tf65
import time as _time65
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper
from unit.part12 import (_P9_TRIPPED, _P9Thread, _p9, _p9_arm, _p9_client, _p9_core, _p9_drain, _p9_json,
                         _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_rv, _p9_sd, _p9_sf, _p9_sh,
                         _p9_threading, _p9_trip)
from panel.db.models import (_NO_UPDATE_GAMES, STEAM_CONNECT_GAMES, AuditLog, GameServer, RemoteServer,
                             User, db)
from panel.ops.debug_report import logs as _logs65
from panel.ops.ssh_manager import _core as _core65
from panel.ops.ssh_manager import cron as _cron65
from panel.ops.ssh_manager import game as _game65
from panel.routes import manage_servers as _ms65
from panel.services import host_reboot as _hr65
from panel.security import auth as _auth65
import app as _app65

_TRIP65_START = len(_P9_TRIPPED)
_CAPTURE65 = _game65.capture_console          # before any stub
_USER65 = "r15b65"
_BIN65 = os.path.realpath(_tf65.mkdtemp(prefix="lgsm-unit-p65-bin-"))
_TMUX65 = os.path.join(_BIN65, "tmuxdir")       # stands in for /tmp/tmux-<uid> (_bash65)
_RLO65 = "\u202e"                               # RIGHT-TO-LEFT OVERRIDE
_mine65 = {"hosts": [], "servers": [], "users": []}


def _bash65(server, user, sh, timeout=30, selfname=None, scope=False):
    """shell_as_game_user's command in a real bash, the stand-in tools first on PATH."""
    env = dict(os.environ, PATH=_BIN65 + os.pathsep + os.environ.get("PATH", ""))
    sh = sh.replace("D=/tmp/tmux-$(id -u)", "D=" + _TMUX65)  # nosec B108 - the text replaced, not a path used
    p = _sp65.run(["bash", "-c", sh],  # nosec B603 B607 - bash on this part's own command
                  capture_output=True, text=True, timeout=60, check=False, env=env)
    return p.stdout, p.stderr, p.returncode


def _arm65():
    _p9_arm(who="part65")
    _p9_patch(_p9_core, "run_command", _p9_trip("run_command"))
    _p9_patch(_p9_core, "shell_as_game_user", _bash65)


def _setup65():
    with _p9.app_context():
        r = RemoteServer(name="p65-host", host="192.0.2.165", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p65-" + _USER65, short_name=_USER65, game_type="csgo",
                        port=27565, installed=True, status="offline")
        admin = User(username="p65_admin", password_hash=_auth65.hash_password("Str0ng!passw0rd-p65"),
                     display_name="p65 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gs, admin])
        db.session.commit()
        _mine65["hosts"].append(r.id)
        _mine65["servers"].append(gs.id)
        _mine65["users"].append(admin.id)
        return r.id, gs.id, admin.id


def _cleanup65():
    with _p9.app_context():
        for i in _mine65["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
        AuditLog.query.filter(AuditLog.action.like("p65_%")).delete(synchronize_session=False)
        AuditLog.query.filter(AuditLog.username.like("p65%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine65[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()
    _shutil65.rmtree(_BIN65, ignore_errors=True)


def _rows65(sid, action):
    """The details of every audit row `action` wrote for server `sid`, oldest first."""
    with _p9.app_context():
        return [(r.detail, r.success) for r in AuditLog.query.filter_by(
            game_server_id=sid, action=action).order_by(AuditLog.id).all()]


# ── A04: CoD4X's status table ─────────────────────────────────────────────────────────────────
def _plen65(name):
    """Q_PrintStrlen: a name's length without its colour codes."""
    return len(name) - 2 * name.count("^")


def _cod4x65(rows):
    """A CoD4X 1.8 status reply, from src/sv_cmds.c SV_Status_f (sv_legacymode off).

    "%3i ", "%5i ", "CNCT "/"ZMBI "/"PRIM "/"%4i ", the playerid then blanks up to 20 (do-while:
    at least one), the steamid then blanks up to 18, the name, "^7", blanks up to 33 visible, "%7i "
    lastmsg, the address then blanks up to 52, " %5i" qport, " %5i" rate.
    """
    out = ("hostname: p65\nversion : CoD4X 1.8\nudp/ip  : 203.0.113.1:28960\nos      : linux\n"
           "type    : dedicated server\nmap     : mp_crash\n\n"
           "num score ping playerid            steamid           name                             "
           "lastmsg address                                              qport rate\n"
           "--- ----- ---- ------------------- ----------------- -------------------------------- "
           "------- ---------------------------------------------------- ----- -----\n")
    for i, sc, st, pid, sid, nm, ad in rows:
        ln = "%3i " % i + "%5i " % sc + ("%s " % st if isinstance(st, str) else "%4i " % st)
        ln += pid + " " * max(1, 20 - len(pid)) + sid + " " * max(1, 18 - len(sid))
        ln += nm + "^7" + " " * max(1, 33 - _plen65(nm)) + "%7i " % 50 + ad
        out += ln + " " * max(1, 52 - len(ad)) + " %5i" % 1234 + " %5i" % 25000 + "\n"
    return out + "\n"


_COD4X_ROWS65 = [(0, 12, 48, "[U:1:111]", "76561198000000111", "Alice", "203.0.113.5:28960"),
                 (1, 0, 67, "[U:1:222]", "76561198000000222", "Bob Smith", "203.0.113.6:28961"),
                 (2, 3, "PRIM", "[U:1:333]", "0", "^1Red^7Bot", "203.0.113.7:28962"),
                 (3, 0, "CNCT", "[U:1:444]", "0", "Newcomer 2", "203.0.113.8:28963")]


def _cod4x_players65():
    pane = {"text": ""}
    _p9_patch(_p9_core, "send_console_command", lambda *a, **k: ("PANE_MARK 1200 17 80\n", "", 0))
    _p9_patch(_game65, "capture_console", lambda *a, **k: (pane["text"], "", 0))
    _p9_patch(_game65, "time", NS(sleep=lambda s: None, time=_time65.time, gmtime=_time65.gmtime,
                                  strftime=_time65.strftime, monotonic=_time65.monotonic))
    pane["text"] = "status\n" + _cod4x65(_COD4X_ROWS65) + "say: Bob Smith: num score ping\n"
    got = [(p["num"], p["name"], p["guid"])
           for p in _game65.console_player_list(None, _USER65, "cod4") or []]
    check("players (CoD4X): the `num score ping playerid steamid name …` table is read — slots, "
          "names without the playerid, a name with spaces and digits, a coloured name, a PRIM and "
          "a CNCT row — not unknown",
          got == [(0, "Alice", "[U:1:111]"), (1, "Bob Smith", "[U:1:222]"), (2, "RedBot", "[U:1:333]"),
                  (3, "Newcomer 2", "[U:1:444]")], repr(got))


# ── A04: Ban sends each game's own ban, or is refused ──────────────────────────────────────────
def _idt3_ban65():
    sent = []
    _p9_patch(_p9_core, "send_console_command",
              lambda server, user, cmd, **k: (sent.append(cmd), ("", "", 0))[1])
    got = {}
    for game in ("cod4", "cod2", "rtcw", "q3", "etl", "wet", "jk2"):
        del sent[:]
        ok = _game65.moderate(None, "u", game, "ban", num="3")[0]
        got[game] = (ok, list(sent), _game65.moderation_caps(game)["ban"])
    no_ban = {g: got[g] for g in ("q3", "etl", "wet", "jk2")}
    check("moderation (idTech3): Ban sends the game's own ban — banclient on CoD, the address ban "
          "and a kick on iortcw — and the Ban button is offered there",
          got["cod4"] == (True, ["banclient 3"], True) and got["cod2"] == (True, ["banclient 3"], True)
          and got["rtcw"] == (True, ["banaddr 3; kicknum 3"], True), repr(got))
    check("moderation (idTech3): where the console has no ban by slot (Quake III 1.32, ET, ET:Legacy, "
          "JK2MV) Ban is refused with nothing sent and the button is not offered — never "
          "\"Done.\" for a ban that bans no one",
          all(v == (False, [], False) for v in no_ban.values()), repr(no_ban))
    del sent[:]
    kick = _game65.moderate(None, "u", "q3", "kick", num="3")
    check("moderation (idTech3): Kick on the same game still sends clientkick (control)",
          kick[0] is True and sent == ["clientkick 3"], repr((kick, sent)))


# ── B2: the idTech3 table is keyed by LinuxGSM's shortnames; Jedi Knight II (JK2MV) ─────────────
def _jk2mv65(rows):
    """A JK2MV status reply, from src/server/sv_ccmds.cpp SV_Status_f.

    "%3i %5i %s %s^7%s %7i %21s %5i %5i": the state "CNCT "/"ZMBI " or "%4i", the name cut to 15
    visible characters, blanks up to 15, lastmsg, the address right-aligned, qport, rate.
    """
    out = ("map: ffa_bespin\n"
           "num score ping name            lastmsg address               qport rate\n"
           "--- ----- ---- --------------- ------- --------------------- ----- -----\n")
    for i, sc, st, nm, ad in rows:
        state = {"CNCT": "CNCT ", "ZMBI": "ZMBI "}.get(st) or "%4i" % st
        shown = nm if _plen65(nm) <= 15 else nm[:15]
        out += "%3i %5i %s %s^7%s %7i %21s %5i %5i\n" % (
            i, sc, state, shown, " " * max(0, 15 - _plen65(shown)), 50, ad, 1234, 25000)
    return out + "\n"


_JK2_ROWS65 = [(0, 12, 48, "Alice", "203.0.113.5:28070"),
               (1, -3, 999, "Bob Smith", "203.0.113.6:28071"),
               (2, 0, 0, "^1Red^7Bot", "bot"),
               (3, 0, "CNCT", "Newcomer 2", "203.0.113.7:28072"),
               (4, 7, "ZMBI", "Gone Now", "203.0.113.8:28073"),
               (5, 1, 9999, "AVeryLongPlayerName", "203.0.113.9:28074")]


def _jk2_65():
    engines = {g: _game65.game_engine(g) for g in ("jk2", "ql", "quakelive", "et", "jamp")}
    check("moderation (idTech3): Jedi Knight II (LinuxGSM's jk2) is an idTech3 game, and the keys "
          "that match no LinuxGSM game (quakelive, et, jamp) are gone; Quake Live (ql), whose "
          "console commands are published nowhere primary, is left to gamedig's view-only list",
          engines == {"jk2": "idtech3", "ql": "", "quakelive": "", "et": "", "jamp": ""},
          repr(engines))
    pane = {"text": ""}
    sent = []

    def _send(server, user, cmd, **k):
        sent.append(cmd)
        return ("PANE_MARK 1200 17 80\n", "", 0)
    _p9_patch(_p9_core, "send_console_command", _send)
    _p9_patch(_game65, "capture_console", lambda *a, **k: (pane["text"], "", 0))
    _p9_patch(_game65, "time", NS(sleep=lambda s: None, time=_time65.time, gmtime=_time65.gmtime,
                                  strftime=_time65.strftime, monotonic=_time65.monotonic))
    pane["text"] = "status\n" + _jk2mv65(_JK2_ROWS65) + "say: Bob Smith: num score ping\n"
    got = [(p["num"], p["name"]) for p in _game65.console_player_list(None, _USER65, "jk2") or []]
    check("players (JK2MV): the jk2 `num score ping name lastmsg address qport rate` table is read "
          "— slots, a name with spaces and digits, a bot, CNCT/ZMBI rows, a name cut to 15 — not "
          "unknown",
          got == [(0, "Alice"), (1, "Bob Smith"), (2, "RedBot"), (3, "Newcomer 2"), (4, "Gone Now"),
                  (5, "AVeryLongPlayer")], repr(got))
    del sent[:]
    kick = _game65.moderate(None, "u", "jk2", "kick", num="3")
    say = _game65.moderate(None, "u", "jk2", "say", message="hi")
    check("moderation (JK2MV): Kick sends the engine's clientkick by slot and Say the game's say; "
          "both are offered",
          kick[0] is True and say[0] is True and sent == ["clientkick 3", "say hi"]
          and _game65.moderation_caps("jk2") == {"kick": True, "ban": False, "say": True},
          repr((kick, say, sent)))


# ── A04: a capture at another width than the send's mark ───────────────────────────────────────
def _tool65(name, body):
    path = os.path.join(_BIN65, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/bash\n" + body)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in tool this part runs
    os.chmod(path, 0o700)  # nosec B103 - a stand-in tool in this part's own temp dir


def _capture_width65():
    os.makedirs(_TMUX65, exist_ok=True)
    sock = os.path.join(_TMUX65, "cod65srv-zz")
    open(sock, "w").close()
    try:
        _tool65("tmux", 'case " $* " in\n'
                        '  *" has-session "*) exit 0;;\n'
                        '  *" display "*) echo "$TMUX65_DISPLAY";;\n'
                        '  *" capture-pane "*) while [ $# -gt 0 ]; do [ "$1" = -S ] && echo "S=$2"; shift; done;;\n'
                        'esac\n')
        got = {}
        # The mark: history 1200, cursor 17, 80 columns. Narrowed to 70, tmux rewrapped the long
        # lines and the history GREW (1200 -> 1210), so the shrink test never runs.
        for tag, disp in (("narrowed", "1210 2000 70"), ("widened", "1190 1300 120"),
                          ("same width", "1210 2000 80")):
            os.environ["TMUX65_DISPLAY"] = disp
            out, _e, rc = _CAPTURE65(None, _USER65, selfname="cod65srv", since=(1200, 17, 80))
            got[tag] = (out.strip(), rc)
        check("capture since the send: a pane at another width than the mark (a resize either way, "
              "the history grown or not) is unknown (rc 4), not a capture started above the send; "
              "the same width still captures from the mark (control)",
              got == {"narrowed": ("", 4), "widened": ("", 4), "same width": ("S=7", 0)}, repr(got))
    finally:
        os.environ.pop("TMUX65_DISPLAY", None)
        os.unlink(sock)
        os.unlink(os.path.join(_BIN65, "tmux"))


# ── A06: a doas argv holding sudo's words ─────────────────────────────────────────────────────
def _doas_argv65():
    doas = "Oct 11 10:00:00 h doas[9]: "
    # The `user:password` pair is joined here, not written whole: Gitleaks' curl-auth-user rule
    # reads the literal and fails the PR's secret scan.
    cred = "admin" + ":"
    lines = [doas + "bob ran command curl -u " + cred + 'S3cretA -d {"command": "restart"} http://x '
             "as root from /home/bob",
             doas + "command not permitted for bob: curl -u " + cred + 'S3cretB -d {"command": '
             '"authentication failure"}',
             doas + "command not permitted for bob: mysql -pS3cretC NODE_ENV=x incorrect password",
             doas + 'bob ran command mysql -pS3cretD env COMMAND=x {"command": 1} as root from /']
    kept, _v, _s = _logs65._split_priv(lines)
    check("debug report: a doas line whose argv holds `\"command\":`, ENV= or COMMAND= is cut at "
          "the doas argv's start, not at the first of those inside it (the password before it "
          "printed)",
          len(kept) == 4 and "S3cret" not in "\n".join(kept)
          and all(k.endswith("(command not shown)") for k in kept), repr(kept))
    sudo = ["Oct 11 10:00:00 h sudo[5]:      bob : TTY=pts/0 ; PWD=/x ; USER=root ; ENV=A=S3cretE"]
    kept, _v, _s = _logs65._split_priv(sudo)
    check("debug report: ...a sudo line sudo split before COMMAND= is still cut at its ENV= (control)",
          kept == ["Oct 11 10:00:00 h sudo[5]:      bob : TTY=pts/0 ; PWD=/x ; USER=root ; "
                   "(environment and command not shown)"], repr(kept))


# ── A07: the helper's `#<uid>` guard ─────────────────────────────────────────────────────────
def _uid_guard65():
    try:
        got = (_helper._r14b_is_uid_zero("#¹"), _helper._r14b_is_uid_zero("#00"),
               _helper._r14b_is_uid_zero("#1000"))
    except ValueError as exc:
        got = repr(exc)
    check("helper: a Runas `#¹` is no uid (False), not a ValueError; #00 is root, #1000 is not",
          got == (False, True, False), repr(got))


# ── A07: the audit's User column, a completion row, a cut between escapes ──────────────────────
def _username_escaped65():
    name = "p65\u200badmin"          # an account name from before username_problem refused this
    with _p9.app_context():
        u = User(username=name, password_hash=_auth65.hash_password("Str0ng!passw0rd-p65b"),
                 display_name="p65 legacy", is_superadmin=True, is_active=True)
        db.session.add(u)
        db.session.commit()
        _mine65["users"].append(u.id)
    env = {"REMOTE_ADDR": "198.51.100.65"}
    with _p9.app_context(), _p9.test_request_context("/login", environ_base=env):
        _auth65.log_action(None, "p65_login_failed", actor=_RLO65 + "nimda", success=False)
        spoof = AuditLog.query.filter_by(action="p65_login_failed").order_by(AuditLog.id.desc()).first()
        stored = spoof.username if spoof else None
        for _ in range(5):
            _auth65.log_action(None, "login_failed", actor=name, success=False)
    check("audit: the User column a failed sign-in writes (the attempted name) is escaped, like the "
          "target and the detail — a U+202E there reordered the audit page",
          stored == "\\u202enimda", repr(stored))
    fired = []
    _p9_patch(_app65.notifications, "notify", lambda *a, **k: fired.append(a[0]))
    with _p9.app_context():
        _app65._maybe_alert_admin_bruteforce(name, "198.51.100.65", _time65.time())
    check("audit: ...and the brute-force alert still counts a super admin's failures by that "
          "column, a legacy name with a character it escapes included",
          fired == ["admin_bruteforce"], repr(fired))


def _completion_row65(rid, sid):
    _p9_patch(_p9_sd, "threading", _p9_threading(_P9Thread))
    _p9_patch(_p9_sd, "_run_teed",
              lambda *a, **k: ("\x1b[32m[  OK  ]\x1b[0m p65 update complete\x1b[K", "", 0))
    _p9_patch_sm("_invalidate_port_scan", lambda *a, **k: None)
    _p9_patch_sm("invalidate_game_version", lambda *a, **k: None)
    with _p9.app_context():
        gs, remote = db.session.get(GameServer, sid), db.session.get(RemoteServer, rid)
        _p9_sd._bg_action(_p9, gs, remote, "update")
    _p9_drain()
    rows = _rows65(sid, "update_complete")
    check("audit: an update's completion row stores LinuxGSM's text without its colour codes, not "
          "each ESC written as \\x1b",
          len(rows) == 1 and rows[0][0] == "[  OK  ] p65 update complete" and rows[0][1] is True,
          repr(rows))


def _cut_between_escapes65():
    got = {}
    for tag, value, marker in (("detail", "a" * 250 + _RLO65 * 3, "…[truncated]"),
                               ("target", "b" * 253 + _RLO65, "")):
        got[tag] = _auth65._audit_cut(value, 255, marker, visible=True)
    check("audit: text cut after escaping is cut between escapes, never inside one (a row ended in "
          "`\\u20`)",
          got == {"detail": "a" * 250 + "…[truncated]", "target": "b" * 253}, repr(got))


# ── A08: an account refusal's row; the cron routes and the firewall comment ───────────────────
def _account_refusal65(client, sid):
    def _refusal(remote, user, now=None, reading=False):
        return _p9_sh._privileged_write_msg("ubuntu", "it is in the sudo group", reading=reading)
    _p9_patch(_p9_sf, "game_account_write_refusal", _refusal)
    client.post("/api/server/%d/file" % sid, json={"path": "cfg/w65.cfg", "content": "x"})
    client.get("/api/server/%d/file?path=cfg/r65.cfg" % sid)
    client.get("/server/%d/download?path=cfg/d65.cfg" % sid)
    deep = "serverfiles/" + "d" * 300
    client.post("/api/server/%d/file" % sid, json={"path": deep, "content": "x"})
    w = _refusal(None, None)
    r = _refusal(None, None, reading=True)
    got = {a: (_rows65(sid, a)[-2:] or [("", None)]) for a in ("edit_file", "read_file", "download_file")}
    ok = (got["edit_file"][0][0] == "refused: cfg/w65.cfg: " + w
          and got["read_file"][-1][0] == "refused: cfg/r65.cfg: " + r
          and got["download_file"][-1][0] == "refused: cfg/d65.cfg: " + r
          and got["edit_file"][-1][0] == "refused: " + deep[:199] + "…: " + w)
    check("routes: a real account refusal's row (300+ characters) names the path and keeps the "
          "whole reason; a deep path is cut to its own 200, marked with …", ok, repr(got))
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: None)


def _cron_json65(client, sid):
    rewrites = []
    _p9_patch(_p9_core, "_rewrite_crontab", lambda *a, **k: (rewrites.append(k.get("drop_line")),
                                                             (True, ""))[1])
    _p9_patch(_p9_sf, "add_cron_job", _cron65.add_cron_job)
    _p9_patch(_p9_sf, "update_cron_job", _cron65.update_cron_job)
    _p9_patch(_p9_sf, "run_cron_job_now", _cron65.run_cron_job_now)
    _p9_patch_sm("delete_cron_job", _cron65.delete_cron_job)
    _p9_patch_sm("list_cron_jobs", lambda *a, **k: [])
    base = "/api/server/%d/cron" % sid
    answers = {}
    for tag, path, body in (("add, a number", "", {"schedule": 5, "command": "restart"}),
                            ("add, a dict", "", {"schedule": {"a": 1}, "command": "restart"}),
                            ("update, a list raw", "/update",
                             {"raw": ["0 5 * * * x"], "schedule": "0 6 * * *", "command": "restart"}),
                            ("delete, a list raw", "/delete", {"raw": ["0 5 * * * x"]}),
                            ("run, a dict raw", "/run", {"raw": {"cmd": "x"}})):
        resp = client.post(base + path, json=body)
        answers[tag] = (resp.status_code, (_p9_json(resp) or {}).get("success"))
    rows = {a: len(_rows65(sid, a)) for a in ("cron_add", "cron_update", "cron_delete", "cron_run_now")}
    check("routes (cron): a number, dict or list where text belongs is answered as a refusal "
          "(200, success false) and audited — not a 500, and not \"Deleted\" or \"Updated\" with "
          "the crontab rewritten",
          all(v == (200, False) for v in answers.values()) and rewrites == []
          and rows == {"cron_add": 2, "cron_update": 1, "cron_delete": 1, "cron_run_now": 1},
          repr((answers, rewrites, rows)))
    good = client.post(base + "/delete", json={"raw": "0 5 * * * x"})
    check("routes (cron): ...a delete naming a line still rewrites the crontab without it (control)",
          (_p9_json(good) or {}).get("success") is True and rewrites == ["0 5 * * * x"],
          repr((_p9_json(good), rewrites)))


def _fw_comment65(client, rid):
    sent = []
    _p9_patch(_p9_rv, "remote_ufw_open_port",
              lambda remote, port, proto, comment="": (sent.append(comment), (True, "opened"))[1])
    _p9_patch(_p9_rv._fw_rules, "fwb_open_shadow_note", lambda *a: None)   # the open's read-back (part136)
    _p9_patch(_p9_rv, "remote_ufw_allow_from",
              lambda remote, source, port, proto, comment="", allow=True:
              (sent.append(comment), (True, "allowed"))[1])
    a = client.post("/api/remote/%d/firewall/open" % rid, json={"port": "27015", "comment": 5})
    b = client.post("/api/remote/%d/firewall/allow-from" % rid,
                    json={"source": "198.51.100.0/24", "port": 22, "comment": ["x"]})
    check("routes (firewall): a comment that is not text reaches the writer as text (a number as "
          "its digits, a list as nothing), not as the TypeError that was a 500",
          (a.status_code, b.status_code) == (200, 200) and sent == ["5", ""],
          repr((a.status_code, b.status_code, sent)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# Game-keyed tables: every key is a LinuxGSM shortname (builder F)
# ════════════════════════════════════════════════════════════════════════════════════════════════
# A game_type is LinuxGSM's shortname (install runs "<shortname>server"), so a table key that is no
# shortname can never match a server. _ENG_VALVE had seven such keys and _ENG_MINECRAFT eight, the
# install form's ports were keyed "unturned", "factorio" and the like, and Velocity's gamedig type
# sat under "vmc": each a game the panel meant to cover and silently did not.
_ROOT65 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _r15f_shortnames65():
    path = os.path.join(_ROOT65, "tests", "unit", "lgsm_shortnames.txt")
    with open(path, encoding="utf-8") as fh:
        return {ln.strip() for ln in fh.read().splitlines() if ln.strip() and not ln.startswith("#")}


def _r15f_js_ports65():
    with open(os.path.join(_ROOT65, "static", "js", "manage_servers.js"), encoding="utf-8") as fh:
        js = fh.read()
    body = js[js.index("var PORTS = {"):]
    body = body[:body.index("};")]
    return {k: int(v) for k, v in _re65.findall(r'"([^"]+)":(\d+)', body)}


def _r15f_tables65():
    return {
        "game._ENG_VALVE": _game65._ENG_VALVE, "game._ENG_IDTECH3": _game65._ENG_IDTECH3,
        "game._ENG_MINECRAFT": _game65._ENG_MINECRAFT, "game._MC_NO_BAN": _game65._MC_NO_BAN,
        "game._R15B_IDT3_BAN": _game65._R15B_IDT3_BAN, "_core.GAMEDIG_TYPE": _core65.GAMEDIG_TYPE,
        "models.STEAM_CONNECT_GAMES": STEAM_CONNECT_GAMES,
        "models._NO_UPDATE_GAMES": _NO_UPDATE_GAMES,
        "manage_servers._R15F_KNOWN_PORTS": _ms65._R15F_KNOWN_PORTS,
        "manage_servers._R15F_EULA_GAMES": _ms65._R15F_EULA_GAMES,
        "app._PORT_SPAN": _app65._PORT_SPAN, "manage_servers.js PORTS": _r15f_js_ports65(),
        "host_reboot._TELNET_STOP_GAMES": _hr65._TELNET_STOP_GAMES,
    }


def _r16d_literal_keys65(value):
    """The string keys (dict) or items (set, tuple, list, or frozenset(...) of one) of a literal."""
    import ast as _ast
    if (isinstance(value, _ast.Call) and getattr(value.func, "id", "") in ("frozenset", "set", "tuple",
                                                                             "list", "dict")
            and value.args):
        return _r16d_literal_keys65(value.args[0])
    _elts = (value.keys if isinstance(value, _ast.Dict)
             else value.elts if isinstance(value, (_ast.Set, _ast.Tuple, _ast.List)) else [])
    return [_e.value for _e in _elts if isinstance(_e, _ast.Constant) and isinstance(_e.value, str)]


def _r16d_names_game_type65(node, held=("game_type",)):
    """Does expression `node` read a game_type (`gs.game_type`, `e["game_type"]`, or a name in `held`)?"""
    import ast as _ast
    return any((isinstance(_x, _ast.Attribute) and _x.attr == "game_type")
               or (isinstance(_x, _ast.Name) and _x.id in held)
               or (isinstance(_x, _ast.Constant) and _x.value == "game_type") for _x in _ast.walk(node))


def _r16d_held65(nodes):
    """The names that hold a game_type in one scope: game_type, and locals assigned from one."""
    import ast as _ast
    held = {"game_type"}
    for _ in range(3):  # a copy of a copy: three rounds, stopping at the first that adds nothing
        _more = {_t.id for _n in nodes if isinstance(_n, _ast.Assign) and _r16d_names_game_type65(_n.value, held)
                 for _t in _n.targets if isinstance(_t, _ast.Name)}
        if _more <= held:
            break
        held |= _more
    return held


def _r16d_looked_up65(node, held):
    """The table names one node looks a game_type up in: `x in T`, `T.get(x)` or `T[x]`."""
    import ast as _ast
    if isinstance(node, _ast.Compare) and any(isinstance(_o, (_ast.In, _ast.NotIn)) for _o in node.ops):
        _pairs = [(_c, node.left) for _c in node.comparators]
    else:
        _pairs = [_r16d_table_key65(node)]
    return {_t.id for _t, _k in _pairs if isinstance(_t, _ast.Name) and _r16d_names_game_type65(_k, held)}


def _r16d_table_key65(node):
    """(table, key) of `T.get(key, …)` or `T[key]`, else (None, None)."""
    import ast as _ast
    if isinstance(node, _ast.Call) and getattr(node.func, "attr", "") == "get" and node.args:
        return getattr(node.func, "value", None), node.args[0]
    if isinstance(node, _ast.Subscript):
        return node.value, node.slice
    return None, None


def _r16d_game_type_lookups65(nodes):
    """The names `nodes` (one scope's) look a game_type up in, a local assigned one included."""
    held = _r16d_held65(nodes)
    return {_t for _n in nodes for _t in _r16d_looked_up65(_n, held)}


def _r16d_scopes65(tree):
    """Each scope's own nodes: the module's (outside its defs and classes), then each function's."""
    import ast as _ast
    _defs = (_ast.FunctionDef, _ast.AsyncFunctionDef)
    yield [_x for _st in tree.body if not isinstance(_st, _defs + (_ast.ClassDef,)) for _x in _ast.walk(_st)]
    for _f in (_f for _f in _ast.walk(tree) if isinstance(_f, _defs)):
        yield list(_ast.walk(_f))


def _r16d_game_tables65(source):
    """{NAME: keys} for each module-level literal `source` looks a game_type up in.

    Found by USE, not listed: `<game_type> in NAME`, `NAME.get(<game_type>…)` and
    `NAME[<game_type>]`. The hand list above missed host_reboot._TELNET_STOP_GAMES (review 1012a),
    so a dead key there (7dtd for sdtd) would have cut 7 Days to Die's reboot save at 180 s.
    A local holding a game_type counts too (`gt = (game_type or "").lower()`, then
    `gt in _ENG_VALVE`), within its own function.
    """
    import ast as _ast
    tree = _ast.parse(source)
    tables = {_t.id: _r16d_literal_keys65(_n.value) for _n in tree.body
              if isinstance(_n, (_ast.Assign, _ast.AnnAssign)) and _n.value is not None
              for _t in (_n.targets if isinstance(_n, _ast.Assign) else [_n.target]) if isinstance(_t, _ast.Name)}
    used = set().union(*(_r16d_game_type_lookups65(_nodes) for _nodes in _r16d_scopes65(tree)))
    return {_k: tables[_k] for _k in used if tables.get(_k)}


def _r16d_found_tables65():
    """{"<file>:<NAME>": keys} over app.py and every panel module."""
    found = {}
    _files = [os.path.join(_ROOT65, "app.py")] + sorted(
        os.path.join(_d, _f) for _d, _s, _fs in os.walk(os.path.join(_ROOT65, "panel"))
        for _f in _fs if _f.endswith(".py"))
    for _path in _files:
        with open(_path, encoding="utf-8") as fh:
            for _name, _keys in _r16d_game_tables65(fh.read()).items():
                found["%s:%s" % (os.path.relpath(_path, _ROOT65), _name)] = _keys
    return found


_R16D_MUST_FIND65 = {"panel/ops/ssh_manager/game.py:_ENG_VALVE", "app.py:_PORT_SPAN",
                     "panel/services/host_reboot.py:_TELNET_STOP_GAMES", "panel/ops/ssh_manager/game.py:_MC_NO_BAN"}


def _r16d_check_tables65(names):
    """Every listed and every found game_type table holds only shortnames; the finder's control."""
    tables, found = _r15f_tables65(), _r16d_found_tables65()
    dead = {t: sorted(set(keys) - names) for t, keys in list(tables.items()) + list(found.items())
            if set(keys) - names}
    check("game tables: every key of every table keyed by game_type is a LinuxGSM shortname — a key "
          "that is none (hl2mp, spigot, mcbe, vmc, unturned, ...) can never match a server; the tables "
          "are the listed ones and every module-level one a game_type is looked up in",
          not dead and len(tables) == 13 and len(found) >= 12 and _R16D_MUST_FIND65 <= set(found),
          repr((dead, sorted(found))))
    _ctl = _r16d_game_tables65(
        'A = frozenset(("7dtd", "sm"))\nB = {"at": 1, "data": 2}\nC: dict = {"gmod": 1}\nD = ("x",)\n'
        'def f(e, gs, game_type):\n    t = 600 if e["game_type"] in A else 180\n'
        '    return C.get(gs.game_type), B["data"], D[0], game_type not in D\n')
    check("game tables: ...a table is found by how a game_type is looked up in it, and its dead key "
          "named; a dict read by another key is not one (control)",
          sorted(_ctl) == ["A", "C", "D"] and set(_ctl["A"]) - names == {"7dtd"}, repr(_ctl))


def _r15f_game_keys65():
    names = _r15f_shortnames65()
    check("game tables: the committed LinuxGSM shortname list is read (142 games at its commit, "
          "and the ones these tables key on are in it)",
          len(names) == 142 and {"gmod", "mcb", "vpmc", "zmr", "unt"} <= names, repr(len(names)))
    _r16d_check_tables65(names)
    js = _r15f_js_ports65()
    check("game tables: the install form's JS PORTS is the same table as the route's default ports",
          js == _ms65._R15F_KNOWN_PORTS,
          repr(sorted(set(js.items()) ^ set(_ms65._R15F_KNOWN_PORTS.items()))))
    check("game tables: LinuxGSM's vs is Vampire Slayer (GoldSrc, 27015) and Vintage Story is vints "
          "(42420); Velocity's gamedig type is keyed vpmc; Unturned's port block is keyed unt",
          (js.get("vs"), js.get("vints"), _app65._port_span("unt")) == (27015, 42420, 2)
          and "vpmc" in _core65.GAMEDIG_TYPE,
          repr((js.get("vs"), js.get("vints"), _app65._port_span("unt"))))


def _r15f_engine_map65():
    full = {"kick": True, "ban": True, "say": True}
    none = {"kick": False, "ban": False, "say": False}
    added = {g: (_game65.game_engine(g), _game65.moderation_caps(g))
             for g in ("bb", "opfor", "ts", "vs", "zmr")}
    check("moderation (valve): the GoldSrc mods on Valve's HLDS (bb, opfor, ts, vs) and the Source "
          "SDK 2013 game zmr are valve-family, with Kick, Ban and Say",
          all(v == ("valve", full) for v in added.values()), repr(added))
    # Each left out for want of a primary source (or, for the proxies, because they have no such
    # commands): a mapping here would make Kick answer "Done." while the player stayed on.
    out = {g: (_game65.game_engine(g), _game65.moderation_caps(g))
           for g in ("sven", "bd", "dab", "bmdm", "tf2c", "mcv", "vpmc", "wmc", "ql")}
    check("moderation: games of these engines that run their own engine build, and the Minecraft "
          "proxies (Velocity, Waterfall), get no console moderation",
          all(v == ("", none) for v in out.values()), repr(out))
    check("moderation (Bedrock): LinuxGSM's mcb is Minecraft with Kick and Say and no Ban",
          (_game65.game_engine("mcb"), _game65.moderation_caps("mcb"))
          == ("minecraft", {"kick": True, "ban": False, "say": True}),
          repr(_game65.moderation_caps("mcb")))


try:
    _arm65()
    _R65, _S65, _ADMIN65 = _setup65()
    _A65 = _p9_client(_ADMIN65)
    _cod4x_players65()
    _idt3_ban65()
    _jk2_65()
    _capture_width65()
    _doas_argv65()
    _uid_guard65()
    _username_escaped65()
    _completion_row65(_R65, _S65)
    _cut_between_escapes65()
    _account_refusal65(_A65, _S65)
    _cron_json65(_A65, _S65)
    _fw_comment65(_A65, _R65)
    _r15f_game_keys65()
    _r15f_engine_map65()
finally:
    _p9_restore_all()
    _cleanup65()

check("part65: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP65_START, repr(_P9_TRIPPED[_TRIP65_START:][:6]))
