"""Part 62 of the unit suite: the fourth 2026-10-11 review's fixes (builder B).

Game files, the debug report, the privileged helper and routes:

* Console player list: a player's chat line `say: Bob: num score ping` is not the idTech3 table's
  header (it made a full server read as confirmed-empty); a pane history that went DOWN when no
  trim was possible (a resize reflow) makes the capture unknown instead of starting it above the
  send.
* Debug report: pkexec's refusal lines and doas's "command not permitted" line are cut before
  their argv as the success lines are; a sudo "(command continued)" line is dropped even when its
  argv holds a refusal phrase.
* Helper: a NOPASSWD grant whose own later item asks a password for every root command is no
  grant; a later rule with an Option_Spec (`TIMEOUT=1h PASSWD: ALL`) takes it back; `#00` is root.
* Routes: upload, editor-save and download rows write the path escaped; an account refusal's row
  names the path; a refusal's reason is never cut off by a long path; the Alerts card's and the
  log-timestamps switch's failed cfg writes are audited with their reason; a daily-restart time
  that is not HH:MM is a 400; an account probe that did not answer stops a retried install; a
  path or contents that cannot be UTF-8 is refused, audited, not a 500; every audit row escapes
  what the audit page could not show.

HOW IT RUNS. On part12's Flask app and stubs, as part58 does: host commands run in a REAL bash
with stand-in tools; nothing reaches a transport.
"""
import contextlib as _ctx62
import io as _io62
import os
import pwd as _pwd62
import shutil as _shutil62
import subprocess as _sp62  # nosec B404 - runs bash on the commands this part's code builds
import tempfile as _tf62
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper
from unit.part12 import (_P9_TRIPPED, _p9, _p9_client, _p9_core, _p9_json, _p9_ms, _p9_patch,
                         _p9_restore_all, _p9_sd, _p9_sf, _p9_so, _p9_trip)
from panel.db.models import AuditLog, GameServer, RemoteServer, User, db
from panel.ops.debug_report import logs as _logs62
from panel.ops.ssh_manager import files as _files62
from panel.ops.ssh_manager import game as _game62
from panel.security import auth as _auth62

_TRIP62_START = len(_P9_TRIPPED)
_CAPTURE62 = _game62.capture_console          # before any stub
_USER62 = "r14b62"
_HOME62 = os.path.realpath(_tf62.mkdtemp(prefix="lgsm-unit-p62-home-"))
_BIN62 = os.path.realpath(_tf62.mkdtemp(prefix="lgsm-unit-p62-bin-"))
_TMUX62 = os.path.join(_BIN62, "tmuxdir")       # stands in for /tmp/tmux-<uid> (_bash62)
_RLO62 = "\u202e"                               # RIGHT-TO-LEFT OVERRIDE
_mine62 = {"hosts": [], "servers": [], "users": []}


def _bash62(server, user, sh, timeout=30, selfname=None, scope=False):
    """shell_as_game_user's command in a real bash, the stand-in tools first on PATH."""
    env = dict(os.environ, PATH=_BIN62 + os.pathsep + os.environ.get("PATH", ""))
    sh = sh.replace("/home/" + _USER62, _HOME62).replace("D=/tmp/tmux-$(id -u)", "D=" + _TMUX62)  # nosec B108 - the text replaced, not a path used
    p = _sp62.run(["bash", "-c", sh],  # nosec B603 B607 - bash on this part's own command
                  capture_output=True, text=True, timeout=60, check=False, env=env)
    return p.stdout, p.stderr, p.returncode


def _tool62(name, body):
    path = os.path.join(_BIN62, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/bash\n" + body)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in tool this part runs
    os.chmod(path, 0o700)  # nosec B103 - a stand-in tool in this part's own temp dir


def _arm62():
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part62's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_core, "run_command", _p9_trip("run_command"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9_core, "shell_as_game_user", _bash62)


def _setup62():
    with _p9.app_context():
        r = RemoteServer(name="p62-host", host="192.0.2.162", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p62-" + _USER62, short_name=_USER62, game_type="csgo",
                        port=27562, installed=True, status="offline")
        admin = User(username="p62_admin", password_hash=_auth62.hash_password("Str0ng!passw0rd-p62"),
                     display_name="p62 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gs, admin])
        db.session.commit()
        _mine62["hosts"].append(r.id)
        _mine62["servers"].append(gs.id)
        _mine62["users"].append(admin.id)
        return r.id, gs.id, admin.id


def _cleanup62():
    with _p9.app_context():
        for i in _mine62["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
        db.session.commit()
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine62[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()
    _shutil62.rmtree(_HOME62, ignore_errors=True)
    _shutil62.rmtree(_BIN62, ignore_errors=True)


def _rows62(sid, action):
    """The details of every audit row `action` wrote for server `sid`, oldest first."""
    with _p9.app_context():
        return [(r.detail, r.success) for r in AuditLog.query.filter_by(
            game_server_id=sid, action=action).order_by(AuditLog.id).all()]


# ── A04: the idTech3 header, and a capture that cannot tell where its send was ─────────────────
_COD62 = ('status\nmap: mp_crash\n'
          'num score ping guid                             name            lastmsg address       qport rate\n'
          '--- ----- ---- -------------------------------- --------------- ------- ------------- ----- ----\n'
          '  0     5   45 1100001aaaaaaaaaaaaaaaaaaaaaaaaa ^1Alice^7             0 203.0.113.5:28960 12345 25000\n'
          '  1     0   67 1100001bbbbbbbbbbbbbbbbbbbbbbbbb Bob Smith            50 203.0.113.9:28961 54321 25000\n')


def _idt3_chat62():
    pane = {"text": ""}
    _p9_patch(_p9_core, "send_console_command", lambda *a, **k: ("PANE_MARK 1200 17\n", "", 0))
    _p9_patch(_game62, "capture_console", lambda *a, **k: (pane["text"], "", 0))
    _p9_patch(_game62, "time", NS(sleep=lambda s: None))
    got = {}
    for tag, text in (("chat", _COD62 + "say: Bob Smith: num score ping\n"),
                      ("chat, guid name", _COD62 + "say;123;1;Bob: num score ping guid name\n"),
                      ("no chat", _COD62)):
        pane["text"] = text
        got[tag] = [p["name"] for p in _game62.console_player_list(None, _USER62, "cod4") or []]
    pane["text"] = "status\nsay: Bob: num score ping\n"
    got["chat only"] = _game62.console_player_list(None, _USER62, "cod4")
    check("players (idTech3): a player's chat line saying `num score ping` after the table is not "
          "its header — the list is still the table's, not a confirmed-empty server; a capture "
          "with only the chat line is unknown",
          got == {"chat": ["Alice", "Bob Smith"], "chat, guid name": ["Alice", "Bob Smith"],
                  "no chat": ["Alice", "Bob Smith"], "chat only": None}, repr(got))


_SRC62 = ('hostname: p62\nplayers : 2 humans, 0 bots (24 max)\n'
          '# userid name uniqueid connected ping loss state\n'
          '#  2 "Ann" STEAM_0:1:5 01:02 40 0 active\n'
          '#  3 "Ben" STEAM_0:1:6 01:02 40 0 active\n')
_GOLD62 = ('players : 1 active (32 max)\n'
           '# \tname\tuserid   \tuniqueid \tfrag\ttime    \tping\tloss\tadr\n'
           '# 1\t"Cat"\t2\tSTEAM_0:1:7\t0\t01:02\t40\t0\t198.51.100.7:27005\n')


def _valve_chat62():
    pane = {"text": ""}
    _p9_patch(_p9_core, "send_console_command", lambda *a, **k: ("PANE_MARK 1200 17\n", "", 0))
    _p9_patch(_game62, "capture_console", lambda *a, **k: (pane["text"], "", 0))
    _p9_patch(_game62, "time", NS(sleep=lambda s: None))
    got = {}
    no_count = _SRC62.replace("players : 2 humans, 0 bots (24 max)\n", "")
    for tag, text in (("chat", _SRC62 + "Ben : uniqueid\n"),
                      ("chat, no count line", no_count + "Ben : uniqueid\n"),
                      ("GoldSrc tab layout", _GOLD62)):
        pane["text"] = "status\n" + text
        got[tag] = [p["name"] for p in _game62.console_player_list(None, _USER62, "gmod") or []]
    check("players (valve): a chat line saying `uniqueid` after the table is not its header — "
          "the table's players, not unknown or an empty server; GoldSrc's tab layout is a header "
          "(control)", got == {"chat": ["Ann", "Ben"], "chat, no count line": ["Ann", "Ben"],
                               "GoldSrc tab layout": ["Cat"]}, repr(got))


def _capture_shrink62():
    os.makedirs(_TMUX62, exist_ok=True)
    sock = os.path.join(_TMUX62, "cod62srv-zz")
    open(sock, "w").close()
    try:
        _tool62("tmux", 'case " $* " in\n'
                        '  *" has-session "*) exit 0;;\n'
                        '  *" display "*) echo "$TMUX62_DISPLAY";;\n'
                        '  *" capture-pane "*) while [ $# -gt 0 ]; do [ "$1" = -S ] && echo "S=$2"; shift; done;;\n'
                        'esac\n')
        got = {}
        # At the mark the history was 1200 rows of a 2000-row limit: tmux's next trim (200 rows)
        # only comes at 2000, so 1200 cannot fall to 1090 by a trim — a resize reflowed it.
        for tag, disp in (("reflowed", "1090 2000"), ("trimmed", "1090 1300")):
            os.environ["TMUX62_DISPLAY"] = disp
            out, _e, rc = _CAPTURE62(None, _USER62, selfname="cod62srv", since=(1200, 17))
            got[tag] = (out.strip(), rc)
        check("capture since the send: a history that went down when no trim was possible "
              "(a resize) is unknown (rc 4, nothing captured), not a capture started above the "
              "send; a real trim still counts (control)",
              got == {"reflowed": ("", 4), "trimmed": ("S=-3", 0)}, repr(got))
    finally:
        os.environ.pop("TMUX62_DISPLAY", None)
        os.unlink(sock)
        os.unlink(os.path.join(_BIN62, "tmux"))


# ── A06: privilege tools' refusals in the debug report ──────────────────────────────────────────
def _priv_refusals62():
    sfx = " [USER=root] [TTY=/dev/pts/0] [CWD=/home/bob] [COMMAND=/usr/bin/mysql -u root -pS3cret%s]"
    pk = "Oct 11 10:00:00 h pkexec[9]: bob: "
    refused = pk + "Error executing command as another user: "
    doas = "Oct 11 10:00:00 h doas[9]: command not permitted for bob: "
    lines = [refused + "Not authorized" + sfx % "A",
             refused + "Request dismissed" + sfx % "B",
             pk + "The value for the SHELL variable was not found the /etc/shells file" + sfx % "C",
             doas + "mysql -pS3cretD",
             doas + "grep 'authentication failure' -pS3cretF",
             pk + "Executing command [USER=root] [TTY=pts/0] [CWD=/" + "d" * 1500
             + "] [COMMAND=/usr/bin/mysql -pS3cretG]"]
    kept, _v, _s = _logs62._split_priv(lines)
    text = "\n".join(kept)
    check("debug report: pkexec's refusal lines (Not authorized, Request dismissed, the env "
          "refusal), doas's \"command not permitted\" (one holding a refusal phrase too) and a "
          "pkexec line with a long CWD are kept without their argv",
          len(kept) == 6 and "S3cret" not in text and text.count("(command not shown)") == 6
          and "Not authorized" in text and "Request dismissed" in text, repr(kept))
    cont = ["Oct 11 10:00:00 h sudo[5]:      bob : (command continued) grep 'authentication failure' "
            + "/var/log/auth.log; mysql -pS3cretE"]
    kept, _v, _s = _logs62._split_priv(cont)
    check("debug report: a sudo \"(command continued)\" line is dropped even when its argv holds "
          "a refusal phrase", kept == [], repr(kept))


# ── A07: who reaches root, as the helper reads sudoers ──────────────────────────────────────────
def _reach62():
    tmp = _tf62.mkdtemp(prefix="lgsm-unit-p62-sudo-")
    caller = _pwd62.getpwuid(os.getuid()).pw_name
    saved = (_helper.SUDOERS_FILE, _helper.SUDOERS_DIR, _helper._groups_of)
    try:
        main = os.path.join(tmp, "sudoers")
        os.makedirs(os.path.join(tmp, "sudoers.d"))
        _helper.SUDOERS_FILE, _helper.SUDOERS_DIR = main, os.path.join(tmp, "sudoers.d")
        _helper._groups_of = lambda _n: set()

        def reach(text):
            with open(main, "w", encoding="utf-8") as fh:
                fh.write(text % {"c": caller})
            with _ctx62.redirect_stderr(_io62.StringIO()):
                return _helper._caller_reaches_root(caller)

        grant = "%(c)s ALL=(ALL) NOPASSWD: ALL\n"
        own = {k: reach(t) for k, t in (
            ("last item PASSWD", "%(c)s ALL=(ALL) NOPASSWD: ALL, PASSWD: ALL\n"),
            ("(root) PASSWD after", "%(c)s ALL=(ALL) NOPASSWD: ALL, (root) PASSWD: ALL\n"),
            ("ALL inherits PASSWD", "%(c)s ALL=(ALL) NOPASSWD: /bin/ls, PASSWD: /bin/x, ALL\n"),
            ("grant", grant),
            ("ALL inherits NOPASSWD", "%(c)s ALL=(ALL) NOPASSWD: /bin/ls, ALL\n"),
            ("later non-root Runas", "%(c)s ALL=(ALL) NOPASSWD: ALL, (nobody) PASSWD: ALL\n"))}
        check("helper: a rule whose own LAST item for every root command asks a password is no "
              "NOPASSWD grant (sudo's last match wins); a bare ALL inheriting NOPASSWD, or a "
              "later item for another Runas, still is (controls)",
              own == {"last item PASSWD": False, "(root) PASSWD after": False,
                      "ALL inherits PASSWD": False, "grant": True, "ALL inherits NOPASSWD": True,
                      "later non-root Runas": True}, repr(own))
        later = {k: reach(grant + t) for k, t in (
            ("TIMEOUT", "%(c)s ALL=(ALL) TIMEOUT=1h PASSWD: ALL\n"),
            ("CWD", "%(c)s ALL=(ALL) CWD=* PASSWD: ALL\n"),
            ("#00", "%(c)s ALL=(#00) PASSWD: ALL\n"),
            ("#1000", "%(c)s ALL=(#1000) PASSWD: ALL\n"))}
        check("helper: a later rule with an Option_Spec before its tags (TIMEOUT=, CWD=) takes a "
              "NOPASSWD grant back, and Runas `#00` is root; `#1000` is not (control)",
              later == {"TIMEOUT": False, "CWD": False, "#00": False, "#1000": True}, repr(later))
    finally:
        (_helper.SUDOERS_FILE, _helper.SUDOERS_DIR, _helper._groups_of) = saved
        _shutil62.rmtree(tmp, ignore_errors=True)


# ── A08: audit rows ─────────────────────────────────────────────────────────────────────────────
def _escaped_paths62(client, sid):
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_p9_sf, "upload_file", lambda *a, **k: (True, "Uploaded"))
    _p9_patch(_p9_sf, "write_file", lambda *a, **k: (True, "Saved"))
    _p9_patch(_p9_sf, "stat_path", lambda r, u, rel: {"rel": rel, "type": "f", "name": "x", "size": 1})
    _p9_patch(_p9_sf, "stream_path", lambda *a, **k: iter([b"x"]))
    name = _RLO62 + "gnp.sh "
    client.post("/api/server/%d/upload" % sid, content_type="multipart/form-data",
                data={"path": "cfg", "file": (_io62.BytesIO(b"x"), name)})
    client.post("/api/server/%d/file" % sid, json={"path": "cfg/" + name, "content": "x"})
    client.get("/server/%d/download?path=cfg/%s" % (sid, name))
    got = {a: _rows62(sid, a)[-1:] for a in ("upload_file", "edit_file", "download_file")}
    ok = all(rows and _RLO62 not in rows[0][0] and "\\u202egnp.sh\\x20" in rows[0][0]
             for rows in got.values())
    check("routes: upload, editor-save and download rows write the path escaped (a U+202E and a "
          "trailing space shown as escapes, as delete's and rename's rows write them)", ok, repr(got))


def _refusals_name_the_path62(client, sid):
    why = "Refused: the 'p62' account on this host can become root."
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: why)
    client.post("/api/server/%d/file" % sid, json={"path": "cfg/w62.cfg", "content": "x"})
    client.get("/api/server/%d/file?path=cfg/r62.cfg" % sid)
    client.get("/server/%d/download?path=cfg/d62.cfg" % sid)
    got = {a: (_rows62(sid, a)[-1:] or [("", None)])[0][0]
           for a in ("edit_file", "read_file", "download_file")}
    check("routes: an account refusal's row names the path it refused, with the reason",
          got == {"edit_file": "refused: cfg/w62.cfg: " + why,
                  "read_file": "refused: cfg/r62.cfg: " + why,
                  "download_file": "refused: cfg/d62.cfg: " + why}, repr(got))
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: None)


def _reason_whole62(client, sid):
    deep = "serverfiles/" + "d" * 300
    r = client.post("/api/server/%d/rename-path" % sid, json={"path": deep, "new_name": "a/b"})
    why = (_p9_json(r) or {}).get("message") or "?"
    row = (_rows62(sid, "rename_file")[-1:] or [("", None)])[0][0]
    check("routes: a refusal's reason is whole in its row however long the path — the path is "
          "cut, marked with …",
          r.status_code == 400 and len(row) <= 250 and row.endswith(": " + why) and "…" in row,
          repr((r.status_code, why, row)))
    _p9_patch(_p9_sf, "write_file", _files62.write_file)      # refused before the host
    client.post("/api/server/%d/file" % sid, json={"path": "../" + "e" * 300, "content": "x"})
    row = (_rows62(sid, "edit_file")[-1:] or [("", None)])[0][0]
    check("routes: ...and a host write's refusal too (an editor save out of the home)",
          len(row) <= 250 and row.endswith(": Invalid path") and "…" in row, repr(row))


def _cfg_writes_audited62(client, sid):
    unread = _files62.LGSM_CONFIG_UNREAD
    _p9_patch(_p9_sf, "lgsm_write_config", lambda *a, **k: (False, unread))
    client.post("/api/server/%d/alerts" % sid, json={"values": {}})
    r = client.post("/api/server/%d/log-timestamps" % sid, json={"enabled": False})
    got = {a: _rows62(sid, a)[-1:] for a in ("server_alerts_save", "set_log_timestamps")}
    check("routes: the Alerts card's and the log-timestamps switch's failed cfg writes are "
          "audited with the writer's reason",
          r.status_code == 502 and all(rows and rows[0][1] is False and unread in rows[0][0]
                                       for rows in got.values()), repr((r.status_code, got)))


def _daily_time62(client, sid):
    calls = []
    _p9_patch(_p9_sd, "set_daily_restart", lambda *a, **k: (calls.append(k.get("hour")), (True, ""))[1])
    _p9_patch(_p9_sd, "_host_timezone_cached", lambda remote: None)
    got = {}
    for t in ("5pm", "17:60", 5, ["17:30"]):
        got[repr(t)] = client.post("/api/server/%d/daily-restart" % sid,
                                   json={"enabled": True, "time": t}).status_code
    good = client.post("/api/server/%d/daily-restart" % sid, json={"enabled": True, "time": "17:30"})
    check("routes: a daily-restart time that is not HH:MM (or not text) is a 400 and moves "
          "nothing; 17:30 still sets it (control)",
          set(got.values()) == {400} and good.status_code == 200 and calls == [17],
          repr((got, good.status_code, calls)))


def _account_probe62():
    ans = {"v": ("", "timed out", -1)}
    _p9_patch(_p9_ms._sm, "read_as_game_user", lambda *a, **k: ans["v"])
    got = {}
    for tag, v in (("no answer", ("", "timed out", -1)), ("empty", ("", "", 0)),
                   ("has linuxgsm.sh", ("motd\nEXISTS\n", "", 0))):
        ans["v"] = v
        got[tag] = _p9_ms._existing_account_verdict(None, (-62, "p62acct"), False)[:2]
    check("install retry: an account probe that did not answer (or said nothing) stops the "
          "install, retryable; one that found linuxgsm.sh uses the account (control)",
          got["no answer"][0] is False and "did not answer" in got["no answer"][1]
          and got["empty"][0] is False and got["has linuxgsm.sh"] == (True, ""), repr(got))


def _not_text62(client, sid):
    for k in ("upload_file", "write_file", "stat_path", "stream_path"):
        _p9_patch(_p9_sf, k, getattr(_files62, k))       # the real ones: refused before the host
    r1 = client.post("/api/server/%d/file" % sid, json={"path": "cfg/\ud800.cfg", "content": "x"})
    r2 = client.post("/api/server/%d/file" % sid, json={"path": "cfg/a62.cfg", "content": "x\ud800"})
    rows = _rows62(sid, "edit_file")[-2:]
    check("routes: an editor save whose path or contents cannot be UTF-8 (a lone surrogate) is "
          "refused and audited, not a 500",
          (r1.status_code, r2.status_code) == (200, 200)
          and [(_p9_json(r) or {}).get("success") for r in (r1, r2)] == [False, False]
          and len(rows) == 2 and all(s is False for _d, s in rows)
          and "must be text" in rows[1][0], repr((r1.status_code, r2.status_code, rows)))


def _audit_floor62(client, sid):
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_p9_sf, "add_cron_job", lambda *a, **k: (False, "no"))
    client.post("/api/server/%d/cron" % sid, json={"schedule": "0 5 * * *" + _RLO62 + "x\ud800",
                                                   "command": "restart"})
    rows = _rows62(sid, "cron_add")[-1:]
    check("audit: every row writes what the audit page could not show as an escape (a request's "
          "cron schedule, here), and a lone surrogate is stored, not a failed commit",
          rows and _RLO62 not in rows[0][0] and "\\u202ex\\ud800" in rows[0][0], repr(rows))
    wide = []
    with _p9.app_context(), _p9.test_request_context("/"):
        for detail in (_RLO62 * 2000, "y" * 10000):
            _auth62.log_action(None, "p62_wide", detail=detail, server=None)
            wide.append(AuditLog.query.filter_by(action="p62_wide").order_by(
                AuditLog.id.desc()).first().detail)
        AuditLog.query.filter_by(action="p62_wide").delete()
        db.session.commit()
    check("audit: a detail over the cap, before escaping or only once escaped, is cut and marked",
          all(w.endswith("…[truncated]") and len(w) <= _auth62._AUDIT_DETAIL_MAX + 12
              and _RLO62 not in w for w in wide), repr([(len(w), w[-20:]) for w in wide]))


try:
    _arm62()
    _R62, _S62, _ADMIN62 = _setup62()
    _A62 = _p9_client(_ADMIN62)
    _idt3_chat62()
    _valve_chat62()
    _capture_shrink62()
    _priv_refusals62()
    _reach62()
    _escaped_paths62(_A62, _S62)
    _refusals_name_the_path62(_A62, _S62)
    _reason_whole62(_A62, _S62)
    _cfg_writes_audited62(_A62, _S62)
    _daily_time62(_A62, _S62)
    _account_probe62()
    _not_text62(_A62, _S62)
    _audit_floor62(_A62, _S62)
finally:
    _p9_restore_all()
    _cleanup62()

check("part62: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP62_START, repr(_P9_TRIPPED[_TRIP62_START:][:6]))
