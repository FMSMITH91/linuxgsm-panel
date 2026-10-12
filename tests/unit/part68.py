"""Part 68 of the unit suite: the sixth review's fixes (review 1012a, builder B).

Game files, cron, the privileged helper and routes:

* Daily restart (when empty): the hourly check is typed by the server's gamedig query-type
  override, as every player read is, when it is written, when the daily heal rewrites it, when a
  port move re-points it, and when the override itself changes. With the map alone, a game
  queryable only through the override got the unconditional `if true` and was restarted daily
  with players on it.

* Scheduled Tasks: an edit or delete naming a line that is no longer there (it changed since the
  page listed it) installs nothing and says so, in the viewer's language, instead of "Deleted"
  with nothing removed or "Updated" with a second schedule; deleting one of two identical tasks
  removes one.

* Jedi Knight II: the player list is asked for with JK2MV's `status notrunc`, so names are whole and
  a Kick by name resolves the player it names, not a lower slot whose name shares 15 characters.

* Return to Castle Wolfenstein: a Ban whose `banaddr` the server refused (a bot, a local client, a
  full ban list) answers that the player was kicked but not banned, not "Done.".

* Helper: `restart-flags` answers by the flag's own entry, so a flag linked to a root-only path
  is no existence oracle over that path, and a dangling one is listed as the remote form lists it.

* Helper: `--job` runs only inside its own SYSTEM unit, not a user manager's unit of the same name.

* Proxy trust: a JSON true in trusted_proxy_users trusts no uid (it was uid 1).

* Debug report: a long token holding a known name is redacted whole, not printed as fragments
  around the name's token.

* Routes: the log-timestamps switch's account refusal keeps its reason whole in the audit row; the
  Scheduled Tasks listing is refused, unread, for an account the panel will not read as; the port
  holders and account reasons that fill an install's or a refusal's sentence are translated with
  it; and host output in an install failure is cleaned of its escape codes.

HOW IT RUNS. On part12's Flask app and stubs, as part65 does; nothing reaches a transport.
"""
import contextlib as _ctx68
import io as _io68
import os
import shutil as _shutil68
import subprocess as _sp68  # nosec B404 - runs bash on the crontab pipeline this part's code builds
import tempfile as _tf68
import time as _time68
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper
from unit.part12 import (_P9_TRIPPED, _p9, _p9_client, _p9_core, _p9_json, _p9_ms, _p9_patch,
                         _p9_restore_all, _p9_sd, _p9_sf, _p9_sh, _p9_so, _p9_trip)
from flask import session as _session68
from panel.core import i18n as _i18n68
from panel.db.models import AuditLog, GameServer, RemoteServer, User, db
from panel.ops.debug_report import privacy as _pv68
from panel.ops.debug_report._base import Ctx as _Ctx68
from panel.ops.ssh_manager import cron as _cron68
from panel.ops.ssh_manager import game as _game68
from panel.security import auth as _auth68
from panel.services import game_ports as _gp68
import app as _app68

_TRIP68_START = len(_P9_TRIPPED)
_REWRITE68 = _p9_core._rewrite_crontab          # before any stub
_USER68 = "r16b68"
_mine68 = {"hosts": [], "servers": [], "users": []}
_CT68 = os.path.realpath(_tf68.mkdtemp(prefix="lgsm-unit-p68-ct-"))
# A game the built-in map has no gamedig type for, and the override an operator sets for it.
_GAME68, _QT68 = "pz", "projectzomboid"


def _arm68():
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part68's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_core, "run_command", _p9_trip("run_command"))
    _p9_patch(_p9_core, "shell_as_game_user", _p9_trip("shell_as_game_user"))
    _p9_patch(_p9_core, "run_privileged", _p9_trip("run_privileged"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))


def _setup68():
    with _p9.app_context():
        r = RemoteServer(name="p68-host", host="192.0.2.168", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p68-" + _USER68, short_name=_USER68,
                        game_type=_GAME68, port=16261, installed=True, status="offline",
                        daily_restart=True)
        admin = User(username="p68_admin", password_hash=_auth68.hash_password("Str0ng!passw0rd-p68"),
                     display_name="p68 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gs, admin])
        db.session.commit()
        _mine68["hosts"].append(r.id)
        _mine68["servers"].append(gs.id)
        _mine68["users"].append(admin.id)
        return r.id, gs.id, admin.id


def _cleanup68():
    with _p9.app_context():
        for i in _mine68["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
        AuditLog.query.filter(AuditLog.username.like("p68%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine68[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()
    _shutil68.rmtree(_CT68, ignore_errors=True)


# ── A04: the restart-when-empty check and the query-type override ─────────────────────────────
def _restart_typed68(client, sid):
    host = NS(id=-68, display_name="p68")
    _restart_written68(host)
    _restart_callers68(client, sid, host)


def _restart_written68(host):
    _p9_patch(_p9_core, "_gamedig_host", lambda server: "192.0.2.168")
    lines = []
    _p9_patch(_p9_core, "_rewrite_crontab",
              lambda server, user, grep_args, add_lines, **k: (lines.append(list(add_lines)),
                                                               (True, ""))[1])
    want = "--type %s 192.0.2.168:16261 " % _QT68
    # 1. Writing it: the toggle.
    _p9_core.set_daily_restart(host, _USER68, _USER68, _GAME68, 16261, True, at=(5, 0),
                               query_type=_QT68)
    written = lines[-1][-1] if lines else ""
    check("daily restart: a game the map has no gamedig type for, queried through the server's "
          "override, gets an hourly check that queries that type, not the unconditional restart",
          _GAME68 not in _p9_core.GAMEDIG_TYPE and want in written and "if true" not in written,
          written)
    # 2. The daily heal: an `if true` line (written before the override) is rewritten to query it.
    old = "10 * * * * " + _p9_core.daily_restart_check_cmd(_USER68, _USER68, "", None, 16261)
    _p9_patch(_p9_core, "run_privileged", lambda *a, **k: (old + "\n", "", 0))
    lines.clear()
    _cron68.upgrade_managed_cron_tracking(host, _USER68, _USER68, game_type=_GAME68, port=16261,
                                          query_type=_QT68)
    healed = lines[-1][-1] if lines else ""
    check("daily restart (heal): the daily upgrade rewrites an unconditional check to query the "
          "server's override type", want in healed and "if true" not in healed, healed)
    _p9_patch(_p9_core, "run_privileged", _p9_trip("run_privileged"))


def _restart_callers68(client, sid, host):
    # 3. Every caller of the heal hands the override over: the page, the daily pass, a port move.
    calls = []
    _p9_patch(_p9_sd._sm, "upgrade_managed_cron_tracking",
              lambda *a, **k: (calls.append(k.get("query_type")), False)[1])
    _gp68._cron_follows(host, _gp68._row(NS(id=1, remote_id=1, name="x", short_name=_USER68,
                                            lgsm_name=_USER68, game_type=_GAME68, port=1,
                                            installed=True, query_type=_QT68)), 16262)
    _p9_patch(_p9_sd, "game_account_write_refusal", lambda *a, **k: None)
    resp = client.post("/api/server/%d/query-type" % sid, json={"query_type": _QT68})
    check("daily restart (re-type): a port move, and setting the query-type override with daily "
          "restart on, rewrite the check with the override",
          calls == [_QT68, _QT68] and (_p9_json(resp) or {}).get("success") is True,
          repr((calls, _p9_json(resp))))
    seen = []
    _p9_patch(_app68, "ensure_node_tools_cron", lambda r: None)
    _p9_patch(_p9_sd._sm, "upgrade_managed_cron_tracking",
              lambda remote, user, *a, **k: seen.append((user, k.get("query_type"))))
    _app68._node_tools_cron_pass(_p9)
    check("daily restart (re-type): ...and so does the daily pass over every server",
          (_USER68, _QT68) in seen, repr(seen))
    _p9_patch(_p9_sd._sm, "upgrade_managed_cron_tracking",
              lambda *a, **k: (calls.append(k.get("query_type")), False)[1])
    with _p9.app_context():
        db.session.get(GameServer, sid).daily_restart = False
        db.session.commit()
    calls.clear()
    client.post("/api/server/%d/query-type" % sid, json={"query_type": ""})
    check("daily restart (re-type): ...and with daily restart off the crontab is not touched "
          "(control)", calls == [], repr(calls))


# ── A04: an edit or delete naming a line that has changed ─────────────────────────────────────
def _crontab68(existing, call):
    """`call()` with _rewrite_crontab's pipeline run in a real bash over a stand-in `crontab`.

    -> (its answer, the crontab after, whether anything was installed).
    """
    store = os.path.join(_CT68, "store")
    tool = os.path.join(_CT68, "crontab")
    with open(tool, "w", encoding="utf-8") as fh:
        fh.write('#!/bin/sh\nif [ "$1" = "-l" ]; then cat "$CT_STORE"; exit 0; fi\n'
                 'cp "$1" "$CT_STORE" && echo installed >> "$CT_STORE.log"\n')
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in the suite runs itself
    os.chmod(tool, 0o700)
    with open(store, "w", encoding="utf-8") as fh:
        fh.write(existing)
    if os.path.exists(store + ".log"):
        os.unlink(store + ".log")

    def _shell(server, user, sh, timeout=30, selfname=None, scope=False):
        env = dict(os.environ, PATH=_CT68 + os.pathsep + os.environ.get("PATH", ""),
                   CT_STORE=store, TMPDIR=_CT68)
        p = _sp68.run(["bash", "-c", sh],  # nosec B603 B607 - bash on the pipeline under test
                      capture_output=True, text=True, env=env, timeout=20, check=False)
        return p.stdout, p.stderr, p.returncode
    _p9_patch(_p9_core, "shell_as_game_user", _shell)
    try:
        res = call()
    finally:
        _p9_patch(_p9_core, "shell_as_game_user", _p9_trip("shell_as_game_user"))
    with open(store, encoding="utf-8") as fh:
        now = fh.read()
    return res, now, os.path.exists(store + ".log")


def _as_lang68(lang, call):
    """`call()` with the admin's UI language set to `lang`, then English again."""
    with _p9.app_context():
        db.session.get(User, _ADMIN68).language = lang
        db.session.commit()
    try:
        return call()
    finally:
        with _p9.app_context():
            db.session.get(User, _ADMIN68).language = "en"
            db.session.commit()


def _cron_stale68(client, sid):
    gone = "0 9 * * * /bin/true changed"
    _cron_stale_pipeline68(gone)
    _cron_stale_route68(client, sid, gone)


def _cron_stale_pipeline68(gone):
    host = NS(id=-68, display_name="p68")
    _p9_patch(_p9_core, "_rewrite_crontab", _REWRITE68)
    _p9_patch(_cron68, "_wrap_cron_command", lambda server, user, command: command)
    have = "0 1 * * * /bin/true a\n0 2 * * * /bin/true b\n"
    dres, dnow, dinst = _crontab68(have, lambda: _cron68.delete_cron_job(host, _USER68, gone))
    ures, unow, uinst = _crontab68(have, lambda: _cron68.update_cron_job(
        host, _USER68, gone, "0 3 * * *", "/bin/true c"))
    check("cron: a delete or an edit naming a line that is no longer in the crontab installs "
          "nothing and says the task changed — not \"Deleted\" with nothing removed, or "
          "\"Updated\" with a second schedule beside the old one",
          dres[0] is False and ures[0] is False and "changed since the page loaded" in dres[1]
          and dres[1] == ures[1] and (dnow, unow) == (have, have) and not (dinst or uinst),
          repr((dres, ures, dnow, unow, dinst, uinst)))
    twin = "0 2 * * * /bin/true b"
    res, now, _inst = _crontab68(have + twin + "\n", lambda: _cron68.delete_cron_job(
        host, _USER68, "  " + twin + " "))
    check("cron: ...deleting one of two identical tasks removes one, and a line still there is "
          "found whitespace and all (control)",
          res[0] is True and now == have, repr((res, now)))
    res, now, _inst = _crontab68(have, lambda: _cron68.update_cron_job(
        host, _USER68, twin, "0 3 * * *", "/bin/true c"))
    check("cron: ...and an edit of a line still there replaces it (control)",
          res[0] is True and now == "0 1 * * * /bin/true a\n0 3 * * * /bin/true c\n",
          repr((res, now)))


def _cron_stale_route68(client, sid, gone):
    # The route says it in the viewer's language.
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_p9_sf._sm, "delete_cron_job", _cron68.delete_cron_job)
    _p9_patch(_p9_core, "_rewrite_crontab", lambda *a, **k: (False, _p9_core.CRON_DROP_GONE))
    resp = _as_lang68("es", lambda: client.post("/api/server/%d/cron/delete" % sid,
                                                json={"raw": gone}))
    got = _p9_json(resp) or {}
    check("cron (es viewer): ...the route answers that refusal in the viewer's language",
          got.get("success") is False and "ha cambiado desde que se cargó" in (got.get("message") or ""),
          repr(got))


# ── A04: JK2MV's `status` and names over 15 characters ───────────────────────────────────────
def _jk2mv68(rows, notrunc):
    """JK2MV's SV_Status_f reply ("%3i %5i %4i %s^7%s %7i %21s %5i %5i"): without `notrunc` each
    name is cut to 15 characters (these have no colour codes) and padded to 15."""
    out = ("map: ffa_bespin\n"
           "num score ping name            lastmsg address               qport rate\n"
           "--- ----- ---- --------------- ------- --------------------- ----- -----\n")
    for i, nm, ad in rows:
        shown = nm if notrunc else nm[:15]
        out += "%3i %5i %4i %s^7%s %7i %21s %5i %5i\n" % (
            i, 0, 50, shown, " " * max(0, 15 - len(shown)), 50, ad, 1234, 25000)
    return out + "\n"


def _jk2_notrunc68():
    rows = [(0, "LongPlayerNameAB", "203.0.113.5:28070"), (1, "LongPlayerNameA", "203.0.113.6:28071"),
            (2, "An Even Longer Player Name", "203.0.113.7:28072")]
    sent = []

    def _send(server, user, cmd, **k):
        sent.append(cmd)
        return ("PANE_MARK 1200 17 80\n", "", 0)

    def _capture(*a, **k):
        cmd = sent[-1] if sent else ""
        return (cmd + "\n" + _jk2mv68(rows, cmd.split()[1:] == ["notrunc"]), "", 0)
    _p9_patch(_p9_core, "send_console_command", _send)
    _p9_patch(_game68, "capture_console", _capture)
    _p9_patch(_game68, "time", NS(sleep=lambda s: None, time=_time68.time, gmtime=_time68.gmtime,
                                  strftime=_time68.strftime, monotonic=_time68.monotonic))
    got = [(p["num"], p["name"]) for p in _game68.console_player_list(None, _USER68, "jk2") or []]
    hit = _game68._resolve_from_console(None, _USER68, "jk2", "LongPlayerNameA", None) or {}
    long_hit = _game68._resolve_from_console(None, _USER68, "jk2", "An Even Longer Player Name",
                                             None) or {}
    check("players (JK2MV): the list is asked for with `status notrunc`, so names over 15 "
          "characters are whole, and a Kick by name resolves the slot it names — not a lower "
          "slot whose name shares its first 15 characters",
          sent[0] == "status notrunc" and hit.get("num") == 1 and long_hit.get("num") == 2
          and got == [(0, "LongPlayerNameAB"), (1, "LongPlayerNameA"),
                      (2, "An Even Longer Player Name")], repr((sent, got, hit, long_hit)))
    del sent[:]
    _game68.console_player_list(None, _USER68, "q3")
    check("players (JK2MV): ...and another idTech3 game still sends a bare `status` (control)",
          sent == ["status"], repr(sent))


# ── A04 lead: iortcw's banaddr refusing a client that is not on the internet ────────────────
def _rtcw_ban68(client, sid):
    sent, reply = [], {"text": ""}

    def _send(server, user, cmd, **k):
        sent.append((cmd, k.get("mark")))
        return ("PANE_MARK 1200 17 80\n", "", 0)
    _p9_patch(_p9_core, "send_console_command", _send)
    _p9_patch(_game68, "capture_console", lambda *a, **k: (reply["text"], "", 0))
    _p9_patch(_game68, "time", NS(sleep=lambda s: None, time=_time68.time, gmtime=_time68.gmtime,
                                  strftime=_time68.strftime, monotonic=_time68.monotonic))
    got = {}
    for tag, text in (("bot", "banaddr 2; kicknum 2\nError: Can ban players connected via the "
                              "internet only.\nBot1 was kicked\n"),
                      ("full", "Error: Maximum number of bans/exceptions exceeded.\n"),
                      ("added", "Added ban: 203.0.113.5/32\nAlice was kicked\n"),
                      ("no reply yet", "")):
        reply["text"] = text
        got[tag] = _game68.moderate(None, _USER68, "rtcw", "ban", num="2")
    check("moderation (iortcw): a Ban whose banaddr the server refused — a bot or local client, a "
          "full ban list — answers that the player was kicked but not banned, not \"Done.\"",
          all(got[t][0] is False and "kicked but not banned" in got[t][1] for t in ("bot", "full"))
          and sent[0] == ("banaddr 2; kicknum 2", True), repr((got, sent[:1])))
    check("moderation (iortcw): ...a ban the server added, or a reply not seen yet, is \"Done.\" "
          "(control)", got["added"] == (True, "Done.") and got["no reply yet"] == (True, "Done."),
          repr(got))
    _p9_patch(_p9_sd._sm, "moderate", lambda *a, **k: got["bot"])
    resp = _as_lang68("fr", lambda: client.post("/api/server/%d/moderate" % sid,
                                                json={"action": "kick", "num": "2"}))
    msg = (_p9_json(resp) or {}).get("message") or ""
    check("moderation (fr viewer): ...and the Players panel says it in the viewer's language",
          "expulsé mais pas banni" in msg, msg)


# ── A07: restart-flags does not follow the flag ─────────────────────────────────────────────
def _restart_flags68():
    root = os.path.join(_CT68, "home")
    target = os.path.join(_CT68, "root-only")
    with open(target, "w", encoding="utf-8") as fh:
        fh.write("x")
    for acct, how in (("plain", "file"), ("toreal", target), ("todead", target + "-not-there"),
                      ("none", None)):
        os.makedirs(os.path.join(root, acct))
        flag = os.path.join(root, acct, ".restart-pending")
        if how == "file":
            open(flag, "w", encoding="utf-8").close()
        elif how:
            os.symlink(how, flag)
    _p9_patch(_helper, "HOME_ROOT", root)
    buf = _io68.StringIO()
    with _ctx68.redirect_stdout(buf):
        rc = _helper.do_restart_flags([], None)
    got = buf.getvalue().split()
    check("helper restart-flags: a flag is answered by its own entry — a link to an existing "
          "root-only path and a link to nothing are both listed, so the answer says nothing about "
          "the target (and matches the remote `ls -1d`); no flag is not listed",
          rc == 0 and got == ["plain", "todead", "toreal"], repr((rc, got)))


# ── A07 lead: --job inside a user manager's unit of the same name ─────────────────────────────
def _own_unit68():
    unit = "linuxgsm-panel-restore.service"
    got = {}
    for tag, cg in (("system", "/system.slice/" + unit),
                    ("user app.slice", "/user.slice/user-1000.slice/user@1000.service/app.slice/" + unit),
                    ("user 'system' slice", "/user.slice/user-1000.slice/user@1000.service/system.slice/"
                     + unit),
                    ("lingering, no user.slice", "/user@1000.service/system.slice/" + unit),
                    ("panel's own", "/system.slice/linuxgsm-panel.service"),
                    ("unreadable", None)):
        _p9_patch(_helper, "_cgroup_of", lambda pid, cg=cg: cg)
        got[tag] = _helper._in_own_unit(unit)
    check("helper --job: runs inside its own system unit, and is refused in a user manager's unit "
          "of the same name (app.slice, or a slice the user named `system`), in the panel's own "
          "unit, or when the cgroup cannot be read",
          got == {"system": True, "user app.slice": False, "user 'system' slice": False,
                  "lingering, no user.slice": False, "panel's own": False, "unreadable": False},
          repr(got))


# ── A07 lead: trusted_proxy_users true ───────────────────────────────────────────────────────
def _proxy_bool68():
    base = _auth68._trusted_proxy_uids([])
    got = (_auth68._trusted_proxy_uids([True]) - base, _auth68._trusted_proxy_uids(True) - base,
           _auth68._trusted_proxy_uids([False]) - base, _auth68._trusted_proxy_uids([4242]) - base)
    check("proxy trust: a JSON true or false in trusted_proxy_users trusts no uid (true was uid 1, "
          "daemon); a uid still counts (control)",
          got == (frozenset(), frozenset(), frozenset(), frozenset({4242})), repr(got))


# ── A06 lead: a long token with a known name inside it ─────────────────────────────────────────
def _named_token68():
    st = _pv68._State()
    st.add("zephyrhost7731", "host", 1)
    ctx = _Ctx68()
    ctx._memo["privacy"] = (True, st)
    left, right = "Q2hhcmxpZUJyb3du" + "eHl6", "OTk4NzY1NDMyMWFi" + "Y2Rl"
    out = _pv68.scrub(ctx, "seen %s-zephyrhost7731-%s done\nplain zephyrhost7731 here" % (left, right))
    check("debug report privacy: a 28+-character token with a known name inside it is redacted "
          "whole, not printed as fragments under 28 around the name's token; the name elsewhere is "
          "still its token (control)",
          left not in out and right not in out and "[redacted]" in out and "plain [host-1] here" in out,
          out)


# ── A08: the routes ──────────────────────────────────────────────────────────────────────────
def _rows68(sid, action):
    with _p9.app_context():
        return [r.detail for r in AuditLog.query.filter_by(game_server_id=sid, action=action)
                .order_by(AuditLog.id).all()]


def _ts_refusal68(client, sid):
    why = _p9_sh._privileged_write_msg("ubuntu", "it is in the sudo group", reading=False)
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: why)
    resp = client.post("/api/server/%d/log-timestamps" % sid, json={"enabled": False})
    rows = _rows68(sid, "set_log_timestamps")
    check("routes (log timestamps): an account refusal's audit row keeps the whole reason (%d "
          "characters), not cut at 250 mid-sentence" % len(why),
          resp.status_code == 409 and len(why) > 250 and rows[-1:] == ["refused: " + why],
          repr((resp.status_code, rows[-1:])))


def _cron_read_refused68(client, sid):
    why = _p9_sh._privileged_write_msg("ubuntu", "it is in the sudo group", reading=True)
    listed, upgraded = [], []
    _p9_patch(_p9_sf._sm, "list_cron_jobs", lambda *a, **k: (listed.append(a), [])[1])
    _p9_patch(_p9_sf._sm, "upgrade_managed_cron_tracking", lambda *a, **k: upgraded.append(a))
    _p9_patch(_p9_sf, "game_account_write_refusal",
              lambda remote, user, now=None, reading=False: why if reading else None)
    resp = client.get("/api/server/%d/cron" % sid)
    got = _p9_json(resp) or {}
    rows = _rows68(sid, "list_cron")
    check("routes (cron): the Scheduled Tasks listing of an account the panel will not read as is "
          "refused (409, the reason as `error`) and audited, and the crontab is never listed",
          resp.status_code == 409 and got.get("error") == why and listed == [] and upgraded == []
          and rows[-1:] == ["refused: " + why], repr((resp.status_code, got, listed, rows[-1:])))
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: None)
    resp = client.get("/api/server/%d/cron" % sid)
    check("routes (cron): ...an account it may read as is listed (control)",
          resp.status_code == 200 and (_p9_json(resp) or {}).get("jobs") == [] and len(listed) == 1,
          repr((resp.status_code, _p9_json(resp), listed)))


def _holders_translated68():
    gs = NS(id=1, port=27015, game_type="csgo", name="a")
    rows = [gs, NS(id=2, port=27115, game_type="csgo", name="rust1")]
    job = NS(withheld={27200}, listening_read=True)
    def slot(value):
        """`value` as the slot of a sentence: tr() translates it there only when it is a Sentence."""
        return _i18n68.tr(_i18n68.Sentence("{v}", v=value))
    with _p9.test_request_context():
        _session68["lang"] = "es"
        held = _p9_ms.withheld_game_ports(rows, gs, {22})
        verdict = {}
        _p9_sh._fold_acct_line(verdict, ["ACCT", "admin1", "1000", "sudo", "admin1"])
        _p9_sh._fold_acct_line(verdict, ["ACCT", "zero", "0", "zero"])
        refused = _p9_sh._refused_by_name(NS(username="ubuntu"), ["root", "ubuntu"], False)
        got = {
            "sibling": slot(held.get(27115, "")),
            "protected": slot(held.get(22, "")),
            "listening": slot(_p9_ms._post_start_port_refused(job, None, gs, 27200) or ""),
            "not a port": slot(_p9_ms._post_start_port_refused(job, None, gs, 0) or ""),
            "group": slot(verdict.get("admin1", "")),
            "uid 0": slot(verdict.get("zero", "")),
            "root": slot(refused.get("root", "")),
            "login": slot(refused.get("ubuntu", "")),
            "outcome": _i18n68.tr(_i18n68.Sentence(
                "{name} installed, but port {port} is already used by {holder}, so the panel did "
                "not open it in the firewall. Free that port on the host, or change it in the "
                "game's own config (Files & Config).", name="x", port=27115, holder=held[27115])),
        }
    want = {"sibling": "'rust1' en este host", "protected": "el SSH de este host o el propio panel",
            "listening": "otra cosa ya escuchaba en él antes de que arrancara este servidor",
            "not a port": "no es un puerto",
            "group": "está en el grupo sudo, que puede convertirse en root",
            "uid 0": "es el uid 0 (root)", "root": "es root",
            "login": "es la cuenta con la que el panel inicia sesión en este host"}
    check("i18n (es viewer): the port holders and the account reasons that fill an install's or a "
          "refusal's sentence are translated with it, not left in English inside it",
          {k: got[k] for k in want} == want and "'rust1' en este host" in got["outcome"]
          and "on this host" not in got["outcome"], repr(got))
    check("i18n: ...and each is still its English as a str, for the audit rows and logs (control)",
          held[27115] == "'rust1' on this host" and verdict["admin1"] ==
          "it is in the sudo group, which can become root", repr((held, verdict)))


def _install_output_clean68():
    _p9_patch(_p9_ms, "host_account_state", lambda remote, user: "absent")
    _p9_patch(_p9_ms._sm, "create_game_user",
              lambda remote, user, timeout=15: ("", "\x1b[31museradd: group 'g' does not exist\x1b[0m\r\n"
                                                "  try again\n", 9))
    ok, why, _retry = _p9_ms.prepare_install_account(None, -68, _USER68 + "x", True)
    check("install: useradd's colour codes, carriage returns and padding are cleaned out of the "
          "failure, as readable_reason cleans every other host output on the row",
          ok is False and "\x1b" not in why and "\r" not in why and "\n" not in why
          and why.endswith("useradd: group 'g' does not exist try again"), repr(why))


try:
    _arm68()
    _R68, _S68, _ADMIN68 = _setup68()
    _A68 = _p9_client(_ADMIN68)
    _restart_typed68(_A68, _S68)
    _cron_stale68(_A68, _S68)
    _jk2_notrunc68()
    _rtcw_ban68(_A68, _S68)
    _restart_flags68()
    _own_unit68()
    _proxy_bool68()
    _named_token68()
    _ts_refusal68(_A68, _S68)
    _cron_read_refused68(_A68, _S68)
    _holders_translated68()
    _install_output_clean68()
finally:
    _p9_restore_all()
    _cleanup68()

check("part68: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP68_START, repr(_P9_TRIPPED[_TRIP68_START:][:6]))
