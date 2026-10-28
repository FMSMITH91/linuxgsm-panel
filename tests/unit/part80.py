"""Part 80 of the unit suite: the tenth review's fixes (review 1013a, builder B).

Game files, the debug report, system_ops and routes:

* A GameServer row whose port is REAL infinity: every gamedig reader answers "unknown" rather than
  raising OverflowError — the player count a scheduled backup asks first among them, which failed
  the backup every hour. The shared player list's fallback runs for real here (part76 stubbed it).

* A port moved at panel start whose account the panel may not write as: the audit row says the
  restart-when-empty check was not repointed (it said nothing, and the check kept asking the old
  port: the neighbour's).

* A host call that RAISES is audited as failed, as the same failure answered with an rc is: a
  direct-SSH host that is down raised past every route's log_action, so a console command, a
  custom command, a kick or a firewall change against it left no trace in /logs.

* The panel's own `sudo -n` argv runs, and a privileged verb run as root or through the no-helper
  shell, run in C.UTF-8: sudo's refusal and ufw's "Default:" line are read by their English words.

HOW IT RUNS. On part12's Flask app and stubs, as part77 does; the locale checks run `env` for real
(no sudo, no host) and replace the module's subprocess handle where the argv would be sudo.
"""
import os
import shlex as _shlex80
import subprocess as _subprocess80  # nosec B404 - runs a Python child that prints its locale
import sys as _sys80
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_audit_count, _p9_client,
                         _p9_core, _p9_patch, _p9_patch_sm, _p9_rv, _p9_restore_all, _p9_sd, _p9_sf, _p9_so)
from panel.core import i18n as _i18n80
from panel.db.models import AuditLog, CustomCommand, GameServer, RemoteServer, User, db
from panel.ops.debug_report import network as _net80
from panel.ops.ssh_manager import cron as _cron80, game as _game80
from panel.routes import _shared as _sh80
from panel.security import auth as _auth80
from panel.services import game_ports as _gp80

_TRIP80_START = len(_P9_TRIPPED)
_mine80 = {"hosts": [], "servers": [], "users": [], "cmds": []}
# Taken before _p9_arm replaces it with the tripwire: the locale check runs `env` through it.
_REAL_EXEC80 = _p9_core._exec_local_argv


def _setup80():
    with _p9.app_context():
        r = RemoteServer(name="p80-host", host="p80.example.invalid", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p80-css", short_name="p80css", game_type="css",
                        port=27080, installed=True, status="online")
        admin = User(username="p80_admin", password_hash=_auth80.hash_password("Str0ng!passw0rd-p80"),
                     display_name="p80 admin", is_superadmin=True, is_active=True)
        cmd = CustomCommand(name="p80say", command_template="say hello", scope_type="all",
                            enabled=True)
        db.session.add_all([gs, admin, cmd])
        db.session.commit()
        _mine80["hosts"].append(r.id)
        _mine80["servers"].append(gs.id)
        _mine80["users"].append(admin.id)
        _mine80["cmds"].append(cmd.id)
        return r.id, gs.id, admin.id, cmd.id


def _cleanup80():
    with _p9.app_context():
        for i in _mine80["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
        for i in _mine80["hosts"]:
            AuditLog.query.filter_by(remote_id=i).delete()
        AuditLog.query.filter(AuditLog.username.like("p80%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((CustomCommand, "cmds"), (GameServer, "servers"), (User, "users"),
                           (RemoteServer, "hosts")):
            for i in _mine80[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A REAL-infinity port is "no port" to every gamedig reader
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Past80(Exception):
    """Raised by the step after run_game_backup's player check: the check answered, and let it on."""


def _past80(*a, **k):
    raise _Past80()


def _outcome80(call):
    """call()'s answer, or the name of the exception it raised."""
    try:
        return call()
    except Exception as exc:  # noqa: BLE001 - the raise IS the failure being checked for
        return "raised " + type(exc).__name__


def _inf_readers80(srv, inf, ran):
    got = {
        "player_count": _outcome80(lambda: _cron80.player_count(srv, "p80u", "css", inf)),
        "player_slots": _outcome80(lambda: _cron80.player_slots(srv, "p80u", "css", inf)),
        "game_map": _outcome80(lambda: _cron80.game_map(srv, "p80u", "css", inf)),
        "version": _outcome80(lambda: _game80._queried_version(srv, "p80u", "css", inf)),
        "list": _outcome80(lambda: _game80._gamedig_player_list(srv, "p80u", "css", inf)),
        # The shared list's own fallback, unstubbed: part76's check replaced it with a constant.
        "shared list": _outcome80(lambda: _game80.player_list(srv, "p80u", "css", inf, shared=True)),
        "backup check": _outcome80(lambda: _game80._backup_players_online(srv, "p80u", "css", inf,
                                                                            None)),
    }
    want = {"player_count": None, "player_slots": (None, None, None), "game_map": "",
            "version": "", "list": None, "shared list": None, "backup check": None}
    check("ports: a REAL-infinity port row is 'unknown' to every gamedig reader — player_count, "
          "player_slots, game_map, the version, both player lists (the shared one's fallback "
          "raised the OverflowError it caught) and the backup's player check — and nothing is run",
          (got, ran) == (want, []), repr((got, ran[:2])))


def _inf_port80():
    inf, ran = float("inf"), []
    _p9_patch(_p9_core, "_gamedig_host", lambda server: "p80.example.invalid")
    _p9_patch(_p9_core, "shell_as_game_user",
              lambda server, user, cmd, **k: ran.append(cmd) or ("", "", 0))
    srv = NS(id=-80)
    _inf_readers80(srv, inf, ran)

    _p9_patch(_cron80, "_ensure_backup_headroom", _past80)
    try:
        _game80.run_game_backup(srv, "p80u", "p80u", game_type="css", port=inf, force=False)
        past = "returned"
    except _Past80:
        past = "past"
    except Exception as exc:  # noqa: BLE001 - which exception is the answer
        past = type(exc).__name__
    check("ports: ...so a scheduled backup of that server goes on as for any unknown count (it "
          "failed every hour as \"backup error (OverflowError)\")", past == "past", past)

    ran.clear()
    _cron80.player_count(srv, "p80u", "css", 27015)
    check("ports: ...while a real port is still queried, at that port (control)",
          [":27015 " in c for c in ran] == [True], repr(ran))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A port moved at start, on an account the panel may not write as
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cron_note80():
    why = _i18n80.Sentence("p80: the account can become root.")
    asked = []
    _p9_patch(_sh80, "game_account_write_refusal", lambda remote, user, **k: why)
    _p9_patch_sm("upgrade_managed_cron_tracking",
                 lambda *a, **k: asked.append(a) or True)
    row = NS(name="p80-css", short_name="p80css", lgsm_name="p80css", game_type="css",
             query_type=None, port=27080)
    refused = _gp80._cron_follows(NS(id=-80), row, 27081)
    _p9_patch(_sh80, "game_account_write_refusal", lambda remote, user, **k: None)
    _p9_patch_sm("upgrade_managed_cron_tracking", lambda *a, **k: asked.append(a) or False)
    plain = _gp80._cron_follows(NS(id=-80), row, 27081)
    check("port resync: an account the panel may not write as says, in the port_resync row, that "
          "its restart-when-empty check was not pointed at the new port, and why (it returned \"\", "
          "and the row read as if only the firewall was left); the cron is not written",
          refused == ("its restart-when-empty check, if it has one, was not pointed at port 27081 "
                      "(p80: the account can become root.)") and len(asked) == 1,
          repr((refused, asked)))
    check("port resync: ...and a plain account whose check did not need repointing still adds no "
          "note (control)", plain == "", repr(plain))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A host call that raises is audited as failed
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _down80(*a, **k):
    raise ConnectionError("Connection to p80.example.invalid:22 timed out.")


def _post80(client, url, body):
    try:
        return client.post(url, json=body).status_code
    except ConnectionError:      # no error handler on part12's app: the raise is the 500
        return "raised"


_WHY80 = "Connection to p80.example.invalid:22 timed out."


def _raised_rows80(client, rid, sid, cid):
    """POST each route with its host call raising: {action: (rows added, success, target, detail)}."""
    actions = ("send_command", "custom_command", "moderate_kick", "remote_port_open", "cron_add")
    before = {a: _p9_audit_count(a) for a in actions}
    _p9_patch(_p9_sf, "send_console_command", _down80)
    _p9_patch(_p9_sd, "send_console_command", _down80)
    _p9_patch_sm("moderate", _down80)
    _p9_patch(_p9_rv, "remote_ufw_open_port", _down80)
    _p9_patch(_p9_sf, "_write_refused", lambda *a, **k: None)
    _p9_patch(_p9_sf, "add_cron_job", _down80)
    for url, body in (("/api/command/%d" % sid, {"command": "status"}),
                      ("/api/server/%d/custom-command/%d" % (sid, cid), {}),
                      ("/api/server/%d/moderate" % sid, {"action": "kick", "target": "Bob"}),
                      ("/api/remote/%d/firewall/open" % rid, {"port": "27090"}),
                      ("/api/server/%d/cron" % sid, {"schedule": "0 4 * * *", "command": "restart"})):
        _post80(client, url, body)
    out = {}
    for a in actions:
        r = _p9_audit(a)
        out[a] = (_p9_audit_count(a) - before[a], r.success, r.target, r.detail)
    return out


def _audit_raise80(client, rid, sid, cid):
    got = _raised_rows80(client, rid, sid, cid)
    console = {a: got[a] for a in ("send_command", "custom_command", "moderate_kick")}
    check("audit: a console command, a custom command and a kick that RAISED (a direct-SSH host "
          "that is down) are each audited once, as failed, with the transport's reason — the "
          "same click against a tailscale host was audited and this one left no row",
          console == {"send_command": (1, False, "p80-css", "status - " + _WHY80),
                      "custom_command": (1, False, "p80-css", "p80say: say hello - " + _WHY80),
                      "moderate_kick": (1, False, "p80-css", "Bob - " + _WHY80)}, repr(console))
    others = {a: got[a] for a in ("remote_port_open", "cron_add")}
    check("audit: ...and so are a firewall change and a scheduled-task write that raised (every "
          "route that audits a failed answer), the target as a failed answer records it",
          others == {"remote_port_open": (1, False, "p80-host:27090/tcp", "both - " + _WHY80),
                     "cron_add": (1, False, "p80-css", "0 4 * * * - " + _WHY80)}, repr(others))

    n = _p9_audit_count("send_command")
    _p9_patch(_p9_sf, "send_console_command", lambda *a, **k: ("", "sudo: refused", 1))
    client.post("/api/command/%d" % sid, json={"command": "status"})
    answered = (_p9_audit_count("send_command") - n, _p9_audit("send_command").detail)
    check("audit: ...while a send the host ANSWERED with a failure is still one row, not two "
          "(control)", answered == (1, "status"), repr(answered))
    _audit_sync80(sid)


def _audit_sync80(sid):
    with _p9.app_context():
        gs = db.session.get(GameServer, sid)
        _p9_patch_sm("run_as_game_user", _down80)
        _p9_patch(_p9_sd, "_after_power_action", lambda *a, **k: None)
        m = _p9_audit_count("details_server")
        try:
            _p9_sd._run_sync_action(_p9, gs, gs.remote, "details", None, "p80-bot")
            out = "returned"
        except ConnectionError:
            out = "raised"
    row = _p9_audit("details_server")
    seen = (out, _p9_audit_count("details_server") - m, row.success, row.username)
    check("audit: a short server action (the route and the chat bots both run it) that raised is "
          "audited as failed under the caller's name, and still raises to its caller",
          seen == ("raised", 1, False, "p80-bot"), repr(seen))


def _audit_queued80(sid):
    """A queued stop-when-empty: _run_queued_action's docstring promises a row for every attempt."""
    with _p9.app_context():
        gs = db.session.get(GameServer, sid)
        gs.stop_pending, gs.restart_pending = True, False
        db.session.commit()
        _p9_patch_sm("run_as_game_user", _down80)
        _p9_patch(_sh80, "_mark_expected_offline", lambda *a, **k: None)
        m = _p9_audit_count("stop_server")
        try:
            _sh80._run_queued_action(_p9, gs)
            out = "returned"
        except ConnectionError:
            out = "raised"
        gs = db.session.get(GameServer, sid)
        gs.stop_pending = False
        db.session.commit()
        # The raised run is counted as an attempt now (review 1015a); the count is per server id,
        # and SQLite hands this one to the next row created.
        _sh80._queued_action_failures.pop(sid, None)
    row = _p9_audit("stop_server")
    seen = (out, _p9_audit_count("stop_server") - m, row.success, row.username)
    check("audit: a queued stop-when-empty whose run raised is audited as failed, by the system "
          "(\"every attempt is audited\" held only for a transport that answers instead of raising), "
          "and still raises to the sweep that ran it", seen == ("raised", 1, False, "system"),
          repr(seen))


def _audit_bootstrap80(rid):
    _p9_patch(_sh80, "remote_bootstrap_vps", _down80)
    n = _p9_audit_count("remote_vps_bootstrap")
    with _p9.app_context():
        try:
            _sh80._BootstrapRun(_p9, rid, {"status": "running", "log": []})._bootstrap({})
            out = "returned"
        except ConnectionError:
            out = "raised"
    row = _p9_audit("remote_vps_bootstrap")
    seen = (out, _p9_audit_count("remote_vps_bootstrap") - n, row.success, row.target, row.detail)
    check("audit: a VPS bootstrap whose run raised is audited as failed, on its host, and the job "
          "still sees the raise (it left no row at all)",
          seen == ("raised", 1, False, "p80-host", _WHY80), repr(seen))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The panel host's own privileged argv runs, in C.UTF-8
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Os80(object):
    """os, with geteuid answering 0."""

    def __getattr__(self, name):
        if name == "geteuid":
            return lambda: 0
        return getattr(os, name)


def _envs80():
    """A fake subprocess module that records each call's (argv, env) and starts nothing."""
    seen = []

    def _popen(argv, **kw):
        seen.append((argv, kw.get("env") or {}))
        raise OSError("p80: not started")

    def _run(argv, **kw):
        seen.append((argv, kw.get("env") or {}))
        return NS(returncode=1, stdout="", stderr="")
    fake = NS(Popen=_popen, run=_run, PIPE=_subprocess80.PIPE, DEVNULL=_subprocess80.DEVNULL,
              TimeoutExpired=_subprocess80.TimeoutExpired)
    return fake, seen


_LOCALE_KEYS80 = ("LC_ALL", "LANG", "LANGUAGE")
_PINNED80 = {"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "LANGUAGE": ""}


def _locale_of80(env):
    """The three locale variables of `env`, as a dict ("<unset>" for one it lacks)."""
    return {k: env.get(k, "<unset>") for k in _LOCALE_KEYS80}


# The child's own locale variables, printed by a Python child (not `env`: the suite's PATH shims
# read `env` as a wrapper command).
_SHOW80_CODE = "\n".join(("import os", "for k in ('LC_ALL', 'LANG', 'LANGUAGE'):",
                           "    print('%s=%s' % (k, os.environ.get(k, '<unset>')))"))
_SHOW80 = (_sys80.executable, "-c", _SHOW80_CODE)


def _env_lines80(out):
    return dict(ln.partition("=")[::2] for ln in (out or "").splitlines() if "=" in ln)


def _german_env80(call):
    """call() with the panel's own environment set to a German host's (LANG and LANGUAGE)."""
    saved = {k: os.environ.get(k) for k in _LOCALE_KEYS80}
    os.environ.update(LANG="de_DE.UTF-8", LANGUAGE="de:en")
    os.environ.pop("LC_ALL", None)
    try:
        return call()
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _three_runs80():
    # The real subprocess for these three runs, as part58 does: _p9_arm's handle is a tripwire.
    armed = _p9_so.subprocess
    _p9_so.subprocess = _subprocess80
    try:
        return {"argv": _REAL_EXEC80(list(_SHOW80), timeout=10)[0],
                "shell": _p9_so._run_verb_shell(" ".join(_shlex80.quote(a) for a in _SHOW80),
                                                timeout=10, sudo=False)[0],
                "debug": _p9_so._debug_run(list(_SHOW80), timeout=10)[0]}
    finally:
        _p9_so.subprocess = armed


def _locale_real80():
    got = {name: _locale_of80(_env_lines80(out)) for name, out in _german_env80(_three_runs80).items()}
    check("locale: on a German host, the panel's own argv runs (`sudo -n <helper>`, a tool run "
          "directly), the no-helper shell form of a privileged verb and the debug report's reads "
          "all run in C.UTF-8 with LANGUAGE empty (sudo's \"Ein Passwort ist notwendig\" never "
          "matched its refusal, ufw's \"Voreinstellung:\" never matched \"Default:\")",
          got == {"argv": _PINNED80, "shell": _PINNED80, "debug": _PINNED80}, repr(got))


def _locale_fake80():
    fake, seen = _envs80()
    _p9_patch(_p9_so, "subprocess", fake)
    _p9_patch(_net80, "subprocess", fake)
    _p9_patch(_p9_so, "_helper_present", lambda: False)
    _p9_patch(_p9_so, "os", _Os80())
    _p9_so._run_verb_once("ufw-status", ["verbose"], 10, False)          # root, no helper
    _p9_patch(_p9_so, "os", os)
    _p9_so._helper_probe_run()                                           # sudo -n <helper> --list-verbs
    _net80.sudo_n_verb("ufw-status", ["verbose"], 10)                    # sudo -n ufw status verbose
    _p9_patch(_p9_so, "_helper_present", lambda: True)
    _p9_so._write_root_file(next(iter(_p9_so._WRITE_TARGET_BY_PATH)), "p80")   # sudo -n <helper>
    heads = [list(a)[:2] for a, _e in seen]
    check("locale: ...and so do a verb run as root with no helper, Diagnostics' helper probe, the "
          "debug report's `sudo -n` read and the helper's file write (each Popen'd with no env, in "
          "the host's language)",
          [_locale_of80(e) for _a, e in seen] == [_PINNED80] * 4
          and [heads[0], heads[2]] == [["ufw", "status"], ["sudo", "-n"]],
          repr((heads, [_locale_of80(e) for _a, e in seen])))
    paths = [e.get("PATH") for _a, e in seen]
    check("locale: ...and the environment carries everything else the panel's has (PATH), so the "
          "tool is still found (control)", paths == [os.environ.get("PATH")] * 4, repr(paths))
    check("locale: _core._r20a_c_env pins exactly LC_ALL, LANG and LANGUAGE",
          _locale_of80(_p9_core._r20a_c_env()) == _PINNED80)


try:
    _p9_arm(who="part80")
    _RID80, _GS80, _ADMIN80, _CMD80 = _setup80()
    _A80 = _p9_client(_ADMIN80)
    _inf_port80()
    _cron_note80()
    _audit_raise80(_A80, _RID80, _GS80, _CMD80)
    _audit_queued80(_GS80)
    _audit_bootstrap80(_RID80)
    _locale_real80()
    _locale_fake80()
finally:
    _p9_restore_all()
    _cleanup80()

check("part80: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP80_START, repr(_P9_TRIPPED[_TRIP80_START:][:6]))
