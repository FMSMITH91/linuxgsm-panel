"""Part 16 of the unit suite: per-row state that outlives its row, and three sinks with no ceiling.

THE ROW-ID HALF. SQLite hands a deleted row's id straight to the next INSERT (plain INTEGER PRIMARY
KEY, no AUTOINCREMENT), so anything keyed by that id — or a worker still holding the deleted row —
lands on whatever row is created next. Driven end to end through the real routes, with the
attacker a DELEGATED admin whose own host or server is the newest row by construction:

  * a bootstrap job outliving its host wrote into the next host's job, flipped it to "done",
    stamped its last_seen and forged a success audit row for it. And when the id was taken while
    its first SSH contact was still in progress (the handshake is the attacker's own box to slow
    down), the host-key pin it then committed landed on the NEW row, and that commit turned the
    worker's row object into the new row: its remaining root steps were aimed at the new host,
    stopped only by the wrong key it had just pinned there;
  * a deleted game server's console backlog, and the long action it was tailing, were served to
    and run on the next server to take its id;
  * a deleted host's pending-package list was served to whoever could see the next host.

THE CEILING HALF. The panel host's fail2ban log read, a server's console backlog, and the audit
log each kept whatever they were handed.

HOW THE APP IS BUILT. Not again: this part drives part12's Flask app, its database and its client
helpers, and re-arms part12's tripwire and deferred-thread queue for its own duration. Everything
it replaces is restored in the finally at the bottom, and it ends by asserting that no route it
drove reached a transport and no worker it queued was left unrun.

IDS ARE REUSED HERE ON PURPOSE. The models now create these tables with AUTOINCREMENT, so no fresh
database reuses an id; an install whose tables were made before that does until its rebuild runs.
The fixes below are for those installs, so part16 rebuilds part12's remote_server and game_server
without AUTOINCREMENT for its own duration (idreuse_support), and gives it back at the end.
"""
import io as _io16
import json as _json16
import os
import sys
import tempfile as _tf16
from datetime import datetime as _dt16
from types import SimpleNamespace as NS

from unit import REPO_ROOT as _REPO16
from unit import idreuse_support as _reuse16
from unit.part01 import check, eq, skip  # noqa: F401
from unit.part05 import _helper, _helper_path
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, P9_HOST2, P9_LOCAL, _P9_CFG_PATH, _P9_TRIPPED,
                         _P9Thread, _p9, _p9_app, _p9_auth, _p9_banlist, _p9_bk, _p9_cfg,
                         _p9_client,
                         _p9_core, _p9_drain, _p9_fake_time, _p9_json, _p9_new_server, _p9_notif,
                         _p9_patch, _p9_queue, _p9_restore_all, _p9_sm, _p9_so, _p9_state,
                         _p9_threading, _p9_trip, _p9_ts)
from panel.db.models import AuditLog, GameServer, Group, RemoteServer, User, db
from panel.routes import _shared as _sh16
from panel.routes import manage_servers as _ms16
from panel.routes import os_updates as _ou16
from panel.routes import remote_security as _rs16
from panel.routes import remotes as _rm16
from panel.routes import server_files as _sf16
from panel.routes import ubuntu_pro as _up16

# The ceilings, read with the values the findings asked for when a name is not there yet, so an
# unfixed tree fails these checks by name instead of crashing the part on an AttributeError.
_LINE_MAX16 = getattr(_sh16, "_CONSOLE_LINE_MAX", 2048)
_BUDGET16 = getattr(_sh16, "_CONSOLE_BACKLOG_BYTES", 256 * 1024)
_DETAIL_MAX16 = getattr(_p9_auth, "_AUDIT_DETAIL_MAX", 8192)
_PW16 = "Str0ng!passw0rd"      # part12's admin password; the delegate below is given it too
_ANY16 = "0.0.0.0"  # nosec B104 - a stored bind address the route is asked to accept, not a bind
_XHR16 = {"X-Requested-With": "XMLHttpRequest"}
_TRIP16_START = len(_P9_TRIPPED)
_CFG16_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None
_MODS16 = (_sh16, _ms16, _sf16)
_saved16_threading = {m: m.threading for m in _MODS16 if hasattr(m, "threading")}
_saved16_time = {m: m.time for m in _MODS16 if hasattr(m, "time")}
_saved16_listeners = dict(_p9_banlist._listeners)
_saved16_log = (_p9.logger.disabled, _p9_app._log.disabled)
_saved16_maps = [(m, dict(m)) for _entries in _p9_state.keyed_state_with_locks()
                 for m, _lk in _entries]
_saved16_osu = (_p9_state._os_update_state["last_run"], dict(_p9_state._os_update_state["hosts"]))


def _req16(client, method, url, **kw):
    """A request made from inside a worker or another request, in an app context of its own.

    A request pushed while an app context is active REUSES it — its `g` (so flask_login's cached
    user) and its database session. A real request never shares either with a background worker
    or with another request, so every nested request here gets a fresh context, one each.
    """
    with _p9.app_context():
        return getattr(client, method)(url, **kw)


def _newest_remote(name):
    with _p9.app_context():
        r = RemoteServer.query.filter_by(name=name).order_by(RemoteServer.id.desc()).first()
        return None if r is None else r.id


def _host_field(rid, field):
    with _p9.app_context():
        r = db.session.get(RemoteServer, rid)
        return None if r is None else getattr(r, field)


def _audits(action, target=None):
    with _p9.app_context():
        q = AuditLog.query.filter_by(action=action)
        if target is not None:
            q = q.filter_by(target=target)
        return [NS(target=a.target, detail=a.detail or "", success=a.success,
                   action=a.action, username=a.username, remote_id=a.remote_id)
                for a in q.order_by(AuditLog.id).all()]


def _new_host(name, host):
    with _p9.app_context():
        r = RemoteServer(name=name, host=host, port=22, username="root", auth_method="password",
                         auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        return r.id


def _drop_host(rid):
    with _p9.app_context():
        r = db.session.get(RemoteServer, rid)
        if r is not None:
            GameServer.query.filter_by(remote_id=rid).delete()
            db.session.delete(r)
            db.session.commit()


def _drop_server(sid):
    with _p9.app_context():
        gs = db.session.get(GameServer, sid)
        if gs is not None:
            db.session.delete(gs)
            db.session.commit()


try:
    with _p9.app_context():
        _reuse16.reuse_ids(db, ("remote_server", "game_server"))
        _reuse16_on = (_reuse16.plain_rowids(db, "remote_server")
                       and _reuse16.plain_rowids(db, "game_server"))
    check("part16: its hosts and servers reuse a deleted row's id (the schema before AUTOINCREMENT)",
          _reuse16_on)
    for _m in _saved16_threading:
        _m.threading = _p9_threading(_P9Thread)
    for _m in _saved16_time:
        _m.time = _p9_fake_time
    _p9.logger.disabled = True
    _p9_app._log.disabled = True
    if _P9_CFG_PATH.exists():
        _P9_CFG_PATH.unlink()
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), setup_complete=True))

    # part12's tripwire, again: nothing below may reach a host or run a command on this machine.
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part16's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9_so, "_git", _p9_trip("system_ops._git"))
    _p9_patch(_p9_ts, "get_tailscale_info",
              lambda force_refresh=False: NS(dns_name=None, installed=False))
    _N16 = []
    _p9_patch(_p9_notif, "notify", lambda key, title, body="": _N16.append((key, title, body)))
    _E16 = []
    _p9_patch(_p9.socketio, "emit", lambda event, data=None, **k: _E16.append((event, data, k)))
    _p9_patch(_rm16, "ssh_test_connection", lambda *a, **k: (True, "Connected."))
    _p9_patch(_rm16, "close_connection", lambda server: None)
    _SHELL16 = []
    _p9_patch(_p9_sm, "shell_as_game_user",
              lambda server, user, sh, **k: (_SHELL16.append((server.host, user)), ("", "", 1))[1])
    _p9_patch(_sf16, "_read_console_window", lambda remote, gs, want, tz: (True, []))
    _p9_patch(_sf16, "_host_timezone_cached", lambda remote, app=None: "UTC")

    # A delegated admin: MANAGE_REMOTES and the server permissions, on part12's host 1 ONLY.
    with _p9.app_context():
        _grp16 = Group(name="p16_delegates", description="", is_default=False)
        _grp16.set_permissions([_p9_auth.MANAGE_REMOTES, _p9_auth.VIEW_SERVERS,
                                _p9_auth.VIEW_CONSOLE, _p9_auth.MANAGE_SERVERS,
                                _p9_auth.SEND_COMMAND])
        _grp16.servers.append(db.session.get(RemoteServer, P9_HOST))
        db.session.add(_grp16)
        _d16 = User(username="p16_delegate", display_name="Delegate", is_superadmin=False,
                    is_active=True, password_hash=db.session.get(User, P9_ADMIN).password_hash)
        _d16.groups.append(_grp16)
        db.session.add(_d16)
        db.session.commit()
        P16_D = _d16.id
    _A16 = _p9_client(P9_ADMIN)
    _D16 = _p9_client(P16_D)
    _A16n, _D16n = _p9_client(P9_ADMIN), _p9_client(P16_D)    # for requests nested in a request

    # ════════════════════════════════════════════════════════════════════════════════════════
    # 745379173 — a bootstrap outliving its host
    # ════════════════════════════════════════════════════════════════════════════════════════
    _bs16 = {"victim": None, "deleted": None, "seen": []}
    _BS16_OLD = _dt16(2000, 1, 1)
    _BS16_FORM = {"name": "p16-victim", "host": "192.0.2.77", "ssh_user": "root", "ssh_port": "22",
                  "auth_method": "password", "credential": "victim-pw", "setup_type": "fresh"}

    def _bs16_attack(remote, progress=None, **opts):
        """The delegate's own box: first contact pins its key (a COMMIT), then a step is held."""
        _p9_core._persist_host_key(remote, "ssh-ed25519 AAAAC3NzaATTACKERKEY")
        progress(1, 3, "[%s] step one" % remote.host, "running")
        # Held here while the delegate deletes it and a superadmin adds a host that takes its id.
        _bs16["deleted"] = _req16(_D16, "post", "/remotes/%d/delete" % _bs16_aid,
                                  json={"password": _PW16}, headers=_XHR16).status_code
        _req16(_A16, "post", "/remotes/add", data=_BS16_FORM, headers=_XHR16)
        _bs16["victim"] = _newest_remote("p16-victim")
        with _p9.app_context():
            _v = db.session.get(RemoteServer, _bs16["victim"])
            _v.last_seen = _BS16_OLD
            db.session.commit()
        # Released: the next step reads its server's address again, and its output is logged.
        _bs16["seen"].append((remote.host, remote.name))
        progress(2, 3, "ATTACKER TEXT: hardening verified, re-enable PasswordAuthentication",
                 "running")
        return True, "VPS bootstrap complete (3/3 steps).", []

    _p9_patch(_sh16, "remote_bootstrap_vps", _bs16_attack)
    _r = _D16.post("/remotes/add", data=dict(_BS16_FORM, name="p16-attacker", host="192.0.2.66",
                                              credential="attacker-pw"), headers=_XHR16)
    _bs16_aid = _newest_remote("p16-attacker")
    check("bootstrap reuse: the delegate adds a fresh host of their own and its bootstrap queues",
          _r.status_code == 200 and _bs16_aid is not None and len(_p9_queue) == 1,
          "%d %r, %d queued" % (_r.status_code, _p9_json(_r), len(_p9_queue)))
    _fn, _a, _k = _p9_queue.pop(0)
    _fn(*_a, **_k)                                   # the attacker's worker, start to finish
    check("bootstrap reuse: the host was deleted mid-run and the next host added took its id",
          _bs16["deleted"] == 200 and _bs16["victim"] == _bs16_aid,
          "delete %r, attacker id %r, victim id %r"
          % (_bs16["deleted"], _bs16_aid, _bs16["victim"]))
    _bs16_vid = _bs16["victim"]
    _st = _p9_json(_A16.get("/api/remote/%d/bootstrap-status" % _bs16_vid))
    check("bootstrap reuse: the new host's own job is untouched (still running, no foreign lines)",
          _st.get("status") == "running" and _st.get("step_name") == "Starting…"
          and not any("ATTACKER" in ln or "192.0.2.66" in ln for ln in _st.get("log") or []),
          repr(_st))
    _r = _A16.post("/api/remote/%d/bootstrap" % _bs16_vid, json={}, headers=_XHR16)
    check("bootstrap reuse: ...so a second bootstrap of the new host is still refused (409)",
          _r.status_code == 409, "%d %r" % (_r.status_code, _p9_json(_r)))
    check("bootstrap reuse: the stale worker did not stamp the new host's last_seen",
          _host_field(_bs16_vid, "last_seen") == _BS16_OLD,
          repr(_host_field(_bs16_vid, "last_seen")))
    check("bootstrap reuse: no success audit row names the new host as bootstrapped",
          not _audits("remote_vps_bootstrap", "p16-victim"),
          repr([(a.target, a.success) for a in _audits("remote_vps_bootstrap")][-3:]))
    check("bootstrap reuse: the stale run is audited under the host it really ran on",
          [(a.target, a.success) for a in _audits("remote_vps_bootstrap", "p16-attacker")]
          == [("p16-attacker", True)],
          repr([(a.target, a.success) for a in _audits("remote_vps_bootstrap")][-3:]))
    # The audit row is filed under a host by id (log_action's remote=, which delegated viewers'
    # /logs reads). That id is the new host's now, so filing the stale run under it would show the
    # deleted host's bootstrap to whoever may see the new one.
    check("bootstrap reuse: ...and that row is filed under NO host, not the one that took the id",
          [a.remote_id for a in _audits("remote_vps_bootstrap", "p16-attacker")] == [None],
          repr([(a.target, a.remote_id) for a in _audits("remote_vps_bootstrap")][-3:]))

    # The new host's own bootstrap: it still pins the key it met on first contact, still marks the
    # host seen, and still audits. The detached row is what the fix hands the bootstrap, so the pin
    # has to be written back once it is done — this is the check that it is.
    _bs16_pin_at_step = []

    def _bs16_normal(remote, progress=None, **opts):
        _p9_core._persist_host_key(remote, "ssh-ed25519 AAAAC3NzaVICTIMKEY")
        progress(1, 1, "Updating packages", "running")
        _bs16_pin_at_step.append(_host_field(remote.id, "host_key"))
        return True, "VPS bootstrap complete (1/1 steps).", []

    _p9_patch(_sh16, "remote_bootstrap_vps", _bs16_normal)
    _p9_drain()
    _st = _p9_json(_A16.get("/api/remote/%d/bootstrap-status" % _bs16_vid))
    check("bootstrap reuse: the new host's own run completes, and its host key is pinned (control)",
          _st.get("status") == "done"
          and _host_field(_bs16_vid, "host_key") == "ssh-ed25519 AAAAC3NzaVICTIMKEY"
          and (_host_field(_bs16_vid, "last_seen") or _BS16_OLD) > _BS16_OLD
          and [a.success for a in _audits("remote_vps_bootstrap", "p16-victim")] == [True],
          repr((_st, _host_field(_bs16_vid, "host_key"), _host_field(_bs16_vid, "last_seen"))))
    check("bootstrap: ...and the pin is on the row by the next step, not only once the run ends",
          _bs16_pin_at_step[:1] == ["ssh-ed25519 AAAAC3NzaVICTIMKEY"], repr(_bs16_pin_at_step))
    check("bootstrap: the new host's own run is filed under its host (control)",
          [a.remote_id for a in _audits("remote_vps_bootstrap", "p16-victim")] == [_bs16_vid],
          repr([(a.target, a.remote_id) for a in _audits("remote_vps_bootstrap")][-3:]))
    # A pin the host ALREADY had is not replaced by what a bootstrap met (a re-bootstrap, or the
    # monitor pinning first): TOFU keeps the first key, and HostKeyMismatch is the answer to a
    # different one, not an overwrite.
    with _sh16._bootstrap_lock:
        _sh16._bootstrap_jobs.pop(_bs16_vid, None)

    def _bs16_other_key(remote, progress=None, **opts):
        remote.host_key = "ssh-ed25519 AAAAC3NzaSOMEOTHERKEY"
        return True, "ok", []

    _p9_patch(_sh16, "remote_bootstrap_vps", _bs16_other_key)
    _sh16._begin_bootstrap(_p9, _bs16_vid, {}, P9_ADMIN)
    _p9_drain()
    check("bootstrap: an existing pin is never replaced by the key a later run saw (control)",
          _host_field(_bs16_vid, "host_key") == "ssh-ed25519 AAAAC3NzaVICTIMKEY",
          repr(_host_field(_bs16_vid, "host_key")))
    with _sh16._bootstrap_lock:
        _sh16._bootstrap_jobs.pop(_bs16_vid, None)
    _drop_host(_bs16_vid)

    # The id taken DURING the first contact: the delegate's box holds the SSH handshake open while
    # its row is deleted and the next host takes the id, then completes it — and the key it
    # presented is pinned, which is a commit. Before the fix that pin was an UPDATE by id, so it
    # landed on the new row, and the commit expired the worker's row object, so the next thing
    # read off it — the address of the next step — came from the new row.
    _bs16.update(victim=None, deleted=None, seen=[])

    def _bs16_first_contact(remote, progress=None, **opts):
        progress(1, 3, "Waiting for package manager to be free", "running")
        _bs16["deleted"] = _req16(_D16, "post", "/remotes/%d/delete" % _bs16_aid,
                                  json={"password": _PW16}, headers=_XHR16).status_code
        _req16(_A16, "post", "/remotes/add", data=_BS16_FORM, headers=_XHR16)
        _bs16["victim"] = _newest_remote("p16-victim")
        _p9_core._persist_host_key(remote, "ssh-ed25519 AAAAC3NzaATTACKERKEY")
        _bs16["seen"].append((remote.host, remote.name))
        return True, "VPS bootstrap complete (3/3 steps).", []

    _p9_patch(_sh16, "remote_bootstrap_vps", _bs16_first_contact)
    _D16.post("/remotes/add", data=dict(_BS16_FORM, name="p16-attacker", host="192.0.2.66",
                                        credential="attacker-pw"), headers=_XHR16)
    _bs16_aid = _newest_remote("p16-attacker")
    _fn, _a, _k = _p9_queue.pop(0)
    _fn(*_a, **_k)
    _bs16_vid = _bs16["victim"]
    check("bootstrap reuse (first contact): the id was taken while the handshake was held",
          _bs16["deleted"] == 200 and _bs16_vid == _bs16_aid, repr((_bs16, _bs16_aid)))
    check("bootstrap reuse (first contact): the old host's key is not pinned on the new one",
          _host_field(_bs16_vid, "host_key") in ("", None),
          repr(_host_field(_bs16_vid, "host_key")))
    check("bootstrap reuse (first contact): the worker's later steps still target ITS host",
          _bs16["seen"] == [("192.0.2.66", "p16-attacker")], repr(_bs16["seen"]))
    _p9_patch(_sh16, "remote_bootstrap_vps", _bs16_normal)
    _p9_drain()
    with _sh16._bootstrap_lock:
        _sh16._bootstrap_jobs.pop(_bs16_vid, None)
    _drop_host(_bs16_vid)

    # ════════════════════════════════════════════════════════════════════════════════════════
    # 745379050 — a deleted server's console, served to and run on the next one
    # ════════════════════════════════════════════════════════════════════════════════════════
    _p9_patch(_ms16, "_stop_game_processes", lambda *a, **k: None)
    _p9_patch(_ms16, "_close_game_firewall", lambda *a, **k: ("", False))
    _p9_patch(_p9_sm, "run_privileged", lambda *a, **k: ("", "", 0))
    _p9_patch(_p9_bk, "remove_game_schedule", lambda sid: None)
    # The uninstall asks the host whether the account is root-capable before it deletes anything
    # (privileged_accounts); here it is a plain game account, as the probe would find it.
    _p9_patch(_ms16, "privileged_accounts", lambda remote, users: {})
    _SECRET16 ="Logging in user 'secret_steam_acct' to Steam Public...OK"
    _cv = _p9_new_server(P9_HOST2, "secretgame", "csgo", 27400, name="p16-secret")
    _cv_remote = NS(host="192.0.2.11", name="p9-host2")
    _sh16._begin_action_tail(_p9, _cv, "update", "/home/secretgame/.panel-update.log", "secretgame")
    _sh16._console_push(_p9, _cv, _SECRET16)
    _r = _D16.get("/api/console/%d" % _cv)
    check("console reuse: the delegate cannot read the other host's console (the boundary)",
          _r.status_code == 403, "got %d" % _r.status_code)
    _r = _A16.post("/servers/%d/delete" % _cv, headers=_XHR16)
    check("console reuse: the uninstall itself succeeds",
          _r.status_code == 200 and _p9_json(_r).get("success") is True, repr(_p9_json(_r)))
    check("console reuse: uninstalling drops the server's console backlog and action tail at once",
          _cv not in _p9_state._console_backlog and _cv not in _p9_state._action_output,
          repr((_p9_state._console_backlog.get(_cv), _p9_state._action_output.get(_cv))))
    # Whatever lands AFTER the delete — a drain already in flight, a push from a worker the
    # delete could not see — must not reach the next server to take the id either.
    _p9_state._console_backlog.setdefault(_cv, []).append({"t": 1.0, "line": _SECRET16})
    _p9_state._install_jobs[_cv] = {"status": "failed", "message": "SteamCMD could not log in",
                                    "updated": 0, "started": 0}
    with _p9.app_context():
        _cv_new = _ms16._create_install_row(P9_HOST, "", "p16mine", "csgo", 27401).id
    check("console reuse: the delegate's next server takes the freed id", _cv_new == _cv,
          "%r vs %r" % (_cv_new, _cv))
    check("console reuse: a new row inherits no install job from the id's previous owner",
          _cv not in _p9_state._install_jobs, repr(_p9_state._install_jobs.get(_cv)))
    with _p9.app_context():
        _ms16._queue_install_job(db.session.get(GameServer, _cv), [])
    check("console reuse: ...while the install queued for it right after the INSERT keeps its job",
          (_p9_state._install_jobs.get(_cv) or {}).get("step_name") == "Queued",
          repr(_p9_state._install_jobs.get(_cv)))
    _r = _D16.get("/api/console/%d" % _cv)
    check("console reuse: the next server's console replays none of the deleted one's lines",
          _r.status_code == 200 and _p9_json(_r).get("panel_lines") == [],
          "%d %r" % (_r.status_code, _p9_json(_r).get("panel_lines")))
    _del16 = list(_SHELL16)
    _sh16._drain_action_output(_p9, NS(host="192.0.2.10", name="p9-host"), _cv)
    check("console reuse: the console poller runs nothing on the new host for the dead action",
          _SHELL16 == _del16, repr(_SHELL16[len(_del16):]))
    _E16.clear()
    _sh16._end_action_tail(_p9, _cv, _cv_remote, "update", 0)
    check("console reuse: the dead action's 'finished' line reaches neither the new server's "
          "backlog nor its live console",
          not any("update finished" in e["line"] for e in _p9_state._console_backlog.get(_cv, []))
          and not [e for e in _E16 if (e[2] or {}).get("room") == "console_%d" % _cv],
          repr((_p9_state._console_backlog.get(_cv), _E16[:2])))
    with _p9_state._install_lock:
        _p9_state._install_jobs.pop(_cv, None)
    _drop_server(_cv)

    # The other way a server goes: its whole host is deleted, and the game rows with it in bulk.
    _h16 = _new_host("p16-doomed", "192.0.2.88")
    _hv16 = _p9_new_server(_h16, "doomedgame", "csgo", 27402)
    _sh16._begin_action_tail(_p9, _hv16, "validate", "/home/doomedgame/.panel-validate.log",
                             "doomedgame")
    _sh16._console_push(_p9, _hv16, _SECRET16)
    _p9_state._console_partial[_hv16] = "half a li"
    _p9_state._os_update_seen[_h16] = {"name": "p16-doomed", "count": 1, "security": 1,
                                       "packages": [], "at": 1.0}
    _p9_state._monitor_state["disk"][_h16] = True
    _r = _A16.post("/remotes/%d/delete" % _h16, json={"password": _PW16}, headers=_XHR16)
    check("host delete: deleting a host drops its servers' and its own per-row state at once",
          _r.status_code == 200 and not any(
              _hv16 in m for m in (_p9_state._console_backlog, _p9_state._action_output,
                                   _p9_state._console_partial))
          and _h16 not in _p9_state._os_update_seen
          and _h16 not in _p9_state._monitor_state["disk"],
          repr((_r.status_code, _p9_state._console_backlog.get(_hv16),
                _p9_state._os_update_seen.get(_h16))))
    _E16.clear()
    _sh16._end_action_tail(_p9, _hv16, NS(host="192.0.2.88", name="p16-doomed"), "validate", 0)
    check("host delete: ...and the dead action's end is not announced into the freed id",
          _hv16 not in _p9_state._console_backlog and not _E16,
          repr((_p9_state._console_backlog.get(_hv16), _E16[:2])))

    # ════════════════════════════════════════════════════════════════════════════════════════
    # 745379196 — a deleted host's pending packages, served to whoever sees the next host
    # ════════════════════════════════════════════════════════════════════════════════════════
    _OSU16 = {"ok": True, "count": 2,
              "packages": [{"name": "openssl-SECRET", "suite": "noble-security"},
                           {"name": "bash", "suite": "noble-updates"}]}
    _p9_patch(_p9_sm, "remote_os_check_updates", lambda r: dict(_OSU16))
    _s16 = _new_host("secret-host", "192.0.2.90")
    _r = _A16.get("/api/remote/%d/check-updates" % _s16)
    check("os-update reuse: a check on the superadmin's host is recorded",
          _r.status_code == 200 and (_p9_state._os_update_seen.get(_s16) or {}).get("count") == 2,
          "%d %r" % (_r.status_code, _p9_state._os_update_seen.get(_s16)))
    check("os-update reuse: the delegate cannot read that host's cache (the boundary)",
          _D16.get("/api/remote/%d/updates-cached" % _s16).status_code == 403)
    _p9_state._os_update_state["hosts"][_s16] = (2, 1)      # what the daily sweep alerted on
    _r = _A16.post("/remotes/%d/delete" % _s16, json={"password": _PW16}, headers=_XHR16)
    check("os-update reuse: deleting the host drops its cached update list at once",
          _r.status_code == 200 and _s16 not in _p9_state._os_update_seen,
          repr(_p9_state._os_update_seen.get(_s16)))
    check("os-update reuse: ...and the counts the daily sweep last alerted on for it",
          _s16 not in _p9_state._os_update_state["hosts"],
          repr(_p9_state._os_update_state["hosts"].get(_s16)))
    # Something written after the delete (the daily sweep holding the old row list) is not the
    # new host's either.
    _p9_state._os_update_seen[_s16] = {"name": "secret-host", "count": 2, "security": 1,
                                       "packages": _OSU16["packages"], "at": 1.0}
    _p9_state._os_update_state["hosts"][_s16] = (2, 1)
    _D16.post("/remotes/add", data={"name": "p16-mine", "host": "192.0.2.91", "ssh_user": "root",
                                    "ssh_port": "22", "auth_method": "password",
                                    "credential": "mine", "setup_type": "existing"},
              headers=_XHR16)
    _mine16 = _newest_remote("p16-mine")
    check("os-update reuse: the delegate's new host takes the freed id", _mine16 == _s16,
          "%r vs %r" % (_mine16, _s16))
    check("os-update reuse: a new host inherits no cached update list from the id's last owner",
          _s16 not in _p9_state._os_update_seen, repr(_p9_state._os_update_seen.get(_s16)))
    # ...nor the sweep's "already told you about 2": a host added after the panel started has its
    # first batch announced (os_updates._os_update_seeds), and an inherited count swallowed it.
    check("os-update reuse: ...nor the alert counts, so its own first batch is still announced",
          _s16 not in _p9_state._os_update_state["hosts"],
          repr(_p9_state._os_update_state["hosts"].get(_s16)))
    _cj = _p9_json(_D16.get("/api/remote/%d/updates-cached" % _s16))
    _sj = _p9_json(_D16.get("/api/os-updates/summary"))
    check("os-update reuse: the new host's card and the banner know nothing of the old host",
          _cj == {"known": False}
          and not any(h.get("name") == "secret-host" for h in _sj.get("hosts") or []),
          repr((_cj, _sj)))
    _drop_host(_s16)

    # A check still IN FLIGHT when the host is deleted and its id taken: it answers after the new
    # host exists. Its first contact pinned the old host's key, and that commit expired the row
    # object — so anything read off it after the check reloads from the NEW row. The identity
    # has to be taken when the row is loaded.
    _s16 = _new_host("secret-host", "192.0.2.92")

    def _osu16_inflight(remote):
        _p9_core._persist_host_key(remote, "ssh-ed25519 AAAAC3NzaSECRETHOST")
        _req16(_A16n, "post", "/remotes/%d/delete" % _s16, json={"password": _PW16},
               headers=_XHR16)
        _req16(_D16n, "post", "/remotes/add", data={
            "name": "p16-mine2", "host": "192.0.2.93", "ssh_user": "root", "ssh_port": "22",
            "auth_method": "password", "credential": "mine", "setup_type": "existing"},
            headers=_XHR16)
        return dict(_OSU16)

    _p9_patch(_p9_sm, "remote_os_check_updates", _osu16_inflight)
    _A16.get("/api/remote/%d/check-updates" % _s16)
    _mine16 = _newest_remote("p16-mine2")
    _cj = _p9_json(_D16.get("/api/remote/%d/updates-cached" % _s16))
    _sj = _p9_json(_D16.get("/api/os-updates/summary"))
    check("os-update reuse: a check that answers after its host's id was taken shows the new host "
          "nothing",
          _mine16 == _s16 and _cj == {"known": False}
          and not any(h.get("id") == _s16 for h in _sj.get("hosts") or []),
          repr((_mine16, _s16, _cj, _sj)))
    # ...and a check of the host that IS there still shows (control).
    _p9_patch(_p9_sm, "remote_os_check_updates", lambda r: dict(_OSU16))
    _A16.get("/api/remote/%d/check-updates" % _s16)
    _cj = _p9_json(_D16.get("/api/remote/%d/updates-cached" % _s16))
    _sj = _p9_json(_D16.get("/api/os-updates/summary"))
    check("os-update: the new host's own check is shown on its card and in the banner (control)",
          _cj.get("known") is True and _cj.get("count") == 2
          and [h.get("name") for h in _sj.get("hosts") or [] if h.get("id") == _s16]
          == ["p16-mine2"], repr((_cj, _sj)))
    _drop_host(_s16)

    # The banner links the panel's own host to its dedicated page (superadmins only; everyone else
    # gets the ordinary manage page). Which host that is now comes out of the same one query that
    # checks the entries' identity, instead of a query of its own.
    _p9_patch(_p9_so, "os_update_available", lambda refresh=True: dict(_OSU16))
    _A16.get("/api/remote/%d/check-updates" % P9_LOCAL)
    _A16.get("/api/remote/%d/check-updates" % P9_HOST)
    with _p9.test_request_context("/"):
        from flask import url_for as _url16
        _want16 = {P9_LOCAL: _url16("server_management"),
                   P9_HOST: _url16("remote_manage", remote_id=P9_HOST)}
    _got16 = {h["id"]: h["url"] for h in _p9_json(_A16.get("/api/os-updates/summary"))["hosts"]
              if h["id"] in _want16}
    check("os-update banner: the panel host links to its own page, another host to its manage page",
          _got16 == _want16, repr((_got16, _want16)))
    _dl16 = {h["id"]: h["url"] for h in _p9_json(_D16.get("/api/os-updates/summary"))["hosts"]}
    check("os-update banner: ...and a delegate sees only their own host, on its manage page",
          _dl16 == {P9_HOST: _want16[P9_HOST]}, repr(_dl16))

    # The daily sweep: a host deleted WHILE it runs. It loaded the host list at its start, and
    # pruned against that same list at its end, so the entry it had just written for the deleted
    # host stayed until the monitor's next pass — under an id the next host added may already own.
    _gone16 = _new_host("p16-gone", "192.0.2.94")

    def _osu16_sweep(remote):
        if remote.id == _gone16:
            _drop_host(_gone16)
        return {"ok": True, "count": 1, "packages": [{"name": "x", "suite": "noble-security"}]}

    _p9_patch(_ou16, "_os_updates_for", _osu16_sweep)
    _p9._maybe_alert_os_updates(force=True)
    check("os-update sweep: a host deleted mid-sweep leaves no entry behind in either map",
          _gone16 not in _p9_state._os_update_seen
          and _gone16 not in _p9_state._os_update_state["hosts"],
          repr((_p9_state._os_update_seen.get(_gone16),
                _p9_state._os_update_state["hosts"].get(_gone16))))
    check("os-update sweep: ...while the hosts that are still there keep theirs (control)",
          P9_HOST in _p9_state._os_update_seen
          and (_p9_state._os_update_seen[P9_HOST].get("count") == 1),
          repr(_p9_state._os_update_seen.get(P9_HOST)))

    # ════════════════════════════════════════════════════════════════════════════════════════
    # 745379347 — a console backlog bounded in lines but not in bytes
    # ════════════════════════════════════════════════════════════════════════════════════════
    _cb16_saved = _p9_state._console_backlog.pop(P9_GS, None)
    for _i in range(700):
        _sh16._console_push(_p9, P9_GS, "%04d" % _i + "x" * 65536)
    _cb16 = _p9_state._console_backlog.get(P9_GS) or []
    check("console backlog: no stored line is longer than the per-line cap",
          _cb16 and max(len(e["line"]) for e in _cb16) <= _LINE_MAX16 + len("\x1b[0m…"),
          "longest %d" % max([len(e["line"]) for e in _cb16] or [0]))
    check("console backlog: the whole backlog stays inside its byte budget",
          sum(len(e["line"]) for e in _cb16) <= _BUDGET16,
          "%d chars in %d lines" % (sum(len(e["line"]) for e in _cb16), len(_cb16)))
    _sh16._console_push(_p9, P9_GS, "[panel] update finished successfully.")
    _cb16 = _p9_state._console_backlog.get(P9_GS) or []
    check("console backlog: the NEWEST lines are the ones kept, and a normal line is kept verbatim",
          _cb16 and _cb16[-1]["line"] == "[panel] update finished successfully."
          and _cb16[-2]["line"].startswith("0699"), repr([e["line"][:8] for e in _cb16[-2:]]))
    _pl16 = _p9_json(_A16.get("/api/console/%d" % P9_GS)).get("panel_lines") or []
    check("console backlog: /api/console replays inside the budget",
          _pl16 and sum(len(e["line"]) for e in _pl16) <= _BUDGET16,
          "%d chars" % sum(len(e["line"]) for e in _pl16))
    # A cut never leaves half a colour escape behind: the browser would print its tail as text.
    _p9_state._console_backlog.pop(P9_GS, None)
    _sgr16 = "a" * (_LINE_MAX16 - 3) + "\x1b[38;2;255;0;0mRED" + "b" * 100
    _sh16._console_push(_p9, P9_GS, _sgr16)
    _cut16 = (_p9_state._console_backlog.get(P9_GS) or [{"line": ""}])[-1]["line"]
    import re as _re16
    check("console backlog: a line cut mid-escape keeps no partial colour sequence",
          "\x1b" not in _re16.sub(r"\x1b\[[0-9;]*m", "", _cut16) and _cut16.endswith("…"),
          repr(_cut16[-30:]))
    _p9_state._console_backlog.pop(P9_GS, None)
    if _cb16_saved is not None:
        _p9_state._console_backlog[P9_GS] = _cb16_saved

    # ════════════════════════════════════════════════════════════════════════════════════════
    # 745379037 — audit rows as big as the request that wrote them
    # ════════════════════════════════════════════════════════════════════════════════════════
    _PRO16 = []
    _p9_patch(_up16, "pro_service",
              lambda remote, service, action: (_PRO16.append((service, action)), (True, "ok"))[1])
    _p9_patch(_up16, "_pro_status_cached", lambda remote, force=False: {})
    with _p9.app_context():
        _al16_before = AuditLog.query.count()
    _r1 = _D16.post("/api/remote/%d/pro-service" % P9_HOST,
                    json={"service": "s" * 1000000, "action": "enable"})
    _r2 = _D16.post("/api/remote/%d/pro-service" % P9_HOST,
                    json={"service": "esm-infra", "action": "a" * 1000000})
    with _p9.app_context():
        _al16_after = AuditLog.query.count()
    check("pro service: an unknown service or action is refused (400) before anything runs or logs",
          _r1.status_code == 400 and _r2.status_code == 400 and not _PRO16
          and _al16_after == _al16_before
          and "Unknown" in _p9_json(_r1).get("message", ""),
          repr((_r1.status_code, _r2.status_code, _PRO16, _al16_after - _al16_before)))
    _r = _D16.post("/api/remote/%d/pro-service" % P9_HOST,
                   json={"service": "esm-infra", "action": "enable"})
    check("pro service: a real service and action still run and are audited (control)",
          _r.status_code == 200 and _PRO16 == [("esm-infra", "enable")]
          and [(a.detail, a.success) for a in _audits("pro_enable")][-1:] == [("esm-infra", True)],
          repr((_r.status_code, _PRO16)))
    with _p9.app_context(), _p9.test_request_context("/"):
        _p9_auth.log_action(None, "x" * 1000000, target="t" * 1000000, detail="y" * 1000000,
                            actor="u" * 1000000)
        _big16 = AuditLog.query.order_by(AuditLog.id.desc()).first()
        _big16 = NS(action=_big16.action, target=_big16.target, detail=_big16.detail,
                    username=_big16.username)
    check("audit log: every column of an entry is capped, however much the caller handed it",
          len(_big16.action) <= 128 and len(_big16.target) <= 255 and len(_big16.username) <= 80
          and len(_big16.detail) <= _DETAIL_MAX16 + 32
          and _big16.detail.endswith("[truncated]"),
          repr((len(_big16.action), len(_big16.target), len(_big16.username),
                len(_big16.detail))))
    with _p9.app_context(), _p9.test_request_context("/"):
        _p9_auth.log_action(None, "p16_short", target="t", detail="an ordinary detail")
    check("audit log: an ordinary entry is stored exactly as given (control)",
          [(a.target, a.detail) for a in _audits("p16_short")] == [("t", "an ordinary detail")])
    _p9_patch(_sf16, "send_console_command", lambda *a, **k: ("", "no tmux session", 1))
    _r = _D16.post("/api/command/%d" % P9_GS, json={"command": "say " + "z" * 1000000})
    _sc16 = (_audits("send_command") or [NS(detail="")])[-1]
    check("audit log: a megabyte console command that failed to send is stored capped",
          _r.status_code == 502 and 0 < len(_sc16.detail) <= _DETAIL_MAX16 + 32,
          "%d, %d chars" % (_r.status_code, len(_sc16.detail)))

    # ════════════════════════════════════════════════════════════════════════════════════════
    # 745379008 — the binding change audited as a success whatever its side effects did
    # ════════════════════════════════════════════════════════════════════════════════════════
    _cp16 = {"fw": (False, "ufw is not reachable"), "f2b": (False, "could not write the jail"),
             "restart": (False, "no systemd unit")}
    _p9_patch(_rs16, "remote_ufw_open_port", lambda *a, **k: _cp16["fw"])
    _p9_patch(_rs16, "remote_ufw_close_port", lambda *a, **k: _cp16["fw"])
    _p9_patch(_p9_so, "ensure_panel_fail2ban", lambda *a, **k: _cp16["f2b"])
    _p9_patch(_p9_so, "restart_panel", lambda *a, **k: _cp16["restart"])
    _p9_patch(_p9_so, "port_in_use", lambda port: False)
    _f2b16_installed = [True]
    _p9_patch(_p9_so, "panel_fail2ban_status", lambda: {"installed": _f2b16_installed[0]})
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), port=5000, bind_host=_ANY16))
    _r = _A16.post("/api/panel/change-port", json={"port": 5055, "bind_host": _ANY16})
    _cpb = (_audits("panel_change_binding") or [NS(success=None, detail="")])[-1]
    check("change-port: a move whose firewall and fail2ban steps failed is audited as a failure",
          _cpb.success is False and "FIREWALL NOT UPDATED" in _cpb.detail
          and "could not write the jail" in _cpb.detail, repr((_cpb.success, _cpb.detail)))
    check("change-port: a restart that failed is audited as its own failed row",
          [a.success for a in _audits("panel_restart")][-1:] == [False],
          repr([(a.success, a.detail) for a in _audits("panel_restart")]))
    check("change-port: the restart-failure reply still tells the operator about the firewall",
          "FIREWALL NOT UPDATED" in _p9_json(_r).get("message", ""), repr(_p9_json(_r)))
    _cp16.update(fw=(True, "ok"), f2b=(True, "jail updated"), restart=(True, "scheduled"))
    _n_restart16 = len(_audits("panel_restart"))
    _r = _A16.post("/api/panel/change-port", json={"port": 5066, "bind_host": _ANY16})
    _cpb = (_audits("panel_change_binding") or [NS(success=None, detail="")])[-1]
    check("change-port: a move that fully took is a successful row and no restart row (control)",
          _p9_json(_r).get("success") is True and _cpb.success is True
          and len(_audits("panel_restart")) == _n_restart16, repr((_p9_json(_r), _cpb.detail)))
    # The new port opened, but the OLD port's rule could not be removed: the panel is still
    # reachable where it was, which is a security side effect that did not follow the move.
    _cp16.update(fw=(True, "ok"))
    _p9_patch(_rs16, "remote_ufw_close_port", lambda *a, **k: (False, "ufw is not reachable"))
    _r = _A16.post("/api/panel/change-port", json={"port": 5070, "bind_host": _ANY16})
    _cpb = (_audits("panel_change_binding") or [NS(success=None, detail="")])[-1]
    check("change-port: a move that left the OLD port's rule open is audited as a failure",
          _cpb.success is False and "still there" in _cpb.detail, repr((_cpb.success, _cpb.detail)))
    _p9_patch(_rs16, "remote_ufw_close_port", lambda *a, **k: _cp16["fw"])
    # A host with no fail2ban at all: ensure_panel_fail2ban no-ops and says ok=False, and there
    # is no jail to follow the move — not a failed move.
    _f2b16_installed[0] = False
    _cp16["f2b"] = (False, "fail2ban isn't installed on this host.")
    _r = _A16.post("/api/panel/change-port", json={"port": 5077, "bind_host": _ANY16})
    _cpb = (_audits("panel_change_binding") or [NS(success=None, detail="")])[-1]
    check("change-port: with no fail2ban installed there is nothing to follow, so it is a success",
          _p9_json(_r).get("success") is True and _cpb.success is True
          and "not installed" in _cpb.detail, repr((_p9_json(_r), _cpb.detail)))
    _f2b16_installed[0] = True
    # The same port, a new bind address: fail2ban is not asked, and that is not a failure.
    _p9_patch(_p9_so, "ensure_panel_fail2ban",
              lambda *a, **k: (_ for _ in ()).throw(AssertionError("fail2ban asked")))
    _p9_patch(_p9_so, "host_has_ip", lambda ip: True)
    _r = _A16.post("/api/panel/change-port", json={"port": 5077, "bind_host": "192.0.2.5"})
    _cpb = (_audits("panel_change_binding") or [NS(success=None, detail="")])[-1]
    check("change-port: a bind-only move that never needed fail2ban is still a success (control)",
          _p9_json(_r).get("success") is True and _cpb.success is True, repr((_p9_json(_r),
                                                                               _cpb.detail)))
    # END OF SECTIONS
finally:
    for _m, _t in _saved16_threading.items():
        _m.threading = _t
    for _m, _t in _saved16_time.items():
        _m.time = _t
    _p9_restore_all()
    _p9_banlist._listeners.clear()
    _p9_banlist._listeners.update(_saved16_listeners)
    _p9.logger.disabled, _p9_app._log.disabled = _saved16_log
    for _m, _v in _saved16_maps:
        _m.clear()
        _m.update(_v)
    _p9_state._os_update_state["last_run"] = _saved16_osu[0]
    _p9_state._os_update_state["hosts"].clear()
    _p9_state._os_update_state["hosts"].update(_saved16_osu[1])
    try:
        with _p9.app_context():
            _reuse16_back = _reuse16.put_back(db)
    except Exception as _e16b:  # noqa: BLE001 - reported by the check below
        _reuse16_back = repr(_e16b)
    try:
        with _p9.app_context():
            db.session.remove()
            db.engine.dispose()
    except Exception:  # nosec B110 - best-effort cleanup of a throwaway database
        pass
    try:
        if _CFG16_SNAPSHOT is None:
            if _P9_CFG_PATH.exists():
                _P9_CFG_PATH.unlink()
        else:
            _P9_CFG_PATH.write_bytes(_CFG16_SNAPSHOT)
    except OSError:  # nosec B110 - best-effort cleanup of the runner's throwaway config
        pass

check("part16: its two tables are given AUTOINCREMENT back by the panel's own migration",
      _reuse16_back == ["remote_server", "game_server"], repr(_reuse16_back))
check("part16: no route under test reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP16_START, repr(_P9_TRIPPED[_TRIP16_START:][:6]))
check("part16: every deferred worker was run (none left to leak into a later check)",
      not _p9_queue,
      "%d left: %s" % (len(_p9_queue), [getattr(f, "__qualname__", f) for f, _a, _k in _p9_queue]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 745379093 — the panel host's fail2ban log read, bounded at every layer
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Remote hosts were never exposed: run_privileged sends them the streaming zcat|awk|grep form, and
# their answer is capped at the transport. The PANEL host's helper built the whole list in memory,
# and its _run_verb collected whatever the verb printed.
_F2B16_DIR = _tf16.mkdtemp(prefix="lgsm-unit-f2b-")
# Dated YESTERDAY, not a fixed day: the readers keep only the last `days` (7) counted back from
# now, so a fixed date made every check below fail once it was a week old (review, 2026-09-29).
_F2B16_DAY = (_dt16.now() - __import__("datetime").timedelta(days=1)).strftime("%Y-%m-%d")
_F2B16_LINE = (_F2B16_DAY + " 10:00:00,123 fail2ban.filter [1]: INFO [sshd] Found "
               "2001:db8::%x - " + _F2B16_DAY + " 10:00:00")
_f2b16_saved = (_helper.F2B_LOG_GLOB, sys.stdout, sys.stderr)


def _f2b16_run(lines):
    with open(os.path.join(_F2B16_DIR, "fail2ban.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    out, err = _io16.StringIO(), _io16.StringIO()
    sys.stdout, sys.stderr = out, err
    try:
        rc = _helper.do_f2b_log_lines(["2026-09-01"], "")
    finally:
        sys.stdout, sys.stderr = _f2b16_saved[1], _f2b16_saved[2]
    return rc, out.getvalue(), err.getvalue()


try:
    _helper.F2B_LOG_GLOB = os.path.join(_F2B16_DIR, "fail2ban.log*")
    _few16 = [_F2B16_LINE % i for i in range(3)] + ["2026-08-01 old line [sshd] Found 1.2.3.4"]
    eq("f2b helper: an ordinary log is printed exactly as before (control)",
       _f2b16_run(_few16)[:2], (0, "\n".join(_few16[:3])))
    _rc16, _out16, _err16 = _f2b16_run([_F2B16_LINE % i for i in range(120000)])
    check("f2b helper: a log past the ceiling stops at it and says so (rc 3), never a partial 0",
          _rc16 == 3 and len(_out16.encode("utf-8")) <= getattr(_helper, "F2B_LOG_MAX_BYTES", 0)
          and "truncated" in _err16,
          "rc %r, %d bytes, %r" % (_rc16, len(_out16.encode("utf-8")), _err16[:80]))
finally:
    _helper.F2B_LOG_GLOB = _f2b16_saved[0]
    import shutil as _sh16util
    _sh16util.rmtree(_F2B16_DIR, ignore_errors=True)

from panel.ops.ssh_manager import _core as _core16  # noqa: E402
eq("f2b helper: its ceiling sits one read chunk under the transports' (they cannot drift)",
   getattr(_helper, "F2B_LOG_MAX_BYTES", None), _core16._MAX_OUTPUT_BYTES - 65536)

# _run_verb, all three branches, against a real child printing more than the ceiling. f2b-log-lines
# is all-or-nothing, so where THIS process's collector cut it (the root and shell forms, and a
# helper that predates its own ceiling, which is what this child stands in for) the answer is the
# helper's own answer for a cut read: rc 3. Any other verb keeps what fits, as it always did.
_BIG16 = [sys.executable, "-c",
          "import sys; sys.stdout.write('A' * (%d + 4096))" % _core16._MAX_OUTPUT_BYTES]
_rv16_saved = (_p9_so._helper_present, _p9_so.os, _p9_so._priv)
_rv16 = {}


class _Os16(object):
    """os, with geteuid answering what a branch needs (or absent)."""

    def __init__(self, euid):
        self._euid = euid

    def __getattr__(self, name):
        if name == "geteuid":
            if self._euid is None:
                raise AttributeError(name)
            return lambda: self._euid
        return getattr(os, name)


def _priv16(argv_for):
    """privileged.py's entry points, with every verb run as the local argv `argv_for(verb)`."""
    return NS(helper_argv=lambda v, a: list(argv_for(v)), tool_argv=lambda v, a: list(argv_for(v)),
              remote_command=lambda v, a, merge_stderr=True: " ".join(
                  __import__("shlex").quote(x) for x in argv_for(v)),
              stdin_for=lambda v: None, VerbError=ValueError)


try:
    _p9_so._priv = _priv16(lambda v: _BIG16)
    _p9_so._helper_present = lambda: True
    _rv16["helper"] = _p9_so._run_verb("f2b-log-lines", ["2026-09-01"], merge_stderr=False)
    _rv16["journal"] = _p9_so._run_verb("journal", ["panel", "20"], merge_stderr=False)
    _p9_so._helper_present = lambda: False
    _p9_so.os = _Os16(0)
    _rv16["root"] = _p9_so._run_verb("f2b-log-lines", ["2026-09-01"], merge_stderr=False)
    _p9_so.os = _Os16(None)            # no geteuid: the shell fallback, with no sudo prefix
    _rv16["shell"] = _p9_so._run_verb("f2b-log-lines", ["2026-09-01"], merge_stderr=False)
finally:
    _p9_so._helper_present, _p9_so.os, _p9_so._priv = _rv16_saved
_rv16_seen = {k: (len(v[0]), v[1][:60], v[2]) for k, v in _rv16.items()}
check("f2b _run_verb: every branch keeps at most the ceiling, and answers a cut read as rc 3",
      all(_rv16.get(k, ("", "", 0))[2] == 3 and "treated as unread" in _rv16[k][1]
          and 0 < len(_rv16[k][0]) <= _core16._MAX_OUTPUT_BYTES
          for k in ("helper", "root", "shell")), repr(_rv16_seen))
check("f2b _run_verb: ...while a verb that is not all-or-nothing keeps what fits, rc 0 (control)",
      _rv16.get("journal", ("", "", -1))[2] == 0
      and len(_rv16["journal"][0]) == _core16._MAX_OUTPUT_BYTES, repr(_rv16_seen.get("journal")))

_f2b16_verb = _p9_so._run_verb
try:
    _p9_so._run_verb = lambda verb, args=(), **k: ("", "panel-helper: truncated", 3)
    _ac16 = (_p9_so.fail2ban_attempt_counts(), _p9_so.fail2ban_top_ips())
    _p9_so._run_verb = lambda verb, args=(), **k: ("", "Command timed out", -1)
    _ac16 += (_p9_so.fail2ban_attempt_counts(), _p9_so.fail2ban_top_ips())
    _p9_so._run_verb = lambda verb, args=(), **k: (_F2B16_LINE % 7, "", 0)
    _ok16 = _p9_so.fail2ban_attempt_counts()
finally:
    _p9_so._run_verb = _f2b16_verb
check("f2b tally: a cut read (rc 3), or a failed one, is unread (None), never a partial tally",
      _ac16 == (None, None, None, None), repr([type(x).__name__ for x in _ac16]))
eq("f2b tally: an ordinary answer is still tallied (control)", _ok16, {"2001:db8::7": 1})


# ════════════════════════════════════════════════════════════════════════════════════════════════
# The fail2ban ceiling, EXACTLY: the helper and the panel agree where "complete" ends
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The helper answers rc 0 up to AND INCLUDING F2B_LOG_MAX_BYTES, and rc 3 one byte past it. The
# panel used to call `len >= F2B_LOG_MAX_BYTES` cut, so an answer of exactly the ceiling (complete
# by the helper's own rc) made both tallies None on the test VPS, where main tallied it. Now the rc
# decides: the helper's where it ran, and the collector's cut, answered as the same rc 3, where it
# did not. Driven through the real _run_verb, with the real helper function in a child for the
# first half and the pre-helper shell form for the second.
_EX16_MAX = getattr(_helper, "F2B_LOG_MAX_BYTES", _core16._MAX_OUTPUT_BYTES - 65536)
_EX16_ONE = _F2B16_LINE % 7
_EX16_IP = "2001:db8::7"
_EX16_DIR = _tf16.mkdtemp(prefix="lgsm-unit-f2b-exact-")
_EX16_CHILD = [sys.executable, "-c", (
    "import importlib.machinery as m, importlib.util as u, sys\n"
    "s = u.spec_from_loader('h', m.SourceFileLoader('h', %r))\n"
    "h = u.module_from_spec(s)\n"
    "s.loader.exec_module(h)\n"
    "h.F2B_LOG_GLOB = %r\n"
    "sys.exit(h.do_f2b_log_lines(['2026-09-01'], ''))\n")
    % (_helper_path, os.path.join(_EX16_DIR, "fail2ban.log*"))]
# The shell form's stand-in: exactly argv[1] bytes of the same lines, and no ceiling of its own.
_CAP16_CHILD = [sys.executable, "-c", (
    "import sys\n"
    "one, n = %r, int(sys.argv[1])\n"
    "k = n // (len(one) + 1)\n"
    "pad = n - (k * (len(one) + 1) - 1)\n"
    "sys.stdout.write('\\n'.join([one] * (k - 1) + [one + 'x' * pad]))\n")
    % _EX16_ONE]


def _ex16_lines(n):
    """Found lines for _EX16_IP which, joined by newlines, are exactly `n` bytes."""
    k = n // (len(_EX16_ONE) + 1)
    return [_EX16_ONE] * (k - 1) + [_EX16_ONE + "x" * (n - (k * (len(_EX16_ONE) + 1) - 1))]


def _ex16_log(n):
    """Write a fail2ban.log whose f2b-log-lines answer is exactly `n` bytes; its line count."""
    lines = _ex16_lines(n)
    with open(os.path.join(_EX16_DIR, "fail2ban.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return len(lines)


def _ex16_helper():
    """The helper's do_f2b_log_lines over _EX16_DIR, run in this process: (rc, bytes printed)."""
    saved = (_helper.F2B_LOG_GLOB, sys.stdout, sys.stderr)
    out = _io16.StringIO()
    _helper.F2B_LOG_GLOB = os.path.join(_EX16_DIR, "fail2ban.log*")
    sys.stdout, sys.stderr = out, _io16.StringIO()
    try:
        rc = _helper.do_f2b_log_lines(["2026-09-01"], "")
    finally:
        _helper.F2B_LOG_GLOB, sys.stdout, sys.stderr = saved
    return rc, len(out.getvalue().encode("utf-8"))


_ex16 = {}
_ex16_saved = (_p9_so._helper_present, _p9_so.os, _p9_so._priv, _p9_so.fail2ban_overview,
               _p9_so.ufw_blocked_ips)
try:
    _p9_so.fail2ban_overview = lambda: {"jails": []}      # top-ips' annotations: not under test
    _p9_so.ufw_blocked_ips = lambda shadowed=None: {}
    _p9_so._helper_present = lambda: True
    _p9_so._priv = _priv16(lambda v: _EX16_CHILD)
    for _name16, _n16 in (("exact", _EX16_MAX), ("over", _EX16_MAX + 1), ("under", _EX16_MAX - 1)):
        _k16 = _ex16_log(_n16)
        _ex16[_name16] = (_k16, _ex16_helper(), _p9_so.fail2ban_attempt_counts(),
                          _p9_so.fail2ban_top_ips() if _name16 == "exact" else None)
    _p9_so._helper_present = lambda: False
    _p9_so.os = _Os16(None)            # the shell fallback, with no sudo prefix
    _C16 = _core16._MAX_OUTPUT_BYTES
    for _name16, _n16 in (("cap", _C16), ("cap+1", _C16 + 1), ("cap-1", _C16 - 1)):
        _p9_so._priv = _priv16(lambda v, _n=_n16: _CAP16_CHILD + [str(_n)])
        _ex16[_name16] = (_n16 // (len(_EX16_ONE) + 1), None, _p9_so.fail2ban_attempt_counts(),
                          None)
finally:
    (_p9_so._helper_present, _p9_so.os, _p9_so._priv, _p9_so.fail2ban_overview,
     _p9_so.ufw_blocked_ips) = _ex16_saved
    import shutil as _sh16ex
    _sh16ex.rmtree(_EX16_DIR, ignore_errors=True)


def _ex16_got(name):
    """What case `name` answered, briefly: (lines written, helper (rc, bytes), tally shape)."""
    k, helper, tally, _top = _ex16.get(name, (None, None, "missing", None))
    return k, helper, (tally if not isinstance(tally, dict) else sorted(tally.items()))


_EX16_TOP = _ex16.get("exact", (0, None, None, None))[3]
check("f2b ceiling: the helper answers exactly its ceiling as complete (rc 0, every byte)",
      _ex16_got("exact")[1] == (0, _EX16_MAX), repr(_ex16_got("exact")[:2]))
check("f2b ceiling: ...one byte past it as cut (rc 3), and one byte under as complete",
      (_ex16_got("over")[1] or (None,))[0] == 3 and _ex16_got("under")[1] == (0, _EX16_MAX - 1),
      repr((_ex16_got("over")[1], _ex16_got("under")[1])))
check("f2b ceiling: the panel tallies an answer the helper called complete at exactly its ceiling",
      _ex16.get("exact", (0, 0, None))[2] == {_EX16_IP: _ex16["exact"][0]},
      repr(_ex16_got("exact")))
check("f2b ceiling: ...and top-ips ranks it, rather than answering None",
      isinstance(_EX16_TOP, list)
      and [(r["ip"], r["attempts"]) for r in _EX16_TOP] == [(_EX16_IP, _ex16["exact"][0])],
      repr(_EX16_TOP)[:200])
check("f2b ceiling: ...one byte past it is unread (None), and one byte under is tallied",
      _ex16.get("over", (0, 0, 0))[2] is None
      and _ex16.get("under", (0, 0, None))[2] == {_EX16_IP: _ex16["under"][0]},
      repr((_ex16_got("over"), _ex16_got("under"))))
check("f2b ceiling: with no helper the collector's cap decides, and exactly the cap is tallied",
      _ex16.get("cap", (0, 0, None))[2] == {_EX16_IP: _ex16["cap"][0]}, repr(_ex16_got("cap")))
check("f2b ceiling: ...one byte past the cap is unread (None), and one byte under is tallied",
      _ex16.get("cap+1", (0, 0, 0))[2] is None
      and _ex16.get("cap-1", (0, 0, None))[2] == {_EX16_IP: _ex16["cap-1"][0]},
      repr((_ex16_got("cap+1"), _ex16_got("cap-1"))))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# ...and on a REMOTE host, where there is no helper: the shell form stops at the same ceiling
# ════════════════════════════════════════════════════════════════════════════════════════════════
# A remote is sent privileged.py's rendering of f2b-log-lines, and its answer was judged by LENGTH:
# remote_fail2ban_attempt_counts called anything within 64 KB of the transport's cap cut, so a
# complete log just under it was thrown away, and remote top-ips tallied whatever arrived. The
# rendering now stops at the helper's ceiling itself and exits 3, and both readers decide from the
# rc. Driven end to end: the real run_privileged and rendering, run by the local transport's own
# shell executor over a sandboxed log (no sudo, nothing privileged), in a UTF-8 locale so a byte
# count that is really a character count shows; and under each awk this machine has, because a
# remote runs whichever one it has (Ubuntu's default is mawk).
import shutil as _shutil16  # noqa: E402

from panel.ops.ssh_manager import hosts as _hosts16  # noqa: E402
from panel.security import privileged as _privm16  # noqa: E402

_RF16_MAX = getattr(_privm16, "F2B_LOG_MAX_BYTES", _EX16_MAX)
_RF16_DIR = _tf16.mkdtemp(prefix="lgsm-unit-f2b-remote-")
_RF16_GLOB = os.path.join(_RF16_DIR, "fail2ban.log*")
_RF16_SRV = NS(name="f2b-remote16", host="192.0.2.16", port=22, username="lgsm", is_local=False,
               auth_method="key", sudo_enabled=True)
_RF16_OTHER = []
_RF16_FEW = [_F2B16_LINE % i for i in range(3)] + ["2026-08-01 old line [sshd] Found 1.2.3.4",
                                                    "2026-09-20 00:00:00 nothing of interest"]


def _rf16_write(lines):
    """Write the sandboxed fail2ban.log; the number of lines."""
    with open(os.path.join(_RF16_DIR, "fail2ban.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return len(lines)


def _rf16_transport(awk=None):
    """A run_command for _core that runs the f2b rendering locally over _RF16_DIR.

    With `awk` in place of the rendering's own when given. Anything else it is sent is refused and
    recorded.
    """
    def _run(server, command, timeout=30, sudo=None, stdin_text=None):
        if _privm16.F2B_LOG_GLOB not in command:
            _RF16_OTHER.append(command[:60])
            return "", "not under test", 1
        cmd = command.replace(_privm16.F2B_LOG_GLOB, _RF16_GLOB)
        if awk:
            cmd = cmd.replace(" awk ", " %s " % awk, 1)
        return _core16._exec_local_shell("export LC_ALL=C.UTF-8; " + cmd, timeout=timeout)
    return _run


def _rf16_read(awk=None):
    """The rendering's own answer over the current log: (rc, bytes of stdout, stderr)."""
    out, err, rc = _rf16_transport(awk)(_RF16_SRV, _privm16.remote_command(
        "f2b-log-lines", ["2026-09-01"], merge_stderr=False))
    return rc, len(out.encode("utf-8")), err


class _Rec16(object):
    """system_ops' logger, keeping the warnings."""

    def __init__(self):
        self.warnings = []

    def warning(self, msg, *a, **k):
        self.warnings.append(msg % a if a else msg)

    def __getattr__(self, name):
        return lambda *a, **k: None


_rf16 = {}
_RF16_AWKS = [a for a in ("gawk", "mawk") if _shutil16.which(a)]
_rf16_saved = (_core16.run_command, _p9_so._log, _hosts16.remote_fail2ban_overview,
               _hosts16.remote_ufw_blocked_ips)
try:
    for _rfawk16 in [None] + _RF16_AWKS:
        _rfk16 = _rf16_write(_ex16_lines(_RF16_MAX))
        _rfexact16 = _rf16_read(_rfawk16)
        _rf16_write(_ex16_lines(_RF16_MAX + 1))
        _rfover16 = _rf16_read(_rfawk16)
        _rf16_write(_ex16_lines(_RF16_MAX - 1))
        _rfunder16 = _rf16_read(_rfawk16)
        # One byte past the ceiling in BYTES, and exactly at it in characters: " - " (3 bytes) is
        # swapped for a space and an e-acute (3 bytes, 2 characters), after the tallied address.
        _rfmb16 = _ex16_lines(_RF16_MAX + 1)
        _rfmb16[0] = _rfmb16[0].replace(" - ", " \u00e9", 1)
        _rf16_write(_rfmb16)
        _rfmulti16 = _rf16_read(_rfawk16)
        _rf16_write(_RF16_FEW)
        _rffew16 = _rf16_transport(_rfawk16)(_RF16_SRV, _privm16.remote_command(
            "f2b-log-lines", ["2026-09-01"], merge_stderr=False))
        _rf16_write(["2026-09-20 00:00:00 nothing of interest"])
        _rfquiet16 = _rf16_read(_rfawk16)
        _rf16[_rfawk16 or "awk"] = (_rfexact16, _rfover16, _rfunder16, _rfmulti16, _rffew16,
                                    _rfquiet16)

    # The two readers, through the real run_privileged and the shipped rendering.
    _core16.run_command = _rf16_transport()
    _hosts16.remote_fail2ban_overview = lambda server: {"jails": []}   # annotations: not under test
    _hosts16.remote_ufw_blocked_ips = lambda server, shadowed=None: {}
    for _rfname16, _rfn16 in (("exact", _RF16_MAX), ("over", _RF16_MAX + 1)):
        _rfk16 = _rf16_write(_ex16_lines(_rfn16))
        _p9_so._log = _Rec16()
        _rf16[_rfname16] = (_rfk16, _hosts16.remote_fail2ban_attempt_counts(_RF16_SRV, days=7),
                            _hosts16.remote_fail2ban_top_ips(_RF16_SRV, limit=20, days=7),
                            list(_p9_so._log.warnings))
    _rf16_write(_RF16_FEW)
    _rf16["few"] = (3, _hosts16.remote_fail2ban_attempt_counts(_RF16_SRV, days=7), None, [])
    _core16.run_command = lambda server, command, timeout=30, sudo=None, stdin_text=None: (
        "", "SSH command timed out", -1)
    _rf16["failed"] = (0, _hosts16.remote_fail2ban_attempt_counts(_RF16_SRV, days=7),
                       _hosts16.remote_fail2ban_top_ips(_RF16_SRV, limit=20, days=7), [])
finally:
    (_core16.run_command, _p9_so._log, _hosts16.remote_fail2ban_overview,
     _hosts16.remote_ufw_blocked_ips) = _rf16_saved
    _shutil16.rmtree(_RF16_DIR, ignore_errors=True)

eq("f2b remote: the rendering's ceiling is the helper's (they cannot drift)",
   getattr(_privm16, "F2B_LOG_MAX_BYTES", None), getattr(_helper, "F2B_LOG_MAX_BYTES", 0))
for _rfawk16 in ["awk"] + _RF16_AWKS:
    _rfe16, _rfo16, _rfu16, _rfm16, _rff16, _rfq16 = _rf16.get(
        _rfawk16, ((None, 0, ""),) * 4 + (("", "", None), (None, 0, "")))
    check("f2b remote (%s): exactly the ceiling is complete (rc 0, every byte)" % _rfawk16,
          _rfe16[:2] == (0, _RF16_MAX), repr(_rfe16))
    check("f2b remote (%s): one byte past it is cut (rc 3), says so, and stops at it" % _rfawk16,
          _rfo16[0] == 3 and _rfo16[1] <= _RF16_MAX and "truncated" in _rfo16[2],
          repr(_rfo16)[:200])
    check("f2b remote (%s): one byte under it is complete (rc 0)" % _rfawk16,
          _rfu16[:2] == (0, _RF16_MAX - 1), repr(_rfu16))
    check("f2b remote (%s): the ceiling counts bytes, as the helper does, not characters"
          % _rfawk16, _rfm16[0] == 3, repr(_rfm16)[:200])
    check("f2b remote (%s): an ordinary log is read exactly as before (control)" % _rfawk16,
          tuple(_rff16) == ("\n".join(_RF16_FEW[:3]), "", 0), repr(_rff16)[:200])
    check("f2b remote (%s): a quiet log is a complete, empty read (rc 0)" % _rfawk16,
          tuple(_rfq16) == (0, 0, ""), repr(_rfq16))
for _rfawk16 in ("gawk", "mawk"):
    if _rfawk16 not in _RF16_AWKS:
        skip("f2b remote (%s): the rendering under %s" % (_rfawk16, _rfawk16),
             "%s is not installed here" % _rfawk16)
_rx16 = _rf16.get("exact", (0, "missing", "missing", []))
_ro16 = _rf16.get("over", (0, "missing", "missing", []))
check("f2b remote: attempt counts tally a log of exactly the ceiling (it was 'within 64 KB': None)",
      _rx16[1] == {_EX16_IP: _rx16[0]}, repr(_rx16[1])[:200])
check("f2b remote: ...and top-ips ranks it",
      isinstance(_rx16[2], list)
      and [(r["ip"], r["attempts"]) for r in _rx16[2]] == [(_EX16_IP, _rx16[0])],
      repr(_rx16[2])[:200])
check("f2b remote: one byte past the ceiling, both are unread (None), never a partial tally",
      _ro16[1] is None and _ro16[2] is None, repr((_ro16[1], _ro16[2]))[:200])
check("f2b remote: ...and each says why (a warning, as the panel host's readers give)",
      len(_ro16[3]) == 2 and all("ceiling" in w for w in _ro16[3]) and not _rx16[3],
      repr((_ro16[3], _rx16[3])))
eq("f2b remote: an ordinary log is tallied (control)",
   _rf16.get("few", (0, None))[1], {"2001:db8::0": 1, "2001:db8::1": 1, "2001:db8::2": 1})
check("f2b remote: a failed read is still unread (None), for both",
      _rf16.get("failed", (0, 0, 0))[1:3] == (None, None), repr(_rf16.get("failed")))
check("f2b remote: nothing but the fail2ban read reached the stand-in transport",
      not _RF16_OTHER, repr(_RF16_OTHER[:3]))
# The fixtures above are dated from the clock (_F2B16_DAY) because the readers keep only the last 7
# days counted back from now; a fixed date made them fail once it was a week old. Said by name.
check("f2b remote: (guard) the fixtures' day is inside the readers' 7-day window",
      _F2B16_DAY >= _p9_so._f2b_cutoff(7),
      "%s is before the readers' cutoff %s" % (_F2B16_DAY, _p9_so._f2b_cutoff(7)))

# ...and the remote form keeps the helper's LINES, not only its ceiling. Its byte count decides
# where a remote says "cut", so a filter that kept more or fewer lines than do_f2b_log_lines would
# cut a remote at another point than the panel host for the same log, and tally other events; the
# ceiling check above compares only the constant. One rotated family (a plain log, a plain .1 and
# a .gz) with Found and Ban lines for several jails, the Unban and Restore Ban lines neither keeps,
# lines ON the cutoff day (kept: the comparison is >=) and the day before. The helper's own read is
# the reference, and what the reader gets from the rendering must be exactly it, under each awk
# (the transport strips the output, awk's closing newline with it, as the SSH ones do). Valid UTF-8
# and no leading blanks: there the two differ by design (the helper counts a bad byte as U+FFFD's
# three; awk's $1 skips leading blanks), as the grep form did.
import gzip as _gz16  # noqa: E402
from datetime import timedelta as _tdfp16  # noqa: E402

# (days before now, time, the rest of the line, kept by the helper), per file of the family. One
# "now" for every date, so a run that crosses midnight cannot shift some of them and not others.
_FP16_NOW = _dt16.now()
_FP16_FAMILY = {
    "fail2ban.log": [
        (2, "10:00:00,000", "filter         [812]: INFO    [nginx-http-auth] Found 192.0.2.44", 1),
        (2, "10:00:01,000", "filter         [812]: INFO    [my_jail.v2] Found 192.0.2.44", 1),
        (2, "10:00:02,000", "filter         [812]: INFO    [sshd] Ignore 10.0.0.1 by ip", 0),
        (2, "10:00:03,000", "actions        [812]: WARNING [sshd] 203.0.113.5 already banned", 0),
        (0, "08:00:00,000", "actions        [812]: NOTICE  [recidive] Ban 203.0.113.5", 1)],
    "fail2ban.log.1": [
        (3, "06:00:00,000", "server         [812]: INFO    Jail 'sshd' started", 0),
        (3, "06:10:00,000", "filter         [812]: INFO    [panel-auth] Found 2001:db8::77", 1),
        (3, "06:10:05,000", "actions        [812]: NOTICE  [panel-auth] Ban 2001:db8::77", 1),
        (3, "06:20:00,000", "actions        [812]: NOTICE  [sshd] Unban 203.0.113.50", 0),
        (3, "06:30:00,000", "actions        [812]: NOTICE  [recidive] Restore Ban 192.0.2.7", 0)],
    "fail2ban.log.2.gz": [
        (4, "23:59:59,900", "filter         [812]: INFO    [sshd] Found 203.0.113.99", 0),
        (4, "23:59:59,950", "actions        [812]: NOTICE  [sshd] Ban 203.0.113.99", 0),
        (3, "00:00:00,000", "filter         [812]: INFO    [sshd] Found 203.0.113.50", 1),
        (3, "00:00:01,000", "actions        [812]: NOTICE  [sshd] Ban 203.0.113.50", 1)],
}


def _fp16_line(days, when, rest):
    """A fail2ban log line `days` before now, as fail2ban writes one."""
    day = (_FP16_NOW - _tdfp16(days=days)).strftime("%Y-%m-%d")
    return "%s %s fail2ban.%s" % (day, when, rest)


def _fp16_write_family():
    """Write _FP16_FAMILY into _RF16_DIR; the lines the helper keeps, in its (sorted) file order."""
    os.makedirs(_RF16_DIR, exist_ok=True)
    kept = []
    for name in sorted(_FP16_FAMILY):
        lines = [(_fp16_line(d, t, r), k) for d, t, r, k in _FP16_FAMILY[name]]
        data = ("\n".join(text for text, _k in lines) + "\n").encode("utf-8")
        opener = _gz16.open if name.endswith(".gz") else open
        with opener(os.path.join(_RF16_DIR, name), "wb") as fh:
            fh.write(data)
        kept += [text for text, k in lines if k]
    return kept


def _fp16_helper(cutoff):
    """The helper's do_f2b_log_lines over _RF16_DIR, run in this process: (rc, stdout, stderr)."""
    saved = (_helper.F2B_LOG_GLOB, sys.stdout, sys.stderr)
    out, err = _io16.StringIO(), _io16.StringIO()
    _helper.F2B_LOG_GLOB, sys.stdout, sys.stderr = _RF16_GLOB, out, err
    try:
        rc = _helper.do_f2b_log_lines([cutoff], "")
    finally:
        _helper.F2B_LOG_GLOB, sys.stdout, sys.stderr = saved
    return rc, out.getvalue(), err.getvalue()


_fp16 = {}
_FP16_KEPT = []
_FP16_CUT = (_FP16_NOW - _tdfp16(days=3)).strftime("%Y-%m-%d")
try:
    _FP16_KEPT = _fp16_write_family()
    _fp16["helper"] = _fp16_helper(_FP16_CUT)
    for _fpawk16 in ["awk"] + _RF16_AWKS:
        _fpout16, _fperr16, _fprc16 = _rf16_transport(None if _fpawk16 == "awk" else _fpawk16)(
            _RF16_SRV, _privm16.remote_command("f2b-log-lines", [_FP16_CUT], merge_stderr=False))
        _fp16[_fpawk16] = (_fprc16, _fpout16, _fperr16)
finally:
    _shutil16.rmtree(_RF16_DIR, ignore_errors=True)
_FP16_REF = _fp16.get("helper", (None, None, None))
eq("f2b parity: (premise) the helper keeps the cutoff day's lines, the .gz's too, and drops the "
   "day before, Unban and Restore Ban", _FP16_REF, (0, "\n".join(_FP16_KEPT), ""))
for _fpawk16 in ["awk"] + _RF16_AWKS:
    eq("f2b parity (%s): the remote rendering prints exactly the helper's lines" % _fpawk16,
       _fp16.get(_fpawk16), (0, _FP16_REF[1], ""))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# _run_verb's timeout, whatever the verb leaves behind — under eventlet AND plain threads
# ════════════════════════════════════════════════════════════════════════════════════════════════
# On the panel host a privileged verb is `sudo -n <helper> <verb>`: the panel's account can kill
# sudo, but not the root helper or what it runs, and those keep the pipes' write ends open. Found on
# the test VPS: `_run_verb("journal", ["panel", "20000"], timeout=1)` answered after 8.6s (main,
# subprocess.run: 1.0s), and a stand-in the kill could not reach held a 1s timeout for 16s under
# threads and 11s under eventlet — the kill's communicate(timeout=5), a SECOND reader on the pipes
# the capped readers were reading (under eventlet it raised "Second simultaneous read", swallowed),
# then each reader's grace of 5s in turn. Their descriptors stayed open, and sudo was left a zombie.
#
# The stand-in here is the same: a grandchild in its OWN session (setsid), so the kill's killpg
# misses it exactly as it misses a root process, ignoring SIGTERM for good measure, holding stdout
# and stderr open. Nothing privileged runs, and the shell branch is driven with no geteuid, so no
# `sudo` prefix either. The same functions run in this process (eventlet-patched, as the service
# is) and in a child interpreter that never imports eventlet's patcher (plain threads), so they
# import nothing from the suite.
import gc as _gc16  # noqa: E402
import shlex as _shlex16  # noqa: E402
import signal as _signal16  # noqa: E402
import time as _time16  # noqa: E402
import weakref as _weakref16  # noqa: E402


def _rv16_stub(so, branch, argv, popen):
    """Point _run_verb's `branch` at the local `argv`, with `popen` as Popen; the originals."""

    class _NoEuid(object):
        """os without geteuid: the shell branch, and no `sudo` prefix on it."""

        def __getattr__(self, name):
            if name == "geteuid":
                raise AttributeError(name)
            return getattr(os, name)

    saved = (so._priv, so._helper_present, so.os, so.subprocess.Popen)
    so._priv = NS(helper_argv=lambda v, a: list(argv), tool_argv=lambda v, a: list(argv),
                  remote_command=lambda v, a, merge_stderr=True: " ".join(
                      _shlex16.quote(x) for x in argv),
                  stdin_for=lambda v: None, VerbError=ValueError)
    so._helper_present = lambda: branch == "helper"
    so.os = os if branch == "helper" else _NoEuid()
    so.subprocess.Popen = popen
    return saved


def _rv16_recorder(real, made, pipes, comms):
    """A Popen stand-in: `real`'s process, recorded with its pipes' identities and communicate()s.

    A function, not a subclass: under tools/nosudo_runner the module's Popen is its shim's method.
    It keeps only the pid and a WEAK reference, as a caller that drops its Popen would: a pipe still
    open afterwards is one something else holds (a reader that never let go), not this recorder.
    """

    def popen(*a, **k):
        p = real(*a, **k)
        made.append((p.pid, _weakref16.ref(p)))
        for s in (p.stdout, p.stderr):
            if s is not None:
                pipes.append(os.readlink("/proc/self/fd/%d" % s.fileno()))
        talk, ref = type(p).communicate, _weakref16.ref(p)

        def communicate(*ca, **ck):
            comms.append(1)
            return talk(ref(), *ca, **ck)
        p.communicate = communicate
        return p
    return popen


def _rv16_open_pipes(pipes):
    """How many of our ends of `pipes` this process still holds open, once garbage is collected."""
    _gc16.collect()
    held = 0
    for fd in os.listdir("/proc/self/fd"):
        try:
            held += os.readlink("/proc/self/fd/" + fd) in pipes
        except OSError:
            continue
    return held


def _rv16_reaped(pid):
    """Whether child `pid` was reaped by the code under test (not a zombie, not still running)."""
    if pid is None:
        return False
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    return False


def _rv16_holder(pidfile):
    """Whether the stand-in named in `pidfile` was still alive; if it was, it is SIGKILLed now.

    The pidfile goes once read, and a pid is killed only while it is still that stand-in (its
    command line names rv16-standin): one already gone may have handed its pid to someone else.
    """
    if not pidfile:
        return None
    try:
        with open(pidfile, encoding="utf-8") as fh:
            pid = int(fh.read().strip())
        os.unlink(pidfile)
        with open("/proc/%d/cmdline" % pid, "rb") as fh:
            if b"rv16-standin" not in fh.read():
                return False
        os.kill(pid, _signal16.SIGKILL)
    except (OSError, ValueError):
        return False
    return True


def _rv16_case(so, core, case):
    """One _run_verb call against a local command: its answer, time, and what it left behind."""
    branch, argv, timeout, pidfile, grace = case
    made, pipes, comms = [], [], []
    saved = _rv16_stub(so, branch, argv, _rv16_recorder(so.subprocess.Popen, made, pipes, comms))
    saved_grace = core._READER_GRACE
    core._READER_GRACE = grace or saved_grace
    t0 = _time16.monotonic()
    try:
        got = so._run_verb("journal", ["panel", "20000"], timeout=timeout, merge_stderr=False)
    finally:
        took = _time16.monotonic() - t0
        so._priv, so._helper_present, so.os, so.subprocess.Popen = saved
        core._READER_GRACE = saved_grace
    return {"got": [got[0][:40], len(got[0]), got[1][:40], len(got[1]), got[2]],
            "took": round(took, 2), "span": [t0, t0 + took], "open": _rv16_open_pipes(pipes),
            "reaped": _rv16_reaped(made[-1][0] if made else None), "communicate": len(comms),
            "holder": _rv16_holder(pidfile)}


def _rv16_all(so, core, cases):
    """Every case, {name: result}, and whether this interpreter is eventlet-patched."""
    patcher = sys.modules.get("eventlet.patcher")
    return {"patched": bool(patcher and patcher.is_monkey_patched("thread")),
            "runs": {name: _rv16_case(so, core, case) for name, case in cases}}


_RV16_TMP = _tf16.mkdtemp(prefix="lgsm-unit-rv16-")


# The stand-in: ignores SIGTERM, names its pid, then holds the pipes for 30s -- silently, or writing
# 64 KB every 10ms. PACED, not `yes`: the pre-fix kill path's communicate() kept everything it read,
# with no ceiling, and against `yes` it took this suite past its 3 GB cap into the OOM killer.
_RV16_STANDIN = os.path.join(_RV16_TMP, "rv16-standin.py")
with open(_RV16_STANDIN, "w", encoding="utf-8") as _fh16:
    _fh16.write("import os, signal, sys, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "with open(sys.argv[1] + '.tmp', 'w') as fh:\n"
                "    fh.write(str(os.getpid()))\n"
                "os.replace(sys.argv[1] + '.tmp', sys.argv[1])\n"
                "for _ in range(3000 if sys.argv[2] == 'write' else 0):\n"
                "    sys.stdout.buffer.write(bytes(65536))\n"
                "    sys.stdout.buffer.flush()\n"
                "    time.sleep(0.01)\n"
                "time.sleep(30)\n")


def _rv16_held(tag, kind, child):
    """(argv, pidfile): /bin/sh running `child`, with a setsid'd stand-in of `kind` behind it."""
    pid = os.path.join(_RV16_TMP, tag + ".pid")
    return ["/bin/sh", "-c", "setsid %s & %s" % (" ".join(_shlex16.quote(x) for x in (
        sys.executable, _RV16_STANDIN, pid, kind)), child)], pid


def _rv16_cases(mode):
    """The cases, for one mode: [name, [branch, argv, timeout, pidfile, reader grace]]."""
    hold, hold_pid = _rv16_held(mode + "-hold", "hold", "printf partial; exec sleep 60")
    shell, shell_pid = _rv16_held(mode + "-shell", "hold", "printf partial; exec sleep 60")
    writer, writer_pid = _rv16_held(mode + "-writer", "write", "exec sleep 60")
    exited, exited_pid = _rv16_held(mode + "-exited", "hold", "printf kept")
    return [["quick", ["helper", ["/bin/sh", "-c", "printf 'hello\\n'; printf 'warn\\n' >&2"],
                       10, None, None]],
            ["big", ["helper", [sys.executable, "-c", "import sys; sys.stdout.write('A' * 3000000);"
                                " sys.stderr.write('B' * 1000000)"], 30, None, None]],
            ["hold", ["helper", hold, 1, hold_pid, None]],
            ["shell", ["shell", shell, 1, shell_pid, None]],
            ["writer", ["helper", writer, 1, writer_pid, None]],
            ["exited", ["helper", exited, 10, exited_pid, 1]]]


# The child: the functions above, then a main that redirects the three config paths (as this
# runner does) before anything else imports panel.core.config.
_RV16_SRC = "\n\n".join(__import__("inspect").getsource(f) for f in (
    _rv16_stub, _rv16_recorder, _rv16_open_pipes, _rv16_reaped, _rv16_holder, _rv16_case,
    _rv16_all)) + ((
    "\n\nimport json, os, shutil, sys, tempfile\n"
    "import gc as _gc16, shlex as _shlex16, signal as _signal16, time as _time16\n"
    "import weakref as _weakref16\n"
    "from types import SimpleNamespace as NS\n"
    "sys.path.insert(0, %r)\n"
    "from panel.core import config as _c\n"
    "_d = tempfile.mkdtemp(prefix='lgsm-unit-rv16-cfg-')\n"
    "for _n in ('CONFIG_FILE', 'SECRET_FILE', 'CRED_KEY_FILE'):\n"
    "    setattr(_c, _n, type(getattr(_c, _n))(_d) / getattr(_c, _n).name)\n"
    "from panel.ops import system_ops as so\n"
    "from panel.ops.ssh_manager import _core as core\n"
    "try:\n"
    "    print('RV16=' + json.dumps(_rv16_all(so, core, json.loads(%r))))\n"
    "finally:\n"
    "    shutil.rmtree(_d, ignore_errors=True)\n")
    % (_REPO16, _json16.dumps(_rv16_cases("threads"))))
import subprocess as _sp16  # noqa: E402  # nosec B404 - the suite's own interpreter, fixed code
_rv16_env = {k: v for k, v in os.environ.items() if k != "PYTEST_CURRENT_TEST"}
_rv16_child = _sp16.Popen([sys.executable, "-c", _RV16_SRC], stdout=_sp16.PIPE,  # nosec B603
                          stderr=_sp16.PIPE, stdin=_sp16.DEVNULL, cwd=_REPO16, env=_rv16_env)
import threading as _thr16  # noqa: E402
_rv16_beat = {"last": _time16.monotonic(), "gaps": [], "run": True}


def _rv16_heartbeat():
    """Record each stretch of over 0.1s that the hub went without running this greenlet."""
    while _rv16_beat["run"]:
        _time16.sleep(0.02)
        now = _time16.monotonic()
        if now - _rv16_beat["last"] > 0.1:
            _rv16_beat["gaps"].append((_rv16_beat["last"], now))
        _rv16_beat["last"] = now


def _rv16_held_hub(gaps, runs):
    """The longest the heartbeat went unrun INSIDE a _run_verb call: each gap cut to each call.

    Only the calls. Between them the check runs its own gc.collect() (_rv16_open_pipes), on the
    hub, over the whole suite's heap; that is not the panel's code, and on GitHub's 26.04 runner it
    alone was a 2.35s gap that failed a correct tree.
    """
    return max([min(b, r["span"][1]) - max(a, r["span"][0]) for a, b in gaps
                for r in runs.values()] + [0.0])


_rv16_hb = _thr16.Thread(target=_rv16_heartbeat, daemon=True)
_rv16_hb.start()
try:
    _RV16 = {"eventlet": _rv16_all(_p9_so, _core16, _rv16_cases("eventlet"))}
finally:
    _rv16_beat["run"] = False
    _time16.sleep(0.1)     # it ends at its next beat; no join(timeout=): see _collect_capped


# ── _collect_capped closes the pipes and reaps ITSELF, for a caller that keeps its Popen ────────
# _run_verb drops its Popen, so once the readers let go, CPython's refcounting alone would close
# those pipes, and Popen.__del__ reaps a dead child: the checks above could not tell. A caller that
# keeps its Popen (the local exec paths' except branch kills it again) gets neither, and the
# docstring promises both. The kill is this check's own, a plain killpg. Both thread kinds: green,
# as _run_verb and the ssh CLI use it, and native inside tpool, as _finish does.
def _cc16_kill(p):
    """SIGKILL `p`'s process group (it leads one); one already gone is fine."""
    try:
        os.killpg(p.pid, _signal16.SIGKILL)
    except ProcessLookupError:
        return


def _cc16_run(threads, popen, argv, timeout):
    """_collect_capped over a Popen this check keeps: (timed out, both pipes closed, reaped)."""
    p = popen(argv, stdout=_sp16.PIPE, stderr=_sp16.PIPE, stdin=_sp16.DEVNULL,
              start_new_session=True)
    res = _core16._collect_capped(p, timeout, threads=threads,
                                  kill=lambda: _cc16_kill(p))
    return res is None, p.stdout.closed and p.stderr.closed, p.returncode is not None


_cc16 = {}
for _kind16 in ("green", "native"):
    for _what16 in ("exits", "held"):
        _argv16, _pid16 = ((["/bin/sh", "-c", "printf ok"], None) if _what16 == "exits" else
                           _rv16_held("cc-%s" % _kind16, "hold", "exec sleep 60"))
        _job16 = (lambda a=_argv16, t=(10 if _what16 == "exits" else 1), k=_kind16: _cc16_run(
            _thr16 if k == "green" else _core16._real_threading,
            _core16.subprocess.Popen if k == "green" else _core16._real_subprocess.Popen, a, t))
        try:
            _cc16[(_kind16, _what16)] = (_job16() if _kind16 == "green"
                                         else _core16._in_tpool(_job16))
        except Exception as _e16c:  # noqa: BLE001 - reported by the check below
            _cc16[(_kind16, _what16)] = repr(_e16c)
        _rv16_holder(_pid16)
check("capped reader: a command that exits has both pipes closed by the collector (green, native)",
      _cc16.get(("green", "exits")) == (False, True, True)
      and _cc16.get(("native", "exits")) == (False, True, True), repr(_cc16))
check("capped reader: ...and one killed at its timeout, a stand-in holding the pipes, is closed "
      "AND reaped", _cc16.get(("green", "held")) == (True, True, True)
      and _cc16.get(("native", "held")) == (True, True, True), repr(_cc16))

try:
    _rv16_out, _rv16_err = _rv16_child.communicate(timeout=120)
except _sp16.TimeoutExpired:
    _rv16_child.kill()
    _rv16_out, _rv16_err = _rv16_child.communicate()
_rv16_line = [ln for ln in _rv16_out.decode("utf-8", "replace").splitlines()
              if ln.startswith("RV16=")]
_RV16["threads"] = (_json16.loads(_rv16_line[-1][5:]) if _rv16_line else
                    {"patched": None, "runs": {}, "stderr": _rv16_err.decode()[-600:]})
for _f16 in os.listdir(_RV16_TMP):              # a stand-in whose case never got to it
    if _f16.endswith(".pid"):
        _rv16_holder(os.path.join(_RV16_TMP, _f16))
__import__("shutil").rmtree(_RV16_TMP, ignore_errors=True)

check("run_verb timeout: the in-suite run is eventlet-patched and the child's is not (they differ)",
      _RV16["eventlet"]["patched"] is True and _RV16["threads"]["patched"] is False,
      repr((_RV16["eventlet"]["patched"], _RV16["threads"].get("patched"),
            _RV16["threads"].get("stderr", ""))))
_TIMED_OUT16 = ["", 0, "Command timed out", 17, -1]
for _mode16 in ("eventlet", "threads"):
    _r16 = _RV16[_mode16]["runs"]
    _q16, _b16 = _r16.get("quick", {}), _r16.get("big", {})
    check("run_verb (%s): a quick command still answers in full, rc 0 (control)" % _mode16,
          _q16.get("got") == ["hello", 5, "warn", 4, 0] and _q16.get("open") == 0
          and _q16.get("reaped") is True, repr(_q16))
    _bg16 = _b16.get("got") or [0] * 5
    check("run_verb (%s): ...and output far past a pipe's buffer, on both pipes, is read whole"
          % _mode16, [_bg16[1], _bg16[3], _bg16[4]] == [3000000, 1000000, 0], repr(_b16)[:300])
    for _case16 in ("hold", "shell", "writer"):
        _c16 = _r16.get(_case16, {})
        check("run_verb (%s, %s): a timeout of 1s answers within 3s though the kill misses a "
              "descendant holding the pipes" % (_mode16, _case16),
              _c16.get("got") == _TIMED_OUT16 and _c16.get("took", 99) < 3, repr(_c16))
        check("run_verb (%s, %s): ...closing our ends of its pipes, reaping the child, and never "
              "reading them with a second reader" % (_mode16, _case16),
              _c16.get("open") == 0 and _c16.get("reaped") is True
              and _c16.get("communicate") == 0, repr(_c16))
    check("run_verb (%s): ...the stand-in really was out of the kill's reach (it outlived the call)"
          % _mode16, _r16.get("hold", {}).get("holder") is True
          and _r16.get("shell", {}).get("holder") is True, repr(_r16.get("hold")))
    _e16 = _r16.get("exited", {})
    check("run_verb (%s): a command that exits while a descendant holds its pipes gets ONE reader "
          "grace for all its pipes, then they are closed" % _mode16,
          _e16.get("got") == ["kept", 4, "", 0, 0] and _e16.get("took", 99) < 1.8
          and _e16.get("open") == 0 and _e16.get("holder") is True, repr(_e16))
# What "kept running" can be told apart from. The process wait is green either way; what holds the
# hub is a NATIVE Event waited in this greenlet, through the 1s reader grace each case above ends in
# (the kill's, or the "exited" case's own). Collecting with threads=_real_threading in
# _collect_verb_output held it 1.10s inside a call; this tree, 0.011s (dev machine). 0.5s sits
# between. Measured INSIDE the calls only (_rv16_held_hub): the whole-window gap this used to be was
# mostly the check's own gc.collect() between them -- six of 0.36-0.44s over 1.9M objects here --
# and it failed a correct tree at 2.35s on GitHub's 26.04 runner (PR #385), while its 1.5s bound
# passed that mutation at 1.45s.
_rv16_held = _rv16_held_hub(_rv16_beat["gaps"], _RV16["eventlet"]["runs"])
check("run_verb (eventlet): the rest of the panel kept running through every wait",
      _rv16_held < 0.5, "the longest gap between heartbeats inside a call was %.2fs" % _rv16_held)


# ── the capped reader itself: eventlet's green read answers "" (a str) for a closed descriptor ──
class _StrEOF16(object):
    """A pipe whose read answers what eventlet's green os.read does when the fd is closed: ""."""

    def __init__(self):
        self.reads = 0

    def read(self, n):
        self.reads += 1
        if self.reads > 1:
            raise RuntimeError("read again after the end")
        return ""


_se16, _sebuf16, _seflags16 = _StrEOF16(), bytearray(), {"truncated": False}
try:
    _core16._pump_capped(_se16, _sebuf16, 16, _seflags16)
    _se16_err = None
except Exception as _e16x:  # noqa: BLE001 - the regression IS the raise
    _se16_err = repr(_e16x)
check("capped reader: a green read's '' ends the read like b'' does (no second read, no error)",
      _se16_err is None and _se16.reads == 1 and not _sebuf16, repr((_se16_err, _se16.reads)))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 745379329 — BY DESIGN: skipped and neutral check runs pass the self-update gate
# ════════════════════════════════════════════════════════════════════════════════════════════════
# No code change, and these pin why. GitHub's own rule for a required check is "successful,
# skipped, or neutral", and main's commits carry legitimately skipped runs: this is the tip of
# main as the check-runs API answered for 83ca9f9 on 2026-09-29 (one run per suite, trimmed to the
# shapes that matter). The PR-only "Open code-scanning alerts (PR)" is skipped on every push, and
# fork PRs file skipped workflow_run runs of "Open code-scanning alerts" beside the push run.
# Counting skipped as failing would block every update the panel is offered.
# (CI's other three jobs are listed too since the gate REQUIRES each of them to be present on a
# code commit — system_ops._CI_REQUIRED; they were trimmed from this sample as "shapes that don't
# matter", and now they do.)
_CI16 = [("checks (ubuntu-24.04 · py3.12)", "success"), ("coverage", "success"),
         ("js coverage", "success"), ("gamedig lockfile (node 22)", "success"),
         ("Analyze (python)", "success"),
         ("Open code-scanning alerts (PR)", "skipped"), ("Open code-scanning alerts", "success"),
         ("Open code-scanning alerts", "skipped"), ("Open code-scanning alerts", "skipped"),
         ("Upload coverage to Codacy", "skipped"), ("deploy", "skipped"), ("lighthouse", "success"),
         ("Scorecard analysis", "neutral")]


def _ci16(runs):
    body = _json16.dumps({"check_runs": [{"name": n, "status": "completed", "conclusion": c}
                                         for n, c in runs]}).encode()
    return lambda req, timeout=8: _io16.BytesIO(body)


_ci16_saved = (_p9_so._repo_slug, _p9_so.urllib.request.urlopen)
try:
    _p9_so._repo_slug = lambda: "o/r"
    _p9_so.urllib.request.urlopen = _ci16(_CI16)
    _ci16_ok = _p9_so._remote_ci_state("a" * 40)
    # A skipped run added beside a FAILING one (a fork PR's workflow_run) masks nothing: every
    # suite's run is listed, and any failing conclusion fails the gate.
    _p9_so.urllib.request.urlopen = _ci16([(n, "failure" if (n, c) == ("Open code-scanning alerts",
                                                                       "success") else c)
                                           for n, c in _CI16])
    _ci16_bad = _p9_so._remote_ci_state("a" * 40)
finally:
    _p9_so._repo_slug, _p9_so.urllib.request.urlopen = _ci16_saved
eq("ci-gate (by design): main's real mix of success, skipped and neutral runs is 'passing'",
   _ci16_ok, "passing")
eq("ci-gate (by design): ...and a skipped run of a check beside its failing run still fails",
   _ci16_bad, "failing")

# ════════════════════════════════════════════════════════════════════════════════════════════════
# Self-heal, backup codes, the game-list lock, key files, db_maintenance's corruption test
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Driven against temp files of their own; none of it touches part12's app or database.
import sqlite3 as _sq16h                                                            # noqa: E402

import db_maintenance as _dbm16h                                                    # noqa: E402
from panel.core import config as _cfg16h                                            # noqa: E402
from panel.db import models as _m16h                                                # noqa: E402
from panel.services import lgsm_data as _lg16h                                      # noqa: E402

_H16_DIR = _tf16.mkdtemp(prefix="heal16-")
# manage.py (imported by earlier parts) sets this for the whole process; these checks are about the
# service's own startup, so it is cleared for them and put back after.
_h16_env = os.environ.pop(_m16h.NO_SELF_HEAL_ENV, None)
_h16_defaults = _m16h._quick_check_patiently.__defaults__
_m16h._quick_check_patiently.__defaults__ = (3, 0.01)


def _h16_db(name, rows=50):
    p = os.path.join(_H16_DIR, name)
    c = _sq16h.connect(p)
    c.execute("CREATE TABLE x (a INTEGER)")
    c.executemany("INSERT INTO x VALUES (?)", [(i,) for i in range(rows)])
    c.commit()
    c.close()
    return p


def _h16_bytes(p):
    try:
        with open(p, "rb") as f:
            return f.read()
    except OSError:
        return None


def _h16_rows(p):
    c = _sq16h.connect(p)
    try:
        return c.execute("SELECT COUNT(*) FROM x").fetchone()[0]
    except _sq16h.Error as e:
        return "unreadable: %s" % e
    finally:
        c.close()


def _h16_write(p, body):
    with open(p, "wb") as f:
        f.write(body)


_H16_GARBAGE = b"garbage, not sqlite " * 60
try:
    # ── 1. a LOCKED database is not a corrupt one ──────────────────────────────────────────────
    _h16_live = _h16_db("locked.db", rows=30)
    _shutil16.copy2(_h16_db("older.db", rows=5), _h16_live + ".backup")   # an OLDER, smaller backup
    _h16_before = _h16_bytes(_h16_live)
    _h16_holder = _sq16h.connect(_h16_live, isolation_level=None)
    _h16_holder.execute("BEGIN EXCLUSIVE")            # another process mid-write
    _h16_real_connect = _sq16h.connect
    _sq16h.connect = lambda p, *a, **k: _h16_real_connect(p, *a, **dict(k, timeout=0.05))
    try:
        try:
            _h16_qc = _m16h._db_quick_check(_h16_live)
        except _sq16h.OperationalError as _e:
            _h16_qc = "raised: %s" % _e
        try:
            _m16h._ensure_db_healthy(_h16_live)
            _h16_heal = "returned"
        except _sq16h.OperationalError as _e:
            _h16_heal = "raised: %s" % _e
    finally:
        _sq16h.connect = _h16_real_connect
        _h16_holder.execute("ROLLBACK")
        _h16_holder.close()
    check("self-heal: quick_check on a LOCKED database raises instead of answering 'corrupt'",
          str(_h16_qc).startswith("raised:") and "locked" in str(_h16_qc), repr(_h16_qc))
    check("self-heal: ...and startup fails on it rather than 'healing' it into the older backup",
          str(_h16_heal).startswith("raised:"), repr(_h16_heal))
    _h16_aside = [n for n in os.listdir(_H16_DIR) if n.startswith("locked.db.corrupt-")]
    check("self-heal: ...the live database is untouched: same bytes, same 30 rows, nothing aside",
          _h16_bytes(_h16_live) == _h16_before and _h16_rows(_h16_live) == 30 and not _h16_aside,
          repr((_h16_rows(_h16_live), _h16_aside)))

    # ── 2. a database that cannot be OPENED is not a corrupt one either ─────────────────────────
    _h16_dir_db = os.path.join(_H16_DIR, "isdir.db")
    os.makedirs(os.path.join(_h16_dir_db, "keep"))    # non-empty, so getsize() is not 0
    try:
        _m16h._ensure_db_healthy(_h16_dir_db)
        _h16_open = "returned"
    except _sq16h.DatabaseError as _e:
        _h16_open = "raised: %s" % _e
    check("self-heal: 'unable to open database file' fails startup and moves nothing aside",
          _h16_open.startswith("raised:") and os.path.isdir(os.path.join(_h16_dir_db, "keep"))
          and not [n for n in os.listdir(_H16_DIR) if n.startswith("isdir.db.corrupt-")],
          _h16_open)

    # ── 3. a genuinely corrupt database: -wal and -shm move WITH it, the backup comes back ─────
    _h16_bad = _h16_db("bad.db", rows=8)
    _shutil16.copy2(_h16_bad, _h16_bad + ".backup")
    _h16_write(_h16_bad, _H16_GARBAGE)
    _h16_write(_h16_bad + "-wal", b"WAL-FRAMES-" * 40)
    _h16_write(_h16_bad + "-shm", b"SHM" * 40)
    check("self-heal: a garbage file IS corruption (control)",
          _m16h._db_quick_check(_h16_bad) is False)
    _m16h._ensure_db_healthy(_h16_bad)
    _h16_as = sorted(n for n in os.listdir(_H16_DIR) if n.startswith("bad.db.corrupt-"))
    _h16_main = [n for n in _h16_as if not n.endswith(("-wal", "-shm"))]
    _h16_base = os.path.join(_H16_DIR, _h16_main[0]) if len(_h16_main) == 1 else ""
    check("self-heal: the corrupt file's -wal and -shm are MOVED aside beside it, not deleted",
          # The -shm is only an index SQLite rebuilds from the -wal (the read-only check maps it,
          # which grows it), so it is held to "moved", the -wal to its exact bytes.
          bool(_h16_base) and _h16_bytes(_h16_base + "-wal") == b"WAL-FRAMES-" * 40
          and os.path.exists(_h16_base + "-shm"), repr(_h16_as))
    check("self-heal: ...nothing of them is left beside the restored database, which is the backup",
          not os.path.exists(_h16_bad + "-wal") and not os.path.exists(_h16_bad + "-shm")
          and _h16_rows(_h16_bad) == 8, repr(_h16_rows(_h16_bad)))

    # ── 4. a move aside that FAILS restores nothing ────────────────────────────────────────────
    _h16_real_replace = os.replace
    for _h16_case, _h16_fail_on in (("the database itself", ""), ("its -wal", "-wal")):
        _h16_p = os.path.join(_H16_DIR, "stuck%d.db" % len(_h16_fail_on))
        _shutil16.copy2(_h16_db("good%d.db" % len(_h16_fail_on), rows=3), _h16_p + ".backup")
        _h16_write(_h16_p, _H16_GARBAGE)
        _h16_write(_h16_p + "-wal", b"uncheckpointed" * 20)
        _h16_snap = (_h16_bytes(_h16_p), _h16_bytes(_h16_p + "-wal"))

        def _h16_replace(src, dst, _fail=_h16_p + _h16_fail_on):
            if str(src) == _fail:
                raise PermissionError("denied")
            return _h16_real_replace(src, dst)
        os.replace = _h16_replace
        try:
            _m16h._ensure_db_healthy(_h16_p)      # logs; never raises for a corrupt file
        finally:
            os.replace = _h16_real_replace
        check("self-heal: when moving %s aside fails, the backup is NOT copied over the files, "
              "which are left exactly as they were" % _h16_case,
              (_h16_bytes(_h16_p), _h16_bytes(_h16_p + "-wal")) == _h16_snap
              and not [n for n in os.listdir(_H16_DIR)
                       if n.startswith(os.path.basename(_h16_p) + ".corrupt-")],
              repr(sorted(n for n in os.listdir(_H16_DIR) if n.startswith("stuck"))))

    # ── 5. the offline CLI never heals ──────────────────────────────────────────────────────────
    _h16_cli = os.path.join(_H16_DIR, "cli.db")
    _shutil16.copy2(_h16_db("clibk.db", rows=2), _h16_cli + ".backup")
    _h16_write(_h16_cli, _H16_GARBAGE)
    os.environ[_m16h.NO_SELF_HEAL_ENV] = "1"
    try:
        _m16h._ensure_db_healthy(_h16_cli)
    finally:
        os.environ.pop(_m16h.NO_SELF_HEAL_ENV, None)
    check("self-heal: with the CLI's flag set nothing is moved or restored",
          _h16_bytes(_h16_cli) == _H16_GARBAGE
          and not [n for n in os.listdir(_H16_DIR) if n.startswith("cli.db.corrupt-")])
    with open(os.path.join(_REPO16, "manage.py"), encoding="utf-8") as _f:
        _h16_msrc = _f.read()
    check("self-heal: manage.py sets that flag BEFORE it builds the app",
          "os.environ[NO_SELF_HEAL_ENV] = \"1\"" in _h16_msrc
          and _h16_msrc.index("os.environ[NO_SELF_HEAL_ENV]") < _h16_msrc.index("app = create_app()"))

    # ── 6. db_maintenance: unreachable is not damaged, and the aside keeps the WAL ──────────────
    _h16_ic_dir = _dbm16h.integrity_check(_h16_dir_db)
    check("dbm: a database that cannot be opened is reported as unreadable, not as damaged",
          _h16_ic_dir[0] is False and _dbm16h.check_unreachable(_h16_ic_dir[1]), repr(_h16_ic_dir))
    _h16_garbage = os.path.join(_H16_DIR, "dbm-garbage.db")
    _h16_write(_h16_garbage, _H16_GARBAGE)
    _h16_ic_bad = _dbm16h.integrity_check(_h16_garbage)
    check("dbm: ...and a garbage file IS damaged (control)",
          _h16_ic_bad[0] is False and not _dbm16h.check_unreachable(_h16_ic_bad[1]),
          repr(_h16_ic_bad))
    _h16_rep_calls = []
    _h16_real_repair = _dbm16h.repair
    _dbm16h.repair = lambda *a, **k: (_h16_rep_calls.append(a), (False, "not really"))[1]
    _h16_stdout, sys.stdout = sys.stdout, _io16.StringIO()
    try:
        _h16_rc = _dbm16h.run_update_maintenance(_h16_dir_db, _h16_dir_db + ".backup")
        _h16_rc_bad = _dbm16h.run_update_maintenance(_h16_garbage, _h16_garbage + ".backup")
    finally:
        sys.stdout = _h16_stdout
        _dbm16h.repair = _h16_real_repair
    check("dbm/update: a database it could not READ aborts the update (2) without repairing it",
          _h16_rc == 2 and all(c[0] != _h16_dir_db for c in _h16_rep_calls),
          repr((_h16_rc, _h16_rep_calls)))
    check("dbm/update: ...while a damaged one is still sent to repair (control)",
          [c[0] for c in _h16_rep_calls] == [_h16_garbage] and _h16_rc_bad == 2,
          repr((_h16_rc_bad, _h16_rep_calls)))
    _h16_wdb = _h16_db("walled.db", rows=4)
    _h16_write(_h16_wdb + "-wal", b"committed-but-not-checkpointed" * 10)
    _h16_ad = _dbm16h._aside(_h16_wdb)
    check("dbm/aside: the forensic copy carries the -wal, under the name SQLite opens it by",
          bool(_h16_ad) and _h16_bytes(_h16_ad) == _h16_bytes(_h16_wdb)
          and _h16_bytes(_h16_ad + "-wal") == b"committed-but-not-checkpointed" * 10,
          repr(_h16_ad))
finally:
    _m16h._quick_check_patiently.__defaults__ = _h16_defaults
    if _h16_env is not None:
        os.environ[_m16h.NO_SELF_HEAL_ENV] = _h16_env

# ── 7. key files appear with their content ─────────────────────────────────────────────────────
_h16_kp = os.path.join(_H16_DIR, "a_key")
_h16_seen = []
_cfg16h._create_key_once(_h16_kp,
                         lambda: (_h16_seen.append(os.path.exists(_h16_kp)), b"KEY-1")[1])
check("key file: nobody can see it before its content is in it (it is linked into place full)",
      _h16_seen == [False] and _h16_bytes(_h16_kp) == b"KEY-1",
      repr((_h16_seen, _h16_bytes(_h16_kp))))
_cfg16h._create_key_once(_h16_kp, lambda: b"KEY-2")
check("key file: ...still created exactly once (control)", _h16_bytes(_h16_kp) == b"KEY-1")
_h16_write(_h16_kp, b"")                         # what a crash between create and write left
_cfg16h._create_key_once(_h16_kp, lambda: b"KEY-3")
check("key file: an EMPTY one is replaced — nothing can have been signed with it",
      _h16_bytes(_h16_kp) == b"KEY-3" and _cfg16h._key_missing(os.path.join(_H16_DIR, "nope")),
      repr(_h16_bytes(_h16_kp)))
check("key file: no temp file is left behind",
      not [n for n in os.listdir(_H16_DIR) if n.startswith(".key-")])

# ── 8. backup codes: one code, one use — however the requests interleave ──────────────────────
from sqlalchemy import create_engine as _ce16h                                      # noqa: E402
from sqlalchemy.orm import Session as _S16h                                         # noqa: E402

_h16_eng = _ce16h("sqlite:///" + os.path.join(_H16_DIR, "codes.db"))
db.metadata.create_all(_h16_eng)
_h16_codes = ["aaaaa-bbbbb", "ccccc-ddddd", "eeeee-fffff"]
with _S16h(_h16_eng) as _s16h:
    _u16h = User(username="codes16", password_hash="x", display_name="codes16", is_active=True)  # nosec B106 - a fixture row, never logged in
    _u16h.set_backup_codes(_h16_codes)
    _s16h.add(_u16h)
    _s16h.commit()
    _h16_uid = _u16h.id


def _h16_remaining():
    with _S16h(_h16_eng) as _s:
        return _s.get(User, _h16_uid).backup_codes_remaining


# Two requests that both READ the list before either wrote it: the second session's copy of the
# row is loaded first, then the first spends and commits — the window the bcrypt yield opened.
_h16_sa, _h16_sb = _S16h(_h16_eng), _S16h(_h16_eng)
try:
    _ua16h, _ub16h = _h16_sa.get(User, _h16_uid), _h16_sb.get(User, _h16_uid)
    _h16_stale = _ub16h.backup_codes                  # loaded, stale from here on
    _h16_a1 = _ua16h.use_backup_code(_h16_codes[0])
    _h16_sa.commit()
    _h16_b1 = _ub16h.use_backup_code(_h16_codes[0])
    _h16_sb.commit()
    check("backup codes: the SAME code spent by two interleaved requests works exactly once",
          _h16_a1 is True and _h16_b1 is False, repr((_h16_a1, _h16_b1)))
    check("backup codes: ...and the refused one did not resurrect it (2 left)",
          _h16_remaining() == 2, repr(_h16_remaining()))
    _ua16h, _ub16h = _h16_sa.get(User, _h16_uid), _h16_sb.get(User, _h16_uid)
    _h16_stale = _ub16h.backup_codes
    _h16_a2 = _ua16h.use_backup_code(_h16_codes[1])
    _h16_sa.commit()
    _h16_b2 = _ub16h.use_backup_code(_h16_codes[2])
    _h16_sb.commit()
    check("backup codes: two DIFFERENT codes interleaved both work (control)",
          _h16_a2 is True and _h16_b2 is True, repr((_h16_a2, _h16_b2)))
    check("backup codes: ...and neither write put the other's spent code back (0 left)",
          _h16_remaining() == 0, repr(_h16_remaining()))
    check("backup codes: ...the spent codes stay spent",
          not _ua16h.use_backup_code(_h16_codes[1]) and not _ub16h.use_backup_code(_h16_codes[2])
          and not _ub16h.use_backup_code(_h16_codes[0]))
finally:
    _h16_sa.close()
    _h16_sb.close()
    _h16_eng.dispose()

# ── 9. the game list is not read under a lock held across a fetch ─────────────────────────────
_h16_saved_lg = (_lg16h._load_serverlist, dict(_lg16h._mem))
_h16_entered, _h16_release = _thr16.Event(), _thr16.Event()
_h16_calls = []


def _h16_slow_load(allow_fetch):
    _h16_calls.append(allow_fetch)
    if len(_h16_calls) == 1:                      # the first re-read is the one "stuck on GitHub"
        _h16_entered.set()
        _h16_release.wait(10)
        return [{"shortname": "old"}], _lg16h.SERVERLIST
    return [{"shortname": "new"}], _lg16h.SERVERLIST


_h16_res = {}
try:
    _lg16h._load_serverlist = _h16_slow_load
    _lg16h._mem.clear()
    _lg16h._mem["serverlist"] = (_time16.time() - 1, [{"shortname": "stale"}])   # due a re-read
    _h16_t = _thr16.Thread(target=lambda: _h16_res.setdefault("t", _lg16h.serverlist()))
    _h16_t.start()
    _h16_entered.wait(5)
    _h16_free = _lg16h._lock.acquire(blocking=False)
    if _h16_free:
        _lg16h._lock.release()
    _h16_t0 = _time16.monotonic()
    _h16_res["meanwhile"] = _lg16h.serverlist()
    _h16_took = _time16.monotonic() - _h16_t0
    check("game list: the lock is FREE while a re-read is out on the network", _h16_free is True)
    check("game list: ...and another request is served the copy it has at once, not after the "
          "fetch", _h16_res["meanwhile"] == [{"shortname": "stale"}] and _h16_took < 1.0,
          repr((_h16_res["meanwhile"], _h16_took)))
    _lg16h.refresh(force=False)                   # a newer copy lands while the slow one is out
    _h16_release.set()
    _h16_t.join(10)
    check("game list: a slow re-read that finishes after a refresh does not put its older copy "
          "back", _lg16h._mem.get("serverlist", (0, None))[1] == [{"shortname": "new"}]
          and _lg16h.serverlist() == [{"shortname": "new"}], repr(_lg16h._mem.get("serverlist")))
finally:
    _h16_release.set()
    _lg16h._load_serverlist = _h16_saved_lg[0]
    _lg16h._mem.clear()
    _lg16h._mem.update(_h16_saved_lg[1])
    _lg16h._inflight.clear()
_shutil16.rmtree(_H16_DIR, ignore_errors=True)
