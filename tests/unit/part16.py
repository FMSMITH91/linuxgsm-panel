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
"""
import io as _io16
import json as _json16
import os
import sys
import tempfile as _tf16
from datetime import datetime as _dt16
from types import SimpleNamespace as NS

from unit.part01 import check, eq  # noqa: F401
from unit.part05 import _helper
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
    _SECRET16 = "Logging in user 'secret_steam_acct' to Steam Public...OK"
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
_F2B16_LINE = ("2026-09-28 10:00:00,123 fail2ban.filter [1]: INFO [sshd] Found "
               "2001:db8::%x - 2026-09-28 10:00:00")
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

# _run_verb, all three branches, against a real child printing more than the ceiling.
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


try:
    _p9_so._priv = NS(helper_argv=lambda v, a: list(_BIG16), tool_argv=lambda v, a: list(_BIG16),
                      remote_command=lambda v, a, merge_stderr=True: " ".join(
                          __import__("shlex").quote(x) for x in _BIG16),
                      stdin_for=lambda v: None, VerbError=ValueError)
    _p9_so._helper_present = lambda: True
    _rv16["helper"] = _p9_so._run_verb("f2b-log-lines", ["2026-09-01"], merge_stderr=False)
    _p9_so._helper_present = lambda: False
    _p9_so.os = _Os16(0)
    _rv16["root"] = _p9_so._run_verb("f2b-log-lines", ["2026-09-01"], merge_stderr=False)
    _p9_so.os = _Os16(None)            # no geteuid: the shell fallback, with no sudo prefix
    _rv16["shell"] = _p9_so._run_verb("f2b-log-lines", ["2026-09-01"], merge_stderr=False)
finally:
    _p9_so._helper_present, _p9_so.os, _p9_so._priv = _rv16_saved
check("f2b _run_verb: every branch keeps at most the transports' ceiling of a verb's output",
      set(_rv16) == {"helper", "root", "shell"}
      and all(r[2] == 0 and 0 < len(r[0]) <= _core16._MAX_OUTPUT_BYTES for r in _rv16.values()),
      repr({k: (len(v[0]), v[1][:60], v[2]) for k, v in _rv16.items()}))

_f2b16_verb = _p9_so._run_verb
_AT_CAP16 = _F2B16_LINE % 1 + "\n"
_AT_CAP16 = _AT_CAP16 * ((_core16._MAX_OUTPUT_BYTES - 65536) // len(_AT_CAP16) + 1)
try:
    _p9_so._run_verb = lambda verb, args=(), **k: (_AT_CAP16, "", 0)
    _ac16 = (_p9_so.fail2ban_attempt_counts(), _p9_so.fail2ban_top_ips())
    _p9_so._run_verb = lambda verb, args=(), **k: ("", "panel-helper: truncated", 3)
    _ac16 += (_p9_so.fail2ban_attempt_counts(), _p9_so.fail2ban_top_ips())
    _p9_so._run_verb = lambda verb, args=(), **k: (_F2B16_LINE % 7, "", 0)
    _ok16 = _p9_so.fail2ban_attempt_counts()
finally:
    _p9_so._run_verb = _f2b16_verb
check("f2b tally: an answer at the ceiling, or the helper's rc 3, is unread (None), not partial",
      _ac16 == (None, None, None, None), repr([type(x).__name__ for x in _ac16]))
eq("f2b tally: an ordinary answer is still tallied (control)", _ok16, {"2001:db8::7": 1})


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 745379329 — BY DESIGN: skipped and neutral check runs pass the self-update gate
# ════════════════════════════════════════════════════════════════════════════════════════════════
# No code change, and these pin why. GitHub's own rule for a required check is "successful,
# skipped, or neutral", and main's commits carry legitimately skipped runs: this is the tip of
# main as the check-runs API answered for 83ca9f9 on 2026-09-29 (one run per suite, trimmed to the
# shapes that matter). The PR-only "Open code-scanning alerts (PR)" is skipped on every push, and
# fork PRs file skipped workflow_run runs of "Open code-scanning alerts" beside the push run.
# Counting skipped as failing would block every update the panel is offered.
_CI16 = [("checks (ubuntu-24.04 · py3.12)", "success"), ("Analyze (python)", "success"),
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
