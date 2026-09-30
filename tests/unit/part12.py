"""Route behaviour for five route modules, driven through a real Flask test client.

server_files, manage_servers, server_detail, _shared and host_local had most of their failure
branches reached by no suite at all: the smoke suite renders their pages and walks the happy path,
and the branches that decide what an operator is TOLD when a host does not answer, a write is
refused, or an install dies half way were only ever read, never run.

HOW THE APP IS BUILT HERE. Not create_app(): that opens the checkout's own data/panel.db (DB_PATH is
a fixed path with no override), attaches data/auth.log, chmods data/ and starts a dozen supervised
background threads. The unit suite must not touch any of that. So this builds a Flask app the way
create_app does in the parts that matter to a route — the same login manager and user loader, the
same register_routes() with every section, the same template filters and context processors —
against a SQLite file in a temp dir, and with the supervisor handed threads that never start.

WHAT IS STUBBED, AND WHERE. Every host-facing call is replaced on the module the ROUTE reaches it
through: `_sm.x` calls are stubbed on the panel.ops.ssh_manager package (the seam the routes use),
and a name a route module imported directly (`from ssh_manager import set_autostart`) is stubbed on
that route module. Behind all of that a TRIPWIRE sits on the transports themselves (paramiko, the
ssh CLI, the local shell, system_ops' runners): anything that still reaches one is recorded and
refused, and a check at the end fails on it — so a missing stub cannot quietly SSH to a TEST-NET
address or run a command on this machine.

Nothing here asserts a `sudo -u` command string: those builders are being rewritten on another
branch. A stub that has to tell two commands apart keys on a token of the command's own protocol
(the __DU_DONE__ marker, `auto-install`, `linuxgsm.sh`), never on how the account is switched to.

Background workers (installs, power actions, content jobs) are not started as threads. Each route
module's `threading` is swapped for one whose Thread only QUEUES its target, and _p9_drain() runs
the queue after the request has returned — the order they really run in, and without a worker
outliving the check that started it (a leaked worker lands in a LATER check's stub).
"""
import os
import tempfile
import threading as _p9_real_threading
import time as _p9_real_time
from types import SimpleNamespace as NS

from unit.part01 import check, eq  # noqa: F401

import app as _p9_app
from flask import Flask as _P9Flask, g as _p9_g
from flask_wtf.csrf import CSRFProtect as _P9Csrf
from panel.core import config as _p9_cfg
from panel.core import panel_state as _p9_state
from panel.db.models import (AuditLog, CustomCommand, GameServer, GlobalBan, Group, RemoteServer,
                             SetupState, User, db)
from panel.ops import backup as _p9_bk
from panel.ops import ssh_manager as _p9_sm
from panel.ops import system_ops as _p9_so
from panel.ops import tailscale_integration as _p9_ts
from panel.ops.ssh_manager import _core as _p9_core
from panel.security import auth as _p9_auth
from panel.security import banlist as _p9_banlist
from panel.services import notifications as _p9_notif

# The checkout's own database, which nothing below may create. Recorded before anything runs so
# the check at the end can tell "this part made it" from "it was already there".
_P9_LIVE_DB = str(_p9_cfg.DB_PATH)
_P9_LIVE_DB_EXISTED = os.path.exists(_P9_LIVE_DB)
_P9_TMP = tempfile.mkdtemp(prefix="lgsm-unit-p09-")
# The runner points config.json at a throwaway dir; an earlier part may have left it unreadable on
# purpose. Snapshot it, start from a fresh install's config, and put the bytes back at the end.
_P9_CFG_PATH = _p9_cfg.CONFIG_FILE
_P9_CFG_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None


# ── deferred threads ────────────────────────────────────────────────────────────────────────────
_p9_queue = []


class _P9Thread:
    """threading.Thread whose start() queues the target instead of running it."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None, name=None):
        self._t, self._a, self._k = target, tuple(args or ()), dict(kwargs or {})

    def start(self):
        _p9_queue.append((self._t, self._a, self._k))

    def join(self, timeout=None):
        return None


_p9_supervised = []


class _P9NoThread(_P9Thread):
    """A Thread for register_routes' supervisor that remembers its target and never starts it.

    A check can then take one loop body out of its supervisor and run a single pass of it.
    """

    def start(self):
        _p9_supervised.append(self._t)


def _p9_threading(thread_cls):
    return NS(Thread=thread_cls, Lock=_p9_real_threading.Lock, RLock=_p9_real_threading.RLock,
              local=_p9_real_threading.local, Event=_p9_real_threading.Event,
              current_thread=_p9_real_threading.current_thread)


def _p9_drain():
    """Run every queued worker (and anything they queue), outside any request. Returns how many."""
    n = 0
    while _p9_queue:
        fn, a, k = _p9_queue.pop(0)
        n += 1
        fn(*a, **k)
    return n


# ── the app ─────────────────────────────────────────────────────────────────────────────────────
_p9 = _P9Flask("app")     # the import name resolves templates/ and static/ at the repo root
_p9.config.update(
    SECRET_KEY="p09-unit-secret",
    SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_P9_TMP, "p09.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"timeout": 5}},
    WTF_CSRF_ENABLED=False, WTF_CSRF_CHECK_DEFAULT=False,
    SESSION_PROTECTION=None, SESSION_COOKIE_SECURE=False, REMEMBER_COOKIE_SECURE=False,
    _MOUNT_PREFIX="/", _TRUST_PROXY=False,
    MAX_CONTENT_LENGTH=_p9_app._MAX_UPLOAD_BYTES + 2 * 1024 * 1024,
)
# Routes and workers log their expected failures with tracebacks; keep the run readable. Restored
# at the end with everything else — BOTH of them: _p9.logger is logging.getLogger("app"), the same
# object as the real app's logger, and it used to stay disabled for the rest of the process, so a
# later part's create_app logged its boot steps into a logger that dropped them.
_p9_saved_applog_disabled = _p9.logger.disabled
_p9.logger.disabled = True
_p9_saved_log_disabled = _p9_app._log.disabled
_p9_app._log.disabled = True
_p9_auth.init_auth(_p9)
db.init_app(_p9)
_P9Csrf(_p9)


@_p9.before_request
def _p9_nonce():
    _p9_g.csp_nonce = "p09"


_p9_saved_listeners = dict(_p9_banlist._listeners)
_p9_saved_app_threading = _p9_app.threading
_p9_app.threading = _p9_threading(_P9NoThread)
try:
    _p9_app.register_routes(_p9)
finally:
    _p9_app.threading = _p9_saved_app_threading
_p9_app.register_template_filters(_p9)
_p9_app.register_context_processors(_p9)

from panel.routes import _shared as _p9_sh            # noqa: E402
from panel.routes import host_local as _p9_hl         # noqa: E402
from panel.routes import remote_security as _p9_rs    # noqa: E402
from panel.routes import remote_vps as _p9_rv         # noqa: E402
from panel.routes import manage_servers as _p9_ms     # noqa: E402
from panel.routes import server_detail as _p9_sd      # noqa: E402
from panel.routes import server_files as _p9_sf       # noqa: E402

_P9_ROUTE_MODS = (_p9_sh, _p9_sd, _p9_ms, _p9_sf, _p9_hl)
_p9_saved_threading = {m: m.threading for m in _P9_ROUTE_MODS if hasattr(m, "threading")}
_p9_saved_time = {m: m.time for m in _P9_ROUTE_MODS if hasattr(m, "time")}
_p9_fake_time = NS(time=_p9_real_time.time, sleep=lambda s: None, monotonic=_p9_real_time.monotonic)

# Everything this part replaces, as (owner, attribute) — saved the first time and restored in the
# finally at the bottom, so no stub outlives the part.
_P9_PATCHED = {}
# A module attribute that was not there before (ssh_manager serves its names through __getattr__):
# restoring means deleting the stub, so the package's own lookup answers again.
_P9_ABSENT = object()


def _p9_patch(owner, name, value):
    key = (owner, name)
    if key not in _P9_PATCHED:
        _P9_PATCHED[key] = owner.__dict__.get(name, _P9_ABSENT) if isinstance(owner, type(os)) \
            else getattr(owner, name)
    setattr(owner, name, value)


def _p9_restore_all():
    for (_o, _n), _v in list(_P9_PATCHED.items()):
        if _v is _P9_ABSENT:
            try:
                delattr(_o, _n)
            except AttributeError:  # nosec B110 - already gone is what restoring means here
                pass
        else:
            setattr(_o, _n, _v)
    _P9_PATCHED.clear()


# ── the tripwire ────────────────────────────────────────────────────────────────────────────────
_P9_TRIPPED = []


def _p9_trip(where, result=("", "refused by part12's tripwire", -1), exc=None):
    def _tripped(*a, **k):
        _P9_TRIPPED.append((where, repr(a[:2])[:120]))
        if exc is not None:
            raise exc
        return result
    return _tripped


def _p9_shell_as(server, user, sh, timeout=30, selfname=None):
    """Run shell_as_game_user's own steps, with run_command looked up on the package."""
    try:
        cmd = _p9_core.game_user_cmd(user, sh, selfname=selfname)
    except _p9_core.UnsafeGameAccount:
        return _p9_core.GAME_ACCOUNT_REFUSED
    return _p9_sm.run_command(server, cmd, timeout=timeout, sudo=False)


def _p9_client(uid):
    c = _p9.test_client()
    with c.session_transaction() as s:
        s["_user_id"] = str(uid)
        s["_fresh"] = True
    return c


# What the lookups below answer for a row that is not there: every field None, so a check about a
# missing row FAILS by name rather than raising AttributeError and taking every later check with it
# (a crash is not a catch). Existence is asked with _p9_exists.
_P9_NO_AUDIT = NS(target=None, detail="", success=None, username=None, id=None)


def _p9_audit(action):
    """The newest audit row for `action`, or _P9_NO_AUDIT."""
    with _p9.app_context():
        r = AuditLog.query.filter_by(action=action).order_by(AuditLog.id.desc()).first()
        return _P9_NO_AUDIT if r is None else NS(target=r.target, detail=r.detail or "",
                                                 success=r.success, username=r.username, id=r.id)


def _p9_audit_count(action):
    with _p9.app_context():
        return AuditLog.query.filter_by(action=action).count()


def _p9_row(sid):
    with _p9.app_context():
        gs = db.session.get(GameServer, sid) if sid is not None else None
        if gs is None:
            return NS(**{c.name: None for c in GameServer.__table__.columns})
        return NS(**{c.name: getattr(gs, c.name) for c in GameServer.__table__.columns})


def _p9_exists(sid):
    with _p9.app_context():
        return sid is not None and db.session.get(GameServer, sid) is not None


def _p9_host_row(rid):
    with _p9.app_context():
        r = db.session.get(RemoteServer, rid)
        if r is None:
            return NS(**{c.name: None for c in RemoteServer.__table__.columns})
        return NS(**{c.name: getattr(r, c.name) for c in RemoteServer.__table__.columns})


def _p9_set(sid, **fields):
    with _p9.app_context():
        gs = db.session.get(GameServer, sid)
        for k, v in fields.items():
            setattr(gs, k, v)
        db.session.commit()


def _p9_set_host(rid, **fields):
    with _p9.app_context():
        r = db.session.get(RemoteServer, rid)
        for k, v in fields.items():
            setattr(r, k, v)
        db.session.commit()


def _p9_new_server(remote_id, short_name, game_type, port, **kw):
    with _p9.app_context():
        gs = GameServer(remote_id=remote_id, name=kw.pop("name", short_name), short_name=short_name,
                        game_type=game_type, port=port, installed=kw.pop("installed", True),
                        status=kw.pop("status", "offline"), **kw)
        db.session.add(gs)
        db.session.commit()
        return gs.id


def _p9_delete_server(sid):
    with _p9.app_context():
        gs = db.session.get(GameServer, sid)
        if gs is not None:
            db.session.delete(gs)
            db.session.commit()


def _p9_flashes(client):
    """The flashed messages waiting in this client's session (and clear them)."""
    with client.session_transaction() as s:
        msgs = [m for _c, m in s.get("_flashes", [])]
        s.pop("_flashes", None)
    return msgs


def _p9_json(resp):
    return resp.get_json(silent=True) or {}


try:
    for _m in _p9_saved_threading:
        _m.threading = _p9_threading(_P9Thread)
    for _m in _p9_saved_time:
        _m.time = _p9_fake_time
    if _P9_CFG_PATH.exists():
        _P9_CFG_PATH.unlink()
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), setup_complete=True))

    # The transports. Everything above them is stubbed per check; these catch what is not.
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part12's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9_so, "_git", _p9_trip("system_ops._git"))
    # shell_as_game_user, sending through the PACKAGE's run_command: the checks below stub that
    # name on the package, and the routes' game-account shell reads went through it until
    # GHSA-hh39-76g3-wxcx moved them onto shell_as_game_user, whose own run_command is _core's.
    # Left real, those reads went past every stub to the tripwire and still passed, on the
    # "couldn't tell" the tripwire's refusal reads as. The command is the real builder's.
    _p9_patch(_p9_sm, "shell_as_game_user", _p9_shell_as)
    # Rendering reads Tailscale state for the nav; that is a host command.
    _p9_patch(_p9_ts, "get_tailscale_info", lambda force_refresh=False: NS(dns_name=None))
    # Every file-manager and cron WRITE first asks the host whether the game account can become
    # root there (_shared.game_account_write_refusal -> privileged_accounts). Its probe is a host
    # command; here every account is a plain game account, as smoke_test answers it. The gate
    # itself is driven, with the host's reply scripted, in part18.
    _p9_patch(_p9_sh, "privileged_accounts", lambda remote, users: {})
    # Notifications are recorded, never sent.
    _P9_NOTIFIED = []
    _p9_patch(_p9_notif, "notify",
              lambda key, title, body="": _P9_NOTIFIED.append((key, title, body)))
    # Socket pushes: recorded on the one SocketIO register_routes built.
    _P9_EMITS = []
    _p9_patch(_p9.socketio, "emit",
              lambda event, data=None, **k: _P9_EMITS.append((event, data, k)))

    with _p9.app_context():
        db.create_all()
        db.session.add(SetupState(step="complete", complete=True))
        _pw = _p9_auth.hash_password("Str0ng!passw0rd")
        _p9_admin = User(username="p9_admin", password_hash=_pw, display_name="Admin",
                         is_superadmin=True, is_active=True)
        _p9_host = RemoteServer(name="p9-host", host="192.0.2.10", port=22, username="root",
                                auth_method="key", auth_credential="", is_online=True)
        _p9_host2 = RemoteServer(name="p9-host2", host="192.0.2.11", port=22, username="root",
                                 auth_method="key", auth_credential="", is_online=True)
        _p9_local = RemoteServer(name="Panel Server", host="127.0.0.1", port=22, username="local",
                                 auth_method="local", auth_credential="", is_local=True,
                                 is_online=True)
        db.session.add_all([_p9_admin, _p9_host, _p9_host2, _p9_local])
        db.session.flush()
        _p9_gs = GameServer(remote_id=_p9_host.id, name="p9-cs", short_name="csgoserver",
                            game_type="csgo", port=27015, installed=True, status="online")
        _p9_gm = GameServer(remote_id=_p9_host.id, name="p9-gmod", short_name="gmodserver",
                            game_type="gmod", port=27016, installed=True, status="offline")
        _p9_other = GameServer(remote_id=_p9_host2.id, name="p9-tf2", short_name="tf2server",
                               game_type="tf2", port=27015, installed=True, status="online")
        db.session.add_all([_p9_gs, _p9_gm, _p9_other])
        db.session.flush()
        # A viewer: VIEW_CONSOLE on host 1 only — no MANAGE_SERVERS, no command rights.
        _p9_vgrp = Group(name="p9_view", description="", is_default=False)
        _p9_vgrp.set_permissions([_p9_auth.VIEW_CONSOLE])
        _p9_vgrp.servers.append(_p9_host)
        db.session.add(_p9_vgrp)
        db.session.flush()
        _p9_viewer = User(username="p9_viewer", password_hash=_pw, display_name="Viewer",
                          is_superadmin=False, is_active=True)
        _p9_viewer.groups.append(_p9_vgrp)
        db.session.add(_p9_viewer)
        db.session.commit()
        P9_ADMIN, P9_VIEWER = _p9_admin.id, _p9_viewer.id
        P9_HOST, P9_HOST2, P9_LOCAL = _p9_host.id, _p9_host2.id, _p9_local.id
        P9_GS, P9_GM, P9_OTHER = _p9_gs.id, _p9_gm.id, _p9_other.id

    _A = _p9_client(P9_ADMIN)
    _V = _p9_client(P9_VIEWER)
    _XHR = {"X-Requested-With": "XMLHttpRequest"}

    # The fixture itself, so a broken harness fails loudly rather than making every check below
    # vacuous: an authenticated admin reaches a route, an anonymous client does not.
    _p9_patch(_p9_sd, "sm_player_count", lambda *a, **k: 3)
    _r = _A.get("/api/server/%d/players" % P9_GS)
    check("p09 harness: the admin client is signed in (a real route answers it)",
          _r.status_code == 200 and _p9_json(_r).get("players") == 3,
          "got %d %r" % (_r.status_code, _p9_json(_r)))
    _r = _p9.test_client().get("/api/server/%d/players" % P9_GS)
    check("p09 harness: an anonymous client is refused", _r.status_code in (302, 401),
          "got %d" % _r.status_code)

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # panel/routes/_shared.py
    # ════════════════════════════════════════════════════════════════════════════════════════════

    # ── _begin_bootstrap / _start_bootstrap_job: the job registry the status endpoint reads ──────
    _bs_seen = []

    def _bs_ok(remote, progress=None, **opts):
        progress(1, 2, "Updating packages", "running")
        progress(2, 2, "Rebooting", "rebooting")
        _bs_seen.append((remote.name, dict(opts)))
        return True, "Bootstrapped.", ["line"]

    _p9_patch(_p9_sh, "remote_bootstrap_vps", _bs_ok)
    _p9_sh._bootstrap_jobs.pop(P9_HOST2, None)
    _p9_set_host(P9_HOST2, is_online=False)
    _bs_started, _bs_msg = _p9_sh._begin_bootstrap(_p9, P9_HOST2, {"timezone": "UTC"}, P9_ADMIN)
    _bs_again, _bs_again_msg = _p9_sh._begin_bootstrap(_p9, P9_HOST2, {}, P9_ADMIN)
    check("bootstrap: a second start while one runs is refused, says why, and queues nothing",
          _bs_started and not _bs_again and "already running" in _bs_again_msg
          and len(_p9_queue) == 1,
          "%r %r / %r %r, %d queued" % (_bs_started, _bs_msg, _bs_again, _bs_again_msg,
                                        len(_p9_queue)))
    _p9_drain()
    _bs_job = dict(_p9_sh._bootstrap_jobs.get(P9_HOST2) or {})
    check("bootstrap: a finished job is 'done' with the host's message and every step logged",
          _bs_job.get("status") == "done" and _bs_job.get("step_name") == "Complete"
          and _bs_job.get("message") == "Bootstrapped." and _bs_job.get("step") == 2
          and "[1/2] Updating packages" in _bs_job.get("log", [])
          and _bs_seen == [("p9-host2", {"timezone": "UTC"})], repr((_bs_job, _bs_seen)))
    check("bootstrap: success marks the host online and writes a successful audit row",
          _p9_host_row(P9_HOST2).is_online is True
          and (_p9_audit("remote_vps_bootstrap") or NS(success=None)).success is True)

    # A job dropped from the registry while the worker runs (the status page pruned it): progress
    # and the final update have nowhere to go, and must not recreate it.
    def _bs_orphaned(remote, progress=None, **opts):
        _p9_sh._bootstrap_jobs.pop(remote.id, None)
        progress(1, 1, "Updating packages", "running")
        return True, "Bootstrapped.", []

    _p9_patch(_p9_sh, "remote_bootstrap_vps", _bs_orphaned)
    _p9_sh._begin_bootstrap(_p9, P9_HOST2, {}, P9_ADMIN)
    _p9_drain()
    check("bootstrap: a job dropped mid-run is not resurrected by its own progress or result",
          P9_HOST2 not in _p9_sh._bootstrap_jobs)
    _p9_patch(_p9_sh, "remote_bootstrap_vps",
              lambda remote, progress=None, **o: (False, "apt could not lock", []))
    _p9_sh._bootstrap_jobs.pop(P9_HOST2, None)
    _p9_sh._begin_bootstrap(_p9, P9_HOST2, {}, P9_ADMIN)
    _p9_drain()
    _bs_job = dict(_p9_sh._bootstrap_jobs.get(P9_HOST2) or {})
    check("bootstrap: a failed run is 'failed', not 'done', and keeps the host's reason",
          _bs_job.get("status") == "failed" and _bs_job.get("step_name") == "Failed"
          and _bs_job.get("message") == "apt could not lock", repr(_bs_job))
    _p9_sh._bootstrap_jobs.pop(99901, None)
    _p9_sh._begin_bootstrap(_p9, 99901, {}, P9_ADMIN)
    _p9_drain()
    _bs_job = dict(_p9_sh._bootstrap_jobs.get(99901) or {})
    check("bootstrap: a host deleted before the job ran fails the job, with the reason in its log",
          _bs_job.get("status") == "failed" and "no longer exists" in _bs_job.get("message", "")
          and any(ln.startswith("ERROR:") for ln in _bs_job.get("log", [])), repr(_bs_job))
    for _k in (P9_HOST2, 99901):
        _p9_sh._bootstrap_jobs.pop(_k, None)

    # ── _bg_cache_commands: a vanished server is skipped, not the whole batch ──────────────────
    _cc_asked = []

    def _cc_list(remote, short, lgsm):
        _cc_asked.append(short)
        return [{"cmd": "start", "desc": "Start"}, {"cmd": "monitor", "desc": "Monitor"}]

    _p9_patch(_p9_sm, "list_server_commands", _cc_list)
    _p9_patch(_p9_sm, "set_autostart", lambda *a, **k: (True, ""))
    _p9_set(P9_GS, autostart=False, commands="[]")
    _p9_sh._bg_cache_commands(_p9, [99902, P9_GS], autostart_ids=[P9_GS])
    _p9_drain()
    _cc_row = _p9_row(P9_GS)
    check("command cache: a missing server id is skipped and the next one is still cached",
          _cc_asked == ["csgoserver"] and '"monitor"' in (_cc_row.commands or ""),
          repr((_cc_asked, _cc_row.commands)))
    check("command cache: autostart is switched on for an imported server whose game has monitor",
          _cc_row.autostart is True)

    # ── _maybe_resolve_public_ip: background, rate-limited, never raises ────────────────────────
    _ip_calls = []
    _p9_patch(_p9_sh, "remote_public_ip",
              lambda r: (_ip_calls.append(r.name), "203.0.113.7")[1])
    _p9_set_host(P9_HOST2, public_ip=None)
    _p9_sh._pubip_resolve_attempts.pop(P9_HOST2, None)
    _p9_sh._maybe_resolve_public_ip(_p9, P9_HOST2)
    _p9_sh._maybe_resolve_public_ip(_p9, P9_HOST2)      # inside the 300 s window: no second job
    check("public IP: a second ask inside the rate-limit window queues nothing",
          len(_p9_queue) == 1, "%d queued" % len(_p9_queue))
    _p9_drain()
    check("public IP: the resolved address is stored on the host",
          _p9_host_row(P9_HOST2).public_ip == "203.0.113.7" and _ip_calls == ["p9-host2"],
          repr((_p9_host_row(P9_HOST2).public_ip, _ip_calls)))
    _p9_sh._pubip_resolve_attempts.pop(P9_HOST2, None)
    _p9_sh._maybe_resolve_public_ip(_p9, P9_HOST2)      # already has one: the worker does nothing
    _p9_drain()
    check("public IP: a host that already has one is not asked again", _ip_calls == ["p9-host2"])

    def _ip_raise(r):
        raise ConnectionError("host down")

    _p9_patch(_p9_sh, "remote_public_ip", _ip_raise)
    _p9_set_host(P9_HOST2, public_ip=None)
    _p9_sh._pubip_resolve_attempts.pop(P9_HOST2, None)
    _p9_sh._maybe_resolve_public_ip(_p9, P9_HOST2)
    _ip_ok = True
    try:
        _p9_drain()
    except Exception:
        _ip_ok = False
    check("public IP: an unreachable host leaves the field empty and the worker does not raise",
          _ip_ok and _p9_host_row(P9_HOST2).public_ip is None)
    _p9_sh._pubip_resolve_attempts.pop(P9_HOST2, None)

    # ── _host_timezone_cached / _maybe_resolve_host_timezone ─────────────────────────────────────
    eq("host timezone: no host at all reads as unknown (''), not UTC",
       _p9_sh._host_timezone_cached(None, _p9), "")
    _tz_calls = []
    _p9_patch(_p9_sm, "host_timezone", lambda r: (_tz_calls.append(r.id), "Europe/Berlin")[1])
    _p9_set_host(P9_HOST2, timezone="")
    _p9_sh._tz_resolve_attempts.pop(P9_HOST2, None)
    with _p9.app_context():
        _tz_now = _p9_sh._host_timezone_cached(db.session.get(RemoteServer, P9_HOST2), _p9)
    _p9_drain()
    check("host timezone: a miss answers '' now and fills the row in the background",
          _tz_now == "" and _p9_host_row(P9_HOST2).timezone == "Europe/Berlin"
          and _tz_calls == [P9_HOST2], repr((_tz_now, _p9_host_row(P9_HOST2).timezone, _tz_calls)))
    _p9_sh._tz_resolve_attempts.pop(P9_HOST2, None)
    _p9_sh._maybe_resolve_host_timezone(_p9, P9_HOST2)   # row already has one: not asked again
    _p9_drain()
    check("host timezone: a host that already has a zone is not read again", _tz_calls == [P9_HOST2])

    def _tz_raise(r):
        raise ConnectionError("down")

    _p9_patch(_p9_sm, "host_timezone", _tz_raise)
    _p9_set_host(P9_HOST2, timezone="")
    _p9_sh._tz_resolve_attempts.pop(P9_HOST2, None)
    _p9_sh._maybe_resolve_host_timezone(_p9, P9_HOST2)
    _tz_ok = True
    try:
        _p9_drain()
    except Exception:
        _tz_ok = False
    check("host timezone: a failed read stores nothing and does not raise",
          _tz_ok and (_p9_host_row(P9_HOST2).timezone or "") == "")
    _p9_sh._tz_resolve_attempts.pop(P9_HOST2, None)

    # ── _record_backup_outcome: audit always, alert on failure unless the server is muted ────────
    _P9_NOTIFIED.clear()
    with _p9.app_context():
        _p9_sh._record_backup_outcome(_p9, P9_GS, "p9-cs", True, "", "scheduled_backup", "T")
    check("backup outcome: a success is audited and alerts nobody",
          _P9_NOTIFIED == [] and (_p9_audit("scheduled_backup") or NS(success=None)).success is True)
    _p9_patch(_p9_notif, "alerts_muted", lambda gs: True)
    with _p9.app_context():
        _p9_sh._record_backup_outcome(_p9, P9_GS, "p9-cs", False, "disk full", "scheduled_backup",
                                      "Scheduled backup failed")
    check("backup outcome: a failure on a MUTED server is audited as failed but not alerted",
          _P9_NOTIFIED == [] and _p9_audit("scheduled_backup").success is False
          and "disk full" in _p9_audit("scheduled_backup").detail)
    _p9_patch(_p9_notif, "alerts_muted", lambda gs: False)
    with _p9.app_context():
        _p9_sh._record_backup_outcome(_p9, P9_GS, "p9-cs", False, "", "queued_backup",
                                      "Queued backup failed")
    check("backup outcome: a failure alerts backup_failed, naming the server, even with no reason",
          len(_P9_NOTIFIED) == 1 and _P9_NOTIFIED[0][0] == "backup_failed"
          and "p9-cs" in _P9_NOTIFIED[0][2] and "no reason given" in _P9_NOTIFIED[0][2],
          repr(_P9_NOTIFIED))

    def _notify_raises(*a, **k):
        raise RuntimeError("telegram down")

    _p9_patch(_p9_notif, "notify", _notify_raises)
    _bo_ok = True
    try:
        with _p9.app_context():
            _p9_sh._record_backup_outcome(_p9, P9_GS, "p9-cs", False, "disk quota", "queued_backup",
                                          "T")
    except Exception:
        _bo_ok = False
    check("backup outcome: an alert channel that raises never breaks the sweep, and the failure "
          "is still on the audit log", _bo_ok and _p9_audit("queued_backup").success is False
          and _p9_audit("queued_backup").detail == "disk quota", repr(_p9_audit("queued_backup")))
    _p9_patch(_p9_notif, "notify",
              lambda key, title, body="": _P9_NOTIFIED.append((key, title, body)))

    # ── the two backup sweeps: config gate, lock, skip rules, outcomes ───────────────────────────
    _bk_runs = []

    def _bk_runner_factory(result):
        def _runner(remote, short, lgsm, keep, **kw):
            _bk_runs.append((short, keep, kw.get("query_type")))
            if isinstance(result, Exception):
                raise result
            return result
        return _runner

    # Scheduled sweep over three servers with three different schedules. Set up BEFORE the gate
    # checks, so a sweep that ignored the gate or the lock would have something due to archive.
    _bk_sched = {P9_GS: {"interval_days": 0, "keep": 3, "last": 1},          # off
                 P9_GM: {"interval_days": 1, "keep": 2, "last": 1},          # due
                 P9_OTHER: {"interval_days": 1, "keep": 5, "last": 1}}       # due
    _p9_patch(_p9_bk, "get_game_schedule",
              lambda sid: dict(_bk_sched.get(sid, {"interval_days": 0, "keep": 1, "last": 0})))
    _p9_patch(_p9_bk, "game_backup_due", lambda sid: True)
    _bk_clock = []
    _p9_patch(_p9_bk, "record_game_backup", lambda sid: _bk_clock.append(sid))
    _p9_set(P9_GM, backup_pending=True)

    _p9_patch(_p9_sh, "is_unreadable", lambda cfg: True)
    _p9_patch(_p9_sh, "run_game_backup", _bk_runner_factory((True, "ok", False)))
    _p9_sh._run_due_game_backups(_p9)
    _p9_sh._run_pending_backups(_p9)
    check("backup sweeps: an unreadable config.json stops BOTH sweeps before any archive runs",
          _bk_runs == [] and _bk_clock == [], repr((_bk_runs, _bk_clock)))
    _p9_patch(_p9_sh, "is_unreadable", _p9_cfg.is_unreadable)

    _p9_state._full_backup_lock.acquire()
    try:
        _p9_sh._run_due_game_backups(_p9)
        _p9_sh._run_pending_backups(_p9)
    finally:
        _p9_state._full_backup_lock.release()
    check("backup sweeps: while another backup holds the lock, neither sweep runs one",
          _bk_runs == [] and _bk_clock == [], repr((_bk_runs, _bk_clock)))
    _p9_set(P9_GM, backup_pending=False)
    _p9_set(P9_OTHER, query_type="source")

    def _bk_players_on(remote, short, lgsm, keep, **kw):
        _bk_runs.append((short, keep, kw.get("query_type")))
        return (False, "3 players online", True) if short == "tf2server" else (True, "", False)

    _p9_patch(_p9_sh, "run_game_backup", _bk_players_on)
    _p9_sh._game_backup_status.clear()
    _p9_sh._run_due_game_backups(_p9)
    check("scheduled backups: a server whose schedule is off is never archived",
          "csgoserver" not in [r[0] for r in _bk_runs], repr(_bk_runs))
    check("scheduled backups: each due server is archived with ITS keep and its query type",
          ("gmodserver", 2, None) in _bk_runs and ("tf2server", 5, "source") in _bk_runs,
          repr(_bk_runs))
    check("scheduled backups: players online leaves the clock alone and marks the server busy",
          P9_OTHER not in _bk_clock
          and (_p9_sh._game_backup_status.get(P9_OTHER) or {}).get("busy") is True
          and _p9_sh._game_backup_status[P9_OTHER].get("msg") == "3 players online",
          repr((_bk_clock, _p9_sh._game_backup_status.get(P9_OTHER))))
    check("scheduled backups: a completed archive moves its server's clock",
          _bk_clock == [P9_GM] and _p9_sh._game_backup_status[P9_GM].get("ok") is True,
          repr((_bk_clock, _p9_sh._game_backup_status.get(P9_GM))))
    # ...and a schedule that is ON but not due yet is left alone: no archive, no clock moved. Every
    # fixture above is due (game_backup_due is stubbed True), so the due gate itself was never
    # asked — deleting it from _back_up_if_due passed every suite, and every server with a schedule
    # would have been archived (players stopped and all) on every hourly tick.
    _bk_runs.clear()
    _bk_clock.clear()
    _p9_patch(_p9_bk, "game_backup_due", lambda sid: sid != P9_GM)
    _p9_patch(_p9_sh, "run_game_backup", _bk_runner_factory((True, "ok", False)))
    _p9_sh._run_due_game_backups(_p9)
    check("scheduled backups: a server whose schedule is on but not due yet is not archived",
          [r[0] for r in _bk_runs] == ["tf2server"] and _bk_clock == [P9_OTHER],
          repr((_bk_runs, _bk_clock)))
    _p9_patch(_p9_bk, "game_backup_due", lambda sid: True)
    _p9_patch(_p9_sh, "run_game_backup", _bk_players_on)   # the queued sweep below expects it
    _p9_set(P9_OTHER, query_type=None)

    # Queued ('wait until empty') sweep: busy stays queued, a raise is reported.
    _p9_set(P9_GM, backup_pending=True)
    _p9_set(P9_OTHER, backup_pending=True)
    _bk_runs.clear()
    _bk_clock.clear()
    _p9_sh._run_pending_backups(_p9)
    check("queued backups: a server that still has players stays queued and shows busy",
          _p9_row(P9_OTHER).backup_pending is True
          and _p9_sh._game_backup_status[P9_OTHER].get("busy") is True)
    check("queued backups: an archived server leaves the queue and its clock moves",
          _p9_row(P9_GM).backup_pending is False and _bk_clock == [P9_GM])
    _P9_NOTIFIED.clear()
    _p9_patch(_p9_sh, "run_game_backup", _bk_runner_factory(OSError("ssh dropped")))
    _p9_sh._run_pending_backups(_p9)
    check("queued backups: a backup that RAISES is audited and alerted, and stays queued",
          _p9_row(P9_OTHER).backup_pending is True
          and _p9_audit("queued_backup").success is False
          and "backup error (OSError)" in _p9_audit("queued_backup").detail
          and [n[0] for n in _P9_NOTIFIED] == ["backup_failed"]
          and _p9_sh._game_backup_status[P9_OTHER].get("ok") is False,
          repr((_p9_audit("queued_backup"), _P9_NOTIFIED)))
    _p9_set(P9_OTHER, backup_pending=False)
    _p9_sh._game_backup_status.clear()

    # ── _run_queued_action: the unattended stop/restart and its retry budget ─────────────────────
    _qa_rc = [0]
    _qa_prio = []
    _p9_patch(_p9_sm, "run_as_game_user",
              lambda remote, user, action, **k: ("", "LinuxGSM said no\n", _qa_rc[0]))

    def _qa_prio_raises(remote, user, *a, **k):
        _qa_prio.append(user)
        raise ConnectionError("renice failed")

    _p9_patch(_p9_sm, "set_game_priority", _qa_prio_raises)

    def _qa_run(**flags):
        _p9_set(P9_GS, **flags)
        with _p9.app_context():
            gs = db.session.get(GameServer, P9_GS)
            ok = _p9_sh._run_queued_action(_p9, gs)
        return ok, _p9_row(P9_GS), _p9_audit(("stop" if flags.get("stop_pending") else "restart")
                                             + "_server")

    _p9_sh._queued_action_failures.pop(P9_GS, None)
    _qa_rc[0] = 1
    _qa_ok, _qa_row, _qa_aud = _qa_run(restart_pending=True, stop_pending=False)
    check("queued restart: a LinuxGSM non-zero exit is NOT retried (it may have worked) — cleared",
          _qa_ok is False and _qa_row.restart_pending is False
          and "no longer queued" in _qa_aud.detail and "exited 1" in _qa_aud.detail,
          repr((_qa_ok, _qa_row.restart_pending, _qa_aud)))
    check("queued restart: a priority nudge that raises is swallowed after the restart",
          _qa_prio == ["csgoserver"], repr(_qa_prio))
    _qa_rc[0] = -1
    _qa_ok, _qa_row, _qa_aud = _qa_run(stop_pending=True, restart_pending=False)
    check("queued stop: no exit status (a timeout) keeps it queued and counts attempt 1 of 3",
          _qa_ok is False and _qa_row.stop_pending is True
          and _p9_sh._queued_action_failures.get(P9_GS) == 1
          and "attempt 1 of 3" in _qa_aud.detail and "will retry" in _qa_aud.detail,
          repr((_qa_row.stop_pending, _p9_sh._queued_action_failures.get(P9_GS), _qa_aud)))
    _qa_run(stop_pending=True)
    _qa_ok, _qa_row, _qa_aud = _qa_run(stop_pending=True)
    check("queued stop: the third unanswered attempt gives up and clears the queue",
          _qa_row.stop_pending is False and P9_GS not in _p9_sh._queued_action_failures
          and "attempt 3 of 3" in _qa_aud.detail and "no longer queued" in _qa_aud.detail,
          repr((_qa_row.stop_pending, _qa_aud)))
    _qa_rc[0] = 2
    _qa_ok, _qa_row, _qa_aud = _qa_run(stop_pending=True)
    check("queued stop: a LinuxGSM exit status stays queued until the server is SEEN stopped",
          _qa_row.stop_pending is True and "until the server is seen stopped" in _qa_aud.detail,
          repr(_qa_aud))
    _p9_sh._queued_action_failures.pop(P9_GS, None)
    _qa_rc[0] = 0

    def _qa_log_raises(*a, **k):
        raise RuntimeError("audit table locked")

    _p9_patch(_p9_sh, "log_action", _qa_log_raises)
    _qa_ok, _qa_row, _ = _qa_run(stop_pending=True)
    check("queued stop: an audit write that fails does not undo a stop that worked",
          _qa_ok is True and _qa_row.stop_pending is False)
    _p9_patch(_p9_sh, "log_action", _p9_auth.log_action)
    for _qrc, _want in ((None, True), (-1, True), (255, True), (0, False)):
        eq("queued action retries: rc %r (stop) -> retry %r" % (_qrc, _want),
           _p9_sh._queued_action_retries("stop", _qrc), _want)

    # ── _run_due_restarts: a status read that raises leaves the queue alone ────────────────────
    def _drs_raise(*a, **k):
        raise ConnectionError("host down")

    _p9_patch(_p9_sh, "get_server_status", _drs_raise)
    _p9_set(P9_GS, restart_pending=True, stop_pending=False)
    _p9_sh._run_due_restarts(_p9)
    check("due restarts: a host that cannot be read keeps the queued restart queued",
          _p9_row(P9_GS).restart_pending is True)
    _p9_set(P9_GS, restart_pending=False)

    # ── _looks_installed: a size that is not a number is "couldn't tell", not "not installed" ────
    def _li_run(remote, cmd, **k):
        if "__DU_DONE__" in cmd:
            return "?? garbage\n__DU_DONE__", "", 0
        return "", "", 0

    _p9_patch(_p9_sm, "run_command", _li_run)
    with _p9.app_context():
        _li = _p9_sh._looks_installed(_p9, db.session.get(RemoteServer, P9_HOST), "csgoserver",
                                      "csgoserver")
    eq("looks installed: an unparseable serverfiles size answers None (couldn't tell)", _li, None)

    # ── _notify_servers_changed / _console_push: best-effort, never raise ───────────────────────
    def _emit_raises(*a, **k):
        raise RuntimeError("socket gone")

    _p9_patch(_p9.socketio, "emit", _emit_raises)
    _nsc_ok = True
    try:
        _p9_sh._notify_servers_changed(_p9)
        _p9_sh._console_push(_p9, 90001, "a line")
    except Exception:
        _nsc_ok = False
    check("console push: a broken socket raises out of neither push, and the line is still kept "
          "for replay", _nsc_ok
          and [e["line"] for e in _p9_state._console_backlog.get(90001, [])] == ["a line"],
          repr(_p9_state._console_backlog.get(90001)))
    _p9_patch(_p9.socketio, "emit",
              lambda event, data=None, **k: _P9_EMITS.append((event, data, k)))
    _P9_EMITS.clear()
    _p9_sh._console_push(_p9, 90001, "")
    check("console push: empty text pushes nothing and records nothing",
          _P9_EMITS == [] and len(_p9_state._console_backlog.get(90001, [])) == 1)
    _p9_state._console_backlog[90002] = None      # a corrupt entry: .extend raises
    _cp_ok = True
    try:
        _p9_sh._console_push(_p9, 90002, "still pushed")
    except Exception:
        _cp_ok = False
    check("console push: a broken backlog entry does not stop the live push",
          _cp_ok and any(e[1] and e[1].get("data") == "still pushed" for e in _P9_EMITS))
    for _k in (90001, 90002):
        _p9_state._console_backlog.pop(_k, None)

    # ── _drain_action_output / _end_action_tail ──────────────────────────────────────────────────
    _p9_state._action_output.pop(90003, None)
    eq("action tail: nothing registered for the server -> False (stop draining)",
       _p9_sh._drain_action_output(_p9, None, 90003), False)

    def _dr_raise(*a, **k):
        raise RuntimeError("drain exploded")

    _p9_state._action_output[90003] = {"action": "update", "path": "/x", "user": "u", "pos": 0,
                                       "prev": None}
    _p9_patch(_p9_sh, "_drain_action_output", _dr_raise)
    _P9_EMITS.clear()
    _eat_ok = True
    try:
        _p9_sh._end_action_tail(_p9, 90003, None, "update", 3)
    except Exception:
        _eat_ok = False
    _p9_patch(_p9_sh, "_drain_action_output", _P9_PATCHED[(_p9_sh, "_drain_action_output")])
    check("action tail: a final drain that raises still deregisters and reports the exit code",
          _eat_ok and 90003 not in _p9_state._action_output
          and any("update failed (exit 3)" in (e[1] or {}).get("data", "") for e in _P9_EMITS),
          repr(_P9_EMITS))
    # ════════════════════════════════════════════════════════════════════════════════════════════
    # panel/routes/host_local.py — the panel host's own management API
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _hl_calls = []

    def _hl_rec(name, result):
        def _f(*a, **k):
            _hl_calls.append((name, a, k))
            if isinstance(result, Exception):
                raise result
            return result
        return _f

    def _hl_boom(name):
        return _hl_rec(name, RuntimeError("%s exploded" % name))

    # Specs with no local host row: a stand-in, never a None handed to host_specs.
    _p9_set_host(P9_LOCAL, is_local=False)
    _p9_patch(_p9_hl, "host_specs",
              lambda h: {"is_local": h.is_local, "auth": h.auth_method, "sudo": h.sudo_enabled})
    _r = _A.get("/api/server-management/specs")
    eq("panel host specs: no local host row -> a local, non-sudo stand-in is asked",
       _p9_json(_r), {"is_local": True, "auth": "local", "sudo": False})
    _r = _A.post("/api/panel/security/autoblock", json={"enabled": True})
    check("panel auto-block: with no local host record it refuses rather than guessing an id",
          _p9_json(_r).get("success") is False and "No local host" in _p9_json(_r).get("message", ""),
          repr(_p9_json(_r)))
    _p9_set_host(P9_LOCAL, is_local=True)

    # The three one-click host toggles: success invalidates the cached status and is audited,
    # failure is a 500 carrying the host's own message.
    for _hl_url, _hl_fn, _hl_act in (
            ("/api/server-management/ufw-allow-tailscale", "ufw_allow_tailscale", "ufw_allow_tailscale"),
            ("/api/server-management/ts-ssh-enable", "tailscale_ssh_enable", "tailscale_ssh_enable"),
            ("/api/server-management/ts-ssh-disable", "tailscale_ssh_disable", "tailscale_ssh_disable")):
        _hl_calls.clear()
        _p9_patch(_p9_so, _hl_fn, _hl_rec(_hl_fn, (True, "done: " + _hl_fn)))
        _p9_patch(_p9_so, "invalidate_server_status", _hl_rec("invalidate", None))
        _r = _A.post(_hl_url)
        check("%s: success re-probes the host status next load and is audited" % _hl_url,
              _r.status_code == 200 and _p9_json(_r).get("message") == "done: " + _hl_fn
              and [c[0] for c in _hl_calls] == [_hl_fn, "invalidate"]
              and (_p9_audit(_hl_act) or NS(detail="")).detail == "done: " + _hl_fn,
              repr((_r.status_code, _hl_calls)))
        _hl_calls.clear()
        _p9_patch(_p9_so, _hl_fn, _hl_rec(_hl_fn, (False, "tailscale is not installed")))
        _r = _A.post(_hl_url)
        check("%s: failure is a 500 with the host's reason, and nothing is invalidated" % _hl_url,
              _r.status_code == 500 and _p9_json(_r).get("message") == "tailscale is not installed"
              and "invalidate" not in [c[0] for c in _hl_calls], repr((_r.status_code, _hl_calls)))

    # Reads whose failure must still answer with the shape the page renders from.
    _p9_patch(_p9_so, "panel_update_status", _hl_boom("panel_update_status"))
    _p9_patch(_p9_so, "panel_version", lambda: "2026.9.26")
    _p9_patch(_p9_so, "panel_commit", lambda: "a1b2c3d+")
    _r = _A.get("/api/panel/update-status")
    _d = _p9_json(_r)
    check("panel update-status: a failed check says 'no update', keeps the version and boot id",
          _d.get("git") is False and _d.get("update_available") is False
          and _d.get("current_version") == "2026.9.26" and _d.get("boot_id") == _p9_hl._BOOT_ID
          and _d.get("message") == "Internal server error", repr(_d))
    # The card writes "<version> · <current_sha>" over the header the page rendered with both; an
    # answer without the commit left a bare date there, which names a whole day of commits.
    check("panel update-status: ...and the commit beside the version, as the check reports it "
          "(no local-changes '+')", _d.get("current_sha") == "a1b2c3d", repr(_d))
    _p9_patch(_p9_so, "panel_update_log", _hl_boom("panel_update_log"))
    _d = _p9_json(_A.get("/api/panel/update-log"))
    check("panel update-log: a failed read is 'no log', not an exception page",
          _d.get("exists") is False and _d.get("lines") == [] and _d.get("boot_id") == _p9_hl._BOOT_ID,
          repr(_d))
    _p9_patch(_p9_so, "list_panel_branches", _hl_boom("list_panel_branches"))
    _d = _p9_json(_A.get("/api/panel/branches"))
    check("panel branches: a failed listing offers no branches and reports main as current",
          _d.get("branches") == [] and _d.get("current") == "main" and "error" in _d, repr(_d))
    _p9_patch(_p9_so, "panel_diagnostics", _hl_boom("panel_diagnostics"))
    _d = _p9_json(_A.get("/api/panel/diagnostics"))
    check("panel diagnostics: a check that raises is reported as ONE failure, not a clean bill",
          _d.get("summary") == "fail" and _d.get("fail") == 1 and _d.get("checks") == [], repr(_d))
    _p9_patch(_p9_so, "panel_integrity", _hl_boom("panel_integrity"))
    _d = _p9_json(_A.get("/api/panel/integrity"))
    check("panel integrity: a failed check says git is unavailable and lists nothing modified",
          _d.get("git") is False and _d.get("modified") == [] and "error" in _d, repr(_d))

    _hl_calls.clear()
    _p9_patch(_p9_so, "panel_self_update", _hl_rec("panel_self_update", (False, "not a git checkout")))
    _d = _p9_json(_A.post("/api/panel/update"))
    check("panel self-update: the outcome is returned as-is and audited with its success flag",
          _d == {"success": False, "message": "not a git checkout"}
          and _p9_audit("panel_self_update").success is False, repr(_d))
    _hl_calls.clear()
    _p9_patch(_p9_so, "panel_switch_branch", _hl_rec("panel_switch_branch", (True, "on dev")))
    _d = _p9_json(_A.post("/api/panel/switch-branch", json={"branch": "  dev  "}))
    check("panel switch-branch: the branch name reaches the switcher trimmed, and is audited",
          _d.get("success") is True and _hl_calls[-1:] and _hl_calls[-1][1] == ("dev",)
          and _p9_audit("panel_switch_branch").target == "dev", repr((_d, _hl_calls)))

    # repair: `paths` is None (restore all) only when absent or not a list — [] restores nothing.
    for _hl_body, _hl_want in (({"paths": "app.py"}, None), ({"paths": []}, []),
                               ({"paths": ["app.py"]}, ["app.py"])):
        _hl_calls.clear()
        _p9_patch(_p9_so, "panel_repair", _hl_rec("panel_repair", (True, "restored", ["app.py"])))
        _A.post("/api/panel/repair", json=_hl_body)
        check("panel repair: body %r reaches panel_repair as %r" % (_hl_body, _hl_want),
              _hl_calls and _hl_calls[-1][1] == (_hl_want,), repr(_hl_calls))
    check("panel repair: a repair that restored files is audited with their names",
          (_p9_audit("panel_repair") or NS(detail="")).detail == "app.py")
    _p9_patch(_p9_so, "panel_repair", _hl_boom("panel_repair"))
    _r = _A.post("/api/panel/repair", json={})
    check("panel repair: a repair that raises is a 500 with a generic message",
          _r.status_code == 500 and _p9_json(_r).get("message") == "Internal server error")

    # database maintenance endpoints — every one stubbed at the model, so nothing opens a real file.
    from panel.db import models as _p9_models   # noqa: E402
    import db_maintenance as _p9_dbm            # noqa: E402
    _p9_patch(_p9_models, "database_stats", _hl_boom("database_stats"))
    _r = _A.get("/api/panel/db-stats")
    check("db-stats: a failed read is a 500, not a zero-byte database",
          _r.status_code == 500 and "size" not in _p9_json(_r))
    _p9_patch(_p9_models, "optimize_database", lambda: (True, "Optimized.", {"freed": 4096}))
    _r = _A.post("/api/panel/optimize-db")
    check("optimize-db: the result's numbers ride along and the freed bytes are audited",
          _p9_json(_r).get("freed") == 4096 and _p9_json(_r).get("success") is True
          and _p9_audit("panel_db_optimize").detail == "freed 4096 bytes", repr(_p9_json(_r)))
    _p9_patch(_p9_hl, "log_action", _hl_boom("log_action"))
    _r = _A.post("/api/panel/optimize-db")
    check("optimize-db: an audit write that fails does not turn a done VACUUM into an error",
          _r.status_code == 200 and _p9_json(_r).get("success") is True)
    _p9_patch(_p9_hl, "log_action", _p9_auth.log_action)
    _p9_patch(_p9_models, "optimize_database", _hl_boom("optimize_database"))
    _r = _A.post("/api/panel/optimize-db")
    check("optimize-db: a VACUUM that raises is a 500 saying so",
          _r.status_code == 500 and _p9_json(_r).get("success") is False)
    _p9_patch(_p9_dbm, "integrity_check", _hl_boom("integrity_check"))
    _d = _p9_json(_A.get("/api/panel/db-health"))
    check("db-health: a check that could not run is healthy=None (unknown), never True",
          _d.get("healthy") is None and _d.get("detail") == "Internal server error", repr(_d))
    _p9_patch(_p9_so, "panel_repair_database", lambda: (True, "repair scheduled"))
    _d = _p9_json(_A.post("/api/panel/repair-db"))
    check("repair-db: the scheduled repair is returned and audited",
          _d == {"success": True, "message": "repair scheduled"}
          and _p9_audit("panel_repair_db").detail == "repair scheduled", repr(_d))
    _p9_patch(_p9_so, "panel_repair_database", _hl_boom("panel_repair_database"))
    _r = _A.post("/api/panel/repair-db")
    check("repair-db: a repair that raises is a 500", _r.status_code == 500)

    # security: bans / block / autoblock / unban / events / log
    _p9_patch(_p9_so, "fail2ban_overview", _hl_boom("fail2ban_overview"))
    _d = _p9_json(_A.get("/api/panel/security/bans"))
    check("security bans: an unreadable fail2ban reads as not installed with no jails",
          _d.get("installed") is False and _d.get("jails") == [] and "error" in _d, repr(_d))

    _hl_calls.clear()
    _p9_patch(_p9_so, "ufw_deny_ip", _hl_rec("ufw_deny_ip", (True, "blocked")))
    _p9_patch(_p9_so, "ufw_undeny_ip", _hl_rec("ufw_undeny_ip", (True, "unblocked")))
    _p9_patch(_p9_banlist, "refresh_soon", _hl_rec("refresh_soon", None))
    _p9_patch(_p9_hl, "tailnet_exempt_ips", lambda remote, ips: set(ips))
    _d = _p9_json(_A.post("/api/panel/security/block", json={"ip": "100.64.0.9"}))
    check("security block: a Tailscale address is refused before any firewall call",
          _d.get("success") is False and "Tailscale address" in _d.get("message", "")
          and not _hl_calls, repr((_d, _hl_calls)))
    _p9_patch(_p9_hl, "tailnet_exempt_ips", lambda remote, ips: set())
    _p9_patch(_p9_hl, "_whitelisted", lambda ip: True)
    _d = _p9_json(_A.post("/api/panel/security/block", json={"ip": "198.51.100.9"}))
    check("security block: a whitelisted address is refused before any firewall call",
          _d.get("success") is False and "whitelist" in _d.get("message", "") and not _hl_calls,
          repr((_d, _hl_calls)))
    _d = _p9_json(_A.post("/api/panel/security/block", json={"ip": "198.51.100.9", "unblock": True}))
    check("security block: UNblocking skips the refusals and refreshes the panel's own ban gate",
          _d.get("success") is True and [c[0] for c in _hl_calls] == ["ufw_undeny_ip", "refresh_soon"]
          and _p9_audit("ufw_unblock").target == "198.51.100.9", repr((_d, _hl_calls)))
    _p9_patch(_p9_hl, "_whitelisted", lambda ip: False)
    _p9_patch(_p9_so, "ufw_deny_ip", _hl_boom("ufw_deny_ip"))
    _r = _A.post("/api/panel/security/block", json={"ip": "198.51.100.9"})
    check("security block: a firewall call that raises is a 500", _r.status_code == 500)

    _hl_calls.clear()
    _p9_patch(_p9_hl, "_run_autoblock_now", _hl_rec("_run_autoblock_now", None))
    _d = _p9_json(_A.post("/api/panel/security/autoblock", json={"enabled": True, "threshold": 7}))
    check("panel auto-block: switching on stores it, applies the threshold and runs a pass now",
          _d.get("success") is True and _d.get("enabled") is True and _d.get("threshold") == 7
          and P9_LOCAL in _p9_app._autoblock_hosts()
          and [c[1][1] for c in _hl_calls if c[0] == "_run_autoblock_now"] == [P9_LOCAL],
          repr((_d, _hl_calls)))
    _hl_calls.clear()
    _d = _p9_json(_A.post("/api/panel/security/autoblock", json={"enabled": False}))
    check("panel auto-block: switching off removes the host and runs no pass",
          _d.get("enabled") is False and P9_LOCAL not in _p9_app._autoblock_hosts()
          and not [c for c in _hl_calls if c[0] == "_run_autoblock_now"], repr(_hl_calls))

    _hl_calls.clear()
    _p9_patch(_p9_so, "fail2ban_unban", _hl_rec("fail2ban_unban", (True, "unbanned")))
    _d = _p9_json(_A.post("/api/panel/security/unban", json={"jail": "sshd", "ip": "203.0.113.4"}))
    check("security unban: the jail and ip reach fail2ban, the gate refreshes, it is audited",
          _d.get("success") is True and _hl_calls[:1] and _hl_calls[0][1] == ("sshd", "203.0.113.4")
          and "refresh_soon" in [c[0] for c in _hl_calls]
          and _p9_audit("fail2ban_unban").detail == "sshd — unbanned", repr((_d, _hl_calls)))
    _hl_calls.clear()
    _p9_patch(_p9_so, "fail2ban_unban", _hl_rec("fail2ban_unban", (False, "not banned")))
    _A.post("/api/panel/security/unban", json={"jail": "sshd", "ip": "203.0.113.4"})
    check("security unban: a failed unban does not refresh the gate",
          "refresh_soon" not in [c[0] for c in _hl_calls], repr(_hl_calls))
    _p9_patch(_p9_so, "fail2ban_unban", _hl_boom("fail2ban_unban"))
    _r = _A.post("/api/panel/security/unban", json={"jail": "sshd", "ip": "203.0.113.4"})
    check("security unban: an unban that raises is a 500", _r.status_code == 500)

    # The audit row names what was acted on: the canonical address, or a fixed text when the
    # request's did not parse — never the request's own text. An IPv6 zone id parsed, so the target
    # carried whatever the client wrote after its '%'. The panel host's routes and the remote twins.
    _hl_zoned = "fe80::1%x panel login failed from 203.0.113.9"
    _p9_patch(_p9_hl, "tailnet_exempt_ips", lambda remote, ips: set())
    _p9_patch(_p9_hl, "_whitelisted", lambda ip: False)
    _p9_patch(_p9_so, "ufw_deny_ip", _hl_rec("ufw_deny_ip", (False, "Invalid IP address.")))
    _p9_patch(_p9_so, "fail2ban_unban", _hl_rec("fail2ban_unban", (False, "Invalid IP address.")))
    _p9_patch(_p9_rs, "tailnet_exempt_ips", lambda remote, ips: set())
    _p9_patch(_p9_rs, "_whitelisted", lambda ip: False)
    _p9_patch(_p9_rs, "remote_ufw_deny_ip", lambda remote, ip: (False, "Invalid IP address."))
    _p9_patch(_p9_rs, "remote_fail2ban_unban", lambda remote, jail, ip: (False, "Invalid IP address."))
    _hl_targets = []
    for _hl_path, _hl_body, _hl_act in (
            ("/api/panel/security/block", {"ip": _hl_zoned}, "ufw_block"),
            ("/api/panel/security/unban", {"jail": "sshd", "ip": _hl_zoned}, "fail2ban_unban"),
            ("/api/remote/%d/security/block" % P9_HOST, {"ip": _hl_zoned}, "ufw_block"),
            ("/api/remote/%d/security/unban" % P9_HOST, {"jail": "sshd", "ip": _hl_zoned},
             "fail2ban_unban")):
        _A.post(_hl_path, json=_hl_body)
        _hl_targets.append(_p9_audit(_hl_act).target)
    eq("security block/unban (panel host and remote): a zone-id address is audited as a fixed "
       "text, never the request's", _hl_targets, ["(not an IP address)"] * 4)
    _p9_patch(_p9_so, "ufw_deny_ip", _hl_rec("ufw_deny_ip", (True, "blocked")))
    _p9_patch(_p9_rs, "remote_ufw_deny_ip", lambda remote, ip: (True, "blocked"))
    _hl_targets = []
    for _hl_path in ("/api/panel/security/block", "/api/remote/%d/security/block" % P9_HOST):
        _A.post(_hl_path, json={"ip": " 2001:0DB8::0009 "})
        _hl_targets.append(_p9_audit("ufw_block").target)
    eq("security block (panel host and remote): ...and an ordinary one as its canonical address "
       "(positive control)", _hl_targets, ["2001:db8::9"] * 2)
    _p9_patch(_p9_rv, "remote_ufw_allow_from", lambda *a, **k: (False, "Source must be an IP"))
    _hl_details = []
    for _hl_src in (_hl_zoned, " 2001:0DB8::/32 ", "2001:DB8::1/64", "10.0.0.5/24"):
        _A.post("/api/remote/%d/firewall/allow-from" % P9_HOST,
                json={"source": _hl_src, "port": "22", "protocol": "tcp"})
        _hl_details.append(_p9_audit("remote_port_allow_from").detail)
    eq("firewall allow-from: the audit names the source as the rule is sent — host bits kept, as "
       "ufw stores an IPv6 source — or a fixed text when it is not one; never the request's own",
       _hl_details, ["from (not an IP address)", "from 2001:db8::/32", "from 2001:db8::1/64",
                     "from 10.0.0.5/24"])
    # ...and through the REAL remote_ufw_allow_from, its privileged call recorded: the rule sent,
    # the message and the audit row must name the source the same way.
    _hl_sent = []
    _hl_rp_saved = _p9_core.run_privileged
    try:
        _p9_core.run_privileged = lambda server, verb, args=(), **k: (
            _hl_sent.append((verb, list(args))), ("", "", 0))[1]
        _p9_patch(_p9_rv, "remote_ufw_allow_from", _p9_sm.hosts.remote_ufw_allow_from)
        _hl_agree = []
        for _hl_src in ("2001:DB8::1/64", " 10.0.0.5/24 "):
            del _hl_sent[:]
            _d = _p9_json(_A.post("/api/remote/%d/firewall/allow-from" % P9_HOST,
                                  json={"source": _hl_src, "port": "22", "protocol": "tcp"}))
            _hl_agree.append((_hl_sent[0][1][0] if _hl_sent else None, _d.get("message"),
                              _p9_audit("remote_port_allow_from").detail))
    finally:
        _p9_core.run_privileged = _hl_rp_saved
    eq("firewall allow-from: ...and the rule sent, the message and the audit agree on the source",
       _hl_agree,
       [("2001:db8::1/64", "Port 22/tcp open from 2001:db8::1/64", "from 2001:db8::1/64"),
        ("10.0.0.5/24", "Port 22/tcp open from 10.0.0.5/24", "from 10.0.0.5/24")])

    _p9_patch(_p9_models, "AuditLog", NS(query=None, action=AuditLog.action))
    _d = _p9_json(_A.get("/api/panel/security/events"))
    _p9_patch(_p9_models, "AuditLog", AuditLog)
    check("security events: a failed query answers no events plus an error, not a 500",
          _d.get("events") == [] and "error" in _d, repr(_d))
    _r = _A.get("/api/panel/security/log?which=../../etc/shadow")
    check("security log: a log name outside the whitelist is refused (400)",
          _r.status_code == 400 and _p9_json(_r).get("error") == "unknown log")
    _hl_calls.clear()
    _p9_patch(_p9_so, "security_log_tail", _hl_rec("security_log_tail", "line1\nline2"))
    _d = _p9_json(_A.get("/api/panel/security/log?which=fail2ban&jail=%20sshd%20"))
    check("security log: the jail is passed trimmed, only for the named log",
          _d.get("text") == "line1\nline2" and _hl_calls[-1:] and _hl_calls[-1][1] == ("fail2ban", 300)
          and _hl_calls[-1][2] == {"jail": "sshd"}, repr(_hl_calls))
    _p9_patch(_p9_so, "security_log_tail", _hl_boom("security_log_tail"))
    _d = _p9_json(_A.get("/api/panel/security/log?which=ssh"))
    check("security log: a failed read answers empty text plus an error",
          _d.get("text") == "" and "error" in _d, repr(_d))

    # The global whitelist (_shared._whitelist_mutate), through the panel-host route.
    _wl_applied = []
    _p9_patch(_p9_sh, "_apply_whitelist_everywhere", lambda app, unban=None: _wl_applied.append(unban))
    _p9_patch(_p9_sh, "_autoblock_hosts", lambda: {P9_LOCAL})
    _wl_auto = []
    _p9_patch(_p9_sh, "_run_autoblock_now", lambda app, rid: _wl_auto.append(rid))
    _d = _p9_json(_A.post("/api/panel/security/whitelist", json={"ip": "198.51.100.23"}))
    _p9_drain()
    check("whitelist add: a single address is stored, lifted everywhere, and auto-block re-run",
          _d.get("added") == "198.51.100.23" and "198.51.100.23" in _d.get("whitelist", [])
          and _wl_applied == ["198.51.100.23"] and _wl_auto == [P9_LOCAL]
          and _p9_audit("whitelist_add").target == "198.51.100.23", repr((_d, _wl_applied)))
    _wl_applied.clear()
    _d = _p9_json(_A.post("/api/panel/security/whitelist", json={"ip": "10.9.0.0/16"}))
    _p9_drain()
    check("whitelist add: a CIDR range is stored but lifts no single ban",
          _d.get("added") == "10.9.0.0/16" and _wl_applied == [None], repr((_d, _wl_applied)))
    _wl_applied.clear()
    _d = _p9_json(_A.post("/api/panel/security/whitelist",
                          json={"ip": "198.51.100.23", "remove": True}))
    _p9_drain()
    check("whitelist remove: the entry goes, the jails are re-synced, and it is audited",
          _d.get("removed") == "198.51.100.23" and "198.51.100.23" not in _d.get("whitelist", [])
          and _wl_applied == [None] and _p9_audit("whitelist_remove").target == "198.51.100.23",
          repr((_d, _wl_applied)))
    _A.post("/api/panel/security/whitelist", json={"ip": "10.9.0.0/16", "remove": True})
    _p9_drain()
    # The raw text still picks the entry to drop, so one stored with a zone before the add refused
    # them can go — but the audit row and the answer name only the address it was read as, or a
    # fixed text, never the request's own.
    _p9_app.update_config(lambda cfg: cfg.update(security_whitelist=[
        "fe80::1%x panel login failed from 203.0.113.9", "198.51.100.24"]))
    _wl_rm = []
    for _wl_raw in ("fe80::1%x panel login failed from 203.0.113.9", "x y from 203.0.113.9",
                    " 198.51.100.24 "):
        _d = _p9_json(_A.post("/api/panel/security/whitelist",
                              json={"ip": _wl_raw, "remove": True}))
        _p9_drain()
        _wl_rm.append((_d.get("removed"), _p9_audit("whitelist_remove").target))
    eq("whitelist remove: the audit target and the 'removed' answer are the parsed address or a "
       "fixed text — never the request's own text", _wl_rm,
       [("fe80::1", "fe80::1"), ("(not an IP address)", "(not an IP address)"),
        ("198.51.100.24", "198.51.100.24")])
    eq("whitelist remove: ...while the raw text still removed the stored zoned entry",
       _p9_app._security_whitelist(), [])

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # panel/routes/server_detail.py
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _sd_runs = []
    _sd_result = [("", "", 0)]

    def _sd_run(remote, user, action, **k):
        _sd_runs.append((user, action, {x: k[x] for x in ("tee_log", "answers") if x in k}))
        r = _sd_result[0]
        if isinstance(r, Exception):
            raise r
        return r

    _sd_side = []
    _p9_patch(_p9_sm, "run_as_game_user", _sd_run)
    _p9_patch(_p9_sm, "_invalidate_port_scan", lambda rid: _sd_side.append(("invalidate", rid)))
    _p9_patch(_p9_sm, "invalidate_game_version", lambda rid, s: _sd_side.append(("version", rid, s)))
    _p9_patch(_p9_sm, "set_game_priority", lambda remote, user, *a, **k: _sd_side.append(("prio", user)))
    _p9_patch(_p9_sm, "server_live_metrics", lambda *a, **k: {"ram_total": 0})   # "can't tell"
    _p9_patch(_p9_sh, "_drain_action_output", lambda app, remote, sid: False)

    # ── the synchronous action path (update-lgsm is the one runnable action that is neither long,
    #    a power action, nor read-only) and the read-only one ─────────────────────────────────────
    _sd_result[0] = ("\x1b[32mUpdating LinuxGSM\x1b[0m\nOK", "", 0)
    _d = _p9_json(_A.post("/api/server/%d/action" % P9_GS, json={"action": "update-lgsm"}))
    check("action update-lgsm: rc 0 is reported as success, naming the server",
          _d == {"success": True, "message": "'update-lgsm' succeeded for 'p9-cs'."}, repr(_d))
    check("action update-lgsm: the audit row holds the output with its colour codes stripped",
          _p9_audit("update-lgsm_server").detail.startswith("Updating LinuxGSM")
          and "\x1b" not in _p9_audit("update-lgsm_server").detail)
    _sd_result[0] = ("Checking\nERROR: could not download lgsm\nExiting now", "", 1)
    _d = _p9_json(_A.post("/api/server/%d/action" % P9_GS, json={"action": "update-lgsm"}))
    check("action failure: the message quotes the LinuxGSM line that names the fault",
          _d.get("success") is False
          and _d.get("message", "").endswith(": ERROR: could not download lgsm"), repr(_d))
    _sd_result[0] = ("step one\nlast words", "", 1)
    _d = _p9_json(_A.post("/api/server/%d/action" % P9_GS, json={"action": "update-lgsm"}))
    check("action failure: with no fault keyword it falls back to the last line",
          _d.get("message", "").endswith(": last words"), repr(_d))
    _sd_result[0] = ("", "", 1)
    _d = _p9_json(_A.post("/api/server/%d/action" % P9_GS, json={"action": "update-lgsm"}))
    check("action failure: no output at all says 'unknown — check the console'",
          "unknown — check the console" in _d.get("message", ""), repr(_d))
    _sd_result[0] = ("Status:      \x1b[32mSTARTED\x1b[0m", "", 0)
    _d = _p9_json(_A.post("/api/server/%d/action" % P9_GS, json={"action": "details"}))
    check("action details (read-only): the output comes back, cleaned, whitespace collapsed",
          _d == {"success": True, "message": "details: Status: STARTED"}, repr(_d))
    _sd_result[0] = ("", "", 0)
    _d = _p9_json(_A.post("/api/server/%d/action" % P9_GS, json={"action": "details"}))
    check("action details: empty output says so rather than printing nothing",
          _d.get("message") == "details: no output", repr(_d))
    _sd_result[0] = ConnectionError("ssh down")
    _r = _A.post("/api/server/%d/action" % P9_GS, json={"action": "details"})
    check("action (JSON): a host that raises is a 500 with a generic message",
          _r.status_code == 500 and _p9_json(_r).get("message") == "Internal server error")

    # The FORM variant: flash + redirect, never the exception text.
    _r = _A.post("/server/%d/action" % P9_GS, data={"action": "details"})
    _fl = _p9_flashes(_A)
    check("action (form): a host that raises flashes a generic failure and audits the error",
          _r.status_code == 302 and _fl == ["That action failed. The audit log has the details."]
          and _p9_audit("details_server").success is False
          and "ssh down" in _p9_audit("details_server").detail, repr((_fl, _p9_audit("details_server"))))
    _r = _A.post("/server/%d/action" % P9_GS, data={"action": "rm -rf"})
    check("action (form): an action outside the runnable set is refused by name",
          _p9_flashes(_A) == ["Unknown or unsupported action: rm -rf"])
    _r = _V.post("/server/%d/action" % P9_GS, data={"action": "restart"})
    check("action (form): a viewer without RESTART is told so, and nothing runs",
          _p9_flashes(_V) == ["You don't have permission to run 'restart'."])
    _sd_result[0] = ("Status: STOPPED", "", 0)
    _r = _V.post("/server/%d/action" % P9_GS, data={"action": "details"})
    check("action (form): a viewer MAY run a read-only action and sees its output",
          _r.status_code == 302 and _p9_flashes(_V) == ["details: Status: STOPPED"])

    # ── background power actions (_bg_power_action) and their completion callback ───────────────
    _sd_done = []
    _p9_set(P9_GS, status="offline", restart_pending=True, stop_pending=False)
    _sd_side.clear()
    _sd_result[0] = ("restarted", "", 0)

    def _prio_raises(remote, user, *a, **k):
        raise ConnectionError("renice refused")

    _p9_patch(_p9_sm, "set_game_priority", _prio_raises)
    with _p9.app_context():
        _sd_ok, _sd_msg = _p9._run_action(db.session.get(GameServer, P9_GS),
                                          db.session.get(RemoteServer, P9_HOST), "restart", None,
                                          origin="telegram",
                                          on_done=lambda ok, d: _sd_done.append((ok, d)))
    check("power action: accepted immediately, before anything ran",
          _sd_ok is True and "issued" in _sd_msg and _sd_done == [], repr((_sd_ok, _sd_msg)))
    _p9_drain()
    check("power action: a clean restart clears the queued 'when empty' flags and the port scan",
          _p9_row(P9_GS).restart_pending is False and ("invalidate", P9_HOST) in _sd_side,
          repr(_sd_side))
    check("power action: a priority nudge that raises still reports success to the caller",
          _sd_done == [(True, "restarted")], repr(_sd_done))
    check("power action: the bot that asked is named in the audit row",
          _p9_audit("restart_server").username == "telegram")
    _p9_patch(_p9_sm, "set_game_priority",
              lambda remote, user, *a, **k: _sd_side.append(("prio", user)))

    _sd_done.clear()
    _sd_result[0] = OSError("channel closed")
    with _p9.app_context():
        _p9._run_action(db.session.get(GameServer, P9_GS), db.session.get(RemoteServer, P9_HOST),
                        "stop", None, on_done=lambda ok, d: _sd_done.append((ok, d)))
    _p9_drain()
    check("power action: a run that raises reaches the caller as a failure, not silence",
          _sd_done == [(False, "the action didn't run")], repr(_sd_done))

    # A row deleted between accepting the action and running it.
    _sd_ghost = _p9_new_server(P9_HOST, "ghostserver", "csgo", 27099, status="offline")
    _sd_done.clear()
    _sd_result[0] = ("", "", 0)
    _sd_runs.clear()
    with _p9.app_context():
        _p9._run_action(db.session.get(GameServer, _sd_ghost), db.session.get(RemoteServer, P9_HOST),
                        "restart", None, on_done=lambda ok, d: _sd_done.append((ok, d)))
    _p9_delete_server(_sd_ghost)
    _p9_drain()
    check("power action: a server removed before it ran is reported gone, and nothing is run",
          _sd_done == [(False, "the server or its host is no longer configured")] and _sd_runs == [],
          repr((_sd_done, _sd_runs)))

    def _done_raises(ok, d):
        raise RuntimeError("telegram is down")

    with _p9.app_context():
        _p9._run_action(db.session.get(GameServer, P9_GS), db.session.get(RemoteServer, P9_HOST),
                        "restart", None, on_done=_done_raises)
    _sd_cb_before = _p9_audit_count("restart_server")
    _sd_cb_ok = True
    try:
        _p9_drain()
    except Exception:
        _sd_cb_ok = False
    check("power action: a completion callback that raises is swallowed, after the restart was "
          "recorded", _sd_cb_ok and _p9_audit_count("restart_server") == _sd_cb_before + 1
          and _p9_audit("restart_server").success is True)

    # ── long actions (_bg_action) ───────────────────────────────────────────────────────────────
    _sd_done.clear()
    _sd_runs.clear()
    _P9_EMITS.clear()
    _sd_mods = []
    _p9_patch(_p9_sd, "_apply_mod_restart", lambda gs, remote: _sd_mods.append(gs.short_name))
    _sd_result[0] = ("mods updated", "", 0)
    with _p9.app_context():
        _sd_ok, _sd_msg = _p9._run_action(db.session.get(GameServer, P9_GS),
                                          db.session.get(RemoteServer, P9_HOST), "mods-update", None,
                                          on_done=lambda ok, d: _sd_done.append((ok, d)))
    check("long action: accepted with 'watch the live console'", "watch the live console" in _sd_msg)
    _p9_drain()
    check("long action: the command runs with its output teed to a file for the console",
          _sd_runs == [("csgoserver", "mods-update", {"tee_log": True, "answers": None})],
          repr(_sd_runs))
    check("long action: a successful mods-update asks whether the server needs a restart",
          _sd_mods == ["csgoserver"] and _sd_done == [(True, "mods updated")],
          repr((_sd_mods, _sd_done)))
    check("long action: the console is told it started and finished",
          [e[1]["data"] for e in _P9_EMITS if e[0] == "console_output"]
          == ["[panel] mods-update started — its output follows.",
              "[panel] mods-update finished successfully."],
          repr([e[1] for e in _P9_EMITS]))
    check("long action: the cached version and port scan are dropped afterwards",
          ("version", P9_HOST, "csgoserver") in _sd_side and ("invalidate", P9_HOST) in _sd_side)

    def _mods_restart_raises(gs, remote):
        raise ConnectionError("restart check failed")

    _p9_patch(_p9_sd, "_apply_mod_restart", _mods_restart_raises)
    _sd_done.clear()
    with _p9.app_context():
        _p9._run_action(db.session.get(GameServer, P9_GS), db.session.get(RemoteServer, P9_HOST),
                        "mods-update", None, on_done=lambda ok, d: _sd_done.append((ok, d)))
    _p9_drain()
    check("long action: a post-update restart check that raises does not turn success into failure",
          _sd_done == [(True, "mods updated")], repr(_sd_done))

    _sd_done.clear()
    _P9_EMITS.clear()
    _sd_result[0] = ConnectionError("dropped mid-update")
    with _p9.app_context():
        _p9._run_action(db.session.get(GameServer, P9_GS), db.session.get(RemoteServer, P9_HOST),
                        "update", None, on_done=lambda ok, d: _sd_done.append((ok, d)))
    _p9_drain()
    check("long action: a run that raises says 'stopped reporting', never 'failed (exit …)'",
          _sd_done == [(False, "the action didn't run")]
          and any("update stopped reporting" in (e[1] or {}).get("data", "") for e in _P9_EMITS),
          repr((_sd_done, [e[1] for e in _P9_EMITS])))

    _sd_done.clear()
    _sd_runs.clear()
    with _p9.app_context():
        _p9._run_action(NS(id=90010, status="offline", short_name="ghostserver",
                           lgsm_name="csgoserver", name="ghost"), NS(id=99904), "fastdl", None,
                        on_done=lambda ok, d: _sd_done.append((ok, d)))
    _p9_drain()
    check("long action: a host deleted before it ran is reported gone and nothing runs",
          _sd_done == [(False, "its host is no longer configured")] and _sd_runs == [],
          repr((_sd_done, _sd_runs)))

    # ── bulk actions ────────────────────────────────────────────────────────────────────────────
    _sd_runs.clear()
    _sd_result[0] = ("", "", 0)
    _d = _p9_json(_A.post("/api/servers/bulk-action",
                          json={"action": "update-lgsm", "server_ids": ["x", None, P9_GS, 99905]}))
    _p9_drain()
    check("bulk action: ids that are not numbers are dropped, unknown ones are skipped by name",
          [q["server_id"] for q in _d.get("queued", [])] == [P9_GS]
          and _d.get("skipped") == [{"server_id": 99905, "name": "#99905", "reason": "not found"}]
          and _sd_runs == [("csgoserver", "update-lgsm", {})], repr((_d, _sd_runs)))
    _sd_result[0] = ConnectionError("down")
    _A.post("/api/servers/bulk-action", json={"action": "update-lgsm", "server_ids": [P9_GS]})
    _sd_bulk_ok = True
    _sd_before = _p9_audit_count("update-lgsm_server")
    try:
        _p9_drain()
    except Exception:
        _sd_bulk_ok = False
    check("bulk action: one server's worker raising is contained in that worker",
          _sd_bulk_ok and _p9_audit_count("update-lgsm_server") == _sd_before)
    _sd_result[0] = ("", "", 0)

    # ── read endpoints whose host call raises ───────────────────────────────────────────────────
    def _raise_conn(*a, **k):
        raise ConnectionError("unreachable")

    _p9_patch(_p9_sd, "sm_player_count", _raise_conn)
    eq("players: a count that raises is null (unknown), never 0",
       _p9_json(_A.get("/api/server/%d/players" % P9_GS)), {"players": None})
    _p9_patch(_p9_sd, "player_list", _raise_conn)
    _d = _p9_json(_A.get("/api/server/%d/playerlist" % P9_GS))
    check("playerlist: a list that raises is 'unknown', not 'nobody connected'",
          _d.get("players") == [] and _d.get("unknown") is True, repr(_d))
    _r = _V.post("/api/server/%d/query-type" % P9_GS, json={"query_type": "csgo"})
    check("query type: a viewer cannot change server configuration (403)", _r.status_code == 403)

    # ── moderation ──────────────────────────────────────────────────────────────────────────────
    _mod_calls = []

    def _mod(remote, short, gtype, action, **kw):
        _mod_calls.append((short, action, kw.get("steamid") or kw.get("target") or ""))
        if short == "cssserver":
            raise ConnectionError("css host down")
        if short == "gmodserver":
            return False, "no session"
        return True, "Done."

    _p9_patch(_p9_sm, "moderate", _mod)
    _p9_patch(_p9_sm, "ensure_persistent_bans", _raise_conn)
    _p9_patch(_p9_sd, "_resolve_from_console",
              lambda remote, short, gtype, target, lgsm: {"steamid": "STEAM_0:0:9001"})
    _p9_patch(_p9_sm, "ensure_persistent_bans", lambda *a, **k: None)
    _A.post("/api/server/%d/moderate" % P9_GS,
            json={"action": "ban", "target": "Named", "scope": "this"})
    check("moderate ban: a name-only Valve ban is issued against the SteamID the console resolved",
          _mod_calls == [("csgoserver", "ban", "STEAM_0:0:9001")], repr(_mod_calls))
    _mod_calls.clear()
    _p9_patch(_p9_sm, "ensure_persistent_bans", _raise_conn)
    _p9_patch(_p9_sd, "_resolve_from_console", _raise_conn)
    _sd_css = _p9_new_server(P9_HOST, "cssserver", "css", 27020, status="online")
    _p9_set(P9_GM, installed=True)
    _d = _p9_json(_A.post("/api/server/%d/moderate" % P9_GS,
                          json={"action": "ban", "target": "Cheater", "scope": "this"}))
    check("moderate ban: a console SteamID lookup and a ban-persistence step that both raise "
          "do not stop the ban", _d.get("success") is True
          and _mod_calls == [("csgoserver", "ban", "Cheater")], repr((_d, _mod_calls)))

    _mod_calls.clear()
    _d = _p9_json(_A.post("/api/server/%d/moderate" % P9_GS,
                          json={"action": "ban", "target": "Cheater", "steamid": "STEAM_0:1:4242",
                                "scope": "all", "reason": "aimbot"}))
    _mod_fanned = sorted(c[0] for c in _mod_calls if c[0] != "csgoserver")
    check("moderate ban-all: every other valve server gets the SteamID ban",
          _mod_fanned == ["cssserver", "gmodserver", "tf2server"]
          and all(c[2] == "STEAM_0:1:4242" for c in _mod_calls), repr(_mod_calls))
    check("moderate ban-all: servers that raised or refused are counted as MISSED, not banned",
          "1 of 3 banned, 2 could not be reached" in _d.get("message", ""), repr(_d))
    _sd_aud = _p9_audit("moderate_ban_all")
    check("moderate ban-all: the audit row is a failure naming the servers that missed it",
          _sd_aud.success is False and "cssserver" in _sd_aud.detail and "gmodserver" in _sd_aud.detail
          and _sd_aud.target == "1 of 3 server(s)", repr(_sd_aud))
    with _p9.app_context():
        _sd_gb = GlobalBan.query.filter_by(steamid="STEAM_0:1:4242").first()
        _sd_gb = None if _sd_gb is None else (_sd_gb.player_name, _sd_gb.reason, _sd_gb.created_by)
    check("moderate ban-all: a superadmin's SteamID ban lands on the managed global list",
          _sd_gb == ("Cheater", "aimbot", "p9_admin")
          and "Added to the global ban list." in _d.get("message", ""), repr(_sd_gb))

    # A moderator scoped to host 1 only: the fan-out must not reach host 2's server.
    with _p9.app_context():
        _mg = Group(name="p9_mods", description="", is_default=False)
        _mg.set_permissions([_p9_auth.MODERATE_SERVER])
        _mg.servers.append(db.session.get(RemoteServer, P9_HOST))
        db.session.add(_mg)
        db.session.flush()
        _mu = User(username="p9_mod", password_hash=_pw, display_name="Mod", is_superadmin=False,
                   is_active=True)
        _mu.groups.append(_mg)
        db.session.add(_mu)
        db.session.commit()
        P9_MOD = _mu.id
    _M = _p9_client(P9_MOD)
    _mod_calls.clear()
    _p9_set(P9_GM, installed=False)          # leave css as the only in-scope target
    # css vanishes between being chosen as a target and being banned — a delete racing the fan-out.
    _sd_real_cas = _p9_sd.can_access_server

    def _cas_and_delete(user, sid):
        ok = _sd_real_cas(user, sid)
        if sid == _sd_css and ok:
            with _p9.app_context():
                db.session.delete(db.session.get(GameServer, _sd_css))
                db.session.commit()
        return ok

    _p9_patch(_p9_sd, "can_access_server", _cas_and_delete)
    _d = _p9_json(_M.post("/api/server/%d/moderate" % P9_GS,
                          json={"action": "ban", "steamid": "STEAM_0:1:777", "scope": "all"}))
    _p9_patch(_p9_sd, "can_access_server", _sd_real_cas)
    check("moderate ban-all (scoped mod): a server on a host they cannot access is never touched",
          "tf2server" not in [c[0] for c in _mod_calls], repr(_mod_calls))
    check("moderate ban-all: a target deleted mid-fan-out is reported missed, not banned",
          "0 of 1 banned, 1 could not be reached" in _d.get("message", ""), repr(_d))
    with _p9.app_context():
        check("moderate ban-all: a non-superadmin's ban is NOT written to the global list",
              GlobalBan.query.filter_by(steamid="STEAM_0:1:777").first() is None)
    _p9_set(P9_GM, installed=True)

    _p9_patch(_p9_sm, "moderate", _raise_conn)
    _r = _A.post("/api/server/%d/moderate" % P9_GS, json={"action": "kick", "target": "x"})
    check("moderate: a console that raises is a 500 with a generic message",
          _r.status_code == 500 and _p9_json(_r).get("message") == "Internal server error")

    # ── custom commands ─────────────────────────────────────────────────────────────────────────
    _r = _A.post("/api/server/%d/custom-command/99906" % P9_GS, json={})
    check("custom command: an id that does not exist is refused (403), not a 500",
          _r.status_code == 403)
    with _p9.app_context():
        _cc = CustomCommand(name="Say", command_template="say hello", scope_type="all", enabled=True)
        db.session.add(_cc)
        db.session.commit()
        _sd_cc = _cc.id
    _sd_sent = []
    _sd_send = [("", "", 1)]

    def _send(remote, user, cmd, **k):
        _sd_sent.append(cmd)
        r = _sd_send[0]
        if isinstance(r, Exception):
            raise r
        return r

    _p9_patch(_p9_sd, "send_console_command", _send)
    _r = _A.post("/api/server/%d/custom-command/%d" % (P9_GS, _sd_cc), json={})
    check("custom command: a send that failed with no stderr says it gave no reason (502)",
          _r.status_code == 502
          and _p9_json(_r).get("message")
          == "The panel could not run that on the host, and it gave no reason.",
          repr(_p9_json(_r)))
    _sd_send[0] = ConnectionError("down")
    _r = _A.post("/api/server/%d/custom-command/%d" % (P9_GS, _sd_cc), json={})
    check("custom command: a send that raises is a 500", _r.status_code == 500)

    # ── the 'when empty' queue and the per-server toggles ──────────────────────────────────────
    _p9_set(P9_GS, restart_pending=False, stop_pending=True)
    _d = _p9_json(_A.post("/api/server/%d/restart-when-empty" % P9_GS))
    _row = _p9_row(P9_GS)
    check("restart-when-empty: queues a restart and supersedes a queued stop",
          _d.get("success") is True and _row.restart_pending is True and _row.stop_pending is False
          and _p9_audit("restart_when_empty").target == "p9-cs")
    _d = _p9_json(_A.post("/api/server/%d/stop-when-empty" % P9_GS))
    _row = _p9_row(P9_GS)
    check("stop-when-empty: queues a stop and supersedes the queued restart",
          _d.get("success") is True and _row.stop_pending is True and _row.restart_pending is False)
    for _u in ("restart-when-empty", "stop-when-empty", "autostart", "daily-restart", "notify-empty"):
        _r = _V.post("/api/server/%d/%s" % (P9_GS, _u), json={"enabled": True})
        check("%s: a viewer without the power permission is refused (403)" % _u,
              _r.status_code == 403, "got %d" % _r.status_code)
    _p9_set(P9_GS, stop_pending=False)

    _sd_auto = [(True, "")]

    def _autostart(remote, user, enabled, selfname=None):
        r = _sd_auto[0]
        if isinstance(r, Exception):
            raise r
        return r

    _p9_patch(_p9_sd, "set_autostart", _autostart)
    _p9_set(P9_GS, autostart=True)
    _d = _p9_json(_A.post("/api/server/%d/autostart" % P9_GS, json={"enabled": False}))
    check("autostart: a crontab that changed flips the stored flag and is audited",
          _d == {"success": True, "enabled": False} and _p9_row(P9_GS).autostart is False
          and _p9_audit("set_autostart").detail == "False", repr(_d))
    _sd_auto[0] = (False, "")
    _r = _A.post("/api/server/%d/autostart" % P9_GS, json={"enabled": True})
    check("autostart: a crontab write that failed is a 500 and the flag is left alone",
          _r.status_code == 500 and _p9_json(_r).get("message") == "Failed to update crontab"
          and _p9_row(P9_GS).autostart is False, repr(_p9_json(_r)))
    _sd_auto[0] = ConnectionError("down")
    _r = _A.post("/api/server/%d/autostart" % P9_GS, json={"enabled": True})
    check("autostart: a host that raises is a 500 and the flag is left alone",
          _r.status_code == 500 and _p9_row(P9_GS).autostart is False)

    _sd_daily = [(False, "crontab refused")]
    def _daily(*a, **k):
        if isinstance(_sd_daily[0], Exception):
            raise _sd_daily[0]
        return _sd_daily[0]

    _p9_patch(_p9_sd, "set_daily_restart", _daily)
    _p9_set(P9_GS, daily_restart=False, daily_restart_at="05:00")
    _r = _A.post("/api/server/%d/daily-restart" % P9_GS, json={"enabled": True, "time": "06:30"})
    check("daily restart: a schedule the host refused is a 500 with its reason; nothing stored",
          _r.status_code == 500 and _p9_json(_r).get("message") == "crontab refused"
          and _p9_row(P9_GS).daily_restart is False and _p9_row(P9_GS).daily_restart_at == "05:00",
          repr(_p9_json(_r)))
    _sd_daily[0] = ConnectionError("down")
    _r = _A.post("/api/server/%d/daily-restart" % P9_GS, json={"enabled": True})
    check("daily restart: a host that raises is a 500", _r.status_code == 500)

    _d = _p9_json(_A.post("/api/server/%d/notify-empty" % P9_GS, json={"enabled": True}))
    check("notify-empty: the one-shot flag is stored and audited",
          _d == {"success": True, "enabled": True} and _p9_row(P9_GS).notify_when_empty is True
          and _p9_audit("set_notify_when_empty").detail == "True")
    _p9_set(P9_GS, notify_when_empty=False)

    # ── refresh-commands and the console command form ───────────────────────────────────────────
    _V.post("/server/%d/refresh-commands" % P9_GS)
    check("refresh commands: a viewer is refused before the host is asked",
          _p9_flashes(_V) == ["You don't have permission to refresh this server's commands."])
    _p9_patch(_p9_sm, "list_server_commands", _raise_conn)
    _p9_set(P9_GS, commands='[{"cmd": "start", "desc": "Start"}]')
    _A.post("/server/%d/refresh-commands" % P9_GS)
    check("refresh commands: a host that raises keeps the stored list and says it could not read",
          _p9_flashes(_A) == ["Could not read the command list for 'p9-cs'."]
          and '"start"' in _p9_row(P9_GS).commands
          and _p9_audit("refresh_commands").success is False)

    _A.post("/server/%d/command" % P9_GS, data={"command": "   "})
    check("console command (form): an empty command is refused without sending anything",
          _p9_flashes(_A) == ["No command entered."])
    _sd_sent.clear()
    _V.post("/server/%d/command" % P9_GS, data={"command": "status"})
    check("console command (form): a viewer without SEND_COMMAND is refused and nothing is sent",
          _p9_flashes(_V) == ["You don't have permission to send commands."] and _sd_sent == [])
    _sd_send[0] = ConnectionError("tmux gone")
    _A.post("/server/%d/command" % P9_GS, data={"command": "status"})
    check("console command (form): a send that raises flashes a generic failure and audits it",
          _p9_flashes(_A) == ["Failed to send that command. The audit log has the details."]
          and _p9_audit("send_command").success is False
          and "tmux gone" in _p9_audit("send_command").detail)

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # panel/routes/server_files.py
    # ════════════════════════════════════════════════════════════════════════════════════════════
    # A file manager on host 1: MANAGE_SERVERS only — may edit files, may NOT change mods (that needs
    # UPDATE_SERVER) and may NOT read the console (that needs VIEW_CONSOLE).
    with _p9.app_context():
        _fg = Group(name="p9_files", description="", is_default=False)
        _fg.set_permissions([_p9_auth.MANAGE_SERVERS])
        _fg.servers.append(db.session.get(RemoteServer, P9_HOST))
        db.session.add(_fg)
        db.session.flush()
        _fu = User(username="p9_files", password_hash=_pw, display_name="Files",
                   is_superadmin=False, is_active=True)
        _fu.groups.append(_fg)
        db.session.add(_fu)
        db.session.commit()
        P9_FILES = _fu.id
    _F = _p9_client(P9_FILES)
    _sf_url = "/api/server/%d" % P9_GS

    # config editor
    _p9_patch(_p9_sf, "lgsm_read_config", _raise_conn)
    _r = _A.get(_sf_url + "/config")
    check("config GET: a read that raises is a 500, not an empty editor",
          _r.status_code == 500 and _p9_json(_r).get("error") == "Internal server error")
    _sf_writes = []
    _sf_write_result = [(True, "")]

    def _sf_write_file(remote, user, rel, content):
        _sf_writes.append(("file", user, rel, content))
        r = _sf_write_result[0]
        if isinstance(r, Exception):
            raise r
        return r

    def _sf_write_cfg(remote, user, lgsm, settings):
        _sf_writes.append(("cfg", user, lgsm, dict(settings)))
        r = _sf_write_result[0]
        if isinstance(r, Exception):
            raise r
        return r

    _p9_patch(_p9_sf, "write_file", _sf_write_file)
    _p9_patch(_p9_sf, "lgsm_write_config", _sf_write_cfg)
    _d = _p9_json(_A.post(_sf_url + "/config", json={"raw": "maxplayers=\"16\"\n"}))
    check("config POST raw: the text is written to the instance's own .cfg and reported saved",
          _d == {"success": True, "message": "Saved"}
          and _sf_writes == [("file", "csgoserver", "lgsm/config-lgsm/csgoserver/csgoserver.cfg",
                              "maxplayers=\"16\"\n")], repr((_d, _sf_writes)))
    _sf_writes.clear()
    _sf_write_result[0] = (False, "")
    _d = _p9_json(_A.post(_sf_url + "/config", json={"settings": {"maxplayers": "20"}}))
    check("config POST settings: the keys go through the safe writer; a refusal reads 'Failed'",
          _d == {"success": False, "message": "Failed"}
          and _sf_writes == [("cfg", "csgoserver", "csgoserver", {"maxplayers": "20"})]
          and _p9_audit("edit_config").success is False, repr((_d, _sf_writes)))
    _sf_write_result[0] = OSError("sftp gone")
    _r = _A.post(_sf_url + "/config", json={"settings": {"a": "b"}})
    check("config POST: a write that raises is a 500 with a generic message",
          _r.status_code == 500 and _p9_json(_r).get("message") == "Internal server error")
    _sf_write_result[0] = (True, "")

    _p9_patch(_p9_sf, "lgsm_game_config", _raise_conn)
    _r = _A.get(_sf_url + "/game-config")
    check("game-config: a read that raises answers an error body the page can show",
          _r.status_code == 200 and _p9_json(_r).get("error") == "Internal server error")

    # alerts
    _p9_patch(_p9_sf, "lgsm_get_values", _raise_conn)
    _d = _p9_json(_A.get(_sf_url + "/alerts"))
    check("alerts GET: a read that raises is 'unknown', never a blank form that Save would write back",
          "values" not in _d and "Nothing has been changed" in _d.get("error", ""), repr(_d))
    _sf_writes.clear()
    _d = _p9_json(_A.post(_sf_url + "/alerts",
                          json={"values": {"discordalert": "TRUE", "discordwebhook": "https://x/y",
                                           "telegramalert": "nope", "evil_key": "rm -rf /"}}))
    check("alerts POST: only known keys are written, and toggles are coerced to on/off",
          _sf_writes == [("cfg", "csgoserver", "csgoserver",
                          {"discordalert": "on", "discordwebhook": "https://x/y",
                           "telegramalert": "off"})] and _d.get("success") is True,
          repr(_sf_writes))
    _sf_write_result[0] = OSError("gone")
    _d = _p9_json(_A.post(_sf_url + "/alerts", json={"values": {"discordalert": "on"}}))
    check("alerts POST: a write that raises answers success=false, not a crash",
          _d.get("success") is False and _d.get("message") == "Internal server error")
    _sf_write_result[0] = (True, "")

    # mods
    _p9_patch(_p9_sf, "mods_available", _raise_conn)
    _d = _p9_json(_A.get(_sf_url + "/mods"))
    check("mods GET: an unreachable host lists nothing rather than failing the card",
          _d == {"available": [], "installed": [], "supported": True}, repr(_d))
    _r = _F.post(_sf_url + "/mods", json={"action": "install", "mod": "sourcemod"})
    check("mods POST: a file manager without UPDATE_SERVER cannot change mods (403)",
          _r.status_code == 403)
    for _body in ({"action": "explode", "mod": "sourcemod"}, {"action": "install", "mod": "../x;rm"},
                  {"action": "install", "mod": ""}):
        _r = _A.post(_sf_url + "/mods", json=_body)
        check("mods POST: %r is refused (400) before LinuxGSM is asked" % (_body,),
              _r.status_code == 400, "got %d" % _r.status_code)
    _sf_mods = [("Installing sourcemod\n\x1b[32mOK\x1b[0m", "", 0)]
    _p9_patch(_p9_sf, "mods_action", lambda remote, user, lgsm, which, mod: _sf_mods[0])
    _p9_patch(_p9_sf, "_apply_mod_restart", lambda gs, remote: ("needed", "Restart to load it."))
    _d = _p9_json(_A.post(_sf_url + "/mods", json={"action": "install", "mod": "sourcemod"}))
    check("mods POST: a finished install says so and offers the restart it needs",
          _d == {"success": True, "message": "Mod install finished. Restart to load it.",
                 "restart_pending": True}, repr(_d))
    _sf_mods[0] = ("Removing\nERROR: mod not installed\n\n", "", 3)
    _d = _p9_json(_A.post(_sf_url + "/mods", json={"action": "remove", "mod": "sourcemod"}))
    check("mods POST: a failure quotes LinuxGSM's last line and offers no restart",
          _d == {"success": False, "message": "Mod remove reported an error: ERROR: mod not installed",
                 "restart_pending": False}, repr(_d))
    _p9_patch(_p9_sf, "mods_action", _raise_conn)
    _d = _p9_json(_A.post(_sf_url + "/mods", json={"action": "install", "mod": "sourcemod"}))
    check("mods POST: an action that raises answers success=false", _d.get("success") is False)

    # file browser: browse, read, write, delete
    _p9_patch(_p9_sf, "browse_dir", lambda remote, user, path, lgsm: None)
    _r = _A.get(_sf_url + "/browse?path=../../etc")
    check("browse: a path the browser refuses is a 400 'Invalid path'",
          _r.status_code == 400 and _p9_json(_r).get("error") == "Invalid path")
    _p9_patch(_p9_sf, "browse_dir", _raise_conn)
    _r = _A.get(_sf_url + "/browse?path=cfg")
    check("browse: a listing that raises is a 500", _r.status_code == 500)
    _p9_patch(_p9_sf, "read_file", lambda remote, user, path: ("hostname x\n", None))
    _d = _p9_json(_A.get(_sf_url + "/file?path=cfg/server.cfg"))
    check("file GET: the content comes back with the path it was read from",
          _d == {"content": "hostname x\n", "path": "cfg/server.cfg"}, repr(_d))
    _sf_write_result[0] = OSError("gone")
    _r = _A.post(_sf_url + "/file", json={"path": "cfg/server.cfg", "content": "x"})
    check("file POST: a write that raises is a 500", _r.status_code == 500)
    _sf_write_result[0] = (True, "")
    _sf_del = [(True, "Deleted")]
    def _sf_delete(remote, user, rel, lgsm):
        if isinstance(_sf_del[0], Exception):
            raise _sf_del[0]
        return _sf_del[0]

    _p9_patch(_p9_sf, "delete_path", _sf_delete)
    _d = _p9_json(_A.post(_sf_url + "/delete-path", json={"path": "cfg/old.cfg"}))
    check("delete-path: the outcome is returned and audited with the path",
          _d == {"success": True, "message": "Deleted"}
          and _p9_audit("delete_file").detail == "cfg/old.cfg", repr(_d))
    _r = _V.post(_sf_url + "/delete-path", json={"path": "cfg/old.cfg"})
    check("delete-path: a viewer cannot delete files (403)", _r.status_code == 403)
    _sf_del[0] = OSError("gone")
    _r = _A.post(_sf_url + "/delete-path", json={"path": "cfg/old.cfg"})
    check("delete-path: a delete that raises is a 500", _r.status_code == 500)

    # download
    _p9_patch(_p9_sf, "stat_path", _raise_conn)
    _r = _A.get("/server/%d/download?path=cfg/server.cfg" % P9_GS)
    check("download: a host that raises flashes that it could not be reached, back to the browser",
          _r.status_code == 302 and "/server/%d/files" % P9_GS in _r.headers.get("Location", "")
          and _p9_flashes(_A) == ["Couldn't reach p9-cs to read that file."])
    _p9_patch(_p9_sf, "stat_path",
              lambda remote, user, rel: {"rel": ".", "type": "d", "name": "csgoserver", "size": 0})
    _A.get("/server/%d/download?path=cfg/.." % P9_GS)
    check("download: a path that resolves to the home directory itself is refused, and says why",
          _p9_flashes(_A) == ["Pick a file or a folder to download, not the whole home directory."])

    # LinuxGSM's game list
    from panel.services import lgsm_data as _p9_lgsm   # noqa: E402
    _sf_cache = (dict(_p9_app._GAME_LIST_CACHE), dict(_p9_app._LGSM_NAME_MAP))
    _sf_games = [[{"shortname": "csgo"}, {"shortname": "tf2"}]]
    _p9_patch(_p9_sf, "load_game_list", lambda: list(_sf_games[0]))
    _p9_patch(_p9_lgsm, "status", lambda: {"reason": "HTTP 403 from GitHub"})
    _p9_patch(_p9_lgsm, "refresh", lambda force=True: True)
    _d = _p9_json(_A.post("/api/lgsm-data/refresh"))
    check("lgsm refresh: a fetch that worked reports the number of games loaded",
          _d == {"success": True, "games": 2, "message": "Loaded 2 games."}, repr(_d))
    _p9_patch(_p9_lgsm, "refresh", lambda force=True: False)
    _d = _p9_json(_A.post("/api/lgsm-data/refresh"))
    check("lgsm refresh: a failed fetch with a cache says it is still showing the cached list, and why",
          _d.get("success") is False and "still showing the cached list of 2 games" in _d["message"]
          and "(HTTP 403 from GitHub)" in _d["message"], repr(_d))
    _sf_games[0] = []
    _d = _p9_json(_A.post("/api/lgsm-data/refresh"))
    check("lgsm refresh: a failed fetch with nothing cached points at outbound access",
          _d.get("success") is False and "check this host's outbound access" in _d["message"],
          repr(_d))
    _p9_patch(_p9_lgsm, "refresh", _raise_conn)
    _d = _p9_json(_A.post("/api/lgsm-data/refresh"))
    check("lgsm refresh: a refresh that raises answers success=false",
          _d == {"success": False, "message": "Internal server error"}, repr(_d))
    _p9_app._GAME_LIST_CACHE.clear()
    _p9_app._GAME_LIST_CACHE.update(_sf_cache[0])
    _p9_app._LGSM_NAME_MAP.clear()
    _p9_app._LGSM_NAME_MAP.update(_sf_cache[1])

    # scheduled tasks (cron)
    _sf_sync = []
    _p9_patch(_p9_sf, "_sync_toggles_from_cron", lambda gs, jobs: _sf_sync.append(jobs))
    _p9_patch(_p9_sm, "upgrade_managed_cron_tracking", lambda *a, **k: None)
    _p9_patch(_p9_sm, "list_cron_jobs", _raise_conn)
    _r = _A.get(_sf_url + "/cron")
    check("cron GET: a listing that raises is a 500, and nothing is synced from it",
          _r.status_code == 500 and _sf_sync == [])
    # ...and one that could not be READ (list_cron_jobs answers None, which the non-raising
    # transports do) says so instead of "No scheduled tasks yet.", and syncs nothing from it —
    # Autostart would be switched off from a crontab the panel never saw. Undriven until now.
    _p9_patch(_p9_sm, "list_cron_jobs", lambda remote, user, lgsm: None)
    _d = _p9_json(_A.get(_sf_url + "/cron"))
    check("cron GET: an unreadable crontab is reported as unknown, not as empty, and syncs nothing",
          "not the same as there being none" in (_d.get("error") or "") and "jobs" not in _d
          and _sf_sync == [], repr((_d, _sf_sync)))
    _sf_jobs = [{"raw": "0 5 * * * monitor", "schedule": "0 5 * * *"}]
    _p9_patch(_p9_sm, "list_cron_jobs", lambda remote, user, lgsm: list(_sf_jobs))
    _sf_cron = [(True, "")]

    def _sf_cron_call(*a, **k):
        r = _sf_cron[0]
        if isinstance(r, Exception):
            raise r
        return r

    _p9_patch(_p9_sf, "add_cron_job", _sf_cron_call)
    _p9_patch(_p9_sf, "update_cron_job", _sf_cron_call)
    _p9_patch(_p9_sm, "delete_cron_job", _sf_cron_call)
    _p9_patch(_p9_sf, "run_cron_job_now", _sf_cron_call)
    _d = _p9_json(_A.post(_sf_url + "/cron", json={"schedule": "0 5 * * *", "command": "monitor"}))
    check("cron add: a job that was added re-syncs the Autostart toggles from the new crontab",
          _d == {"success": True, "message": "Added"} and _sf_sync == [_sf_jobs]
          and _p9_audit("cron_add").detail == "0 5 * * *", repr((_d, _sf_sync)))
    _sf_sync.clear()
    _sf_cron[0] = (False, "bad schedule")
    _d = _p9_json(_A.post(_sf_url + "/cron", json={"schedule": "nope", "command": "monitor"}))
    check("cron add: a refused job is reported with its reason and nothing is re-synced",
          _d == {"success": False, "message": "bad schedule"} and _sf_sync == [], repr(_d))
    _sf_cron[0] = (True, "")
    _d = _p9_json(_A.post(_sf_url + "/cron/update",
                          json={"raw": "0 5 * * * monitor", "schedule": "0 6 * * *"}))
    check("cron update: success is reported and audited with the new schedule",
          _d == {"success": True, "message": "Updated"}
          and _p9_audit("cron_update").detail == "0 6 * * *", repr(_d))
    _sf_cron[0] = OSError("gone")
    for _u in ("/cron", "/cron/update", "/cron/delete"):
        _r = _A.post(_sf_url + _u, json={"raw": "x", "schedule": "* * * * *", "command": "monitor"})
        check("cron %s: a crontab write that raises is a 500" % _u, _r.status_code == 500,
              "got %d" % _r.status_code)
    _d = _p9_json(_A.post(_sf_url + "/cron/run", json={"raw": "x"}))
    check("cron run: a run that raises answers success=false",
          _d == {"success": False, "message": "Internal server error"}, repr(_d))
    _r = _V.post(_sf_url + "/cron/run", json={"raw": "x"})
    check("cron run: a viewer cannot run scheduled tasks (403)", _r.status_code == 403)
    _sf_cron[0] = (True, "")

    # GMod content: status read, uninstall worker, apply worker
    _sf_gm = "/api/server/%d/gmod-content" % P9_GM
    _p9_patch(_p9_sf, "gmod_current_mounts", _raise_conn)
    _d = _p9_json(_A.get(_sf_gm))
    check("gmod content GET: a status read that raises is an error with no games to tick",
          _d.get("games") == [] and _d.get("error") == "Internal server error", repr(_d))

    _gmc = {"mounts": ["cstrike", "tf"], "cu": {"user": "gmcontent", "present": {"cstrike": 1}},
            "removed": ["cstrike"], "installed": [], "setup": []}

    def _gmc_mounts(remote, user):
        m = _gmc["mounts"]
        if isinstance(m, Exception):
            raise m
        return None if m is None else list(m)

    def _gmc_setup(remote, user, cu_user, games):
        _gmc["setup"].append((user, cu_user, list(games)))
        return True, "Mounted."

    def _gmc_ensure(remote):
        cu = _gmc["cu"]
        if isinstance(cu, Exception):
            raise cu
        return cu

    _p9_patch(_p9_sf, "gmod_current_mounts", _gmc_mounts)
    _p9_patch(_p9_sf, "gmod_mount_setup", _gmc_setup)
    _p9_patch(_p9_sf, "detect_content_user", lambda remote, games: _gmc["cu"])
    _p9_patch(_p9_sf, "ensure_content_user", _gmc_ensure)
    _p9_patch(_p9_sf, "uninstall_gmod_content",
              lambda remote, cu_user, games: (True, list(_gmc["removed"]), ""))
    _p9_patch(_p9_sf, "install_gmod_content",
              lambda remote, cu_user, games: (True, list(_gmc["installed"]), ""))
    _p9_sf._release_gmod_content_host(P9_HOST)
    _d = _p9_json(_A.post(_sf_gm, json={"action": "uninstall", "games": ["cstrike", "bogus"]}))
    _r2 = _A.post(_sf_gm, json={"action": "uninstall", "games": ["cstrike"]})
    check("gmod uninstall: accepted with only known games, and a second job on the host is refused",
          _d.get("success") is True and _d.get("games") == ["cstrike"] and _r2.status_code == 409,
          repr((_d, _r2.status_code)))
    _p9_drain()
    _st = _p9_sf._gmod_job_state(P9_GM) or {}
    check("gmod uninstall: the removed game leaves THIS server's mounts and the rest stay",
          _gmc["setup"] == [("gmodserver", "gmcontent", ["tf"])]
          and _st.get("status") == "done" and _st.get("msg") == "Removed from host: cstrike",
          repr((_gmc["setup"], _st)))
    check("gmod uninstall: the host is released once the job is published",
          _p9_sf._claim_gmod_content_host(P9_HOST) is True)
    _p9_sf._release_gmod_content_host(P9_HOST)

    _gmc["setup"].clear()
    _gmc["mounts"] = None
    _gmc["removed"] = []
    _A.post(_sf_gm, json={"action": "uninstall", "games": ["cstrike"]})
    _p9_drain()
    _st = _p9_sf._gmod_job_state(P9_GM) or {}
    check("gmod uninstall: unreadable mounts are left alone, and an unconfirmed removal is an error",
          _gmc["setup"] == [] and _st.get("status") == "error"
          and "Couldn't confirm the removal of cstrike" in _st.get("msg", ""),
          repr((_gmc["setup"], _st)))
    _gmc["mounts"] = RuntimeError("probe exploded")
    _A.post(_sf_gm, json={"action": "uninstall", "games": ["cstrike"]})
    _p9_drain()
    _st = _p9_sf._gmod_job_state(P9_GM) or {}
    check("gmod uninstall: a worker that raises publishes 'Uninstall failed' and frees the host",
          _st.get("status") == "error" and _st.get("msg", "").startswith("Uninstall failed")
          and _p9_sf._claim_gmod_content_host(P9_HOST) is True, repr(_st))
    _p9_sf._release_gmod_content_host(P9_HOST)

    # apply: no content user / nothing selected / a worker that raises
    _gmc["mounts"] = ["cstrike"]
    _gmc["cu"] = None
    _A.post(_sf_gm, json={"action": "mount", "games": ["cstrike"]})
    _p9_drain()
    _st = _p9_sf._gmod_job_state(P9_GM) or {}
    check("gmod apply: no content user could be prepared -> an error, and nothing is mounted",
          _st.get("status") == "error" and "No content storage" in _st.get("msg", "")
          and _gmc["setup"] == [], repr(_st))
    _A.post(_sf_gm, json={"action": "mount", "games": []})
    _p9_drain()
    _st = _p9_sf._gmod_job_state(P9_GM) or {}
    check("gmod apply: an empty selection unmounts everything (no content user needed)",
          _gmc["setup"] == [("gmodserver", "", [])] and _st.get("status") == "done", repr(_st))
    _gmc["cu"] = RuntimeError("useradd failed")
    _A.post(_sf_gm, json={"action": "mount", "games": ["cstrike"]})
    _p9_drain()
    _st = _p9_sf._gmod_job_state(P9_GM) or {}
    check("gmod apply: a worker that raises publishes 'Content setup failed' and frees the host",
          _st.get("status") == "error" and _st.get("msg", "").startswith("Content setup failed")
          and _p9_sf._claim_gmod_content_host(P9_HOST) is True, repr(_st))
    _p9_sf._release_gmod_content_host(P9_HOST)

    class _NoStart(_P9Thread):
        def start(self):
            raise RuntimeError("can't start new thread")

    _gmc["cu"] = {"user": "gmcontent", "present": {}}
    _p9_sf.threading = _p9_threading(_NoStart)
    try:
        _r = _A.post(_sf_gm, json={"action": "mount", "games": ["cstrike"]})
    finally:
        _p9_sf.threading = _p9_threading(_P9Thread)
    check("gmod apply: a worker that cannot start fails the request AND releases the host",
          _r.status_code == 500 and _p9_sf._claim_gmod_content_host(P9_HOST) is True,
          "got %d" % _r.status_code)
    _p9_sf._release_gmod_content_host(P9_HOST)
    _p9_sf._gmod_content_apply_state.pop(P9_GM, None)

    for _gm_action in ("uninstall", "mount"):
        with _p9.app_context():
            _h3 = RemoteServer(name="p9-host3", host="192.0.2.13", port=22, username="root",
                               auth_method="key", auth_credential="", is_online=True)
            db.session.add(_h3)
            db.session.commit()
            _h3_id = _h3.id
        _g3 = _p9_new_server(_h3_id, "gmodserver", "gmod", 27015)
        _gmc["mounts"] = ["cstrike"]
        _gmc["cu"] = {"user": "gmcontent", "present": {"cstrike": 1}}
        _r = _A.post("/api/server/%d/gmod-content" % _g3,
                     json={"action": _gm_action, "games": ["cstrike"]})
        _p9_delete_server(_g3)
        with _p9.app_context():
            db.session.delete(db.session.get(RemoteServer, _h3_id))
            db.session.commit()
        _gmc["setup"].clear()
        _p9_drain()
        _st = _p9_sf._gmod_content_apply_state.get(_g3) or {}
        check("gmod %s: a host deleted before the job ran is reported as gone, and nothing is touched"
              % _gm_action,
              _r.status_code == 200 and _st.get("status") == "error"
              and _st.get("msg") == "The host is no longer registered with the panel."
              and _gmc["setup"] == [] and _p9_sf._claim_gmod_content_host(_h3_id) is True,
              repr((_r.status_code, _st, _gmc["setup"])))
        _p9_sf._release_gmod_content_host(_h3_id)
        _p9_sf._gmod_content_apply_state.pop(_g3, None)

    # uploads
    _sf_up = [(True, "")]
    _sf_ups = []

    def _sf_upload(remote, user, reldir, name, data, overwrite=False):
        _sf_ups.append((reldir, name, data, overwrite))
        r = _sf_up[0]
        if isinstance(r, Exception):
            raise r
        return r

    _p9_patch(_p9_sf, "upload_file", _sf_upload)
    _p9_patch(_p9_sf, "_MAX_UPLOAD_BYTES", 16)
    _r = _A.post(_sf_url + "/upload", data={"path": "cfg"}, content_type="multipart/form-data")
    check("upload: no file is a 400", _r.status_code == 400
          and _p9_json(_r).get("message") == "No file provided")
    import io as _p9_io   # noqa: E402
    _r = _A.post(_sf_url + "/upload", content_type="multipart/form-data",
                 data={"path": "cfg", "file": (_p9_io.BytesIO(b"x" * 17), "big.cfg")})
    check("upload: a file over the limit is refused before anything is written",
          _r.status_code == 400 and "too large" in _p9_json(_r).get("message", "") and _sf_ups == [])
    _sf_up[0] = (False, _p9_sf.UPLOAD_EXISTS)
    _r = _A.post(_sf_url + "/upload", content_type="multipart/form-data",
                 data={"path": "cfg", "file": (_p9_io.BytesIO(b"abc"), "server.cfg")})
    check("upload: an existing file without overwrite=1 is a 409 conflict naming the file",
          _r.status_code == 409 and _p9_json(_r).get("conflict") is True
          and _p9_json(_r).get("name") == "server.cfg" and _sf_ups[-1:] and _sf_ups[-1][3] is False)
    _sf_up[0] = (True, "")
    _d = _p9_json(_A.post(_sf_url + "/upload", content_type="multipart/form-data",
                          data={"path": "cfg", "overwrite": "1",
                                "file": (_p9_io.BytesIO(b"abc"), "server.cfg")}))
    check("upload: an explicit overwrite writes the bytes and says so in the audit row",
          _d.get("success") is True and _sf_ups[-1:] == [("cfg", "server.cfg", b"abc", True)]
          and _p9_audit("upload_file").detail == "cfg/server.cfg (overwrote)", repr(_d))
    _sf_up[0] = OSError("gone")
    _r = _A.post(_sf_url + "/upload", content_type="multipart/form-data",
                 data={"path": "cfg", "file": (_p9_io.BytesIO(b"abc"), "x.cfg")})
    check("upload: a write that raises is a 500", _r.status_code == 500)
    _r = _V.post(_sf_url + "/upload", content_type="multipart/form-data",
                 data={"path": "cfg", "file": (_p9_io.BytesIO(b"abc"), "x.cfg")})
    check("upload: a viewer cannot upload (403)", _r.status_code == 403)
    _r = _V.post(_sf_url + "/upload-check", json={"path": "cfg", "names": ["a"]})
    check("upload-check: a viewer cannot probe the file tree (403)", _r.status_code == 403)
    _p9_patch(_p9_sf, "stat_upload_targets", lambda remote, user, path, names: None)
    _r = _A.post(_sf_url + "/upload-check", json={"path": "../..", "names": ["a"]})
    check("upload-check: a target directory the browser refuses is a 400",
          _r.status_code == 400 and _p9_json(_r).get("error") == "Invalid path")

    # console read and the console-command API
    _r = _F.get("/api/console/%d" % P9_GS)
    check("console: an account without VIEW_CONSOLE gets 403 and no lines",
          _r.status_code == 403 and _p9_json(_r).get("lines") == [])
    _sf_tail = []
    _p9_patch(_p9_sm, "read_as_game_user",
              lambda remote, user, sh, timeout=30, selfname=None:
              (_sf_tail.append((sh, selfname)), ("B\nE", "", 0))[1])
    _d = _p9_json(_A.get("/api/console/%d?lines=lots" % P9_GS))
    check("console: a non-numeric ?lines= falls back to the default window, not a 500",
          _d.get("readable") is True and _sf_tail and "tail -250 " in _sf_tail[-1][0], repr(_sf_tail))
    # The read names the console log, <lgsm_name>-console.log, so the script name is passed to be
    # checked (GHSA-hh39-76g3-wxcx): the builder refuses an unsafe one before anything is sent.
    with _p9.app_context():
        _sf_lgsm = db.session.get(GameServer, P9_GS).lgsm_name
    check("console: the read passes the server's LinuxGSM script name along to be checked",
          _sf_tail and _sf_tail[-1][1] == _sf_lgsm and _sf_lgsm in _sf_tail[-1][0],
          repr((_sf_tail[-1:], _sf_lgsm)))

    _sf_lt = [(False, "")]
    _p9_patch(_p9_sf, "lgsm_write_config", lambda *a, **k: _sf_lt[0])
    _r = _A.post(_sf_url + "/log-timestamps", json={"enabled": False})
    check("log timestamps: a config write that failed is a 502 saying so",
          _r.status_code == 502 and _p9_json(_r).get("error") == "Could not write the LinuxGSM config")
    _p9_patch(_p9_sf, "lgsm_get_values", lambda *a, **k: {"logtimestamp": '"on"'})
    eq("log timestamps: GET reads the (quoted) LinuxGSM value",
       _p9_json(_A.get(_sf_url + "/log-timestamps")), {"enabled": True})
    _p9_patch(_p9_sf, "lgsm_get_values", _raise_conn)
    _r = _A.get(_sf_url + "/log-timestamps")
    check("log timestamps: a read that raises is a 500", _r.status_code == 500)

    _r = _A.post("/api/command/%d" % P9_GS, json={"command": "  "})
    check("console command API: an empty command is a 400", _r.status_code == 400)
    _sd_send[0] = ("", "", 0)
    _sd_sent.clear()
    _p9_patch(_p9_sf, "send_console_command", _send)
    _d = _p9_json(_A.post("/api/command/%d" % P9_GS, json={"command": "status"}))
    check("console command API: a sent command is echoed back and audited",
          _d == {"success": True, "command": "status"} and _sd_sent == ["status"]
          and _p9_audit("send_command").success is True, repr(_d))
    _sd_send[0] = ("", "no server running", 1)
    _r = _A.post("/api/command/%d" % P9_GS, json={"command": "status"})
    check("console command API: a failed send is a 502 and audited as failed",
          _r.status_code == 502 and _p9_audit("send_command").success is False)
    _sd_send[0] = ValueError("not a transport problem")
    _r = _A.post("/api/command/%d" % P9_GS, json={"command": "status"})
    check("console command API: an error that is NOT a lost host stays a 500 (it is ours)",
          _r.status_code == 500 and "unreachable" not in _p9_json(_r))

    # ── module-level console helpers ────────────────────────────────────────────────────────────
    import ipaddress as _p9_ipa   # noqa: E402
    eq("evict: a console nobody watches drops nobody",
       _p9_sf._evict_unauthorized_viewers(_p9, _p9.socketio, 90020), 0)

    def _ev_emit_raises(*a, **k):
        raise RuntimeError("socket closed")

    _ev_left = []
    _p9_patch(_p9.socketio.server, "leave_room",
              lambda sid, room, namespace=None: _ev_left.append((sid, room)))
    with _p9_sf._viewers_lock:
        _p9_sf._console_viewers[P9_OTHER] = {"sid-p9-v": P9_VIEWER}   # no access to host 2
    _p9_patch(_p9.socketio, "emit", _ev_emit_raises)
    with _p9.app_context():
        _ev_n = _p9_sf._evict_unauthorized_viewers(_p9, _p9.socketio, P9_OTHER)
    _p9_patch(_p9.socketio, "emit", lambda event, data=None, **k: _P9_EMITS.append((event, data, k)))
    check("evict: a viewer without access is dropped even when telling them fails",
          _ev_n == 1 and P9_OTHER not in _p9_sf._console_viewers, repr(_ev_n))
    # The ROOM is what delivers the stream; the viewer map only decides whether the host is polled.
    # Leaving the room and sending the "revoked" notice were one try block with the notice first, so
    # a notice that raised skipped the leave: the revoked socket stayed in console_<id> and went on
    # receiving whatever another viewer's poll pushed. The fix leaves the room first, on its own.
    check("evict: a revoked viewer leaves the console ROOM even when the revoked notice fails",
          _ev_left == [("sid-p9-v", "console_%d" % P9_OTHER)], repr(_ev_left))
    # ...and the other way round: a leave that raises still sends the notice, to the socket itself.
    _p9_patch(_p9.socketio.server, "leave_room", _ev_emit_raises)
    _P9_EMITS.clear()
    with _p9_sf._viewers_lock:
        _p9_sf._console_viewers[P9_OTHER] = {"sid-p9-v2": P9_VIEWER}
    with _p9.app_context():
        _ev_n = _p9_sf._evict_unauthorized_viewers(_p9, _p9.socketio, P9_OTHER)
    check("evict: a leave that raises still drops the viewer and tells that socket it was revoked",
          _ev_n == 1 and P9_OTHER not in _p9_sf._console_viewers
          and [(e[1] or {}).get("data") for e in _P9_EMITS if e[2].get("to") == "sid-p9-v2"]
          == ["[access to this console was revoked]"], repr(_P9_EMITS))
    _p9_patch(_p9.socketio.server, "leave_room", _P9_PATCHED[(_p9.socketio.server, "leave_room")])
    # ...and reaching the server is not enough: the socket must still hold VIEW_CONSOLE. The file
    # manager can reach host 1 but may not read its consoles, so a join that outlived the
    # permission is evicted just like one that lost the host — while the viewer beside it, who
    # holds VIEW_CONSOLE there, keeps watching. Nothing else drove the permission half of
    # _viewer_still_allowed: deleting it passed both the unit and the smoke suite.
    with _p9_sf._viewers_lock:
        _p9_sf._console_viewers[P9_GS] = {"sid-p9-files": P9_FILES, "sid-p9-view": P9_VIEWER}
    with _p9.app_context():
        _ev_n = _p9_sf._evict_unauthorized_viewers(_p9, _p9.socketio, P9_GS)
    with _p9_sf._viewers_lock:
        _ev_kept = dict(_p9_sf._console_viewers.pop(P9_GS, None) or {})
    check("evict: a viewer who reaches the server but no longer holds VIEW_CONSOLE is dropped",
          _ev_n == 1 and _ev_kept == {"sid-p9-view": P9_VIEWER}, repr((_ev_n, _ev_kept)))

    _p9_patch(_p9_banlist, "active", lambda: True)
    _p9_patch(_p9_banlist, "is_banned", lambda ip, widen=True: str(ip) == "198.51.100.66")
    _p9_patch(_p9.socketio.server, "disconnect", _ev_emit_raises)
    with _p9_sf._viewers_lock:
        _p9_sf._socket_addrs["sid-p9-banned"] = (_p9_ipa.ip_address("198.51.100.66"), None)
        _p9_sf._socket_addrs["sid-p9-fine"] = (_p9_ipa.ip_address("198.51.100.67"), None)
    eq("ban sweep: only the banned socket is dropped, even when the disconnect itself fails",
       _p9_sf._drop_banned_sockets(_p9, _p9.socketio), 1)
    with _p9_sf._viewers_lock:
        _p9_sf._socket_addrs.pop("sid-p9-banned", None)
        _p9_sf._socket_addrs.pop("sid-p9-fine", None)
    for _n in ("active", "is_banned"):
        _p9_patch(_p9_banlist, _n, _P9_PATCHED[(_p9_banlist, _n)])

    # ── the console socket handlers, through flask-socketio's test client ───────────────────────
    # Only the panel's own disconnect hooks run here: an earlier part deliberately registers one that
    # raises (to prove the next still runs) and leaves it behind, and it would print a traceback.
    from panel.ops import socket_hooks as _p9_hooks   # noqa: E402
    _p9_hooks_saved = dict(_p9_hooks._hooks)
    _p9_hooks._hooks.clear()
    _p9_hooks._hooks.update({k: f for k, f in _p9_hooks_saved.items()
                             if getattr(f, "__module__", "").startswith("panel.")})
    _sio_anon = _p9.socketio.test_client(_p9, flask_test_client=_p9.test_client())
    check("socket: an anonymous handshake is refused", not _sio_anon.is_connected())
    _sio_v = _p9.socketio.test_client(_p9, flask_test_client=_V)
    check("socket: a signed-in viewer's handshake is accepted", _sio_v.is_connected())
    _sio_v.emit("join_console", {"server_id": "not-a-number"})
    _sio_v.emit("join_console", {"server_id": 0})
    _sio_v.emit("join_console", {"server_id": P9_GS})
    with _p9_sf._viewers_lock:
        _sio_watch = {k: dict(v) for k, v in _p9_sf._console_viewers.items()}
    check("socket join: a malformed or non-positive id joins nothing; a real one registers the viewer",
          list(_sio_watch) == [P9_GS] and list(_sio_watch[P9_GS].values()) == [P9_VIEWER],
          repr(_sio_watch))
    _sio_v.emit("leave_console", {"server_id": None})
    with _p9_sf._viewers_lock:
        check("socket leave: a malformed id leaves the registration alone",
              P9_GS in _p9_sf._console_viewers)
    _sio_v.disconnect()
    with _p9_sf._viewers_lock:
        check("socket disconnect: a socket that closed without leaving stops the poller for it",
              P9_GS not in _p9_sf._console_viewers and not _p9_sf._viewer_creds,
              repr((_p9_sf._console_viewers, _p9_sf._viewer_creds)))
    _p9_hooks._hooks.clear()
    _p9_hooks._hooks.update(_p9_hooks_saved)

    _p9_drain()     # page renders queue background timezone reads; run them under the stubs
    # ── one pass of the console poller, taken out of its supervisor ─────────────────────────────
    _cp_poller = None
    for _sup in _p9_supervised:
        for _cell in (getattr(_sup, "__closure__", None) or ()):
            try:
                if getattr(_cell.cell_contents, "__name__", "") == "console_poller":
                    _cp_poller = _cell.cell_contents
            except ValueError:  # nosec B110 - an empty cell is not the poller
                pass
    check("console poller: register_routes handed it to the supervisor (so a pass can be driven)",
          _cp_poller is not None, repr([getattr(s, "__qualname__", s) for s in _p9_supervised]))

    class _P9StopLoop(Exception):
        pass

    def _cp_stop(_s):
        raise _P9StopLoop()

    def _cp_one_pass():
        _p9_sf.time = NS(time=_p9_real_time.time, sleep=_cp_stop, monotonic=_p9_real_time.monotonic)
        try:
            _cp_poller()
        except _P9StopLoop:
            return True
        finally:
            _p9_sf.time = _p9_fake_time
        return False

    if _cp_poller is not None:
        _cp_drained = []

        def _cp_drain_raises(app, remote, sid):
            _cp_drained.append(sid)
            raise ConnectionError("tail failed")

        _p9_patch(_p9_sf, "_drain_action_output", _cp_drain_raises)
        _P9_EMITS.clear()
        with _p9_sf._viewers_lock:
            _p9_sf._console_viewers.clear()
            _p9_sf._console_viewers.update({99930: {"sid-gone": P9_ADMIN},
                                            P9_OTHER: {"sid-noaccess": P9_VIEWER},
                                            P9_GS: {"sid-ok": P9_ADMIN}})
        _cp_ok = _cp_one_pass()
        with _p9_sf._viewers_lock:
            _cp_left = {k: dict(v) for k, v in _p9_sf._console_viewers.items()}
        check("console poller: one pass skips a deleted server, evicts a viewer who lost access, and "
              "reads only the console someone may still watch",
              _cp_ok and _cp_drained == [P9_GS] and P9_OTHER not in _cp_left
              and any((e[1] or {}).get("data") == "[access to this console was revoked]"
                      for e in _P9_EMITS), repr((_cp_drained, _cp_left)))
        check("console poller: one console whose read raises does not end the pass",
              _cp_ok and P9_GS in _cp_left)

        def _cp_forget_raises(ids):
            raise RuntimeError("state corrupt")

        _p9_patch(_p9_sf, "_forget_unwatched_consoles", _cp_forget_raises)
        _cp_drained.clear()
        check("console poller: a pass that raises is contained, and the loop carries on to its sleep",
              _cp_one_pass() and _cp_drained == [])
        with _p9_sf._viewers_lock:
            _p9_sf._console_viewers.clear()

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # panel/routes/manage_servers.py — the install job, retry and uninstall
    # ════════════════════════════════════════════════════════════════════════════════════════════
    # A scripted host. Every knob is a list read front to back (the last value repeats), so a flow
    # can say "the first auto-install reports missing packages, the second works". A value that is
    # an Exception is raised. `boom` names steps that raise.
    import ast as _p9_ast           # noqa: E402
    import inspect as _p9_inspect   # noqa: E402
    import re as _p9_re             # noqa: E402
    import shlex as _p9_shlex       # noqa: E402
    _ms = {}
    _ms_log = []

    def _ms_reset(**kw):
        _ms.clear()
        _ms.update(acct={}, lgsm=[("LinuxGSM ready", "", 0)], auto=[("installed", "", 0)],
                   looks=[True], classify=[None], missing=[[]], deps=[(True, "")],
                   detect=[{"game_port": None, "open_ports": []}], listen=[set()],
                   listen_pre=[set()], tagged=[set()],
                   start=[("Starting", "", 0)], cmds=[[]], unset=[(True, "")],
                   cu=[{"user": "gmcontent"}], mount=[(True, "Mounted.")], aux=[{}],
                   userdel=[("", "", 0)], boom=set())
        _ms.update(kw)
        _ms_log.clear()

    def _ms_next(key):
        seq = _ms[key]
        v = seq.pop(0) if len(seq) > 1 else seq[0]
        if isinstance(v, Exception):
            raise v
        return v

    def _ms_boom(step):
        if step in _ms["boom"]:
            raise ConnectionError("%s failed on the host" % step)

    def _ms_run_command(remote, cmd, timeout=30, sudo=None, stdin_text=None):
        """Answer the install job's shell commands from the scripted plan, logging each step."""
        if cmd.startswith("id ") and "echo EXISTS" in cmd:
            st = _ms["acct"].get(_p9_shlex.split(cmd)[1], "NOTEXISTS")
            return ("", "timed out", -1) if st is None else (st, "", 0)
        if "LGSM_ACCT_PROBE_DONE" in cmd:
            # The uninstall's "is this account root on the host?" probe (privileged_accounts):
            # every scripted account is a plain game account, in its own group only. Not logged —
            # it is a read, and the step lists below are what these checks compare.
            _users = _p9_re.findall(r'echo "NOACCT ([a-z0-9_-]+)"', cmd)
            return ("".join("ACCT %s 1001 %s\n" % (u, u) for u in _users)
                    + "LGSM_ACCT_PROBE_DONE\n", "", 0)
        if "wget" in cmd and "linuxgsm.sh" in cmd:
            _ms_log.append("lgsm")
            return _ms_next("lgsm")
        if "auto-install" in cmd:
            _ms_log.append("auto:%d" % timeout)
            return _ms_next("auto")
        return _ms_side_step(cmd)

    def _ms_side_step(cmd):
        """Log (and maybe fail) the best-effort step `cmd` is, or log it as unrecognised."""
        for tok, step in (("lgsm/tmp", "wipe"), ("eula.txt", "mc-eula"), ("python3 -c", "scpsl-eula"),
                          ("config_localadmin", "scpsl-seed")):
            if tok in cmd:
                _ms_log.append(step)
                _ms_boom(step)
                return "", "", 0
        _ms_log.append("?" + cmd[:40])
        return "", "", 0

    def _ms_run_priv(remote, verb, args=(), timeout=30, merge_stderr=True, sudo=True):
        _ms_log.append(verb)
        _ms_boom(verb)
        if verb == "user-delete-force":
            return _ms_next("userdel")
        return "", "", 0

    def _ms_run_as(remote, user, action, **k):
        _ms_log.append("as:" + action)
        _ms_boom(action)
        return _ms_next("start") if action == "start" else ("", "", 0)

    def _ms_write_cfg(remote, user, lgsm, settings):
        _ms_log.append("cfg:" + ",".join("%s=%s" % kv for kv in sorted(settings.items())))
        if "port" in settings:
            _ms_boom("port-write")
        if settings.get("steamcmdforcewindows") == "no":
            return _ms_next("unset")
        return True, ""

    def _ms_install_content(remote, cu_user, games, on_progress=None):
        _ms_log.append("gmod-content:" + ",".join(games))
        if on_progress:
            on_progress("Downloading content")
        return True, list(games), ""

    def _ms_ensure_cu(remote):
        _ms_boom("gmod")
        return _ms_next("cu")

    _p9_patch(_p9_sm, "run_command", _ms_run_command)
    _p9_patch(_p9_sm, "run_privileged", _ms_run_priv)
    _p9_patch(_p9_sm, "run_as_game_user", _ms_run_as)
    _p9_patch(_p9_sm, "create_game_user",
              lambda remote, user, timeout=30: (_ms_log.append("useradd"), _ms_boom("useradd"),
                                                ("", "", 0))[2])
    _p9_patch(_p9_sm, "read_as_game_user",
              lambda remote, user, sh, timeout=30, selfname=None: ("EXISTS", "", 0))
    _p9_patch(_p9_sm, "list_server_commands", lambda r, s, l: (_ms_boom("cmds"), _ms_next("cmds"))[1])
    _p9_patch(_p9_sm, "_invalidate_port_scan", lambda rid: None)
    _p9_patch(_p9_sm, "host_os_slug", _raise_conn)
    _p9_patch(_p9_ms, "install_game_dependencies",
              lambda remote, gt, extra=None, account=None, selfname=None: (
                  _ms_log.append("deps:%s" % (extra or "")),
                  account is not None and _ms_log.append("deps-for:%s/%s" % (account, selfname)),
                  _ms_next("deps"))[2])
    _p9_patch(_p9_ms, "parse_missing_deps", lambda out: _ms_next("missing"))
    _p9_patch(_p9_ms, "classify_install_failure", lambda out: _ms_next("classify"))
    _p9_patch(_p9_ms, "_looks_installed", lambda app, r, s, l: _ms_next("looks"))
    _p9_patch(_p9_ms, "lgsm_write_config", _ms_write_cfg)
    _p9_patch(_p9_ms, "_resolve_source_aux_ports",
              lambda *a: (_ms_boom("aux"), _ms_next("aux"))[1])
    _p9_patch(_p9_ms, "install_game_cron",
              lambda r, s, l, supported: (_ms_log.append("cron"), _ms_boom("cron"))[0])
    _p9_patch(_p9_ms, "ensure_persistent_bans",
              lambda r, s, l: (_ms_log.append("bans"), _ms_boom("bans"))[0])
    _p9_patch(_p9_ms, "detect_game_ports",
              lambda r, s, l: (_ms_boom("detect"), _ms_next("detect"))[1])
    # `listen` answers once the server has been started, `listen_pre` before: nothing of the new
    # server's is listening until its first start, and step 6 scans right before it opens ports.
    _p9_patch(_p9_ms, "_remote_listening_ports",
              lambda r: _ms_next("listen" if "as:start" in _ms_log else "listen_pre"))
    _p9_patch(_p9_sm, "protected_host_ports", lambda r: {22})
    _p9_patch(_p9_sm, "remote_ufw_tagged_ports", lambda r, n: _ms_next("tagged"))
    _ms_legacy_fw = [(0, "", [])]     # what the legacy (untagged) cleanup answers
    _p9_patch(_p9_ms, "remote_ufw_close_game_port",
              lambda r, p, name="", legacy=False, ports=(): (
                  _ms_log.append("ufw-close:%s:%s:%s" % (p, name, legacy)), _ms_boom("ufw-close"),
                  _ms_legacy_fw[0])[2])
    _p9_patch(_p9_ms, "remote_ufw_allow_game_ports",
              lambda r, ports, name: _ms_log.append("ufw-allow:%s" % sorted(ports)))
    _p9_patch(_p9_ms, "set_autostart",
              lambda r, s, on, l=None: (_ms_log.append("autostart"), _ms_boom("autostart"))[0])
    _p9_patch(_p9_ms, "ensure_content_user", _ms_ensure_cu)
    _p9_patch(_p9_ms, "install_gmod_content", _ms_install_content)
    _p9_patch(_p9_ms, "gmod_mount_setup", lambda r, s, cu, games: _ms_next("mount"))
    _p9_patch(_p9_ms, "load_game_list",
              lambda: [{"shortname": g, "legacy_os": ""} for g in
                       ("csgo", "gmod", "mc", "scpsl", "rust")])
    _ms_free = [(27150, False)]
    _p9_patch(_p9_ms, "resolve_free_port", lambda r, rid, want, gt: _ms_next_free())

    def _ms_next_free():
        v = _ms_free.pop(0) if len(_ms_free) > 1 else _ms_free[0]
        return v

    def _ms_install(game, name="", port="", content=None):
        data = {"remote_id": str(P9_HOST), "game_type": game, "server_name": name, "port": port}
        if content:
            data["content_games"] = content
        r = _A.post("/servers/add", data=data, headers=_XHR)
        with _p9.app_context():
            want = name or (game + "server")
            gs = (GameServer.query.filter_by(remote_id=P9_HOST)
                  .order_by(GameServer.id.desc()).first())
            sid = gs.id if gs is not None and gs.short_name.startswith(want) else None
        return r, sid

    def _ms_job(sid):
        with _p9_state._install_lock:
            return dict(_p9_state._install_jobs.get(sid) or {})

    # ── the install route's refusals ────────────────────────────────────────────────────────────
    _ms_reset()
    for _body, _want in ((dict(game_type="doom"), "Invalid or unknown game type."),
                         (dict(game_type="csgo", server_name="Bad Name!"), "Server name must be"),
                         (dict(game_type="csgo", server_name="csgoserver"),
                          "already exists on this remote")):
        _data = dict({"remote_id": str(P9_HOST), "port": "", "server_name": ""}, **_body)
        _r = _A.post("/servers/add", data=_data, headers=_XHR)
        check("install refused: %r -> 400 %r" % (_body, _want),
              _r.status_code == 400 and _want in _p9_json(_r).get("message", ""),
              repr((_r.status_code, _p9_json(_r))))
    _ms_free[:] = [(None, False)]
    _r = _A.post("/servers/add", data=dict(remote_id=str(P9_HOST), game_type="csgo", port="27500",
                                           server_name="p9free"), headers=_XHR)
    check("install refused: no free port near the request says so instead of guessing one",
          _r.status_code == 400 and "No free port near 27500" in _p9_json(_r).get("message", ""))

    # A typed name in capitals is folded to lowercase, not refused. It becomes a Linux account, and
    # INSTANCE_NAME_RE only admits lowercase, so the fold has to happen before the name is judged.
    # Nothing held it: the fold moved when install_game_server was split, and deleting it left every
    # suite green while "P9Upper" became a refusal.
    _ms_free[:] = [(27186, False)]
    _ms_reset(lgsm=[("", "fail", 1)])
    _r = _A.post("/servers/add", data=dict(remote_id=str(P9_HOST), game_type="csgo", port="27186",
                                           server_name="P9Upper"), headers=_XHR)
    _p9_drain()
    with _p9.app_context():
        _ms_up = GameServer.query.filter_by(remote_id=P9_HOST, short_name="p9upper").first()
        _ms_up = (_ms_up.id, _ms_up.name) if _ms_up is not None else None
    check("install: a typed name in capitals is folded to lowercase, not refused",
          _p9_json(_r).get("success") is True and _ms_up is not None and _ms_up[1] == "p9upper",
          repr((_r.status_code, _p9_json(_r), _ms_up)))
    if _ms_up is not None:
        _p9_delete_server(_ms_up[0])

    # A blank name whose default is taken in the TABLE and then on the HOST skips past both.
    _ms_free[:] = [(28015, False)]
    _ms_taken = [_p9_new_server(P9_HOST, "rustserver", "rust", 28100),
                 _p9_new_server(P9_HOST, "rustserver2", "rust", 28101),
                 _p9_new_server(P9_HOST, "rustserver4", "rust", 28102)]
    _ms_reset(acct={"rustserver3": "EXISTS"}, lgsm=[("", "fail", 1)])
    _r, _ms_sid = _ms_install("rust")
    _p9_drain()
    check("install: a default name taken in the panel AND as a host account moves on to a free one",
          _p9_json(_r).get("success") is True
          and "the default name was taken — using 'rustserver5'" in _p9_json(_r).get("message", "")
          and _p9_row(_ms_sid).short_name == "rustserver5", repr(_p9_json(_r)))
    check("install: a LinuxGSM setup that exits non-zero fails the ROW, with the tool's words",
          _p9_row(_ms_sid).status == "failed"
          and _p9_row(_ms_sid).install_error == "LinuxGSM setup failed: fail", repr(_p9_row(_ms_sid)))
    _p9_delete_server(_ms_sid)
    for _n in _ms_taken:
        _p9_delete_server(_n)

    # ── Flow A: gmod with content, through every recoverable trouble the job knows about ─────────
    _ms_free[:] = [(27150, False)]
    _ms_reset(lgsm=[("useradd: unknown user p9gmod", "", 1), ("LinuxGSM ready", "", 0)],
              deps=[(False, "apt locked"), (False, "still locked"), RuntimeError("apt died"),
                    (True, "")],
              auto=[("missing deps", "", 1), ("still missing", "", 1), ("after deps", "", 1),
                    ("Invalid platform", "", 1), ("windows depot pulled", "", 0), ("done", "", 0)],
              missing=[["lib32gcc-s1"], ["libsdl2"], []],
              looks=[False, False, True],
              classify=[None, ("steam_platform", "SteamCMD refused this platform.")],
              unset=[(False, "write refused")],
              aux=[{"clientport": 27106}],
              cmds=[[{"cmd": "monitor", "desc": "Monitor"}]],
              detect=[{"game_port": 27160, "open_ports": [27160, 27161]}, ConnectionError("gone")],
              listen=[OSError("ss failed")],
              mount=[(False, "couldn't read the content group")],
              boom={"steam-dumps-sweep", "wipe", "validate", "port-write", "cron", "bans",
                    "ufw-close", "autostart", "start"})
    _r, _ms_a = _ms_install("gmod", "p9gmod", "27150", content=["cstrike", "notagame"])
    check("install flow A: accepted with a message pointing at the progress corner",
          _p9_json(_r).get("success") is True and _ms_a is not None
          and _p9_row(_ms_a).content_games == "cstrike"
          and _ms_job(_ms_a).get("total") == 9, repr((_p9_json(_r), _ms_job(_ms_a))))
    _p9_drain()
    _ja = _ms_job(_ms_a)
    _ra = _p9_row(_ms_a)
    check("install flow A: an account sudo cannot resolve yet is retried, not failed",
          _ms_log.count("lgsm") == 2, repr(_ms_log))
    check("install flow A: missing packages reported by LinuxGSM are installed and the download re-run",
          "deps:lib32gcc-s1" in _ms_log and "deps:libsdl2" in _ms_log
          and _ms_log.count("auto:1800") == 4, repr(_ms_log))
    # The retry names the account and its script: a name the panel's weekly copy of LinuxGSM's
    # list refuses is looked up again at the release THAT script runs, which is the list its
    # check_deps read. Without them the lookup cannot happen and the refusal stands.
    check("install flow A: each retry names the game account and its LinuxGSM script",
          _ms_log.count("deps-for:p9gmod/gmodserver") == 2
          and all(x == "deps-for:p9gmod/gmodserver" for x in _ms_log if x.startswith("deps-for:")),
          repr([x for x in _ms_log if x.startswith("deps")]))
    check("install flow A: 'Invalid platform' primes with the Windows depot, then UNSETS the key "
          "(tried twice) whatever happened",
          "cfg:steamcmdforcewindows=yes" in _ms_log and "auto:2700" in _ms_log
          and _ms_log.count("cfg:steamcmdforcewindows=no") == 2
          and _ms_log.index("cfg:steamcmdforcewindows=no") > _ms_log.index("auto:2700"), repr(_ms_log))
    check("install flow A: the step log shows the workaround and the Linux binary fetch",
          any("Working around a SteamCMD bug" in ln for ln in _ja.get("log", []))
          and any("Fetching the Linux server binaries" in ln for ln in _ja.get("log", [])),
          repr(_ja.get("log")))
    check("install flow A: the Source aux ports are written, the reported port adopted and opened",
          "cfg:clientport=27106" in _ms_log and _ra.port == 27160
          and "ufw-allow:[27160, 27161]" in _ms_log, repr(_ms_log))
    # Aikido 745379215: the adoption step ran the untagged sweep on the port it left — which, on a
    # fresh install, can hold no rule of this server's (the ports are opened after it) — and took
    # whatever ALLOW was there. It closes only rules tagged with THIS server's name now.
    check("install flow A: leaving the allocated port closes only rules tagged with this server's "
          "name there — no untagged sweep",
          "ufw-close:27150:p9gmod:False" in _ms_log
          and not any(e.startswith("ufw-close:") and e.endswith(":True") for e in _ms_log),
          repr([e for e in _ms_log if e.startswith("ufw-close")]))
    check("install flow A: GMod content is installed for the selected game only, with progress",
          "gmod-content:cstrike" in _ms_log
          and any("Downloading content" in ln for ln in _ja.get("log", [])), repr(_ms_log))
    check("install flow A: a start that raised and a port scan that raised end 'didn't start', "
          "with the files kept (installed, offline)",
          _ja.get("status") == "done" and _ja.get("warn") is True
          and _ja.get("message")
          == "p9gmod installed, but it didn't start — check the console for the reason."
          and _ra.installed is True and _ra.status == "offline", repr((_ja, _ra.status)))
    check("install flow A: the audit row says the start failed",
          _p9_audit("install_complete").success is False
          and _p9_audit("install_complete").detail == "start failed")

    # ── Flow F: minecraft that starts but has not opened its port yet ───────────────────────────
    _ms_free[:] = [(25600, False)]
    _ms_reset(detect=[ConnectionError("details timed out")], listen=[{1}],
              boom={"mc-eula", "cmds"})
    _r, _ms_f = _ms_install("mc", "p9mc", "25600")
    _p9_drain()
    _jf = _ms_job(_ms_f)
    check("install flow F: a failed EULA write, command read and port detect are all non-fatal",
          "mc-eula" in _ms_log and _jf.get("status") == "done", repr((_ms_log, _jf)))
    check("install flow F: a clean start whose port is not open yet is 'starting', not a failure",
          _jf.get("warn") is True
          and "installed and starting — it hasn't opened port 25600" in _jf.get("message", "")
          and _p9_audit("install_complete").detail == "started; port 25600 not open after 90s",
          repr(_jf))

    # ── Flow G: SCP:SL — its EULA and per-port config are seeded; failures there are non-fatal ──
    _ms_free[:] = [(7777, False)]
    _ms_reset(listen=[{7777}], boom={"scpsl-eula", "scpsl-seed", "aux"})
    _r, _ms_g = _ms_install("scpsl", "p9scp", "7777")
    _p9_drain()
    _jg = _ms_job(_ms_g)
    check("install flow G: SCP:SL gets its EULA and its per-port config seeded, and still starts",
          "scpsl-eula" in _ms_log and "scpsl-seed" in _ms_log
          and _jg.get("message") == "p9scp installed and started", repr((_ms_log, _jg)))

    # ── Flows H/I: GMod content with no content user / content setup raising ────────────────────
    for _lbl, _knobs in (("no content user could be prepared", dict(cu=[None])),
                         ("content setup raised", dict(boom={"gmod"}))):
        _ms_free[:] = [(27170, False)]
        _ms_reset(listen=[{27170}], **_knobs)
        _r, _ms_h = _ms_install("gmod", "p9gm" + ("h" if "no" in _lbl else "i"), "27170",
                                content=["cstrike"])
        _p9_drain()
        check("install: %s -> the install still completes and starts (content is best-effort)" % _lbl,
              _ms_job(_ms_h).get("status") == "done" and "gmod-content:cstrike" not in _ms_log
              and _p9_row(_ms_h).status == "online", repr((_ms_job(_ms_h), _ms_log)))
        _p9_delete_server(_ms_h)

    # ── step 6 opens only ports that are this server's to open (Aikido 745379031, 745379277) ────
    # The port was checked free when the install was asked for, twenty minutes of SteamCMD before
    # step 6 opens it, and when the game reports that same port nothing looked again.
    _ms_free[:] = [(27192, False)]
    _ms_reset(listen_pre=[{22, 27192}])
    _r, _ms_t = _ms_install("csgo", "p9race", "27192")
    _p9_drain()
    check("install: a port something else took while the files downloaded is not opened for it",
          "ufw-allow:[]" in _ms_log and "ufw-allow:[27192]" not in _ms_log, repr(_ms_log))
    check("install: ...and the install says so, rather than 'installed and started'",
          "port 27192 is already used by another process on this host"
          in _ms_job(_ms_t).get("message", ""), repr(_ms_job(_ms_t)))
    _p9_delete_server(_ms_t)
    _ms_free[:] = [(27193, False)]
    _ms_reset(listen_pre=[None])
    _r, _ms_t = _ms_install("csgo", "p9noscan", "27193")
    _p9_drain()
    check("install: ...while a scan that cannot be read still opens the port the allocation "
          "verified (positive control — a busy host must not leave a new server closed)",
          "ufw-allow:[27193]" in _ms_log, repr(_ms_log))
    _p9_delete_server(_ms_t)
    # A retry of an install whose server an earlier attempt started — a panel restart mid-install
    # fails the row — finds that server listening on its own port. A rule tagged with this
    # server's name already opens it; that is not "another process".
    _ms_free[:] = [(27199, False)]
    _ms_reset(listen_pre=[{27199}], tagged=[{27199}], listen=[{27199}])
    _r, _ms_t = _ms_install("csgo", "p9again", "27199")
    _p9_drain()
    check("install: a port already open under this server's OWN tag is not held back as someone "
          "else's — no false 'another process' warning",
          "ufw-allow:[27199]" in _ms_log
          and _ms_job(_ms_t).get("message") == "p9again installed and started",
          repr((_ms_log, _ms_job(_ms_t).get("message"))))
    _p9_delete_server(_ms_t)
    # `details` is run as the game account, over a config that account can write. Only the GAME
    # port went through any check; "Query <another server's port>" was opened under this server's
    # name — re-tagging that server's rule, which this one's uninstall then deleted.
    _ms_sib = _p9_new_server(P9_HOST, "p9sib", "rust", 27197)
    _ms_free[:] = [(27194, False)]
    _ms_reset(detect=[{"game_port": 27194, "open_ports": [22, 27194, 27198]}])
    _r, _ms_t = _ms_install("csgo", "p9query", "27194")
    _p9_drain()
    # Two refused ports, not one: the first becomes the conflict the install reports, and the
    # post-start re-read already skips that one — the second is what only the withheld set stops.
    _ms_opened = [_p9_ast.literal_eval(e.split(":", 1)[1]) for e in _ms_log
                  if e.startswith("ufw-allow:")]
    check("install: a reported port inside ANOTHER server's block, or SSH's, is not opened — at "
          "step 6, nor by the re-read after the first start",
          len(_ms_opened) == 2 and all(a == [27194] for a in _ms_opened), repr(_ms_log))
    _p9_delete_server(_ms_t)
    _p9_delete_server(_ms_sib)
    _ms_free[:] = [(27195, False)]
    _ms_reset(detect=[{"game_port": 22, "open_ports": [22]}])
    _r, _ms_t = _ms_install("csgo", "p9ssh", "27195")
    _p9_drain()
    check("install: a reported game port of 22 is not adopted — the row keeps its port, and SSH "
          "is not opened under the server's name",
          _p9_row(_ms_t).port == 27195 and "ufw-allow:[27195]" in _ms_log
          and not any(22 in _p9_ast.literal_eval(e.split(":", 1)[1])
                      for e in _ms_log if e.startswith("ufw-allow:")),
          repr((_p9_row(_ms_t).port, _ms_log)))
    _p9_delete_server(_ms_t)

    # ── a failure a retry cannot fix, and the Windows-prime whose reset works first time ─────────
    _ms_free[:] = [(27190, False)]
    _ms_reset(looks=[False], auto=[("Invalid platform", "", 1)],
              classify=[("steam_platform", "SteamCMD refused this platform."),
                        ("os_unsupported", "LinuxGSM does not support this game on this release.")])
    _r, _ms_c = _ms_install("csgo", "p9final", "27190")
    _p9_drain()
    _rc = _p9_row(_ms_c)
    check("install: the Windows-prime reset that works first time is written once, not twice",
          _ms_log.count("cfg:steamcmdforcewindows=no") == 1, repr(_ms_log))
    check("install: a failure LinuxGSM will never fix stops at once and offers Remove, not Retry",
          _ms_log.count("auto:1800") == 2 and _rc.status == "failed"
          and _rc.install_retryable is False
          and _rc.install_error == "LinuxGSM does not support this game on this release.",
          repr((_ms_log, _rc.install_error, _rc.install_retryable)))
    _p9_delete_server(_ms_c)

    _ms_free[:] = [(27191, False)]
    _ms_reset(lgsm=[("", "no route to host", 1)])
    _r, _ms_p = _ms_install("csgo", "p9nojob", "27191")
    with _p9_state._install_lock:
        _p9_state._install_jobs.pop(_ms_p, None)
    _p9_drain()
    check("install: a job pruned from the registry mid-run still records its failure on the row",
          _p9_row(_ms_p).status == "failed" and _ms_job(_ms_p) == {}
          and _p9_row(_ms_p).install_error == "LinuxGSM setup failed: no route to host",
          repr(_p9_row(_ms_p)))
    _p9_delete_server(_ms_p)

    # ── failures before the files land ─────────────────────────────────────────────────────────
    _ms_free[:] = [(27180, False)]
    _ms_reset(lgsm=[("Unknown game server", "", 0)])
    _r, _ms_b = _ms_install("csgo", "p9bad", "27180")
    _p9_drain()
    _rb = _p9_row(_ms_b)
    check("install: LinuxGSM not knowing the game fails the row as 'Invalid game type', retryable",
          _rb.status == "failed" and _rb.install_error.startswith("Invalid game type")
          and _rb.install_retryable is True and _ms_job(_ms_b).get("status") == "failed", repr(_rb))
    _p9_delete_server(_ms_b)

    _ms_free[:] = [(27181, False)]
    _ms_reset(lgsm=[("", "denied", 1)])
    _real_rif = _p9_ms.record_install_failure
    _p9_patch(_p9_ms, "record_install_failure", _raise_conn)
    _r, _ms_d = _ms_install("csgo", "p9rif", "27181")
    _p9_drain()
    _p9_patch(_p9_ms, "record_install_failure", _real_rif)
    check("install: a failure that cannot be written to the row still fails the live job",
          _ms_job(_ms_d).get("status") == "failed" and _p9_row(_ms_d).status == "installing",
          repr(_ms_job(_ms_d)))
    _p9_delete_server(_ms_d)

    _ms_free[:] = [(27182, False)]
    _ms_reset(boom={"useradd"})
    _p9_patch(_p9_ms, "readable_reason", _raise_conn)
    _r, _ms_e = _ms_install("csgo", "p9boom", "27182")
    _p9_drain()
    _p9_patch(_p9_ms, "readable_reason", _P9_PATCHED[(_p9_ms, "readable_reason")])
    _je = _ms_job(_ms_e)
    check("install: a crash that even the failure recorder cannot record still ends the job 'failed'",
          _je.get("status") == "failed" and "useradd failed on the host" in _je.get("message", ""),
          repr(_je))
    _p9_delete_server(_ms_e)

    # The job itself, taken from the retry route's closure, for the two guards a route cannot reach.
    _ms_rv = _p9_inspect.unwrap(_p9.view_functions["retry_install"])
    _ms_rij = dict(zip(_ms_rv.__code__.co_freevars,
                       (c.cell_contents for c in _ms_rv.__closure__)))["_run_install_job"]
    _ms_reset()
    _ms_rij(99951, P9_HOST, "p9none", "csgo", "csgoserver", 27015, [])
    _p9_drain()
    check("install job: a row deleted before the job ran does nothing on the host",
          _ms_log == [], repr(_ms_log))
    _ms_x = _p9_new_server(P9_HOST, "p9empty", "csgo", 27183, installed=False, status="installing")
    _ms_rij(_ms_x, P9_HOST, "", "csgo", "csgoserver", 27183, [])
    _p9_drain()
    check("install job: an empty instance name fails before ANY host command (rm -rf /home/ guard)",
          _ms_log == [] and _p9_row(_ms_x).status == "failed"
          and "missing instance name" in _p9_row(_ms_x).install_error, repr((_ms_log, _p9_row(_ms_x))))

    # ── retry ──────────────────────────────────────────────────────────────────────────────────
    _p9_set(_ms_x, status="offline", install_error="")
    _r = _A.post("/servers/%d/retry-install" % _ms_x, headers=_XHR)
    check("retry: a server whose install did not fail is refused",
          _r.status_code == 400 and "didn't fail" in _p9_json(_r).get("message", ""))
    _p9_set(_ms_x, status="failed", install_error="SteamCMD timed out", install_retryable=True,
            autostart=False)
    with _p9_state._install_lock:
        _p9_state._install_jobs[_ms_x] = {"status": "running", "updated": _p9_real_time.time()}
    _r = _A.post("/servers/%d/retry-install" % _ms_x, headers=_XHR)
    check("retry: an install that is already running is refused",
          _r.status_code == 400 and "already running" in _p9_json(_r).get("message", ""))
    with _p9_state._install_lock:
        _p9_state._install_jobs.pop(_ms_x, None)
    _ms_reset(acct={"p9empty": "EXISTS"}, cmds=[[{"cmd": "monitor", "desc": "Monitor"}]],
              listen=[{27183}])
    _r = _A.post("/servers/%d/retry-install" % _ms_x, headers=_XHR)
    _p9_drain()
    _rx = _p9_row(_ms_x)
    check("retry: an account the first attempt made (its linuxgsm.sh present) is reused, not recreated",
          _p9_json(_r).get("success") is True and "useradd" not in _ms_log
          and _ms_job(_ms_x).get("status") == "done", repr((_p9_json(_r), _ms_log)))
    check("retry: the retried install records Autostart on once monitor is scheduled, and runs",
          _rx.autostart is True and _rx.status == "online" and "cron" in _ms_log, repr(_rx))
    # A reason still on the row when a run completes (a failure recorded while it ran) is cleared by
    # the finish — the retry route clears it up front, so this drives the job directly.
    _p9_set(_ms_x, install_error="stale reason", install_retryable=False)
    _ms_reset(acct={"p9empty": "EXISTS"}, listen=[{27183}])
    _ms_rij(_ms_x, P9_HOST, "p9empty", "csgo", "csgoserver", 27183, [])
    _p9_drain()
    check("install job: a run that completes clears a failure reason left on the row",
          _p9_row(_ms_x).install_error == "" and _p9_row(_ms_x).install_retryable is True,
          repr(_p9_row(_ms_x)))
    _ms_orphan = _p9_new_server(99952, "p9orphan", "csgo", 27184, installed=False, status="failed")
    _r = _A.post("/servers/%d/retry-install" % _ms_orphan, headers=_XHR)
    check("retry: a server whose host row is gone is refused, not crashed",
          _r.status_code == 400 and "host is gone" in _p9_json(_r).get("message", ""),
          repr((_r.status_code, _p9_json(_r))))
    _p9_delete_server(_ms_orphan)

    # ── uninstall ──────────────────────────────────────────────────────────────────────────────
    with _p9_state._install_lock:
        _p9_state._install_jobs[_ms_x] = {"status": "running", "updated": _p9_real_time.time()}
    _r = _A.post("/servers/%d/delete" % _ms_x, headers=_XHR)
    check("uninstall: refused with 409 (JSON) while the install is still running",
          _r.status_code == 409 and _p9_exists(_ms_x))
    with _p9_state._install_lock:
        _p9_state._install_jobs.pop(_ms_x, None)

    _ms_fw = [(0, "", [])]
    _p9_patch(_p9_ms, "remote_ufw_close_by_name",
              lambda r, n, ports=None, held=(), tagged=None: _ms_next_fw())

    def _ms_next_fw():
        v = _ms_fw[0]
        if isinstance(v, Exception):
            raise v
        return v

    _ms_reset(userdel=[("", "userdel: user p9empty is currently used by process 1", 8)],
              boom={"user-kill-processes", "steam-dumps-sweep"})
    _r = _A.post("/servers/%d/delete" % _ms_x)
    check("uninstall (form): a userdel that failed keeps the row and flashes the host's reason",
          _r.status_code == 302 and _p9_exists(_ms_x)
          and any("currently used by process" in m for m in _p9_flashes(_A))
          and _p9_audit("uninstall_server").success is False)
    check("uninstall: a failed process kill and dump sweep do not stop the account removal attempt",
          "user-delete-force" in _ms_log, repr(_ms_log))
    _ms_reset(userdel=[ConnectionError("ssh dropped")])
    _r = _A.post("/servers/%d/delete" % _ms_x, headers=_XHR)
    check("uninstall (JSON): a removal that raises is a 500 and the row stays",
          _r.status_code == 500 and _p9_json(_r).get("success") is False
          and _p9_exists(_ms_x))
    _r = _A.post("/servers/%d/delete" % _ms_x)
    check("uninstall (form): a removal that raises flashes a generic failure",
          _r.status_code == 302 and _p9_flashes(_A) == ["Internal server error"])
    _ms_reset()
    _ms_fw[0] = ConnectionError("ufw unreachable")
    _p9_patch(_p9_bk, "remove_game_schedule", _raise_conn)
    _r = _A.post("/servers/%d/delete" % _ms_x)
    check("uninstall (form): success flashes, even when the firewall and schedule cleanup raised — "
          "and it says the server's rules may still be open, rather than nothing",
          _r.status_code == 302 and not _p9_exists(_ms_x)
          and _p9_flashes(_A) == ["Server 'p9empty' uninstalled. " + _p9_sm.UFW_UNREAD_NOTE],
          repr((_p9_row(_ms_x), _p9_flashes(_A))))
    _ms_y = _p9_new_server(P9_HOST, "p9fw", "csgo", 27185)
    _ms_fw[0] = (2, "", [])
    # This one's cleanup works, and it has a FINISHED install job: the row id is handed to the next
    # server created, so a job left behind makes /install-status answer for that new server with
    # this one's outcome. The check above cannot see it — its schedule cleanup raises first.
    _p9_patch(_p9_bk, "remove_game_schedule", lambda sid: None)
    with _p9_state._install_lock:
        _p9_state._install_jobs[_ms_y] = {"status": "done", "updated": _p9_real_time.time()}
    _d = _p9_json(_A.post("/servers/%d/delete" % _ms_y, headers=_XHR))
    check("uninstall (JSON): the firewall rules it removed are counted in the message",
          _d == {"success": True, "message": "Server 'p9fw' uninstalled. 2 firewall rule(s) removed.",
                 "warn": False},
          repr(_d))
    # Aikido 745379215: past its tagged rules, uninstall takes an UNTAGGED allow on its port (a
    # panel that did not tag yet left those) — and only when no other server's block holds it.
    check("uninstall: the untagged legacy sweep runs on a port no other server holds",
          "ufw-close:27185::True" in _ms_log, repr([e for e in _ms_log if "ufw-close" in e]))
    _ms_z = _p9_new_server(P9_HOST, "p9fwnext", "csgo", 27187)
    _ms_zz = _p9_new_server(P9_HOST, "p9fwrust", "rust", 27186)     # its block is 27186-27187
    _ms_reset()
    _ms_fw[0] = (0, "", [])
    _d = _p9_json(_A.post("/servers/%d/delete" % _ms_z, headers=_XHR))
    check("uninstall: ...and NOT on a port inside another server's block — that rule is at least as "
          "likely to be theirs",
          _d.get("success") is True and not any("ufw-close:27187" in e for e in _ms_log),
          repr((_d, [e for e in _ms_log if "ufw-close" in e])))
    _p9_delete_server(_ms_zz)
    # What the cleanups could not remove, or left on purpose, is in the uninstall's answer: a rule
    # that stayed open used to read as a clean uninstall, since only the delete count was kept.
    _ms_w = _p9_new_server(P9_HOST, "p9fwleft", "csgo", 27189)
    _ms_stuck = ("Still open, as it could not be removed: 27190 — remove it from the host's "
                 "Firewall page.")
    _ms_kept = "Left in place, as the panel does not make rules like these: 27191 DENY."
    _ms_fw[0] = (1, "1 rule(s) removed for p9fwleft. " + _ms_stuck + " " + _ms_kept,
                 [_ms_stuck, _ms_kept])
    _ms_legacy_fw[0] = (1, "Port 27189: 1 rule(s) removed. " + _ms_stuck, [_ms_stuck])
    _ms_reset()
    _d = _p9_json(_A.post("/servers/%d/delete" % _ms_w, headers=_XHR))
    check("uninstall: a rule the cleanup could not remove, or left, is named in the answer — once",
          _d == {"success": True, "message": "Server 'p9fwleft' uninstalled. 2 firewall rule(s) "
                                             "removed. " + _ms_stuck + " " + _ms_kept,
                 "warn": True}, repr(_d))
    _ms_v = _p9_new_server(P9_HOST, "p9fwhalf", "csgo", 27193)
    _ms_fw[0], _ms_legacy_fw[0] = (2, "", []), (0, "", [])
    _ms_reset(boom={"ufw-close"})
    _d = _p9_json(_A.post("/servers/%d/delete" % _ms_v, headers=_XHR))
    check("uninstall: a legacy sweep that raised keeps the count of what the name cleanup removed, "
          "and says the rest may still be open",
          _d == {"success": True, "message": "Server 'p9fwhalf' uninstalled. 2 firewall rule(s) "
                                             "removed. " + _p9_sm.UFW_UNREAD_NOTE,
                 "warn": True}, repr(_d))
    _ms_fw[0], _ms_legacy_fw[0] = (0, "", []), (0, "", [])
    with _p9_state._install_lock:
        _ms_y_job = _p9_state._install_jobs.pop(_ms_y, None)
    check("uninstall: the removed server's install job goes with its row (the id is reused)",
          _d.get("success") is True and _ms_y_job is None, repr(_ms_y_job))
    for _n in (_ms_a, _ms_f, _ms_g):
        _p9_delete_server(_n)

    # ── layout and password-change helpers (routes/tags.py) ─────────────────────────────────────
    # Neither was driven by any suite: storing an order for a host the caller cannot see, and
    # dropping "remember me" across a password change, both passed unit and smoke alike.
    from panel.routes import tags as _p9_tags             # noqa: E402
    from panel.db.models import UserSession as _P9US      # noqa: E402
    check("layout: a server order for a host the caller cannot see is dropped, not stored",
          _p9_tags._clean_server_order({"1": [11, 12], "2": [21], "x": [11], "3": "junk"},
                                       {1}, {11, 21}) == {"1": [11]},
          repr(_p9_tags._clean_server_order({"1": [11, 12], "2": [21], "x": [11], "3": "junk"},
                                            {1}, {11, 21})))
    # A password change signs the device in again; whether that login is remembered comes from
    # THIS device's session row, and only when there is no row from its remember cookie.
    _p9_patch(_p9_tags, "_has_remember_cookie", lambda: True)
    _rem = []
    with _p9.app_context():
        db.session.add_all([_P9US(user_id=P9_VIEWER, sid="p9-rem-on", remember=True),
                            _P9US(user_id=P9_VIEWER, sid="p9-rem-off", remember=False)])
        db.session.commit()
        _rem_u = db.session.get(User, P9_VIEWER)
        # Unrolled rather than a loop: this whole part is one try block, already over mccabe's limit.
        _p9_patch(_p9_tags, "current_user", NS(_sid="p9-rem-on"))       # row says remembered
        _rem.append(_p9_tags._remember_this_device(_rem_u))
        _p9_patch(_p9_tags, "current_user", NS(_sid="p9-rem-off"))      # row says not, cookie or no
        _rem.append(_p9_tags._remember_this_device(_rem_u))
        _p9_patch(_p9_tags, "current_user", NS(_sid="p9-rem-none"))     # no such row: the cookie
        _rem.append(_p9_tags._remember_this_device(_rem_u))
        _p9_patch(_p9_tags, "current_user", NS(_sid=None))              # no sid at all: the cookie
        _rem.append(_p9_tags._remember_this_device(_rem_u))
        _P9US.query.filter(_P9US.sid.in_(["p9-rem-on", "p9-rem-off"])).delete(
            synchronize_session=False)
        db.session.commit()
    _p9_patch(_p9_tags, "current_user", _P9_PATCHED[(_p9_tags, "current_user")])
    _p9_patch(_p9_tags, "_has_remember_cookie", _P9_PATCHED[(_p9_tags, "_has_remember_cookie")])
    check("password change: 'remember me' is read from this device's session row, else its cookie",
          _rem == [True, False, True, True], repr(_rem))

    # ── END OF SECTIONS ──
finally:
    for _m, _t in _p9_saved_threading.items():
        _m.threading = _t
    for _m, _t in _p9_saved_time.items():
        _m.time = _t
    _p9_restore_all()
    _p9_banlist._listeners.clear()
    _p9_banlist._listeners.update(_p9_saved_listeners)
    _p9_app._log.disabled = _p9_saved_log_disabled
    _p9.logger.disabled = _p9_saved_applog_disabled
    try:
        with _p9.app_context():
            db.session.remove()
            db.engine.dispose()
    except Exception:  # nosec B110 - best-effort cleanup of a throwaway database
        pass
    try:
        if _P9_CFG_SNAPSHOT is None:
            if _P9_CFG_PATH.exists():
                _P9_CFG_PATH.unlink()
        else:
            _P9_CFG_PATH.write_bytes(_P9_CFG_SNAPSHOT)
    except OSError:  # nosec B110 - best-effort cleanup of the runner's throwaway config
        pass

check("part12: no route under test reached a real transport (every host call was stubbed)",
      not _P9_TRIPPED, repr(_P9_TRIPPED[:6]))
check("part12: nothing in this part created the checkout's own data/panel.db",
      _P9_LIVE_DB_EXISTED or not os.path.exists(_P9_LIVE_DB), _P9_LIVE_DB)
check("part12: every deferred worker was run (none left to leak into a later check)",
      not _p9_queue,
      "%d left: %s" % (len(_p9_queue), [getattr(f, "__qualname__", f) for f, _a, _k in _p9_queue]))


# ══ Privilege boundary: who may join the game-account group, the helper's environment, and the
#    root installer's reads and chowns inside the panel-owned tree ═════════════════════════════
# Every check below drives the real code: the helper loaded from tools/panel-helper (part05's
# module), and install.sh / uninstall.sh functions lifted out whole and run under bash. The host's
# own passwd, group, sudoers, doas and polkit files are never consulted: each is pointed at a
# sandbox made here and put back afterwards.
import grp as _pb_real_grp                                                        # noqa: E402
import pwd as _pb_real_pwd                                                        # noqa: E402
import shutil as _pb_shutil                                                       # noqa: E402
import stat as _pb_stat                                                           # noqa: E402
import subprocess as _pb_sp  # nosec B404 - bash and python on sandbox fixtures   # noqa: E402
import sys as _pb_sys                                                             # noqa: E402

from unit.part01 import skip as _pb_skip                                         # noqa: E402
from unit.part05 import _helper as _pbh, _root as _pb_root                       # noqa: E402
from unit.part06 import _inst_shfn as _pb_shfn                                   # noqa: E402
from panel.security import privileged as _pb_priv                                # noqa: E402

_PB = tempfile.mkdtemp(prefix="lgsm-unit-pb-")
_PB_HOME = os.path.join(_PB, "home")
os.makedirs(_PB_HOME)
_PB_ROOT = os.geteuid() == 0
# The uid a sandbox home can really carry: as root any uid can be given one; otherwise only this
# process's own (a CI runner's 1001 is inside 1000..60000; anything else skips the home checks).
_PB_GAME_UID = 1001 if _PB_ROOT else os.getuid()
_PB_HOMES_OK = 1000 <= _PB_GAME_UID <= 60000


def _pb_run(script, env=None, cwd=None, timeout=30):
    r = _pb_sp.run(["bash", "-c", script], capture_output=True, text=True, check=False,  # nosec B603 B607 - fixture script
                   timeout=timeout, cwd=cwd, env=dict(os.environ, **(env or {})))
    return r


# ── 1. gameuser-group: only a real GAME account joins the group the second sudoers line names ─
class _PbGr:
    def __init__(self, name, gid, mem=()):
        self.gr_name, self.gr_gid, self.gr_mem = name, gid, list(mem)


_pb_accounts = {}          # name -> (uid, gid, home)
_pb_groups = {}            # name -> _PbGr


def _pb_account(name, uid, gid=None, home=None, groups=(), install=None):
    """A fake account; `install` makes a LinuxGSM marker in its sandbox home."""
    gid = uid if gid is None else gid
    home = home or os.path.join(_PB_HOME, name)
    _pb_accounts[name] = (uid, gid, home)
    _pb_groups.setdefault(name, _PbGr(name, gid))
    for g in groups:
        _pb_groups[g].gr_mem.append(name)
    if install is not None and not os.path.lexists(home):
        os.makedirs(home)
        if install == "lgsm":
            os.makedirs(os.path.join(home, "lgsm", "config-lgsm"))
        elif install == "script":
            open(os.path.join(home, "linuxgsm.sh"), "w").close()
        if _PB_ROOT:
            for d, dirs, files in os.walk(home):
                for n in [d] + [os.path.join(d, x) for x in dirs + files]:
                    os.lchown(n, uid, gid)


def _pb_getpwnam(name):
    if name not in _pb_accounts:
        raise KeyError(name)
    uid, gid, home = _pb_accounts[name]
    return NS(pw_name=name, pw_uid=uid, pw_gid=gid, pw_dir=home)


def _pb_getpwuid(uid):
    for n, (u, _g, _h) in _pb_accounts.items():
        if u == uid:
            return _pb_getpwnam(n)
    raise KeyError(uid)


def _pb_getgrgid(gid):
    for g in _pb_groups.values():
        if g.gr_gid == gid:
            return g
    raise KeyError(gid)


def _pb_getgrnam(name):
    if name not in _pb_groups:
        raise KeyError(name)
    return _pb_groups[name]


_pb_groups.update({"users": _PbGr("users", 100), "cdrom": _PbGr("cdrom", 24),
                   "microk8s": _PbGr("microk8s", 1500), "friends": _PbGr("friends", 1600),
                   "doasers": _PbGr("doasers", 1601), "polgrp": _PbGr("polgrp", 1602),
                   "lgsmpanel-games": _PbGr("lgsmpanel-games", 1700), "sudo": _PbGr("sudo", 27)})
_G = _PB_GAME_UID
_pb_account("lgsmpanel", 998)
_pb_account("gamer", _G, install="lgsm")
_pb_account("scripted", _G, gid=_G + 20, install="script")
_pb_account("alice", _G, gid=_G + 1, install="")                     # a person: a home, no install
_pb_account("postgres", 114, install="lgsm")                          # service account, below UID_MIN
_pb_account("nobody", 65534, install="lgsm")                          # above UID_MAX
_pb_account("cdromer", _G, gid=_G + 2, groups=("cdrom",), install="lgsm")
_pb_account("k8s", _G, gid=_G + 3, groups=("microk8s",), install="lgsm")
_pb_account("friendly", _G, gid=_G + 4, groups=("users", "friends"), install="lgsm")
_pb_account("linked", _G, gid=_G + 5, home=os.path.join(_PB_HOME, "linked"))
os.symlink(os.path.join(_PB_HOME, "gamer"), os.path.join(_PB_HOME, "linked"))
_pb_account("markerlink", _G, gid=_G + 6, install="")
os.symlink(os.path.join(_PB_HOME, "gamer", "lgsm"), os.path.join(_PB_HOME, "markerlink", "lgsm"))
_pb_account("doasme", _G, gid=_G + 7, groups=("doasers",), install="lgsm")
_pb_account("polme", _G, gid=_G + 8, groups=("polgrp",), install="lgsm")
_pb_account("pklame", _G, gid=_G + 9, install="lgsm")
_pb_account("member", _G, gid=_G + 10, groups=("lgsmpanel-games",), install="")
_pb_account("sudomember", _G, gid=_G + 11, groups=("lgsmpanel-games", "sudo"), install="lgsm")

_pb_policy = os.path.join(_PB, "policy")
os.makedirs(os.path.join(_pb_policy, "sudoers.d"))
os.makedirs(os.path.join(_pb_policy, "rules.d"))
os.makedirs(os.path.join(_pb_policy, "pkla", "50-local.d"))
open(os.path.join(_pb_policy, "sudoers"), "w").close()
with open(os.path.join(_pb_policy, "login.defs"), "w") as _fh:
    _fh.write("# test\nUID_MIN\t\t 1000\nUID_MAX\t\t60000\nGID_MIN\t\t 1000\nGID_MAX\t\t60000\n")
with open(os.path.join(_pb_policy, "doas.conf"), "w") as _fh:
    _fh.write("# admins\npermit persist setenv { PATH=/bin } :doasers as root\ndeny steam\n")
with open(os.path.join(_pb_policy, "rules.d", "60-units.rules"), "w") as _fh:
    _fh.write('polkit.addRule(function(action, subject) {\n'
              '  if (action.id == "org.freedesktop.systemd1.manage-units" &&\n'
              '      subject.isInGroup("polgrp")) { return polkit.Result.YES; }\n});\n')
with open(os.path.join(_pb_policy, "pkla", "50-local.d", "units.pkla"), "w") as _fh:
    _fh.write("[let pklame manage units]\nIdentity=unix-user:pklame\n"
              "Action=org.freedesktop.systemd1.manage-units\nResultAny=yes\n"
              "[friendly may ask]\nIdentity=unix-group:friends\nAction=x\nResultAny=auth_admin\n")
with open(os.path.join(_PB, "panel.conf"), "w") as _fh:
    _fh.write("panel_dir=%s\n" % os.path.join(_PB_HOME, "lgsmpanel", "linuxgsm-panel"))

_pb_saved = {k: getattr(_pbh, k) for k in (
    "pwd", "grp", "HOME_ROOT", "LOGIN_DEFS", "DOAS_CONFS", "POLKIT_RULE_DIRS", "POLKIT_PKLA_DIRS",
    "SUDOERS_FILE", "SUDOERS_DIR", "NSSWITCH_FILE", "PANEL_CONF", "subprocess", "resolve",
    "_escalation_verdict")}
_pb_sudo_uid = os.environ.get("SUDO_UID")
_pb_calls = []


def _pb_fake_run(argv, *a, **k):
    _pb_calls.append(list(argv))
    if os.path.basename(argv[0]) == "useradd":
        _pb_account(argv[-1], 2000 + len(_pb_accounts), install="")
    return NS(returncode=0, stdout="", stderr=b"" if k.get("capture_output") and not k.get("text") else "")


try:
    _pbh.pwd = NS(getpwnam=_pb_getpwnam, getpwuid=_pb_getpwuid)
    _pbh.grp = NS(getgrgid=_pb_getgrgid, getgrnam=_pb_getgrnam,
                  getgrall=lambda: list(_pb_groups.values()))
    _pbh.HOME_ROOT = _PB_HOME
    _pbh.LOGIN_DEFS = os.path.join(_pb_policy, "login.defs")
    _pbh.DOAS_CONFS = (os.path.join(_pb_policy, "doas.conf"),)
    _pbh.POLKIT_RULE_DIRS = (os.path.join(_pb_policy, "rules.d"),)
    _pbh.POLKIT_PKLA_DIRS = (os.path.join(_pb_policy, "pkla"),)
    _pbh.SUDOERS_FILE = os.path.join(_pb_policy, "sudoers")
    _pbh.SUDOERS_DIR = os.path.join(_pb_policy, "sudoers.d")
    _pbh.NSSWITCH_FILE = os.path.join(_pb_policy, "no-nsswitch")
    _pbh.PANEL_CONF = os.path.join(_PB, "panel.conf")
    _pbh.subprocess = NS(run=_pb_fake_run, PIPE=_pb_sp.PIPE, STDOUT=_pb_sp.STDOUT,
                         DEVNULL=_pb_sp.DEVNULL, TimeoutExpired=_pb_sp.TimeoutExpired)
    _pbh.resolve = lambda n: "/usr/sbin/" + n
    os.environ["SUDO_UID"] = "998"            # invoked by the panel's own account

    _pb_why = {n: _pbh._enrolment_refusal(n) for n in (
        "gamer", "scripted", "friendly", "alice", "postgres", "nobody", "lgsmpanel", "cdromer",
        "k8s", "doasme", "polme", "pklame", "linked", "markerlink", "ghost")}
    if _PB_HOMES_OK:
        check("enrol gate: a LinuxGSM account with an ordinary uid and ordinary groups is accepted"
              " (lgsm/config-lgsm, or linuxgsm.sh; `users` and a gid>=GID_MIN group are fine)",
              _pb_why["gamer"] == "" and _pb_why["scripted"] == "" and _pb_why["friendly"] == "",
              repr({k: _pb_why[k] for k in ("gamer", "scripted", "friendly")}))
        check("enrol gate: a person's login account with no LinuxGSM install is REFUSED",
              "no LinuxGSM install" in _pb_why["alice"], repr(_pb_why["alice"]))
        check("enrol gate: a home that is a symlink to a game account's home is refused",
              "no LinuxGSM install" in _pb_why["linked"], repr(_pb_why["linked"]))
        check("enrol gate: ...and so is a marker (~/lgsm) that is a symlink into another home",
              "no LinuxGSM install" in _pb_why["markerlink"], repr(_pb_why["markerlink"]))
        check("enrol gate: a system group (gid < GID_MIN, e.g. cdrom) is refused: allowlist, not "
              "denylist", "system group cdrom" in _pb_why["cdromer"], repr(_pb_why["cdromer"]))
        check("enrol gate: ...and microk8s is refused by NAME even as an ordinary gid",
              "microk8s" in _pb_why["k8s"], repr(_pb_why["k8s"]))
    else:
        _pb_skip("enrol gate: home-directory checks", "this uid (%d) is not an ordinary one" % _G)
    check("enrol gate: service accounts and nobody are refused by uid, whatever their home holds",
          "outside this host's range" in _pb_why["postgres"]
          and "outside this host's range" in _pb_why["nobody"],
          repr((_pb_why["postgres"], _pb_why["nobody"])))
    check("enrol gate: the panel's own account is refused", _pb_why["lgsmpanel"] != "",
          repr(_pb_why["lgsmpanel"]))
    check("enrol gate: an account that does not exist is refused", _pb_why["ghost"] != "")
    check("enrol gate: a doas `permit :group` for one of its groups is 'can reach root'",
          "doas" in _pb_why["doasme"] and "reach root" in _pb_why["doasme"], repr(_pb_why["doasme"]))
    check("enrol gate: a polkit rule naming one of its groups is 'can reach root'",
          "polkit rule" in _pb_why["polme"], repr(_pb_why["polme"]))
    check("enrol gate: a .pkla granting it 'yes' is 'can reach root' (an auth_admin one is not)",
          "polkit authority" in _pb_why["pklame"] and "polkit" not in _pb_why["friendly"],
          repr((_pb_why["pklame"], _pb_why["friendly"])))
    check("enrol gate: _escalation_verdict itself says yes for doas and polkit (install.sh evicts)",
          _pbh._escalation_verdict("doasme")[0] == "yes"
          and _pbh._escalation_verdict("polme")[0] == "yes"
          and _pbh._escalation_verdict("k8s")[0] == "yes", "")
    with open(os.path.join(_pb_policy, "doas.conf"), "a") as _fh:
        _fh.write('permit "odd name"\n')
    check("enrol gate: a doas rule it cannot parse is 'unknown', never 'no'",
          _pbh._escalation_verdict("gamer")[0] == "unknown", repr(_pbh._escalation_verdict("gamer")))
    with open(os.path.join(_pb_policy, "doas.conf"), "w") as _fh:
        _fh.write("permit persist :doasers\n")

    # The verb, and its two legitimate callers.
    import io as _pb_io
    _pb_stderr_saved = _pbh.sys.stderr
    try:
        _pbh.sys.stderr = _pb_io.StringIO()
        del _pb_calls[:]
        _pb_rc_alice = _pbh.do_gameuser_group(["alice"], "")
        _pb_calls_alice = list(_pb_calls)
        del _pb_calls[:]
        _pb_rc_pg = _pbh.do_gameuser_group(["postgres"], "")
        _pb_calls_pg = list(_pb_calls)
        del _pb_calls[:]
        _pb_rc_gamer = _pbh.do_gameuser_group(["gamer"], "")
        _pb_calls_gamer = list(_pb_calls)
        del _pb_calls[:]
        _pb_rc_member = _pbh.do_gameuser_group(["member"], "")
        _pb_rc_sudomember = _pbh.do_gameuser_group(["sudomember"], "")
        _pb_errtext = _pbh.sys.stderr.getvalue()
        # user-create enrols what it has just created, so create_game_user's gameuser-group call
        # right after finds a member; a name that is a privileged group is created, not enrolled.
        del _pb_calls[:]
        _pb_rc_uc = _pbh.main(["panel-helper", "user-create", "newbie"])
        _pb_calls_uc = [os.path.basename(c[0]) for c in _pb_calls]
        del _pb_calls[:]
        _pb_rc_uc2 = _pbh.main(["panel-helper", "user-create", "lxd"])
        _pb_calls_uc2 = [os.path.basename(c[0]) for c in _pb_calls]
        _pb_uc_err = _pbh.sys.stderr.getvalue()
    finally:
        _pbh.sys.stderr = _pb_stderr_saved
    if _PB_HOMES_OK:
        check("gameuser-group: a login account with no install is refused and nothing runs",
              _pb_rc_alice == 1 and not _pb_calls_alice, "rc=%s ran=%s" % (_pb_rc_alice, _pb_calls_alice))
        check("gameuser-group: an imported LinuxGSM account is enrolled (groupadd -f, usermod -aG)",
              _pb_rc_gamer == 0 and [os.path.basename(c[0]) for c in _pb_calls_gamer]
              == ["groupadd", "usermod"] and _pb_calls_gamer[1][-1] == "gamer",
              "rc=%s ran=%s" % (_pb_rc_gamer, _pb_calls_gamer))
        check("gameuser-group: an existing member needs no install (the content account's tree may"
              " be empty), but one that has since gained sudo is still refused",
              _pb_rc_member == 0 and _pb_rc_sudomember == 1
              and "sudomember in lgsmpanel-games: it can already reach root" in _pb_errtext,
              "member=%s sudomember=%s %r" % (_pb_rc_member, _pb_rc_sudomember, _pb_errtext[-200:]))
    check("gameuser-group: postgres (a service uid) is refused and nothing runs",
          _pb_rc_pg == 1 and not _pb_calls_pg, "rc=%s ran=%s" % (_pb_rc_pg, _pb_calls_pg))
    check("user-create: the account it has just made is enrolled in the same run",
          _pb_rc_uc == 0 and _pb_calls_uc == ["useradd", "groupadd", "usermod"], repr(_pb_calls_uc))
    check("user-create: ...but a name that is a root-equivalent group is created and NOT enrolled",
          _pb_rc_uc2 == 0 and _pb_calls_uc2 == ["useradd"]
          and "created lxd but did not enrol it" in _pb_uc_err, repr((_pb_calls_uc2, _pb_uc_err[-160:])))
finally:
    for _k, _v in _pb_saved.items():
        setattr(_pbh, _k, _v)
    if _pb_sudo_uid is None:
        os.environ.pop("SUDO_UID", None)
    else:
        os.environ["SUDO_UID"] = _pb_sudo_uid

check("enrol gate: the helper's, install.sh's and privileged.py's root-equivalent groups include "
      "the ones the survey added",
      {"microk8s", "lpadmin", "kmem", "incus", "systemd-journal", "ssl-cert"}
      <= set(_pbh.NEVER_ENROL_GROUPS) & set(_pb_priv._NEVER_A_CONTENT_GROUP)
      and set(_pbh.NEVER_A_CONTENT_GROUP) == set(_pbh.NEVER_ENROL_GROUPS))

# install.sh asks the helper the same question before it enrols anyone, and fails closed.
_pb_inst = open(os.path.join(_pb_root, "install.sh"), encoding="utf-8").read()
_pb_er = _pb_shfn("enrolment_refusal")
_pb_sync = _pb_shfn("sync_game_user_group")
check("install.sh: the backfill asks enrolment_refusal before usermod -aG",
      "enrolment_refusal" in _pb_sync
      and _pb_sync.index("enrolment_refusal") < _pb_sync.index('usermod -aG "${GAME_GROUP}"'))
_pb_hd = os.path.join(_PB, "helperdir")
os.makedirs(_pb_hd)
_r = _pb_run(_pb_er + 'enrolment_refusal root; echo "[$?]"', env={"HELPER_DIR": _pb_hd})
check("install.sh enrolment_refusal: with no helper to ask, it refuses (fails closed)",
      "helper that checks game accounts is not installed" in _r.stdout, _r.stdout + _r.stderr)
_pb_shutil.copy(os.path.join(_pb_root, "tools", "panel-helper"), os.path.join(_pb_hd, "panel-helper"))
_r = _pb_run(_pb_er + 'enrolment_refusal root; enrolment_refusal no-such-account-pb',
             env={"HELPER_DIR": _pb_hd})
_pb_lns = _r.stdout.splitlines()
check("install.sh enrolment_refusal: the helper's reason comes back, one line per account (root"
      " is refused; a missing account is not an account)",
      len(_pb_lns) == 2 and _pb_lns[0] and "not an account on this host" in _pb_lns[1],
      _r.stdout + _r.stderr)
with open(os.path.join(_pb_hd, "panel-helper"), "w") as _fh:
    _fh.write("raise SystemExit(3)\n")
_r = _pb_run(_pb_er + 'enrolment_refusal root', env={"HELPER_DIR": _pb_hd})
check("install.sh enrolment_refusal: a helper that does not answer is a refusal, not a pass",
      "could not check it" in _r.stdout, _r.stdout + _r.stderr)

# ── 2. The helper's interpreter and the environment its children get ─────────────────────────
_pb_first = open(os.path.join(_pb_root, "tools", "panel-helper"), encoding="utf-8").readline()
check("helper: the shebang names /usr/bin/python3 outright, isolated (-I), not `env python3`",
      _pb_first.strip() == "#!/usr/bin/python3 -I", repr(_pb_first))
_pb_env_saved = dict(os.environ)
try:
    os.environ.update({"BASH_ENV": "/tmp/pb-evil", "PATH": "/tmp/pb-evil:/usr/bin",
                       "PYTHONPATH": "/tmp/pb", "http_proxy": "http://pb.invalid",
                       "SUDO_UID": "998", "FOO": "1"})
    _pb_ce = _pbh._clean_env(DEBIAN_FRONTEND="noninteractive")
    check("helper _clean_env: a fixed PATH and locale, sudo's identity kept, nothing else inherited",
          _pb_ce["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin" and _pb_ce["SUDO_UID"] == "998"
          and _pb_ce["DEBIAN_FRONTEND"] == "noninteractive"
          and not {"BASH_ENV", "PYTHONPATH", "http_proxy", "FOO"} & set(_pb_ce), repr(_pb_ce))
    _pb_su = _pbh._self_update_env("-", "-")
    check("helper: the root-run installer's environment is built, not copied (no BASH_ENV)",
          "BASH_ENV" not in _pb_su and "FOO" not in _pb_su and _pb_su["PANEL_SELF_UPDATE"] == "1"
          and _pb_su["PATH"] == _pbh.CHILD_PATH and _pb_su.get("SUDO_UID") == "998", repr(_pb_su))
    _pb_dbr = _pbh._db_repair_as(NS(pw_uid=1234, pw_gid=1234, pw_name="x", pw_dir="/home/x"))
    check("helper: the db repair child gets a clean environment with the account's HOME",
          _pb_dbr["env"]["HOME"] == "/home/x" and "FOO" not in _pb_dbr["env"], repr(_pb_dbr["env"]))
    _pb_seen = []
    _pb_sub_saved, _pb_res_saved = _pbh.subprocess, _pbh.resolve
    try:
        _pbh.subprocess = NS(run=lambda argv, **k: (_pb_seen.append(k.get("env")),
                                                    NS(returncode=0, stdout="", stderr=""))[1],
                             TimeoutExpired=_pb_sp.TimeoutExpired)
        _pbh.resolve = lambda n: "/usr/bin/" + n
        _pbh.main(["panel-helper", "apt-install", "curl"])
    finally:
        _pbh.subprocess, _pbh.resolve = _pb_sub_saved, _pb_res_saved
    check("helper main: a table verb's tool runs with the clean environment (+DEBIAN_FRONTEND)",
          len(_pb_seen) == 1 and _pb_seen[0] and "BASH_ENV" not in _pb_seen[0]
          and "FOO" not in _pb_seen[0] and _pb_seen[0].get("DEBIAN_FRONTEND") == "noninteractive",
          repr(_pb_seen))
finally:
    os.environ.clear()
    os.environ.update(_pb_env_saved)
# _scrub_environ, as the __main__ block runs it: in a child, so this process keeps its own.
_r = _pb_sp.run([_pb_sys.executable, "-I", "-c",
                 "import importlib.machinery as m, importlib.util as u, os, sys\n"
                 "l = m.SourceFileLoader('h', sys.argv[1])\n"
                 "h = u.module_from_spec(u.spec_from_loader('h', l)); l.exec_module(h)\n"
                 "h._scrub_environ(); print(sorted(os.environ.items()))",
                 os.path.join(_pb_root, "tools", "panel-helper")],
                capture_output=True, text=True, check=False, timeout=30,
                env={"BASH_ENV": "/x", "FOO": "1", "SUDO_UID": "5", "PATH": "/tmp:/usr/bin"})
check("helper: the __main__ block scrubs its own environment before any verb runs",
      "_scrub_environ()" in open(os.path.join(_pb_root, "tools", "panel-helper"), encoding="utf-8")
      .read().split('if __name__ == "__main__":')[1][:80]
      and "BASH_ENV" not in _r.stdout and "FOO" not in _r.stdout
      and "('PATH', '/usr/sbin:/usr/bin:/sbin:/bin')" in _r.stdout and "('SUDO_UID', '5')" in _r.stdout,
      _r.stdout + _r.stderr)
# install.sh writes the Defaults line for the helper, first, and visudo accepts the file.
_pb_wsg = _pb_shfn("write_sudoers_grant")
_pb_blk = _pb_wsg[_pb_wsg.index("        {\n            echo \"Defaults!"):]
_pb_blk = _pb_blk[:_pb_blk.index("} > /etc/sudoers.d/linuxgsm-panel") + 1]
_pb_sud = os.path.join(_PB, "linuxgsm-panel.sudoers")
check("install.sh: the helper's PATH in sudoers is the helper's own CHILD_PATH",
      'HELPER_SECURE_PATH="%s"' % _pbh.CHILD_PATH in _pb_inst)
_r = _pb_run(_pb_blk + " > " + _pb_sud,
             env={"HELPER_DST": "/usr/local/lib/linuxgsm-panel/panel-helper", "PANEL_USER": "lgsmpanel",
                  "GAME_GROUP": "lgsmpanel-games",
                  "HELPER_SECURE_PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
_pb_lines = open(_pb_sud, encoding="utf-8").read().splitlines() if os.path.exists(_pb_sud) else []
check("install.sh: the grant opens with `Defaults!<helper> env_reset, secure_path=...`",
      _pb_lines[:1] == ['Defaults!/usr/local/lib/linuxgsm-panel/panel-helper env_reset, '
                        'secure_path="/usr/sbin:/usr/bin:/sbin:/bin"'] and len(_pb_lines) == 3,
      repr(_pb_lines))
_pb_visudo = _pb_shutil.which("visudo") or ("/usr/sbin/visudo" if os.path.exists("/usr/sbin/visudo") else "")
if _pb_visudo and _PB_ROOT:
    _r = _pb_sp.run([_pb_visudo, "-cf", _pb_sud], capture_output=True, text=True, check=False)  # nosec B603 - fixed argv
    check("install.sh: ...and visudo -cf accepts the three lines", _r.returncode == 0,
          _r.stdout + _r.stderr)
else:
    _pb_skip("install.sh: visudo accepts the grant", "no visudo, or not root")
check("helper: the sudoers parser skips the Defaults! line (it is no user specification)",
      len(_pbh._sudoers_matching_rules(_pb_lines, "lgsmpanel", {"lgsmpanel"}, 998, {998})) == 2)

# ── 3. Hard links: never chmod'd (content-grant-read) or chowned (install.sh) as root ─────────
_pb_cg = os.path.join(_PB, "chmod")
os.makedirs(_pb_cg)
_pb_victim = os.path.join(_PB, "victim-file")
with open(_pb_victim, "w") as _fh:
    _fh.write("secret")
os.chmod(_pb_victim, 0o600)
os.link(_pb_victim, os.path.join(_pb_cg, "hl"))
with open(os.path.join(_pb_cg, "plain"), "w") as _fh:
    _fh.write("x")
os.chmod(os.path.join(_pb_cg, "plain"), 0o600)
_pb_dfd = os.open(_pb_cg, os.O_RDONLY | os.O_DIRECTORY)
try:
    _pbh._chmod_nofollow("hl", _pb_stat.S_IRGRP, dir_fd=_pb_dfd)
    _pbh._chmod_nofollow("plain", _pb_stat.S_IRGRP, dir_fd=_pb_dfd)
finally:
    os.close(_pb_dfd)
check("helper _chmod_nofollow: a hard-linked file (a second name for, say, /etc/shadow) is left "
      "alone", _pb_stat.S_IMODE(os.stat(_pb_victim).st_mode) == 0o600,
      oct(os.stat(_pb_victim).st_mode))
check("helper _chmod_nofollow: ...while a file with one name still gets g+r (control)",
      _pb_stat.S_IMODE(os.stat(os.path.join(_pb_cg, "plain")).st_mode) == 0o640)
_pb_inst_code = "\n".join(_ln for _ln in _pb_inst.splitlines() if not _ln.lstrip().startswith("#"))
check("install.sh: no recursive chown of the panel tree is left (comments aside)",
      'chown -R "${PANEL_USER}' not in _pb_inst_code and _pb_inst_code.count("_chown_panel_tree") == 5)
try:
    _pb_daemon = _pb_real_pwd.getpwnam("daemon")
    _pb_real_grp.getgrnam("daemon")
except KeyError:
    _pb_daemon = None
if _PB_ROOT and _pb_daemon is not None:
    _pb_pd = os.path.join(_PB, "chown", "panel")
    os.makedirs(os.path.join(_pb_pd, "sub"))
    for _n in ("plain", "sub/deep"):
        open(os.path.join(_pb_pd, _n), "w").close()
    _pb_v2 = os.path.join(_PB, "chown", "rootfile")
    open(_pb_v2, "w").close()
    os.link(_pb_v2, os.path.join(_pb_pd, "sub", "hl"))
    os.symlink(_pb_v2, os.path.join(_pb_pd, "sl"))
    _r = _pb_run("set -euo pipefail\nwarn() { echo \"WARN $*\"; }\n"
                 + _pb_shfn("_chown_panel_tree") + "_chown_panel_tree",
                 env={"PANEL_DIR": _pb_pd, "PANEL_USER": "daemon"})
    _pb_own = {n: os.lstat(os.path.join(_pb_pd, n)).st_uid
               for n in ("", "sub", "plain", "sub/deep", "sub/hl", "sl")}
    check("install.sh _chown_panel_tree: the tree, its directories and single-name files are "
          "the panel user's, a link is chowned as a link",
          _r.returncode == 0 and all(_pb_own[n] == _pb_daemon.pw_uid
                                     for n in ("", "sub", "plain", "sub/deep", "sl")),
          "%r %s" % (_pb_own, _r.stderr))
    check("install.sh _chown_panel_tree: ...but a hard link is NOT, nor its target, and it says so",
          _pb_own["sub/hl"] == 0 and os.stat(_pb_v2).st_uid == 0 and "sub/hl" in _r.stdout,
          "%r %r" % (_pb_own, _r.stdout))
else:
    _pb_skip("install.sh _chown_panel_tree: driven", "needs root and a daemon account")

# ── 4. The self-update installer runs from "/", and ignores its working directory ─────────────
_pb_seen = []
_pb_sub_saved = _pbh.subprocess
try:
    _pbh.subprocess = NS(run=lambda argv, **k: (_pb_seen.append(k), NS(returncode=0))[1],
                         STDOUT=_pb_sp.STDOUT, TimeoutExpired=_pb_sp.TimeoutExpired)
    _pbh._run_installer_to(None, "/home/lgsmpanel/linuxgsm-panel", {})
finally:
    _pbh.subprocess = _pb_sub_saved
check("helper self-update: the root installer starts in /, not in the panel-owned checkout",
      len(_pb_seen) == 1 and _pb_seen[0].get("cwd") == "/", repr(_pb_seen))
_pb_src_blk = _pb_inst[_pb_inst.index('SRC=""\nif [[ -n "${PANEL_SELF_UPDATE:-}" ]]'):]
_pb_src_blk = _pb_src_blk[:_pb_src_blk.index("\nfi\n") + 4]
_pb_ck = os.path.join(_PB, "checkout")
os.makedirs(_pb_ck)
for _n in ("app.py", "requirements.txt"):
    open(os.path.join(_pb_ck, _n), "w").close()
_pb_src = "ok() { :; }\nPANEL_SELF_UPDATE=\"${PSU:-}\"\n" + _pb_src_blk + 'echo "SRC=[${SRC}]"'
_r1 = _pb_run(_pb_src, cwd=_pb_ck)
_r2 = _pb_run(_pb_src, cwd=_pb_ck, env={"PSU": "1"})
check("install.sh: an operator run from a checkout uses it as the source (control)",
      "SRC=[%s]" % os.path.realpath(_pb_ck) in _r1.stdout or "SRC=[%s]" % _pb_ck in _r1.stdout,
      _r1.stdout + _r1.stderr)
check("install.sh: ...but a panel self-update never takes its working directory as the source",
      "SRC=[]" in _r2.stdout, _r2.stdout + _r2.stderr)
_pb_fc = _pb_shfn("fetch_code")
check("install.sh fetch_code: the extracting tar runs as PANEL_DIR's owner when that is not root",
      'x_as="sudo -u ${x_owner}"' in _pb_fc and '${x_as} tar -C "${PANEL_DIR}" --no-same-owner -xf -'
      in _pb_fc, _pb_fc[:200])

# ── 5. Root reads a file in the panel's tree as its owner: no link, no FIFO ──────────────────
_pb_rd = os.path.join(_PB, "reads", "panel")
os.makedirs(os.path.join(_pb_rd, "data"))
_pb_secret = os.path.join(_PB, "reads", "secret")
with open(_pb_secret, "w") as _fh:
    _fh.write('{"port": 7777}\nroot:$6$hash:1\n')
os.chmod(_pb_secret, 0o600)
_pb_ver_sh = ("set -euo pipefail\n" + _pb_shfn("_owner_read") + _pb_shfn("panel_port")
              + _pb_shfn("_epoch_version") + _pb_shfn("_version_file"))
_pb_cfg = os.path.join(_pb_rd, "data", "config.json")
with open(_pb_cfg, "w") as _fh:
    _fh.write('{"port": 5123}')
with open(os.path.join(_pb_rd, "VERSION"), "w") as _fh:
    _fh.write("0.9-hand\x1b]0;pwned\x07\n")
_r = _pb_run(_pb_ver_sh + "panel_port; _version_file", env={"PANEL_DIR": _pb_rd})
check("install.sh panel_port/_version_file: a real config and VERSION still read (control), with "
      "a terminal escape in VERSION stripped", _r.stdout.split("\n")[:2] == ["5123", "0.9-hand]0;pwned"],
      repr(_r.stdout))
os.remove(_pb_cfg)
os.symlink(_pb_secret, _pb_cfg)
os.remove(os.path.join(_pb_rd, "VERSION"))
os.symlink(_pb_secret, os.path.join(_pb_rd, "VERSION"))
_r = _pb_run(_pb_ver_sh + "panel_port; _version_file", env={"PANEL_DIR": _pb_rd})
check("install.sh: a config.json or VERSION symlinked to a root-only file is not read through "
      "(port 5000, version unknown; nothing of the file printed)",
      _r.stdout.split("\n")[:2] == ["5000", "unknown"] and "7777" not in _r.stdout
      and "hash" not in _r.stdout, repr(_r.stdout))
os.remove(_pb_cfg)
os.mkfifo(_pb_cfg)
try:
    # _owner_read itself, past panel_port's [[ -f ]]: the file can become a FIFO after that test.
    _r = _pb_run(_pb_ver_sh + '_owner_read "${PANEL_DIR}/data/config.json"; echo "[done]"',
                 env={"PANEL_DIR": _pb_rd}, timeout=20)
    _pb_fifo_ok = _r.stdout.strip() == "[done]"
except _pb_sp.TimeoutExpired:
    _pb_fifo_ok = False
check("install.sh _owner_read: a FIFO in place of config.json is refused, not waited on",
      _pb_fifo_ok)
if _PB_ROOT and _pb_daemon is not None and _pb_shutil.which("sudo"):
    os.remove(_pb_cfg)
    _pb_shutil.copy(_pb_secret, _pb_cfg)                      # a REAL file, root's, mode 0600
    os.chmod(_PB, 0o755)
    os.chmod(os.path.join(_PB, "reads"), 0o755)
    os.chown(_pb_rd, _pb_daemon.pw_uid, -1)
    os.chmod(_pb_rd, 0o755)
    os.chmod(os.path.join(_pb_rd, "data"), 0o755)
    _r = _pb_run(_pb_ver_sh + "panel_port", env={"PANEL_DIR": _pb_rd})
    check("install.sh panel_port: as root, a panel-owned tree is read AS ITS OWNER (a root-only "
          "file there is not read)", _r.stdout.strip() == "5000", repr(_r.stdout + _r.stderr))
    os.chmod(_PB, 0o700)
else:
    _pb_skip("install.sh panel_port: read as the owner", "needs root, sudo and a daemon account")
# uninstall.sh reads config.json the same way, and takes the sudo grants away first.
_pb_un = open(os.path.join(_pb_root, "uninstall.sh"), encoding="utf-8").read()
_pb_cr = _pb_un[_pb_un.index("_conf_read() {"):]
_pb_cr = _pb_cr[:_pb_cr.index("\n}\n") + 3]
_r = _pb_run("set -euo pipefail\n" + _pb_cr + '_conf_read "$F"; echo "[rc=$?]"',
             env={"PANEL_DIR": _pb_rd, "F": os.path.join(_pb_rd, "VERSION")}, timeout=20)
check("uninstall.sh _conf_read: a symlinked config.json is not followed",
      "hash" not in _r.stdout and "[rc=0]" in _r.stdout, repr(_r.stdout))
check("uninstall.sh: no python open() of a path in the panel's tree is left",
      "open('${PANEL_DIR}" not in _pb_un)
check("uninstall.sh: the sudoers grants and the game group go BEFORE the panel's files are removed",
      _pb_un.index("rm -f /etc/sudoers.d/linuxgsm-panel") < _pb_un.index('rm -rf "${PANEL_DIR}"')
      and "groupdel lgsmpanel-games" in _pb_un)

# ── 6. tailscale-up-login never writes through something planted at its /run log ─────────────
_pb_log = os.path.join(_PB, "ts-up.log")
_pb_tsv = os.path.join(_PB, "ts-victim")
with open(_pb_tsv, "w") as _fh:
    _fh.write("keep")


class _PbOs:
    """os, with unlink planting a symlink straight after it runs (the race O_EXCL closes)."""
    def __getattr__(self, name):
        return getattr(os, name)

    @staticmethod
    def unlink(p):
        try:
            os.unlink(p)
        finally:
            os.symlink(_pb_tsv, p)


_pb_ts_saved = (_pbh.os, _pbh.TS_UP_LOG, _pbh.TS_UP_POLL_SECONDS, _pbh.subprocess, _pbh.resolve)
_pb_popen = []
try:
    _pbh.TS_UP_LOG, _pbh.TS_UP_POLL_SECONDS = _pb_log, 0
    _pbh.resolve = lambda n: "/usr/bin/" + n
    _pbh.subprocess = NS(Popen=lambda *a, **k: _pb_popen.append(a), DEVNULL=_pb_sp.DEVNULL,
                         STDOUT=_pb_sp.STDOUT)
    _pb_rc_plain = _pbh.do_tailscale_up_login(["no", "-"], "")
    _pb_plain_mode = _pb_stat.S_IMODE(os.lstat(_pb_log).st_mode)
    _pbh.os = _PbOs()
    try:
        _pbh.do_tailscale_up_login(["no", "-"], "")
        _pb_raced = "wrote through it"
    except OSError as _e:
        _pb_raced = type(_e).__name__
finally:
    (_pbh.os, _pbh.TS_UP_LOG, _pbh.TS_UP_POLL_SECONDS, _pbh.subprocess, _pbh.resolve) = _pb_ts_saved
check("helper tailscale-up-login: the log is created fresh, 0600 (control)",
      _pb_rc_plain == 0 and _pb_plain_mode == 0o600 and len(_pb_popen) == 1,
      "rc=%s mode=%o" % (_pb_rc_plain, _pb_plain_mode))
check("helper tailscale-up-login: a symlink planted at the log path after the unlink is refused, "
      "and its target is not truncated", _pb_raced == "FileExistsError"
      and open(_pb_tsv, encoding="utf-8").read() == "keep", _pb_raced)

# ── 7. Remote content renderings act AS the content account, not as root ─────────────────────
_pb_rg = _pb_priv.remote_command("content-grant-read", ["cu", "cu", "gm", "cstrike"])
_pb_rr = _pb_priv.remote_command("content-game-remove", ["cu", "cstrike", "cssserver"])
check("privileged: the remote content grant's chmods run as the content account (a link in its "
      "tree cannot aim root's chmod -R), usermod stays root's",
      _pb_rg.startswith("usermod -aG cu gm; ")
      and all(p.startswith("runuser -u cu -- chmod ") for p in _pb_rg.split("; ")[1:])
      and _pb_rg.count("runuser -u cu -- chmod") == 3, _pb_rg)
check("privileged: ...and the remote content removal's rm -rf runs as that account too",
      _pb_rr.count("runuser -u cu -- rm -rf ") == 3 and "; rm -rf" not in _pb_rr, _pb_rr)
_pb_rm = _pb_priv.remote_command("gmod-mount-read", ["gm"])
check("privileged: ...and the remote mount.cfg read is the game account's (a link to /etc/shadow "
      "there is read with its rights, not root's)",
      _pb_rm.startswith("runuser -u gm -- cat /home/gm/serverfiles/garrysmod/cfg/mount.cfg"), _pb_rm)
# Driven, where it can be: the rendered grant as root against a content tree whose game directory
# is a link to a root-owned one. root's chmod -R used to follow it; the account's cannot touch it.
if _PB_ROOT and _pb_daemon is not None and _pb_shutil.which("runuser"):
    _pb_ct = tempfile.mkdtemp(prefix="lgsm-unit-pb-ct-")
    os.chmod(_pb_ct, 0o755)
    _pb_rootdir = os.path.join(_pb_ct, "rootdir")
    os.makedirs(_pb_rootdir)
    with open(os.path.join(_pb_rootdir, "f"), "w") as _fh:
        _fh.write("x")
    os.chmod(os.path.join(_pb_rootdir, "f"), 0o600)
    _pb_game = os.path.join(_pb_ct, "tree")
    os.makedirs(_pb_game)
    os.chown(_pb_game, _pb_daemon.pw_uid, -1)
    os.symlink(_pb_rootdir, os.path.join(_pb_game, "cstrike"))
    os.lchown(os.path.join(_pb_game, "cstrike"), _pb_daemon.pw_uid, -1)
    _pb_cmd = _pb_rg.split("; ")[-1].replace("/home/cu/serverfiles/cstrike",
                                             os.path.join(_pb_game, "cstrike")).replace("-u cu", "-u daemon")
    _r = _pb_run(_pb_cmd)
    check("privileged: (driven) the remote grant's chmod -R through a link to a root-owned tree "
          "changes nothing there", _pb_stat.S_IMODE(os.stat(os.path.join(_pb_rootdir, "f")).st_mode)
          == 0o600, "%s -> %o" % (_pb_cmd, os.stat(os.path.join(_pb_rootdir, "f")).st_mode))
    _pb_shutil.rmtree(_pb_ct, ignore_errors=True)
else:
    _pb_skip("privileged: (driven) remote grant as the content account", "needs root and runuser")

_pb_shutil.rmtree(_PB, ignore_errors=True)

# ── 8. The update's snapshot and rollback act in the panel-owned tree AS ITS OWNER ────────────
# install.sh's own lines, lifted out whole: the TREE_SUDO decision, [1/6]'s mkdir and code
# snapshot with snapshot_ok, and the health-check rollback's wipe-and-unpack of code and data.
_pb_inst = open(os.path.join(_pb_root, "install.sh"), encoding="utf-8").read()


def _pb_between(start, end, include_end=False):
    i = _pb_inst.index(start)
    j = _pb_inst.index(end, i)
    return _pb_inst[i:j + (len(end) if include_end else 0)]


_pb_tree = _pb_between('    TREE_SUDO=""\n', '    info "[1/6] Snapshotting')
_pb_snap = (_pb_between('    ${TREE_SUDO:-} mkdir -p -- "${BACKUP}"', "\n", include_end=True)
            + [ln for ln in _pb_inst.splitlines() if ln.strip().startswith("${TREE_SUDO:-} tar -C "
                                                                          '"${PANEL_DIR}" --ignore')][0]
            + "\n" + [ln for ln in _pb_inst.splitlines() if ln.strip().startswith("snapshot_ok() {")][0]
            + '\nsnapshot_ok "${BACKUP}/code.tgz" && echo SNAP_OK\n')
_pb_rb = _pb_between('    ${TREE_SUDO:-} find "${PANEL_DIR}" -mindepth 1 -maxdepth 1 \\\n        ! -name data',
                     "\n    install_deps || true")
check("install.sh: the snapshot, snapshot_ok and both rollbacks go through TREE_SUDO",
      "TREE_SUDO=\"sudo -u ${_tree_owner} env -C /\"" in _pb_tree
      and _pb_snap.count("${TREE_SUDO:-}") == 4 and _pb_rb.count("${TREE_SUDO:-}") == 4
      and _pb_inst.count('> "${BACKUP}/') == 0, _pb_snap + _pb_rb)
_pb_ph = "set -euo pipefail\ndie() { echo \"DIE: $*\"; exit 1; }\nSNAP_GZ='gzip -1'\n"
if _PB_ROOT and _pb_daemon is not None and _pb_shutil.which("sudo"):
    _pb_up = tempfile.mkdtemp(prefix="lgsm-unit-pb-upd-")
    os.chmod(_pb_up, 0o755)
    _pb_pd = os.path.join(_pb_up, "panel")
    _pb_rootdir = os.path.join(_pb_up, "rootonly")
    os.makedirs(os.path.join(_pb_pd, "data"))
    os.makedirs(_pb_rootdir)                                   # root's, 0755: daemon cannot write
    with open(os.path.join(_pb_pd, "app.py"), "w") as _fh:
        _fh.write("# app\n")
    with open(os.path.join(_pb_pd, "data", "config.json"), "w") as _fh:
        _fh.write('{"port": 5000}')
    _pb_sec = os.path.join(_pb_up, "secret")
    with open(_pb_sec, "w") as _fh:
        _fh.write("ROOT-ONLY-SECRET")
    os.chmod(_pb_sec, 0o600)
    for _d, _ds, _fs in os.walk(_pb_pd):
        for _n in [_d] + [os.path.join(_d, x) for x in _ds + _fs]:
            os.lchown(_n, _pb_daemon.pw_uid, _pb_daemon.pw_gid)
    os.link(_pb_sec, os.path.join(_pb_pd, "hl"))              # root's file, a second name in the tree
    # data/.backups planted as a link to a directory the panel user cannot write.
    os.symlink(_pb_rootdir, os.path.join(_pb_pd, "data", ".backups"))
    os.lchown(os.path.join(_pb_pd, "data", ".backups"), _pb_daemon.pw_uid, _pb_daemon.pw_gid)
    _pb_env = {"PANEL_DIR": _pb_pd, "BACKUP": os.path.join(_pb_pd, "data", ".backups", "20260101-000000")}
    _r = _pb_run(_pb_ph + _pb_tree + _pb_snap, env=_pb_env)
    check("install.sh [1/6]: a data/.backups linked to a root-owned directory gets nothing from root"
          " (the mkdir runs as the panel user, and fails)",
          os.listdir(_pb_rootdir) == [] and "SNAP_OK" not in _r.stdout, "%r %r" % (os.listdir(_pb_rootdir), _r.stdout))
    os.unlink(os.path.join(_pb_pd, "data", ".backups"))
    _r = _pb_run(_pb_ph + _pb_tree + _pb_snap, env=_pb_env)
    _pb_tgz = os.path.join(_pb_env["BACKUP"], "code.tgz")
    _pb_members, _pb_hl_body = [], b""
    if os.path.exists(_pb_tgz):
        import tarfile as _pb_tar
        with _pb_tar.open(_pb_tgz) as _t:
            _pb_members = _t.getnames()
            _pb_hl_body = b"".join(_t.extractfile(m).read() for m in _t.getmembers()
                                   if m.isfile() and m.name.endswith("hl"))
    check("install.sh [1/6]: the snapshot is still made, and is the panel user's (control)",
          "SNAP_OK" in _r.stdout and "./app.py" in _pb_members
          and os.stat(_pb_tgz).st_uid == _pb_daemon.pw_uid, "%r %r" % (_r.stdout, _pb_members))
    check("install.sh [1/6]: a hard link to a root-only file is NOT copied into the panel-readable "
          "snapshot", b"ROOT-ONLY-SECRET" not in _pb_hl_body and _pb_members != [], repr(_pb_members))
    # The rollback, from that snapshot plus a data snapshot: the tree comes back, as the owner's.
    _pb_run("tar -C %s -czf %s/data.tgz ." % (os.path.join(_pb_pd, "data"), _pb_env["BACKUP"]))
    os.remove(os.path.join(_pb_pd, "app.py"))
    with open(os.path.join(_pb_pd, "newfile.py"), "w") as _fh:
        _fh.write("# added by the failed version\n")
    _r = _pb_run(_pb_ph + _pb_tree + _pb_rb + '\necho RB_DONE\n', env=_pb_env)
    check("install.sh rollback: the previous code and data come back, unpacked as the panel user",
          "RB_DONE" in _r.stdout and os.path.exists(os.path.join(_pb_pd, "app.py"))
          and not os.path.exists(os.path.join(_pb_pd, "newfile.py"))
          and os.stat(os.path.join(_pb_pd, "app.py")).st_uid == _pb_daemon.pw_uid
          and os.path.exists(os.path.join(_pb_pd, "data", "config.json")),
          "%r %r" % (_r.stdout, _r.stderr))
    check("install.sh rollback: ...and root's file behind the hard link is untouched",
          open(_pb_sec).read() == "ROOT-ONLY-SECRET" and os.stat(_pb_sec).st_uid == 0)
    _pb_shutil.rmtree(_pb_up, ignore_errors=True)
else:
    _pb_skip("install.sh snapshot/rollback as the tree's owner (driven)", "needs root, sudo and daemon")
# SECURITY.md documents the grant install.sh now writes, Defaults line included.
_pb_secdoc = open(os.path.join(_pb_root, ".github", "SECURITY.md"), encoding="utf-8").read()
check("docs: SECURITY.md shows the helper's Defaults! line exactly as install.sh writes it",
      'Defaults!/usr/local/lib/linuxgsm-panel/panel-helper env_reset, secure_path="%s"'
      % _pbh.CHILD_PATH in _pb_secdoc and "#!/usr/bin/python3 -I" in _pb_secdoc
      and "after copying its own" not in _pb_secdoc)
