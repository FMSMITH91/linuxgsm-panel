"""Part 18 of the unit suite: every worker that holds a row, against an id another row took.

SQLite handed a deleted row's id to the next INSERT (a plain INTEGER PRIMARY KEY is the rowid), and
the panel's workers run for seconds to half an hour between loading their host or game server and
writing their outcome to it or acting on it again. Each block below starts one worker, and while
its long step is in flight (inside the stub of the SSH call it makes) deletes its row and inserts a
new row WITH THE SAME ID — an explicit id, so the block works whatever the table's schema — and
then asserts what the worker wrote, and where it acted, once the step returned. Most blocks also
commit the worker's own session in that step, as the first SSH contact with a host does (it pins
the host key): that commit is what made the ORM reload a held object from the row that took the id.

The second half is the class fix: AUTOINCREMENT on the tables whose ids are kept (models,
panel/db/id_sequence.py), replayed on databases built from the schema before it, and read back
through the backup, restore-validation and salvage paths that touch the file.

HOW THE APP IS BUILT. As part16 does: part12's Flask app, database and client helpers, part12's
tripwire and deferred-thread queue re-armed for this part's duration, everything restored in the
finally, and a closing check that nothing reached a transport and no worker was left queued.
"""
import datetime as _dt18
import os
import sqlite3 as _sq18
import tarfile as _tar18
import tempfile as _tf18
from types import SimpleNamespace as NS

import sqlalchemy as _sa18
from flask import Flask as _Flask18

from unit import idreuse_support as _reuse18
from unit.part01 import check
from unit.part12 import (P9_ADMIN, _P9_CFG_PATH, _P9_TRIPPED, _P9Thread, _p9, _p9_app, _p9_auth,
                         _p9_banlist, _p9_cfg, _p9_client, _p9_core, _p9_drain, _p9_fake_time,
                         _p9_json, _p9_notif, _p9_patch, _p9_queue, _p9_restore_all, _p9_sm,
                         _p9_so, _p9_state, _p9_supervised, _p9_threading, _p9_trip, _p9_ts)
import db_maintenance as _dbm18
from panel.db import models as _m18
from panel.db.models import (AuditLog, GameServer, GlobalBan, MetricSample, RemoteServer,
                             RowReplaced, User, db)
from panel.ops import backup as _bk18
from panel.routes import _shared as _sh18
from panel.routes import api as _api18
from panel.routes import custom_commands as _cc18
from panel.routes import manage_servers as _ms18
from panel.routes import panel_backup as _pb18
from panel.routes import server_detail as _sd18
from panel.routes import server_files as _sf18
from panel.services import monitoring as _mon18

_XHR18 = {"X-Requested-With": "XMLHttpRequest"}
_TRIP18_START = len(_P9_TRIPPED)
_CFG18_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None
_MODS18 = (_sh18, _ms18, _sf18, _sd18, _pb18, _cc18)
_saved18_threading = {m: m.threading for m in _MODS18 if hasattr(m, "threading")}
_saved18_time = {m: m.time for m in _MODS18 if hasattr(m, "time")}
_saved18_listeners = dict(_p9_banlist._listeners)
_saved18_log = (_p9.logger.disabled, _p9_app._log.disabled)
_saved18_maps = [(m, dict(m)) for _entries in _p9_state.keyed_state_with_locks()
                 for m, _lk in _entries]
_saved18_monitor = {k: dict(v) for k, v in _p9_state._monitor_state.items()}
_saved18_osu_run = _p9_state._os_update_state["last_run"]
_mine18 = {"hosts": [], "servers": [], "bans": []}   # every row this part made, deleted at the end


class _SyncPool18:
    """ThreadPoolExecutor, run in order on the calling thread.

    The blocks need a deterministic order between one job's step and the next job's lookup.
    """

    def __init__(self, max_workers=None):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def map(self, fn, items):
        return [fn(i) for i in items]


_SYNC18 = NS(futures=NS(ThreadPoolExecutor=_SyncPool18))


def _ctx18():
    return _p9.app_context()


def _host18(name, host):
    with _ctx18():
        r = RemoteServer(name=name, host=host, port=22, username="root", auth_method="key",
                         auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        _mine18["hosts"].append(r.id)
        return r.id


def _server18(rid, short, port, **kw):
    with _ctx18():
        gs = GameServer(remote_id=rid, name=kw.pop("name", "p18-" + short), short_name=short,
                        game_type=kw.pop("game_type", "csgo"), port=port,
                        installed=kw.pop("installed", True), status=kw.pop("status", "offline"),
                        **kw)
        db.session.add(gs)
        db.session.commit()
        _mine18["servers"].append(gs.id)
        return gs.id


def _take_server18(sid, rid=None, **fields):
    """Delete server `sid` and create another WITH ITS ID, as another request would.

    `rid` is the new server's host (the old one's by default).
    """
    with _ctx18():
        old = db.session.get(GameServer, sid)
        if old is not None:              # (a host delete may have taken it already)
            rid = rid if rid is not None else old.remote_id
            db.session.delete(old)
            db.session.commit()
        new = GameServer(id=sid, remote_id=rid, name=fields.pop("name", "p18-taker"),
                         short_name=fields.pop("short_name", "takerserver"),
                         game_type=fields.pop("game_type", "csgo"), port=fields.pop("port", 27600),
                         installed=fields.pop("installed", True),
                         status=fields.pop("status", "offline"), **fields)
        db.session.add(new)
        db.session.commit()
    return sid


def _take_host18(rid, host="192.0.2.199", name="p18-taker-host"):
    """Delete host `rid` with its servers, as delete_remote does, and create another WITH ITS ID."""
    with _ctx18():
        GameServer.query.filter_by(remote_id=rid).delete()
        db.session.delete(db.session.get(RemoteServer, rid))
        db.session.commit()
        db.session.add(RemoteServer(id=rid, name=name, host=host, port=22, username="root",
                                    auth_method="key", auth_credential="", is_online=True))
        db.session.commit()
    return rid


def _row18(model, rid):
    """The row's columns as a namespace, or None when there is no such row."""
    with _ctx18():
        r = db.session.get(model, rid)
        return None if r is None else NS(**{c.name: getattr(r, c.name)
                                            for c in model.__table__.columns})


def _audits18(action):
    with _ctx18():
        return [NS(target=a.target, game_server_id=a.game_server_id, remote_id=a.remote_id,
                   success=a.success, detail=a.detail or "")
                for a in AuditLog.query.filter_by(action=action).order_by(AuditLog.id).all()]


def _pin_commit18():
    """What a first SSH contact does in the worker's own session: commit (the host-key pin)."""
    db.session.commit()


def _supervised18(name):
    """The loop body register_routes handed its supervisor under `name` (part12 never starts it)."""
    for runner in _p9_supervised:
        cells = dict(zip(runner.__code__.co_freevars,
                         (c.cell_contents for c in runner.__closure__ or ())))
        if cells.get("name") == name:
            return cells.get("target")
    return None


class _Stop18(Exception):
    """Raised by the fake sleep to end a supervised loop after one pass."""


def _one_pass18(loop, long_sleep):
    """Run a supervised loop until it sleeps `long_sleep` seconds (the end of its first pass)."""
    def _sleep(s):
        if s == long_sleep:
            raise _Stop18()
    saved = _p9_app.time
    _p9_app.time = NS(time=saved.time, sleep=_sleep, monotonic=saved.monotonic)
    try:
        loop()
    except _Stop18:
        return True
    finally:
        _p9_app.time = saved
    return False


def _only_installed18(keep):
    """Mark every installed server outside `keep` not installed; returns the ids, for _reinstall18."""
    with _ctx18():
        changed = [g.id for g in GameServer.query.filter_by(installed=True).all()
                   if g.id not in keep]
        for gid in changed:
            db.session.get(GameServer, gid).installed = False
        db.session.commit()
    return changed


def _reinstall18(ids):
    with _ctx18():
        for gid in ids:
            g = db.session.get(GameServer, gid)
            if g is not None:
                g.installed = True
        db.session.commit()


def _only_flagged18(keep, flags):
    """Clear the boolean columns `flags` on every server outside `keep`."""
    with _ctx18():
        for g in GameServer.query.all():
            if g.id not in keep:
                for f in flags:
                    setattr(g, f, False)
        db.session.commit()


def _only_status18(keep, statuses, to):
    """Every server outside `keep` whose status is in `statuses` is set to `to`."""
    with _ctx18():
        for g in GameServer.query.filter(GameServer.status.in_(statuses)).all():
            if g.id not in keep:
                g.status = to
        db.session.commit()


def _raises18(fn, *a, **k):
    """None when fn(*a, **k) returns; repr of what it raised otherwise (the regression)."""
    try:
        fn(*a, **k)
    except Exception as e:  # noqa: BLE001 - a raise is the regression these checks look for
        return repr(e)
    return None


def _commit18():
    """'wrote' when the session's commit landed, 'refused' when RowReplaced refused it."""
    try:
        db.session.commit()
    except RowReplaced:
        db.session.rollback()
        return "refused"
    return "wrote"


def _reads18(obj, attrs):
    """Each attribute of `obj`, or 'refused' where reading it raised RowReplaced."""
    out = []
    for a in attrs:
        try:
            out.append(getattr(obj, a))
        except RowReplaced:
            out.append("refused")
    return out


def _cache18(rows):
    """_bg_cache_commands for `rows` with their identities; without, on a tree that has none."""
    ids = [g.id for g in rows]
    try:
        _sh18._bg_cache_commands(_p9, ids, autostart_ids=ids,
                                 births={g.id: _m18.row_birth(g) for g in rows})
    except TypeError:       # a tree without `births`: the checks after it then fail by name
        _sh18._bg_cache_commands(_p9, ids, autostart_ids=ids)


def _forget_sids18(sids):
    from panel.routes import host_terminal as _ht
    with _ht._sid_lock:
        for sid in sids:
            _ht._sid_host.pop(sid, None)
            _ht._sid_owner.pop(sid, None)


def _restore18():
    """Everything this part replaced, put back; its own rows deleted. The part's `finally`."""
    for m, t in _saved18_threading.items():
        m.threading = t
    for m, t in _saved18_time.items():
        m.time = t
    _p9_restore_all()
    _p9_banlist._listeners.clear()
    _p9_banlist._listeners.update(_saved18_listeners)
    _p9.logger.disabled, _p9_app._log.disabled = _saved18_log
    for m, v in _saved18_maps:
        m.clear()
        m.update(v)
    for k, v in _saved18_monitor.items():
        _p9_state._monitor_state[k].clear()
        _p9_state._monitor_state[k].update(v)
    _p9_state._os_update_state["last_run"] = _saved18_osu_run
    if _p9_state._full_backup_lock.locked():
        _p9_state._full_backup_lock.release()
    _raises18(_delete_mine18)
    _raises18(_restore_config18)


def _delete_mine18():
    with _p9.app_context():
        GlobalBan.query.filter(GlobalBan.id.in_(_mine18["bans"])).delete(synchronize_session=False)
        for gid in _mine18["servers"]:
            g = db.session.get(GameServer, gid)
            if g is not None:
                db.session.delete(g)
        for rid in _mine18["hosts"]:
            GameServer.query.filter_by(remote_id=rid).delete()
            r = db.session.get(RemoteServer, rid)
            if r is not None:
                db.session.delete(r)
        db.session.commit()
        db.session.remove()


def _restore_config18():
    if _CFG18_SNAPSHOT is None:
        if _P9_CFG_PATH.exists():
            _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFG18_SNAPSHOT)


_NO_LOGIN18 = _p9_auth.hash_password(os.urandom(12).hex())   # a hash nobody holds the password of


# ── The stubs the blocks below install: each stands in for one host call and, while that call
# ── is "in flight", deletes the worker's row and gives its id to a new one. Module level, not
# ── inside the try, so each is a function of its own rather than a branch of the try.
def _prepare18(remote, remote_id, short_name, fresh):
    if _inst18["swap"]:
        _pin_commit18()
        # The operator deletes the host mid-install; a host added next takes its id, and the
        # first server installed on it takes the server's id and queues its own job.
        _take_host18(_ih18, host="192.0.2.182", name="p18-install-taker")
        _take_server18(_is18, rid=_ih18, name="p18-install-taker", short_name="takerserver",
                       installed=False, status="installing")
        with _ctx18():
            _ms18._queue_install_job(db.session.get(GameServer, _is18), [])
    return True, "", False


def _deps18(job, remote):
    job.p(2, "Installing dependencies")
    _inst18["cmds"].append(("deps", remote.host))


def _lgsm18(job, remote):
    job.p(3, "Downloading LinuxGSM")
    _inst18["cmds"].append(("lgsm", remote.host))
    return False


def _gameuser18(server, user, action, timeout=60, selfname=None, answers=None, tee_log=False):
    _pw18["runs"].append((server.host, user, action))
    if user == "powserver" and _pw18.get("swap"):
        _pw18["swap"] = False
        _pin_commit18()
        _take_server18(_ps18, name="p18-power-taker", short_name="takerserver",
                       restart_pending=True, stop_pending=True)
    return ("done", "", 0)


def _gameuser18_long(server, user, action, timeout=60, selfname=None, answers=None,
                     tee_log=False):
    _pw18["runs"].append((server.host, user, action))
    if user == "longserver":
        _take_server18(_ps18b, name="p18-long-taker", short_name="takerserver")
    return ("mods updated", "", 0)


def _gameuser18_sync(server, user, action, timeout=60, selfname=None, answers=None,
                     tee_log=False):
    _pin_commit18()
    _take_server18(_ps18d, name="p18-sync-taker", short_name="synctakerserver")
    return ("Status: STARTED", "", 0)


def _moderate18(server, short, game_type, action, **kw):
    _bans18.append(short)
    if short == "banone":
        _take_server18(_b218, name="p18-ban-taker", short_name="bantakerserver",
                       game_type="csgo")
    return True, "Done."


def _list18(remote, short, selfname=None):
    _cmds18.append(short)
    if short == "cmdone":
        _take_server18(_c218, name="p18-cmd-taker", short_name="cmdtakerserver")
    return [{"cmd": "monitor", "short": "m", "desc": "d"}]


def _pubip18(remote):
    _pin_commit18()
    _take_host18(_iph18, host="192.0.2.188", name="p18-ip-taker")
    return "203.0.113.77"


def _tz18(remote):
    # No commit here, unlike the address read above: the row is never reloaded, so only the
    # flush check stands between this write and the host that took the id.
    _take_host18(_tzh18, host="192.0.2.190", name="p18-tz-taker")
    return "America/Chicago"


def _gbackup18(remote, short, lgsm, keep, **kw):
    _bkruns18.append(short)
    if short == "bkone":
        _pin_commit18()
        _take_server18(_bk118, name="p18-bk-taker", short_name="bktakerserver",
                       backup_pending=True)
    return (True, "", False)


def _gbackup18_full(remote, short, lgsm, keep, **kw):
    _bkruns18.append(short)
    if short == "bkone":
        _take_server18(_bk118b, name="p18-bk-taker", short_name="bktakerserver",
                       backup_pending=True)
    return (True, "", False)


def _age18(sid):
    def _mut(cfg):
        cfg.setdefault("game_schedules", {}).setdefault(str(sid), {})["last"] = 1.0
    _p9_cfg.update_config(_mut)


def _gbackup18_sched(remote, short, lgsm, keep, **kw):
    _bkruns18.append(short)
    if short == "bktwo":
        _take_server18(_bk218, name="p18-sched-taker", short_name="schedtakerserver")
    return (False, "disk full", False)


def _gbackup18_queue(remote, short, lgsm, keep, **kw):
    _bkruns18.append(short)
    if short == "qone":
        _take_server18(_q118, name="p18-q-taker", short_name="qtakerserver",
                       backup_pending=True)
    return (True, "", False)


def _gameuser18_queued(server, user, action, timeout=60, selfname=None, answers=None,
                       tee_log=False):
    _rs18.append(user)
    if user == "rsone":
        _take_server18(_r118, name="p18-rs-taker", short_name="rstakerserver", status="online",
                       restart_pending=True)
    return ("", "", 0)


def _status18_idle(remote, gs, **k):
    if gs.short_name == "rsidle" and _rsi18["swap"]:
        _rsi18["swap"] = False
        _take_server18(_rsi18["id"], name="p18-rsi-taker", short_name="rsitakerserver",
                       status="online", restart_pending=True)
        return "offline"          # found stopped: the sweep clears the flags without a reload
    return "online"


def _shell18(server, user, sh, timeout=30, selfname=None):
    _xs18.append(user)
    if user == "xone":
        _take_server18(_x118, name="p18-x-taker", short_name="xtakerserver",
                       installed=False, status="installing")
    return ("Status: STOPPED", "", 0)


def _reach18(remote):
    if remote.id == _mh18 and remote.host == "192.0.2.197":
        _take_host18(_mh18, host="192.0.2.170", name="p18-mon-taker")
        _take_server18(_ms118, rid=_mh18, name="p18-mon-taker", short_name="montakerserver",
                       port=27590, status="offline")
    return True


def _slots18(gs, primary=None):
    if gs.id == _pl118 and gs.short_name == "plone":
        _take_server18(_pl118, name="p18-pl-taker", short_name="pltakerserver",
                       status="online")
        return gs.id, (7, 10, "Old Server's In-Game Name")
    return gs.id, (0, 10, "x")


def _hostmetrics18(work, **_k):
    remote, games = work
    out = []
    for sid, _short, _port, _gt, _qt in games:
        if sid == _sp118:
            _take_server18(_sp118, name="p18-sp-taker", short_name="sptakerserver")
        out.append((sid, {"ram_total": 1000, "ram_used": 1, "cpu_percent": 1,
                          "game_cpu_percent": 5, "game_ram_mb": 50}, remote.id, ""))
    return out


def _ports18(remote):
    if remote.id == _dh18:
        _take_server18(_ds118, name="p18-dash-taker", short_name="dashtakerserver",
                       status="online")
    return set()


def _ensure18(remote):
    _nt18.append(remote.host)
    if remote.id == _nh118:
        _take_host18(_nh218, host="192.0.2.176", name="p18-nt-taker")


def _steamban18(remote, short, lgsm, steamid, unban=False):
    _gbans18.append(short)
    if short == "gbone":
        _take_server18(_gb218, name="p18-gb-taker", short_name="gbtakerserver",
                       game_type="csgo")
    return True, "banned"


def _bulk18(remote, users):
    _renice18.append((remote.host, tuple(users)))
    if remote.id == _kh18:
        _take_host18(_kh218, host="192.0.2.160", name="p18-keep-taker")


def _osucheck18(remote):
    # No commit in the sweep's own session: the checks run on pool threads, and a first
    # contact's pin is stored from there in a session of its own.
    if remote.id == _oh18 and remote.host == "192.0.2.163":
        _take_host18(_oh18, host="192.0.2.164", name="p18-osu-taker")
    return {"ok": True, "packages": [{"name": "openssl-p18", "suite": "noble-security"}]}


def _prepare18_gone(remote, remote_id, short_name, fresh):
    # The operator deletes the server mid-install. Nothing takes its id, and the worker's own
    # session is not committed, so none of the objects it holds reload.
    with _ctx18():
        db.session.delete(db.session.get(GameServer, _inst18["gone"]))
        db.session.commit()
    return True, "", False


def _steamban18_pin(remote, short, lgsm, steamid, unban=False):
    _fb18["bans"].append((short, steamid))
    if short == _fb18["first"] and _fb18["swap"]:
        _fb18["swap"] = False
        # The first contact with the host pins its key, committing the pass's own session.
        _pin_commit18()
        _take_server18(_fb18["next"], name="p18-fb-taker", short_name="fbtakerserver",
                       game_type="csgo")
    return True, "banned"


def _steamban18_record(remote, short, lgsm, steamid, unban=False):
    _gbx18.append((short, steamid, unban))
    return True, "banned"


def _fb_servers18(prefix, port, addr):
    """Three installed valve servers on one new host, the only installed ones; the others' ids."""
    rid = _host18("p18-%s-host" % prefix, addr)
    ids = [_server18(rid, "%s%s" % (prefix, n), port + i, game_type="csgo")
           for i, n in enumerate(("one", "two", "three"))]
    _fb18.update(bans=[], swap=True, first=prefix + "one", next=ids[1])
    return ids, _only_installed18(set(ids))


def _abreconcile18(remote):
    _ab18["hosts"].append(remote.host)
    event, _ab18["event"] = _ab18["event"], None
    if event is not None:
        event([i for i in _ab18["pair"] if i != remote.id][0])
    return 0, 0


def _ab_deleted18(other):
    """The other host is deleted as delete_remote does (its opt-in dropped); a new one takes its id."""
    from panel.routes import remotes as _rm18
    _rm18._forget_deleted_remote_config(other, [])
    _take_host18(other, host="192.0.2.159", name="p18-ab-taker")


def _ab_kept18(other):
    """...the same, but the config write that drops its opt-in did not land (it is best-effort)."""
    _take_host18(other, host="192.0.2.158", name="p18-ab-taker2")


def _ab_tick18(addrs, event):
    """One hourly auto-block tick over two new opted-in hosts at `addrs`.

    `event(other_id)` runs while the first of them is being reconciled. Returns (whether one tick
    ran, the addresses reconciled).
    """
    ids = [_host18("p18-ab-%s" % a.rsplit(".", 1)[1], a) for a in addrs]
    _ab18.update(hosts=[], pair=ids, event=event)
    _p9_cfg.update_config(lambda cfg: cfg.update({"autoblock_hosts": sorted(ids)}))
    ran = _ticks18(_p9_app._autoblock_watch, 3600)
    _p9_cfg.update_config(lambda cfg: cfg.update({"autoblock_hosts": []}))
    return ran, list(_ab18["hosts"])


def _ticks18(loop, seconds):
    """Run `loop(app)`, which sleeps `seconds` BEFORE each pass, for exactly one pass."""
    slept = []

    def _sleep(s):
        if s == seconds:
            slept.append(s)
            if len(slept) > 1:
                raise _Stop18()
    saved = _p9_app.time
    _p9_app.time = NS(time=saved.time, sleep=_sleep, monotonic=saved.monotonic)
    try:
        loop(_p9)
    except _Stop18:
        return True
    finally:
        _p9_app.time = saved
    return False


def _outcome18(fn, *a):
    """('returned', value), or ('raised', repr) when fn(*a) raised."""
    try:
        return "returned", fn(*a)
    except Exception as e:  # noqa: BLE001 - a raise is what these checks look for
        return "raised", repr(e)


def _ban_add18(steamid):
    with _ctx18():
        gb = GlobalBan(steamid=steamid, created_by="p18")
        db.session.add(gb)
        db.session.commit()
        _mine18["bans"].append(gb.id)
        return gb.id


try:
    for _m in _saved18_threading:
        _m.threading = _p9_threading(_P9Thread)
    for _m in _saved18_time:
        _m.time = _p9_fake_time
    _p9.logger.disabled = True
    _p9_app._log.disabled = True
    if _P9_CFG_PATH.exists():
        _P9_CFG_PATH.unlink()
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), setup_complete=True))

    # part12's tripwire, again: nothing below may reach a host or run a command on this machine.
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part18's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9_so, "_git", _p9_trip("system_ops._git"))
    _p9_patch(_p9_ts, "get_tailscale_info",
              lambda force_refresh=False: NS(dns_name=None, installed=False))
    _N18 = []
    _p9_patch(_p9_notif, "notify", lambda key, title, body="": _N18.append((key, title, body)))
    _p9_patch(_p9.socketio, "emit", lambda event, data=None, **k: None)
    # A long action's console tail reads the host's output file through this.
    _p9_patch(_p9_sm, "shell_as_game_user", lambda server, user, sh, **k: ("", "", 1))
    _A18 = _p9_client(P9_ADMIN)

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # The identity guard (models.RowReplaced): a held row whose id another row took
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _gh18 = _host18("p18-guard-host", "192.0.2.180")
    _gs18 = _server18(_gh18, "guardserver", 27500, name="p18-guard")
    with _ctx18():
        _held18 = db.session.get(GameServer, _gs18)
        _held18_name = _held18.name
        _take_server18(_gs18, name="p18-guard-taker", restart_pending=True)
        _g18_replaced = _m18.replaced_since_loaded(_held18)
        _g18_still = _m18.still_held(_held18)
        _g18_ref = _p9_auth._audit_ref(GameServer, _held18)
        _held18.restart_pending = False           # a write through the held, un-reloaded object
        _g18_flush = _commit18()
        _g18_reads = _reads18(_held18, ("name", "short_name", "id"))
    check("guard: the held object knows its id now names another row",
          _g18_replaced is True and _g18_still is False, repr((_g18_replaced, _g18_still)))
    check("guard: a write through it is refused, and the row that took the id keeps its values",
          _g18_flush == "refused" and _row18(GameServer, _gs18).restart_pending is True,
          repr((_g18_flush, _row18(GameServer, _gs18))))
    check("guard: ...and every later read of it is refused, never the other row's values",
          _g18_reads == ["refused", "refused", "refused"], repr(_g18_reads))
    check("guard: an audit row about it is filed under no server, not the one that took the id",
          _g18_ref is None, repr(_g18_ref))
    with _ctx18():
        _ok18 = db.session.get(GameServer, _gs18)
        _ok18.status = "online"
        db.session.commit()
        _ok18_name, _ok18_ref = _ok18.name, _p9_auth._audit_ref(GameServer, _ok18)
        _ok18.created_at = _dt18.datetime(2020, 1, 1)     # the row's own write of its identity
        db.session.commit()
        _ok18_after = (_ok18.name, _m18.still_held(_ok18))
    check("guard: a row that is still itself reads, writes and is audited as before (control)",
          _ok18_name == "p18-guard-taker" and _ok18_ref is not None
          and _row18(GameServer, _gs18).status == "online"
          and _ok18_after == ("p18-guard-taker", True), repr((_ok18_name, _ok18_after)))
    with _ctx18():
        _loaded18 = db.session.get(GameServer, _gs18)
        _born18 = _m18.row_birth(_loaded18)
    _take_server18(_gs18, name="p18-guard-third")
    with _ctx18():
        _g18_same = (_m18.same_row(GameServer, _gs18, _born18),
                     _m18.claim_row(GameServer, _gs18, _born18) is None,
                     _m18.taken_by_another(GameServer, _gs18, _born18),
                     _m18.claim_row(GameServer, _gs18, _m18._NO_BIRTH) is not None,
                     _m18.taken_by_another(GameServer, 987654, _born18))
    check("guard: by id, a lookup names the row a caller saw only while it holds the id",
          _g18_same == (None, True, True, True, False), repr(_g18_same))
    check("guard: the row that took the id is not the one the caller saw",
          _held18_name == "p18-guard" and _row18(GameServer, _gs18).name == "p18-guard-third")
    from sqlalchemy.orm import load_only as _load_only18
    with _ctx18():
        _part18 = (db.session.query(GameServer).options(_load_only18(GameServer.name))
                   .filter(GameServer.id == _gs18).one())
        _part18_read = _reads18(_part18, ("name", "status")) + [_m18.still_held(_part18)]
    check("guard: a row loaded without created_at is not taken for a replaced one when the rest "
          "loads", _part18_read == ["p18-guard-third", "offline", True], repr(_part18_read))
    # A row this session inserted and then held without a read: its identity is the one it was
    # inserted with (the after_insert listener), not whatever its first reload finds.
    with _ctx18():
        _ins18 = GameServer(remote_id=_gh18, name="p18-guard-new", short_name="guardnewserver",
                            game_type="csgo", port=27501, installed=True, status="offline")
        db.session.add(_ins18)
        db.session.commit()                # expires it: nothing of it is loaded now
        _ins18_id = _sa18.inspect(_ins18).identity[0]      # read without loading it
        _mine18["servers"].append(_ins18_id)
        _take_server18(_ins18_id, name="p18-guard-new-taker", status="online")
        _ins18_held = _m18.still_held(_ins18)
        _ins18_reads = _reads18(_ins18, ("name",))
        _ins18.status = "installing"
        _ins18_flush = _commit18()
    check("guard: a row inserted and held unread knows its id was taken (its birth is the insert's)",
          _ins18_held is False and _ins18_reads == ["refused"],
          repr((_ins18_held, _ins18_reads)))
    check("guard: ...and a write through it is refused, the row that took the id keeping its values",
          _ins18_flush == "refused" and _row18(GameServer, _ins18_id).status == "online",
          repr((_ins18_flush, _row18(GameServer, _ins18_id).status)))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # The install job (manage_servers): its entry, its row, and the host its steps run on
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _ih18 = _host18("p18-install-host", "192.0.2.181")
    _is18 = _server18(_ih18, "instserver", 27510, installed=False, status="installing")
    _inst18 = {"cmds": [], "swap": True}

    _p9_patch(_ms18, "prepare_install_account", _prepare18)
    _p9_patch(_ms18, "_install_dependencies", _deps18)
    _p9_patch(_ms18, "_install_linuxgsm", _lgsm18)
    _run_job18 = _ms18._install_job_runner(_p9)
    with _ctx18():
        _ms18._queue_install_job(db.session.get(GameServer, _is18), [])
    _run_job18(_is18, _ih18, "instserver", "csgo", "csgoserver", 27510, [], fresh=True)
    _fn, _a, _k = _p9_queue.pop(0)
    _fn(*_a, **_k)
    _ij18 = dict(_p9_state._install_jobs.get(_is18) or {})
    check("install: the next server's own job is untouched (still queued, no foreign step)",
          _ij18.get("step_name") == "Queued" and _ij18.get("status") == "running"
          and not _ij18.get("log"), repr(_ij18))
    _ir18 = _row18(GameServer, _is18)
    check("install: the server that took the id is not marked failed, configuring or installed",
          _ir18.status == "installing" and not _ir18.install_error and _ir18.installed is False,
          repr((_ir18.status, _ir18.install_error, _ir18.installed)))
    check("install: no step ran on the host that took the id (the job stopped at the next step)",
          not any(_h == "192.0.2.182" for _s, _h in _inst18["cmds"]), repr(_inst18["cmds"]))
    with _p9_state._install_lock:
        _p9_state._install_jobs.pop(_is18, None)
    # Control: the same job with nothing deleted runs its next step, on its own host.
    _ih18b = _host18("p18-install-host2", "192.0.2.183")
    _is18b = _server18(_ih18b, "inst2server", 27511, installed=False, status="installing")
    _inst18.update(cmds=[], swap=False)
    with _ctx18():
        _ms18._queue_install_job(db.session.get(GameServer, _is18b), [])
    _run_job18(_is18b, _ih18b, "inst2server", "csgo", "csgoserver", 27511, [], fresh=True)
    _p9_drain()
    # ...dependencies first, THEN LinuxGSM: fetching LinuxGSM needs wget and LinuxGSM runs curl, and
    # on a minimal host it is the dependency step that installs them.
    check("install: with its row still there the job goes on to steps 2 and 3, on its own host, "
          "dependencies before LinuxGSM (control)",
          _inst18["cmds"] == [("deps", "192.0.2.183"), ("lgsm", "192.0.2.183")]
          and (_p9_state._install_jobs.get(_is18b) or {}).get("step") == 3,
          repr((_inst18["cmds"], _p9_state._install_jobs.get(_is18b))))
    with _p9_state._install_lock:
        _p9_state._install_jobs.pop(_is18b, None)
    # Deleted mid-install with no row taking the id, and no commit in the worker: nothing reloads,
    # so only the job's own check before each step (_InstallRun.progress) can stop it.
    _ih18c = _host18("p18-install-host3", "192.0.2.168")
    _is18c = _server18(_ih18c, "inst3server", 27512, installed=False, status="installing")
    _inst18.update(cmds=[], gone=_is18c)

    _p9_patch(_ms18, "prepare_install_account", _prepare18_gone)
    with _ctx18():
        _ms18._queue_install_job(db.session.get(GameServer, _is18c), [])
    _run_job18(_is18c, _ih18c, "inst3server", "csgo", "csgoserver", 27512, [], fresh=True)
    _p9_drain()
    check("install: a server deleted during step 1 gets no step 2, on its host or any other",
          _row18(GameServer, _is18c) is None and _inst18["cmds"] == [],
          repr((_row18(GameServer, _is18c), _inst18["cmds"])))
    with _p9_state._install_lock:
        _p9_state._install_jobs.pop(_is18c, None)

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # Power actions (server_detail): start/stop/restart in the background, a long action, bulk
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _ph18 = _host18("p18-power-host", "192.0.2.184")
    _ps18 = _server18(_ph18, "powserver", 27520, name="p18-power", status="online")
    _pw18 = {"runs": [], "prio": [], "mods": []}

    _p9_patch(_p9_sm, "run_as_game_user", _gameuser18)
    _p9_patch(_p9_sm, "set_game_priority", lambda remote, user, *a, **k: _pw18["prio"].append(user))
    _p9_patch(_p9_sm, "server_live_metrics", lambda *a, **k: {"ram_total": 1, "port_open": True,
                                                              "game_procs": 3})
    _p9_patch(_p9_sm, "_invalidate_port_scan", lambda rid: None)
    _p9_patch(_p9_sm, "invalidate_game_version", lambda rid, short: None)
    _p9_patch(_sd18, "_apply_mod_restart", lambda gs, remote: _pw18["mods"].append(gs.short_name))

    _pw18["swap"] = True
    with _ctx18():
        _p9._run_action(db.session.get(GameServer, _ps18), db.session.get(RemoteServer, _ph18),
                        "restart", None)
    _p9_drain()
    _pr18 = _row18(GameServer, _ps18)
    check("power action: the server that took the id keeps its queued flags",
          _pr18.restart_pending is True and _pr18.stop_pending is True,
          repr((_pr18.restart_pending, _pr18.stop_pending)))
    check("power action: ...and gets no priority nudge", _pw18["prio"] == [], repr(_pw18["prio"]))
    _pa18 = [a for a in _audits18("restart_server") if a.target in ("p18-power", "p18-power-taker")]
    check("power action: the restart is still audited, as the server it ran on, under no server",
          [(a.target, a.game_server_id) for a in _pa18] == [("p18-power", None)],
          repr([(a.target, a.game_server_id) for a in _pa18]))

    # A long action: the server is looked up again when it ends.
    _ps18b = _server18(_ph18, "longserver", 27521, name="p18-long")
    _pw18["mods"].clear()

    _p9_patch(_p9_sm, "run_as_game_user", _gameuser18_long)
    with _ctx18():
        _p9._run_action(db.session.get(GameServer, _ps18b), db.session.get(RemoteServer, _ph18),
                        "mods-update", None)
    _p9_drain()
    check("long action: a mods-update's restart is not applied to the server that took the id",
          _pw18["mods"] == [], repr(_pw18["mods"]))
    _pl18 = [a for a in _audits18("mods-update_complete") if "p18-long" in a.target
             or a.target in ("longserver", "takerserver")]
    check("long action: its outcome is not audited under that server, nor by its name",
          [a.game_server_id for a in _pl18] == [None]
          and not any("taker" in a.target for a in _pl18),
          repr([(a.target, a.game_server_id) for a in _pl18]))
    _ps18c = _server18(_ph18, "long2server", 27522, name="p18-long2")
    _pw18["mods"].clear()
    with _ctx18():
        _p9._run_action(db.session.get(GameServer, _ps18c), db.session.get(RemoteServer, _ph18),
                        "mods-update", None)
    _p9_drain()
    check("long action: a server that is still itself gets its mods restart check (control)",
          _pw18["mods"] == ["long2server"], repr(_pw18["mods"]))

    # Bulk: the request checks access to each row and queues a worker per server.
    _pw18["runs"].clear()
    _p9_patch(_p9_sm, "run_as_game_user", _gameuser18)
    _pb18_sid = _server18(_ph18, "bulkserver", 27523, name="p18-bulk")
    _r = _A18.post("/api/servers/bulk-action", json={"action": "details",
                                                     "server_ids": [_pb18_sid]})
    _take_server18(_pb18_sid, name="p18-bulk-taker", short_name="bulktakerserver")
    _p9_drain()
    check("bulk action: the queued worker runs nothing on the server that took the id",
          _p9_json(_r).get("queued") and not any(u == "bulktakerserver" for _h, u, _x in _pw18["runs"]),
          repr((_p9_json(_r), _pw18["runs"])))

    # A synchronous action inside the request: its reply and its audit row.
    _ps18d = _server18(_ph18, "syncserver", 27524, name="p18-sync")

    _p9_patch(_p9_sm, "run_as_game_user", _gameuser18_sync)
    _r = _A18.post("/server/%d/action" % _ps18d, data={"action": "details"})
    with _A18.session_transaction() as _s18:
        _fl18 = [m for _c, m in _s18.get("_flashes", [])]
        _s18.pop("_flashes", None)
    check("sync action: the request still answers, naming the server it ran on (not a 500)",
          _r.status_code == 302 and any(m.startswith("details:") for m in _fl18),
          "%d %r" % (_r.status_code, _fl18))
    _psa18 = [a for a in _audits18("details_server") if a.target in ("p18-sync", "p18-sync-taker")]
    check("sync action: its audit row is not filed under the server that took the id",
          [(a.target, a.game_server_id) for a in _psa18] == [("p18-sync", None)],
          repr([(a.target, a.game_server_id) for a in _psa18]))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # The cross-server ban fan-out: targets chosen (and access-checked) in the request, banned
    # later, a few at a time
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _bh18 = _host18("p18-ban-host", "192.0.2.185")
    _bo18 = _server18(_bh18, "banorigin", 27530, game_type="csgo")
    _b118 = _server18(_bh18, "banone", 27531, game_type="csgo")
    _b218 = _server18(_bh18, "bantwo", 27532, game_type="csgo")
    _bans18 = []

    _p9_patch(_p9_sm, "moderate", _moderate18)
    _p9_patch(_p9_sm, "ensure_persistent_bans", lambda *a, **k: None)
    _p9_patch(_sd18, "concurrent", _SYNC18)
    _other_valve18 = _only_installed18({_bo18, _b118, _b218})   # just this block's three
    _r = _A18.post("/api/server/%d/moderate" % _bo18,
                   json={"action": "ban", "steamid": "STEAM_0:1:1818", "scope": "all"})
    check("ban fan-out: the ban reaches the targets that are still themselves (control)",
          _bans18[:2] == ["banorigin", "banone"], repr((_bans18, _p9_json(_r))))
    check("ban fan-out: ...and not the server that took a target's id between the choice and "
          "its turn", "bantakerserver" not in _bans18, repr(_bans18))
    _reinstall18(_other_valve18)

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # Background writers in _shared: the command-list cache, the public-IP and timezone reads
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _ch18 = _host18("p18-cmd-host", "192.0.2.186")
    _c118 = _server18(_ch18, "cmdone", 27540)
    _c218 = _server18(_ch18, "cmdtwo", 27541)
    _cmds18, _auto18 = [], []

    _p9_patch(_p9_sm, "list_server_commands", _list18)
    _p9_patch(_p9_sm, "set_autostart",
              lambda remote, short, on, selfname=None: (_auto18.append(short), (True, ""))[1])
    with _ctx18():
        _cache18([db.session.get(GameServer, _c118), db.session.get(GameServer, _c218)])
    _p9_drain()
    check("command cache: the server that took a later id is not given the list, nor Autostart",
          "cmdtakerserver" not in _cmds18 + _auto18
          and _row18(GameServer, _c218).commands in ("[]", "", None),
          repr((_cmds18, _auto18, _row18(GameServer, _c218).commands)))
    check("command cache: the first server gets its list and its Autostart (control)",
          _cmds18[:1] == ["cmdone"] and _auto18[:1] == ["cmdone"], repr((_cmds18, _auto18)))

    _iph18 = _host18("p18-ip-host", "192.0.2.187")

    _p9_patch(_sh18, "remote_public_ip", _pubip18)
    _sh18._pubip_resolve_attempts.pop(_iph18, None)
    _sh18._maybe_resolve_public_ip(_p9, _iph18)
    _p9_drain()
    check("public IP: an address read off a deleted host is not stored on the host that took its id",
          _row18(RemoteServer, _iph18).public_ip in ("", None),
          repr(_row18(RemoteServer, _iph18).public_ip))

    _tzh18 = _host18("p18-tz-host", "192.0.2.189")

    _p9_patch(_p9_sm, "host_timezone", _tz18)
    _sh18._tz_resolve_attempts.pop(_tzh18, None)
    _sh18._maybe_resolve_host_timezone(_p9, _tzh18)
    _p9_drain()
    check("host timezone: a deleted host's clock is not stored on the host that took its id",
          _row18(RemoteServer, _tzh18).timezone in ("", None),
          repr(_row18(RemoteServer, _tzh18).timezone))

    # The rate limits, keyed by the same ids: a host or server that takes one starts fresh.
    _sh18._pubip_resolve_attempts[_iph18] = 9e18
    _sh18._cmd_fetch_attempts[_c218] = 9e18
    _take_host18(_iph18, host="192.0.2.191", name="p18-ip-third")
    _take_server18(_c218, name="p18-cmd-third", short_name="cmdthirdserver")
    check("rate limits: a new row does not inherit the deleted one's public-IP or command-fetch "
          "rate limit", _iph18 not in _sh18._pubip_resolve_attempts
          and _c218 not in _sh18._cmd_fetch_attempts,
          repr((_sh18._pubip_resolve_attempts.get(_iph18), _sh18._cmd_fetch_attempts.get(_c218))))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # GMod content jobs (server_files): the host they act on, and the card they report to
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _gmh18 = _host18("p18-gmod-host", "192.0.2.192")
    _gms18 = _server18(_gmh18, "gmodp18server", 27550, game_type="gmod")
    _gmops18 = []
    _p9_patch(_sf18, "detect_content_user",
              lambda remote, games: (_gmops18.append(("detect", remote.host)),
                                     {"user": "gmcontent"})[1])
    _p9_patch(_sf18, "uninstall_gmod_content",
              lambda remote, user, games: (_gmops18.append(("uninstall", remote.host)),
                                           (True, list(games), ""))[1])
    _p9_patch(_sf18, "gmod_current_mounts", lambda remote, user: ["cstrike"])
    _p9_patch(_sf18, "gmod_mount_setup",
              lambda remote, user, cu, games: (_gmops18.append(("mount", remote.host)),
                                               (True, "Mounted."))[1])
    _r = _A18.post("/api/server/%d/gmod-content" % _gms18,
                   json={"action": "uninstall", "games": ["cstrike"]})
    # Deleted before the job ran: the host a new host took the id of, and its server with it.
    _take_host18(_gmh18, host="192.0.2.193", name="p18-gmod-taker")
    _take_server18(_gms18, rid=_gmh18, name="p18-gmod-taker", short_name="gmodtakerserver",
                   game_type="gmod")
    _p9_drain()
    check("gmod content: a job whose host and server were replaced does nothing on the new host",
          _r.status_code == 200 and not [op for op in _gmops18 if op[1] == "192.0.2.193"],
          repr((_r.status_code, _gmops18)))
    check("gmod content: ...and reports nothing onto the card of the server that took the id",
          _gms18 not in _sf18._gmod_content_apply_state
          and _sf18._claim_gmod_content_host(_gmh18) is True,
          repr(_sf18._gmod_content_apply_state.get(_gms18)))
    _sf18._release_gmod_content_host(_gmh18)

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # Backups: on demand, the full run, the scheduled ticker and the 'wait until empty' queue
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _bkh18 = _host18("p18-backup-host", "192.0.2.194")
    _bk118 = _server18(_bkh18, "bkone", 27560, name="p18-bk-one")
    _bkruns18 = []

    _p9_patch(_pb18, "run_game_backup", _gbackup18)
    _p9_patch(_sh18, "run_game_backup", _gbackup18)
    _p9_state._game_backup_status.pop(_bk118, None)
    _r = _A18.post("/api/panel/backup/game/%d" % _bk118, json={"force": True})
    _p9_drain()
    check("backup (on demand): the server that took the id is shown no outcome of it",
          _r.status_code == 200 and _bk118 not in _p9_state._game_backup_status,
          repr((_r.status_code, _p9_state._game_backup_status.get(_bk118))))
    check("backup (on demand): ...and its schedule clock is not moved by it",
          not _bk18.get_game_schedule(_bk118)["last"], repr(_bk18.get_game_schedule(_bk118)))
    check("backup (on demand): the lock is released", not _p9_state._full_backup_lock.locked())

    # The full run: a server replaced while it is archived, and the server after it.
    _bk218 = _server18(_bkh18, "bktwo", 27561, name="p18-bk-two", backup_pending=True)
    _bk318 = _server18(_bkh18, "bkthree", 27562, name="p18-bk-three")
    _take_server18(_bk118, name="p18-bk-one-again", short_name="bkone")
    _bk118b = _bk118
    _bkruns18.clear()
    _others18 = _only_installed18({_bk118b, _bk218, _bk318})
    _p9_state._game_backup_status.pop(_bk118b, None)

    _p9_patch(_pb18, "run_game_backup", _gbackup18_full)
    _p9_patch(_pb18, "_record_full_clock", lambda app, summary: None)
    _bk18_held = _p9_state._full_backup_lock.acquire(timeout=5)   # the route hands it over held
    _pb18._run_full_backup(_p9)
    check("full backup: the server that took an id mid-run gets no status and keeps its queue",
          _bk118b not in _p9_state._game_backup_status
          and _row18(GameServer, _bk118b).backup_pending is True,
          repr((_p9_state._game_backup_status.get(_bk118b), _row18(GameServer, _bk118b))))
    check("full backup: ...and the run goes on to the servers after it",
          _bk18_held and _bkruns18 == ["bkone", "bktwo", "bkthree"]
          and _row18(GameServer, _bk218).backup_pending is False
          and (_p9_state._game_backup_status.get(_bk318) or {}).get("ok") is True,
          repr((_bkruns18, _row18(GameServer, _bk218).backup_pending)))

    # The scheduled ticker: due by its own schedule, replaced while archived.
    _bk18.set_game_schedule(_bk218, 1, 3)
    _bk18.set_game_schedule(_bk318, 1, 3)

    _age18(_bk218)
    _age18(_bk318)
    _bk218_last = _bk18.get_game_schedule(_bk218)["last"]
    _bkruns18.clear()

    _p9_patch(_sh18, "run_game_backup", _gbackup18_sched)
    _p9_state._game_backup_status.pop(_bk218, None)
    _sh18._run_due_game_backups(_p9)
    _sa18r = [a for a in _audits18("scheduled_backup") if a.target in ("p18-bk-two", "p18-sched-taker")]
    check("scheduled backup: the server that took the id has its schedule clock left alone",
          _bk18.get_game_schedule(_bk218)["last"] == _bk218_last,
          repr((_bk218_last, _bk18.get_game_schedule(_bk218))))
    check("scheduled backup: ...and the status map holds nothing for it",
          _bk218 not in _p9_state._game_backup_status,
          repr(_p9_state._game_backup_status.get(_bk218)))
    check("scheduled backup: its failure is not audited under that server",
          all(a.game_server_id is None for a in _sa18r), repr([(a.target, a.game_server_id)
                                                              for a in _sa18r]))
    check("scheduled backup: the server after it is still backed up (control)",
          _bkruns18 == ["bktwo", "bkthree"], repr(_bkruns18))

    # The 'wait until empty' queue: two queued servers, the first replaced while it is archived.
    _q118 = _server18(_bkh18, "qone", 27563, backup_pending=True)
    _q218 = _server18(_bkh18, "qtwo", 27564, backup_pending=True)
    _only_flagged18({_q118, _q218}, ("backup_pending",))
    _bkruns18.clear()

    _p9_patch(_sh18, "run_game_backup", _gbackup18_queue)
    _q18_err = _raises18(_sh18._run_pending_backups, _p9)
    check("queued backup: the server that took the id keeps its queue and gets no status",
          _row18(GameServer, _q118).backup_pending is True
          and _q118 not in _p9_state._game_backup_status,
          repr((_q18_err, _row18(GameServer, _q118).backup_pending)))
    check("queued backup: ...and the next queued server is still backed up and dequeued",
          _q18_err is None and "qtwo" in _bkruns18
          and _row18(GameServer, _q218).backup_pending is False,
          repr((_q18_err, _bkruns18, _row18(GameServer, _q218).backup_pending)))
    _reinstall18(_others18)

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # Tickers: the queued restart/stop sweep and the stranded-install reconcile
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _rh18 = _host18("p18-restart-host", "192.0.2.195")
    _r118 = _server18(_rh18, "rsone", 27570, status="online", restart_pending=True)
    _r218 = _server18(_rh18, "rstwo", 27571, status="online", restart_pending=True)
    _only_flagged18({_r118, _r218}, ("restart_pending", "stop_pending"))
    _p9_patch(_sh18, "get_server_status", lambda remote, gs, **k: "online")
    _p9_patch(_sh18, "sm_player_count", lambda *a, **k: 0)
    _rs18 = []

    _p9_patch(_p9_sm, "run_as_game_user", _gameuser18_queued)
    _rs18_err = _raises18(_sh18._run_due_restarts, _p9)
    check("queued restart: the server that took the id keeps its queued restart",
          _row18(GameServer, _r118).restart_pending is True, repr(_row18(GameServer, _r118)))
    check("queued restart: ...and the next queued server is still restarted and dequeued",
          _rs18_err is None and "rstwo" in _rs18
          and _row18(GameServer, _r218).restart_pending is False,
          repr((_rs18_err, _rs18, _row18(GameServer, _r218).restart_pending)))

    _reconcile18 = _supervised18("install-reconcile")
    _xh18 = _host18("p18-reconcile-host", "192.0.2.196")
    _x118 = _server18(_xh18, "xone", 27580, installed=False, status="installing")
    _x218 = _server18(_xh18, "xtwo", 27581, installed=False, status="installing")
    _xs18 = []

    _p9_patch(_p9_sm, "shell_as_game_user", _shell18)
    _only_status18({_x118, _x218}, ("installing", "configuring", "failed"), "offline")
    _x18_ran = _reconcile18 is not None and _one_pass18(_reconcile18, 600)
    _xr118, _xr218 = _row18(GameServer, _x118), _row18(GameServer, _x218)
    check("install reconcile: a row replaced during its check is not reconciled from it",
          _x18_ran and _xr118.status == "installing" and _xr118.installed is False,
          repr((_x18_ran, _xr118.status, _xr118.installed)))
    check("install reconcile: ...and the stranded row after it still is (control)",
          _xr218.status == "offline" and _xr218.installed is True,
          repr((_xs18, _xr218.status, _xr218.installed)))
    # A queued restart whose server is found stopped clears its flags WITHOUT a reload first: if
    # the row was replaced during that status read, the flush refuses the write and leaves it in
    # the sweep's session, for the next server's audit commit to refuse again, unless rolled back.
    _rsi18 = {"swap": True}
    _rsi18["id"] = _server18(_rh18, "rsidle", 27572, status="online", restart_pending=True)
    _rsn18 = _server18(_rh18, "rsnext", 27573, status="online", restart_pending=True)
    _only_flagged18({_rsi18["id"], _rsn18}, ("restart_pending", "stop_pending"))
    _rs18.clear()

    _p9_patch(_sh18, "get_server_status", _status18_idle)
    _rsi18_err = _raises18(_sh18._run_due_restarts, _p9)
    _rsi18_rows = [(a.target, a.game_server_id, a.success) for a in _audits18("restart_server")
                   if a.target == "p18-rsnext"]
    check("queued restart: a refused write for a replaced server leaves the next server's restart "
          "its audit row", _rsi18_err is None and _rs18 == ["rsnext"]
          and _rsi18_rows == [("p18-rsnext", _rsn18, True)],
          repr((_rsi18_err, _rs18, _rsi18_rows)))
    check("queued restart: ...and the server that took the id keeps its queued restart",
          _row18(GameServer, _rsi18["id"]).restart_pending is True,
          repr(_row18(GameServer, _rsi18["id"])))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # Sweeps that probe first and apply after: the monitor, the player poll, the metric history,
    # and the dashboard's status poll
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _mh18 = _host18("p18-mon-host", "192.0.2.197")
    _ms118 = _server18(_mh18, "monone", 27590, status="offline")
    _mh218 = _host18("p18-mon-host2", "192.0.2.198")
    _ms218 = _server18(_mh218, "montwo", 27591, status="online")
    _p9_patch(_mon18, "concurrent", _SYNC18)

    _p9_patch(_mon18, "_host_reachable", _reach18)
    _p9_patch(_mon18, "_remote_listening_ports",
              lambda remote: {27590} if remote.host == "192.0.2.197" else set())
    _p9_patch(_mon18, "_host_disk_pct", lambda remote: 10)
    _p9_patch(_mon18, "_host_load_mem", lambda remote: (None, None))
    _p9_patch(_mon18, "_host_restart_flags", lambda remote: set())
    with _ctx18():
        _mon18._monitor_pass()
    check("monitor: the new host's server is not judged by the deleted host's port scan",
          _row18(GameServer, _ms118).status == "offline"
          and _ms118 not in _p9_state._monitor_state["servers"],
          repr((_row18(GameServer, _ms118).status,
                _p9_state._monitor_state["servers"].get(_ms118))))
    check("monitor: ...and the rest of the pass is still recorded (control)",
          _row18(GameServer, _ms218).status == "offline", repr(_row18(GameServer, _ms218)))

    _plh18 = _host18("p18-players-host", "192.0.2.171")
    _pl118 = _server18(_plh18, "plone", 27592, status="online")
    _pl218 = _server18(_plh18, "pltwo", 27599, status="online")

    _p9_patch(_mon18, "concurrent", _SYNC18)
    _p9_patch(_mon18, "_query_server_slots", _slots18)
    _p9_patch(_mon18, "sm_player_slots_batch", lambda *a, **k: None)   # per server, as above
    _p9_state._player_counts.pop(_pl118, None)
    _p9_state._player_counts.pop(_pl218, None)
    _mon18._refresh_player_counts(_p9)
    check("player poll: the server that took the id is not shown the deleted one's count or name",
          _pl118 not in _p9_state._player_counts, repr(_p9_state._player_counts.get(_pl118)))
    check("player poll: a server that is still itself has its count recorded (control)",
          (_p9_state._player_counts.get(_pl218) or {}).get("count") == 0,
          repr(_p9_state._player_counts.get(_pl218)))

    _sph18 = _host18("p18-sample-host", "192.0.2.172")
    _sp118 = _server18(_sph18, "spone", 27593, status="online")

    _p9_patch(_mon18, "_query_host_metrics", _hostmetrics18)
    with _ctx18():
        MetricSample.query.filter_by(server_id=_sp118).delete()
        db.session.commit()
        _sp18top = db.session.query(db.func.max(MetricSample.id)).scalar() or 0
    _mon18._record_metric_samples(_p9)
    with _ctx18():
        _sp18n = MetricSample.query.filter_by(server_id=_sp118).count()
        _sp18h = MetricSample.query.filter(MetricSample.id > _sp18top,
                                           MetricSample.server_id != _sp118).count()
    check("metric history: no sample of the deleted server is kept under the id another took",
          _sp18n == 0, "%d sample(s)" % _sp18n)
    check("metric history: the other servers are still sampled (control)", _sp18h > 0,
          "%d" % _sp18h)
    with _ctx18():
        _orph18 = GameServer(remote_id=987650, name="p18-orphan", short_name="orphanserver",
                             game_type="csgo", port=27599, installed=True, status="online")
        db.session.add(_orph18)
        db.session.commit()
        _mine18["servers"].append(_orph18.id)
    _orph18_err = _raises18(_mon18._record_metric_samples, _p9)
    check("metric history: a server whose host row is missing does not stop the pass",
          _orph18_err is None, _orph18_err)
    with _ctx18():
        db.session.delete(db.session.get(GameServer, _orph18.id))
        db.session.commit()

    _dh18 = _host18("p18-dash-host", "192.0.2.173")
    _ds118 = _server18(_dh18, "dashone", 27594, status="online")

    _p9_patch(_api18, "concurrent", _SYNC18)
    _p9_patch(_api18, "_remote_listening_ports", _ports18)
    _p9_patch(_sh18, "remote_public_ip", lambda remote: "")   # the poll resolves missing addresses
    _r = _A18.get("/api/servers")
    _p9_drain()
    check("dashboard poll: the status found for a deleted server is not written onto the one that "
          "took its id", _r.status_code == 200 and _row18(GameServer, _ds118).status == "online",
          repr((_r.status_code, _row18(GameServer, _ds118).status)))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # Passes that act on every row as it was loaded: shown safe, with no change of their own
    # ════════════════════════════════════════════════════════════════════════════════════════════
    # The daily node-tools pass re-reads each row just before acting (_still_in_db, a refresh):
    # a row whose id was taken is skipped, not turned into the new row.
    _nh118 = _host18("p18-nt-host", "192.0.2.174")
    _nh218 = _host18("p18-nt-host2", "192.0.2.175")
    _nt18 = []

    _p9_patch(_p9_app, "ensure_node_tools_cron", _ensure18)
    _p9_patch(_p9_sm, "upgrade_managed_cron_tracking", lambda *a, **k: None)
    _p9_app._node_tools_cron_pass(_p9)
    check("node-tools pass: a host whose id was taken during the pass is skipped, not acted on "
          "as the new host", "192.0.2.176" not in _nt18 and "192.0.2.174" in _nt18, repr(_nt18))

    # The global ban fan-out loads its servers once. With no commit in the pass, a row replaced
    # mid-pass is skipped (app._valve_ban_target), never acted on as its successor. A first
    # contact's commit mid-pass is its own block at the end of this part.
    _gbh18 = _host18("p18-gban-host", "192.0.2.177")
    _gb118 = _server18(_gbh18, "gbone", 27595, game_type="csgo")
    _gb218 = _server18(_gbh18, "gbtwo", 27596, game_type="csgo")
    _gbans18 = []

    _p9_patch(_p9_app, "console_steamid_ban", _steamban18)
    _p9_patch(_p9_app, "ensure_persistent_bans", lambda *a, **k: None)
    _p9_app._fan_out_global_ban(_p9, "STEAM_0:1:1819")
    check("global ban fan-out: a server replaced mid-pass is never acted on as its successor",
          "gbone" in _gbans18 and "gbtakerserver" not in _gbans18, repr(_gbans18))

    # The priority keeper: no writes, and every host is read before the first renice.
    _keeper18 = _supervised18("priority-keeper")
    _kh18 = _host18("p18-keep-host", "192.0.2.178")
    _kh218 = _host18("p18-keep-host2", "192.0.2.179")
    _server18(_kh18, "kpone", 27597)
    _server18(_kh218, "kptwo", 27598)
    _renice18 = []

    _p9_patch(_p9_app, "set_game_priority_bulk", _bulk18)
    # The unprivileged nice read cannot answer here: every account is reniced, as before.
    _p9_patch(_p9_app, "game_users_off_priority", lambda *a, **k: None)
    _k18_ran = _keeper18 is not None and _one_pass18(_keeper18, 120)
    check("priority keeper: a host replaced mid-pass is never reniced as its successor",
          _k18_ran and not any(h == "192.0.2.160" for h, _u in _renice18),
          repr((_k18_ran, _renice18)))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # The daily OS-update sweep, and an open terminal
    # ════════════════════════════════════════════════════════════════════════════════════════════
    from panel.routes import os_updates as _osu18
    from panel.routes import host_terminal as _ht18
    _oh18 = _host18("p18-osu-host", "192.0.2.163")

    _p9_patch(_osu18, "concurrent", _SYNC18)
    _p9_patch(_osu18, "_os_updates_for", _osucheck18)
    _p9_state._os_update_state["hosts"].pop(_oh18, None)
    _p9_state._os_update_seen.pop(_oh18, None)
    _p9._maybe_alert_os_updates(force=True)
    check("os-update sweep: the host that took a checked host's id inherits none of its counts",
          _oh18 not in _p9_state._os_update_state["hosts"]
          and _oh18 not in _p9_state._os_update_seen,
          repr((_p9_state._os_update_state["hosts"].get(_oh18),
                _p9_state._os_update_seen.get(_oh18))))
    check("os-update sweep: the other hosts are still recorded (control)",
          any(h != _oh18 for h in _p9_state._os_update_state["hosts"]),
          repr(sorted(_p9_state._os_update_state["hosts"])))

    _tmh18 = _host18("p18-term-host", "192.0.2.165")
    _p9_patch(_ht18._ts, "open_session", lambda sid, remote, is_local, **k: None)
    _sio18 = _p9.socketio.test_client(_p9, flask_test_client=_A18)
    _sio18.emit("term_open", {"remote_id": _tmh18, "cols": 80, "rows": 24})
    with _ht18._sid_lock:
        _tsid18 = [s for s, e in _ht18._sid_host.items()
                   if (e[0] if isinstance(e, tuple) else e) == _tmh18]
    with _ctx18():
        _tkept18 = [s for s, _u in _ht18.revoked_terminal_sids()]
    _take_host18(_tmh18, host="192.0.2.166", name="p18-term-taker")
    with _ctx18():
        _tgone18 = [s for s, _u in _ht18.revoked_terminal_sids()]
    check("terminal: a shell stays open while its host is the one it was opened on (control)",
          len(_tsid18) == 1 and _tsid18[0] not in _tkept18, repr((_tsid18, _tkept18)))
    check("terminal: ...and its access re-check refuses it once another host took the id",
          len(_tsid18) == 1 and _tsid18[0] in _tgone18, repr((_tsid18, _tgone18)))
    _sio18.disconnect()
    _forget_sids18(_tsid18)

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # The global ban fan-out and sync when a first contact commits the pass's own session: a later
    # server whose id is taken then reloads from the other row
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _fb18 = {}

    _p9_patch(_p9_app, "console_steamid_ban", _steamban18_pin)
    _p9_patch(_p9_app, "ensure_persistent_bans", lambda *a, **k: None)
    _fbi18, _fbo18 = _fb_servers18("fb", 27601, "192.0.2.154")
    _fb18_err = _raises18(_p9_app._fan_out_global_ban, _p9, "STEAM_0:1:1820")
    _fb18_rows = [(a.detail, a.success) for a in _audits18("global_ban_apply")
                  if a.target == "STEAM_0:1:1820"]
    _reinstall18(_fbo18)
    check("global ban fan-out: a server whose id was taken after the pass's first commit does not "
          "stop the pass", _fb18_err is None, _fb18_err)
    check("global ban fan-out: ...the server after it still gets the ban, and the one that took "
          "the id does not", _fb18["bans"] == [("fbone", "STEAM_0:1:1820"),
                                               ("fbthree", "STEAM_0:1:1820")],
          repr(_fb18["bans"]))
    check("global ban fan-out: ...and its outcome row is written", _fb18_rows == [("2 applied", True)],
          repr(_fb18_rows))

    _ban_add18("STEAM_0:1:1821")
    with _ctx18():
        _sb18_n = GlobalBan.query.count()
    _sb18_before = len(_audits18("global_ban_sync"))
    _sbi18, _sbo18 = _fb_servers18("sb", 27604, "192.0.2.156")
    _sb18_err = _raises18(_p9_app._sync_global_bans, _p9)
    _sb18_rows = [(a.detail, a.success) for a in _audits18("global_ban_sync")][_sb18_before:]
    _reinstall18(_sbo18)
    _sb18_to = sorted({s for s, _i in _fb18["bans"]})
    check("global ban sync: a server whose id was taken after the pass's first commit does not "
          "stop the pass", _sb18_err is None, _sb18_err)
    check("global ban sync: ...the server after it still gets every ban, and the one that took "
          "the id none", _sb18_to == ["sbone", "sbthree"]
          and ("sbthree", "STEAM_0:1:1821") in _fb18["bans"], repr(_fb18["bans"]))
    check("global ban sync: ...and its outcome row is written",
          _sb18_rows == [("%d applied" % (2 * _sb18_n), True)], repr((_sb18_n, _sb18_rows)))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # The hourly auto-block tick: hosts taken from its snapshot of the opted-in list
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _ab18 = {}

    _p9_patch(_p9_app, "_autoblock_reconcile", _abreconcile18)
    _ab18_ctl = _ab_tick18(("192.0.2.150", "192.0.2.151"), None)
    check("autoblock tick: with nothing changed, both opted-in hosts are reconciled (control)",
          _ab18_ctl[0] and sorted(_ab18_ctl[1]) == ["192.0.2.150", "192.0.2.151"], repr(_ab18_ctl))
    _ab18_del = _ab_tick18(("192.0.2.152", "192.0.2.153"), _ab_deleted18)
    check("autoblock tick: a host that took a deleted host's id during the tick is not reconciled",
          _ab18_del[0] and len(_ab18_del[1]) == 1 and "192.0.2.159" not in _ab18_del[1],
          repr(_ab18_del))
    _ab18_kept = _ab_tick18(("192.0.2.140", "192.0.2.141"), _ab_kept18)
    check("autoblock tick: ...nor when the delete's config write left the deleted host's opt-in",
          _ab18_kept[0] and len(_ab18_kept[1]) == 1 and "192.0.2.158" not in _ab18_kept[1],
          repr(_ab18_kept))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # Helpers that promise never to raise, handed a server another row took the id of
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _nrh18 = _host18("p18-nr-host", "192.0.2.162")
    _nrs18 = _server18(_nrh18, "nrserver", 27607)
    check("never-raise helpers (premise): the tag mute check and the maintenance probe are the "
          "real ones here, not a stub", _p9_notif.alerts_muted.__module__ == _p9_notif.__name__
          and _mon18._lgsm_maintenance_running.__module__ == _mon18.__name__,
          repr((_p9_notif.alerts_muted, _mon18._lgsm_maintenance_running)))
    with _ctx18():
        _nr18 = db.session.get(GameServer, _nrs18)
        _nr18_remote = _nr18.remote
        db.session.commit()                  # expires both, as a worker's first contact does
        _take_server18(_nrs18, name="p18-nr-taker", short_name="nrtakerserver")
        _nr18_muted = _outcome18(_p9_notif.alerts_muted, _nr18)
        _nr18_maint = _outcome18(_mon18._lgsm_maintenance_running, _nr18_remote, _nr18)
    check("never-raise helpers: the tag mute check fails open for it rather than raising",
          _nr18_muted == ("returned", False), repr(_nr18_muted))
    check("never-raise helpers: the maintenance probe answers False for it rather than raising",
          _nr18_maint == ("returned", False), repr(_nr18_maint))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # An id a page posts back: Global Bans left open while its newest ban was replaced
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _gbx18 = []

    _p9_patch(_p9_app, "console_steamid_ban", _steamban18_record)
    _stale18 = _ban_add18("STEAM_0:1:1822")
    with _ctx18():
        db.session.delete(db.session.get(GlobalBan, _stale18))     # another superadmin removes it
        db.session.commit()
    _fresh18 = _ban_add18("STEAM_0:1:1823")                        # ...and adds another
    _r = _A18.post("/global-bans/%d/delete" % _stale18)
    _p9_drain()
    with _ctx18():
        _fresh18_row = db.session.get(GlobalBan, _fresh18)
        _fresh18_sid = None if _fresh18_row is None else _fresh18_row.steamid
    check("global bans: a stale page's Remove finds its ban gone, and the ban added after it stays",
          _fresh18 != _stale18 and _r.status_code == 404 and _fresh18_sid == "STEAM_0:1:1823",
          repr((_stale18, _fresh18, _r.status_code, _fresh18_sid)))
    check("global bans: ...and nothing is lifted anywhere",
          not any(sid == "STEAM_0:1:1823" for _s, sid, _u in _gbx18), repr(_gbx18))
finally:
    _restore18()

check("part18: no worker under test reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP18_START, repr(_P9_TRIPPED[_TRIP18_START:][:6]))
check("part18: every deferred worker was run (none left to leak into a later check)",
      not _p9_queue,
      "%d left: %s" % (len(_p9_queue), [getattr(f, "__qualname__", f) for f, _a, _k in _p9_queue]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# The class fix: AUTOINCREMENT on the tables whose ids are kept, and the migration that gives it
# to a database made before it
# ════════════════════════════════════════════════════════════════════════════════════════════════
_KEYED18 = ("user", "group", "remote_server", "game_server", "custom_command", "server_tag",
            "global_ban", "invite", "user_session")
check("autoincrement: exactly the keyed tables declare it, and they are the ones the migration "
      "rebuilds",
      sorted(t.name for t in db.metadata.sorted_tables
             if t.dialect_options["sqlite"]["autoincrement"]) == sorted(_KEYED18)
      and sorted(m.__table__.name for m in _m18._AUTOINCREMENT_MODELS) == sorted(_KEYED18),
      repr(sorted(t.name for t in db.metadata.sorted_tables
                  if t.dialect_options["sqlite"]["autoincrement"])))
_TMP18 = _tf18.mkdtemp(prefix="lgsm-unit-p18-")
_apps18 = []


def _app18(path):
    """A Flask app bound to the database file at `path`, for the migration's own session."""
    a = _Flask18("p18_idseq_%d" % len(_apps18))
    a.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + path,
                    SQLALCHEMY_TRACK_MODIFICATIONS=False,
                    SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"timeout": 5}})
    db.init_app(a)
    _apps18.append(a)
    return a


def _old_db18(name):
    """A panel database as create_all() made it BEFORE AUTOINCREMENT, holding rows and a hole.

    Returns (path, old metadata). The newest server is deleted, so its id (3) is free; an audit row
    still names it, and an association row names an id (7) no server has had in this file.
    """
    path = os.path.join(_TMP18, name)
    old = _reuse18._old_schema(db.metadata, _KEYED18)
    eng = _sa18.create_engine("sqlite:///" + path)
    old.create_all(eng)
    t = old.tables
    with eng.begin() as c:
        c.execute(t["user"].insert(), [{"id": i, "username": "p18u%d" % i, "password_hash": _NO_LOGIN18}
                                       for i in (1, 2)])
        c.execute(t["group"].insert(), [{"id": i, "name": "p18g%d" % i} for i in (1, 2)])
        c.execute(t["remote_server"].insert(), [{"id": i, "name": "h%d" % i, "host": "192.0.2.%d" % i,
                                                 "username": "root"} for i in (1, 2)])
        # Installed servers: data migration 1 leaves their Autostart alone, so every value the
        # rebuild carries is still the one it had.
        c.execute(t["game_server"].insert(), [{"id": i, "remote_id": 1, "name": "s%d" % i,
                                               "short_name": "s%dserver" % i, "game_type": "csgo",
                                               "port": 27000 + i, "installed": True}
                                              for i in (1, 2, 3)])
        c.execute(t["game_server"].delete().where(t["game_server"].c.id == 3))
        c.execute(t["audit_log"].insert(), [{"id": 1, "username": "x", "action": "start_server",
                                             "target": "s1", "game_server_id": 3}])
        c.execute(t["server_tag"].insert(), [{"id": 1, "name": "p18t1"}])
        c.execute(t["game_server_tags"].insert(), [{"tag_id": 4, "game_server_id": 7}])
        c.execute(t["custom_command"].insert(), [{"id": 1, "name": "c1", "command_template": "say"}])
        c.execute(t["user_groups"].insert(), [{"user_id": 2, "group_id": 2}])
        c.execute(t["global_ban"].insert(), [{"id": 1, "steamid": "STEAM_0:1:18"}])
        c.execute(t["invite"].insert(), [{"id": 1, "token_hash": "p18" * 16,
                                          "expires_at": _soon18()}])
        c.execute(t["user_session"].insert(), [{"id": 1, "user_id": 1, "sid": "p18s1"}])
    eng.dispose()
    return path, old


def _soon18():
    """A day from now, naive UTC as the models store it."""
    return (_dt18.datetime.now(_dt18.timezone.utc) + _dt18.timedelta(days=1)).replace(tzinfo=None)


def _rows18(path, tables=_KEYED18 + ("game_server_tags", "user_groups", "audit_log")):
    """{table: [{column: raw stored value}] by id}: what the file holds, read around the ORM."""
    con = _sq18.connect(path)
    con.row_factory = _sq18.Row
    try:
        out = {}
        for name in tables:
            rows = con.execute('SELECT * FROM "%s"' % name).fetchall()  # nosec B608 - a fixed name
            out[name] = sorted((dict(r) for r in rows), key=lambda d: sorted(d.items(), key=str))
        return out
    finally:
        con.close()


def _plain18(path, name):
    con = _sq18.connect(path)
    try:
        sql = con.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                          (name,)).fetchone()
        return sql is not None and "AUTOINCREMENT" not in sql[0].upper()
    finally:
        con.close()


def _seq18(path):
    """{table: seq} from sqlite_sequence; {} when the file has none (no AUTOINCREMENT table)."""
    try:
        return dict(_one18(path, "SELECT name, seq FROM sqlite_sequence"))
    except _sq18.OperationalError:
        return {}


def _one18(path, sql, args=()):
    con = _sq18.connect(path)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


# The row _nofk_floor18 adds to each table that holds a keyed id without a foreign key.
_NOFK_ROW18 = {"audit_log": {"action": "p18-nofk", "username": "x"},
               "metric_sample": {}, "host_sample": {}}


def _nofk_floor18(name, table, column):
    """The next-id floor the rebuild gives `name` when only `table`.`column` names an id above it.

    A database from before (_old_db18) with one more row, in `table`, whose `column` names id 40,
    and no foreign key declared on that column; then the keyed tables rebuilt, and `name`'s entry in
    sqlite_sequence read back.
    """
    path, _ = _old_db18("nofk-%s-%s.db" % (table, column))
    row = dict(_NOFK_ROW18[table], **{column: 40})
    con = _sq18.connect(path)
    try:
        con.execute('INSERT INTO "%s" (%s) VALUES (%s)'  # nosec B608 - fixed names
                    % (table, ", ".join('"%s"' % c for c in row), ", ".join("?" * len(row))),
                    list(row.values()))
        con.commit()
    finally:
        con.close()
    with _app18(path).app_context():
        _m18._give_keyed_tables_autoincrement()
    return _seq18(path).get(name)


def _next_after_delete18(model, **fields):
    """(id of the newest row, deleted; id of the row added after it). Call in an app context."""
    first = model(**fields)
    db.session.add(first)
    db.session.commit()
    first_id = first.id
    db.session.delete(first)
    db.session.commit()
    second = model(**fields)
    db.session.add(second)
    db.session.commit()
    return first_id, second.id


def _start18(path):
    """One start's migrations on the database at `path`: None, or the error that stopped them."""
    try:
        with _app18(path).app_context():
            _m18._run_light_migrations()
        return None
    except Exception as e:  # noqa: BLE001 - a lock or a failed migration is the finding
        return repr(e)[:200]


def _write18(path, sql, rows=()):
    con = _sq18.connect(path)
    try:
        if rows:
            con.executemany(sql, rows)
        else:
            con.execute(sql)
        con.commit()
    finally:
        con.close()


def _data_migration18():
    """Data migration 1 replayed: an upgrade from a version whose install rows started On."""
    path, _ = _old_db18("autostart.db")
    # Made by the old install route (no autostart given, so the model's default On): one that
    # failed before step 5, an installed server, and a failed one a write had already set Off.
    _write18(path, "INSERT INTO game_server (id, remote_id, name, short_name, game_type, port, "
                   "installed, autostart) VALUES (?, 1, ?, ?, 'csgo', ?, ?, ?)",
             [(10, "p18-failed", "p18fserver", 27110, 0, 1),
              (11, "p18-up", "p18userver", 27111, 1, 1),
              (12, "p18-off", "p18oserver", 27112, 0, 0)])
    check("data migration (premise): the old database has run none (user_version 0), and its "
          "game_server table must be rebuilt after the migration (the write lock)",
          _one18(path, "PRAGMA user_version") == [(0,)] and _plain18(path, "game_server"), "")
    err = _start18(path)
    got = dict(_one18(path, "SELECT id, autostart FROM game_server WHERE id >= 10"))
    check("data migration: an upgrade sets Autostart Off on an install that never finished (the "
          "old default On, over a crontab no monitor line reached) and keeps an installed "
          "server's On", err is None and got == {10: 0, 11: 1, 12: 0}, repr((err, got)))
    check("data migration: ...committed before the rebuild and the index build, which take the "
          "write lock on connections of their own (nothing locked, game_server rebuilt), and "
          "counted: user_version 1",
          err is None and not _plain18(path, "game_server")
          and _one18(path, "PRAGMA user_version") == [(1,)],
          repr((err, _plain18(path, "game_server"), _one18(path, "PRAGMA user_version"))))
    # A retry of that install, on this version, wrote the monitor line and recorded On: evidence.
    _write18(path, "UPDATE game_server SET autostart = 1 WHERE id = 10")
    err = _start18(path)
    check("data migration: ...ONCE: the next start leaves an unfinished install's On alone (this "
          "version records it only on what a write or a read reported)",
          err is None and _one18(path, "SELECT autostart FROM game_server WHERE id = 10") == [(1,)],
          repr((err, _one18(path, "SELECT autostart FROM game_server WHERE id = 10"))))


try:
    # ── the replay: a database from before, through the real startup migration ────────────────
    _p18a, _old18 = _old_db18("before.db")
    _before18 = _rows18(_p18a)
    check("autoincrement (premise): the database built from the old schema lacks it everywhere",
          all(_plain18(_p18a, n) for n in _KEYED18), "")
    _a18 = _app18(_p18a)
    with _a18.app_context():
        _m18._run_light_migrations()
    check("autoincrement: an upgrade gives every keyed table AUTOINCREMENT",
          not any(_plain18(_p18a, n) for n in _KEYED18),
          repr([n for n in _KEYED18 if _plain18(_p18a, n)]))
    check("autoincrement: every row comes through with its id and every stored value unchanged",
          _rows18(_p18a) == _before18, "the copy changed what the file holds")
    _idx18 = {r[0] for r in _one18(_p18a, "SELECT name FROM sqlite_master WHERE type='index'")}
    _want_idx18 = {ix.name for m in _m18._AUTOINCREMENT_MODELS for ix in m.__table__.indexes}
    check("autoincrement: each rebuilt table keeps its indexes, and nothing of the copy is left",
          _want_idx18 <= _idx18
          and not _one18(_p18a, "SELECT name FROM sqlite_master WHERE name LIKE '\\_idseq%' "
                                "ESCAPE '\\'")
          and _one18(_p18a, "PRAGMA integrity_check") == [("ok",)],
          repr((_want_idx18 - _idx18, _one18(_p18a, "PRAGMA integrity_check"))))
    with _a18.app_context():
        _n18 = GameServer(remote_id=1, name="n1", short_name="n1server", game_type="csgo",
                          port=28001)
        _t18 = _m18.ServerTag(name="p18t-new")
        _h18 = RemoteServer(name="h-new", host="192.0.2.9", username="root")
        _u18 = User(username="p18u-new", password_hash=_NO_LOGIN18)
        db.session.add_all([_n18, _t18, _h18, _u18])
        db.session.commit()
        _ids18 = (_n18.id, _t18.id, _h18.id, _u18.id)
        db.session.delete(_n18)
        db.session.commit()
        _n18b = GameServer(remote_id=1, name="n2", short_name="n2server", game_type="csgo",
                           port=28002)
        db.session.add(_n18b)
        db.session.commit()
        _next18 = _n18b.id
        _again18 = _m18._give_keyed_tables_autoincrement()
    check("autoincrement: the next id is above every id anything still names (the deleted "
          "server's audit row, an orphan tag row)", _ids18 == (8, 5, 3, 3), repr(_ids18))
    check("autoincrement: ...and a deleted row's id is never handed out again",
          _next18 == 9, repr(_next18))
    check("autoincrement: a second start finds nothing to rebuild", _again18 == [], repr(_again18))

    # ── an older install still: columns the ALTERs add, and the audit backfill beside it ────────
    _p18b, _ = _old_db18("ancient.db")
    _con18 = _sq18.connect(_p18b)
    for _ix in ("ix_audit_log_game_server_id", "ix_audit_log_remote_id"):
        _con18.execute('DROP INDEX IF EXISTS "%s"' % _ix)  # nosec B608 - fixed names
    for _tb, _col in (("audit_log", "game_server_id"), ("audit_log", "remote_id"),
                      ("game_server", "content_games"), ("remote_server", "timezone")):
        _con18.execute('ALTER TABLE "%s" DROP COLUMN "%s"' % (_tb, _col))  # nosec B608 - fixed names
    _con18.commit()
    _con18.close()
    _b18 = _app18(_p18b)
    try:
        with _b18.app_context():
            _m18._run_light_migrations()
        _anc18_err = None
    except Exception as _e18:  # noqa: BLE001 - a lock or a failed copy is the regression
        _anc18_err = repr(_e18)
    _anc18 = _rows18(_p18b, ("game_server", "remote_server", "audit_log"))
    check("autoincrement: an install old enough to lack columns gets them and the rebuild in one "
          "start, with nothing locked",
          _anc18_err is None and not any(_plain18(_p18b, n) for n in _KEYED18)
          and all("content_games" in r for r in _anc18["game_server"])
          and all("timezone" in r for r in _anc18["remote_server"]),
          repr((_anc18_err, [n for n in _KEYED18 if _plain18(_p18b, n)])))
    check("autoincrement: ...its audit backfill still runs beside it (the row names server s1)",
          [r.get("game_server_id") for r in _anc18["audit_log"]] == [1],
          repr(_anc18["audit_log"]))

    # ── a table it cannot copy without loss is left exactly as it was ───────────────────────────
    _p18c, _ = _old_db18("extra.db")
    _con18 = _sq18.connect(_p18c)
    _con18.execute("ALTER TABLE server_tag ADD COLUMN legacy_note TEXT")
    _con18.execute("UPDATE server_tag SET legacy_note = 'kept' WHERE id = 1")
    _con18.execute("DROP TABLE custom_command")
    _con18.execute("CREATE TABLE custom_command (id INTEGER NOT NULL, name VARCHAR(80), "
                   "command_template VARCHAR(500), argument_label VARCHAR(80), "
                   "argument_pattern VARCHAR(200), scope_type VARCHAR(16), "
                   "scope_value VARCHAR(64), enabled BOOLEAN, created_by VARCHAR(80), "
                   "created_at DATETIME, PRIMARY KEY (id))")
    _con18.execute("INSERT INTO custom_command (id, name, command_template) VALUES (1, NULL, 'say')")
    _con18.commit()
    _con18.close()
    _cc18_cols = {r[1] for r in _one18(_p18c, "PRAGMA table_info(custom_command)")}
    check("autoincrement (premise): the hand-made table has exactly the model's columns, so only "
          "its NULL can stop the copy",
          _cc18_cols == {c.name for c in _m18.CustomCommand.__table__.columns},
          repr(sorted(_cc18_cols)))
    _c18 = _app18(_p18c)
    with _c18.app_context():
        _done18 = _m18._give_keyed_tables_autoincrement()
    check("autoincrement: a column the models no longer declare keeps its table as it was",
          "server_tag" not in _done18 and _plain18(_p18c, "server_tag")
          and _one18(_p18c, "SELECT legacy_note FROM server_tag") == [("kept",)],
          repr((_done18, _one18(_p18c, "SELECT * FROM server_tag"))))
    check("autoincrement: a row the models' constraints refuse rolls its table's copy back whole",
          "custom_command" not in _done18 and _plain18(_p18c, "custom_command")
          and _one18(_p18c, "SELECT id, name FROM custom_command") == [(1, None)]
          and not _one18(_p18c, "SELECT name FROM sqlite_master WHERE name LIKE '\\_idseq%' "
                                "ESCAPE '\\'"),
          repr((_done18, _one18(_p18c, "SELECT name FROM sqlite_master WHERE type='table'"))))
    check("autoincrement: ...and the other tables are still rebuilt (control)",
          sorted(_done18) == sorted(n for n in _KEYED18 if n not in ("server_tag", "custom_command")),
          repr(_done18))

    # ── what else reads the file: restore validation, and the salvage a repair falls back to ────
    def _archive18(dbpath, name):
        out = os.path.join(_TMP18, name)
        with _tar18.open(out, "w:gz") as tar:
            tar.add(dbpath, arcname="panel.db")
        return out

    check("autoincrement: restore validation accepts a backup of an upgraded database "
          "(sqlite_sequence is a table like any other)",
          _bk18._restore_db_refusal(_archive18(_p18a, "after.tar.gz")) == "",
          _bk18._restore_db_refusal(_archive18(_p18a, "after.tar.gz")))
    _p18d, _ = _old_db18("preupgrade.db")
    check("autoincrement: ...and one taken before the upgrade, which the next start then rebuilds",
          _bk18._restore_db_refusal(_archive18(_p18d, "before.tar.gz")) == "",
          _bk18._restore_db_refusal(_archive18(_p18d, "before.tar.gz")))
    _salv18 = os.path.join(_TMP18, "salvaged.db")
    _dump18 = _dbm18._rebuild_via_dump(_p18a, _salv18)
    _seq_a18 = _seq18(_p18a)
    _seq_s18 = _seq18(_salv18) if _dump18 else {}
    check("autoincrement: a salvage by dump keeps AUTOINCREMENT and every table's sequence",
          _dump18 and _seq_a18 and not any(_plain18(_salv18, n) for n in _KEYED18)
          and all(_seq_s18.get(n, 0) >= _seq_a18.get(n, 0) for n in _seq_a18),
          repr((_dump18, _seq_a18, _seq_s18)))

    # ── the floor from the columns that hold an id without a foreign key, each on its own ────────
    _nf18_ag = _nofk_floor18("game_server", "audit_log", "game_server_id")
    _nf18_ms = _nofk_floor18("game_server", "metric_sample", "server_id")
    _nf18_ar = _nofk_floor18("remote_server", "audit_log", "remote_id")
    _nf18_hs = _nofk_floor18("remote_server", "host_sample", "remote_id")
    check("autoincrement: a game server id only an audit row still names is not handed out again",
          _nf18_ag == 40, repr(_nf18_ag))
    check("autoincrement: ...nor one only a metric sample still names", _nf18_ms == 40,
          repr(_nf18_ms))
    check("autoincrement: a host id only an audit row still names is not handed out again",
          _nf18_ar == 40, repr(_nf18_ar))
    check("autoincrement: ...nor one only a host sample still names", _nf18_hs == 40,
          repr(_nf18_hs))

    # ── the tables keyed by a page's own URLs: a ban, an invite and a login session ─────────────
    with _a18.app_context():
        _nx18 = (_next_after_delete18(_m18.GlobalBan, steamid="STEAM_0:1:1830"),
                 _next_after_delete18(_m18.Invite, token_hash="p18x" * 16, expires_at=_soon18()),
                 _next_after_delete18(_m18.UserSession, user_id=1, sid="p18-next"))
    check("autoincrement: a removed global ban, invite or login session's id is not given to the "
          "next one", all(a != b for a, b in _nx18), repr(_nx18))
    _data_migration18()
finally:
    for _a in _apps18:
        try:
            with _a.app_context():
                db.session.remove()
                db.engine.dispose()
        except Exception:  # nosec B110 - best-effort cleanup of throwaway databases
            pass
    import shutil as _shutil18
    _shutil18.rmtree(_TMP18, ignore_errors=True)
