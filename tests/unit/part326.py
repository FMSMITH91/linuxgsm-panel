"""Part 326 of the unit suite: a lead a host's proof of the Updates and Websites work turned up.

1. The nightly window reads a server's crontab itself (as the game account) before it updates the server's game: a
   server whose own scheduled task runs `update` is left to that task even when nothing read the crontab since the
   panel started, and a crontab that could not be read (or whose read is refused) leaves the server alone that night,
   with a History row saying why. The Updates row says when the crontab is not read yet, and opening the page reads
   none.

HOW IT RUNS. Through part12's app (its tripwire armed): the window by updates_auto.tick, the Start by its route over a
stand-in host that runs the panel's real awk over fixture `ss -e` lines, the cache switch by its route.
"""
import os
import re as _re326
import shlex as _shlex326
import shutil as _shutil326
import subprocess as _sp326  # nosec B404 - bash over this part's own fixtures
import tempfile as _tf326
import time as _time326

from flask import g as _g326

from unit.part01 import check, eq
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_patch_sm, _p9_quiet_lookups,
                         _p9_restore_all)
from panel.core import config as _cfg326
from panel.core.clock import utcnow as _utcnow326
from panel.db.models import (AuditLog as _Audit326, GameServer as _GS326, RemoteServer as _Remote326, User as _User326,
                             Website as _Site326, WebsiteDomain as _Dom326, WebsiteProxy as _Proxy326, db as _db326)
from panel.ops.ssh_manager import _core as _core326, portscan as _ps326, websites as _sw326
from panel.routes import _shared as _sh326, server_detail as _sd326, websites as _w326, websites_proxy as _wpx326
from panel.services import (game_updates as _gu326, game_updates_run as _gur326, monitoring as _mon326,
                            updates as _u326, updates_auto as _ua326)
from panel.routes import updates_game as _ug326

_ROWS326 = {"sites": [], "remotes": [], "users": [], "servers": []}
_TOKEN326 = "y" * 40
_STEAM326 = ("Update available\n* Local build: 22345678\n* Remote build: 22399999\n* Branch: public\n"
             "https://steamdb.info/app/4020/history\n")
_TASK326 = {"command": "/home/p326gmod/gmodserver update > /dev/null 2>&1", "schedule": "15 5 * * *"}


def _client326(uid):
    _g326.pop("_login_user", None)
    return _p9_client(uid)


def _setup326():
    r = _Remote326(name="p326-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.126", timezone="UTC")
    su = _User326(username="p326-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db326.session.add_all([r, su])
    _db326.session.commit()
    _ROWS326["remotes"].append(r.id)
    _ROWS326["users"].append(su.id)
    return r, su


def _gs326(host, name, game, short, port, status="offline"):
    gs = _GS326(name=name, game_type=game, short_name=short, port=port, remote_id=host.id, installed=True,
                status=status)
    _db326.session.add(gs)
    _db326.session.commit()
    _ROWS326["servers"].append(gs.id)
    return gs


# ── 1. The window reads the crontab itself ─────────────────────────────────────────────────────────
def _window326(gs, cron):
    """One window pass over `gs`: (update_game ran, crontab reads, the update_skipped rows' details)."""
    updated, reads = [], []

    def _list(remote, user, selfname=None):
        reads.append(user)
        return [dict(j) for j in cron] if isinstance(cron, list) else cron
    _p9_patch_sm("list_cron_jobs", _list)
    _p9_patch(_gur326, "update_game", lambda app, g, actor, backup=False: updated.append(g.id))
    _u326.forget_server(gs.id)              # nothing read since the panel started
    _gu326.note_output(gs.id, _STEAM326)
    start = _db326.session.query(_db326.func.max(_Audit326.id)).scalar() or 0
    _ua326._DONE.clear()
    _ua326.tick(_p9)
    rows = [a.detail for a in _Audit326.query.filter(_Audit326.id > start, _Audit326.game_server_id == gs.id,
                                                     _Audit326.action == "update_skipped")]
    return updated, reads, rows


def _window_now326():
    """Open the window around the host's clock now (UTC): the window's pass and the Updates row read the same night."""
    now = _time326.gmtime()
    t = now.tm_hour * 60 + now.tm_min
    start, end = ("%02d:%02d" % divmod((t + d) % 1440, 60) for d in (-1, 30))
    _cfg326.update_config(lambda cfg: cfg.update({_u326.CFG: {"start": start, "end": end, "off": []}}))
    return start


def _s1_window(host, su):
    gs = _gs326(host, "p326-gmod", "gmod", "p326gmod", 27215)
    at = _window_now326()
    _p9_patch(_ua326, "_site_ids", lambda: [])
    _p9_patch(_ua326, "_server_ids", lambda: [gs.id])
    _p9_patch(_ua326, "_pending_addons", lambda g, cfg: [])
    _p9_patch(_gu326, "check_pass", lambda now=None: None)
    _p9_patch(_sh326, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_mon326, "_cached_player_count", lambda sid: 0)
    own = _window326(gs, [_TASK326])
    eq("nightly window (updates_auto.tick), a crontab nothing read since the panel started: the window reads it as the "
       "game account, finds the server's own update task and leaves the server to it (no update, no skip row)",
       own, ([], ["p326gmod"], []))
    eq("nightly window: what it read is remembered, so the Updates row names that task",
       (_u326.lgsm_cron_seen(gs.id) or {}).get("game"), "15 5 * * *")
    unread = _window326(gs, None)
    eq("nightly window, a crontab that could not be read: the server is left alone that night (no update), and History "
       "says why", (unread[0], unread[1], [_ua326.CRON_UNREAD in d for d in unread[2]]), ([], ["p326gmod"], [True]))
    row = _row326(su, gs)
    eq("Updates (GET /api/updates after the unread crontab): the row says the window could not read its scheduled "
       "tasks and left it alone", row.get("when"), _ug326.S_TRIED_UNREAD.replace("{at}", at))
    _p9_patch(_sh326, "game_account_write_refusal", lambda *a, **k: "refused: a root-capable account")
    refused = _window326(gs, [])
    _p9_patch(_sh326, "game_account_write_refusal", lambda *a, **k: None)
    eq("nightly window, a crontab read the account's refusal stops: not read, so the server is left alone (no update)",
       (refused[0], refused[1], len(refused[2])), ([], [], 1))
    plain = _window326(gs, [])
    eq("nightly window (control: its crontab read, no update task in it): the window updates the server",
       (plain[0], plain[1], plain[2]), ([gs.id], ["p326gmod"], []))


def _row326(su, gs):
    _u326.forget_counts()
    body = _p9_json(_client326(su.id).get("/api/updates"))
    rows = {r["ref"]: r for g in body.get("groups") or [] for r in g["items"]}
    return rows.get("game:%d" % gs.id) or {}


def _s1_row(host, su):
    gs = _db326.session.query(_GS326).filter_by(short_name="p326gmod").one()
    reads = []
    _p9_patch_sm("list_cron_jobs", lambda remote, user, selfname=None: reads.append(user) or [])
    _u326.forget_server(gs.id)
    _gu326.note_output(gs.id, _STEAM326)
    _ua326._DONE.clear()
    unread = _row326(su, gs).get("when") or ""
    _u326.note_lgsm_cron(gs.id, [])
    read = _row326(su, gs).get("when") or ""
    eq("Updates (GET /api/updates, a crontab not read since the panel started): the row says its scheduled tasks are "
       "not read yet and the window reads them first, and opening the page reads none",
       (unread.endswith(" " + _ug326.S_CRON_UNREAD), reads), (True, []))
    eq("Updates (control: its crontab read, no update task): the window's words alone",
       (read.startswith("By itself"), _ug326.S_CRON_UNREAD in read), (True, False))


def _cleanup326():
    _db326.session.rollback()
    remotes = _ROWS326["remotes"] or [0]
    sites = sorted(set(_ROWS326["sites"]) | {s.id for s in _Site326.query.filter(_Site326.remote_id.in_(remotes))})
    _Audit326.query.filter(_Audit326.website_id.in_(sites or [0])).delete(synchronize_session=False)
    _Audit326.query.filter(_Audit326.remote_id.in_(remotes)).delete(synchronize_session=False)
    _Audit326.query.filter(_Audit326.game_server_id.in_(_ROWS326["servers"] or [0])).delete(synchronize_session=False)
    for row in (_Dom326.query.filter(_Dom326.website_id.in_(sites or [0])).all()
                + _Proxy326.query.filter(_Proxy326.remote_id.in_(remotes)).all()):
        _db326.session.delete(row)
    for model, ids in ((_Site326, sites), (_GS326, _ROWS326["servers"]), (_User326, _ROWS326["users"]),
                       (_Remote326, _ROWS326["remotes"])):
        for i in ids:
            got = _db326.session.get(model, i)
            if got is not None:
                _db326.session.delete(got)
    _db326.session.commit()
    _cfg326.update_config(lambda cfg: cfg.pop(_u326.CFG, None))
    for i in _ROWS326["servers"]:
        _u326.forget_server(i)
        _gu326.forget(i)
    _ua326._DONE.clear()
    _u326.forget_counts()


def _ran326(step, *args):
    """Run one section: True when it ran to the end, else None (the traceback kept in _ran326.last)."""
    import traceback
    try:
        step(*args)
        _ran326.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db326.session.rollback()
        _ran326.last = traceback.format_exc()[-1500:]
        return None


_ran326.last = ""
_trips326 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part326")
        _cfg326.update_config(lambda cfg: cfg.update({_u326.CFG: {"start": "04:00", "end": "05:00", "off": []}}))
        _host326r, _su326 = _setup326()
        for _sec326 in (_s1_window, _s1_row):
            check("part326: %s ran to the end" % _sec326.__name__, _ran326(_sec326, _host326r, _su326), _ran326.last)
        eq("part326: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips326:], [])
    finally:
        _p9_restore_all()
        _cleanup326()
