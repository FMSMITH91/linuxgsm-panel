"""Part 326 of the unit suite: three leads a host's proof of the Updates and Websites work turned up.

1. The nightly window reads a server's crontab itself (as the game account) before it updates the server's game: a
   server whose own scheduled task runs `update` is left to that task even when nothing read the crontab since the
   panel started, and a crontab that could not be read (or whose read is refused) leaves the server alone that night,
   with a History row saying why. The Updates row says when the crontab is not read yet, and opening the page reads
   none.
2. A panel Start's port check counts only a socket of the protocol the game binds on its port, held by another
   account: another server's UDP query socket on a Minecraft server's TCP port is no clash, and another account's TCP
   listener there is refused naming that account. Both reads of the host's sockets (the port scan and the host sample
   that shares it) carry each socket's protocol.
3. Turning "Page cache in the web proxy" off is applied at once: the proxy loads its configuration without the cache.

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


# ── 2. The Start's port check: the game's protocol, another account ────────────────────────────────
_SS_RE326 = _re326.compile(r"ss -H -l[nt]{2}ue?(?: '\(([^)]*)\)')? 2>/dev/null")
_SAMPLE326 = ("cpu  100 0 100 800 0 0 0\nGJA 0\ncpu  110 0 110 880 0 0 0\nGJB 0\nGAMERAM 0 0\nGUP 0\n"
              "MEM 8000000000 2000000000\nLOAD 0.1 0.2 0.3\nDISK 1000 500\nCORES 2\nUPTIME 999\n")
_PMC_UDP326 = "udp   UNCONN 0      0                 *:25565            *:*    uid:1202 ino:91 sk:1 <->"
_PMC_TCP326 = "tcp   LISTEN 0      4096              *:25566            *:*    uid:1202 ino:92 sk:2 <->"
_OTHER_TCP326 = "tcp   LISTEN 0      4096              *:25565            *:*    uid:1202 ino:93 sk:3 <->"
_ROOT_TCP326 = "tcp   LISTEN 0      4096              *:25565            *:*    ino:94 sk:4 <->"
_GMOD_TCP326 = "tcp   LISTEN 0      4096              *:27216            *:*    uid:1202 ino:95 sk:5 <->"


def _bash326(script):
    return _sp326.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,  # nosec B603 B607
                      check=False).stdout


def _host326(ss_lines, passwd, ran):
    """run_command answering every `ss` read (the scan, the host sample, a server's sample) with its real awk."""
    uids = {ln.split(":")[0]: ln.split(":")[2] for ln in open(passwd, encoding="ascii").read().split()}

    def _printf(m):
        ports = set(_re326.findall(r"sport = :(\d+)", m.group(1) or ""))
        lines = [ln for ln in ss_lines if not ports or ln.split()[4].rsplit(":", 1)[1] in ports]
        return "printf '%s\\n' " + " ".join(_shlex326.quote(ln) for ln in lines) if lines else "true"

    def _run(server, cmd, timeout=None, sudo=None, **_kw):
        if "ss -H" not in cmd:
            return "", "", 0
        ran.append("sample" if "ps -u" in cmd else "host" if "PORTS" in cmd else "scan")
        parts = [p for p in cmd.split(" ; ") if "ss -H" in p]
        script = " ; ".join(_SS_RE326.sub(_printf, p) for p in parts).replace('"/etc/passwd"', '"%s"' % passwd)
        for name, uid in uids.items():
            script = script.replace("$(id -u %s 2>/dev/null)" % name, uid)
        out = _bash326(script)
        return (_SAMPLE326 + out if "ps -u" in cmd else out), "", 0
    return _run


def _fresh326(host):
    _core326._live_metrics_cache.clear()
    _core326._host_metrics_cache.clear()
    _ps326._port_scan_cache.pop(host.id, None)


def _start326(host, su, gs, lines, passwd, started, sample_first=False):
    """POST start (no force) over a host whose sockets are `lines`: (success, port_in_use, message, started, reads)."""
    ran = []
    _p9_patch_sm("run_command", _host326(lines, passwd, ran))
    _fresh326(host)
    if sample_first:            # the dashboard's host sample read the sockets a moment before
        _core326.host_live_metrics(host)
    del started[:]
    body = _p9_json(_client326(su.id).post("/api/server/%d/action" % gs.id, json={"action": "start"}))
    return body.get("success"), bool(body.get("port_in_use")), body.get("message") or "", list(started), ran


def _s2_port(host, su):
    _p9_quiet_lookups()
    d = _tf326.mkdtemp(prefix="lgsm-unit-p326-ss-")
    passwd = os.path.join(d, "passwd")
    with open(passwd, "w", encoding="ascii") as fh:
        fh.write("root:x:0:0::/root:/bin/sh\np326mc:x:1201:1201::/home/p326mc:/bin/bash\n"
                 "p326pmc:x:1202:1202::/home/p326pmc:/bin/bash\np326gm:x:1203:1203::/home/p326gm:/bin/bash\n")
    mc = _gs326(host, "p326-mc", "mc", "p326mc", 25565)
    _gs326(host, "p326-pmc", "pmc", "p326pmc", 25566, status="online")
    gm = _gs326(host, "p326-gm", "gmod", "p326gm", 27216)
    started = []
    _p9_patch(_sd326, "_bg_power_action", lambda app, gs, remote, action, actor, origin=None, on_done=None:
              started.append((gs.id, action)))
    try:
        udp = _start326(host, su, mc, [_PMC_UDP326, _PMC_TCP326], passwd, started)
        shared = _start326(host, su, mc, [_PMC_UDP326, _PMC_TCP326], passwd, started, sample_first=True)
        tcp = _start326(host, su, mc, [_PMC_UDP326, _PMC_TCP326, _OTHER_TCP326], passwd, started)
        root = _start326(host, su, mc, [_ROOT_TCP326], passwd, started)
        gmod = _start326(host, su, gm, [_GMOD_TCP326], passwd, started)
    finally:
        _shutil326.rmtree(d, ignore_errors=True)
        _fresh326(host)
    eq("port check (POST /api/server/<id>/action start): a stopped Minecraft server beside another account's UDP query "
       "socket on its TCP port 25565 starts, with no \"Port in use\" question",
       (udp[0], udp[1], udp[3]), (True, False, [(mc.id, "start")]))
    eq("port check: the same when the dashboard's host sample read the sockets (the scan it shares carries each "
       "socket's protocol too)", (shared[:2], shared[3], "scan" in shared[4]),
       ((True, False), [(mc.id, "start")], False))
    eq("port check (control: another account's TCP listener on the game's TCP port): still asked, naming the account",
       (tcp[0], tcp[1], "the 'p326pmc' account" in tcp[2], tcp[3]), (False, True, True, []))
    eq("port check (control: a socket no account is printed for, root's): asked as before, not by a known server",
       (root[0], root[1], "not by a server the panel knows" in root[2], root[3]), (False, True, True, []))
    eq("port check (control: a game that binds both protocols): another account's TCP socket on its port is a clash",
       (gmod[0], gmod[1], "the 'p326pmc' account" in gmod[2], gmod[3]), (False, True, True, []))


# ── 3. Page cache turned off: applied at once ──────────────────────────────────────────────────────
def _site326(host, name):
    s = _Site326(remote_id=host.id, name=name, state="running", enabled=True, kind="static",
                 proxy_secret=_cfg326.encrypt_secret(_TOKEN326))
    _db326.session.add(s)
    _db326.session.flush()
    s.account, s.port = "ws%d" % s.id, 20900 + s.id % 90
    _db326.session.add(_Dom326(website_id=s.id, domain="%s.example.org" % name, is_primary=True,
                               verified_at=_utcnow326(), dns_state="matching"))
    _db326.session.commit()
    _ROWS326["sites"].append(s.id)
    return s


def _forget_cache326(cfg):
    """Take the page cache option this section saved out of the panel's config again."""
    cfg.pop("websites_cache_build", None)


def _s3_cache_off(host, su):
    _site326(host, "p326site")
    row = _w326.proxy_row(host.id)
    row.installed_version = "2.11.9"
    _db326.session.commit()
    loaded, threads = [], []
    _p9_patch(_sw326, "proxy_status", lambda remote, proxy=None: (True, "installed=yes\nversion=v2.11.9\ncache=yes\n"))
    _p9_patch(_sw326, "ports_apply", lambda remote, proxy, enabled: (True, "ok"))
    _p9_patch(_sw326, "proxy_apply", lambda remote, text, sites=(), proxy=None, start_it=False:
              loaded.append(text) or (True, "ok"))

    class _Thread326:
        def __init__(self, target=None, args=(), daemon=None):
            self.args = args

        def start(self):
            threads.append(self.args[1])
    _p9_patch(_wpx326, "threading", type("_T", (), {"Thread": _Thread326}))
    _cfg326.update_config(lambda cfg: cfg.update(websites_cache_build=True))
    try:
        off = _client326(su.id).post("/websites/proxy/options", json={"options": {"cache_build": False}})
        off_loaded = list(loaded)
        del loaded[:]
        again = _client326(su.id).post("/websites/proxy/options", json={"options": {"cache_build": False}})
        again_loaded = list(loaded)
        on = _client326(su.id).post("/websites/proxy/options", json={"options": {"cache_build": True}})
    finally:
        _cfg326.update_config(_forget_cache326)
    eq("web proxy options (POST /websites/proxy/options, page cache turned off): applied at once, the proxy loads its "
       "configuration without the cache and its admin socket",
       (off.status_code, _p9_json(off).get("message"), len(off_loaded),
        all("\tadmin off" in t and "admin unix/" not in t for t in off_loaded)),
       (200, _wpx326.S_APPLIED, 1, True))
    eq("web proxy options (controls: saved again unchanged, nothing applied; turned on, the build starts and the save "
       "itself loads nothing)", (again.status_code, again_loaded, on.status_code, threads, loaded),
       (200, [], 200, [host.id], []))


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
    _forget326()


def _forget326():
    """What the panel keeps outside the database for this part's servers: the window, the servers' reads."""
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
        for _sec326 in (_s1_window, _s1_row, _s2_port, _s3_cache_off):
            check("part326: %s ran to the end" % _sec326.__name__, _ran326(_sec326, _host326r, _su326), _ran326.last)
        eq("part326: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips326:], [])
    finally:
        _p9_restore_all()
        _cleanup326()
