"""Part 324 of the unit suite: website blocking and game updates as a real host showed them.

1. A ban's end is fail2ban's: its ticket's time plus its ban time, raised by fail2ban's growing ban after the ban
   action ran (the action's actionprolong). The Blocked visitors list says the end fail2ban will lift it at.
2. A ban names the site its counted lines asked for (the jail's tag), never another site's refused request; a ban
   fail2ban restores from its database at a jail's start keeps the site recorded before.
3. Unblock of an address already lifted on the host answers yes (the row then goes); another site's address is
   still not this site's to lift.
4. A game's run state and status count only its own account's sockets on its port: another account's socket on the
   same number (a query socket on UDP 25565 beside a Minecraft server's TCP 25565) never reads it as running, so
   Start is not refused as a no-op and the server list says offline.
5. The nightly window that stopped a server and could not start it again says so in History (and in its alert).
6. The Updates page: the greyed button's real reason (nothing listed; a host's packages); a queued update says so
   first; Update now's question names the server and whether the players on are warned; History's plain lines; the
   window's words follow the host's clock (now, tonight, the next night).
7. Settings' Outside services: the OWASP note follows every switch as it is flipped. The web proxy card's exposure
   summary says the mode in force after a refused save. Unblock asks first.
8. A web proxy apply with the page cache's admin socket on both sides loads the new configuration through it
   instead of restarting the proxy (its page cache and connections kept).

HOW IT RUNS. The root helper's verbs over scratch folders (part322's tree), fail2ban's action lines run as fail2ban
runs them (its tags filled in), the routes through part12's app (its tripwire armed), the pages' scripts in node.
"""
import calendar as _cal324
import json as _json324
import os
import re as _re324
import shlex as _shlex324
import shutil as _shutil324
import socket as _socket324
import subprocess as _sp324  # nosec B404 - bash over this part's own fixtures, node over the panel's scripts
import tempfile as _tf324
import threading as _th324
import time as _time324
from datetime import datetime as _dt324, timezone as _tz324
from types import SimpleNamespace as _NS324

from flask import g as _g324

from unit.part01 import check, eq
from unit.part12 import (_P9_PATCHED, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_patch_sm,
                         _p9_quiet_lookups, _p9_restore_all)
from unit.part322 import (_F2b322, _GUARD322, _H322, _host_helper322, _line322, _node322, _quiet322, _Seams322,
                          _tree322)
from panel.core import config as _cfg324
from panel.core.clock import utcnow as _utcnow324
from panel.db.models import (AuditLog as _Audit324, GameServer as _GS324, RemoteServer as _Remote324, User as _User324,
                             Website as _Site324, WebsiteDomain as _Dom324, WebsiteProxy as _Proxy324, db as _db324)
from panel.ops.ssh_manager import _core as _core324, portscan as _ps324, websites as _sw324
from panel.routes import _shared as _sh324, server_detail as _sd324
from panel.security.auth import log_action as _log324
from panel.services import (game_updates as _gu324, monitoring as _mon324, notifications as _nt324, updates as _u324,
                            updates_auto as _ua324)

_ROWS324 = {"sites": [], "remotes": [], "users": [], "servers": []}
_V324, _O324 = "198.51.100.7", "198.51.100.23"
_TOKEN324 = "x" * 40


def _client324(uid):
    _g324.pop("_login_user", None)
    _g324.__dict__.pop("_websites_access_cache", None)
    return _p9_client(uid)


def _setup324():
    r = _Remote324(name="p324-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.124", timezone="UTC")
    su = _User324(username="p324-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db324.session.add_all([r, su])
    _db324.session.commit()
    _ROWS324["remotes"].append(r.id)
    _ROWS324["users"].append(su.id)
    return r, su


def _site324(host, name, **kw):
    s = _Site324(remote_id=host.id, name=name, state="running", proxy_secret=_cfg324.encrypt_secret(_TOKEN324),
                 **dict({"kind": "static"}, **kw))
    _db324.session.add(s)
    _db324.session.flush()
    s.account, s.port = "ws%d" % s.id, 20600 + s.id % 300
    _db324.session.add(_Dom324(website_id=s.id, domain="%s.example.org" % name, is_primary=True,
                               verified_at=_utcnow324(), dns_state="matching"))
    _db324.session.commit()
    _ROWS324["sites"].append(s.id)
    return s


def _gs324(host, name, game, short, port, status="online", **kw):
    gs = _GS324(name=name, game_type=game, short_name=short, port=port, remote_id=host.id, installed=True,
                status=status, **kw)
    _db324.session.add(gs)
    _db324.session.commit()
    _ROWS324["servers"].append(gs.id)
    return gs


def _when324(epoch):
    return _dt324.fromtimestamp(int(epoch), _tz324.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ── fail2ban running the action file's lines, its tags filled in ───────────────────────────────────
def _f2b_act324(key, tags):
    """fail2ban running `key` (actionban, actionprolong...) of the helper's action file for a ticket's `tags`.

    None when the file has no such action (fail2ban then runs nothing for it); else the helper verb's (rc, output).
    """
    m = _re324.search(r"^%s = (.*)$" % key, _H322.WEB_GUARD_ACTION_TEXT, _re324.M)
    if not m or not m.group(1).strip():
        return None
    cmd = m.group(1)
    for k, v in tags.items():
        cmd = cmd.replace("<%s>" % k, str(v))
    argv = cmd.split()
    return _quiet322(_H322.ACTIONS[argv[1]], _H322.validate(argv[1], argv[2:]), "")


def _blocked324(su, site):
    body = _p9_json(_client324(su.id).get("/websites/%d/blocked" % site.id))
    return {e["ip"]: e for e in body.get("entries") or []}, body.get("others")


def _guard_tree324(f2b):
    d = _tf324.mkdtemp(prefix="lgsm-unit-p324-")
    seams, proxy = _tree322(d, [], f2b)
    _quiet322(_H322._web_guard_apply, dict(_GUARD322), proxy)
    _p9_patch(_sw324, "_helper", _host_helper322)
    return d, seams


def _log_line324(ip, tag, host):
    with open(_H322.WEB_SECURITY_LOG, "a", encoding="utf-8") as fh:
        fh.write((_line322(ip, tag, host) if tag else _line322(ip, "x", host).replace(',"lgsm":"x"', "")) + "\n")


# ── 1. The ban's end is fail2ban's ─────────────────────────────────────────────────────────────────
def _s1_until(host, su):
    from panel.routes import websites_guard as _rg
    site = _site324(host, "p324a")
    d, seams = _guard_tree324(_F2b322())
    try:
        _rg._set_cursor(host.id, 0)
        _log_line324(_V324, "login", site.domains[0].domain)
        _log_line324(_O324, "login", site.domains[0].domain)
        t = _time324.time() - 3.4
        # The observer raises a repeat offender's ban after the ban action ran (fail2ban: "Increase Ban").
        _f2b_act324("actionban", {"ip": _V324, "name": "lgsm-web-login", "time": "%.6f" % t, "bantime": 60,
                                  "restored": 0})
        _f2b_act324("actionprolong", {"ip": _V324, "name": "lgsm-web-login", "time": "%.6f" % t, "bantime": 240})
        _f2b_act324("actionban", {"ip": _O324, "name": "lgsm-web-login", "time": "%.6f" % t, "bantime": 600,
                                  "restored": 0})
        got = _blocked324(su, site)[0]
    finally:
        seams.restore()
        _shutil324.rmtree(d, ignore_errors=True)
    eq("blocked visitors (fail2ban's actionban, then its actionprolong for a growing ban, down to GET "
       "/websites/<id>/blocked): the list says the end fail2ban lifts it at (its ban's time plus the raised ban time), "
       "not the first ban time from when the action ran",
       ((got.get(_V324) or {}).get("since"), (got.get(_V324) or {}).get("until")),
       (_when324(t), _when324(int(t) + 240)))
    eq("blocked visitors (control: a ban fail2ban does not raise): it ends at its time plus its ban time",
       (got.get(_O324) or {}).get("until"), _when324(int(t) + 600))


# ── 2. The site a ban names ────────────────────────────────────────────────────────────────────────
def _s2_site(host, su):
    from panel.routes import websites_guard as _rg
    a, b = _site324(host, "p324b"), _site324(host, "p324c")
    da, db_ = a.domains[0].domain, b.domains[0].domain
    d, seams = _guard_tree324(_F2b322())
    try:
        _rg._set_cursor(host.id, 0)
        t = "%.3f" % _time324.time()
        _log_line324(_V324, "login", da)          # counted by the login jail, on a
        _log_line324(_V324, "scan", db_)          # the other jail's line, on b
        _log_line324(_V324, None, db_)            # a refused request (untagged), on b
        _f2b_act324("actionban", {"ip": _V324, "name": "lgsm-web-login", "time": t, "bantime": 600, "restored": 0})
        fresh = (_V324 in _blocked324(su, a)[0], _blocked324(su, b))
        # A restart of the jail: its stop flushes the entries, its start restores the live ban from fail2ban's database.
        _quiet322(_H322.do_website_guard_flush, ["lgsm-web-login"], "")
        _log_line324(_V324, None, db_)
        _f2b_act324("actionban", {"ip": _V324, "name": "lgsm-web-login", "time": t, "bantime": 600, "restored": 1})
        restored = (_V324 in _blocked324(su, a)[0], _blocked324(su, b))
        _log_line324(_O324, "login", db_)
        _f2b_act324("actionban", {"ip": _O324, "name": "lgsm-web-login", "time": t, "bantime": 600, "restored": 0})
        control = _O324 in _blocked324(su, b)[0]
    finally:
        seams.restore()
        _shutil324.rmtree(d, ignore_errors=True)
    eq("blocked visitors (fail2ban's actionban, a fresh ban): the site is the one its jail's counted line asked for, "
       "not the site of the address's newest line (another jail's, or a refused request on another site)",
       fresh, (True, ({}, 1)))
    eq("blocked visitors (fail2ban's actionban after a jail restart, restored from its database): the ban keeps the "
       "site recorded before, never the site of the newest line in the log", restored, (True, ({}, 1)))
    eq("blocked visitors (control: a fresh ban counted on the other site): that site lists it", control, True)


# ── 3. Unblock of an address already lifted ────────────────────────────────────────────────────────
def _s3_lifted(host, su):
    from panel.routes import websites_guard as _rg
    a, b = _site324(host, "p324d"), _site324(host, "p324e")
    f2b = _F2b322()
    d, seams = _guard_tree324(f2b)
    try:
        _rg._set_cursor(host.id, 0)
        _log_line324(_V324, "login", a.domains[0].domain)
        _log_line324(_O324, "login", b.domains[0].domain)
        t = "%.3f" % _time324.time()
        for ip in (_V324, _O324):
            f2b.banned["lgsm-web-login"].add(ip)
            _f2b_act324("actionban", {"ip": ip, "name": "lgsm-web-login", "time": t, "bantime": 600, "restored": 0})
        listed = _V324 in _blocked324(su, a)[0]
        f2b(["fail2ban-client", "set", "lgsm-web-login", "unbanip", _V324])      # by hand, on the host
        del f2b.calls[:]
        c = _client324(su.id)
        lifted = c.post("/websites/%d/blocked/unban" % a.id, json={"ip": _V324})
        other = _client324(su.id).post("/websites/%d/blocked/unban" % a.id, json={"ip": _O324})
        junk = _client324(su.id).post("/websites/%d/blocked/unban" % a.id, json={"ip": "not-an-address"})
        released = [x for x in f2b.calls if x[:1] == ["set"]]
    finally:
        seams.restore()
        _shutil324.rmtree(d, ignore_errors=True)
    eq("blocked visitors (POST /websites/<id>/blocked/unban of an address fail2ban's unbanip already lifted on the "
       "host): it answers yes, said as already unblocked, so the page drops the row",
       (listed, lifted.status_code, _p9_json(lifted).get("success"), _p9_json(lifted).get("message")),
       (True, 200, True, "It was already unblocked."))
    eq("blocked visitors (Unblock, control: an address only another site's list holds, or no address at all): still "
       "not this site's to lift, and fail2ban is not asked to",
       (other.status_code, junk.status_code, released), (404, 404, []))


# ── 4. Run state and status: the game account's own sockets ────────────────────────────────────────
_PMC_UDP324 = "udp   UNCONN 0      0                 *:25565            *:*    uid:1102 ino:91 sk:1 <->"
_PMC_TCP324 = "tcp   LISTEN 0      4096              *:25566            *:*    uid:1102 ino:92 sk:2 <->"
_MC_TCP324 = "tcp   LISTEN 0      4096              *:25565            *:*    uid:1101 ino:93 sk:3 <->"
_SAMPLE324 = ("cpu  100 0 100 800 0 0 0\nGJA 0\ncpu  110 0 110 880 0 0 0\nGJB 0\nGAMERAM 0 0\nGUP 0\n"
              "MEM 8000000000 2000000000\nLOAD 0.1 0.2 0.3\nDISK 1000 500\nCORES 2\nUPTIME 999\n")
_SS_RE324 = _re324.compile(r"ss -H -l[nt]{2}ue?(?: '\(([^)]*)\)')? 2>/dev/null")


def _bash324(script):
    return _sp324.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,  # nosec B603 B607
                      check=False).stdout


def _host324(ss_lines, passwd):
    """run_command answering the live sample and the port scan by running their real awk over `ss_lines`."""
    uids = {ln.split(":")[0]: ln.split(":")[2] for ln in open(passwd, encoding="ascii").read().split()}

    def _printf(m):
        ports = set(_re324.findall(r"sport = :(\d+)", m.group(1) or ""))
        lines = [ln for ln in ss_lines if not ports or ln.split()[4].rsplit(":", 1)[1] in ports]
        return "printf '%s\\n' " + " ".join(_shlex324.quote(ln) for ln in lines) if lines else "true"

    def _run(server, cmd, timeout=None, sudo=None, **_kw):
        if not _SS_RE324.search(cmd):
            return "", "", 0
        script = _SS_RE324.sub(_printf, cmd).replace('"/etc/passwd"', '"%s"' % passwd)
        for name, uid in uids.items():
            script = script.replace("$(id -u %s 2>/dev/null)" % name, uid)
        if "ps -u" in cmd:          # the live sample: its port line run for real, the rest fixed figures
            return _SAMPLE324 + _bash324(" ; ".join(p for p in script.split(" ; ") if "PORT" in p)), "", 0
        return _bash324(script), "", 0
    return _run


def _restore_one324(owner, name):
    if (owner, name) in _P9_PATCHED:
        setattr(owner, name, _P9_PATCHED.pop((owner, name)))


def _s4_own_port(host, su):
    _p9_quiet_lookups()
    d = _tf324.mkdtemp(prefix="lgsm-unit-p324-ss-")
    passwd = os.path.join(d, "passwd")
    with open(passwd, "w", encoding="ascii") as fh:
        fh.write("root:x:0:0::/root:/bin/sh\np324mc:x:1101:1101::/home/p324mc:/bin/bash\n"
                 "p324pmc:x:1102:1102::/home/p324pmc:/bin/bash\n")
    mc = _gs324(host, "p324-mc", "mc", "p324mc", 25565, status="online")
    pmc = _gs324(host, "p324-pmc", "pmc", "p324pmc", 25566, status="online")
    started = []
    _p9_patch(_sd324, "_bg_power_action", lambda app, gs, remote, action, actor, origin=None, on_done=None:
              started.append((gs.id, action)))
    try:
        out = {}
        for name, lines in (("other", [_PMC_UDP324, _PMC_TCP324]), ("own", [_PMC_UDP324, _PMC_TCP324, _MC_TCP324])):
            _p9_patch_sm("run_command", _host324(lines, passwd))
            _core324._live_metrics_cache.clear()
            _ps324._port_scan_cache.pop(host.id, None)
            _db324.session.get(_GS324, mc.id).status = "online"
            _db324.session.commit()
            del started[:]
            r = _client324(su.id).post("/api/server/%d/action" % mc.id, json={"action": "start", "force": True})
            _ps324._port_scan_cache.pop(host.id, None)
            listed = _client324(su.id).get("/api/servers").get_json(silent=True)
            rows = {x["id"]: x["status"] for x in listed if isinstance(x, dict)} if isinstance(listed, list) else {}
            out[name] = (_p9_json(r).get("success"), list(started), rows.get(mc.id), rows.get(pmc.id))
    finally:
        _shutil324.rmtree(d, ignore_errors=True)
        _core324._live_metrics_cache.clear()
        _ps324._port_scan_cache.pop(host.id, None)
        _restore_one324(_sd324, "_bg_power_action")
        _restore_one324(_core324, "run_command")
    eq("run state (POST /api/server/<id>/action start, and GET /api/servers): a Minecraft server whose TCP 25565 is "
       "closed, beside another account's UDP 25565 query socket, is not refused as already running and lists as "
       "offline; the other server, on its own port, stays online",
       out["other"], (True, [(mc.id, "start")], "offline", "online"))
    eq("run state (control: its own account listens on its port): Start is refused as a no-op and it lists as online",
       out["own"], (False, [], "online", "online"))


# ── 5. The window leaves a server stopped: History says so ─────────────────────────────────────────
_STEAM324 = ("Update available\n* Local build: 12345678\n* Remote build: 12399999\n* Branch: public\n"
             "https://steamdb.info/app/4020/history\n")
_IN324 = _cal324.timegm((2026, 11, 27, 4, 30, 0))


def _window_run324(gs, answers):
    """One nightly window pass over `gs` (Back up first on), _run_action answering `answers` per step."""
    ran, sent = [], []

    def _run(app, g, remote, action, actor, origin=None, on_done=None, port_gate=None):
        ran.append(action)
        ok, said = answers.get(action, (True, "ok"))
        if ok is False and action == "start":
            return False, said                    # _run_action's own refusal: on_done never fires
        if on_done is not None:
            on_done(ok, said)
        return True, "'%s' started" % action
    _p9_patch(_sd324, "_run_action", _run)
    _p9_patch(_nt324, "notify", lambda kind, title, text, *a, **k: sent.append(text))
    _gu324.note_output(gs.id, _STEAM324)
    start = _db324.session.query(_db324.func.max(_Audit324.id)).scalar() or 0
    _ua324._DONE.clear()
    _ua324.tick(_p9, now=_IN324)
    rows = [(a.action, a.detail, bool(a.success)) for a in _Audit324.query.filter(
        _Audit324.id > start, _Audit324.game_server_id == gs.id, _Audit324.action == "update_left_stopped")]
    return ran, rows, sent


def _s5_left_stopped(host, su):
    gs = _gs324(host, "p324-gmod2", "gmod", "p324gmod2", 27125)
    _u324.set_backup_first(gs.id, True)
    _p9_patch(_ua324, "_site_ids", lambda: [])
    _p9_patch(_ua324, "_server_ids", lambda: [gs.id])
    _p9_patch(_ua324, "_pending_addons", lambda g, cfg: [])
    _p9_patch(_gu324, "check_pass", lambda now=None: None)
    _p9_patch(_sh324, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_mon324, "_cached_player_count", lambda sid: 0)
    _p9_patch(_sh324, "get_server_status", lambda remote, g, distinguish_unresponsive=False: "online")
    refused = "That server is already running. Use 'restart' if you want it bounced."
    ran, rows, sent = _window_run324(gs, {"start": (False, refused)})
    hist = [h for h in _p9_json(_client324(su.id).get("/api/updates")).get("history") or []
            if h.get("action") == "update_left_stopped" and h.get("target") == gs.name]
    eq("nightly window, Back up first (updates_auto.tick -> update_game): a start refused after the update leaves a "
       "History row saying the server was left stopped and why, marked failed, and the alert says so too",
       (ran, [(a, "left stopped: " + refused in dt, ok) for a, dt, ok in rows],
        [h.get("badge") for h in hist][:1], ["left stopped" in s for s in sent]),
       (["stop", "backup", "update", "start"], [("update_left_stopped", True, False)], ["failed"], [True]))
    ran, rows, sent = _window_run324(gs, {"update": (False, "SteamCMD failed"), "start": (False, refused)})
    eq("nightly window: an update that fails and a start again that is refused: the History row and one alert with "
       "both reasons", (ran, len(rows), len(sent), "SteamCMD failed" in "".join(sent), "left stopped" in "".join(sent)),
       (["stop", "backup", "update", "start"], 1, 1, True, True))
    ran, rows, sent = _window_run324(gs, {})
    eq("nightly window (control: the server starts again): no left-stopped row, no alert", (ran[-1:], rows, sent),
       (["start"], [], []))
    _u324.set_backup_first(gs.id, False)
    _restore_one324(_sd324, "_run_action")


# ── 6. The Updates page ────────────────────────────────────────────────────────────────────────────
def _rows324(su):
    body = _p9_json(_client324(su.id).get("/api/updates"))
    return {r["ref"]: r for g in body.get("groups") or [] for r in g["items"]}, body


def _s6_queue_first(host, su, gs):
    _p9_patch(_sh324, "game_account_write_refusal", lambda *a, **k: None)
    _gu324.note_output(gs.id, _STEAM324)
    _u324.note_lgsm_cron(gs.id, [{"command": "/home/p324gmod/gmodserver update > /dev/null 2>&1",
                                  "schedule": "15 5 * * *"}])
    c = _client324(su.id)
    queued = _p9_json(c.post("/api/updates/game/%d" % gs.id, json={"when": "empty"}))
    row = _rows324(su)[0].get("game:%d" % gs.id) or {}
    cancel = _p9_json(_client324(su.id).post("/api/updates/game/%d" % gs.id, json={"when": "cancel"}))
    _u324.note_lgsm_cron(gs.id, [])
    eq("Updates (Update when empty on a server whose own task runs update): the row and the answer say it is queued "
       "first, before the task; Don't wait answers with the task's line again",
       (queued.get("when"), row.get("when"), cancel.get("when")),
       ("Queued: it updates as soon as no players are on.", "Queued: it updates as soon as no players are on.",
        "By itself: its scheduled task runs update (15 5 * * *, the host's clock)."))


def _s6_confirm(host, su, gs):
    gs.status = "online"          # a running server (section 4's server list read the host's ports)
    _db324.session.commit()
    _gu324.note_output(gs.id, _STEAM324)
    out = {}
    for n in (3, 0):
        _p9_patch(_mon324, "_cached_player_count", lambda sid, n=n: n)
        row = _rows324(su)[0].get("game:%d" % gs.id) or {}
        act = row.get("action") or {}
        out[n] = (act.get("confirm_title"), "The 3 player(s) on now are warned in the game first" in
                  (act.get("confirm") or ""), (act.get("confirm") or "").startswith(row.get("cost") or "?"))
    eq("Updates (a game row's Update now): its question names the server, says what it costs and, with players on, "
       "that they are warned in the game first and how long before",
       out[3], ("Update p324-gmod now?", True, True))
    eq("Updates (control: nobody on): the question names the server and its cost, no warning", out[0],
       ("Update p324-gmod now?", False, True))


def _s6_history(host, su, gs):
    tail = ("ll, use YldRebuildInvalidPlatformTracking instead OK\n[ OK ] Starting gmodserver")
    teed = {"out": _STEAM324 + "Success! App '4020' fully installed.\n"}
    _p9_patch(_sd324, "_run_teed", lambda app, remote, sid, short, action, selfname, monitor=True:
              (teed["out"], "", 0))
    _p9_patch(_sd324, "_db_dump_before", lambda *a, **k: None)
    _p9_patch(_sh324, "game_account_write_refusal", lambda *a, **k: None)
    _gu324.note_output(gs.id, _STEAM324)
    start = _db324.session.query(_db324.func.max(_Audit324.id)).scalar() or 0
    _client324(su.id).post("/api/server/%d/action" % gs.id, json={"action": "update"})
    deadline = _time324.time() + 10
    while _time324.time() < deadline:
        _db324.session.expire_all()
        if _Audit324.query.filter(_Audit324.id > start, _Audit324.action == "update_complete").count():
            break
        _time324.sleep(0.05)
    _log324(None, "update_complete", target=gs.name, server=gs, success=True, detail=tail)
    _log324(None, "update_complete", target=gs.name, server=gs, success=False, detail=tail)
    _log324(su, "update_when_empty", target=gs.name, server=gs, detail="queued")
    _log324(su, "update_when_empty", target=gs.name, server=gs, detail="no longer queued")
    hist = [(h["action"], h["badge"], h["detail"]) for h in _rows324(su)[1].get("history") or []
            if h.get("target") == gs.name and h["action"] in ("update_complete", "update_when_empty")][:5]
    eq("Updates (History, after the server page's Update ran in the background): an update's end is one plain line, "
       "the build it installed when LinuxGSM printed it, else \"Updated.\"; a failed one says where its output is; "
       "Update when empty says it waits for players to leave, or no longer does",
       hist, [("update_when_empty", "cancelled", "No longer waiting for players to leave."),
              ("update_when_empty", "queued", "Queued for when players leave."),
              ("update_complete", "failed", "The update failed: the audit log keeps LinuxGSM's output."),
              ("update_complete", "done", "Updated."),
              ("update_complete", "done", "Updated to build 12399999.")])


def _hhmm324(minutes):
    return "%02d:%02d" % divmod(minutes % 1440, 60)


def _s6_window_words(host, su, gs):
    site = _site324(host, "p324w", kind="php", php_version="8.4")
    site.image_digest, site.image_key = "localhost/p324-old:1", "files-1"
    _db324.session.commit()
    _ua324._DONE.clear()          # nothing tried in a window yet (section 5's tick ran on its own clock)
    _gu324.note_output(gs.id, _STEAM324)
    now = _time324.gmtime()
    t = now.tm_hour * 60 + now.tm_min
    out = {}
    for name, (s, e) in (("open", (t - 1, t + 30)), ("over", (t - 180, t - 120)), ("ahead", (t + 120, t + 180))):
        _cfg324.update_config(lambda cfg, s=s, e=e: cfg.update({_u324.CFG: {"start": _hhmm324(s), "end": _hhmm324(e),
                                                                           "off": []}}))
        _u324.forget_counts()
        rows = _rows324(su)[0]
        out[name] = ((rows.get("game:%d" % gs.id) or {}).get("when"), (rows.get("website:%d" % site.id) or {}).get("when"))
    _cfg324.update_config(lambda cfg: cfg.pop(_u324.CFG, None))
    s0, e0 = _hhmm324(t - 1), _hhmm324(t + 30)
    eq("Updates (the rows' window words, on the host's clock): inside the window they say it updates now, in tonight's "
       "window, until its end, never a start already past",
       out["open"], ("By itself now, in tonight's window (until %s, the host's clock), if no players are on." % e0,
                     "By itself now, in tonight's window (until %s, the host's clock)." % e0))
    eq("Updates (the window ran a while ago and is over): the next night, at its start",
       out["over"], ("By itself the next night at %s (the host's clock), if no players are on." % _hhmm324(t - 180),
                     "By itself the next night at %s (the host's clock)." % _hhmm324(t - 180)))
    eq("Updates (control: the window is still ahead tonight): tonight, at its start", out["ahead"],
       ("By itself tonight at %s (the host's clock), if no players are on." % _hhmm324(t + 120),
        "By itself tonight at %s (the host's clock)." % _hhmm324(t + 120)))
    check("Updates (window words): the open window's start is not said as a time ahead", s0 not in (out["open"][0] or ""),
          out["open"])


# ── 6 and 7. The pages' scripts ────────────────────────────────────────────────────────────────────
def _node324(page, scripts, scenario, routes):
    """part322's node harness with the window's addEventListener (settings.js listens for pageshow).

    And getElementById('') is null, as a browser's is (settings.js asks for an optional note by an empty id).
    """
    import unit.part301 as _p301
    saved = _p301._HARNESS301
    try:
        _p301._HARNESS301 = saved.replace("confirmDialog: function (o) {",
                                          "addEventListener: function () {}, confirmDialog: function (o) {", 1).replace(
            "getElementById: function (id) { return all(root,", "getElementById: function (id) { return !id ? null : all(root,", 1)
        return _node322(page, scripts, scenario, routes)
    finally:
        _p301._HARNESS301 = saved


_SAFE_SCN324 = r"""
  for (let i = 0; i < 6; i++) await tick();
  const why = $('upd-safe-why');
  return {disabled: $('upd-safe').disabled, why: why.hidden ? '' : why.textContent};
"""


def _upd_body324(rows, history=None):
    return {"success": True, "count": len(rows), "settings": {"start": "04:00", "end": "05:00"},
            "groups": [{"key": "os", "title": "Host system", "items": rows}] if rows else [], "history": history or []}


def _updates_page324():
    from unit.part301 import _page301
    from unit.part12 import P9_ADMIN
    return _page301("updates.html", P9_ADMIN, allowed=True)


def _s6_safe_why():
    page = _updates_page324()
    osrow = {"kind": "os", "ref": "os:1", "name": "host", "host": "", "what": ["2 package(s)"], "notes": [], "cost": "c",
             "security": False, "safe": False, "auto": None, "auto_editable": False, "when": "w", "when_link": None,
             "action": {"href": "/remote/1?update=os#os-updates"}, "link": ""}
    host = _node324(page, ["updates.js"], _SAFE_SCN324, {"/api/updates": _upd_body324([osrow])})
    empty = _node324(page, ["updates.js"], _SAFE_SCN324, {"/api/updates": _upd_body324([])})
    eq("Updates page (js/updates.js, only a host's packages listed): the greyed button's reason is what they need (a "
       "restart or a reboot, run from their own page), never that they are not the viewer's",
       (host.get("disabled"), host.get("why"), host.get("error")),
       (True, "What is listed can restart services or need a reboot: its Update now opens the page that runs it.", None))
    eq("Updates page (nothing listed): the greyed button says there is nothing to update now",
       (empty.get("disabled"), empty.get("why"), empty.get("error")), (True, "Nothing to update now.", None))


_GAME_SCN324 = r"""
  for (let i = 0; i < 6; i++) await tick();
  const btns = $('upd-list').querySelectorAll('button');
  btns[0]._on.click();
  for (let i = 0; i < 4; i++) await tick();
  btns[1]._on.click();
  for (let i = 0; i < 4; i++) await tick();
  return {title: dialogs.length ? dialogs[0].title : '', when: $('upd-list').textContent,
          hist: $('upd-history-list').textContent};
"""


def _game_page324():
    """A game row's page (js/updates.js) after Update now and Update when empty are pressed: what it showed."""
    game = {"kind": "game", "ref": "game:5", "name": "gm", "host": "", "what": ["1 to 2."], "notes": [], "cost": "c",
            "security": False, "safe": False, "auto": True, "auto_editable": False, "when": "By itself tonight.",
            "when_link": None, "link": "", "action": {"post": "/api/updates/game/5", "body": {"when": "now"},
                                                     "confirm": "Players are kicked.", "confirm_title": "Update gm now?"},
            "later": {"post": "/api/updates/game/5", "queued": False}}
    hist = [{"at": "2026-11-27T04:00:00Z", "at_host": "2026-11-27 04:00", "who": "admin", "action": "update_when_empty",
             "target": "gm", "ok": True, "badge": "queued", "detail": "Queued for when players leave."}]
    return _node324(_updates_page324(), ["updates.js"], _GAME_SCN324, {
        "/api/updates": dict(_upd_body324([]), groups=[{"key": "game", "title": "Game servers", "items": [game]}],
                             history=hist),
        "/api/updates/game/5": {"success": True, "message": "Queued", "queued": True,
                                "when": "Queued: it updates as soon as no players are on."}})


def _s6_when_line():
    got = _game_page324()
    eq("Updates page (a game row, Update when empty): the row's line turns into the queue's at once",
       ("Queued: it updates as soon as no players are on." in (got.get("when") or ""),
        "By itself tonight." in (got.get("when") or ""), got.get("error")), (True, False, None))


def _s6_title():
    got = _game_page324()
    eq("Updates page (a game row, Update now): its question carries the server's name", (got.get("title"),
                                                                                         got.get("error")),
       ("Update gm now?", None))


def _s6_badge():
    got = _game_page324()
    eq("Updates page (History): a queued update is marked queued, not done",
       ("Queued" in (got.get("hist") or ""), "Done" in (got.get("hist") or ""), got.get("error")), (True, False, None))


def _s7_outside(su):
    page = _client324(su.id).get("/settings").data.decode("utf-8", "replace")
    got = _node324(page, ["settings.js"], r"""
  const box = $('s-outside_game_update_check'), note = $('s-outside_game_update_check-owasp');
  const asks = $('s-outside_update_check');
  if (!box || !note || !asks) return {missing: [!!box, !!note, !!asks]};
  const before = note.className.indexOf('d-none') >= 0;
  box.checked = false;
  box._on.change();
  const after = note.className.indexOf('d-none') >= 0;
  asks.checked = false;
  asks._on.change();
  return {before: before, after: after, asked: dialogs.length, stillOn: asks.checked};
""", {})
    eq("Settings (Outside services, js/settings.js): a switch turned off shows \"Off: outside OWASP's recommendation.\" "
       "at once, before Save, as the switches that ask first do",
       (got.get("before"), got.get("after"), got.get("missing"), got.get("error")), (True, False, None, None))
    eq("Settings (Outside services, control): a switch that asks before it goes off still asks, and stays on until "
       "Confirm", (got.get("asked"), got.get("stillOn")), (1, True))


# ── 8. An apply loads through the admin socket when both sides have it ────────────────────────────
def _admin_server324(path, got):
    """A unix socket at `path` answering one request 200, its bytes kept in got["req"]."""
    srv = _socket324.socket(_socket324.AF_UNIX, _socket324.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    srv.settimeout(10)

    def _serve():
        try:
            conn, _a = srv.accept()
            with conn:
                conn.settimeout(5)
                data = b""
                while b"\r\n\r\n" not in data:
                    data += conn.recv(4096)
                head, _sep, body = data.partition(b"\r\n\r\n")
                want = int(_re324.search(rb"Content-Length: (\d+)", head).group(1))
                while len(body) < want:
                    body += conn.recv(4096)
                got["req"] = head + b"\r\n\r\n" + body
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
        finally:
            srv.close()
    t = _th324.Thread(target=_serve, daemon=True)
    t.start()
    return t


def _apply324(d, old_text, new_text, admin):
    """website-proxy-apply over scratch paths, the proxy running: (rc, output, systemctl calls, request seen)."""
    calls, got = [], {}
    conf = os.path.join(d, "Caddyfile")
    with open(conf, "w", encoding="utf-8") as fh:
        fh.write(old_text)
    units = {}
    for key in ("WEB_PROXY_UNIT_FILE", "WEB_REBIND_UNIT_FILE", "WEB_REBIND_TIMER_FILE"):
        units[key] = os.path.join(d, key.lower())
        with open(units[key], "w", encoding="utf-8") as fh:
            fh.write(getattr(_H322, key.replace("_FILE", "_TEXT")))

    def _quiet(argv, timeout=60, **k):
        calls.append(list(argv[1:]))
        return 0, "ActiveState=active\nSubState=running\nNRestarts=0\n" if argv[1:2] == ["show"] else ""

    def _validated(text, pw):
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write(text)
        return True
    sock = os.path.join(d, "admin.sock")
    server = _admin_server324(sock, got) if admin else None
    me = _NS324(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_name="lgsmweb")
    seams = _Seams322(WEB_PROXY_BIN=_shutil324.which("true") or "/bin/true", pwd=_NS324(getpwnam=lambda n: me),
                      WEB_PROXY_CONF=conf, WEB_PROXY_CERTS=os.path.join(d, "certs"), WEB_PROXY_ADMIN=sock,
                      WEB_START_POLL=0, resolve=lambda name: name, _run_quiet=_quiet, _web_validated=_validated,
                      _web_listen_ok=lambda text, pw: (text, ["127.0.0.1"]), _web_write=lambda path, data, mode, *a:
                      open(path, "wb").write(data), **units)
    try:
        rc, out = _quiet322(_H322.do_website_proxy_apply, ["reload"],
                            _json324.dumps({"caddyfile": new_text, "files": {}}))
    finally:
        seams.restore()
    if server is not None:
        server.join(5)
    return rc, out, [c for c in calls if c[:1] in (["restart"], ["reload"])], got.get("req", b"")


def _cleanup324():
    _db324.session.rollback()
    remotes = _ROWS324["remotes"] or [0]
    sites = sorted(set(_ROWS324["sites"]) | {s.id for s in _Site324.query.filter(_Site324.remote_id.in_(remotes))})
    _Audit324.query.filter(_Audit324.website_id.in_(sites or [0])).delete(synchronize_session=False)
    _Audit324.query.filter(_Audit324.remote_id.in_(remotes)).delete(synchronize_session=False)
    _Audit324.query.filter(_Audit324.game_server_id.in_(_ROWS324["servers"] or [0])).delete(synchronize_session=False)
    for d in _Dom324.query.filter(_Dom324.website_id.in_(sites or [0])).all():
        _db324.session.delete(d)
    for p in _Proxy324.query.filter(_Proxy324.remote_id.in_(remotes)).all():
        _db324.session.delete(p)
    for model, ids in ((_Site324, sites), (_GS324, _ROWS324["servers"]), (_User324, _ROWS324["users"]),
                       (_Remote324, _ROWS324["remotes"])):
        for i in ids:
            row = _db324.session.get(model, i)
            if row is not None:
                _db324.session.delete(row)
    _db324.session.commit()
    from panel.routes import websites_guard as _rg
    _cfg324.update_config(lambda cfg: cfg.pop(_rg.CURSOR_KEY, None))
    _cfg324.update_config(lambda cfg: cfg.pop(_u324.CFG, None))
    for i in _ROWS324["servers"]:
        _u324.forget_server(i)
        _gu324.forget(i)
    _ua324._DONE.clear()
    _u324.forget_counts()


def _ran324(step, *args):
    """Run one section: its result (True for none), or None when it raised (the traceback kept in _ran324.last)."""
    import traceback
    try:
        got = step(*args)
        _ran324.last = ""
        return True if got is None else got
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        from flask import has_app_context
        if has_app_context():
            _db324.session.rollback()
        _ran324.last = traceback.format_exc()[-1500:]
        return None


_ran324.last = ""
_PAGES324 = (
    _s6_safe_why,
    _s6_when_line,
    _s6_title,
    _s6_badge,
)
_HOST324 = (
    _s1_until,
    _s2_site,
    _s3_lifted,
    _s4_own_port,
    _s5_left_stopped,
)
_GAME324 = (
    _s6_queue_first,
    _s6_confirm,
    _s6_history,
    _s6_window_words,
)
_USER324 = (
    _s7_outside,
)
for _sec324 in _PAGES324:
    check("part324: %s ran to the end" % _sec324.__name__, _ran324(_sec324), _ran324.last)
_trips324 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part324")
        _p9_patch(_sw324, "site_probe", lambda remote, site: (False, "not read in part324"))
        _cfg324.update_config(lambda cfg: cfg.update({_u324.CFG: {"start": "04:00", "end": "05:00", "off": []}}))
        _host324r, _su324 = _setup324()
        _gm324 = _gs324(_host324r, "p324-gmod", "gmod", "p324gmod", 27115)
        for _sec324 in _HOST324:
            check("part324: %s ran to the end" % _sec324.__name__, _ran324(_sec324, _host324r, _su324), _ran324.last)
        for _sec324 in _GAME324:
            check("part324: %s ran to the end" % _sec324.__name__, _ran324(_sec324, _host324r, _su324, _gm324),
                  _ran324.last)
        for _sec324 in _USER324:
            check("part324: %s ran to the end" % _sec324.__name__, _ran324(_sec324, _su324), _ran324.last)
        eq("part324: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips324:], [])
    finally:
        _p9_restore_all()
        _cleanup324()
