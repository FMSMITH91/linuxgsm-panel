"""Part 323 of the unit suite: game updates on the Updates page (a newer build of the game itself).

1. One source of truth: the server page's check-update (POST /api/server/<id>/action) is read into the store the
   Updates page lists from (a "game" row with the installed and available build, the branch and SteamDB's history);
   "No update available" takes the row away; an update that ran (the background action) leaves the server on the
   build it printed, and its run time prices the next one. Another read-only action changes nothing.
2. The rows (GET /api/updates): who may update the server sees it; the cost (kicks players, or nobody when the
   server is stopped); automatic updates' default per family with its reason (Steam on, Minecraft off); a server
   whose own crontab runs update says so; the switch (POST /api/updates/auto) and Back up first.
3. Update now (POST /api/updates/game/<id>): through the server's own action path; with players on and a console
   chat command the players are warned first (unless LinuxGSM warns them itself); refused for an account the panel
   may not run code as; refused for a viewer who may not update.
4. Update when empty: queued on the server (update_pending); the due-actions sweep runs it once the server is read
   empty or stopped, never with players on, and the queue clears.
5. The nightly window (updates_auto.tick): only a server with a newer build, automatic updates on, no players and
   no scheduled update task of its own; Back up first stops, backs up, updates and starts; a failed step brings the
   server back up and sends the alert; outside the window nothing runs.
6. The daily check (game_updates.check_pass, from the window's loop): one server per pass, never read first, then
   the one read longest ago; a busy server is skipped; a read is not repeated within a day (a failed one after 6 h).
7. The page (js/updates.js): a game row's Update now asks with its cost first; Update when empty and Don't wait;
   the family's reason under the switch; Back up first; Check games now.

HOW IT RUNS. part12's app and database; every host call is a stand-in, part12's tripwire is armed.
"""
import calendar as _cal323
import os
import time as _time323

from flask import g as _g323

from unit.part01 import check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch, _p9_patch_sm, _p9_restore_all
from panel.core import config as _cfg323
from panel.core.panel_state import r36j_route_job as _job323
from panel.db.models import (AuditLog as _Audit323, GameServer as _GS323, RemoteServer as _Remote323,
                             User as _User323, db as _db323)
from panel.routes import _shared as _sh323, server_detail as _sd323, updates_game as _ug323
from panel.security import auth as _auth323
from panel.services import (game_updates as _gu323, game_updates_run as _gur323, lgsm_players as _lgp323,
                            monitoring as _mon323, notifications as _nt323, updates as _u323, updates_auto as _ua323)

_ROWS323 = {"servers": [], "users": [], "remotes": [], "groups": []}
_IN323 = _cal323.timegm((2026, 11, 27, 4, 30, 0))
_OUT323 = _cal323.timegm((2026, 11, 27, 12, 0, 0))
_STEAM323 = ("[ .... ] Checking for update: SteamCMD\r[  OK  ] Checking for update: SteamCMD\n\n"
             "\x1b[1m\x1b[4mUpdate\x1b[0m available\n* Local build: \x1b[31m12345678\x1b[0m\n"
             "* Remote build: \x1b[32m12399999\x1b[0m\n* Branch: public\n\x1b[3mhttps://steamdb.info/app/4020/history\n")
_NONE323 = ("[  OK  ] Checking for update: SteamCMD\n\nNo update available\n* Local build: 12399999\n"
            "* Remote build: 12399999\n* Branch: public\nhttps://steamdb.info/app/4020/history\n")
_MC323 = "Update available\n* Local build: 1.21.4\n* Remote build: 1.21.5\n"


def _client323(uid):
    _g323.pop("_login_user", None)
    return _p9_client(uid)


def _rows323(uid):
    d = _client323(uid).get("/api/updates").get_json(silent=True) or {}
    return {x["ref"]: x for g in d.get("groups") or [] for x in g["items"]}, d


def _setup323():
    r = _Remote323(name="p323-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.81")
    _db323.session.add(r)
    _db323.session.commit()
    _ROWS323["remotes"].append(r.id)
    su = _User323(username="p323-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    nobody = _User323(username="p323-nobody", password_hash=os.urandom(8).hex(), is_superadmin=False, is_active=True)
    _db323.session.add_all([su, nobody])
    _db323.session.commit()
    _ROWS323["users"] += [su.id, nobody.id]
    return r, su, nobody


def _gs323(host, name, game, short, status="online"):
    gs = _GS323(name=name, game_type=game, short_name=short, port=27015 + len(_ROWS323["servers"]),
                remote_id=host.id, installed=True, status=status)
    _db323.session.add(gs)
    _db323.session.commit()
    _ROWS323["servers"].append(gs.id)
    return gs


def _member323(name, perms, gs):
    """A user in a group of its own holding `perms` on server `gs`."""
    import json
    from panel.db.models import Group
    u = _User323(username=name, password_hash=os.urandom(8).hex(), is_superadmin=False, is_active=True)
    grp = Group(name=name + "-g", permissions=json.dumps(perms))
    grp.game_servers = [gs]
    u.groups = [grp]
    _db323.session.add_all([u, grp])
    _db323.session.commit()
    _ROWS323["users"].append(u.id)
    _ROWS323["groups"].append(grp.id)
    return u


def _settings323(**kw):
    _cfg323.update_config(lambda cfg: cfg.update({_u323.CFG: dict({"start": "04:00", "end": "05:00", "off": []}, **kw)}))


def _seams323():
    _p9_patch(_sh323, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_ua323, "_site_ids", lambda: [])
    _p9_patch(_ua323, "_server_ids", lambda: list(_ROWS323["servers"]))
    _p9_patch(_ua323, "_pending_addons", lambda gs, cfg: [])
    _p9_patch(_gu323, "_installed_ids", lambda: list(_ROWS323["servers"]))
    _p9_patch(_nt323, "notify", lambda *a, **k: None)
    _p9_patch(_sd323, "_db_dump_before", lambda *a, **k: None)


def _actions_stub323(record, answers=None):
    """A stand-in for server_detail._run_action: records (server, action, origin); on_done answered at once."""
    answers = answers or {}

    def _run(app, gs, remote, action, actor, origin=None, on_done=None, port_gate=None):
        record.append((gs.id, action, origin if actor is None else getattr(actor, "username", "?")))
        ok, detail = answers.get(action, (True, "ok"))
        if on_done is not None:
            on_done(ok, detail)
        return True, "'%s' started" % action
    return _run


# ── 1. one source of truth ────────────────────────────────────────────────────────────────────────
def _s1_check(host, su):
    gs = _gs323(host, "p323-gmod", "gmod", "p323gmod")
    said = {"out": _STEAM323}
    _p9_patch_sm("run_as_game_user", lambda server, user, action, **k: (said["out"], "", 0))
    r = _client323(su.id).post("/api/server/%d/action" % gs.id, json={"action": "check-update"})
    row = _rows323(su.id)[0].get("game:%d" % gs.id) or {}
    eq("game updates (the server page's check-update, POST /api/server/<id>/action): what it printed is the Updates "
       "page's game row: the installed and the available build, the branch, SteamDB's history, Update now and Update "
       "when empty, never a security mark",
       (r.status_code, row.get("what", [None])[0], len(row.get("what") or []),
        [n.get("url") for n in row.get("notes") or []], bool((row.get("action") or {}).get("post")),
        bool(row.get("later")), row.get("security"), row.get("safe")),
       (200, "12345678 to 12399999 (branch public).", 2, ["https://steamdb.info/app/4020/history"], True, True, False,
        False))
    said["out"] = "Server details: nothing about builds\n"
    _client323(su.id).post("/api/server/%d/action" % gs.id, json={"action": "details"})
    check("game updates control: another read-only action (details) leaves the row as check-update left it",
          "game:%d" % gs.id in _rows323(su.id)[0], _gu323.seen(gs.id))
    said["out"] = _NONE323
    _client323(su.id).post("/api/server/%d/action" % gs.id, json={"action": "check-update"})
    eq("game updates: check-update saying \"No update available\" takes the row away",
       ("game:%d" % gs.id in _rows323(su.id)[0], _gu323.seen(gs.id).get("state")), (False, "none"))
    return gs


def _s1_update(host, su, gs):
    _gu323.note_output(gs.id, _STEAM323)
    teed = {"rc": 1}
    _p9_patch(_sd323, "_run_teed", lambda app, remote, sid, short, action, selfname, monitor=True:
              (_STEAM323 + "Updating gmodserver\n", "", teed["rc"]))
    _client323(su.id).post("/api/server/%d/action" % gs.id, json={"action": "update"})
    _wait323(lambda: _Audit323.query.filter_by(game_server_id=gs.id, action="update_complete").count() >= 1)
    kept = _gu323.seen(gs.id).get("state")
    teed["rc"] = 0
    _client323(su.id).post("/api/server/%d/action" % gs.id, json={"action": "update"})
    _wait323(lambda: _gu323.seen(gs.id).get("state") == "none")
    got = _gu323.seen(gs.id)
    eq("game updates (the server page's Update, run in the background): a failed update keeps the row; one that "
       "exited 0 leaves the server on the build it printed (the row goes), and its run time is measured",
       (kept, got.get("state"), got.get("local"), _gu323.update_minutes(gs.id)), ("available", "none", "12399999", 1))


def _wait323(cond, secs=10):
    deadline = _time323.time() + secs
    while _time323.time() < deadline:
        _db323.session.expire_all()
        if cond():
            return True
        _time323.sleep(0.05)
    return False


# ── 2. the rows ───────────────────────────────────────────────────────────────────────────────────
def _s2_rows(host, su, nobody, gmod):
    mc = _gs323(host, "p323-mc", "mc", "p323mc", status="offline")
    _u323.note_lgsm_cron(gmod.id, [])       # its crontab read: no update task of its own
    _gu323.note_output(gmod.id, _STEAM323)
    _gu323.note_output(mc.id, _MC323)
    rows, _d = _rows323(su.id)
    g, m = rows.get("game:%d" % gmod.id) or {}, rows.get("game:%d" % mc.id) or {}
    eq("game rows: a Steam game updates by itself in the window (its reason beside the switch) and costs a restart "
       "measured on its last update; Minecraft is off by default with its own reason, and costs nothing while stopped",
       (g.get("auto"), g.get("auto_why"), g.get("when"), g.get("cost"), m.get("auto"), m.get("auto_why"), m.get("when"),
        m.get("cost"), m.get("what", [None])[0]),
       (True, _gu323.WHY_STEAM, "By itself tonight at 04:00 (the host's clock), if no players are on.",
        "Players are kicked: the server restarts (about 1 min, as its last update took).", False, _gu323.WHY_MINECRAFT,
        "Automatic updates are off for it: it waits for Update now.", _ug323.COST_STOPPED, "1.21.4 to 1.21.5."))
    addons, upd = _member323("p323-addons", [_auth323.MANAGE_ADDONS], gmod), _member323("p323-upd", [_auth323.UPDATE_SERVER], gmod)
    a_rows, a_body = _rows323(addons.id)
    eq("game rows: a viewer who opens the page for the server's add-ons but may not run its Update sees no game row; "
       "one who may update it does (control)",
       (a_body.get("success"), [k for k in a_rows if k.startswith("game:")],
        "game:%d" % gmod.id in _rows323(upd.id)[0]), (True, [], True))
    _s2_cron(su, gmod)
    _s2_switches(su, gmod, mc)
    return mc


def _row323(uid, gs):
    """The Updates page's row of game server `gs` for user `uid` ({} when it is not listed)."""
    return _rows323(uid)[0].get("game:%d" % gs.id) or {}


def _s2_cron(su, gmod):
    _u323.note_lgsm_cron(gmod.id, [{"command": "cd /home/p323gmod && ./gmodserver update-lgsm", "schedule": "0 5 * * 0"}])
    only_lgsm = _row323(su.id, gmod).get("when")
    _u323.note_lgsm_cron(gmod.id, [{"command": "/home/p323gmod/gmodserver update > /dev/null 2>&1",
                                    "schedule": "15 5 * * *"}])
    eq("game rows: a server whose crontab runs LinuxGSM's update says that task updates it (an update-lgsm task is "
       "not one)",
       (only_lgsm, _row323(su.id, gmod).get("when")),
       ("By itself tonight at 04:00 (the host's clock), if no players are on.",
        "By itself: its scheduled task runs update (15 5 * * *, the host's clock)."))
    _u323.note_lgsm_cron(gmod.id, [])


def _s2_switches(su, gmod, mc):
    on = _client323(su.id).post("/api/updates/auto", json={"ref": "game:%d" % mc.id, "on": True})
    off = _client323(su.id).post("/api/updates/auto", json={"ref": "game:%d" % gmod.id, "on": False})
    bk = _client323(su.id).post("/api/updates/game/%d/backup" % gmod.id, json={"on": True})
    m, g = _row323(su.id, mc), _row323(su.id, gmod)
    eq("game rows (POST /api/updates/auto, /api/updates/game/<id>/backup): Minecraft switched on and a Steam game "
       "off are both kept against their family's default, off answered with OWASP's note (never refused); Back up "
       "first is kept",
       (on.status_code, m.get("auto"), off.status_code, "OWASP" in ((off.get_json() or {}).get("note") or ""),
        g.get("auto"), bk.status_code, g.get("backup")), (200, True, 200, True, False, 200, True))
    _settings323()


# ── 3. Update now ─────────────────────────────────────────────────────────────────────────────────
def _s3_now(host, su, nobody, gmod):
    ran, said = [], []
    _p9_patch(_sd323, "_run_action", _actions_stub323(ran))
    _p9_patch(_gur323, "WARN_SECS", 0)
    _p9_patch_sm("send_console_command", lambda server, user, cmd, **k: said.append(cmd) or ("", "", 0))
    _p9_patch(_lgp323, "lgsm_warns", lambda remote, gs: False)
    _p9_patch(_mon323, "_cached_player_count", lambda sid: 0)
    url = "/api/updates/game/%d" % gmod.id
    empty = _client323(su.id).post(url, json={"when": "now"})
    eq("Update now (POST /api/updates/game/<id>, no players on): the update runs at once through the server's own "
       "action path, as the viewer", (empty.status_code, ran[-1:]), (200, [(gmod.id, "update", "p323-super")]))
    del ran[:]
    _p9_patch(_mon323, "_cached_player_count", lambda sid: 3)
    warned = _client323(su.id).post(url, json={"when": "now"})
    _wait323(lambda: bool(ran))
    eq("Update now with players on: they are told in the game's own chat first, then the update runs",
       ((warned.get_json() or {}).get("message"), said, ran),
       (_gur323.S_WARNED, ["say " + _gur323.WARN_TEXT], [(gmod.id, "update", "p323-super")]))
    del ran[:], said[:]
    _p9_patch(_lgp323, "lgsm_warns", lambda remote, gs: True)
    _client323(su.id).post(url, json={"when": "now"})
    eq("Update now control: where LinuxGSM warns the players itself the panel says nothing (players told once)",
       (said, ran), ([], [(gmod.id, "update", "p323-super")]))
    del ran[:]
    _p9_patch(_sh323, "game_account_write_refusal", lambda *a, **k: "a root-capable account")
    refused = _client323(su.id).post(url, json={"when": "now"})
    _p9_patch(_sh323, "game_account_write_refusal", lambda *a, **k: None)
    denied = _client323(nobody.id).post(url, json={"when": "now"})
    eq("Update now: refused for an account the panel may not run code as, and for a viewer who may not update it",
       ((refused.get_json() or {}).get("success"), denied.status_code in (403, 404), ran), (False, True, []))


# ── 4. Update when empty ──────────────────────────────────────────────────────────────────────────
def _s4_empty(host, su, gmod):
    ran = []
    _p9_patch(_sd323, "_run_action", _actions_stub323(ran))
    q = _client323(su.id).post("/api/updates/game/%d" % gmod.id, json={"when": "empty"})
    _db323.session.refresh(gmod)
    queued = (q.status_code, (q.get_json() or {}).get("queued"), gmod.update_pending,
              (_rows323(su.id)[0].get("game:%d" % gmod.id) or {}).get("when"))
    _p9_patch(_sh323, "get_server_status", lambda remote, gs, distinguish_unresponsive=False: "online")
    _p9_patch(_sh323, "sm_player_count", lambda *a, **k: 2)
    ready = _sh323._r37b_queued_ready(gmod)
    _sh323._settle_queued_action(_p9, gmod)
    busy = list(ran)
    _p9_patch(_sh323, "sm_player_count", lambda *a, **k: 0)
    _sh323._settle_queued_action(_p9, gmod)
    _db323.session.refresh(gmod)
    eq("Update when empty: queued on the server (its row says so); the due-actions sweep takes it, leaves it queued "
       "while players are on, and runs the update once the server reads empty, the queue then cleared",
       (queued, ready, busy, ran, gmod.update_pending),
       ((200, True, True, "Queued: it updates as soon as no players are on."), True, [],
        [(gmod.id, "update", "when empty")], False))
    _client323(su.id).post("/api/updates/game/%d" % gmod.id, json={"when": "empty"})
    c = _client323(su.id).post("/api/updates/game/%d" % gmod.id, json={"when": "cancel"})
    _db323.session.refresh(gmod)
    eq("Update when empty control: Don't wait takes it off the queue", ((c.get_json() or {}).get("queued"),
                                                                        gmod.update_pending), (False, False))


# ── 5. the nightly window ─────────────────────────────────────────────────────────────────────────
def _tick323(now):
    _ua323._DONE.clear()
    _ua323.tick(_p9, now=now)


def _s5_window(host, su, gmod, mc):
    ran, checks, cron = [], [], []
    # The window reads each server's crontab as its account (updates.read_lgsm_cron): `cron` is what it holds.
    _p9_patch_sm("list_cron_jobs", lambda remote, user, selfname=None: [dict(j) for j in cron])
    _p9_patch(_sd323, "_run_action", _actions_stub323(ran))
    _p9_patch(_gu323, "check_pass", lambda now=None: checks.append(now))
    _p9_patch(_mon323, "_cached_player_count", lambda sid: 0)
    _p9_patch(_sh323, "get_server_status", lambda remote, gs, distinguish_unresponsive=False: "online")
    _gu323.note_output(gmod.id, _STEAM323)
    _gu323.note_output(mc.id, _MC323)
    _tick323(_OUT323)
    outside = list(ran)
    _tick323(_IN323)
    eq("nightly window (updates_auto.tick): outside it nothing runs; inside it the Steam game with a newer build is "
       "updated through its own action path, Minecraft (off by default) is not; the daily check runs every pass",
       (outside, ran, len(checks)), ([], [(gmod.id, "update", "automatic")], 2))
    del ran[:]
    _p9_patch(_mon323, "_cached_player_count", lambda sid: 4)
    _tick323(_IN323)
    skip = _Audit323.query.filter_by(game_server_id=gmod.id, action="update_skipped").order_by(_Audit323.id.desc()).first()
    eq("nightly window: a game server with players on waits for the next night, and the history says why",
       (ran, "it has players on" in (skip.detail if skip else "")), ([], True))
    del ran[:]
    _p9_patch(_mon323, "_cached_player_count", lambda sid: 0)
    cron[:] = [{"command": "./gmodserver update", "schedule": "15 5 * * *"}]
    _tick323(_IN323)
    del cron[:]
    check("nightly window: a server whose own scheduled task runs update is left to it", ran == [], ran)
    _u323.set_backup_first(gmod.id, True)
    _tick323(_IN323)
    eq("nightly window, Back up first: the running server is stopped, backed up, updated and started again",
       [a for _i, a, _o in ran], ["stop", "backup", "update", "start"])
    del ran[:]
    sent = []
    _p9_patch(_nt323, "notify", lambda *a, **k: sent.append(a[0]))
    _p9_patch(_sd323, "_run_action", _actions_stub323(ran, {"update": (False, "SteamCMD failed")}))
    _tick323(_IN323)
    eq("nightly window: an update that fails brings the stopped server back up and sends the auto_update_failed alert",
       ([a for _i, a, _o in ran], sent), (["stop", "backup", "update", "start"], ["auto_update_failed"]))
    _u323.set_backup_first(gmod.id, False)
    _p9_patch(_nt323, "notify", lambda *a, **k: None)


# ── 6. the daily check ────────────────────────────────────────────────────────────────────────────
def _s6_check(gmod, mc):
    read = []
    _p9_restore_one323(_gu323, "check_pass")
    _p9_patch_sm("run_as_game_user", lambda server, user, action, **k: read.append((user, action)) or (_NONE323, "", 0))
    with _gu323._LOCK:
        for i in (gmod.id, mc.id):
            _gu323._SEEN.pop(i, None)
    now = _time323.time()
    first = _gu323.check_pass(now)
    with _job323(mc.id, "action"):
        busy = _gu323.check_pass(now)
    second = _gu323.check_pass(now)
    third = _gu323.check_pass(now + 3600)
    eq("daily check (game_updates.check_pass): one server per pass, the never-read first; a server the panel is "
       "running an action on is skipped; once both are read nothing is read again within the day",
       (first, busy, second, third, [a for _u, a in read]), (gmod.id, None, mc.id, None, ["check-update"] * 2))
    from panel.core import outside_services as _out323
    _cfg323.update_config(lambda cfg: cfg.update({_out323.GAME_UPDATE_CHECK: False}))
    with _gu323._LOCK:
        _gu323._SEEN.pop(gmod.id, None)
    off = _gu323.check_pass(now)
    _cfg323.update_config(lambda cfg: cfg.pop(_out323.GAME_UPDATE_CHECK, None))
    eq("daily check: with Settings -> Outside services -> Daily game update check off, no server is read",
       (off, len(read)), (None, 2))
    _gu323.note_output(gmod.id, _NONE323, now=now)
    _gu323.note_output(mc.id, "the host did not answer", now=now)
    eq("daily check: a server read a day ago is due again, one whose read failed after 6 hours (not after 1)",
       (_gu323.due_for_check(gmod.id, now + 86400), _gu323.due_for_check(mc.id, now + 3600),
        _gu323.due_for_check(mc.id, now + 6 * 3600)), (True, False, True))


def _p9_restore_one323(owner, name):
    from unit.part12 import _P9_PATCHED
    key = (owner, name)
    if key in _P9_PATCHED:
        setattr(owner, name, _P9_PATCHED.pop(key))


# ── 7. the page ───────────────────────────────────────────────────────────────────────────────────
_SCN323 = r"""
  for (let i = 0; i < 6; i++) await tick();
  const btns = $('upd-list').querySelectorAll('button');
  const out = {text: $('upd-list').textContent, check: !$('upd-games-check').hidden, labels: btns.map(function (b) { return b.textContent; })};
  btns[0]._on.click();
  for (let i = 0; i < 4; i++) await tick();
  out.dialog = dialogs.length ? dialogs[0].bodyText : '';
  btns[1]._on.click();
  for (let i = 0; i < 4; i++) await tick();
  out.after = btns[1].textContent;
  out.calls = calls.filter(function (c) { return c[0] === 'POST'; });
  return out;
"""


def _s7_page():
    from unit.part301 import _page301
    from unit.part12 import P9_ADMIN
    from unit.part322 import _node322
    page = _page301("updates.html", P9_ADMIN, allowed=True)
    row = {"kind": "game", "ref": "game:5", "name": "gm", "host": "", "what": ["1 to 2."], "notes": [],
           "cost": "Players are kicked: the server restarts.", "security": False, "safe": False, "auto": True,
           "auto_editable": True, "when": "w", "when_link": None, "link": "", "auto_why": "On by default: why.",
           "backup": False, "backup_post": "/api/updates/game/5/backup",
           "action": {"post": "/api/updates/game/5", "body": {"when": "now"}, "confirm": "Players are kicked."},
           "later": {"post": "/api/updates/game/5", "queued": False}}
    got = _node322(page, ["updates.js"], _SCN323, {
        "/api/updates": {"success": True, "count": 1, "groups": [{"key": "game", "title": "Game servers", "items": [row]}],
                         "settings": {"start": "04:00", "end": "05:00", "can_check": True}, "history": []},
        "/api/updates/game/5": {"success": True, "message": "Queued", "queued": True}})
    eq("Updates page (js/updates.js, a game row): Update now asks with its cost first; Update when empty posts to "
       "the server's queue and turns into Don't wait; the family's reason and Back up first are on the row; Check "
       "games now is offered",
       (got.get("dialog"), [c[2] for c in got.get("calls") or []][-1:], got.get("after"),
        "On by default: why." in (got.get("text") or ""), "Back up first at night" in (got.get("text") or ""),
        got.get("check"), got.get("error")),
       ("Players are kicked.", [{"when": "empty"}], " Don't wait", True, True, True, None))
    off = _node322(page, ["updates.js"], "for (let i = 0; i < 6; i++) await tick(); return {text: $('upd-list').textContent};", {
        "/api/updates": {"success": True, "count": 1, "groups": [{"key": "game", "title": "Game servers",
                                                                  "items": [dict(row, auto=False)]}],
                         "settings": {}, "history": []}})
    eq("Updates page (a game row with automatic updates off): no Back up first, which only the nightly window does; its "
       "reason stays", ("Back up first at night" in (off.get("text") or ""), "On by default: why." in (off.get("text") or ""),
                        off.get("error")), (False, True, None))


def _cleanup323():
    _db323.session.rollback()
    _db323.session.query(_Audit323).filter(_Audit323.game_server_id.in_(_ROWS323["servers"] or [0])).delete(
        synchronize_session=False)
    from panel.db.models import Group as _Grp323
    for model, ids in ((_GS323, _ROWS323["servers"]), (_Grp323, _ROWS323["groups"]), (_User323, _ROWS323["users"]),
                       (_Remote323, _ROWS323["remotes"])):
        for i in ids:
            row = _db323.session.get(model, i)
            if row is not None:
                _db323.session.delete(row)
    _db323.session.commit()
    _cfg323.update_config(lambda cfg: cfg.pop(_u323.CFG, None))
    for i in _ROWS323["servers"]:
        _u323.forget_server(i)
    _ua323._DONE.clear()
    _u323.forget_counts()


def _ran323(step, *args):
    """Run one section: its result, or None when it raised (the traceback kept in _ran323.last)."""
    import traceback
    try:
        return step(*args) or True
    except Exception:
        _ran323.last = traceback.format_exc()[-1500:]
        return None


_ran323.last = ""
_trips323 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part323")
        # The rows' window words by the clock's phase are part324's: pinned here to before tonight's start.
        _p9_patch(_u323, "window_phase", lambda remote, cfg, now=None: "tonight")
        _seams323()
        _settings323()
        _host323, _su323, _nobody323 = _setup323()
        _gmod323 = _ran323(_s1_check, _host323, _su323)
        check("part323: _s1_check ran to the end", _gmod323, _ran323.last)
        if isinstance(_gmod323, _GS323):
            check("part323: _s1_update ran to the end", _ran323(_s1_update, _host323, _su323, _gmod323), _ran323.last)
            _mc323 = _ran323(_s2_rows, _host323, _su323, _nobody323, _gmod323)
            check("part323: _s2_rows ran to the end", _mc323, _ran323.last)
            check("part323: _s3_now ran to the end", _ran323(_s3_now, _host323, _su323, _nobody323, _gmod323),
                  _ran323.last)
            check("part323: _s4_empty ran to the end", _ran323(_s4_empty, _host323, _su323, _gmod323), _ran323.last)
            if isinstance(_mc323, _GS323):
                check("part323: _s5_window ran to the end", _ran323(_s5_window, _host323, _su323, _gmod323, _mc323),
                      _ran323.last)
                check("part323: _s6_check ran to the end", _ran323(_s6_check, _gmod323, _mc323), _ran323.last)
        check("part323: _s7_page ran to the end", _ran323(_s7_page), _ran323.last)
        eq("part323: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips323:], [])
    finally:
        _p9_restore_all()
        _cleanup323()
