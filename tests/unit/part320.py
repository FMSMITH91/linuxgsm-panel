"""Part 320 of the unit suite: one Updates page, and automatic updates in a nightly window.

1. The page and its list (GET /updates, /api/updates): a website with an update is listed with what it changes, what
   it costs, when it installs by itself and its own Update route; one with nothing new is not. A customer sees only
   their own site, without Update now; a user who manages nothing gets 404 and no nav entry.
2. Settings: the window (superadmin, HH:MM, start not end) and an item's automatic updates (who may update it). Off
   answers OWASP's recommendation as a note, never a refusal.
3. The nightly window (updates_auto.tick): inside the window on the host's clock a pending site is updated through
   its own Update; outside it, busy (open connections from the web proxy), switched off, or already tried in this
   window, it is not; a security update (the signed catalog's `security` section) is applied even when off.
4. Rollback: a failed automatic update installs the site again from its previous image (pinned: no build, no
   pull, the image must still be on the host), records it and sends the auto_update_failed alert; an add-on's
   update keeps its record and unit and a failed one is put back (rollback_sh).
5. The website Overview says what is waiting and when it installs by itself.
6. The catalog's `security` section: the panels' check and the signer's.
7. Update everything safe now: step-up first, then the safe rows only (an add-on on a server with players waits).
8. History, the LinuxGSM and host rows, and the nav's count.

HOW IT RUNS. part12's app and its database; ssh_manager.websites' install runs for real down to the account's
shell, which is recorded (part319's seams). Nothing reaches a host: part12's tripwire is armed.
"""
import calendar as _cal320
import os
import time as _time320

from flask import g as _g320

from unit.part01 import check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch, _p9_restore_all
from panel.core import config as _cfg320
from panel.core.panel_state import _os_update_seen as _osseen320
from panel.db.models import (AuditLog as _Audit320, GameServer as _GS320, RemoteServer as _Remote320,
                             User as _User320, Website as _Site320, db as _db320)
from panel.ops import system_ops as _so320
from panel.ops.ssh_manager import websites as _sw320
from panel.routes import addons_change as _ch320, updates as _ru320, websites as _w320
from panel.security import auth as _auth320
from panel.services import (addons as _ad320, catalog_security as _cs320, notifications as _nt320,
                            updates as _u320, updates_auto as _ua320, websites as _ws320,
                            websites_access as _wa320)
from panel.services import monitoring as _mon320

_TOKEN320 = "q" * 40
_ROWS320 = {"sites": [], "remotes": [], "users": [], "groups": [], "servers": []}
_SH320 = []
_PROBE320 = {"uid": 1005, "gid": 1005, "splice": True, "cpu_delegated": True, "os": "26.04",
             "podman": "podman version 5.7.0"}
# 2026-11-27 04:30 and 12:00 UTC (a host with no zone recorded keeps UTC).
_IN320 = _cal320.timegm((2026, 11, 27, 4, 30, 0))
_OUT320 = _cal320.timegm((2026, 11, 27, 12, 0, 0))
_NEXT320 = _cal320.timegm((2026, 11, 28, 4, 10, 0))


def _client320(uid):
    _g320.pop("_login_user", None)
    _g320.__dict__.pop("_websites_access_cache", None)
    return _p9_client(uid)


def _get320(uid, path):
    return _client320(uid).get(path)


def _post320(uid, path, body=None, stale=False):
    c = _client320(uid)
    if stale:
        with c.session_transaction() as s:
            s["_auth_at"] = _time320.time() - 86400
    return c.post(path, json=body if body is not None else {})


def _user320(name, superadmin=False):
    u = _User320(username=name, password_hash=os.urandom(8).hex(), is_superadmin=superadmin, is_active=True)
    _db320.session.add(u)
    _db320.session.commit()
    _ROWS320["users"].append(u.id)
    return u


def _rows320():
    r = _Remote320(name="p320-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.80")
    _db320.session.add(r)
    _db320.session.commit()
    _ROWS320["remotes"].append(r.id)
    return r, _user320("p320-super", True)


def _site320(host, name, pending=True, kind="php"):
    s = _Site320(remote_id=host.id, name=name, kind=kind, state="running", php_version="8.4",
                 proxy_secret=_cfg320.encrypt_secret(_TOKEN320))
    _db320.session.add(s)
    _db320.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    _db320.session.commit()
    _ROWS320["sites"].append(s.id)
    if pending:
        s.image_digest, s.image_key = "localhost/p320-old:1", "old-files"
    else:
        _w320.note_installed(s)
    _db320.session.commit()
    return s


def _as_site320(remote, account, sh, timeout=120, stdin_text=None):
    """The account's shell, recorded; it answers as a host where each step worked."""
    _SH320.append((account, sh, stdin_text or ""))
    return True, "0\n" if "ss -Htn" in sh else ""


def _seams320():
    # The window's passes see this part's rows only: other parts leave websites and game servers in the full run.
    _p9_patch(_ua320, "_site_ids", lambda: list(_ROWS320["sites"]))
    _p9_patch(_ua320, "_server_ids", lambda: list(_ROWS320["servers"]))
    _p9_patch(_ua320, "_pending_addons", lambda gs, cfg: [])
    # The window's daily game check reads every installed server of the database: part323 drives it.
    from panel.services import game_updates as _gu320
    _p9_patch(_gu320, "check_pass", lambda now=None: None)
    _p9_patch(_sw320, "_as_site", _as_site320)
    _p9_patch(_sw320, "_ids", lambda remote, site: ((1005, 1005), dict(_PROBE320)))
    _p9_patch(_sw320, "runtime_ready", lambda remote: "")
    _p9_patch(_sw320, "_helper", lambda remote, verb, args=(), timeout=120, doc=None: (True, "account=exists"))
    _p9_patch(_sw320, "quota_set", lambda *a, **k: (True, "quota"))
    _p9_patch(_sw320, "cpu_limit", lambda *a, **k: (True, "container"))


def _settings320(**kw):
    _cfg320.update_config(lambda cfg: cfg.update({_u320.CFG: dict({"start": "04:00", "end": "05:00", "off": []}, **kw)}))


def _rows_of(uid):
    r = _get320(uid, "/api/updates")
    d = r.get_json(silent=True) or {"status": r.status_code, "body": r.data[-300:]}
    return [x for g in d.get("groups") or [] for x in g["items"]], d


# ── 1. the page and its list ──────────────────────────────────────────────────────────────────────
def _s1_page(host, su):
    pend, fresh = _site320(host, "p320-pending"), _site320(host, "p320-current", pending=False)
    page = _get320(su.id, "/updates")
    rows = _rows_of(su.id)[0]
    mine = {r["ref"]: r for r in rows if r["kind"] == "website"}
    r = mine.get("website:%d" % pend.id) or {}
    eq("updates (GET /updates, /api/updates as a superadmin): the page opens, a website with a new image and new "
       "site files is listed with both changes, its cost, the nightly window's time and its own Update route; a "
       "website already current is not listed",
       (page.status_code, b'id="upd-page"' in page.data, len(r.get("what") or []), r.get("cost") == _u320.COST_SITE_BUILD,
        r.get("when"), (r.get("action") or {}).get("post"), r.get("safe"), r.get("auto"),
        "website:%d" % fresh.id in mine),
       (200, True, 2, True, "By itself tonight at 04:00 (the host's clock).", "/websites/%d/update-image" % pend.id,
        True, True, False))
    cust = _user320("p320-cust")
    cust.totp_enabled = True        # a customer must have 2FA (WEBSITES_CUSTOMER_2FA): this one has
    grp = _wa320.make_customer_group("p320", [pend], [_auth320.VIEW_WEBSITES])
    cust.groups = [grp]
    _db320.session.commit()
    _ROWS320["groups"].append(grp.id)
    other = _site320(host, "p320-other")
    crow, cd = _rows_of(cust.id)
    check("updates: a customer sees their own website's update (when it installs by itself), not another site's, and "
          "no Update now or automatic switch (Update needs Manage websites)",
          [(x["ref"], x["action"], x["auto_editable"]) for x in crow] == [("website:%d" % pend.id, None, False)],
          repr(cd)[:600])
    nobody = _user320("p320-nobody")
    home = _get320(nobody.id, "/")
    eq("updates: a user who manages nothing gets 404 from the page and its API, and no Updates entry in the nav; "
       "the superadmin's nav has it with its count badge",
       (_get320(nobody.id, "/updates").status_code, _get320(nobody.id, "/api/updates").status_code,
        b'href="/updates"' in home.data, b'id="nav-updates-count"' in page.data),
       (404, 404, False, True))
    _u320.forget_counts()
    eq("updates: the nav's count is the number of rows the viewer may see",
       _get320(su.id, "/api/updates/count").get_json(), {"count": len(_rows_of(su.id)[0])})
    return pend, other, cust


# ── 2. settings ───────────────────────────────────────────────────────────────────────────────────
def _s2_settings(host, su, pend, cust):
    got = [_post320(su.id, "/api/updates/window", {"start": s, "end": e}).status_code
           for s, e in (("03:15", "04:45"), ("25:00", "04:00"), ("04:00", "04:00"))]
    stored = _u320.settings()
    eq("updates settings (POST /api/updates/window): HH:MM is stored, an hour past 23 and a start equal to its end "
       "are refused; a customer may not set it",
       (got, stored["start"], stored["end"], _post320(cust.id, "/api/updates/window",
                                                       {"start": "01:00", "end": "02:00"}).status_code),
       ([200, 400, 400], "03:15", "04:45", 403))
    _settings320()
    off = _post320(su.id, "/api/updates/auto", {"ref": "website:%d" % pend.id, "on": False})
    body = off.get_json() or {}
    eq("updates settings (POST /api/updates/auto): automatic updates off for one website is saved, answered with "
       "OWASP's recommendation as a note (never a refusal), and its row then says it waits; a customer may not "
       "switch it",
       (off.status_code, "OWASP" in (body.get("note") or ""), "website:%d" % pend.id in _u320.settings()["off"],
        _post320(cust.id, "/api/updates/auto", {"ref": "website:%d" % pend.id, "on": True}).status_code),
       (200, True, True, 403))
    rows, _d = _rows_of(su.id)
    r = next((x for x in rows if x["ref"] == "website:%d" % pend.id), {})
    eq("updates settings: an item switched off says it waits for Update now", (r.get("auto"), r.get("when")),
       (False, "Automatic updates are off for it: it waits for Update now."))
    _post320(su.id, "/api/updates/auto", {"ref": "website:%d" % pend.id, "on": True})
    check("updates settings control: switched on again, it is off no more",
          "website:%d" % pend.id not in _u320.settings()["off"], _u320.settings())


# ── 3. the nightly window ─────────────────────────────────────────────────────────────────────────
_RAN320 = []


def _install_stub320(results):
    def _install(site, restart=True, progress=None):
        _RAN320.append((site.id, _ws320.pinned_image(site)))
        return results.pop(0) if results else (True, "ok")
    return _install


def _tick320(now):
    del _RAN320[:]
    _ua320.tick(_p9, now=now)
    return [sid for sid, _pin in _RAN320]


def _s3_window(host, su, pend, other):
    _p9_patch(_w320, "install_site", _install_stub320([]))
    _p9_patch(_nt320, "notify", lambda *a, **k: None)
    _ua320._DONE.clear()
    _settings320(off=["website:%d" % other.id])
    _p9_patch(_sw320, "recent_requests", lambda remote, site: 0)
    out = _tick320(_OUT320)
    first = _tick320(_IN320)
    again = _tick320(_IN320 + 600)
    eq("nightly window (updates_auto.tick): outside the window nothing runs; inside it the pending website is "
       "updated through its own Update, once (a second pass in the same window leaves it), and a website switched "
       "off is left",
       (out, first, again), ([], [pend.id], []))
    eq("nightly window: the update is in the history as automatic, done", _last_row320(pend.id, "website_update"),
       (True, "automatic: image updated"))
    _ua320._DONE.clear()
    _p9_patch(_sw320, "recent_requests", lambda remote, site: 2)
    busy = _tick320(_NEXT320)
    eq("nightly window: a website with open connections from the web proxy (visitors in the last minutes) waits for "
       "the next window, and the history says so",
       (busy, "answered visitors" in _last_row320(pend.id, "update_skipped")[1]), ([], True))
    _ua320._DONE.clear()
    _p9_patch(_sw320, "recent_requests", lambda remote, site: 0)
    _p9_patch(_u320, "security", lambda: _cs320.parsed({"sites": ["php"]}))
    sec = _tick320(_NEXT320 + 60)
    eq("nightly window: a security update (the catalog's security section names php) is applied even to the website "
       "switched off; the other pending site with automatic on is updated too, one after the other",
       sorted(sec), sorted([pend.id, other.id]))
    rows = _rows_of(su.id)[0]
    r = next((x for x in rows if x["ref"] == "website:%d" % other.id), {})
    eq("nightly window: its row is marked a security update that installs by itself though automatic updates are off",
       (r.get("security"), r.get("when")),
       (True, "A security update: it installs by itself tonight at 04:00, though automatic updates are off for it."))
    _p9_patch(_u320, "security", lambda: _cs320.parsed(None))
    _settings320()


def _s3_busy_read(host):
    site = _site320(host, "p320-busy")
    _p9_restore_one(_sw320, "recent_requests")     # the window's stand-in: the real read now
    del _SH320[:]
    n = _sw320.recent_requests(host, site)
    sh = _SH320[-1][1] if _SH320 else ""
    eq("recent_requests: the established connections to the site's own port on the host, read with ss in the C "
       "locale as the site's account",
       (n, "LC_ALL=C ss -Htn state established '( sport = :%d )'" % site.port in sh), (0, True))


# ── 4. rollback ───────────────────────────────────────────────────────────────────────────────────
def _s4_rollback(host, su):
    site = _site320(host, "p320-rollback")
    sent = []
    _p9_patch(_nt320, "notify", lambda *a, **k: sent.append(a))
    _p9_patch(_w320, "install_site", _install_stub320([(False, "the new image did not start"), (True, "ok")]))
    _ua320._DONE.clear()
    _settings320()
    _p9_patch(_sw320, "recent_requests", lambda remote, site: 0)
    # The other pending sites were tried in this window already: this pass takes this one alone.
    _ua320._DONE.update({"website:%d" % i: "2026-11-27" for i in _ROWS320["sites"] if i != site.id})
    del _RAN320[:]
    _ua320.tick(_p9, now=_IN320 + 1200)
    mine = [pin for sid, pin in _RAN320 if sid == site.id]
    ok, detail = _last_row320(site.id, "website_update")
    eq("rollback: a failed automatic update installs the website again from the image it ran before (pinned), says "
       "so in the history and sends the auto_update_failed alert",
       (mine, ok, "put back on its previous image" in detail, [a[0] for a in sent]),
       (["", "localhost/p320-old:1"], False, True, ["auto_update_failed"]))
    return site


def _last_row320(site_id, action):
    """(success, detail) of the site's newest audit row of `action`; (None, "") when there is none."""
    row = (_Audit320.query.filter(_Audit320.website_id == site_id, _Audit320.action == action)
           .order_by(_Audit320.id.desc()).first())
    return (row.success, row.detail or "") if row is not None else (None, "")


def _last_install320():
    """The install shell of the last install recorded ("" when none ran)."""
    inst = [sh for _a, sh, _i in _SH320 if "SITE_FILES_REFUSED" in sh]
    return inst[-1] if inst else ""


def _s4_rollback_shell(site):
    _p9_restore_one(_w320, "install_site")
    _seams320()
    del _SH320[:]
    ok, _said = _ua320.rollback_site(site, "localhost/p320-old:1")
    sh = _last_install320()
    eq("rollback (the real install down to the account's shell): the previous image must still be on the host "
       "(podman image exists), and nothing is built or pulled",
       (ok, "podman image exists localhost/p320-old:1 || { echo SITE_PULL_FAILED; exit 23; }" in sh,
        "podman build" in sh, "podman pull -q localhost/p320-old:1" in sh, _ws320.pinned_image(site)),
       (True, True, False, False, ""))
    del _SH320[:]
    _w320.install_site(site)
    sh = _last_install320()
    check("rollback control: the website's own Update still builds its image from the catalog",
          "podman build" in sh and "podman image exists localhost/p320-old:1" not in sh, sh[-400:])


def _p9_restore_one(owner, name):
    from unit.part12 import _P9_PATCHED
    key = (owner, name)
    if key in _P9_PATCHED:
        setattr(owner, name, _P9_PATCHED.pop(key))


def _gs320(host, name):
    gs = _GS320(name=name, game_type="cod4", short_name="p320cod", port=28960, remote_id=host.id, installed=True,
                status="online")
    _db320.session.add(gs)
    _db320.session.commit()
    _ROWS320["servers"].append(gs.id)
    return gs


def _s4_addon(host, su):
    gs = _gs320(host, "p320-cod")
    sent, shells = [], []

    def _worker(app, gs_id, born, addon_id, who, kind, choice):
        from panel.routes import addons as _ra
        with _ra._JOBS_LOCK:
            _ra._JOBS[(gs_id, addon_id)] = {"running": False, "why": "The add-on was installed but didn't start.",
                                            "tail": "", "kind": kind}

    def _shell(server, user, sh, timeout=30, selfname=None, stdin_text=None):
        shells.append(sh)
        return "ADDON_ROLLED_BACK\n", "", 0
    _p9_patch(_ch320, "_worker", _worker)
    from unit.part12 import _p9_patch_sm
    _p9_patch_sm("shell_as_game_user", _shell)
    _p9_patch(_nt320, "notify", lambda *a, **k: sent.append(a))
    from panel.routes import _shared as _sh320
    _p9_patch(_sh320, "game_account_write_refusal", lambda *a, **k: None)
    ok, why = _ua320.update_addon(_p9, gs, "b3", "automatic")
    sh = shells[-1] if shells else ""
    d = _ad320.addon_dir(gs.short_name, "b3")
    eq("add-on rollback: a failed update puts the add-on back on the record and unit it had (their .prev copies), "
       "restarts it and watches it, records it and sends the alert",
       (ok, bool(why), "mv -f %s/addon.json.prev %s/addon.json" % (d, d) in sh, "ADDON_ROLLED_BACK" in sh,
        "ADDON_NO_PREVIOUS" in sh, [a[0] for a in sent]),
       (False, True, True, True, True, ["auto_update_failed"]))
    keep = _ad320.reconfigure_sh(gs.short_name, "b3", "[Unit]\n", "{}\n", {}, {}, {"rebuild": True, "keep_prev": True})
    plain = _ad320.reconfigure_sh(gs.short_name, "b3", "[Unit]\n", "{}\n", {}, {}, {"rebuild": True})
    cp = "cp -pf %s/addon.json %s/addon.json.prev" % (d, d)
    eq("add-on update: with keep_prev the record and unit are copied before the update writes its own record (and "
       "removed once it ran well); without it nothing is copied",
       (cp in keep and keep.index(cp) < keep.find(_ad320._put_sh("%s/addon.json" % d, "{}\n")),
        "rm -f %s/addon.json.prev" % d in keep, cp in plain), (True, True, False))
    return gs


def _s4_addon_guards(gs):
    """update_addon runs the card's own checks first: the account's write refusal, and a reboot holding the server."""
    from panel.routes import _shared as _sh320
    ran = []
    _p9_patch(_ch320, "_worker", lambda *a, **k: ran.append(a[3]))
    _p9_patch(_sh320, "game_account_write_refusal", lambda *a, **k: "refused: a root-capable account")
    refused = _ua320.update_addon(_p9, gs, "b3", "automatic")
    _p9_patch(_sh320, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_sh320, "_reboot_holds", lambda server: True)
    held = _ua320.update_addon(_p9, gs, "b3", "automatic")
    _p9_restore_one(_sh320, "_reboot_holds")
    skip = (_Audit320.query.filter(_Audit320.game_server_id == gs.id, _Audit320.action == "update_skipped")
            .order_by(_Audit320.id.desc()).first())
    eq("add-on update (nightly window, safe now): refused for a root-capable game account and while a reboot holds "
       "the server, before anything runs as the account, and the history says why",
       (refused[0], held[0], ran, skip.detail if skip is not None else ""),
       (False, False, [], "automatic: b3 not updated, its host is being rebooted; the next window tries again"))


def _s4_addon_once(gs):
    """A server's add-ons are read from its host once per window, not on every pass of the loop."""
    reads = []
    _p9_patch(_ua320, "_pending_addons", lambda server, cfg: reads.append(server.id) or [])
    _ua320._DONE.clear()
    _ua320._DONE.update({"website:%d" % i: "2026-11-27" for i in _ROWS320["sites"]})
    _ua320.tick(_p9, now=_IN320)
    _ua320.tick(_p9, now=_IN320 + 300)
    _ua320.tick(_p9, now=_OUT320)
    eq("nightly window: each game server's add-ons are read once per window (two passes inside it, one outside)",
       reads.count(gs.id), 1)
    _p9_patch(_ua320, "_pending_addons", lambda server, cfg: [])


def _s4_addon_switch(gs):
    """An add-on's automatic switch: refused for a holder of Manage add-ons who cannot reach that server."""
    from panel.db.models import Group as _Grp320
    grp = _Grp320(name="p320-addons", description="")
    grp.set_permissions([_auth320.MANAGE_ADDONS])
    _db320.session.add(grp)
    _db320.session.commit()
    _ROWS320["groups"].append(grp.id)
    other = _user320("p320-addon-admin")
    other.groups = [grp]
    _db320.session.commit()
    with _u320._SEEN_LOCK:
        _u320._ADDONS_SEEN[gs.id] = {"at": 0, "rows": {"b3": {"reason": "image", "version": "1", "new": "2"}}}
    ref = "addon:%d:b3" % gs.id
    eq("updates settings (POST /api/updates/auto): an add-on's switch is refused for a user who holds Manage add-ons "
       "but cannot reach its server, and works for one who can",
       (_post320(other.id, "/api/updates/auto", {"ref": ref, "on": False}).status_code,
        _post320(_ROWS320["users"][0], "/api/updates/auto", {"ref": ref, "on": False}).status_code,
        ref in _u320.settings()["off"]), (403, 200, True))
    _u320.set_auto(ref, True)
    with _u320._SEEN_LOCK:
        _u320._ADDONS_SEEN.pop(gs.id, None)


def _s4_change_steps():
    """addons_change._change_steps passes keep_prev for an update only (read from the function it builds `how` in)."""
    import ast
    import inspect
    src = inspect.getsource(_ch320._change_steps)
    tree = ast.parse(src)
    keys = [k.value for n in ast.walk(tree) if isinstance(n, ast.Dict) for k in n.keys if isinstance(k, ast.Constant)]
    check("add-on update: _change_steps asks reconfigure_sh to keep the previous record and unit (keep_prev) for an "
          "update", "keep_prev" in keys and 'kind == "update"' in src.split('"keep_prev":', 1)[-1][:40], keys)


# ── 5. the website Overview ───────────────────────────────────────────────────────────────────────
def _s5_overview(host, su, pend):
    from panel.routes import websites_view as _wv320
    with _p9.test_request_context():
        img = _wv320._image(pend, {})
    eq("website Overview (its image block): how many updates are ready and what, and that it installs by itself at "
       "the window's start",
       (img.get("update_available"), (img.get("ready") or "").startswith("2 update(s) ready: "), img.get("when"),
        img.get("note")), (True, True, "By itself tonight at 04:00 (the host's clock).", ""))
    _u320.set_auto("website:%d" % pend.id, False)
    with _p9.test_request_context():
        img = _wv320._image(pend, {})
    check("website Overview: with automatic updates off, the lasting note names OWASP's recommendation",
          "OWASP" in (img.get("note") or "") and img.get("auto") is False, img)
    _u320.set_auto("website:%d" % pend.id, True)


# ── 6. the catalog's security section ─────────────────────────────────────────────────────────────
def _s6_catalog():
    import importlib.util as _ilu
    from unit.part01 import _root
    spec = _ilu.spec_from_file_location("addon_catalog_p320", os.path.join(_root, "tools", "addon_catalog.py"))
    tool = _ilu.module_from_spec(spec)
    spec.loader.exec_module(tool)
    floor = __import__("json").load(open(os.path.join(_root, "panel", "addon_images", "catalog.json")))
    good = dict(floor, security={"addons": ["b3"], "sites": ["php"], "note": "base image fix"})
    bad = dict(floor, security={"sites": ["mail"]})
    eq("catalog security section: the panels accept addons/sites/note and refuse anything else; the signer accepts "
       "a source with a good one and refuses a bad one by the same check",
       (_cs320.security_problems(good["security"]), bool(_cs320.security_problems({"sites": ["mail"]})),
        bool(_cs320.security_problems({"x": 1})), tool.source_problems(good), bool(tool.source_problems(bad)),
        sorted(_cs320.parsed(good["security"])["addons"])),
       ([], True, True, [], True, ["b3"]))


# ── 7. Update everything safe now ─────────────────────────────────────────────────────────────────
def _s7_safe(host, su, gs):
    _p9_patch(_w320, "install_site", _install_stub320([]))
    with _u320._SEEN_LOCK:
        _u320._ADDONS_SEEN[gs.id] = {"at": 0, "rows": {"b3": {"reason": "image", "version": "1", "new": "2"}}}
    _p9_patch(_mon320, "_cached_player_count", lambda sid: 3)
    stale = _post320(su.id, "/api/updates/safe", stale=True)
    with _p9.test_request_context():
        refs = _ru320._safe_rows(su)
        _p9_patch(_mon320, "_cached_player_count", lambda sid: 0)
        refs_empty = _ru320._safe_rows(su)
    eq("safe now (POST /api/updates/safe): a stale sign-in confirms the password first; the safe rows are the "
       "websites, and an add-on only while its server has no players on",
       (stale.status_code, "addon:%d:b3" % gs.id in refs, "addon:%d:b3" % gs.id in refs_empty,
        all(r.split(":")[0] in ("website", "addon", "lgsm") for r in refs_empty)), (403, False, True, True))
    calls = []
    _p9_patch(_ru320, "_run_one", lambda app, user, ref: calls.append(ref))
    r = _post320(su.id, "/api/updates/safe")
    deadline = _time320.time() + 10
    while len(calls) < len(refs_empty) and _time320.time() < deadline:
        _time320.sleep(0.05)
    eq("safe now: with a fresh sign-in each safe row is run in the background, one after the other",
       (r.status_code, (r.get_json() or {}).get("started"), sorted(calls)), (202, len(refs_empty), sorted(refs_empty)))
    with _u320._SEEN_LOCK:
        _u320._ADDONS_SEEN.pop(gs.id, None)


# ── 8. history, LinuxGSM and host rows ────────────────────────────────────────────────────────────
def _s8_rows(host, su, cust, gs):
    from panel.services import lgsm_releases as _lr320
    _url320 = _lr320.RELEASES_PAGE + "/tag/v26.6.0"
    _p9_patch(_lr320, "releases", lambda newest=None: [{"tag": "v26.6.0", "url": _url320, "blocks": [], "cut": False}])
    _u320.note_lgsm(gs.id, {"release": "v26.4.0", "latest": "v26.6.0", "behind": True})
    local = host.id
    _osseen320[local] = {"name": "p320-host", "count": 3, "security": 1, "at": 1, "created": host.created_at,
                         "packages": [{"name": "openssl", "label": "openssl", "suite": "noble-security"}]}
    rows, d = _rows_of(su.id)
    lg = next((x for x in rows if x["ref"] == "lgsm:%d" % gs.id), {})
    os_ = next((x for x in rows if x["kind"] == "os"), {})
    _osseen320.pop(local, None)
    _u320.forget_server(gs.id)
    eq("updates rows: a server behind LinuxGSM's latest release is listed as safe with update-lgsm through its own "
       "action route and the notes of the release it moves to; the panel host's packages with their security count and the host card's Update",
       (lg.get("safe"), (lg.get("action") or {}).get("body"), lg.get("notes"), bool(os_), os_.get("security"),
        ((os_.get("action") or {}).get("href") or "").endswith("?update=os#os-updates")),
       (True, {"action": "update-lgsm"}, [{"title": "v26.6.0", "url": _url320}], True, True, True))
    return d


def _s8_history(d, cust):
    hist = d.get("history") or []
    eq("updates history: the automatic runs are in it, by 'automatic'; a customer reads only their own site's rows",
       (any(h["who"] == "automatic" and h["action"] == "website_update" for h in hist),
        {h["target"] for h in _rows_of(cust.id)[1].get("history") or []} <= {"p320-pending"}), (True, True))


def _cleanup320():
    _db320.session.rollback()
    from panel.db.models import Group as _Grp320
    _db320.session.query(_Audit320).filter(_Audit320.website_id.in_(_ROWS320["sites"] or [0])).delete(
        synchronize_session=False)
    for model, ids in ((_Site320, _ROWS320["sites"]), (_GS320, _ROWS320["servers"]), (_Grp320, _ROWS320["groups"]),
                       (_User320, _ROWS320["users"]), (_Remote320, _ROWS320["remotes"])):
        for i in ids:
            row = _db320.session.get(model, i)
            if row is not None:
                _db320.session.delete(row)
    _db320.session.commit()
    _cfg320.update_config(lambda cfg: cfg.pop(_u320.CFG, None))
    _ua320._DONE.clear()
    _u320.forget_counts()


def _ran320(step, *args):
    """Run one section: its result, or None when it raised (the traceback kept in _ran320.last)."""
    import traceback
    try:
        _ran320.last = ""
        return step(*args) or True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db320.session.rollback()
        _ran320.last = traceback.format_exc()[-1500:]
        return None


_ran320.last = ""
_trips320 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part320")
        _seams320()
        _p9_patch(_so320, "panel_update_cached", lambda: None)
        _host320, _su320 = _rows320()
        _got320 = _ran320(_s1_page, _host320, _su320)
        check("part320: _s1_page ran to the end", _got320, _ran320.last)
        _pend320, _other320, _cust320 = _got320 if isinstance(_got320, tuple) else (None, None, None)
        for _name320, _step320, _args320 in (
                ("_s2_settings", _s2_settings, (_host320, _su320, _pend320, _cust320)),
                ("_s3_window", _s3_window, (_host320, _su320, _pend320, _other320)),
                ("_s3_busy_read", _s3_busy_read, (_host320,)),
                ("_s4_rollback", lambda h, s: _s4_rollback_shell(_s4_rollback(h, s)), (_host320, _su320)),
                ("_s4_change_steps", _s4_change_steps, ()),
                ("_s5_overview", _s5_overview, (_host320, _su320, _pend320)),
                ("_s6_catalog", _s6_catalog, ())):
            check("part320: %s ran to the end" % _name320, _ran320(_step320, *_args320), _ran320.last)
        _gs320v = _ran320(_s4_addon, _host320, _su320)
        check("part320: _s4_addon ran to the end", _gs320v, _ran320.last)
        if isinstance(_gs320v, _GS320):
            for _name320, _step320 in (("_s4_addon_guards", _s4_addon_guards), ("_s4_addon_once", _s4_addon_once),
                                       ("_s4_addon_switch", _s4_addon_switch)):
                check("part320: %s ran to the end" % _name320, _ran320(_step320, _gs320v), _ran320.last)
            check("part320: _s7_safe ran to the end", _ran320(_s7_safe, _host320, _su320, _gs320v), _ran320.last)
            _d320 = _ran320(_s8_rows, _host320, _su320, _cust320, _gs320v)
            check("part320: _s8_rows ran to the end", _d320, _ran320.last)
            check("part320: _s8_history ran to the end", _ran320(_s8_history, _d320 if isinstance(_d320, dict) else {},
                                                                 _cust320), _ran320.last)
        eq("part320: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips320:], [])
    finally:
        _p9_restore_all()
        _w320._STATUS.clear()
        _cleanup320()
