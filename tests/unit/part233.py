"""Part 233 of the unit suite: Settings -> Outside services, one switch per outside call.

1. The switches: on unless config.json holds exactly false; a Settings post without the switches block
   changes none of them.
2. The Settings card: one switch per service with its note, checked from the stored value, a confirm
   only on the update check and the breached-password check; a save stores each switch, names the
   change in the audit row, and drops a cached update status when the update check moves.
3. Each call site with its switch off asks nothing: the panel update check (status, the Update button,
   the branch list and a branch switch), LinuxGSM's files and release notes, game icons, Steam Workshop
   titles, Modrinth, and the public-address lookup. With the switch on, each still asks.
4. Text: every row in Spanish and French; the Workshop card's "off" line and the confirm step in the
   page's JavaScript; docs/PRIVACY.md names each switch.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; the switch is read through
outside_services.config_value, which each check replaces, and every network function is a recorder.
Nothing reaches the network, a host or data/.
"""
import os
import urllib.error as _urlerr233
import urllib.parse as _urlparse233
import urllib.request as _urlreq233
from types import SimpleNamespace as _NS233

from unit.part01 import check, eq
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_delete_server, _p9_json,
                         _p9_new_server, _p9_patch, _p9_restore_all)
from panel.core import i18n as _i18n233
from panel.core import outside_services as _osv233
from panel.db.models import AuditLog as _AL233
from panel.ops import system_ops as _so233
from panel.ops.ssh_manager import _core as _core233
from panel.routes import admin_notifications as _an233
from panel.services import game_icons as _gi233
from panel.services import lgsm_data as _lgd233
from panel.services import lgsm_releases as _lgr233
from panel.services import modrinth as _mr233
from panel.services import steam_workshop as _ws233

_trips233 = len(_P9_TRIPPED)
_LIVE233 = ("PERMANENT_SESSION_LIFETIME", "SESSION_ABSOLUTE_SECONDS", "REMEMBER_COOKIE_DURATION",
            "STEP_UP_MINUTES", "SESSION_PROTECTION", "REQUIRE_2FA")
_FORM233 = {"session_idle_minutes": "30", "session_absolute_hours": "8", "remember_days": "3"}


def _switches233(stored):
    """Read every switch from `stored` (a dict standing in for config.json)."""
    _p9_patch(_osv233, "config_value", lambda key, default=None: stored.get(key, default))


def _off233(*keys):
    """Switch `keys` off (the rest on) for the checks that follow, until _p9_restore_all."""
    _switches233({k: False for k in keys})


def _urllib233(owner, **request):
    """Give `owner` its own `urllib` whose request functions named in `request` are stand-ins.

    The module's name is replaced, not urllib's attribute: a stdlib attribute set by a test would
    stand in for every module and thread (part37's gate).
    """
    req = _NS233(Request=_urlreq233.Request, HTTPRedirectHandler=_urlreq233.HTTPRedirectHandler, **request)
    _p9_patch(owner, "urllib", _NS233(request=req, parse=_urlparse233, error=_urlerr233))


def _recorder233(answer=None, exc=None):
    """(function recording each call's arguments, the list it records into)."""
    calls = []

    def _rec(*a, **kw):
        calls.append(a)
        if exc is not None:
            raise exc
        return answer
    return _rec, calls


# ── 1. the switches ──────────────────────────────────────────────────────────────────────────────
def _basics233():
    got = {}
    for label, stored in (("missing", {}), ("false", {_osv233.GAME_ICONS: False}),
                          ("true", {_osv233.GAME_ICONS: True}), ("0", {_osv233.GAME_ICONS: 0}),
                          ("text", {_osv233.GAME_ICONS: "false"}), ("none", {_osv233.GAME_ICONS: None})):
        _switches233(stored)
        got[label] = _osv233.enabled(_osv233.GAME_ICONS)
        _p9_restore_all()
    eq("outside services: a switch is off only when config.json holds exactly false (missing, true, 0, "
       "\"false\" and null are on)", got,
       {"missing": True, "false": False, "true": True, "0": True, "text": True, "none": True})
    marked = dict.fromkeys((_osv233.FORM_MARKER, _osv233.UPDATE_CHECK, _osv233.MODRINTH), "on")
    parsed = _osv233.parse_form(marked)
    eq("outside services: a post with the switches block stores every switch (an unticked one as off); "
       "one without it stores none",
       (_osv233.parse_form({_osv233.UPDATE_CHECK: "on"}), sorted(k for k, v in parsed.items() if v),
        sorted(parsed) == sorted(_osv233.KEYS)),
       ({}, sorted([_osv233.UPDATE_CHECK, _osv233.MODRINTH]), True))
    eq("outside services: seven switches, the confirm step on the update check and the breached-password "
       "check only",
       (len(_osv233.SERVICES), sorted(s["key"] for s in _osv233.SERVICES if s.get("confirm"))),
       (7, sorted([_osv233.UPDATE_CHECK, _osv233.BREACH_CHECK])))


# ── 2. the Settings card and its save ────────────────────────────────────────────────────────────
def _row233(page, key):
    """The <input> tag of one switch on the Settings page ("" when it is missing)."""
    at = page.find('id="s-%s"' % key)
    return page[page.rfind("<input", 0, at):page.find(">", at) + 1] if at >= 0 else ""


def _settings_page233(stored):
    _p9_patch(_an233, "load_config", lambda: dict(stored))
    try:
        return _p9_client(P9_ADMIN).get("/settings").get_data(as_text=True)
    finally:
        _p9_restore_all()
        _p9_arm(who="part233")


def _page233():
    on = _settings_page233({})
    off = _settings_page233({_osv233.GAME_ICONS: False, _osv233.UPDATE_CHECK: False})
    rows = {s["key"]: _row233(on, s["key"]) for s in _osv233.SERVICES}
    eq("settings: the Outside services card has one switch per service, each on by default, with its note "
       "and the hidden marker that says the post carries them",
       ('id="sec-outside"' in on, 'name="outside_services_form" value="1"' in on,
        [k for k, tag in rows.items() if not ('name="%s"' % k in tag and "checked" in tag)],
        [s["key"] for s in _osv233.SERVICES if s["note"] not in on.replace("&#39;", "'")]),
       (True, True, [], []))
    eq("settings: a switch saved off is drawn unticked, the others stay ticked",
       ("checked" in _row233(off, _osv233.GAME_ICONS), "checked" in _row233(off, _osv233.UPDATE_CHECK),
        "checked" in _row233(off, _osv233.MODRINTH)), (False, False, True))
    eq("settings: the update check and the breached-password check show OWASP's recommended value, with the "
       "'outside OWASP's recommendation' note drawn only while the switch is off",
       ([("OWASP recommends on" in on, 'class="small text-warning d-none" id="s-%s-owasp"' % k in on,
          'class="small text-warning" id="s-%s-owasp"' % k in off) for k in (_osv233.UPDATE_CHECK,)],
        'class="small text-warning d-none" id="s-%s-owasp"' % _osv233.BREACH_CHECK in off),
       ([(True, True, True)], True))
    eq("settings: only the update check and the breached-password check ask before they go off",
       sorted(k for k, tag in rows.items() if "data-confirm-off=" in tag),
       sorted([_osv233.UPDATE_CHECK, _osv233.BREACH_CHECK]))


def _last_audit233():
    with _p9.app_context():
        r = _AL233.query.filter_by(action="settings_update").order_by(_AL233.id.desc()).first()
        return r.detail if r else ""


def _save233(saved, form):
    """POST the Settings form as the admin; (status, what was stored, the audit detail)."""
    live = {k: _p9.config.get(k) for k in _LIVE233}
    try:
        r = _p9_client(P9_ADMIN).post("/settings/save", data=dict(_FORM233, **form))
    finally:
        _p9.config.update(live)
    return r.status_code, {k: saved[k] for k in _osv233.KEYS if k in saved}, _last_audit233()


def _save_cases233():
    saved, cache_was = {}, dict(_so233._update_cache)
    _p9_patch(_an233, "update_config", lambda mutate: mutate(saved))
    _switches233(saved)
    ticked = {k: "on" for k in _osv233.KEYS if k not in (_osv233.GAME_ICONS, _osv233.UPDATE_CHECK)}
    try:
        _so233._update_cache.update(ts=1.0, data={"p233": 1})
        first = _save233(saved, dict(ticked, outside_services_form="1"))
        dropped = _so233._update_cache.get("data")
        _so233._update_cache.update(ts=1.0, data={"p233": 2})
        again = _save233(saved, dict(ticked, outside_services_form="1"))
        kept = _so233._update_cache.get("data")
        stale = _save233(saved, {"site_title": "p233"})
    finally:
        _so233._update_cache.clear()
        _so233._update_cache.update(cache_was)
    return first, dropped, again, kept, stale


def _save_checks233():
    try:
        first, dropped, again, kept, stale = _save_cases233()
    finally:
        _p9_restore_all()
        _p9_arm(who="part233")
    want = {k: k not in (_osv233.GAME_ICONS, _osv233.UPDATE_CHECK) for k in _osv233.KEYS}
    eq("settings save: every switch is stored, an unticked one as false, and the audit row names what went off",
       (first[0], first[1], "Outside services: Panel update check (GitHub) off, Game icons (linuxgsm.com) off"
        in first[2]), (302, want, True))
    eq("settings save: turning the update check off drops the cached update status; a save that leaves it "
       "off keeps the cache and writes no switch change into the audit row",
       (dropped, kept, "Outside services" in again[2]), (None, {"p233": 2}, False))
    eq("settings save: a post without the switches block (a page opened before them) changes none",
       (stale[0], stale[1]), (302, want))


# ── 3a. the panel update check ───────────────────────────────────────────────────────────────────
def _git_rec233():
    rec, calls = _recorder233(("abc1234", "", 0))
    _p9_patch(_so233, "_git", rec)
    _p9_patch(_so233, "_update_in_progress", lambda: False)
    return calls


def _update_status233():
    _off233(_osv233.UPDATE_CHECK)
    calls = _git_rec233()
    computed, computes = _recorder233({"git": True, "p233": True})
    _p9_patch(_so233, "_compute_update_status", computed)
    off = _so233.panel_update_status(force=True)
    route = _p9_json(_p9_client(P9_ADMIN).get("/api/panel/update-status?force=1"))
    off_gits, off_computes = [c[0][0] for c in calls], len(computes)
    _switches233({})
    on = _so233.panel_update_status(force=True)
    eq("update check off: the status says so (no update, no Update button) with no git fetch and nothing "
       "asked of GitHub; the route answers the same",
       (off.get("update_check_off"), off.get("update_available"), off.get("git"), "fetch" in off_gits,
        off_computes, route.get("update_check_off"), route.get("message") == _so233.UPDATE_CHECK_OFF),
       (True, False, False, False, 0, True, True))
    eq("update check on: the status is computed as before", (on.get("p233"), len(computes)), (True, 1))


def _update_actions233():
    _off233(_osv233.UPDATE_CHECK)
    calls = _git_rec233()
    _p9_patch(_so233, "_is_git_checkout", lambda: True)
    launch, launches = _recorder233((True, "started"))
    _p9_patch(_so233, "_launch_installer", launch)
    fetch_all, fetched = _recorder233()
    _p9_patch(_so233, "_fetch_all_branches", fetch_all)
    update = _so233.panel_self_update()
    branches = _so233.list_panel_branches()
    switch = _so233.panel_switch_branch("main")
    off_gits, off_fetched = [c[0][0] for c in calls], list(fetched)
    _switches233({})
    _p9_patch(_so233, "_r12a_tracked_tip", lambda b: "x")
    _so233.list_panel_branches()
    eq("update check off: the Update button, the branch list and a branch switch ask GitHub nothing "
       "(no install launched, no fetch, no ls-remote) and say why",
       (update, launches, off_fetched, switch, "ls-remote" in off_gits, "fetch" in off_gits, branches[0] == [branches[1]]),
       ((False, _so233.UPDATE_CHECK_OFF), [], [], (False, _so233.UPDATE_CHECK_OFF), False, False, True))
    eq("update check on: the branch list fetches the branches as before", len(fetched), 1)


# ── 3b. LinuxGSM's files and release notes ───────────────────────────────────────────────────────
def _thread_rec233(owner):
    started = []
    _p9_patch(owner, "threading", _NS233(Thread=lambda **kw: _NS233(start=lambda: started.append(kw.get("name")))))
    return started


def _lgsm_reads233(stored):
    """(download answer, urlopen calls, threads started by latest_release and releases) under `stored`."""
    _switches233(stored)
    rec, opened = _recorder233(exc=OSError("p233"))
    _urllib233(_lgd233, urlopen=rec)
    started = _thread_rec233(_lgd233)
    lgr_started = _thread_rec233(_lgr233)
    latest_was, cache_was = dict(_lgd233._latest), dict(_lgr233._cache)
    lgr_open, lgr_opened = _recorder233(exc=OSError("p233"))
    _p9_patch(_lgr233, "_open", lgr_open)
    try:
        _lgd233._latest.update(until=0.0, running=False)
        _lgr233._cache.update(until=0.0, running=False)
        answer = _lgd233._download(_lgd233._BASE + _lgd233.SERVERLIST, _lgd233.SERVERLIST)
        _lgd233.latest_release()
        _lgr233.releases()
        notes = _lgr233._fetch()
        threads = (list(started), list(lgr_started))
    finally:
        _lgd233._latest.update(latest_was)
        _lgr233._cache.update(cache_was)
        _p9_restore_all()
        _p9_arm(who="part233")
    return answer, len(opened), threads, notes, len(lgr_opened)


def _lgsm233():
    off = _lgsm_reads233({_osv233.LGSM_GITHUB: False})
    on = _lgsm_reads233({})
    eq("LinuxGSM switch off: no file is downloaded (the cached copy answers, status says it is switched "
       "off), no newest-version or release-notes read starts, and the notes are not asked for",
       off, ((None, _osv233.OFF_MESSAGE), 0, ([], []), None, 0))
    eq("LinuxGSM switch on: the file is asked for, both background reads start, the notes are asked for",
       (on[1], on[2], on[4]), (1, (["lgsm-latest"], ["lgsm-releases"]), 1))


# ── 3c. game icons, Steam Workshop, Modrinth ─────────────────────────────────────────────────────
def _icons233(stored):
    _switches233(stored)
    fetch, fetched = _recorder233(None)
    _p9_patch(_gi233, "_cmpd_cached", lambda script: None)
    _p9_patch(_gi233, "_cmpd_fetch_icon", fetch)
    opener, built = _recorder233(None)
    _urllib233(_gi233, build_opener=opener)
    _gi233._failed.pop("p233server", None)
    got = _gi233.icon("p233server", {"p233server"})
    http = _gi233._cmpd_http_get(_gi233.INDEX_URL, 10)
    backoff = "p233server" in _gi233._failed
    _gi233._failed.pop("p233server", None)
    _p9_restore_all()
    return got, len(fetched), backoff, http[2], len(built)


def _icons_checks233():
    eq("game icons off: no icon or index is fetched, and none is put on the retry backoff, so turning the "
       "switch back on fetches at once",
       _icons233({_osv233.GAME_ICONS: False}), (None, 0, False, "turned off in Settings", 0))
    eq("game icons on: a missing icon is fetched", _icons233({})[1], 1)


def _steam233(stored):
    _switches233(stored)
    opener, built = _recorder233(None)
    _urllib233(_ws233, build_opener=opener)
    _ws233._wsc_cache.pop("2330000001", None)
    sid = _p9_new_server(P9_HOST, "p233ws", "gmod", 27233)
    try:
        route = _p9_json(_p9_client(P9_ADMIN).get("/api/server/%d/workshop/titles?ids=2330000001" % sid))
    finally:
        _p9_delete_server(sid)
        _p9_restore_all()
        _p9_arm(who="part233")
    return route.get("off"), route.get("complete"), len(built)


def _mdr_http233(stored):
    """(why, build_opener calls) for Modrinth's own GET under `stored`."""
    _switches233(stored)
    opener, built = _recorder233(None)
    _urllib233(_mr233, build_opener=opener)
    try:
        return _mr233._mdr_http_get(_mr233.API + "/search", 10, frozenset({"api.modrinth.com"}))[1], len(built)
    finally:
        _p9_restore_all()


def _modrinth233(stored):
    _switches233(stored)
    get, got = _recorder233((None, "p233"))
    _p9_patch(_mr233, "_mdr_http_get", get)
    answers = (_mr233.search("lux")[1], _mr233.resolve("AAAABBBB")[1],
               _mr233.download({"url": "https://cdn.modrinth.com/x.jar", "sha512": "0" * 128})[1])
    sid = _p9_new_server(P9_HOST, "p233mc", "pmc", 25233)
    try:
        r = _p9_client(P9_ADMIN).get("/api/server/%d/plugins/search?q=lux" % sid)
    finally:
        _p9_delete_server(sid)
        _p9_restore_all()
        _p9_arm(who="part233")
    return answers, len(got), (r.status_code, _p9_json(r).get("error"))


def _steam_modrinth233():
    eq("Steam Workshop off: the titles route asks Steam nothing and says the titles are switched off",
       _steam233({_osv233.STEAM_WORKSHOP: False}), (True, False, 0))
    eq("Steam Workshop on: Steam is asked (here it does not answer) and the route does not say off",
       _steam233({}), (False, False, 2))
    off = _modrinth233({_osv233.MODRINTH: False})
    on = _modrinth233({})
    eq("Modrinth off: search, resolve and download answer that it is switched off without a request, and the "
       "search route says so", off, ((_mr233.OFF,) * 3, 0, (502, _mr233.OFF)))
    eq("Modrinth off: its one GET builds no opener; on, it does",
       (_mdr_http233({_osv233.MODRINTH: False}), _mdr_http233({})[1]), (("turned off in Settings", 0), 1))
    eq("Modrinth on: the API is asked (here it does not answer) and the route says it could not be reached",
       (on[1] > 0, on[2]), (True, (502, _mr233.UNAVAILABLE)))


# ── 3d. the public address lookup ────────────────────────────────────────────────────────────────
def _pubip233(stored, route_src):
    _switches233(stored)
    asked = []

    def _rc(server, cmd, timeout=30, sudo=None, stdin_text=None):
        asked.append(cmd)
        return (route_src if "route get" in cmd else "1.2.3.4"), "", 0
    _p9_patch(_core233, "run_command", _rc)
    srv = _NS233(id=-23301, name="p233", host="p233.example.invalid", is_local=False)
    _core233._gamedig_host_cache.pop(srv.id, None)
    try:
        return _core233.remote_public_ip(srv), any("ipify" in c or "opendns" in c for c in asked)
    finally:
        _core233._gamedig_host_cache.pop(srv.id, None)
        _p9_restore_all()


def _pubip_checks233():
    eq("public address lookup off: a host behind a router asks no service and gets no public address; a "
       "host with a public address of its own still answers with it",
       (_pubip233({_osv233.PUBLIC_IP: False}, "10.0.0.5"), _pubip233({_osv233.PUBLIC_IP: False}, "1.2.3.9")),
       (("", False), ("1.2.3.9", False)))
    eq("public address lookup on: a host behind a router asks one service", _pubip233({}, "10.0.0.5"),
       ("1.2.3.4", True))


# ── 4. text ──────────────────────────────────────────────────────────────────────────────────────
def _read233(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _text233():
    keys = [s[f] for s in _osv233.SERVICES for f in ("label", "note", "confirm", "owasp") if f in s]
    keys += ["Outside services", _mr233.OFF, _so233.UPDATE_CHECK_OFF, _osv233.OFF_MESSAGE,
             "Titles are off: the Steam Web API is turned off in Settings → Outside services. "
             "The ids can still be edited."]
    eq("outside services: every row, note, confirm and refusal is in the Spanish and French catalogs",
       {lang: [k for k in keys if k not in _i18n233.catalog(lang)] for lang in ("es", "fr")}, {"es": [], "fr": []})


def _js_docs233():
    js = _read233("panel", "static", "js", "settings.js")
    hook = js[js.find("#sec-outside input[data-confirm-off]"):]
    check("settings.js: a switch that asks puts itself back on and goes off only from the dialog's Confirm, and "
          "its outside-OWASP note follows it",
          "box.checked = true;" in hook and "onConfirm: function(){ box.checked = false; sync(); }" in hook
          and "note.classList.toggle('d-none', box.checked)" in hook
          and hook.find("box.checked = true;") < hook.find("confirmDialog("), hook[:400])
    check("server_workshop.js: titles switched off are said to be off, not that Steam did not answer",
          "if (d && d.off) msg(t('Titles are off:" in _read233("panel", "static", "js", "server_workshop.js"))
    doc = _read233("docs", "PRIVACY.md")
    eq("PRIVACY.md: no service is left as 'a switch is planned', and each switch is named where its service is",
       ("switch is planned" in doc, [s["label"] for s in _osv233.SERVICES
                                     if "*%s*" % s["label"].split(" (")[0] not in doc]), (False, []))


try:
    _p9_arm(who="part233")
    _basics233()
    _page233()
    _save_checks233()
    _update_status233()
    _p9_restore_all()
    _p9_arm(who="part233")
    _update_actions233()
    _p9_restore_all()
    _p9_arm(who="part233")
    _lgsm233()
    _icons_checks233()
    _steam_modrinth233()
    _pubip_checks233()
    _text233()
    _js_docs233()
finally:
    _p9_restore_all()
check("part233: no check reached a real host", len(_P9_TRIPPED) == _trips233, repr(_P9_TRIPPED[_trips233:][:4]))
