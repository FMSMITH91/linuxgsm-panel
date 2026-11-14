"""Part 205 of the unit suite: updating LinuxGSM says what it did, shows what's new, and is one click.

update-lgsm (LinuxGSM's command_update_linuxgsm.sh) prints the files it checked and replaced, never
the release it moved to, and the panel said only "'update-lgsm' succeeded for 'x'." while the page's
"LinuxGSM v26.5.0 · v26.6.0 available" line stayed as it was until a reload. Held here:

* the update-lgsm route reads the script's release before and after the run and says "updated from
  A to B", "already up to date", "still on A: B was not installed", "could not read" or why it
  failed; the reply carries the line's new state and the notes of the releases in between; the
  outcome is said in the server's console (a panel marker, which makes every open page re-read its
  LinuxGSM line); a bot caller gets the same English sentence;
* /api/server/<id>/version carries the notes of the releases a server is behind by;
* lgsm_releases: GitHub's answer is cut to plain-text blocks (no tags, link targets, markup, drafts,
  prereleases or odd tags; the generated per-PR list and anything past the cap are left to the
  release page, whose URL is built from the tag); reads never wait on GitHub, start one background
  read at a time, and a copy missing the newest release is re-read at most hourly; the fetch is the
  fixed api.github.com URL;
* the page: the "available" note is a button opening the notes with "Update LinuxGSM" for a viewer
  the Maintenance menu offers update-lgsm to, the reply goes to that dialog, and nothing from the
  notes reaches innerHTML.

Everything drives part12's app with its transport tripwire armed and every host call stubbed.
"""
import json as _json205
import os as _os205
import time as _time205

from unit.part01 import check
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, P9_VIEWER, _P9_TRIPPED, _p9_arm, _p9_client, _p9_json,
                         _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_sd, _p9_set)
from panel.ops.ssh_manager import _core as _smc205
from panel.services import lgsm_data as _lgd205, lgsm_releases as _lgr205

_TRIP205_START = len(_P9_TRIPPED)
_SAVED_CACHE205 = dict(_lgr205._cache)


def _gh205(tag, body, **kw):
    """One item of GitHub's releases answer (invented notes)."""
    item = {"tag_name": tag, "draft": False, "prerelease": False, "body": body,
            "published_at": "2031-01-02T03:04:05Z", "html_url": "https://example.invalid/x"}
    item.update(kw)
    return item


_ANSWER205 = [
    _gh205("v30.3.0", "## Highlights\n\n- **Backups:** faster ([#9](https://example.invalid/pull/9)).\n"
                      "\n## What's Changed\n* fix(a): one by @someone in https://example.invalid/pull/1\n"),
    _gh205("v30.2.0", "Plain paragraph.\n- an item\n"),
    _gh205("v30.1.0", "- old item\n"),
    _gh205("v30.4.0-rc1", "- a candidate\n"),
    _gh205("v30.9.0", "- a draft\n", draft=True),
    _gh205("v30.8.0", "- a prerelease\n", prerelease=True),
    _gh205("v30.0.0; rm -rf ~", "- odd tag\n"),
    "not a release",
]
_PARSED205 = _lgr205.parse(_ANSWER205)


def _seed205(releases):
    """The cached copy holding `releases`, fresh, so nothing starts a read."""
    now = _time205.time()
    _lgr205._cache.update(releases=releases, read=now, until=now + 86400, running=False)


# ── the parser and sanitiser ─────────────────────────────────────────────────────────────────────
check("lgsm_releases.parse: releases newest first; drafts, prereleases and odd tags are dropped",
      [r["tag"] for r in _PARSED205 or []] == ["v30.3.0", "v30.2.0", "v30.1.0"], repr(_PARSED205))
check("lgsm_releases.parse: each release links its own page, built from the tag (never the answer's URL)",
      [r["url"] for r in _PARSED205 or []][:1] == [
          "https://github.com/GameServerManagers/LinuxGSM/releases/tag/v30.3.0"]
      and _PARSED205[0]["date"] == "2031-01-02", repr(_PARSED205[:1]))
check("lgsm_releases.parse: an answer that is not GitHub's list is None",
      _lgr205.parse({"message": "API rate limit exceeded"}) is None and _lgr205.parse(None) is None)
_b205, _cut205 = _lgr205.blocks(
    "## <b>Head</b>\n- **Bold** [words](javascript:alert(1)) ![img](https://example.invalid/i.png)"
    "<script>alert(1)</script> `code`\n1. numbered\nplain <img src=x onerror=alert(1)> text\n")
check("lgsm_releases.blocks: Markdown and HTML become plain text (no tags, link targets or markup)",
      _b205 == [{"k": "h", "t": "Head"}, {"k": "li", "t": "Bold words alert(1) code"},
                {"k": "li", "t": "numbered"}, {"k": "p", "t": "plain text"}] and _cut205 is False,
      repr(_b205))
check("lgsm_releases.blocks: GitHub's generated per-PR list is left to the release page",
      _PARSED205[0]["blocks"] == [{"k": "h", "t": "Highlights"}, {"k": "li", "t": "Backups: faster (#9)."}]
      and _PARSED205[0]["cut"] is True, repr(_PARSED205[:1]))
_long205, _lcut205 = _lgr205.blocks("\n".join("- item %d %s" % (i, "x" * 200) for i in range(40)))
check("lgsm_releases.blocks: one release is capped, and says it was",
      _lcut205 is True and 0 < len(_long205) < 40
      and sum(len(b["t"]) for b in _long205) <= _lgr205._NOTE_CHARS, repr((len(_long205), _lcut205)))
check("lgsm_releases.plain: control characters do not survive",
      _lgr205.plain("a\x1b[31mb\x00c") == "a [31mb c", repr(_lgr205.plain("a\x1b[31mb\x00c")))

# ── between and the cache ────────────────────────────────────────────────────────────────────────
try:
    _seed205(_PARSED205)
    _btw205 = [r["tag"] for r in _lgr205.between("v30.1.0", "v30.3.0")]
    _one205 = [r["tag"] for r in _lgr205.between(None, "v30.2.0")]
    _none205 = (_lgr205.between("v30.3.0", "v30.3.0"), _lgr205.between("v30.1.0", "master"))
finally:
    _lgr205._cache.clear()
    _lgr205._cache.update(_SAVED_CACHE205)
check("lgsm_releases.between: the releases after one up to another, newest first",
      _btw205 == ["v30.3.0", "v30.2.0"], repr(_btw205))
check("lgsm_releases.between: an unread start gives the end release alone; no range or a bad end, none",
      _one205 == ["v30.2.0"] and _none205 == ([], []), repr((_one205, _none205)))

_fetches205 = []
_saved_fetch205 = _lgr205._fetch
try:
    _lgr205._fetch = lambda: (_fetches205.append(1), _time205.sleep(0.3), _PARSED205)[2]
    _lgr205._cache.update(releases=None, read=0.0, until=0.0, running=False)
    _t205 = _time205.monotonic()
    _first205 = _lgr205.releases()
    _took205 = _time205.monotonic() - _t205
    _second205 = _lgr205.releases()
    for _ in range(50):
        if not _lgr205._cache["running"]:
            break
        _time205.sleep(0.05)
    _after205 = [r["tag"] for r in _lgr205.releases()]
    _n_after205 = len(_fetches205)
    _lgr205.releases("v30.3.0")                    # the newest is held: nothing to read
    _held205 = len(_fetches205)
    _lgr205.releases("v30.5.0")                    # newer than the copy, but read under an hour ago
    _soon205 = len(_fetches205)
    _lgr205._cache["read"] -= 3601
    _lgr205.releases("v30.5.0")                    # ...and past the hour: one re-read
    for _ in range(50):
        if not _lgr205._cache["running"]:
            break
        _time205.sleep(0.05)
    _late205 = len(_fetches205)
finally:
    _lgr205._fetch = _saved_fetch205
    _lgr205._cache.clear()
    _lgr205._cache.update(_SAVED_CACHE205)
check("lgsm_releases.releases: never waits on GitHub, and one read at a time",
      _first205 == [] and _took205 < 0.2 and _second205 == [] and _n_after205 == 1,
      repr((_first205, _took205, _second205, _fetches205)))
check("lgsm_releases.releases: once read the copy is served; a newer release re-reads at most hourly",
      _after205 == ["v30.3.0", "v30.2.0", "v30.1.0"] and _held205 == 1 and _soon205 == 1 and _late205 == 2,
      repr((_after205, _held205, _soon205, _late205)))

_asked205 = []


def _open205(req):
    _asked205.append((req.full_url, req.get_header("User-agent"), req.get_header("Accept")))
    return _json205.dumps(_ANSWER205[:2]).encode()


def _down205(req):
    raise OSError("down")


_saved_open205 = _lgr205._open
try:
    _lgr205._open = _open205
    _fetched205 = _lgr205._fetch()
    _lgr205._open = _down205
    _fetch_fail205 = _lgr205._fetch()
finally:
    _lgr205._open = _saved_open205
check("lgsm_releases._fetch: LinuxGSM's releases on api.github.com; a failure is None",
      [r["tag"] for r in _fetched205 or []] == ["v30.3.0", "v30.2.0"] and _fetch_fail205 is None
      and _asked205 == [("https://api.github.com/repos/GameServerManagers/LinuxGSM/releases?per_page=20",
                         "linuxgsm-panel", "application/vnd.github+json")], repr((_asked205, _fetched205)))


# ── the update-lgsm route ────────────────────────────────────────────────────────────────────────
def _update205(before, after, rc=0, out="", latest="v30.3.0", client=P9_ADMIN):
    """POST update-lgsm with the release read as `before` then `after`: (reply, events, console)."""
    events, pushed = [], []
    reads = iter((before, after))

    def _versions(remote, account, selfname):
        events.append(("read", account, selfname))
        return next(reads), None

    def _run(remote, user, action, **k):
        events.append(("run", user, action))
        return out, "", rc
    _p9_arm(who="part205")
    _p9_patch_sm("lgsm_versions", _versions)
    _p9_patch_sm("run_as_game_user", _run)
    _p9_patch_sm("list_server_commands", lambda *a, **k: [])
    _p9_patch(_lgd205, "latest_release", lambda: latest)
    _p9_patch(_p9_sd, "_console_push", lambda app, sid, text, ts=None: pushed.append((sid, text)))
    try:
        _seed205(_PARSED205)
        resp = _p9_client(client).post("/api/server/%d/action" % P9_GS, json={"action": "update-lgsm"})
        return _p9_json(resp), events, pushed
    finally:
        _p9_restore_all()
        _lgr205._cache.clear()
        _lgr205._cache.update(_SAVED_CACHE205)


_d205, _ev205, _push205 = _update205("v30.1.0", "v30.3.0")
check("update-lgsm: says it moved, from which release to which",
      _d205.get("success") is True
      and _d205.get("message") == "LinuxGSM on 'p9-cs' updated from v30.1.0 to v30.3.0.", repr(_d205))
check("update-lgsm: the release is read once before the run and once after it",
      [e[0] for e in _ev205] == ["read", "run", "read"] and _ev205[1] == ("run", "csgoserver", "update-lgsm"),
      repr(_ev205))
check("update-lgsm: the reply carries the LinuxGSM line's new state and what's new in between",
      {k: (_d205.get("lgsm") or {}).get(k) for k in ("release", "latest", "behind", "before")}
      == {"release": "v30.3.0", "latest": "v30.3.0", "behind": False, "before": "v30.1.0"}
      and [r["tag"] for r in (_d205.get("lgsm") or {}).get("notes", [])] == ["v30.3.0", "v30.2.0"]
      and (_d205.get("lgsm") or {}).get("notes_url") == "https://github.com/GameServerManagers/LinuxGSM/releases",
      repr(_d205.get("lgsm")))
check("update-lgsm: the outcome is said in the server's console as a panel marker (open pages re-read)",
      _push205 == [(P9_GS, "[panel] update-lgsm: LinuxGSM on 'p9-cs' updated from v30.1.0 to v30.3.0.")],
      repr(_push205))

_d205, _ev205, _push205 = _update205("v30.3.0", "v30.3.0")
check("update-lgsm: on the latest already, it says so and shows no notes",
      _d205.get("success") is True
      and _d205.get("message") == "LinuxGSM on 'p9-cs' is already up to date (v30.3.0)."
      and (_d205.get("lgsm") or {}).get("notes") == [], repr(_d205))
_d205, _ev205, _push205 = _update205("v30.1.0", "v30.1.0")
check("update-lgsm: exit 0 that left it behind the latest is not reported as done",
      _d205.get("success") is False
      and _d205.get("message") == "LinuxGSM on 'p9-cs' is still on v30.1.0: v30.3.0 was not installed."
      and (_d205.get("lgsm") or {}).get("behind") is True, repr(_d205))
_d205, _ev205, _push205 = _update205("v30.1.0", None)
check("update-lgsm: a release it cannot read afterwards is said, never guessed",
      _d205.get("success") is True and "could not read which LinuxGSM release" in _d205.get("message", "")
      and (_d205.get("lgsm") or {}).get("release") == "", repr(_d205))
_fail_out205 = ("[  OK  ] Updating LinuxGSM csgoserver: Selecting repo: GitHub\n"
                "[ FAIL ] Updating LinuxGSM csgoserver: Selecting repo: Unable to to access GitHub or "
                "Bitbucket repositories\n")
_d205, _ev205, _push205 = _update205("v30.1.0", "v30.1.0", rc=1, out=_fail_out205)
check("update-lgsm: a failure names LinuxGSM's own line for it",
      _d205.get("success") is False and _d205.get("message") == (
          "LinuxGSM could not be updated on 'p9-cs': [ FAIL ] Updating LinuxGSM csgoserver: Selecting "
          "repo: Unable to to access GitHub or Bitbucket repositories")
      and len(_push205) == 1, repr((_d205, _push205)))

# A bot (no panel account) runs the same path: _run_action answers the English sentence.
_bot205 = []
try:
    _p9_arm(who="part205")
    _reads205 = iter(("v30.2.0", "v30.3.0"))
    _p9_patch_sm("lgsm_versions", lambda remote, account, selfname: (next(_reads205), None))
    _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: ("", "", 0))
    _p9_patch_sm("list_server_commands", lambda *a, **k: [])
    _p9_patch(_lgd205, "latest_release", lambda: "v30.3.0")
    _p9_patch(_p9_sd, "_console_push", lambda app, sid, text, ts=None: None)
    _seed205(_PARSED205)
    from unit.part12 import _p9   # noqa: E402
    from panel.db.models import GameServer as _GS205   # noqa: E402
    with _p9.app_context():
        _gs205 = _GS205.query.get(P9_GS)
        _bot205.append(_p9_sd._run_action(_p9, _gs205, _gs205.remote, "update-lgsm", None, origin="telegram"))
finally:
    _p9_restore_all()
    _lgr205._cache.clear()
    _lgr205._cache.update(_SAVED_CACHE205)
check("update-lgsm from a bot: the same plain English outcome",
      _bot205 and _bot205[0][0] is True
      and str(_bot205[0][1]) == "LinuxGSM on 'p9-cs' updated from v30.2.0 to v30.3.0.", repr(_bot205))


# ── the version endpoint ─────────────────────────────────────────────────────────────────────────
def _version205(release):
    _p9_arm(who="part205")
    _p9_patch_sm("game_version", lambda *a, **k: {"reported": "", "build": "", "appid": "",
                                                   "updated": None, "label": ""})
    _p9_patch_sm("lgsm_versions", lambda remote, account, selfname: (release, None))
    _p9_patch(_lgd205, "latest_release", lambda: "v30.3.0")
    try:
        _seed205(_PARSED205)
        return _p9_client(P9_ADMIN).get("/api/server/%d/version" % P9_GS).get_json() or {}
    finally:
        _p9_restore_all()
        _lgr205._cache.clear()
        _lgr205._cache.update(_SAVED_CACHE205)


_v205 = _version205("v30.1.0")
check("version endpoint: a server behind gets the notes of the releases it would move through",
      [r["tag"] for r in _v205.get("lgsm_notes", [])] == ["v30.3.0", "v30.2.0"]
      and (_v205.get("lgsm") or {}).get("behind") is True, repr(_v205))
check("version endpoint: an up-to-date or unread server gets none",
      _version205("v30.3.0").get("lgsm_notes") == [] and _version205(None).get("lgsm_notes") == [])


# ── the page ─────────────────────────────────────────────────────────────────────────────────────
def _page205(uid):
    _p9_arm(who="part205")
    _p9_patch(_p9_sd, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_p9_sd, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch(_smc205, "run_command", lambda *a, **k: ("", "", 1))
    try:
        r = _p9_client(uid).get("/server/%d" % P9_GS)
        return r.status_code, r.get_data(as_text=True)
    finally:
        _p9_restore_all()


_p9_set(P9_GS, commands=_json205.dumps([{"cmd": "update-lgsm", "desc": "Check and apply any LinuxGSM updates."},
                                        {"cmd": "details", "desc": "Display server information."}]))
_pg205, _pg_v205 = _page205(P9_ADMIN), _page205(P9_VIEWER)
check("server page: the available note is a button that opens what's new",
      _pg205[0] == 200 and 'id="lgsm-behind-btn"' in _pg205[1] and 'data-action="showLgsmUpdate"' in _pg205[1]
      and "js/lgsm_update.js" in _pg205[1], repr(_pg205[0]))
check("server page: 'Update LinuxGSM' is offered to whom the Maintenance menu offers update-lgsm",
      'id="lgsm-behind" class="text-warning d-none" data-can-update="1"' in _pg205[1]
      and _pg_v205[0] == 200 and 'data-can-update="0"' in _pg_v205[1], repr(_pg_v205[0]))


def _read205(*parts):
    with open(_os205.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


_js205 = _read205("panel", "static", "js", "lgsm_update.js")
_sa205 = _read205("panel", "static", "js", "server_actions.js")
_code205 = "\n".join(ln.split("//")[0] for ln in _js205.splitlines())
check("lgsm_update.js: nothing from the release notes reaches markup (no innerHTML or insertAdjacentHTML)",
      "innerHTML" not in _code205 and "insertAdjacentHTML" not in _code205 and "textContent" in _code205)
check("lgsm_update.js: links open GitHub's release pages only, with rel=noopener",
      "a.rel = 'noopener noreferrer';" in _code205 and "url.indexOf(RELEASES) === 0" in _code205)
check("lgsm_update.js: the dialog scrolls inside and stays on screen",
      "max-height:85vh" in _code205 and "overflow-y:auto" in _code205)
check("lgsm_update.js: 'Update LinuxGSM' runs update-lgsm through the control bar's action",
      "_doServerAction('update-lgsm', btn, true)" in _code205
      and "getAttribute('data-can-update') === '1'" in _code205)
check("server_actions.js: an update-lgsm reply goes to the what's-new dialog",
      "if (d.lgsm && typeof window.lgsmUpdateResult === 'function') { window.lgsmUpdateResult(d); return; }"
      in _sa205)
check("part205: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP205_START, repr(_P9_TRIPPED[_TRIP205_START:]))
