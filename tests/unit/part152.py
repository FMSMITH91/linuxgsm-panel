"""Part 152 of the unit suite: the install page's game icons, and the scheduled Rust wipe.

Icons (panel/services/game_icons.py, /game-icon/<script>): the panel fetches LinuxGSM's icons
itself, so the browser only loads images from the panel. Held here: only a LinuxGSM script name the
serverlist knows is looked up (a traversal or an unknown name reads nothing), only https
linuxgsm.com uploads are fetched, and only a real PNG/JPEG/WEBP is kept or served — SVG and other
bytes are refused. No check reaches the network: the one fetch function is stood in for.

Wipes (panel/services/wipe_schedule.py, panel/routes/wipe_schedule.py): the schedule maths, how a
wipe's output is judged, and the sweep's order — a backup first, and NO wipe after a failed one.
"""
import datetime
import json
import os
import pathlib
import re as _re152
import tempfile

from unit.part01 import check
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_HOST, P9_VIEWER, _P9_TRIPPED, _p9, _p9_arm, _p9_audit,
                         _p9_client, _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm,
                         _p9_restore_all)
from unit.part75 import _cut_or75, _js75, _run_js75
from panel.ops.ssh_manager import _core as _smc152
from panel.routes import _shared as _sh152
from panel.security import privileged as _priv152
from panel.routes import wipe_schedule as _wr152
from panel.services import game_icons as _gi152
from panel.services import lgsm_data as _lgd152
from panel.services import lgsm_players as _lgp152
from panel.services import wipe_schedule as _ws152

_TRIP152_START = len(_P9_TRIPPED)
_PNG_cmpd = b"\x89PNG\r\n\x1a\n" + b"\0" * 64
_JPG_cmpd = b"\xff\xd8\xff\xe0" + b"\0" * 64
_WEBP_cmpd = b"RIFF\x10\0\0\0WEBPVP8 " + b"\0" * 64
_SVG_cmpd = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
_UP_cmpd = "https://linuxgsm.com/wp-content/uploads/2020/02/"
_INDEX_cmpd = (
    '<a href="https://linuxgsm.com/servers/rustserver/"><img src="https://cdn.example.test/h.jpg" '
    'class="card-img-top" alt="Rust"></a>\n'
    '<a href="https://linuxgsm.com/servers/rustserver/"><img alt="Rust" class="games" '
    'style="width:32px" src="' + _UP_cmpd + 'rust-icon.jpg" /></a>\n'
    '<a href="https://linuxgsm.com/servers/gmodserver/"><img alt="GMod" class="games" '
    'src="' + _UP_cmpd + 'gmod-icon.svg" /></a>\n'
    '<a href="https://linuxgsm.com/servers/tf2server/"><img alt="TF2" class="games" '
    'src="https://evil.example.test/wp-content/uploads/tf2.png" /></a>\n'
    '<a href="https://linuxgsm.com/servers/vhserver/"><img alt="Valheim" class="games" '
    'src="https://linuxgsm.com/wp-content/themes/linuxgsm/img/avatar.jpg" /></a>\n')

# ── sniffing and the URL allowlist ──────────────────────────────────────────────────────────────
check("icons: PNG, JPEG and WEBP are recognised by their first bytes",
      _gi152.sniff(_PNG_cmpd) == ("image/png", "png") and _gi152.sniff(_JPG_cmpd) == ("image/jpeg", "jpg")
      and _gi152.sniff(_WEBP_cmpd) == ("image/webp", "webp"))
check("icons: SVG, GIF, HTML and nothing at all are refused",
      _gi152.sniff(_SVG_cmpd) is None and _gi152.sniff(b"GIF89a" + b"\0" * 20) is None
      and _gi152.sniff(b"<!doctype html><html>") is None and _gi152.sniff(b"") is None)
check("icons: only https linuxgsm.com uploads are fetchable",
      _gi152._cmpd_allowed_url(_UP_cmpd + "a.png", uploads_only=True)
      and not _gi152._cmpd_allowed_url("http://linuxgsm.com/wp-content/uploads/a.png", uploads_only=True)
      and not _gi152._cmpd_allowed_url("https://linuxgsm.com.evil.example.test/wp-content/uploads/a.png")
      and not _gi152._cmpd_allowed_url("https://user@linuxgsm.com/wp-content/uploads/a.png")
      and not _gi152._cmpd_allowed_url(_UP_cmpd + "../../wp-config.php", uploads_only=True)
      and not _gi152._cmpd_allowed_url("https://linuxgsm.com/wp-admin/a.png", uploads_only=True))
_idx_cmpd = _gi152.parse_index(_INDEX_cmpd)
check("icons: the servers page maps each script to its small linuxgsm.com icon, nothing else",
      _idx_cmpd == {"rustserver": _UP_cmpd + "rust-icon.jpg", "gmodserver": _UP_cmpd + "gmod-icon.svg"},
      repr(_idx_cmpd))

# ── icon(): what it reads, fetches, keeps and serves ────────────────────────────────────────────
_gets_cmpd = []
_answers_cmpd = {}


def _get_cmpd(url, cap):
    _gets_cmpd.append(url)
    return _answers_cmpd.get(url, (None, None, "no stand-in"))


_saved_gi_cmpd = (_gi152._CACHE_DIR, _gi152._cmpd_http_get, dict(_gi152._state), dict(_gi152._failed))
_tmp_cmpd = pathlib.Path(tempfile.mkdtemp(prefix="lgsm-unit-p152-"))
_KNOWN_cmpd = {"rustserver", "gmodserver", "vhserver"}
try:
    # Armed: the closing "nothing reached a real transport" check reads only what an armed tripwire
    # records, and this part never armed it (review 1109 T11).
    _p9_arm(who="part152")
    _gi152._CACHE_DIR = _tmp_cmpd
    _gi152._cmpd_http_get = _get_cmpd
    _gi152._state.update(index=None, index_at=0.0, index_failed_until=0.0)
    _gi152._failed.clear()
    _answers_cmpd[_gi152.INDEX_URL] = (_INDEX_cmpd.encode(), "text/html", None)
    _answers_cmpd[_UP_cmpd + "rust-icon.jpg"] = (_JPG_cmpd, "image/jpeg", None)
    _answers_cmpd[_UP_cmpd + "gmod-icon.svg"] = (_SVG_cmpd, "image/svg+xml", None)

    _gets_cmpd.clear()
    _trav_cmpd = [_gi152.icon(n, _KNOWN_cmpd | {n}) for n in
                  ("../../etc/passwd", "rust/../../x", "RUSTSERVER", "rustserver\n", "a" * 40 + "server")]
    check("icons: a traversal or malformed name is refused before any read or fetch",
          _trav_cmpd == [None] * 5 and not _gets_cmpd, repr((_trav_cmpd, _gets_cmpd)))
    check("icons: a well-formed name LinuxGSM does not list is refused, and nothing is fetched",
          _gi152.icon("nosuchserver", _KNOWN_cmpd) is None and not _gets_cmpd, repr(_gets_cmpd))

    _rust_cmpd = _gi152.icon("rustserver", _KNOWN_cmpd)
    check("icons: a listed game's JPEG is fetched from the index's URL and served as image/jpeg",
          _rust_cmpd == (_JPG_cmpd, "image/jpeg")
          and _gets_cmpd == [_gi152.INDEX_URL, _UP_cmpd + "rust-icon.jpg"], repr((_rust_cmpd, _gets_cmpd)))
    _gets_cmpd.clear()
    check("icons: a second ask is served from the cache under data/, with no fetch",
          _gi152.icon("rustserver", _KNOWN_cmpd) == (_JPG_cmpd, "image/jpeg") and not _gets_cmpd
          and (_tmp_cmpd / "rustserver.jpg").read_bytes() == _JPG_cmpd, repr(_gets_cmpd))

    check("icons: an SVG answer is refused and never written",
          _gi152.icon("gmodserver", _KNOWN_cmpd) is None
          and not any(p.name.startswith("gmodserver") for p in _tmp_cmpd.iterdir()))
    _gets_cmpd.clear()
    check("icons: a refused icon is not fetched again on the next ask (it backs off)",
          _gi152.icon("gmodserver", _KNOWN_cmpd) is None and not _gets_cmpd, repr(_gets_cmpd))

    # Non-image bytes that CLAIM to be a PNG; and a real PNG behind a wrong Content-Type.
    _gi152._failed.clear()
    _answers_cmpd[_UP_cmpd + "gmod-icon.svg"] = (b"<html>not an image</html>", "image/png", None)
    _lie_cmpd = _gi152.icon("gmodserver", _KNOWN_cmpd)
    _gi152._failed.clear()
    _answers_cmpd[_UP_cmpd + "gmod-icon.svg"] = (_PNG_cmpd, "text/html", None)
    _ctype_cmpd = _gi152.icon("gmodserver", _KNOWN_cmpd)
    check("icons: bytes that are not an image are refused whatever Content-Type says, and a picture "
          "served as text/html is refused too",
          _lie_cmpd is None and _ctype_cmpd is None
          and not any(p.name.startswith("gmodserver") for p in _tmp_cmpd.iterdir()))
    (_tmp_cmpd / "vhserver.png").write_bytes(_SVG_cmpd)
    check("icons: a cached file that is not a real image is never served (re-sniffed on read)",
          _gi152.icon("vhserver", _KNOWN_cmpd) is None)
    # A saved index is read back through the same allowlist: a hand-edited or stale file cannot
    # point a fetch at another host or path, nor carry a name that is not a script name.
    (_tmp_cmpd / "index.json").write_text(json.dumps({"at": 1.0, "icons": {
        "rustserver": "https://cdn.example.test/rust.png", "../etc": _UP_cmpd + "x.png",
        "vhserver": "https://linuxgsm.com/servers/vh.png", "gmodserver": _UP_cmpd + "gmod.png"}}))
    _saved_ix_cmpd = _gi152._cmpd_saved_index()
    check("icons: a saved index keeps only script names whose icon URL is a linuxgsm.com upload",
          _saved_ix_cmpd == ({"gmodserver": _UP_cmpd + "gmod.png"}, 1.0), repr(_saved_ix_cmpd))

    # ── the route ──
    _p9_patch(_lgd152, "serverlist", lambda allow_fetch=True: [
        {"shortname": "rust", "gameservername": "rustserver", "gamename": "Rust"}])
    _A_cmpd = _p9_client(P9_ADMIN)
    _ok_cmpd = _A_cmpd.get("/game-icon/rustserver")
    _bad_cmpd = [_A_cmpd.get(u).status_code for u in
                 ("/game-icon/..%2F..%2Fetc%2Fpasswd", "/game-icon/gmodserver", "/game-icon/x.svg")]
    _view_cmpd = _p9_client(P9_VIEWER).get("/game-icon/rustserver").status_code
    _anon_cmpd = _p9.test_client().get("/game-icon/rustserver").status_code
finally:
    _p9_restore_all()
    _gi152._CACHE_DIR, _gi152._cmpd_http_get = _saved_gi_cmpd[0], _saved_gi_cmpd[1]
    _gi152._state.clear()
    _gi152._state.update(_saved_gi_cmpd[2])
    _gi152._failed.clear()
    _gi152._failed.update(_saved_gi_cmpd[3])
check("icon route: a listed game's icon comes from the panel's origin, nosniff, as its real type",
      _ok_cmpd.status_code == 200 and _ok_cmpd.headers.get("Content-Type") == "image/jpeg"
      and _ok_cmpd.headers.get("X-Content-Type-Options") == "nosniff" and _ok_cmpd.data == _JPG_cmpd,
      repr((_ok_cmpd.status_code, dict(_ok_cmpd.headers))))
check("icon route: traversal, an unlisted game and an SVG name are each a 404", _bad_cmpd == [404] * 3,
      repr(_bad_cmpd))
check("icon route: needs the install page's permission, and a login",
      _view_cmpd in (302, 403) and _anon_cmpd in (302, 401), repr((_view_cmpd, _anon_cmpd)))

with open(os.path.join(_root, "panel", "templates", "install_server.html"), encoding="utf-8") as _fh_cmpd:
    _tpl_cmpd = _fh_cmpd.read()
check("install page: every tile's picture is the panel's own route (no other image origin; the script "
      "builds /game-icon/<script> from data-icon-script, checked below)",
      'data-icon-script="{{ g.shortname }}server"' in _tpl_cmpd
      and 'src="http' not in _tpl_cmpd and "src='http" not in _tpl_cmpd)


# ── the wipe schedule: cron maths ───────────────────────────────────────────────────────────────
def _utc_cmpd(*a):
    return datetime.datetime(*a, tzinfo=datetime.timezone.utc).timestamp()


_ft_cmpd, _line_cmpd = _ws152.spec_for("first-thursday", "19:00", "")
_wk_cmpd, _ = _ws152.spec_for("weekly-thursday", "07:30", "")
check("wipe: the first-Thursday preset is the 1st-7th AND a Thursday",
      _line_cmpd == "0 19 1-7 * 4"
      and _ws152.next_after(_ft_cmpd, _utc_cmpd(2026, 11, 1), "UTC") == _utc_cmpd(2026, 11, 5, 19)
      and _ws152.next_after(_ft_cmpd, _utc_cmpd(2026, 11, 5, 19), "UTC") == _utc_cmpd(2026, 12, 3, 19))
check("wipe: every Thursday at 07:30, in the viewer's own zone",
      _ws152.next_after(_wk_cmpd, _utc_cmpd(2026, 11, 6), "UTC") == _utc_cmpd(2026, 11, 12, 7, 30)
      and _ws152.next_after(_wk_cmpd, _utc_cmpd(2026, 11, 6), "America/New_York")
      == _utc_cmpd(2026, 11, 12, 12, 30))
_or_cmpd = _ws152.parse_cron("0 0 1 * 1")
check("wipe: a custom cron with day-of-month AND weekday fires on either (as cron does)",
      _ws152.next_after(_or_cmpd, _utc_cmpd(2026, 11, 3), "UTC") == _utc_cmpd(2026, 11, 9))
check("wipe: a line that is not a 5-field cron schedule is refused",
      all(_ws152.parse_cron(x) is None for x in
          ("@monthly", "0 19 * *", "60 * * * *", "0 24 * * *", "* * 0 * *", "*/0 * * * *", "0 0 5-1 * *",
           "0 0 * * 4; rm -rf ~", ""))
      and _ws152.spec_for("custom", "", "bogus")[0] is None
      and _ws152.spec_for("weekly-thursday", "25:00", "")[0] is None)

# ── judging a wipe's output ─────────────────────────────────────────────────────────────────────
_OK_cmpd = ("[ WARN ] Wiping rustserver: Server wipe will reset the map data\n"
            "removing .map file(s)... OK\nSuccess! Full wipe\n")
check("wipe: LinuxGSM's success line with exit 0 is a wipe", _ws152.judge(_OK_cmpd, 0, "full-wipe")[0] == "wiped")
check("wipe: 'Wipe not required' is a run with nothing to delete, not a failure",
      _ws152.judge("[  OK  ] Wiping rustserver: Wipe not required\n", 0, "wipe")[0] == "nothing")
check("wipe: LinuxGSM's players-online refusal is 'refused', and nothing was wiped",
      _ws152.judge("[ INFO ] Stopping rustserver: 3 players are on the server: stop prevented\n", 0,
                   "wipe")[0] == "refused")
# A non-zero exit WITH the success line (and no FAIL before it) is a wipe: LinuxGSM prints that line
# only once the files are gone, and a start that fails after it exits 1 (part160, review 1108).
check("wipe: a FAIL, a non-zero exit, or an exit 0 with no success line is a failure",
      _ws152.judge("removing .db file(s)... FAIL\nSuccess! Full wipe\n", 0, "full-wipe")[0] == "failed"
      and _ws152.judge("[ WARN ] Wiping rustserver: Server wipe will reset the map data\n", 1,
                       "full-wipe")[0] == "failed"
      and _ws152.judge("", 0, "wipe")[0] == "failed")


# ── the sweep: backup first, never a wipe after a failed backup ─────────────────────────────────
def _run_cmpd(backup, wipe_out=(_OK_cmpd, "", 0), kind="full", pending=True, wait_empty=True, **opts):
    """One sweep over a fresh Rust server whose wipe is due; returns (backups, commands run, entry).

    opts: `now` (the sweep's time), `extra` (fields over the stored entry), `holds` (a reboot holds it).
    """
    sid = _p9_new_server(P9_HOST, "rustserver", "rust", 28015, name="p152-rust")
    backups, cmds = [], []
    try:
        with _p9.app_context():
            from panel.db.models import GameServer, db
            gs = db.session.get(GameServer, sid)
            entry = dict(_ws152.identity(gs), kind=kind, preset="custom", at="", cron="0 19 * * 4",
                         tz="UTC", wait_empty=wait_empty, anchor=_utc_cmpd(2026, 11, 1),
                         pending_since=0, backed_up=0, tried=0, wait="")
        entry.update(opts.get("extra") or {})
        _ws152.put(sid, entry)
        _p9_arm(who="part152")
        _p9_patch(_sh152, "_marked_backup",
                  lambda *a, **k: (backups.append((a[2], k.get("force"))), backup)[1])
        _p9_patch(_sh152, "_alert_backup", lambda *a, **k: None)
        _p9_patch(_sh152, "_reboot_holds", lambda gs: bool(opts.get("holds")))
        _p9_patch(_lgp152, "timeout_for", lambda *a, **k: 900)
        _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: (cmds.append(action), wipe_out)[1])
        now = opts.get("now") or (_utc_cmpd(2026, 11, 5, 19, 1) if pending else _utc_cmpd(2026, 11, 2))
        _wr152.sweep(_p9, now=now)
        return backups, cmds, _ws152.get(sid)
    finally:
        _p9_restore_all()
        _ws152.put(sid, None)
        _p9_delete_server(sid)


_bk_fail_cmpd = _run_cmpd((False, "not enough disk space", False))
_aud_fail_cmpd = _p9_audit("wipe_server")
check("wipe sweep: a FAILED backup blocks the wipe — LinuxGSM's wipe is never run",
      len(_bk_fail_cmpd[0]) == 1 and _bk_fail_cmpd[1] == [], repr(_bk_fail_cmpd[:2]))
check("wipe sweep: ...and that is audited as a failure, naming the backup",
      _aud_fail_cmpd.success is False and "backup before it failed" in _aud_fail_cmpd.detail
      and "not enough disk space" in _aud_fail_cmpd.detail, repr(_aud_fail_cmpd))
check("wipe sweep: ...and the wipe is no longer pending (not retried until its next time)",
      _bk_fail_cmpd[2] and not _bk_fail_cmpd[2].get("pending_since")
      and _bk_fail_cmpd[2]["last"]["ok"] is False, repr(_bk_fail_cmpd[2]))

_bk_ok_cmpd = _run_cmpd((True, "Backed up", False))
_aud_ok_cmpd = _p9_audit("wipe_server")
check("wipe sweep: a good backup, then LinuxGSM's full-wipe as the game account",
      _bk_ok_cmpd[0] == [("rustserver", False)] and _bk_ok_cmpd[1] == ["full-wipe"],
      repr(_bk_ok_cmpd[:2]))
check("wipe sweep: a wipe that worked is audited as a success and leaves nothing pending",
      _aud_ok_cmpd.success is True and "Full wipe done" in _aud_ok_cmpd.detail
      and not _bk_ok_cmpd[2].get("pending_since"), repr((_aud_ok_cmpd, _bk_ok_cmpd[2])))

_bk_busy_cmpd = _run_cmpd((False, "2 player(s) online", True), kind="map")
check("wipe sweep: players online at backup time — no wipe, still pending, with the reason",
      _bk_busy_cmpd[1] == [] and _bk_busy_cmpd[2].get("pending_since")
      and "player" in _bk_busy_cmpd[2].get("wait", ""), repr(_bk_busy_cmpd))
_forced_cmpd = _run_cmpd((True, "", False), kind="map", wait_empty=False)
check("wipe sweep: with 'wait until empty' off the backup is forced, then the map wipe runs",
      _forced_cmpd[0][0][1] is True and _forced_cmpd[1] == ["wipe"], repr(_forced_cmpd[:2]))
_refused_cmpd = _run_cmpd((True, "", False),
                          wipe_out=("[ INFO ] Stopping rustserver: 1 players are on the server: stop prevented", "", 0))
check("wipe sweep: LinuxGSM refusing (players on) keeps it pending, the backup already counted",
      _refused_cmpd[2].get("pending_since") and _refused_cmpd[2].get("backed_up"), repr(_refused_cmpd[2]))
_notdue_cmpd = _run_cmpd((True, "", False), pending=False)
check("wipe sweep: before its time nothing is backed up or wiped",
      _notdue_cmpd[0] == [] and _notdue_cmpd[1] == [], repr(_notdue_cmpd[:2]))

# A schedule left behind by a deleted server whose id a NEW server took: dropped, never run.
_sid_cmpd = _p9_new_server(P9_HOST, "rustserver", "rust", 28015, name="p152-heir")
_stale_cmds_cmpd = []
try:
    _ws152.put(_sid_cmpd, {"short_name": "rustserver", "remote_id": P9_HOST, "born": "2001-01-01 00:00:00",
                           "kind": "full", "preset": "custom", "cron": "* * * * *", "tz": "UTC",
                           "anchor": 0, "pending_since": 1})
    _p9_arm(who="part152")
    _p9_patch(_sh152, "_marked_backup", lambda *a, **k: (_stale_cmds_cmpd.append("backup"), (True, "", False))[1])
    _p9_patch_sm("run_as_game_user", lambda *a, **k: (_stale_cmds_cmpd.append("wipe"), ("", "", 0))[1])
    _wr152.sweep(_p9)
    _stale_left_cmpd = _ws152.get(_sid_cmpd)
finally:
    _p9_restore_all()
    _ws152.put(_sid_cmpd, None)
    _p9_delete_server(_sid_cmpd)
check("wipe sweep: another server's schedule under a reused id is dropped and never run",
      _stale_cmds_cmpd == [] and _stale_left_cmpd is None, repr((_stale_cmds_cmpd, _stale_left_cmpd)))

# Thursday 5 November 2026, 19:00 UTC, seven hours late: past GRACE_SECONDS, so skipped, not run late.
_late_now_cmpd = _utc_cmpd(2026, 11, 6, 2)
_late_cmpd = _run_cmpd((True, "", False), pending=False, now=_late_now_cmpd)
_aud_late_cmpd = _p9_audit("wipe_server")
check("wipe sweep: a wipe the panel missed by more than the grace time is skipped and audited, not run late",
      _late_cmpd[0] == [] and _late_cmpd[1] == [] and _late_cmpd[2].get("anchor") == _late_now_cmpd
      and not _late_cmpd[2].get("pending_since") and _aud_late_cmpd.success is False
      and _aud_late_cmpd.target == "p152-rust" and _aud_late_cmpd.detail.startswith("skipped: it was due"),
      repr((_late_cmpd, _aud_late_cmpd)))
_held_cmpd = _run_cmpd((True, "", False), holds=True)
check("wipe sweep: while a host reboot holds the server nothing is backed up or wiped; it stays pending",
      _held_cmpd[0] == [] and _held_cmpd[1] == [] and _held_cmpd[2].get("pending_since")
      and "reboot" in _held_cmpd[2].get("wait", ""), repr(_held_cmpd))
_gaveup_cmpd = _run_cmpd((True, "", False), extra={
    "pending_since": _utc_cmpd(2026, 11, 5, 19, 1) - _ws152.MAX_WAIT_SECONDS - 60,
    "wait": "2 player(s) online"})
check("wipe sweep: a wipe still waiting after MAX_WAIT_SECONDS gives up, unwiped, saying why",
      _gaveup_cmpd[0] == [] and _gaveup_cmpd[1] == [] and not _gaveup_cmpd[2].get("pending_since")
      and _gaveup_cmpd[2]["last"]["ok"] is False and "still waiting" in _gaveup_cmpd[2]["last"]["detail"]
      and "2 player(s) online" in _gaveup_cmpd[2]["last"]["detail"], repr(_gaveup_cmpd))

with open(os.path.join(_root, "tools", "panel-helper"), encoding="utf-8") as _fh_cmpd:
    _helper_cmpd = _fh_cmpd.read()
check("wipe: wipe and full-wipe are LinuxGSM commands the panel and its helper may run as the game account",
      {"wipe", "full-wipe"} <= set(_priv152.LGSM_ACTIONS)
      and {"wipe", "full-wipe"} <= set(_smc152.SCOPED_LGSM_ACTIONS)
      and _helper_cmpd.count('"wipe", "full-wipe"') == 2, repr(_priv152.LGSM_ACTIONS))

# ── the route ───────────────────────────────────────────────────────────────────────────────────
_rsid_cmpd = _p9_new_server(P9_HOST, "rustserver", "rust", 28015, name="p152-route")
_csid_cmpd = _p9_new_server(P9_HOST, "csgoserver", "csgo", 27099, name="p152-cs")
try:
    _p9_arm(who="part152")
    _A2_cmpd = _p9_client(P9_ADMIN)
    _url_cmpd = "/api/server/%d/wipe-schedule" % _rsid_cmpd
    _set_cmpd = _A2_cmpd.post(_url_cmpd, json={"enabled": True, "kind": "full", "preset": "first-thursday",
                                               "at": "19:00", "tz": "Europe/London", "wait_empty": True})
    _aud_set_cmpd = _p9_audit("wipe_schedule_server")
    _got_cmpd = _A2_cmpd.get(_url_cmpd).get_json()
    _bad_set_cmpd = [_A2_cmpd.post(_url_cmpd, json=b).status_code for b in (
        {"enabled": "yes"}, {"enabled": True, "kind": "nuke", "preset": "custom", "cron": "* * * * *"},
        {"enabled": True, "kind": "map", "preset": "custom", "cron": "@reboot"},
        {"enabled": True, "kind": "map", "preset": "first-thursday", "at": "19:00", "wait_empty": "no"})]
    _cs_cmpd = _A2_cmpd.post("/api/server/%d/wipe-schedule" % _csid_cmpd,
                             json={"enabled": True, "kind": "map", "preset": "first-thursday", "at": "19:00"})
    _viewer_cmpd = _p9_client(P9_VIEWER).post(_url_cmpd, json={"enabled": False}).status_code
    _off_cmpd = _A2_cmpd.post(_url_cmpd, json={"enabled": False}).get_json()
finally:
    _p9_restore_all()
    _ws152.put(_rsid_cmpd, None)
    _p9_delete_server(_rsid_cmpd)
    _p9_delete_server(_csid_cmpd)
check("wipe route: a Rust server's schedule is stored, audited, and read back with its next run",
      _set_cmpd.status_code == 200 and _got_cmpd.get("enabled") and _got_cmpd.get("kind") == "full"
      and _got_cmpd.get("cron") == "0 19 1-7 * 4" and _got_cmpd.get("tz") == "Europe/London"
      and isinstance(_got_cmpd.get("next"), float) and _aud_set_cmpd.success is True,
      repr((_set_cmpd.status_code, _got_cmpd, _aud_set_cmpd)))
check("wipe route: a non-boolean switch, an unknown kind, a bad cron and a bad flag are each a 400",
      _bad_set_cmpd == [400] * 4, repr(_bad_set_cmpd))
check("wipe route: a game LinuxGSM has no wipe for is refused",
      _cs_cmpd.status_code == 400, repr((_cs_cmpd.status_code, _cs_cmpd.get_json())))
check("wipe route: an account without the Scheduled Tasks permission cannot change it",
      _viewer_cmpd in (302, 403), repr(_viewer_cmpd))
check("wipe route: turning it off removes the schedule", _off_cmpd.get("enabled") is False, repr(_off_cmpd))

with open(os.path.join(_root, "panel", "static", "js", "wipe_schedule.js"), encoding="utf-8") as _fh_cmpd:
    _wjs_cmpd = _fh_cmpd.read()
_SETTLE_cmpd = "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
# The card's own script, driven: Save opens the red dialog and posts NOTHING until it is confirmed.
_name_wjs_cmpd = "wipe card: Save confirms before it posts"
_wout_cmpd = _run_js75(_name_wjs_cmpd, (
    _SETTLE_cmpd + "global.window = global; global.MOUNT = ''; global.serverId = 7; global.t = s => s;\n"
    "const els = {}; const mk = id => (els[id] = els[id] || {id, value: '', hidden: false, checked: true,\n"
    "  textContent: '', className: ''});\n"
    "global.document = {getElementById: mk, addEventListener: () => 0};\n"
    "const posts = [], dialogs = [];\n"
    "global.fetch = (u, o) => { posts.push([u, o && o.method, o && JSON.parse(o.body)]);\n"
    "  return Promise.resolve({ok: true, json: () => Promise.resolve({success: true, enabled: true})}); };\n"
    "window.confirmDialog = o => dialogs.push(o);\n"
    + _wjs_cmpd + "\n"
    "(async () => { mk('wipe-kind').value = 'full'; mk('wipe-preset').value = 'first-thursday';\n"
    "  mk('wipe-at').value = '19:00'; let prevented = false;\n"
    "  window.saveWipeSchedule({preventDefault: () => { prevented = true; }}); await settle();\n"
    "  const before = posts.length, d = dialogs[0] || {};\n"
    "  if (d.onConfirm) d.onConfirm(); await settle();\n"
    "  console.log(JSON.stringify({prevented, before, dialogs: dialogs.length, cls: d.confirmClass,\n"
    "    title: d.title, posts})); })();\n"))
if _wout_cmpd is not None:
    _wp_cmpd = (_wout_cmpd.get("posts") or [[None, None, {}]])[0]
    check("wipe card: Save opens a red confirm dialog and posts nothing until it is confirmed; then the "
          "full wipe is posted",
          _wout_cmpd.get("prevented") is True and _wout_cmpd.get("before") == 0 and _wout_cmpd.get("dialogs") == 1
          and _wout_cmpd.get("cls") == "btn-danger" and _wout_cmpd.get("title") == "Schedule a full wipe?"
          and len(_wout_cmpd.get("posts") or []) == 1 and _wp_cmpd[0] == "/api/server/7/wipe-schedule"
          and _wp_cmpd[1] == "POST" and _wp_cmpd[2].get("kind") == "full" and _wp_cmpd[2].get("enabled") is True,
          repr(_wout_cmpd))

# The install page's tiles: the search, the select they mirror, and a click that sets it.
_MS_cmpd = _js75("manage_servers.js")
_name_tiles_cmpd = "install page: game tiles search, mirror and set the select"
_tout_cmpd = _run_js75(_name_tiles_cmpd, (
    "global.window = global;\n"
    "function tile(game, search) { const a = {'data-game': game, 'data-search': search};\n"
    "  return {game, hidden: false, disabled: false, getAttribute: k => (k in a ? a[k] : null),\n"
    "    setAttribute: (k, v) => { a[k] = String(v); }, pressed: () => a['aria-pressed']}; }\n"
    "const tiles = [tile('rust', 'rust rustserver'), tile('gmod', \"garry's mod gmodserver\"),\n"
    "  tile('mohaa', 'medal of honor: allied assault mohaaserver')];\n"
    "const events = [], none = {hidden: true};\n"
    "const sel = {value: '', options: [{value: 'rust', disabled: false}, {value: 'mohaa', disabled: true}],\n"
    "  dispatchEvent: e => events.push([e.type, e.bubbles])};\n"
    "global.document = {querySelectorAll: () => tiles,\n"
    "  getElementById: id => ({'game-type-select': sel, 'game-search-none': none})[id] || null};\n"
    + "".join(_cut_or75(_MS_cmpd, "function %s(" % _f) + "\n"
              for _f in ("filterGameTiles", "syncGameTiles", "pickGameTile"))
    + "const shown = () => tiles.filter(x => !x.hidden).map(x => x.game);\n"
    "filterGameTiles({value: 'GMODserv'}); const one = shown();\n"
    "filterGameTiles({value: 'allied medal'}); const two = shown();\n"
    "filterGameTiles({value: 'zzz'}); const zero = [shown(), none.hidden];\n"
    "filterGameTiles({value: ''}); const all = [shown(), none.hidden];\n"
    "syncGameTiles(); const dis = tiles.map(x => x.disabled);\n"
    "tiles[2].disabled = true; pickGameTile(tiles[2]); const afterOff = [sel.value, events.length];\n"
    "pickGameTile(tiles[0]);\n"
    "console.log(JSON.stringify({one, two, zero, all, dis, afterOff, val: sel.value, events,\n"
    "  pressed: tiles.map(x => x.pressed())}));\n"))
if _tout_cmpd is not None:
    check("install page: the search keeps the tiles whose name or script holds every word typed, and says "
          "when none does",
          _tout_cmpd.get("one") == ["gmod"] and _tout_cmpd.get("two") == ["mohaa"]
          and _tout_cmpd.get("zero") == [[], False] and _tout_cmpd.get("all") == [["rust", "gmod", "mohaa"], True],
          repr(_tout_cmpd))
    check("install page: a tile mirrors the select (a game the host cannot install, or not offered, is "
          "disabled), and a click sets the select and fires its change; a disabled tile does nothing",
          _tout_cmpd.get("dis") == [False, True, True] and _tout_cmpd.get("afterOff") == ["", 0]
          and _tout_cmpd.get("val") == "rust" and _tout_cmpd.get("events") == [["change", True]]
          and _tout_cmpd.get("pressed") == ["true", "false", "false"], repr(_tout_cmpd))
# The icons wait for the page's load event, and then load only for the tiles the grid's own scroll
# box shows. Given their URLs in the markup, Chrome's lazy-load distance fetched most of the grid at
# once; and loaded all at once after load, the hundred-odd icon requests (each a linuxgsm.com fetch,
# one at a time, until the panel caches it) were most of the page's requests, so Lighthouse's
# simulator took their ~1 s as this host's response time and put the first paint at 4.5 s. The
# tile's <img> names its script in data-icon-script only, and the script builds the URL (escaped:
# CodeQL's js/xss-through-dom, #487).
_tile_img_cmpd = _re152.search(r'<img [^>]*data-icon-script[^>]*>', _tpl_cmpd)
check("install page: a tile names its icon's script in data-icon-script, so the markup itself fetches "
      "no icon",
      _tile_img_cmpd is not None
      and 'data-icon-script="{{ g.shortname }}server"' in _tile_img_cmpd.group(0)
      and not _re152.search(r'\ssrc=', _tile_img_cmpd.group(0)), _tile_img_cmpd and _tile_img_cmpd.group(0))
check("install page: the URL the script builds is the icon route's own (/game-icon/<script>)",
      "MOUNT + '/game-icon/' + encodeURIComponent(" in _MS_cmpd
      and '"GET /game-icon/<script>"' in open(os.path.join(_root, "tests", "url_map_baseline.json"),
                                               encoding="utf-8").read(), "")
_wire_at_cmpd = _MS_cmpd.find("if (document.readyState === 'complete') startGameIcons();")
_wire_cmpd = (_MS_cmpd[_wire_at_cmpd:_MS_cmpd.find("\n", _MS_cmpd.find("\n", _wire_at_cmpd) + 1)]
              if _wire_at_cmpd >= 0 else "/* MISSING the load wiring */")
_name_icons_cmpd = ("install page: the icons start on the page's load event, not before, and then "
                    "only for the tiles the grid's scroll box shows, at the mount's /game-icon/ URL "
                    "with the script name escaped")
_iout_cmpd = _run_js75(_name_icons_cmpd, (
    "global.window = global; const on = {}; global.MOUNT = '/p';\n"
    "window.addEventListener = (ev, fn) => { on[ev] = fn; };\n"
    "function img(u) { const a = {'data-icon-script': u};\n"
    "  return {src: '', getAttribute: k => (k in a ? a[k] : null), removeAttribute: k => { delete a[k]; },\n"
    "    has: () => 'data-icon-script' in a}; }\n"
    "const imgs = [img('rustserver'), img('../x\"><b')];\n"
    "const grid = {querySelectorAll: () => imgs.filter(i => i.has())};\n"
    "global.document = {readyState: 'loading', getElementById: id => (id === 'game-grid' ? grid : null)};\n"
    "const io = {seen: [], dropped: []};\n"
    "global.IntersectionObserver = function (cb, opts) { io.cb = cb; io.opts = opts;\n"
    "  this.observe = el => io.seen.push(el); this.unobserve = el => io.dropped.push(el); };\n"
    + "var _r37d_iconWatch = null;\n"   # the module's one observer (manage_servers.js, part157)
    + _cut_or75(_MS_cmpd, "function _loadGameIcon(") + "\n"
    + _cut_or75(_MS_cmpd, "function startGameIcons(") + "\n" + _wire_cmpd + "\n"
    "const src = () => imgs.map(i => i.src);\n"
    "const before = src();\n"
    "if (on.load) on.load();\n"
    "const atLoad = src();\n"
    "if (io.cb) io.cb([{target: imgs[0], isIntersecting: true}, {target: imgs[1], isIntersecting: false}]);\n"
    "const inView = src();\n"
    "if (io.cb) io.cb([{target: imgs[1], isIntersecting: true}]);\n"
    "console.log(JSON.stringify({before, atLoad, inView, after: src(), left: imgs.map(i => i.has()),\n"
    "  waited: typeof on.load, root: !!io.opts && io.opts.root === grid, observed: io.seen.length,\n"
    "  dropped: io.dropped.map(d => imgs.indexOf(d))}));\n"))
if _iout_cmpd is not None:
    check(_name_icons_cmpd,
          _iout_cmpd.get("before") == ["", ""] and _iout_cmpd.get("waited") == "function"
          and _iout_cmpd.get("atLoad") == ["", ""] and _iout_cmpd.get("root") is True
          and _iout_cmpd.get("observed") == 2
          and _iout_cmpd.get("inView") == ["/p/game-icon/rustserver", ""]
          and _iout_cmpd.get("after") == ["/p/game-icon/rustserver", "/p/game-icon/..%2Fx%22%3E%3Cb"]
          and _iout_cmpd.get("left") == [False, False] and _iout_cmpd.get("dropped") == [0, 1],
          repr(_iout_cmpd))
check("part152: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP152_START, repr(_P9_TRIPPED[_TRIP152_START:]))
