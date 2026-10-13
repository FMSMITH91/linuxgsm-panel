"""Part 70 of the unit suite: review 1012b's core, backup, ssh-core and reboot fixes (builder A).

Held here, each against the code path the finding named:

* config.json's cookie_secure is an on/off setting like the others: a quoted "false" is off (it
  reached Flask as a string, and `Secure=false` is still Secure), and 0.0 is off, not the default;
* Optimize database says VACUUM was deferred when it was, in the viewer's language;
* "Internal server error" and the tag-name rule read in the viewer's language;
* the update card's two `git rev-list` reads: a failed read is not "0 behind";
* a Tailscale IPv6 address is bracketed in a URL;
* the terminal's in-stream notices are in the language of the viewer who opened it;
* a leftover Serve route that could not be removed keeps remove_panel_route's own reason;
* a console line holding a control character is refused (^C stopped the game);
* a reboot plan row's one-hour give-up waits out a silent host in a rollback, and a LinuxGSM
  command in flight.

HOW IT RUNS. Pure functions and part12's Flask app and database, with every outside call stood in
for (part20's _patch / _patched, undone at the end of each block), and node on this part's own
fixtures. Nothing touches the network, sudo, a real host or the checkout's data/.
"""
import json as _json70
import os as _os70
import types as _types70

import flask as _flask70

import app as _app70
from unit.part01 import check, skip
from unit.part12 import P9_ADMIN, P9_GS, _P9_CFG_PATH, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_flashes
from unit.part20 import _patch, _patched
from unit.part47 import _SETTLE47, _cut47, _node47
from panel.core import config as _cfg70
from panel.core import http as _http70
from panel.core import i18n as _i18n70
from panel.db import models as _models70
from panel.ops import serve_upkeep as _su70
from panel.ops import system_ops as _so70
from panel.ops import tailscale_integration as _ts70
from panel.ops import terminal_session as _term70
from panel.ops.ssh_manager import _core as _smc70
from panel.ops.ssh_manager import hosts as _smh70
from panel.routes import server_detail as _sd70
from panel.routes import server_files as _sf70
from panel.security import privileged as _priv70
from panel.services import host_reboot as _hr70
from panel.services import reboot_words as _rw70

NS = _types70.SimpleNamespace
_ROOT70 = _os70.path.dirname(_os70.path.dirname(_os70.path.dirname(_os70.path.abspath(__file__))))


def _cat70(lang):
    out = {}
    folder = _os70.path.join(_ROOT70, "translations", lang)
    for name in sorted(_os70.listdir(folder)):
        if name.endswith(".json"):
            with open(_os70.path.join(folder, name), encoding="utf-8") as fh:
                out.update(_json70.load(fh))
    return out


_CAT70 = {lg: _cat70(lg) for lg in ("es", "fr")}
# The account's language as this part found it, put back after each block that switches it (it was
# reset to "en", so a later part reading the account saw this part's choice, not the earlier one's).
with _p9.app_context():
    _LANG70_WAS = _models70.db.session.get(_models70.User, P9_ADMIN).language
# part12's transport tripwire, armed at the top of each block below that drives a route (review
# 1012c: none was armed, so a route that gained a host call would run it for real with every check
# green); the part ends by checking nothing it drove reached one.
_TRIP70_START = len(_P9_TRIPPED)


def _as70(lang):
    """Set P9_ADMIN's saved language (the account's choice wins over the session's)."""
    with _p9.app_context():
        _models70.db.session.get(_models70.User, P9_ADMIN).language = lang
        _models70.db.session.commit()


def _tr70(lang, s):
    """i18n.tr(s) as a viewer whose session language is `lang` sees it."""
    with _p9.test_request_context("/"):
        _flask70.session["lang"] = lang
        return _i18n70.tr(s)


# ── A01: cookie_secure, and a 0.0 in an on/off setting ───────────────────────────────────────────
def _load70(body):
    snap = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None
    try:
        with open(_P9_CFG_PATH, "w", encoding="utf-8") as fh:
            _json70.dump(body, fh)
        return _cfg70.load_config()
    finally:
        if snap is None:
            _P9_CFG_PATH.unlink()
        else:
            _P9_CFG_PATH.write_bytes(snap)


_ck70 = _load70({"cookie_secure": "false", "use_https": 0.0, "trust_proxy": 1.0})
_ck2_70 = _load70({"cookie_secure": "maybe"})
_ck3_70 = _load70({"cookie_secure": "TRUE"})
check("config: a hand-edited \"cookie_secure\": \"false\" is off (the string reached Flask, Werkzeug wrote "
      "`Secure=false`, a browser treats any Secure as Secure, and a plain-HTTP panel looped to /login); "
      "\"TRUE\" is on, and a word it cannot read is dropped so the computed answer applies",
      _ck70.get("cookie_secure") is False and _ck3_70.get("cookie_secure") is True
      and "cookie_secure" not in _ck2_70, repr((_ck70.get("cookie_secure"), _ck2_70, _ck3_70.get("cookie_secure"))))
check("config: ...and 0.0 / 1.0 in an on/off setting are off / on (str(0.0) is \"0.0\", no word, so a "
      "hand-written 0.0 for use_https took the default: on)",
      _ck70.get("use_https") is False and _ck70.get("trust_proxy") is True, repr(_ck70))


# ── A01: Optimize database when VACUUM was deferred ──────────────────────────────────────────────
def _opt70(result, lang):
    try:
        _as70(lang)
        with _patched():
            _p9_arm(_patch, "part70")
            _patch(_models70, "_run_maintenance", lambda path: result)
            return _p9_client(P9_ADMIN).post("/api/panel/optimize-db", json={}).get_json() or {}
    finally:
        _as70(_LANG70_WAS)


_opt_busy70 = _opt70((False, False), "es")
_opt_ok70 = _opt70((True, True), "en")
_busy_es70 = _CAT70["es"].get("Refreshed stats, but the WAL could not be trimmed and VACUUM was deferred — "
                              "the database was busy. Run it again in a moment.")
check("optimize database: a deferred VACUUM is said in the answer (`vacuumed` false, the message in the "
      "viewer's language); a VACUUM that ran says so",
      _opt_busy70.get("success") is True and _opt_busy70.get("vacuumed") is False
      and bool(_busy_es70) and _opt_busy70.get("message") == _busy_es70
      and _opt_ok70.get("vacuumed") is True, repr((_opt_busy70, _opt_ok70)))

with open(_os70.path.join(_ROOT70, "static", "js", "remote_manage_host.js"), encoding="utf-8") as _fh70:
    _rmh70 = _fh70.read()


def _opt_page70(answer):
    """What optimizeDb() puts in #diag-db-msg for the route's `answer`."""
    return _node47(
        "const els = {'diag-optimize-btn': {}, 'diag-db-msg': {}};\n"
        "global.document = {getElementById: id => els[id] || null};\n"
        "const MOUNT = ''; const t = s => s; const escapeHtml = s => String(s);\n"
        "const tfHtml = (s, v) => s.replace('{size}', v.size); const fmtBytes = b => b + ' B';\n"
        "const loadDbStats = () => {};\n"
        "global.fetch = () => Promise.resolve({json: () => Promise.resolve(%s)});\n" % _json70.dumps(answer)
        + _SETTLE47 + _cut47(_rmh70, "function optimizeDb") + "\n"
        "(async () => { optimizeDb(); await settle(); console.log(JSON.stringify(els['diag-db-msg'].innerHTML)); })();")


_pg_busy70 = _opt_page70(_opt_busy70)
_pg_ok70 = _opt_page70(dict(_opt_ok70, freed=0))
if _pg_busy70 is None:
    skip("optimize database: the page shows a deferred VACUUM's message, not \"Optimized.\"", "no node")
else:
    check("optimize database: the page shows a deferred VACUUM's message, not \"Optimized.\" (it printed "
          "\"Optimized.\" on every success, whatever the message said); a VACUUM that ran still says "
          "\"Optimized.\"",
          isinstance(_pg_busy70, str) and _busy_es70 in _pg_busy70 and "Optimized" not in _pg_busy70
          and isinstance(_pg_ok70, str) and "Optimized." in _pg_ok70, repr((_pg_busy70, _pg_ok70)))


# ── A01: two fixed messages in the viewer's language ─────────────────────────────────────────────
with _p9.test_request_context("/"):
    _flask70.session["lang"] = "fr"
    _ise70 = _http70._log_and_generic("p70: an expected test exception")
try:
    _as70("es")
    with _patched():
        _p9_arm(_patch, "part70")
        _tag70 = _p9_client(P9_ADMIN).post("/api/tags", json={"name": "-p70"}).get_json() or {}
finally:
    _as70(_LANG70_WAS)
check("i18n: \"Internal server error\" (79 routes' generic failure) reads in the viewer's language",
      _ise70 == "Erreur interne du serveur", repr(_ise70))
check("i18n: ...and so does the tag-name rule a bad tag name is refused with",
      _tag70.get("success") is False and _tag70.get("message") == _CAT70["es"].get(_models70.TAG_NAME_HELP),
      repr(_tag70))


# ── A02: the update card's rev-list reads ────────────────────────────────────────────────────────
def _upd70(count, walk):
    """_compute_update_status with `git rev-list --count` answering `count` and the walk `walk`."""
    asked = []

    def _git(args, timeout=45):
        if args[:2] == ["rev-list", "--first-parent"] and "--count" in args:
            return count
        if args[:2] == ["rev-list", "--first-parent"]:
            return walk
        if args[:2] == ["rev-parse", "--short"]:
            return ("abc1234", "", 0)
        return ("", "", 0)
    with _patched():
        _patch(_so70, "_git", _git)
        _patch(_so70, "_is_git_checkout", lambda: True)
        _patch(_so70, "panel_version", lambda: "2026.10.1")
        _patch(_so70, "_tracked_branch", lambda: _so70._DEFAULT_BRANCH)
        _patch(_so70, "_remote_ci_state", lambda sha: asked.append(sha) or "unknown")
        _patch(_so70, "github_repo_url", lambda: "")
        return _so70._compute_update_status(), asked


_TIMEOUT70 = ("", "git timed out", -1)
_u_count70 = _upd70(_TIMEOUT70, ("a" * 40, "", 0))
_u_walk70 = _upd70(("3", "", 0), _TIMEOUT70)
_u_none70 = _upd70(("0", "", 0), _TIMEOUT70)
_UNREAD70 = "Couldn't read how far behind the update source this panel is."
check("self-update: a `rev-list --count` that fails is not \"0 behind\": no update, not fetched, and the "
      "Update button's answer says the count could not be read (it read as \"You're up to date\")",
      _u_count70[0].get("fetched") is False and _u_count70[0].get("update_available") is False
      and _u_count70[0].get("message") == _UNREAD70 and "behind" not in _u_count70[0], repr(_u_count70))
check("self-update: ...and a failed walk of the commits behind says so too, asking GitHub about none (it "
      "fell through to the silent up-to-date line with no reason); 0 behind is still up to date",
      _u_walk70[0].get("message") == _UNREAD70 and _u_walk70[0].get("update_available") is False
      and _u_walk70[1] == [] and _u_none70[0].get("behind") == 0 and _u_none70[0].get("fetched") is True,
      repr((_u_walk70, _u_none70)))


def _switch70():
    def _git(args, timeout=45):
        return _TIMEOUT70 if args[0] == "rev-list" else ("", "", 0)
    with _patched():
        _patch(_so70, "_git", _git)
        return _so70._verified_branch_target("main")


_sw70 = _switch70()
check("self-update: switching branch with a failed read of the branch's versions says it could not read "
      "them (it said none of them had passed their checks)",
      _sw70[0] == "" and _tr70("fr", _sw70[1]).startswith("Impossible de lire les versions de"), repr(_sw70))


# ── A02: an IPv6 Tailscale address in a URL ──────────────────────────────────────────────────────
_V6_70 = ":".join(["fd7a", "115c", "a1e0", "", "70"])
_V4_70 = ".".join(["100", "64", "0", "70"])
with _patched():
    _patch(_ts70, "get_tailscale_ip", lambda family=4: _V6_70)
    _sug6_70 = _ts70._tailnet_ip_suggestion(5000, "http")
    _patch(_ts70, "get_tailscale_ip", lambda family=4: _V4_70)
    _sug4_70 = _ts70._tailnet_ip_suggestion(5000, "http")
check("tailscale: a node with only an IPv6 tailnet address is suggested at http://[addr]:port (the URL "
      "had no brackets and no browser opens it); an IPv4 one is unchanged, and the bind is the bare address",
      _sug6_70["url"] == "http://[%s]:5000" % _V6_70 and _sug6_70["note_value"] == _sug6_70["url"]
      and _sug6_70["bind_host"] == _V6_70 and _sug4_70["url"] == "http://%s:5000" % _V4_70,
      repr((_sug6_70, _sug4_70)))
check("startup: the printed \"Open … in your browser\" address brackets an IPv6 bind",
      _app70._r17a_url_host("::") == "[::]" and _app70._r17a_url_host(_V4_70) == _V4_70
      and _app70._r17a_url_host("[::1]") == "[::1]", "")


# ── A02 lead: the terminal's in-stream notices ───────────────────────────────────────────────────
_said70 = []
with _p9.test_request_context("/"):
    _flask70.session["lang"] = "es"
    _ts_es70 = _term70.Session("p70", "p70", lambda sid, data: _said70.append(data), lambda *a: None)
    # Two sessions: once one is truncating, its own drop notice is held back with the output.
    _ts_es2_70 = _term70.Session("p70c", "p70c", lambda sid, data: _said70.append(data), lambda *a: None)
_ts_es70._emit("x" * (_term70._MAX_BYTES_PER_SEC + 1))
_ts_es2_70._report_dropped(5)
_ts_en70 = _term70.Session("p70b", "p70b", lambda sid, data: _said70.append(data), lambda *a: None)
_ts_en70._report_dropped(7)
check("terminal: the \"output truncated\" and \"input dropped\" notices are in the language of the viewer "
      "who opened the terminal (English in every language: the pump has no viewer); without one, English",
      len(_said70) == 3 and "salida truncada" in _said70[0] and "512 KB/s" in _said70[0]
      and "se descartaron 5 bytes" in _said70[1] and "7 bytes of input were dropped" in _said70[2],
      repr(_said70))


# ── A02 lead: a leftover Serve route that could not be removed keeps its own reason ──────────────
def _route_err70(off):
    with _patched():
        _patch(_ts70, "_fresh_panel_route", lambda route, port: {"url": "https://p70", "mount": "/p70"})
        _patch(_ts70, "serve_off_args", off)
        return _ts70.remove_panel_route({}, 5000)[1]


def _verb_err70(url, mount):
    raise _priv70.VerbError("p70")


_lo70 = {}
for _k70, _off70 in (("mount", _verb_err70), ("listener", lambda url, mount: None)):
    _err70 = _route_err70(_off70)
    with _patched():
        _patch(_ts70, "remove_stale_panel_routes", lambda port, mount, _e=_err70: ("failed", [], _e))
        _out70 = _su70._remove_serve_leftovers(5000, "/", "p70", lambda detail, ok: None)
    _lo70[_k70] = (_out70, _tr70("es", _su70._leftover_note(_out70)))
check("serve: a leftover route the boot could not remove for one of remove_panel_route's own reasons (an "
      "unnameable mount, an unreadable listener) records that reason, and the note says it in the viewer's "
      "language (both read \"(an unexpected error)\")",
      _lo70["mount"][0] == "failed:unnamed-mount" and _lo70["listener"][0] == "failed:listener-unread"
      and _CAT70["es"][_ts70.R17A_UNNAMED_MOUNT] in _lo70["mount"][1]
      and _CAT70["es"][_ts70.R17A_LISTENER_UNREAD] in _lo70["listener"][1], repr(_lo70))


# ── A03: a console line holding a control character ──────────────────────────────────────────────
_CTRL70 = ("\x03", "\x1a", "\x1c", "say a\nquit", "say\x7f", "say\ta", "\x1b[A")


def _send70(cmd):
    ran = []
    with _patched():
        _patch(_smc70, "shell_as_game_user", lambda s, u, inner, **k: ran.append(inner) or ("", "", 0))
        res = _smc70.send_console_command(None, "p70game", cmd, selfname="p70srv")
    return res, ran


_ctl70 = {c: _send70(c) for c in _CTRL70}
_plain70 = _send70("say héllo; it's \"ok\"")
check("console send: a line holding a control character (U+0003 is ^C to the game, U+001A ^Z, U+001C "
      "^\\, a newline a second line, DEL, a tab, an escape) is refused and nothing runs; ordinary text "
      "still sends",
      all(v == (_smc70.CONSOLE_CONTROL_REFUSED, []) for v in _ctl70.values())
      and _plain70[0] == ("", "", 0) and len(_plain70[1]) == 1, repr((_ctl70, _plain70)))

_sent70 = []
try:
    _as70("es")
    with _patched():
        _p9_arm(_patch, "part70")
        _patch(_sf70, "send_console_command", lambda *a, **k: _sent70.append(a) or ("", "", 0))
        _patch(_sd70, "send_console_command", lambda *a, **k: _sent70.append(a) or ("", "", 0))
        _c70 = _p9_client(P9_ADMIN)
        _api70 = _c70.post("/api/command/%d" % P9_GS, json={"command": "\x03"})
        _c70.post("/server/%d/command" % P9_GS, data={"command": "say a\x1aquit"})
        _form70 = _p9_flashes(_c70)
finally:
    _as70(_LANG70_WAS)
_CTRL_ES70 = _CAT70["es"].get("A console command can't contain control characters or line breaks.")
check("console send: both senders refuse a control character up front, in the viewer's language, and send "
      "nothing (the send's refusal would have read as \"Console (tmux) not accessible\")",
      _api70.status_code == 400 and (_api70.get_json() or {}).get("error") == _CTRL_ES70 and bool(_CTRL_ES70)
      and _form70 == [_CTRL_ES70] and _sent70 == [], repr((_api70.status_code, _api70.get_json(), _form70, _sent70)))


# ── A05: the one-hour give-up of a reboot plan row ───────────────────────────────────────────────
def _rollback70(answers):
    """restore_host over one rollback row whose step never resolves; the host answers per `answers`."""
    gs = NS(id=-70, lgsm_name="p70srv", short_name="p70", name="p70")
    d = {"restore": "pending", "owner": "none", "stop": "stopped", "act": "now"}
    finished = []
    with _patched():
        _patch(_hr70, "_records", lambda rows: [(gs, d)])
        _patch(_hr70, "_act_one", lambda remote, g, row, now, rb: None)
        _patch(_hr70, "_set_rr", lambda g, row: None)
        _patch(_hr70, "_finish", lambda remote, recs, now, rb: finished.append(now))
        with _p9.app_context():
            for now, ident in answers:
                _patch(_smh70, "host_boot_identity", lambda r, _i=ident: _i)
                _hr70.restore_host(NS(id=-70), [gs], now)
    return d, finished


_IDENT70 = {"mid": "p70", "boot": "p70"}
_silent70 = _rollback70([(1000, _IDENT70), (1100, None), (1000 + 7200, None), (1000 + 7300, _IDENT70)])
_answer70 = _rollback70([(1000, _IDENT70), (1000 + 3600, _IDENT70)])
check("reboot: a rollback whose host goes silent for over an hour keeps its rows pending, and the hour "
      "starts again when it answers (every row was reported failed and the plan cleared, so the "
      "monitor's locks stayed aside); a host that answers still gives up after an hour, saying the "
      "reboot was called off",
      _silent70[0]["restore"] == "pending" and _silent70[1] == []
      and _silent70[0].get("pending_since") == 1000 + 7300
      and _answer70[0]["restore"] == "failed" and "called off" in _answer70[0]["result"]
      and _answer70[1] == [4600], repr((_silent70, _answer70)))


def _held70(detail, times):
    """_act over one panel-owned row whose start waits with `detail`, at each `now`."""
    gs = NS(id=-71, lgsm_name="p70srv", short_name="p70", name="p70")
    d = {"restore": "pending", "owner": "panel", "stop": "stopped"}
    with _patched():
        _patch(_hr70, "safe_start", lambda remote, g: ("wait", detail))
        _patch(_hr70, "_scope_ready", lambda remote, row, now: True)
        _patch(_hr70, "_set_rr", lambda g, row: None)
        _patch(_hr70, "_finish", lambda remote, recs, now, rb: None)
        with _p9.app_context():
            for now in times:
                _hr70._act(NS(id=-71), [(gs, d)], now, False)
    return d


_inflight70 = _held70("inflight", [1000, 1000 + 3700, 1000 + 7400])
_noanswer70 = _held70("the host did not answer", [1000, 1000 + 3700])
check("reboot: a start held because a LinuxGSM update or backup is running for the server stays pending "
      "past the hour (it was reported failed after an hour, and never started) until the day's give-up "
      "(part73); one whose host does not answer still gives up after an hour",
      _inflight70["restore"] == "pending" and _noanswer70["restore"] == "failed"
      and "called off" not in _noanswer70["result"], repr((_inflight70, _noanswer70)))
_rw_es70 = _rw70.row_gave_up({"pending_since": 0}, 3600, True)
check("reboot: ...and the rollback's give-up reason does not claim a reboot happened",
      _rw_es70[0] == "failed" and "called off" in _rw_es70[1], repr(_rw_es70))


# ── A05 lead: the reboot dialog names the panel's own work in the viewer's language ──────────────
with _patched():
    _patch(_so70, "_update_in_progress", lambda: True)
    _pb70 = _hr70._panel_host_blockers()
with open(_os70.path.join(_ROOT70, "static", "js", "nags.js"), encoding="utf-8") as _fh70:
    _nags70 = _fh70.read()
_DOM70 = ("function El(tag){ this.tag = tag; this.attrs = {}; this.children = []; }\n"
          "El.prototype.setAttribute = function(k, v){ this.attrs[k] = v; };\n"
          "El.prototype.appendChild = function(c){ this.children.push(c); return c; };\n"
          "El.prototype.replaceChild = function(n, o){ this.children[this.children.indexOf(o)] = n; return o; };\n"
          "Object.defineProperty(El.prototype, 'firstChild', {get(){ return this.children[0]; }});\n"
          "global.document = {createElement: t => new El(t), createTextNode: t => ({text: t})};\n")
_bl70 = _node47(_DOM70 + "\n".join(_cut47(_nags70, h) for h in (
    "function _rbEl", "function _rbName", "function _rbRow", "function _rbBlockersList"))
    + "\nconst ul = _rbBlockersList({blockers: %s});\n" % _json70.dumps(
        [dict(b, name=str(b["name"])) for b in _pb70] + [{"kind": "backup", "name": "p70-srv"}])
    + "console.log(JSON.stringify(ul.children.map(li => [li.children[0].textContent, "
      "'data-no-i18n' in li.children[0].attrs])));")
if _bl70 is None:
    skip("reboot dialog: the panel's own blocker is a translatable phrase", "no node")
else:
    check("reboot dialog: a blocker that is the panel's own work (an update, a restore, a full backup) is "
          "named by the phrase \"the panel\", left to the page's translator (it was a name marked "
          "data-no-i18n, English in every language); a server's name stays untranslated",
          [b.get("panel") for b in _pb70] == [True]
          and _bl70 == [["the panel", False], ["p70-srv", True]], repr((_pb70, _bl70)))

check("part70: nothing its routes drove reached a real transport (part12's tripwire, armed in each)",
      len(_P9_TRIPPED) == _TRIP70_START, repr(_P9_TRIPPED[_TRIP70_START:][:6]))
