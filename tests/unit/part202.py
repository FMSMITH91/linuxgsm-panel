"""Part 202 of the unit suite: a game's secrets masked out of every console view and the chat bots' tail.

Project Zomboid starts as `-servername <name> -adminpassword <password>` (LinuxGSM's pzserver
startparameters) and echoes that into its console log, which anyone holding VIEW_CONSOLE was shown.
Held here, each through its caller, against a console log on disk read by bash:

* the poller's push (_console_tick), /api/console's window and its read from a place, the catch-up
  on return (_serve_console_catchups), the panel's own console lines and their replay
  (_console_push, `panel_lines`), and the chat bots' /console tail (_console_text);
* the stitching: the push and the window show the same line as the same text, and the stream goes
  on with only what is new;
* one config read per cache period, never one per line; a failed read keeps the flag pattern;
* which settings count as secrets (LinuxGSM's own list, the names, the secrets files);
* the flag pattern on long hostile lines: linear time.

Every value here is invented.
"""
import base64 as _b64_202
import json as _json202
import os as _os202
import shutil as _shutil202
import subprocess as _sp202  # nosec B404 - bash on this part's own console log
import tempfile as _tf202
import time as _time202
from types import SimpleNamespace as NS

from panel.core import panel_state as _ps202
from panel.db.models import GameServer as _GameServer202, db as _db202
from panel.routes import _shared as _sh202
from panel.routes import server_files as _sf202
from panel.services import console_secrets as _cs202
from panel.services.bots import commands as _bc202
from unit.part01 import check, eq
from unit.part12 import (P9_GS, P9_VIEWER, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch,
                         _p9_patch_sm, _p9_restore_all)

_TRIP202 = len(_P9_TRIPPED)
_ADMIN202 = "Zq7PfixtureAdmin"
_STEAM202 = "Fixture5Steam"
_KEPT202 = "Fixture9Kept"
_UNREAD202 = "OtherUnread42"          # in no config: only the flag pattern can mask it
_SECRETS202 = (_ADMIN202, _STEAM202, _KEPT202, _UNREAD202)
_M202 = _cs202.MASK
# _default.cfg, common.cfg, secrets-common.cfg, <instance>.cfg, secrets-<instance>.cfg (_core.LGSM_CFG_ORDER).
_CFG202 = [
    'adminpassword="CHANGE_ME"\nstartparameters="-servername ${selfname} -adminpassword ${adminpassword}"\n',
    'steampass="%s"\nmaxplayers="16"\n' % _STEAM202,
    '',
    'adminpassword="%s"\nrconpassword="${adminpassword}"\nservername="Fixture Island"\n' % _ADMIN202,
    'customkey="%s"\nab="xy"\n' % _KEPT202,
]
_LOG202 = [
    "Starting: ./start-server.sh -servername pzserver -adminpassword %s -port 16261" % _ADMIN202,
    "Admin account created with %s" % _ADMIN202,
    "steamcmd +login fixtureuser %s" % _STEAM202,
    "-adminpassword %s" % _UNREAD202,
    "kept %s here" % _KEPT202,
    "Server name is Fixture Island, 16 slots",
]
_SHOWN202 = [
    "Starting: ./start-server.sh -servername pzserver -adminpassword %s -port 16261" % _M202,
    "Admin account created with %s" % _M202,
    "steamcmd +login fixtureuser %s" % _M202,
    "-adminpassword %s" % _M202,
    "kept %s here" % _M202,
    "Server name is Fixture Island, 16 slots",
]


def _frames202(texts):
    """lgsm_cfg_texts' reply: each file base64'd between its W<n> frame."""
    return "".join("__LGSMP_W%d_B__%s__LGSMP_W%d_E__" % (i, _b64_202.b64encode(t.encode()).decode(), i)
                   for i, t in enumerate(texts))


def _leaks202(text):
    """The invented secrets that appear in `text`."""
    return [s for s in _SECRETS202 if s in text]


class _Host202:
    """read_as_game_user against this part's files: the config read answered, the console log read by bash."""

    def __init__(self, log):
        self.log, self.real, self.cfg_reads, self.cfg_fail = log, None, 0, False

    def __call__(self, server, user, sh, timeout=30, selfname=None):
        if "__LGSMP_W0_B__" in sh:
            self.cfg_reads += 1
            return ("", "SSH command timed out", -1) if self.cfg_fail else (_frames202(_CFG202), "", 0)
        if self.real:
            sh = sh.replace(self.real, self.log)
        p = _sp202.run(["bash", "-c", sh],  # nosec B603 B607 - bash on this part's own command
                       capture_output=True, text=True, timeout=30, check=False)
        return p.stdout, p.stderr, p.returncode


class _Sio202:
    def __init__(self):
        self.sent = []

    def emit(self, event, data=None, **kw):
        self.sent.append((event, data, kw))


def _write202(path, lines, mode="w"):
    with open(path, mode, encoding="utf-8", newline="") as fh:
        fh.write("".join(ln + "\n" for ln in lines))


# ── which settings are secrets ───────────────────────────────────────────────────────────────────
eq("console secrets: the values masked are LinuxGSM's own masked settings (adminpassword, CHANGE_ME included), a "
   "setting named like a secret (steampass) and every setting in a secrets file; not a ${reference}, a short "
   "value or an ordinary setting", _cs202.secret_values(_CFG202), {"CHANGE_ME", _ADMIN202, _STEAM202, _KEPT202})
eq("console secrets: LinuxGSM v26.6.0's fn_info_messages_password_strip list, all fourteen",
   sorted(_cs202.LGSM_MASKED_KEYS),
   sorted(["serverpassword", "rconpassword", "adminpassword", "statspassword", "httppassword", "telnetpassword",
           "wsapikey", "gslt", "betapassword", "authtoken", "usertoken", "apikey", "gspassword", "eosclientsecret"]))
eq("console secrets: the cache period and the retry after a failed read", (_cs202._TTL, _cs202._RETRY), (120.0, 30.0))

# ── the flag and key forms ───────────────────────────────────────────────────────────────────────
_FORMS202 = (
    ("-adminpassword abc123 -port 1", "-adminpassword %s -port 1" % _M202),
    ('+rcon_password "my pw" +map x', "+rcon_password %s +map x" % _M202),
    ("+sv_setsteamaccount ABCDEF0123", "+sv_setsteamaccount %s" % _M202),
    ("-gslt=QQQ1", "-gslt=%s" % _M202),
    ("TheIsland?listen?ServerPassword=foo?ServerAdminPassword=bar",
     "TheIsland?listen?ServerPassword=%s?ServerAdminPassword=%s" % (_M202, _M202)),
    ("rcon.password=xyz9", "rcon.password=%s" % _M202),
    ("Server password: hunter9", "Server password: %s" % _M202),
    ("\x1b[32m-adminpassword\x1b[0m zzz9", "\x1b[32m-adminpassword\x1b[0m %s" % _M202),
    # Not secrets: no `=`/`:` after a plain word, a switch, an empty flag followed by the next one.
    ("Password protected: false", "Password protected: false"),
    ("Server password: NOT SET", "Server password: NOT SET"),
    ("-password -port 27015", "-password -port 27015"),
    ("Your password has changed", "Your password has changed"),
)
for _in202, _want202 in _FORMS202:
    eq("console secrets: the flag/key form %r" % _in202, _cs202.mask_text(_in202), _want202)

# ── ReDoS: long hostile lines cost linear time ───────────────────────────────────────────────────
_HOSTILE202 = ["-" * 524288, "a" * 524288, "-a " * 174762, "password" * 65536, "?password=" * 52428,
               "-password\x1b[0m" * 40329, "\x1b[1m" * 131072, "-adminpassword " * 34952, "m" * 524288]
_t0202 = _time202.perf_counter()
_out202 = [_cs202.mask_text(h) for h in _HOSTILE202]
_took202 = _time202.perf_counter() - _t0202
check("console secrets: nine 512 KB hostile lines (dashes, one word, flags with no value, colour codes) are masked "
      "in linear time: all of them in under 5 s (measured about 0.3 s)", _took202 < 5.0, "%.2f s" % _took202)
check("console secrets: ...and a run of flags with no value masks each flag's next flag as nothing",
      _out202[7] == _HOSTILE202[7], _out202[7][:80])

_TMP202 = _tf202.mkdtemp(prefix="lgsm-unit-p202-")
_log202 = _os202.path.join(_TMP202, "pzserver-console.log")
_host202 = _Host202(_log202)
_SID202 = -20201
_gs202 = NS(id=_SID202, console_log=_log202, remote=NS(timezone=""), short_name="pz202", lgsm_name="pzserver")
try:
    _p9_arm(who="part202")
    _p9_patch(_sf202, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch_sm("read_as_game_user", _host202)
    for _k202 in (_SID202, P9_GS):
        _cs202.forget(_k202)
        _sf202._console_offsets.pop(_k202, None)
        _sf202._console_partial.pop(_k202, None)
        _ps202._console_backlog.pop(_k202, None)

    # ── the poller's push ───────────────────────────────────────────────────────────────────────
    _sio202 = _Sio202()
    _write202(_log202, ["boot line"])
    _sf202._console_tick(_p9, _sio202, _gs202, _SID202)          # first sight: the end, nothing read
    _write202(_log202, _LOG202, "a")
    _sf202._console_tick(_p9, _sio202, _gs202, _SID202)
    _push202 = [d for e, d, _k in _sio202.sent if e == "console_output"]
    _pdata202 = _push202[0]["data"] if _push202 else ""
    _prows202 = [r["line"] for r in _push202[0]["rows"]] if _push202 else []
    eq("console secrets: the poller pushes the pz start line and every secret masked, the rest as written",
       _pdata202.split("\n"), _SHOWN202)
    eq("console secrets: ...and the push's rows are the same masked lines", _prows202, _SHOWN202)
    eq("console secrets: ...with ONE config read for that push of six lines", _host202.cfg_reads, 1)

    # The stream goes on: the next tick pushes only the new line, and reads no config (cached).
    _write202(_log202, ["player joined: -adminpassword %s" % _ADMIN202], "a")
    _sf202._console_tick(_p9, _sio202, _gs202, _SID202)
    _push202 = [d for e, d, _k in _sio202.sent if e == "console_output"]
    eq("console secrets: the console keeps streaming, the next tick pushes only its new line, masked",
       [p["data"] for p in _push202[1:]], ["player joined: -adminpassword %s" % _M202])
    eq("console secrets: ...and the cached values cost no further config read", _host202.cfg_reads, 1)

    # ── the catch-up on return ──────────────────────────────────────────────────────────────────
    with _sf202._viewers_lock:
        _sf202._console_viewers[_SID202] = {"sock202": P9_VIEWER}
        _sf202._console_catchups[_SID202] = {"sock202": {"id": 7, "since": None, "tries": 0}}
    _sio202.sent.clear()
    _sf202._serve_console_catchups(_p9, _sio202, _gs202, _SID202)
    _cu202 = [d for e, d, _k in _sio202.sent if e == "console_catchup"]
    _culines202 = [r["line"] for r in _cu202[0]["lines"]] if _cu202 else []
    eq("console secrets: the catch-up on return shows the log's lines masked as the push showed them",
       _culines202, ["boot line"] + _SHOWN202 + ["player joined: -adminpassword %s" % _M202])
    check("console secrets: ...and no secret in the catch-up's answer", _cu202 and not _leaks202(_json202.dumps(_cu202)),
          repr(_leaks202(_json202.dumps(_cu202))))

    # ── the panel's own console lines ───────────────────────────────────────────────────────────
    _panel202 = []
    _p9_patch(_p9.socketio, "emit", lambda event, data=None, **k: _panel202.append((event, data, k)))
    _sh202._console_push(_p9, _SID202, "[panel] update: steamcmd +login u %s -adminpassword %s"
                         % (_STEAM202, _UNREAD202))
    _pl202 = _panel202[0][1]["data"] if _panel202 else ""
    eq("console secrets: a panel console line is pushed masked (the cached value and the flag)", _pl202,
       "[panel] update: steamcmd +login u %s -adminpassword %s" % (_M202, _M202))
    eq("console secrets: ...and kept masked in the backlog a reload replays",
       [e["line"] for e in _ps202._console_backlog.get(_SID202, [])], [_pl202])
finally:
    with _sf202._viewers_lock:
        _sf202._console_viewers.pop(_SID202, None)
        _sf202._console_catchups.pop(_SID202, None)
    _p9_restore_all()

# ── /api/console, its read from a place, panel_lines and the chat bots, on a real server row ─────
_host202.cfg_reads = 0
try:
    _p9_arm(who="part202")
    _p9_patch(_sf202, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch_sm("read_as_game_user", _host202)
    _p9_patch(_p9.socketio, "emit", lambda event, data=None, **k: None)
    with _p9.app_context():
        _host202.real = _db202.session.get(_GameServer202, P9_GS).console_log
    _write202(_log202, _LOG202)
    _V202 = _p9_client(P9_VIEWER)
    _r202 = _V202.get("/api/console/%d?lines=50" % P9_GS)
    _api202 = _p9_json(_r202)
    eq("console secrets: /api/console shows a VIEW_CONSOLE-only viewer the log masked, line for line as the poller "
       "pushed it (so the page's stitching still matches the two)",
       (_r202.status_code, [r["line"] for r in _api202.get("lines", [])]), (200, _SHOWN202))
    check("console secrets: ...and no secret anywhere in its answer", not _leaks202(_r202.get_data(as_text=True)),
          repr(_leaks202(_r202.get_data(as_text=True))))
    _r202 = _V202.get("/api/console/%d?place=1" % P9_GS)
    eq("console secrets: /api/console's read from a place (socket down) shows the same masked lines",
       (_r202.status_code, [r["line"] for r in _p9_json(_r202).get("lines", [])]), (200, _SHOWN202))
    eq("console secrets: ...both reads of this server took one config read between them", _host202.cfg_reads, 1)
    _sh202._console_push(_p9, P9_GS, "[panel] start: -adminpassword %s" % _ADMIN202)
    _r202 = _V202.get("/api/console/%d?lines=50" % P9_GS)
    eq("console secrets: the panel lines /api/console replays are masked",
       [e["line"] for e in _p9_json(_r202).get("panel_lines", [])][-1:], ["[panel] start: -adminpassword %s" % _M202])

    # The chat bots' /console and !console tail (one function for both).
    _p9_patch_sm("capture_console", lambda *a, **k: ("\n".join(_LOG202), "", 0))
    _bot202 = _bc202._console_text(_p9, "p9-cs", lines=20)
    check("console secrets: the chat bots' console tail masks the pz start line and every secret",
          all(s in _bot202 for s in _SHOWN202) and not _leaks202(_bot202), _bot202[-400:])

    # A config read that fails: the flag pattern still masks, the value is tried again after _RETRY.
    _cs202.forget(P9_GS)
    _host202.cfg_fail, _host202.cfg_reads = True, 0
    with _p9.app_context():
        _row202 = _db202.session.get(_GameServer202, P9_GS)
        _first202 = _cs202.mask_for(_row202, _LOG202[0])
        _cs202.forget(P9_GS)
        _cs202.refresh(_row202, now=1000.0)
        _cs202.refresh(_row202, now=1000.0 + 29)
        _early202 = _host202.cfg_reads
        _cs202.refresh(_row202, now=1000.0 + 31)
        _late202 = _host202.cfg_reads
        _host202.cfg_fail = False
        _cs202.forget(P9_GS)
        _host202.cfg_reads = 0
        _cs202.refresh(_row202, now=2000.0)
        _cs202.refresh(_row202, now=2000.0 + 119)
        _ttl_early202 = _host202.cfg_reads
        _cs202.refresh(_row202, now=2000.0 + 121)
        _ttl_late202 = _host202.cfg_reads
    eq("console secrets: with the config unreadable the pz start line is still masked by its flag", _first202,
       _SHOWN202[0])
    eq("console secrets: a failed config read is tried again after 30 s, not before", (_early202, _late202), (2, 3))
    eq("console secrets: a good read is trusted for 120 s, then read again", (_ttl_early202, _ttl_late202), (1, 2))
finally:
    _cs202.forget(P9_GS)
    _cs202.forget(_SID202)
    _ps202._console_backlog.pop(P9_GS, None)
    _ps202._console_backlog.pop(_SID202, None)
    _sf202._console_offsets.pop(_SID202, None)
    _sf202._console_partial.pop(_SID202, None)
    _p9_restore_all()
    _shutil202.rmtree(_TMP202, ignore_errors=True)

check("part202: nothing reached a real transport", len(_P9_TRIPPED) == _TRIP202, repr(_P9_TRIPPED[_TRIP202:]))
