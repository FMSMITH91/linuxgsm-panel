"""Part 248 of the unit suite: server actions, the console and backups.

1. LinuxGSM's output is read in time linear in its length: the players-online, update-busy, wipe,
   backup-failure and not-installed lines, the `details` secret labels, the debug report's key=value
   scrub and the release notes' links. A line of one tag (or key word) repeated with no phrase after
   it took time growing with its square (the key=value scrub with its cube); judged on growth.
2. The port check before a Start or a not-online Restart: when the game port is listening and a process
   of the server's own game account runs (its stored status is stale), a Restart goes ahead and a Start
   says the server may already be up (still offering Start anyway); otherwise as before.
3. A port saved BACK to the stored one while a Start runs (clearing pending_port): the stored port still
   follows the port the game bound, and the save waits for the next start.
4. The sign-in paths: the file browser refuses ~/.bash_aliases, ~/.bashrc.d and ~/.k5users too, and a
   restore (of an uploaded archive as well) keeps every sign-in path as the account has it, never the
   archive's copy (run by bash on part190's stand-in home).
5. Writes refused while the server is being restored (its files replaced, its crontab set aside and put
   back): the daily restart, LinuxGSM log timestamps off, GMod content apply and remove, and the two
   silent cron writes (the restart check's re-type, newly gained maintenance commands).
6. A resting console (console_rest) is read on the pass that answers a page's catch-up, as the poller
   runs the two: serve the catch-ups, then the tick.
7. A backup's database dump runs only once the backup goes ahead: not for one skipped for players online
   (the hourly ticker's, the queued sweep's and the wipe's path, and "Back up now"), and before the
   archive when it does go ahead.
8. A reboot of the panel's own host waits while a game server is being restored (the panel process runs
   the restore, on any host): blocked with the restore named, through the no-host-row reboot route too.
9. A panel backup restore reads the archive's shape header by header before anything unpacks it, for a
   decrypted archive as for a plain one: a member declaring more than the free disk space, a name that
   is not one of the four, or a fifth member is refused there.

HOW IT RUNS. Every caller is called in-process on invented text; the one that reads a host has its
game-account shell stubbed. Nothing reaches a host or data/.
"""
import gzip as _gz248
import os as _os248
import pathlib as _pl248
import shutil as _shutil248
import sys
import tarfile as _tf248
import tempfile as _tmp248
import time as _time248
from types import SimpleNamespace as _NS248

from unit.part01 import check, eq, skip
from unit.part12 import (_P9_TRIPPED, P9_ADMIN, P9_HOST, _P9Thread, _p9, _p9_arm, _p9_client, _p9_delete_server,
                         _p9_drain, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all, _p9_row, _p9_set,
                         _p9_threading)
from unit.part187 import _r42m_growth, _r42m_grows_linearly
from unit.part190 import _U190, _UNDO190, _Sb190, _crafted190, _missing190
from panel.core.panel_state import _console_offsets as _offsets248, r36j_route_job as _job248
from panel.db.models import _NO_BIRTH as _NO_BIRTH248, GameServer as _GS248, db as _db248
from panel.ops import backup as _bk248, system_ops as _so248
from panel.ops.ssh_manager import files as _files248, game as _game248
from panel.routes import _shared as _sh248, console_rest as _crest248, server_detail as _sd248
from panel.routes import databases as _dbr248, game_restore as _grr248, panel_backup as _pbk248
from panel.routes import server_files as _sf248
from panel.services import host_reboot as _hr248
from unit.part110 import _Unread110
from panel.services import game_restore as _grs248
from panel.services import lgsm_players as _lgp248, lgsm_releases as _rel248, wipe_schedule as _wipe248

_app248 = sys.modules["app"]

# ── 1. linear reads of LinuxGSM's output ─────────────────────────────────────────────────────────
_R30_HOST = _NS248(id=248, display_name="this host", name="local", is_local=True, auth_method="local")
_r30_shell_out = {"text": ""}


def _r30_installed_call(text):
    """A callable running _looks_installed over `details` output `text` -> its verdict."""
    def call():
        _r30_shell_out["text"] = text
        return _sh248._looks_installed(_app248, _R30_HOST, "r30game", "rustserver")
    return call


def _r30_call(fn, text):
    """A callable running fn(text)."""
    return lambda: fn(text)


# Each: (what, the caller over a text, the repeated unit, its size, the answer a real line still gets).
_R30_REAL_STOP = "[ INFO ] Stopping rustserver: 3 players are on the server: stop prevented\n"
_R30_CASES = (
    ("a stop's players-online line", lambda t: _lgp248.outcome(t + "\n" + _R30_REAL_STOP, "stop"), "[ INFO ] ", 4000,
     {"code": "lgsm_refused", "kind": "stop", "players": 3}),
    ("an update's busy line", lambda t: _lgp248.outcome(t + "\n[ INFO ] Updating rustserver: Checking update: "
                                                        "Update is already running (PID 1)", "update"),
     "[ INFO ] ", 4000, {"code": "lgsm_busy", "kind": "update"}),
    ("a wipe's not-required line", lambda t: _wipe248.judge(t + "\n[  OK  ] Wipe not required\n", 0, "full-wipe")[0],
     "[ OK ] ", 4000, "nothing"),
    ("a wipe's start and unstopped lines", lambda t: _wipe248.judge(
        t.replace("[ OK ] ", "[ START ] ") + "\n" + t.replace("[ OK ] ", "[ FAIL ] ") + "\n[ START ] Full wipe\n"
        "Success! Full wipe complete\n", 0, "full-wipe")[0], "[ OK ] ", 3000, "wiped"),
    ("a backup's in-progress FAIL", lambda t: _game248._bkverify_text_failed(t + "\nBackup in progress ... FAIL", ""),
     "in progress ", 4000, True),
    ("the not-installed check", lambda t: _r30_installed_call(t + "\nserverfiles missing")(),
     "serverfiles ", 4000, False),
    ("details' secret labels", lambda t: _sd248._dtl_mask_labelled(t + "\nRCON password: s3cr3t-r30\n")[1],
     "password ", 4000, {"s3cr3t-r30"}),
    ("the debug report's key=value scrub", lambda t: "s3cr3t-r30" in _so248._redact(t + " token=s3cr3t-r30"),
     "password-", 100, False),
    ("a release note's links", lambda t: _rel248.plain("[the notes](https://example.invalid/n) " + t)[:9],
     "[", 8000, "the notes"),
)
_r30_grow = {}
_p9_patch_sm("shell_as_game_user", lambda *a, **k: (_r30_shell_out["text"], "", 0))
try:
    for _r30_what, _r30_fn, _r30_unit, _r30_n, _r30_want in _R30_CASES:
        _r30_grow[_r30_what] = (_r42m_growth(lambda k, _f=_r30_fn, _u=_r30_unit: _r30_call(_f, _u * k), _r30_n),
                                _r30_want)
finally:
    _p9_restore_all()
for _r30_what, (_r30_got, _r30_want) in _r30_grow.items():
    check("lgsm output r30: %s over a line of its tag (or key word) repeated is read in time that grows linearly "
          "with it (4x the line, under 8x the time), and the real line after it still gives its answer" % _r30_what,
          _r42m_grows_linearly(_r30_got) and _r30_got[2] == (_r30_want, _r30_want),
          "x%.1f %.3fs %r" % _r30_got)
eq("lgsm output r30: the players-online line still reads with other tags before it on the same line",
   _lgp248.outcome("[ INFO ] a [ INFO ] Stopping x: 12 players are on the server: restart postponed", "restart"),
   {"code": "lgsm_postponed", "kind": "restart", "players": 12})
eq("lgsm output r30: the key=value scrub still keeps a hyphen-led key and masks only its value",
   _so248._redact("--db-password=hunter2r30 next"), "--db-password=[redacted] next")


# ── 2. the port check when the server's own account runs ─────────────────────────────────────────
_pc_sid248 = _p9_new_server(P9_HOST, "p248pc", "csgo", 42480, name="p248-pc", status="offline")
_pc248 = {"bg": [], "metrics": None, "reads": 0}


def _pc_metrics248(remote, user, port):
    _pc248["reads"] += 1
    return _pc248["metrics"]


def _pc_act248(client, action, metrics):
    """POST the action endpoint with the game port listening -> (json, background actions started, metrics reads)."""
    _pc248["metrics"] = metrics
    n_bg, n_rd = len(_pc248["bg"]), _pc248["reads"]
    r = client.post("/api/server/%d/action" % _pc_sid248, json={"action": action})
    return r.get_json(silent=True) or {}, len(_pc248["bg"]) - n_bg, _pc248["reads"] - n_rd


_PC_UP248 = {"ram_total": 1, "game_procs": 3}
_PC_DOWN248 = {"ram_total": 1, "game_procs": 0}
_PC_UNREAD248 = {"ram_total": 0, "game_procs": 0}
try:
    _p9_arm(who="part248")
    _pc_trips248 = len(_P9_TRIPPED)
    _p9_patch_sm("_remote_listening_ports", lambda remote: {42480, 22})
    _p9_patch_sm("server_live_metrics", _pc_metrics248)
    _p9_patch(_sd248, "_bg_power_action", lambda app, gs, remote, action, actor, **k: _pc248["bg"].append(action))
    _p9_patch(_sd248, "_live_run_state", lambda gs, remote: None)
    _pc_c248 = _p9_client(P9_ADMIN)
    _pc248["restart_up"] = _pc_act248(_pc_c248, "restart", _PC_UP248)
    _pc248["start_up"] = _pc_act248(_pc_c248, "start", _PC_UP248)
    _pc248["restart_down"] = _pc_act248(_pc_c248, "restart", _PC_DOWN248)
    _pc248["restart_unread"] = _pc_act248(_pc_c248, "restart", _PC_UNREAD248)
    _pc248["restart_raises"] = _pc_act248(_pc_c248, "restart", None)
    _pc248["trips"] = _P9_TRIPPED[_pc_trips248:]
finally:
    _p9_restore_all()
    _p9_delete_server(_pc_sid248)
_PC_BUSY248 = "Port 42480 is already in use on this host (not by a server the panel knows). Start anyway?"
check("port check r30: a Restart of a server whose status is stale (offline) while its own game account runs and "
      "its port listens goes ahead, from one read of its processes",
      _pc248["restart_up"][0].get("success") is True and _pc248["restart_up"][1:] == (1, 1), repr(_pc248["restart_up"]))
check("port check r30: a Start of it is refused saying it may already be up, and still offers Start anyway",
      _pc248["start_up"][0].get("port_in_use") is True and _pc248["start_up"][1] == 0
      and "may already be up" in (_pc248["start_up"][0].get("message") or ""), repr(_pc248["start_up"]))
eq("port check r30: with none of its account's processes running, or that read failing (zero sample or None), a "
   "Restart is refused as before, blaming the unknown listener",
   [(_pc248[k][0].get("message"), _pc248[k][1]) for k in ("restart_down", "restart_unread", "restart_raises")],
   [(_PC_BUSY248, 0)] * 3)
check("port check r30: ...and nothing reached a host", _pc248["trips"] == [], repr(_pc248["trips"]))

# ── 3. a port saved back to the stored one during a Start ────────────────────────────────────────
_pb_sid248 = _p9_new_server(P9_HOST, "p248pb", "csgo", 42490, name="p248-pb", status="offline")


def _pb_run248():
    """The stand-in Start: while it runs, the Settings tab saves the stored port back (pending cleared)."""
    _p9_set(_pb_sid248, pending_port=None)
    return "Starting csgoserver: OK", "", 0


try:
    _p9_arm(who="part248")
    _pb_trips248 = len(_P9_TRIPPED)
    _p9_patch(_sd248, "threading", _p9_threading(_P9Thread))
    _p9_patch_sm("run_as_game_user", lambda *a, **k: _pb_run248())
    _p9_patch_sm("set_game_priority", lambda *a, **k: None)
    _p9_patch(_lgp248, "allowance_seconds", lambda *a, **k: 0)
    _p9_patch_sm("_remote_listening_ports", lambda remote: set())
    _p9_patch_sm("protected_host_ports", lambda remote: {22})
    _p9_patch_sm("upgrade_managed_cron_tracking", lambda *a, **k: True)
    _p9_patch_sm("remote_ufw_close_game_port", lambda remote, port, user: (1, ""))
    _p9_patch(_sh248, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_sd248, "_live_run_state", lambda gs, remote: None)
    _p9_set(_pb_sid248, port=42490, pending_port=42491)
    _p9_client(P9_ADMIN).post("/api/server/%d/action" % _pb_sid248, json={"action": "start"})
    _p9_drain()
    _pb248 = (_p9_row(_pb_sid248).port, _p9_row(_pb_sid248).pending_port, _P9_TRIPPED[_pb_trips248:])
finally:
    _p9_restore_all()
    _p9_delete_server(_pb_sid248)
eq("pending port r30: a port saved back to the stored one during a Start: the stored port follows the port the "
   "game bound, the save waits for the next start, and nothing reached a host", _pb248, (42491, 42490, []))

# ── 4. the sign-in paths ─────────────────────────────────────────────────────────────────────────
eq("sign-in paths r30: ~/.bash_aliases, a file in ~/.bashrc.d and ~/.k5users are sign-in paths to the file browser",
   [_files248._is_login_path(n) for n in (".bash_aliases", ".bashrc.d/x.sh", ".bashrc.d", ".k5users")], [True] * 4)
eq("sign-in paths r30: the restore keeps every sign-in path the file browser refuses (never cleared, never "
   "extracted)", sorted(set(_files248._LOGIN_DIRS + _files248._LOGIN_FILES) - set(_grs248.KEEP)), [])
_SIGNIN248 = (".bashrc", ".bash_aliases", ".k5login", ".rhosts", ".profile")


def _signin_restore248():
    """Restore an archive holding planted sign-in files over a home with its own .bashrc. -> what is left."""
    sb = _Sb190()
    try:
        sb.put(".bashrc", "own bashrc\n")
        name = _crafted190(sb, [("././" + n, _tf248.REGTYPE, "") for n in _SIGNIN248]
                           + [("././.bashrc.d/", _tf248.DIRTYPE, ""), ("././.bashrc.d/x.sh", _tf248.REGTYPE, ""),
                              ("././serverfiles/", _tf248.DIRTYPE, ""), ("././serverfiles/new.cfg", _tf248.REGTYPE, "")])
        ready = sb.vet(name)[1][1]
        with open(_os248.path.join(sb.bdir, _UNDO190), "wb") as f:
            f.write(b"undo")
        out, rc = sb.run(_grs248.restore_script(_U190, _U190, name, ready["t0"], ready["need"], _UNDO190,
                                                busy_polls=1, members=ready["members"]))
        return (_grs248.restore_outcome(out, rc)[0], sb.read(".bashrc"),
                [n for n in _SIGNIN248[1:] + (".bashrc.d",) if _os248.path.lexists(_os248.path.join(sb.home, n))],
                sb.read("serverfiles/new.cfg"))
    finally:
        sb.gone()


if _missing190:
    skip("sign-in paths r30: a restore keeps the account's own sign-in files", "missing tools: %s" % _missing190)
else:
    eq("sign-in paths r30: a restore of an archive that holds .bashrc, .bash_aliases, .k5login, .rhosts, .profile "
       "and .bashrc.d restores the game files but keeps the account's own .bashrc and brings in none of the others",
       _signin_restore248(), ("done", "own bashrc\n", [], ""))


# ── 5. writes refused while a restore runs ───────────────────────────────────────────────────────
_rg_sid248 = _p9_new_server(P9_HOST, "p248rg", "gmod", 42500, name="p248-rg")
_rg248 = {"writes": []}


def _rg_write248(what):
    """A recorder standing in for a host writer: notes `what` and answers success."""
    def rec(*a, **k):
        _rg248["writes"].append(what)
        return True, ""
    return rec


def _rg_posts248(client):
    """Each write route's (status, body) and the silent writers' answers, run once."""
    base = "/api/server/%d/" % _rg_sid248
    r = [client.post(base + "daily-restart", json={"enabled": True, "time": "05:00", "tz": "UTC"}),
         client.post(base + "log-timestamps", json={"enabled": False}),
         client.post(base + "gmod-content", json={"action": "mount", "games": ["cstrike"]}),
         client.post(base + "gmod-content", json={"action": "uninstall", "games": ["cstrike"]})]
    with _p9.app_context():
        gs = _db248.session.get(_GS248, _rg_sid248)
        _sd248._r16b_retype_restart_check(gs)
        gained = _sh248.lg265_schedule_gained(gs, [{"cmd": "start"}], [{"cmd": "start"}, {"cmd": "update"}])
    return [x.status_code for x in r], gained


try:
    _p9_arm(who="part248")
    _rg_trips248 = len(_P9_TRIPPED)
    _p9_set(_rg_sid248, daily_restart=True)
    _p9_patch(_sd248, "set_daily_restart", _rg_write248("daily"))
    _p9_patch(_sf248, "lgsm_write_config", _rg_write248("cfg"))
    _p9_patch_sm("upgrade_managed_cron_tracking", lambda *a, **k: _rg248["writes"].append("retype") or True)
    _p9_patch_sm("add_maintenance_cron", _rg_write248("gained"))
    _p9_patch(_sh248, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_sf248, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_sd248, "game_account_write_refusal", lambda *a, **k: None)
    _rg_c248 = _p9_client(P9_ADMIN)
    with _job248(_rg_sid248, _sh248.GRS_KIND):
        _rg248["held"] = _rg_posts248(_rg_c248) + (list(_rg248["writes"]),)
    _rg248["trips"] = _P9_TRIPPED[_rg_trips248:]
    # The silent writers with no restore: both write (controls for the two that answer nothing).
    del _rg248["writes"][:]
    with _p9.app_context():
        _rg_gs248 = _db248.session.get(_GS248, _rg_sid248)
        _sd248._r16b_retype_restart_check(_rg_gs248)
        _rg248["free"] = (_sh248.lg265_schedule_gained(_rg_gs248, [{"cmd": "start"}],
                                                        [{"cmd": "start"}, {"cmd": "update"}]), list(_rg248["writes"]))
finally:
    _p9_restore_all()
    _p9_delete_server(_rg_sid248)
eq("restore gate r30: while the server is being restored, the daily restart, log timestamps off and GMod content "
   "apply and remove answer 409, the restart check's re-type and newly gained maintenance commands write nothing, "
   "and no writer ran", _rg248["held"], ([409, 409, 409, 409], set(), []))
eq("restore gate r30: with no restore, the re-type and the gained command both write (control)",
   _rg248["free"], ({"update"}, ["retype", "gained"]))
check("restore gate r30: ...and nothing reached a host", _rg248["trips"] == [], repr(_rg248["trips"]))


# ── 6. a served catch-up wakes a resting console ─────────────────────────────────────────────────
_CR_SID248 = 9248006
_cr_gs248 = _NS248(id=_CR_SID248, remote=_NS248(id=9248006), short_name="p248cr", name="p248-cr")
_cr248 = {"reads": 0, "emits": []}


def _cr_tick248(app, socketio, gs, server_id):
    """The poller's tick, standing in: a read that finds nothing new (offsets unchanged)."""
    _cr248["reads"] += 1
    return True


def _cr_pass248(catchup):
    """One poller pass over a console resting after 5 quiet reads, with or without a page's catch-up."""
    _offsets248[_CR_SID248] = {"ino": 7, "pos": 100, "chain": 1, "idle": 5, "read_at": _time248.time()}
    _sf248._console_viewers[_CR_SID248] = {"sock248"}
    if catchup:
        _sf248._console_catchups[_CR_SID248] = {"sock248": {"id": 1, "since": None, "tries": 0}}
    n = _cr248["reads"]
    sock = _NS248(emit=lambda event, reply, to=None: _cr248["emits"].append((event, to)))
    _sf248._serve_console_catchups(_app248, sock, _cr_gs248, _CR_SID248)
    _crest248.tick(_cr_tick248, _sf248._console_catchups, _app248, sock, _cr_gs248, _CR_SID248)
    return _cr248["reads"] - n


try:
    _p9_patch(_sf248, "_console_catchup", lambda gs, server_id, req: {"server_id": server_id, "id": req["id"]})
    _cr248["quiet"] = _cr_pass248(False)
    _cr248["caught"] = _cr_pass248(True)
finally:
    _p9_restore_all()
    for _cr_map248 in (_offsets248, _sf248._console_viewers, _sf248._console_catchups, _crest248._woken):
        _cr_map248.pop(_CR_SID248, None)
eq("console rest r30: a resting console is not read on a quiet pass, and is read on the pass that answers a page's "
   "catch-up (the answer sent to that page)", (_cr248["quiet"], _cr248["caught"], _cr248["emits"]),
   (0, 1, [("console_catchup", "sock248")]))


# ── 7. the database dump waits for the player check ──────────────────────────────────────────────
_dd_sid248 = _p9_new_server(P9_HOST, "p248dd", "csgo", 42510, name="p248-dd")


class _DdStop248(Exception):
    """Raised by the first host call after the player check: the backup was going ahead."""


def _dd_runs248(players):
    """Both callers once with `players` online ("" for none) -> [(dumps, outcome or "went ahead")] per caller."""
    out = []
    _p9_patch(_game248, "_backup_players_online", lambda *a, **k: players)

    def stop(*a, **k):
        raise _DdStop248()
    _p9_patch_sm("shell_as_game_user", stop)
    for call in (lambda: _sh248._marked_backup(_dd_sid248, _dd_row248.remote, "p248dd", "csgoserver", 3,
                                               game_type="csgo", port=42510),
                 lambda: _pbk248._back_up_one_now(_app248, _dd_sid248, "p248-dd", (3, False), _NO_BIRTH248)):
        n = len(_dd248)
        try:
            got = call()
        except _DdStop248:
            got = "went ahead"
        out.append((len(_dd248) - n, got if got == "went ahead" else bool(got)))
    return out


_dd248 = []
try:
    _p9_arm(who="part248")
    _dd_trips248 = len(_P9_TRIPPED)
    _p9_patch(_dbr248, "dump_for_backup", lambda sid, remote, account: _dd248.append(sid))
    _p9_patch(_game248, "_lg264_bk_before", lambda *a, **k: None)
    with _p9.app_context():
        _dd_row248 = _db248.session.get(_GS248, _dd_sid248)
        _dd_busy248 = _dd_runs248("2 player(s) online")
        _dd_go248 = _dd_runs248("")
    _dd_trip_list248 = _P9_TRIPPED[_dd_trips248:]
finally:
    _p9_restore_all()
    _p9_delete_server(_dd_sid248)
    _sh248._game_backup_status.pop(_dd_sid248, None)
eq("backup dump r30: a backup skipped for players online (the ticker's path and Back up now) dumps no database",
   [d for d, _ in _dd_busy248], [0, 0])
eq("backup dump r30: one that goes ahead dumps them once, before the archive is made (the next host call)",
   _dd_go248, [(1, "went ahead"), (1, "went ahead")])
check("backup dump r30: ...and nothing reached a host", _dd_trip_list248 == [], repr(_dd_trip_list248))


# ── 8. the panel host's reboot waits for a game server's restore ─────────────────────────────────
_hb248 = {}
try:
    _p9_arm(who="part248")
    _hb_trips248 = len(_P9_TRIPPED)
    _hb_sent248 = []
    _p9_patch(_so248, "server_reboot", lambda delay=5: (_hb_sent248.append(delay), (True, "Server will reboot"))[1])
    _p9_patch(_pbk248, "RemoteServer", _Unread110(False))
    _hb_c248 = _p9_client(P9_ADMIN)
    with _p9.app_context():
        _hb248["idle"] = [b["kind"] for b in _hr248._panel_host_blockers()]
    _grr248._grs_status[9248008] = {"running": True}
    try:
        with _p9.app_context():
            _hb248["restoring"] = [b["kind"] for b in _hr248._panel_host_blockers()]
        _hb_r248 = _hb_c248.post("/api/server-management/reboot", json={"delay": 5})
        _hb_j248 = _hb_r248.get_json(silent=True) or {}
        _hb248["route"] = (_hb_r248.status_code, [b.get("kind") for b in _hb_j248.get("blockers") or ()],
                           "restore of a game server" in (_hb_j248.get("message") or ""), len(_hb_sent248))
    finally:
        _grr248._grs_status.pop(9248008, None)
    _hb248["trips"] = _P9_TRIPPED[_hb_trips248:]
finally:
    _p9_restore_all()
eq("panel host reboot r30: no game-restore blocker with no restore running, one while a game server is restored",
   (_hb248.get("idle"), _hb248.get("restoring")), ([], ["game_restore"]))
eq("panel host reboot r30: the no-host-row reboot route answers 409 naming the restore and sends no reboot",
   _hb248.get("route"), (409, ["game_restore"], True, 0))
check("panel host reboot r30: ...and nothing reached a host", _hb248.get("trips") == [], repr(_hb248.get("trips")))
