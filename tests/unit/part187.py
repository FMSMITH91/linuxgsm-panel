"""Part 187 of the unit suite: review pass 29's fixes in the monitor, LinuxGSM details and the report.

Held here:
* The monitor's LinuxGSM lock probe on the panel's own host runs as the game account (the panel's
  account cannot enter a game home), so a stop LinuxGSM made pages nothing there either; a lock
  still there, or one that could not be read, still pages.
* The two readers of LinuxGSM `details` that were regexes (the config file line, the Server IP /
  Internet IP port) answer as those regexes did on random text, and in linear time when the
  server's name (printed first, on one line) is built to make them backtrack.
* The XML config form's comment walk gives the same fields as before and stays linear with many
  comments on one line, many comment lines, or many properties before one comment.
* The debug report's manual full backup line counts servers held by a scheduled wipe or a queued
  stop or restart, from the summary _FullBackupTally writes.

HOW IT RUNS. Every host call is stubbed (the local transport, the game-account shell); the details
text is invented, shaped like LinuxGSM's info_messages.sh output. Nothing reaches a host or data/.
"""
import random as _random187
import re as _re187
import time as _time187
from types import SimpleNamespace as _NS187

from unit.part01 import check, eq
from unit.part12 import _p9_patch, _p9_patch_sm, _p9_restore_all
from panel.core import panel_state as _ps187
from panel.ops import backup as _bk187
from panel.ops.debug_report import _base as _base187, data as _data187
from panel.ops.ssh_manager import files as _files187, game as _game187
from panel.routes import panel_backup as _pb187
from panel.services import game_config_form as _g187
from panel.services import host_reboot as _hr187, monitoring as _mon187, notifications as _nt187

# ── 1. the monitor's lock probe on the panel's own host ─────────────────────────────────────────
_r42m_gs = _NS187(id=918187, name="p187-mon", short_name="r42mgame", lgsm_name="rustserver", game_type="rust")
_r42m_local = _NS187(id=187, display_name="this host", name="local", is_local=True, auth_method="local")
_r42m_said = []
_r42m_lock_calls = []


def _r42m_down(as_game_word, own=False):
    """Two confirmed-down sweeps on a local row. -> (recorded, pages, unannounced, lock shells).

    The stub answers `as_game_word` only to a line that runs as the game account (`sudo -u
    r42mgame bash -c ...`, or the bare line when the panel itself is that account); the panel's
    own account, without root, cannot search the 0750 home and reads it as unread.
    """
    del _r42m_said[:]
    del _r42m_lock_calls[:]
    _ps187._expected_offline.pop(_r42m_gs.id, None)
    _mon187._monitor_state["server_misses"].pop(_r42m_gs.id, None)
    _mon187._monitor_state["server_unannounced"].pop(_r42m_gs.id, None)

    def _run_local(cmd, timeout=30, sudo=False, stdin_text=None):
        if "pgrep" in cmd:
            return "IDLE", "", 0
        _r42m_lock_calls.append((cmd[:30], sudo))
        as_game = (cmd.startswith("sudo -u r42mgame bash -c ") and not sudo) or (own and not sudo)
        return (as_game_word if as_game else "LGSM_LOCK_unread"), "", 0

    _p9_patch_sm("_run_local", _run_local)
    _p9_patch(_hr187, "_own_account", lambda: "r42mgame" if own else "r42mpanel")
    _p9_patch(_nt187, "notify", lambda kind, *a, **k: _r42m_said.append(kind))
    try:
        prev = True
        for _ in range(_mon187._DOWN_CONFIRM_SWEEPS):
            prev = _mon187._server_transition(_r42m_local, _r42m_gs, False, prev, False)
    finally:
        _p9_restore_all()
    return (prev, list(_r42m_said), _mon187._monitor_state["server_unannounced"].pop(_r42m_gs.id, False),
            len(_r42m_lock_calls))


_r42m_runs = [_r42m_down("LGSM_LOCK_none"), _r42m_down("LGSM_LOCK_held"), _r42m_down("LGSM_LOCK_unread"),
              _r42m_down(""), _r42m_down("LGSM_LOCK_none", own=True)]
eq("monitor r42m: on the panel's own host the lock probe runs as the game account, in one shell: its "
   "monitoring lock gone (LinuxGSM's own stop) records the server down without a page; a lock still "
   "there, or a probe the game account could not answer, pages; a game under the panel's own account "
   "is read directly",
   _r42m_runs,
   [(False, [], True, 1), (False, ["server_down"], False, 1), (False, ["server_down"], False, 1),
    (False, ["server_down"], False, 1), (False, [], True, 1)])
check("monitor r42m: the panel-host lock probe never asks for root (no sudo bash -c wrapper)",
      all(not _s for _c, _s in _r42m_lock_calls), repr(_r42m_lock_calls))


# ── 2. LinuxGSM details: the config file line and the Server IP port ────────────────────────────
# The regexes the readers replaced, kept as the reference the string code must answer like.
_r42m_old_cfg = _re187.compile(r"config file[^:\n]*:[ \t]*(/\S+\.(?:cfg|ini|properties|xml|json|txt|conf))(?!\S)",
                               _re187.I)
_r42m_old_ip = _re187.compile(r"(?:server|internet)\s+ip:[^\n]*:(\d{2,5})[ \t\r]*(?:\n|\Z)", _re187.I)


def _r42m_old_cfg_path(t):
    m = _r42m_old_cfg.search(t)
    return m.group(1) if m else ""


def _r42m_old_ip_port(t):
    m = _r42m_old_ip.search(t)
    return int(m.group(1)) if m else None


_r42m_cabc = ["config file", "Config File", "CONFIG FILE", "conf\u0131g file", "config", " file", ":", ": ", " ",
              "\t", "\n", "\r", "\xa0", "/", "/home/u/", "a", ".cfg", ".CFG", ".ini", ".conf", ".txt", "x.json",
              ".properties", ".xm", "l", "(FILE MISSING)"]
_r42m_iabc = ["server", "Server", "internet", "INTERNET", " ", "\t", "\n", "\r", "ip:", "IP:", ":", "1", "27015",
              "123456", "[2001:db8::1]", "0.0.0.0", "a", "\u0663\u0664", "Server IP:", "Internet IP:\t"]
_r42m_rng = _random187.Random(187)  # nosec B311 - a seeded fuzz corpus, not security
_r42m_cfg_bad = [t for t in ("".join(_r42m_rng.choice(_r42m_cabc) for _ in range(_r42m_rng.randint(0, 14)))
                             for _ in range(30000))
                 if _r42m_old_cfg_path(t) != _files187._r42m_config_file_path(t)]
_r42m_ip_bad = [t for t in ("".join(_r42m_rng.choice(_r42m_iabc) for _ in range(_r42m_rng.randint(0, 14)))
                            for _ in range(30000))
                if _r42m_old_ip_port(t) != _game187._r42m_ip_line_port(t)]
check("details r42m: the config file reader answers as the regex it replaced on 30000 random texts (labels in "
      "any case, colons, blanks, line breaks, paths and extensions)", not _r42m_cfg_bad, repr(_r42m_cfg_bad[:3]))
check("details r42m: the Server IP / Internet IP port reader answers as the regex it replaced on 30000 random "
      "texts (IPv6 addresses, ports too long, non-ASCII digits, labels split over a line break)",
      not _r42m_ip_bad, repr(_r42m_ip_bad[:3]))

# Invented values, laid out as LinuxGSM's info_messages.sh prints `details`.
_R42M_HEAD = ("Summary\n=====\nServer name:\t%s\nServer description:\tA test server\n"
              "Server IP:\t%s\nInternet IP:\t%s\nStatus:\tSTOPPED\n\n")
_R42M_SCRIPT = ("Script Details\n=====\nScript name:\tcsgoserver\nLinuxGSM version:\tv26.4.0\n"
                "Config file:\t/home/r42mgame/serverfiles/csgo/cfg/csgoserver.cfg\n\n")
_r42m_files_said = []


def _r42m_game_config(name):
    """lgsm_game_config over a `details` whose server name is `name`. -> (rel, seconds)."""
    out = ("__LGSMP_REAL_HOME__=/home/r42mgame\n" + _R42M_HEAD % (name, "0.0.0.0:27015", "192.0.2.10:27015")
           + _R42M_SCRIPT + "__LGSMP_DETAILS_DONE__")
    del _r42m_files_said[:]
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: (out, "", 0))
    _p9_patch_sm("read_file", lambda server, user, rel: (_r42m_files_said.append(rel) or "x", None))
    try:
        t0 = _time187.monotonic()
        got = _files187.lgsm_game_config(_r42m_local, "r42mgame", "csgoserver")
        took = _time187.monotonic() - t0
    finally:
        _p9_restore_all()
    return got["rel"], list(_r42m_files_said), took


def _r42m_ports(name, ip_line):
    """detect_game_ports over a `details` with no port table. -> (game port, open ports, seconds)."""
    out = _R42M_HEAD % (name, ip_line, ip_line) + _R42M_SCRIPT
    _p9_patch_sm("run_as_game_user", lambda *a, **k: (out, "", 0))
    try:
        t0 = _time187.monotonic()
        got = _game187.detect_game_ports(_r42m_local, "r42mgame", "csgoserver", "csgo")
        took = _time187.monotonic() - t0
    finally:
        _p9_restore_all()
    return got["game_port"], got["open_ports"], took


# Measured on this machine: the replaced regexes took 0.8 s at 88 KB and 3.1 s at 176 KB of the label
# repeated, growing with the square of the length; the string code takes milliseconds.
_r42m_gc_plain = _r42m_game_config("My Server")
_r42m_gc_slow = _r42m_game_config("config file " * 12000)
eq("details r42m: Files & Config finds the config file `details` names, relative to the home, and reads it",
   _r42m_gc_plain[:2], ("serverfiles/csgo/cfg/csgoserver.cfg", ["serverfiles/csgo/cfg/csgoserver.cfg"]))
check("details r42m: a server name of 'config file' repeated 12000 times (144 KB, no colon) is read in "
      "linear time and the real Config file line still wins (well under 0.6 s)",
      _r42m_gc_slow[0] == "serverfiles/csgo/cfg/csgoserver.cfg" and _r42m_gc_slow[2] < 0.6,
      "%r %.2fs" % (_r42m_gc_slow[0], _r42m_gc_slow[2]))
eq("details r42m: with no port table, the port ending the Server IP line is the game port (an IPv6 address's "
   "own colons are not)", [_r42m_ports("My Server", "[2001:db8::1234]:27016")[:2],
                           _r42m_ports("My Server", "0.0.0.0:0")[:2]],
   [(27016, [27016]), (None, [])])
_r42m_ip_slow = _r42m_ports("server ip:" * 20000, "0.0.0.0:27017")
check("details r42m: a server name of 'server ip:' repeated 20000 times (200 KB) is read in linear time and "
      "the real Server IP line's port still wins (well under 0.6 s)",
      _r42m_ip_slow[0] == 27017 and _r42m_ip_slow[2] < 0.6, "%r %.2fs" % (_r42m_ip_slow[0], _r42m_ip_slow[2]))

