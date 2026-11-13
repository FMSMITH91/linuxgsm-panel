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
              "123456", "[2001:db8::1]", "0.0.0.0", "a", "\u0663\u0664", "Server IP:", "Internet IP:\t"]  # nosec B104 - sample text, not a bind
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


def _r42m_best(call, reps):
    """The fastest of three timings of `reps` calls to `call`, in seconds."""
    best = None
    for _ in range(3):
        t0 = _time187.monotonic()
        for _ in range(reps):
            call()
        took = _time187.monotonic() - t0
        best = took if best is None else min(best, took)
    return best


def _r42m_growth(make, n):
    """How long make(size)() takes at size 4n against size n. -> (ratio, seconds per 4n call, answers).

    Judged on growth, not on wall time, so a loaded machine cannot fail it: linear code gives about 4,
    quadratic about 16. make(size) returns a callable with its input already built. The n calls are
    repeated until one timing reaches 20 ms and the 4n ones get the same count, so the ratio is not
    the clock's resolution; each is the fastest of three. The answers are those of n and 4n.
    """
    small, big = make(n), make(4 * n)
    reps = 1
    while _r42m_best(small, reps) < 0.02 and reps < 4096:
        reps *= 2
    t_small, t_big = _r42m_best(small, reps), _r42m_best(big, reps)
    return t_big / max(t_small, 1e-9), t_big / reps, (small(), big())


# Linear is ~4, quadratic ~16 (the replaced code measured 13.5-15 per 4x here); 8 lies between.
# The 10 s per call is only a guard against a hang, not a speed bar.
_R42M_GROWTH_MAX = 8.0
_R42M_HANG_S = 10.0


def _r42m_grows_linearly(got):
    return got[0] < _R42M_GROWTH_MAX and got[1] < _R42M_HANG_S


_r42m_out = {}


def _r42m_details_out(name, ip_line="0.0.0.0:27015"):
    """`details` output (invented values) whose server name is `name`, as lgsm_game_config's shell prints it."""
    return ("__LGSMP_REAL_HOME__=/home/r42mgame\n" + _R42M_HEAD % (name, ip_line, ip_line) + _R42M_SCRIPT
            + "__LGSMP_DETAILS_DONE__")


def _r42m_stub_details():
    """Point both details callers' game-account shells at _r42m_out["text"], and record what is read."""
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: (_r42m_out["text"], "", 0))
    _p9_patch_sm("run_as_game_user", lambda *a, **k: (_r42m_out["text"], "", 0))
    _p9_patch_sm("read_file", lambda server, user, rel: (_r42m_files_said.append(rel) or "x", None))


def _r42m_game_config_call(name):
    """A callable running lgsm_game_config over a `details` whose server name is `name` -> its rel."""
    text = _r42m_details_out(name)

    def call():
        _r42m_out["text"] = text
        return _files187.lgsm_game_config(_r42m_local, "r42mgame", "csgoserver")["rel"]
    return call


def _r42m_ports_call(name, ip_line):
    """A callable running detect_game_ports over a `details` with no port table -> (game port, open ports)."""
    text = _r42m_details_out(name, ip_line)

    def call():
        _r42m_out["text"] = text
        got = _game187.detect_game_ports(_r42m_local, "r42mgame", "csgoserver", "csgo")
        return got["game_port"], got["open_ports"]
    return call


# Measured on this machine: the replaced regexes took 0.8 s at 88 KB and 3.1 s at 176 KB of the label
# repeated, growing with the square of the length; the string code takes milliseconds.
_r42m_stub_details()
try:
    _r42m_gc_plain = (_r42m_game_config_call("My Server")(), list(_r42m_files_said))
    _r42m_gc_grow = _r42m_growth(lambda k: _r42m_game_config_call("config file " * k), 3000)
    _r42m_ip_plain = [_r42m_ports_call("My Server", "[2001:db8::1234]:27016")(),
                      _r42m_ports_call("My Server", "0.0.0.0:0")()]
    _r42m_ip_grow = _r42m_growth(lambda k: _r42m_ports_call("server ip:" * k, "0.0.0.0:27017"), 4000)
finally:
    _p9_restore_all()
eq("details r42m: Files & Config finds the config file `details` names, relative to the home, and reads it",
   _r42m_gc_plain, ("serverfiles/csgo/cfg/csgoserver.cfg", ["serverfiles/csgo/cfg/csgoserver.cfg"]))
check("details r42m: a server name of 'config file' repeated (36 KB, then 144 KB, no colon) is read in time "
      "that grows linearly with it (4x the name, under 8x the time), and the real Config file line still wins",
      _r42m_grows_linearly(_r42m_gc_grow) and _r42m_gc_grow[2] == ("serverfiles/csgo/cfg/csgoserver.cfg",) * 2,
      "x%.1f %.3fs %r" % _r42m_gc_grow)
eq("details r42m: with no port table, the port ending the Server IP line is the game port (an IPv6 address's "
   "own colons are not)", _r42m_ip_plain, [(27016, [27016]), (None, [])])
check("details r42m: a server name of 'server ip:' repeated (40 KB, then 160 KB) is read in time that grows "
      "linearly with it (4x the name, under 8x the time), and the real Server IP line's port still wins",
      _r42m_grows_linearly(_r42m_ip_grow) and _r42m_ip_grow[2] == ((27017, [27017]),) * 2,
      "x%.1f %.3fs %r" % _r42m_ip_grow)

# ── 3. the XML config form's comment walk ───────────────────────────────────────────────────────
# The helpers the walk had before, kept as the reference its answers must match.
def _r42m_old_own_line(text, pos):
    line_start = max(text.rfind("\n", 0, pos), text.rfind("\r", 0, pos)) + 1
    return not text[line_start:pos].strip()


def _r42m_old_before(text, comments, ci, last_end, pos, section):
    above = None
    while ci < len(comments) and comments[ci][0] < pos:
        s, e, words = comments[ci]
        ci += 1
        if s >= last_end and "<property" not in words and _r42m_old_own_line(text, s):
            section = words if len(words) <= _g187._GCF_SECTION_MAX else section
            gap = text[e:pos]
            above = words if not gap.strip() and len(_g187._GCF_EOL.findall(gap)) <= 1 else None
    return ci, section, above


def _r42m_old_trail(text, comments, ci, end):
    if ci < len(comments):
        gap = text[end:comments[ci][0]]
        if not gap.strip() and not _g187._GCF_EOL.search(gap):
            return comments[ci], ci + 1
    return None, ci


def _r42m_old_parse(text):
    _p9_patch(_g187, "_gcf_xml_before", _r42m_old_before)
    _p9_patch(_g187, "_gcf_xml_trail", _r42m_old_trail)
    try:
        return _g187._gcf_parse_xml(text)
    finally:
        _p9_restore_all()


_r42m_xabc = ["<!--", "-->", "<!-- g -->", "<!-- help -->", '<property name="a" value="1"/>',
              "<property name='b' value='2' />", "<property", "<!-- <property -->", " ", "\t", "\n", "\r", "\r\n",
              "\x0b", "\xa0", "\u2028", "x"]
_r42m_xtexts = ["".join(_r42m_rng.choice(_r42m_xabc) for _ in range(_r42m_rng.randint(0, 14))) for _ in range(12000)]
_r42m_xold = [_r42m_old_parse(t) for t in _r42m_xtexts]
_r42m_xml_bad = [t for t, o in zip(_r42m_xtexts, _r42m_xold) if o != _g187._gcf_parse_xml(t)]
check("game config form r42m: the XML comment walk gives the fields (group, help, place) the old walk gave "
      "on 12000 random texts (own-line and trailing comments, CR LF, Unicode blanks)",
      not _r42m_xml_bad, repr(_r42m_xml_bad[:3]))
_r42m_ol_abc = [" ", "\t", "\n", "\r", "\x0b", "\x85", "\u2028", "a", "<"]
_r42m_ol_bad = [(t, i) for t in ("".join(_r42m_rng.choice(_r42m_ol_abc) for _ in range(_r42m_rng.randint(0, 9)))
                                 for _ in range(4000)) for i in range(len(t) + 1)
                if _r42m_old_own_line(t, i) != _g187._gcf_own_line(t, i)]
check("game config form r42m: 'only blanks before it on its line' answers as the line-start search it "
      "replaced, at every place of 4000 random texts", not _r42m_ol_bad, repr(_r42m_ol_bad[:3]))

# Measured on this machine: the old walk took 0.83 s at 80000 comment lines, 0.25 s at 60000 comments on
# one line and 1.0 s at 30000 properties before one comment, each growing with the square.
_R42M_P = '<property name="a" value="b"/>'


def _r42m_xml_call(text):
    return lambda: len(_g187._gcf_parse_xml(text) or ())


_r42m_xcases = (("comment lines then a property", 30000, lambda k: "<!---->\n" * k + _R42M_P + "\n", lambda k: 1),
                ("comments on one line then a property", 40000,
                 lambda k: "<!---->" * k + "\n" + _R42M_P + "\n", lambda k: 1),
                ("properties then one comment", 12000,
                 lambda k: "".join('<property name="a%d" value="b"/>\n' % i for i in range(k)) + "<!-- x -->\n",
                 lambda k: k))
_r42m_xslow = []
for _r42m_label, _r42m_n, _r42m_make, _r42m_want in _r42m_xcases:
    _r42m_got = _r42m_growth(lambda k, _mk=_r42m_make: _r42m_xml_call(_mk(k)), _r42m_n)
    _r42m_xslow.append((_r42m_label, _r42m_got[2] == (_r42m_want(_r42m_n), _r42m_want(4 * _r42m_n)),
                        _r42m_grows_linearly(_r42m_got), "x%.1f %.3fs" % _r42m_got[:2]))
check("game config form r42m: an XML file of 30000/120000 comment lines, 40000/160000 comments on one line, or "
      "12000/48000 properties before one comment is parsed in time that grows linearly with it (4x the file, "
      "under 8x the time), with every field found", all(_ok and _lin for _l, _ok, _lin, _t in _r42m_xslow),
      repr(_r42m_xslow))

# ── 4. the debug report's manual full backup line ───────────────────────────────────────────────
def _r42m_manual(ok, players, held):
    """The report's manual-backup line for a run with these outcomes, from _FullBackupTally's summary."""
    tally = _pb187._FullBackupTally()
    tally.ok_n, tally.skip_n, tally.held = ok, players, list(held)
    conf = {"full_backup_last": 1000, "full_backup_summary": tally.summary()}
    _p9_patch(_bk187, "load_config", lambda *a, **k: conf)
    try:
        res = _base187.Result()
        _data187._r12b_manual_line(res)
    finally:
        _p9_restore_all()
    return "\n".join(res.lines).split(": ", 1)[-1]


_r42m_m_held = _r42m_manual(0, 0, ["r42m-alpha"])
_r42m_m_mixed = _r42m_manual(2, 1, ["r42m-alpha", "r42m-beta"])
_r42m_m_none = _r42m_manual(3, 0, [])
check("debug report r42m: a manual full backup whose one server was held by its scheduled wipe says 1 held, "
      "not '0 backed up, 0 failed, 0 skipped' alone, and names no server",
      "0 backed up, 0 failed, 0 skipped, 1 held by a scheduled wipe or a queued stop or restart" in _r42m_m_held
      and "r42m-alpha" not in _r42m_m_held, _r42m_m_held)
check("debug report r42m: held servers are counted beside the players-online skips; a run with none held "
      "reads as before",
      "2 backed up, 0 failed, 1 skipped, 2 held by" in _r42m_m_mixed and "r42m-beta" not in _r42m_m_mixed
      and "3 backed up, 0 failed, 0 skipped" in _r42m_m_none and "held" not in _r42m_m_none,
      repr((_r42m_m_mixed, _r42m_m_none)))
