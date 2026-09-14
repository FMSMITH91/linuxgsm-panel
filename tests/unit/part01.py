from unit import REPO_ROOT as _UNIT_ROOT  # noqa: E402

"""Fast unit tests for the pure-logic helpers — no network, no SSH, no live DB.

These lock in the behaviour of the parsing/classification code where subtle bugs
tend to hide: firewall rule grouping + lock-out protection, game-port selection,
password policy, safe int parsing, and secret encryption. Several of these would
have caught real regressions (wrong protocol split, opening non-essential ports,
deleting the last SSH rule, a non-numeric port 500).

    python tests/unit_test.py      # exits 0 if all pass, 1 otherwise
"""
import json  # noqa: F401 - re-export: a later part imports this from here
import glob  # noqa: F401 - re-export: a later part imports this from here
import os
import re  # noqa: F401 - re-export: a later part imports this from here
import sys
from types import SimpleNamespace as NS

sys.path.insert(0, _UNIT_ROOT)
from panel.ops.ssh_manager import _core as _sm_core
from panel.ops.ssh_manager import cron as _sm_cron
from panel.ops.ssh_manager import files as _sm_files
from panel.ops.ssh_manager import firewall as _sm_firewall  # noqa: F401 - re-export: a later part imports this from here
from panel.ops.ssh_manager import game as _sm_game  # noqa: F401 - re-export: a later part imports this from here
from panel.ops.ssh_manager import gmod as _sm_gmod  # noqa: F401 - re-export: a later part imports this from here
from panel.ops.ssh_manager import hosts as _sm_hosts
from panel.ops.ssh_manager import portscan as _sm_portscan  # noqa: F401 - re-export: a later part imports this from here

# ── Where a panel module's SOURCE lives ────────────────────────────────────────────────────────
# Several gates below read module source as text (grep-style checks, AST scans). They used to
# name files as bare root-relative basenames — open("ssh_manager.py") — which stopped being true
# the moment the modules moved into panel/. Two of those sites had an os.path.exists() guard and
# would have skipped silently, still reporting green while checking nothing at all.
#
# So resolve a module to its real file ONCE, here, by walking the tree. A future move needs no
# edit, and a NAME THAT NO LONGER EXISTS RAISES rather than being quietly skipped — a gate that
# can't find its subject is a broken gate, not a passing one.
_root = _UNIT_ROOT
_PKG_DIRS = ("panel",)


def _modpath(name):
    """Absolute path to panel module `name` ("ssh_manager.py" or "ssh_manager"). Raises if absent.

    A name may resolve to a PACKAGE directory rather than a file: ssh_manager became one. Every
    source gate below asks a question about "that module's source", and the honest answer for a
    package is all of it — so this returns the directory and _modsrc concatenates it. Resolving to
    a single file inside would make each gate silently scan one eighth of what it used to."""
    leaf = name if name.endswith(".py") else name + ".py"
    stem = leaf[:-3]
    cand = os.path.join(_root, leaf)
    if os.path.exists(cand):
        return cand
    for pkg in _PKG_DIRS:
        for dirpath, dirnames, files in os.walk(os.path.join(_root, pkg)):
            if leaf in files:
                return os.path.join(dirpath, leaf)
            if stem in dirnames and os.path.exists(os.path.join(dirpath, stem, "__init__.py")):
                return os.path.join(dirpath, stem)
    raise FileNotFoundError(
        "no panel module named %r — a source gate is pointed at a file that no longer exists" % leaf)


def _modfiles(name):
    """Every source FILE for panel module `name` — one for a module, all of them for a package.

    Source gates that scan line-by-line or parse an AST need real files, not concatenated text
    (line numbers have to mean something, and two files concatenated is not valid to attribute to
    either). Gates that only search for a string can use _modsrc instead."""
    path = _modpath(name)
    if os.path.isdir(path):
        return [os.path.join(path, f) for f in sorted(os.listdir(path)) if f.endswith(".py")]
    return [path]


def _modsrc(name):
    """Source text of panel module `name`. For a package, every .py in it, concatenated.

    Raises if the module is gone (see _modpath)."""
    path = _modpath(name)
    if os.path.isdir(path):
        return "\n".join(open(os.path.join(path, f), encoding="utf-8").read()
                         for f in sorted(os.listdir(path)) if f.endswith(".py"))
    return open(path, encoding="utf-8").read()

from panel.core import config  # noqa: F401 - re-export: a later part imports this from here
from panel.security import privileged as _privmod
from panel.ops import ssh_manager as sm
from panel.services import notifications as N  # noqa: F401 - re-export: a later part imports this from here
from panel.ops import system_ops as SO
from app import (password_problem, _int_or, _valid_ip_or_cidr, _valid_hex_color,  # noqa: F401 - re-export: a later part imports this from here
    _clean_console_text)
from panel.services.bots.telegram import (_parse_tg_command)  # noqa: F401 - re-export: a later part imports this from here
from panel.services.bots.commands import (_command_arg)  # noqa: F401 - re-export: a later part imports this from here
from panel.db.prefs import (_apply_user_server_order)
from panel.services.monitoring import (_whitelisted)  # noqa: F401 - re-export: a later part imports this from here
from panel.db.prefs import (_apply_user_order)
from panel.security.auth import can_access_remote, client_ip  # noqa: F401 - re-export: a later part imports this from here

results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))


def eq(name, got, want):
    check(name, got == want, "got %r want %r" % (got, want))


# ── perf guard: importing `auth` must NOT compute the ~400ms bcrypt "dummy" hash.
#    It's lazy (computed on the first bad-login attempt, warmed off-thread by init_auth)
#    so panel startup stays fast — a regression here re-adds ~0.4s to every boot. This
#    runs BEFORE the dummy_password_check() call later in this file, which is what
#    actually populates it. ──
check("perf: auth import does no bcrypt work (dummy hash stays lazy)",
      sys.modules["panel.security.auth"]._DUMMY_BCRYPT_HASH is None)

# ── password policy ───────────────────────────────────────────
check("weak: too short", password_problem("Ab1!") is not None)
check("weak: no upper", password_problem("test1234!@") is not None)
check("weak: no lower", password_problem("TEST1234!@") is not None)
check("weak: no digit", password_problem("TestTest!@") is not None)
check("weak: no symbol", password_problem("TestTest12") is not None)
check("strong password accepted", password_problem("Test1234!@") is None)

# ── accent colour (Settings → Branding) is emitted into a CSS custom property, so it MUST be a
#    strict #rrggbb literal — never arbitrary text that could carry `}`/`<` and break out. ──
eq("hex colour: valid passes through (lowercased)", _valid_hex_color("#10B981"), "#10b981")
eq("hex colour: bare 6-hex gets a '#'", _valid_hex_color("1a2b3c"), "#1a2b3c")
eq("hex colour: surrounding whitespace trimmed", _valid_hex_color("  #ABCDEF "), "#abcdef")
eq("hex colour: blank -> '' (use built-in)", _valid_hex_color(""), "")
eq("hex colour: None -> ''", _valid_hex_color(None), "")
eq("hex colour: 3-digit shorthand rejected", _valid_hex_color("#fff"), "")
eq("hex colour: named colour rejected", _valid_hex_color("red"), "")
eq("hex colour: CSS/HTML breakout rejected", _valid_hex_color("#fff;}</style><script>"), "")
eq("hex colour: too long rejected", _valid_hex_color("#1234567"), "")

# ── remote fail2ban helpers: the remote unban docstring says it mirrors the panel-host version and
# it did not — no jail allowlist, .match (which accepts a trailing newline against a ^…$ pattern),
# and no IP canonicalisation, so unbanning 2001:0DB8::0001 silently missed the stored 2001:db8::1.
_F2B_STATUS = "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, panel-auth\n"
_F2B_JAIL = ("Status for the jail: sshd\n   |- Currently banned: 1\n   |- Total banned: 3\n"
             "   |- Total failed: 0\n   `- Banned IP list: 10.0.0.9\n")


def _f2b_fake_run(server, cmd, **kw):
    # These are the commands privileged.py renders for the SSH transport, so match on the argv
    # shape rather than on a `2>` suffix that the verb rendering no longer always adds.
    parts = cmd.split()
    if parts[:2] == ["fail2ban-client", "status"]:
        return ((_F2B_JAIL if len(parts) > 2 and not parts[2].startswith("2>") else _F2B_STATUS),
                "", 0)
    if "command -v fail2ban-client" in cmd:
        return ("yes", "", 0)
    return ("1", "", 0)


_orig_f2b = _sm_core.run_command
try:
    _sm_core.run_command = _f2b_fake_run
    eq("f2b remote: a non-canonical IPv6 is normalised before unbanning",
       _sm_hosts.remote_fail2ban_unban(None, "sshd", "2001:0DB8::0001"),
       (True, "Unbanned 2001:db8::1 from sshd."))
    check("f2b remote: an unknown jail is refused against the host's own list",
          _sm_hosts.remote_fail2ban_unban(None, "nosuch", "10.0.0.9")[0] is False)
    check("f2b remote: a non-IP is refused",
          _sm_hosts.remote_fail2ban_unban(None, "sshd", "not-an-ip")[0] is False)
    check("f2b remote: a trailing newline in the jail name is stripped, not accepted raw",
          _sm_hosts.remote_fail2ban_unban(None, "sshd\n", "10.0.0.9") == (True, "Unbanned 10.0.0.9 from sshd."))
finally:
    _sm_core.run_command = _orig_f2b
eq("f2b: _canonical_ip normalises", _sm_hosts._canonical_ip(" 2001:0DB8::0001 "), "2001:db8::1")
eq("f2b: _canonical_ip rejects junk", _sm_hosts._canonical_ip("nope"), None)
check("f2b: _valid_ip still answers a bool", _sm_hosts._valid_ip("10.0.0.1") is True)

# ── config keys must agree with the code that reads them ────────────────────────────────────────
# Each of these was a real divergence: a documented ssh_timeout nothing read (the two SSH paths
# hardcoded 15 and 12), and an autoblock threshold that defaulted to 20 when read and 100 when
# saved — so saving Settings once made the panel five times more permissive than documented.
from panel.core import config as _cfgmod
_CFG_READERS = "".join(_modsrc(m) for m in
                       ("app", "ssh_manager", "system_ops", "notifications", "backup"))
check("config: every DEFAULT_CONFIG key has a reader",
      all(k in _CFG_READERS for k in _cfgmod.DEFAULT_CONFIG),
      str([k for k in _cfgmod.DEFAULT_CONFIG if k not in _CFG_READERS]))
# Prove the helper READS the knob, rather than that it happens to return the default. The old
# form compared against DEFAULT_CONFIG, which only holds while no config on disk overrides it —
# and tests/smoke_test.py now writes ssh_timeout=1 (see the note there), so the assertion
# depended on suite ORDER for its truth. Driving the value directly is both stronger and
# order-independent: a helper that ignored config would fail this, where it passed before.
_sshto_saved = _cfgmod.load_config().get("ssh_timeout")
try:
    for _want in (7, 30):
        _c = _cfgmod.load_config()
        _c["ssh_timeout"] = _want
        _cfgmod.save_config(_c)
        eq("config: ssh_timeout=%d is what the SSH layer uses" % _want,
           _sm_core._ssh_connect_timeout(), _want)
    # ...and the clamp holds at both ends, so a hostile or fat-fingered value cannot make the
    # panel hang forever or busy-fail.
    for _set, _want in ((0, 1), (-5, 1), (9999, 120)):
        _c = _cfgmod.load_config()
        _c["ssh_timeout"] = _set
        _cfgmod.save_config(_c)
        eq("config: ssh_timeout=%r clamps to %d" % (_set, _want),
           _sm_core._ssh_connect_timeout(), _want)
finally:
    _c = _cfgmod.load_config()
    if _sshto_saved is None:
        _c.pop("ssh_timeout", None)
    else:
        _c["ssh_timeout"] = _sshto_saved
    _cfgmod.save_config(_c)
eq("config: with no override the SSH layer uses the documented default",
   _sm_core._ssh_connect_timeout(), _cfgmod.DEFAULT_CONFIG["ssh_timeout"])
# Reads app.py AND the route modules: the line moved out with its section when register_routes
# was split, and pinning it to one file would have made this gate quietly stop checking anything.
_autoblock_src = _modsrc("app") + "".join(
    open(os.path.join(_root, "panel", "routes", _f), encoding="utf-8").read()
    for _f in sorted(os.listdir(os.path.join(_root, "panel", "routes"))) if _f.endswith(".py"))
check("config: the autoblock default is one constant, not two",
      "_AUTOBLOCK_DEFAULT_THRESHOLD), 100000)" in _autoblock_src)

# ── On-disk paths must resolve to the CHECKOUT ROOT, not to the module's own directory ──────────
# Every one of these used to be `Path(__file__).parent / …` in a module that sat at the repo root,
# where the two were the same thing. Moving the modules into panel/ silently redefined all five:
# DATA_DIR became panel/core/data/, translations/ became panel/core/translations/, and the LinuxGSM
# cache landed outside the gitignore rule written for it.
#
# The DATA_DIR one is the reason this gate exists. It raises NOTHING — the panel boots, finds no
# database where it is now looking, creates an empty one beside the code, and presents a fresh
# install while the real data/ (database, secret key, credential key, TLS certs) sits untouched one
# directory up. A factory reset with no error. It happened to a test run here before the fix.
#
# So: resolved, absolute, and compared against the repo root. Anchoring is in panel/__init__.py.
import panel as _panelpkg
from pathlib import Path as _Path
from panel.services import lgsm_data as _lgd
from panel.core import i18n as _i18n

_CHECKOUT = _Path(_root).resolve()
eq("paths: panel.REPO_ROOT is the checkout root", _panelpkg.REPO_ROOT.resolve(), _CHECKOUT)
for _label, _got, _want in (
        ("config.DATA_DIR", _cfgmod.DATA_DIR, "data"),
        ("config.DB_PATH", _cfgmod.DB_PATH, "data/panel.db"),
        ("config.SECRET_FILE", _cfgmod.SECRET_FILE, "data/secret_key"),
        ("config.CRED_KEY_FILE", _cfgmod.CRED_KEY_FILE, "data/cred_key"),
        ("config.CONFIG_FILE", _cfgmod.CONFIG_FILE, "data/config.json"),
        ("i18n translations dir", _i18n._DIR, "translations"),
        ("lgsm_data cache dir", _lgd._CACHE_DIR, "data/lgsm"),
        ("system_ops.PANEL_DIR", SO.PANEL_DIR, "."),
):
    eq("paths: %s resolves under the checkout root, not the module's own dir" % _label,
       str(_Path(_got).resolve()), str((_CHECKOUT / _want).resolve()))
# ── The package layering is one-directional, and stays that way ────────────────────────────────
# panel/ is core -> db -> security -> ops -> services. That ordering is the whole reason the
# package split is worth anything: it is what makes "where does this go?" answerable, and what
# keeps the import graph acyclic. Nothing enforces it but this.
#
# MODULE-LEVEL imports only. Two function-local imports deliberately cross the grain — auth wants
# ssh_manager.game_engine, ssh_manager wants lgsm_data's dependency list — and they are written
# lazily for exactly that reason (auth's carries the comment). A lazy import inside a function
# body costs nothing at import time and cannot make a load-order cycle, so the rule is about where
# an import SITS, not merely which module it names.
import ast as _ast_layer
_LAYERS = ["core", "db", "security", "ops", "services"]
_layer_bad = []
for _dp, _dns, _fs in os.walk(os.path.join(_root, "panel")):
    _dns[:] = [_d for _d in _dns if _d != "__pycache__"]
    _sub = os.path.basename(_dp)
    if _sub not in _LAYERS:
        continue
    for _f in _fs:
        if not _f.endswith(".py") or _f == "__init__.py":
            continue
        _tree = _ast_layer.parse(open(os.path.join(_dp, _f), encoding="utf-8").read())
        for _node in _tree.body:          # .body, not .walk: top level only, so lazy imports pass
            _names = []
            if isinstance(_node, _ast_layer.ImportFrom) and (_node.module or "").startswith("panel."):
                _names = [_node.module]
            elif isinstance(_node, _ast_layer.Import):
                _names = [_a.name for _a in _node.names if _a.name.startswith("panel.")]
            for _nm in _names:
                _target = _nm.split(".")[1]
                if _target in _LAYERS and _LAYERS.index(_target) > _LAYERS.index(_sub):
                    _layer_bad.append("panel/%s/%s imports panel.%s at module level"
                                      % (_sub, _f, _target))
check("layering: no panel package imports DOWN the stack at module level",
      not _layer_bad, "; ".join(sorted(set(_layer_bad))))

# ...and the module directories must hold no data dir of their own — the shape the bug leaves behind.
_stray = [os.path.relpath(os.path.join(_dp, _d), _root)
          for _dp, _dns, _ in os.walk(os.path.join(_root, "panel"))
          for _d in _dns if _d in ("data", "translations")]
check("paths: no stray data/ or translations/ dir was created inside panel/",
      not _stray, ", ".join(_stray))

# ── terminal.py: ONE renderer, because this had drifted into four incompatible ANSI regexes and two
# carriage-return rules that contradicted each other (each docstring calling the other wrong).
from panel.core import terminal as _term
eq("terminal: SGR colour stripped", _term.strip_escapes("\x1b[31mred\x1b[0m"), "red")
eq("terminal: erase-line stripped (an SGR-only regex left a literal '[K')",
   _term.strip_escapes("a\x1b[Kb"), "ab")
eq("terminal: private modes stripped (a CSI-only-with-letters regex left these)",
   _term.strip_escapes("\x1b[?2004ha\x1b[?1l"), "a")
eq("terminal: two-byte escapes stripped (these rendered as '>' and '=')",
   _term.strip_escapes("\x1b>a\x1b=b\x1b(Bc"), "abc")
eq("terminal: OSC window title stripped", _term.strip_escapes("\x1b]0;title\x07x"), "x")
eq("terminal: control CHARACTERS are left for the renderers", _term.strip_escapes("a\rb\bc"), "a\rb\bc")
eq("terminal: \\r overwrites from column 0", _term.apply_carriage_returns("abcdef\rXY"), "XYcdef")
eq("terminal: a line ENDING in \\r keeps its content (split('\\r')[-1] would lose it)",
   _term.apply_carriage_returns("done\r"), "done")
eq("terminal: backspaces erase", _term.apply_backspaces("ab\b\bxy"), "xy")
eq("terminal: render_line does all three", _term.render_line("\x1b[31ms\b\x1b[0msay hi\r"), "say hi")
eq("terminal: render treats \\r\\n as a line break", _term.render("a\r\nb"), "a\nb")
eq("terminal: empty input is returned unchanged", _term.render(""), "")

# ── console cleaning: Minecraft/Paper's JLine console writes ANSI escapes (incl. \x1b[K -> a visible
#    "[K"), carriage returns, and bare "> " prompt lines into its log. Strip them for display; leave
#    plain-text (Source/CoD/GMod) consoles untouched. ──
_mc_raw = ("\x1b[K[02:46:21 INFO]: UUID of player Kitty is abc\n> \n"
           "\x1b[K[02:46:21 INFO]: Connection closed\n> \n")
_mc_clean = _clean_console_text(_mc_raw)
check("console: JLine \\x1b[K erase-line removed (no visible '[K')", "[K" not in _mc_clean)
check("console: bare '> ' prompt lines dropped",
      not any(ln.strip() == ">" for ln in _mc_clean.split("\n")))
check("console: real log lines preserved",
      "[02:46:21 INFO]: UUID of player Kitty is abc" in _mc_clean
      and "[02:46:21 INFO]: Connection closed" in _mc_clean)
eq("console: ANSI colour codes stripped",
   _clean_console_text("\x1b[0;32mgreen\x1b[0m text"), "green text")
# A carriage return OVERWRITES from column 0 — it does not start a new line. Rendering it as a
# newline (the old behaviour) split JLine's prompt-erase into stray blank lines.
eq("console: \\r overwrites from column 0 instead of starting a line",
   _clean_console_text("abc\rX"), "Xbc")
eq("console: a line merely ENDING in \\r is still shown in full",
   _clean_console_text("> say hi\r"), "> say hi")
eq("console: \\r\\n is a real line break", _clean_console_text("first\r\nsecond"), "first\nsecond")
# JLine re-renders a typed command with syntax colour by erasing and rewriting it. Without applying
# backspaces every discarded attempt stays on screen: "say hi" reads as "ssasay  hi".
eq("console: backspaces erase, as a terminal would",
   _clean_console_text("> s\bsa\b\bsay hi"), "> say hi")
eq("console: two-byte escapes (ESC> / ESC=) are stripped, not shown as '>' and '=>'",
   _clean_console_text("\x1b[?1l\x1b>\x1b[?1000l\x1b=\x1b[?2004hdone"), "done")
eq("console: an OSC window-title sequence is stripped",
   _clean_console_text("\x1b]0;a title\x07ready"), "ready")
# The real thing: bytes taken verbatim from the panel's own Minecraft console log, where a typed
# "say hi" rendered as "> ssasay  hi" followed by ">=>" noise.
_jline_real = ("> s\b\x1b[31msa\x1b[0m\x1b[K\b\bsay\x1b[K\x1b[31m \x1b[0m\b \x1b[36mh\x1b[0m"
               "\x1b[K\x1b[36mi\x1b[0m\r\r\n"
               "\x1b[?1l\x1b>\x1b[?1000l\x1b[?2004l\x1b[?1h\x1b=\x1b[?2004h> \r\x1b[K"
               "[23:52:54 INFO]: [Not Secure] [Server] hi\r\n")
_jline_clean = _clean_console_text(_jline_real)
eq("console: a real JLine command echo renders as typed",
   [ln for ln in _jline_clean.split("\n") if ln.strip()],
   ["> say hi", "[23:52:54 INFO]: [Not Secure] [Server] hi"])
check("console: no control characters survive to the browser",
      not any(ord(c) < 32 and c != "\n" for c in _jline_clean), repr(_jline_clean[:80]))
eq("console: an echoed command line ('> list') is kept",
   _clean_console_text("> list"), "> list")
eq("console: plain Source/CoD line untouched",
   _clean_console_text("L 01/01/2026 - 12:00: player connected"),
   "L 01/01/2026 - 12:00: player connected")
eq("console: empty input -> empty", _clean_console_text(""), "")

# ── safe int parsing (a non-numeric port must not raise) ──────
eq("_int_or valid", _int_or("2222", 22), 2222)
eq("_int_or blank -> default", _int_or("", 22), 22)
eq("_int_or junk -> default", _int_or("abc", 22), 22)
eq("_int_or None -> default", _int_or(None, 5000), 5000)
eq("_int_or whitespace", _int_or("  80 ", 1), 80)

# ── per-user layout order: _apply_user_order is the single chokepoint every page's ordering goes
# through, so its edge cases are the whole feature's correctness. "No saved order" MUST mean "the
# list you passed in, untouched" — that is what keeps the default layout the default.
_ord_items = [NS(id=1), NS(id=2), NS(id=3), NS(id=4)]
_ids = lambda seq: [o.id for o in seq]
eq("order: no saved order leaves the default alone", _ids(_apply_user_order(_ord_items, None)), [1, 2, 3, 4])
eq("order: empty saved order leaves the default alone", _ids(_apply_user_order(_ord_items, [])), [1, 2, 3, 4])
eq("order: a full saved order is applied", _ids(_apply_user_order(_ord_items, [3, 1, 4, 2])), [3, 1, 4, 2])
eq("order: items missing from the order keep their default order, after the ordered ones",
   _ids(_apply_user_order(_ord_items, [4, 2])), [4, 2, 1, 3])
eq("order: ids that no longer exist are ignored (a host was deleted)",
   _ids(_apply_user_order(_ord_items, [99, 3, 42, 1])), [3, 1, 2, 4])
eq("order: junk entries are skipped, the rest still applies",
   _ids(_apply_user_order(_ord_items, ["2", None, {}, 1])), [2, 1, 3, 4])
eq("order: a duplicated id does not displace its first position",
   _ids(_apply_user_order(_ord_items, [3, 1, 3])), [3, 1, 2, 4])
eq("order: an all-junk order is the same as no order", _ids(_apply_user_order(_ord_items, ["x", None])),
   [1, 2, 3, 4])
check("order: the input list is never mutated in place",
      (_apply_user_order(_ord_items, [4, 3, 2, 1]) is not _ord_items) and _ids(_ord_items) == [1, 2, 3, 4])
eq("order: a custom key function is honoured (ordering by something other than .id)",
   [o.rid for o in _apply_user_order([NS(rid=7), NS(rid=8)], [8, 7], key=lambda o: o.rid)], [8, 7])
# Per-host server order. The dashboard slices ONE flat list per host, so this pass must reorder each
# host's members WITHOUT disturbing anything else about the list — a host with no saved order, and the
# positions the other hosts occupy, both have to come out untouched.
_srv = lambda i, r: NS(id=i, remote_id=r)
_mixed = [_srv(10, 1), _srv(11, 2), _srv(12, 1), _srv(13, 2), _srv(14, 1)]
_sids = lambda seq: [o.id for o in seq]
eq("server order: no saved order leaves the list alone", _sids(_apply_user_server_order(_mixed, {})),
   [10, 11, 12, 13, 14])
eq("server order: a junk pref value leaves the list alone",
   _sids(_apply_user_server_order(_mixed, {"server_order": "not a dict"})), [10, 11, 12, 13, 14])
eq("server order: one host is reordered within its own slots, other hosts untouched",
   _sids(_apply_user_server_order(_mixed, {"server_order": {"1": [14, 12, 10]}})),
   [14, 11, 12, 13, 10])
eq("server order: two hosts reordered independently",
   _sids(_apply_user_server_order(_mixed, {"server_order": {"1": [12, 10, 14], "2": [13, 11]}})),
   [12, 13, 10, 11, 14])
eq("server order: a host with no entry keeps its default order",
   _sids(_apply_user_server_order(_mixed, {"server_order": {"2": [13, 11]}})),
   [10, 13, 12, 11, 14])
eq("server order: ids from another host cannot pull a server across hosts",
   _sids(_apply_user_server_order(_mixed, {"server_order": {"1": [11, 13, 14]}})),
   [14, 11, 10, 13, 12])
eq("server order: an int key (not the JSON string key) is ignored, not crashed on",
   _sids(_apply_user_server_order(_mixed, {"server_order": {1: [14, 12, 10]}})),
   [10, 11, 12, 13, 14])
check("server order: the input list is not mutated",
      (_apply_user_server_order(_mixed, {"server_order": {"1": [14, 10, 12]}}) is not _mixed)
      and _sids(_mixed) == [10, 11, 12, 13, 14])
# ui_prefs accessors: a corrupt or NULL blob must degrade to the default layout, never raise into a
# page render, and only whitelisted keys may take effect (a retired key stops working on upgrade).
_UsrP = __import__("panel.db.models", fromlist=["User"]).User
_up = _UsrP()
check("ui_prefs: unset column reads as no preferences", _up.get_ui_prefs() == {})
_up.ui_prefs = "not json at all"
check("ui_prefs: a corrupt blob reads as no preferences", _up.get_ui_prefs() == {})
_up.ui_prefs = '["a","list","not","a","dict"]'
check("ui_prefs: a non-object blob reads as no preferences", _up.get_ui_prefs() == {})
_up.ui_prefs = '{"host_order": [2, 1], "evil_key": "x"}'
check("ui_prefs: only whitelisted keys are returned",
      _up.get_ui_prefs() == {"host_order": [2, 1]})
_up.set_ui_pref("host_order", [3, 2])
check("ui_prefs: set writes a whitelisted key", _up.get_ui_prefs()["host_order"] == [3, 2])
_up.set_ui_pref("not_a_key", [1])
check("ui_prefs: set ignores a non-whitelisted key", "not_a_key" not in _up.get_ui_prefs())
_up.set_ui_pref("host_order", None)
check("ui_prefs: clearing a key restores the default (absent, not empty)",
      _up.get_ui_prefs() == {} and "host_order" not in (_up.ui_prefs or ""))

# ── new-user language: Settings holds a concrete language code. It used to allow a blank
# "creator's language" value which read as English anyway — confusing on the page, so it is gone.
from app import (_new_user_language as _nul)
_LANGS = {"en": "English", "es": "Espanol", "fr": "Francais"}
eq("new-user lang: the configured language is used", _nul({"default_language": "fr"}, _LANGS), "fr")
eq("new-user lang: English when configured so", _nul({"default_language": "en"}, _LANGS), "en")
eq("new-user lang: a blank left over from an older install reads as English",
   _nul({"default_language": ""}, _LANGS), "en")
eq("new-user lang: a missing key reads as English", _nul({}, _LANGS), "en")
eq("new-user lang: a language no longer supported cannot be assigned",
   _nul({"default_language": "de"}, _LANGS), "en")
eq("new-user lang: junk in the config cannot be assigned", _nul({"default_language": 42}, _LANGS), "en")

# ── the install default layout: a superadmin's published arrangement sits UNDER each user's own, and
# the merge is per-KEY so someone who only reordered their tiles still gets the house host order.
from panel.db.prefs import (_effective_prefs as _ep)
_U = lambda prefs: NS(is_authenticated=True, get_ui_prefs=lambda: prefs)
eq("default: no default and no user prefs -> nothing", _ep(_U({}), {}), {})
eq("default: the install default applies when the user has none",
   _ep(_U({}), {"default_ui_prefs": {"host_order": [2, 1]}}), {"host_order": [2, 1]})
eq("default: the user's own key wins over the default",
   _ep(_U({"host_order": [1, 2]}), {"default_ui_prefs": {"host_order": [2, 1]}}),
   {"host_order": [1, 2]})
eq("default: merge is per-key, not all-or-nothing",
   _ep(_U({"panels": {"dash_tiles": ["host"]}}),
       {"default_ui_prefs": {"host_order": [2, 1], "panels": {"dash_tiles": ["total"]}}}),
   {"host_order": [2, 1], "panels": {"dash_tiles": ["host"]}})
eq("default: a non-whitelisted key in the published default is ignored",
   _ep(_U({}), {"default_ui_prefs": {"host_order": [1], "evil": "x"}}), {"host_order": [1]})
eq("default: a junk default is ignored", _ep(_U({}), {"default_ui_prefs": "nope"}), {})
eq("default: an anonymous visitor still gets the house layout",
   _ep(NS(is_authenticated=False), {"default_ui_prefs": {"host_order": [3]}}), {"host_order": [3]})


class _BoomPrefs:
    is_authenticated = True

    def get_ui_prefs(self):
        raise RuntimeError("db gone")


eq("default: a failure reading user prefs falls back to the house layout, no raise",
   _ep(_BoomPrefs(), {"default_ui_prefs": {"host_order": [9]}}), {"host_order": [9]})

# ── movable panels: _panel_layout decides what a page renders and in what order. The safety property
# is that it can only ever return keys the PAGE declared — several panels are permission-gated, so a
# stored key must never be able to conjure one.
from panel.db.prefs import (_clean_panel_map as _cpm, _panel_layout as _pl)
_KEYS = ["total", "online", "offline", "players", "host"]
eq("panels: no prefs -> the page's own default order", _pl({}, "dash_tiles", _KEYS), (_KEYS, []))
eq("panels: a saved order is applied",
   _pl({"panels": {"dash_tiles": ["host", "total"]}}, "dash_tiles", _KEYS),
   (["host", "total", "online", "offline", "players"], []))
eq("panels: a key the page did not declare cannot appear",
   _pl({"panels": {"dash_tiles": ["evil_panel", "host"]}}, "dash_tiles", _KEYS),
   (["host", "total", "online", "offline", "players"], []))
eq("panels: a hidden key is removed from visible and reported as hidden",
   _pl({"hidden": {"dash_tiles": ["offline"]}}, "dash_tiles", _KEYS),
   (["total", "online", "players", "host"], ["offline"]))
eq("panels: hiding an undeclared key is a no-op",
   _pl({"hidden": {"dash_tiles": ["nope"]}}, "dash_tiles", _KEYS), (_KEYS, []))
eq("panels: another region's layout does not leak in",
   _pl({"panels": {"other": ["host"]}}, "dash_tiles", _KEYS), (_KEYS, []))
eq("panels: junk pref shapes fall back to the default",
   _pl({"panels": "nope", "hidden": 7}, "dash_tiles", _KEYS), (_KEYS, []))
eq("panels: a duplicated key is not rendered twice",
   _pl({"panels": {"dash_tiles": ["host", "host", "total"]}}, "dash_tiles", _KEYS),
   (["host", "total", "online", "offline", "players"], []))
eq("panels: a panel added by a NEW version appears for an existing user",
   _pl({"panels": {"dash_tiles": ["host", "total"]}}, "dash_tiles", _KEYS + ["brand_new"]),
   (["host", "total", "online", "offline", "players", "brand_new"], []))
eq("panels: an empty declared list renders nothing", _pl({"panels": {"dash_tiles": ["host"]}},
   "dash_tiles", []), ([], []))
# _clean_panel_map guards what gets STORED: cosmetic data, so junk is dropped, not rejected.
eq("panels: a clean map survives", _cpm({"dash_tiles": ["total", "host"]}), {"dash_tiles": ["total", "host"]})
eq("panels: non-dict input -> empty", _cpm("nope"), {})
eq("panels: a bad region name is dropped", _cpm({"Bad Region!": ["total"]}), {})
eq("panels: bad keys are dropped, good ones kept",
   _cpm({"dash_tiles": ["total", "<script>", "", 42, "host"]}), {"dash_tiles": ["total", "host"]})
eq("panels: duplicate keys are collapsed", _cpm({"r": ["a", "a", "b"]}), {"r": ["a", "b"]})
check("panels: key count is capped", len(_cpm({"r": ["k%d" % i for i in range(200)]})["r"]) == 60)
check("panels: region count is capped", len(_cpm({"r%d" % i: ["a"] for i in range(50)})) == 20)

# ── tags: the name charset is pinned at the DATA layer, so no route can store one that would need
# escaping to be safe in HTML, in a filter key, or in alert text.
_TagM = __import__("panel.db.models", fromlist=["ServerTag"]).ServerTag
for _good in ("production", "PvE", "source games", "cs-1.6", "v2.0_beta", "A"):
    try:
        _TagM(name=_good)
        _ok = True
    except ValueError:
        _ok = False
    check("tag name accepted: %r" % _good, _ok)
for _bad in ("<script>", "drop; table", "tag'name", 'tag"name', " leading", "", "x" * 33,
             "emoji🎮", "back\\slash", "semi;colon"):
    try:
        _TagM(name=_bad)
        _rej = False
    except ValueError:
        _rej = True
    check("tag name rejected: %r" % _bad, _rej)
# _alerts_muted: any tag saying "don't alert" wins, and it must never raise inside a poller thread.
from panel.services.notifications import alerts_muted as _am   # moved out of app.py in #93
_tg = lambda n: NS(notify=n)
check("mute: no tags -> not muted", _am(NS(tags=[], short_name="s")) is False)
check("mute: all tags notify -> not muted", _am(NS(tags=[_tg(True), _tg(True)], short_name="s")) is False)
check("mute: one muting tag wins", _am(NS(tags=[_tg(True), _tg(False)], short_name="s")) is True)
check("mute: None tags -> not muted", _am(NS(tags=None, short_name="s")) is False)


class _BoomTags:
    short_name = "boom"

    @property
    def tags(self):
        raise RuntimeError("db gone")


check("mute: a failure fails OPEN (alert still sent, no raise)", _am(_BoomTags()) is False)

# ── transports must decode leniently: command output is GAME SERVER output (player names, mod
# chatter, latin-1 logs), so it is not guaranteed valid UTF-8. A strict decode raises inside
# subprocess, gets swallowed by the generic handler, and returns ("", ..., -1) — a caller then
# cannot tell "printed nothing" from "could not be decoded". The paramiko path already used
# errors="replace"; these two did not.
_bad_out, _bad_err, _bad_rc = _sm_core._run_local(r"printf 'caf\351: cannot start\n'", timeout=10, sudo=False)
check("transport (local): invalid UTF-8 in stdout still returns the text",
      _bad_rc == 0 and _bad_out.startswith("caf") and "cannot start" in _bad_out)
check("transport (local): the undecodable byte becomes U+FFFD, not a lost result",
      "�" in _bad_out and _bad_out != "")
_bad2_out, _bad2_err, _bad2_rc = _sm_core._run_local(r"printf 'x\200y\n' >&2; printf 'ok\n'",
                                               timeout=10, sudo=False)
check("transport (local): invalid UTF-8 on stderr does not blank stdout",
      _bad2_rc == 0 and _bad2_out == "ok" and _bad2_err.startswith("x"))
_sshkw = {}


class _FakeCompleted:
    stdout = "out"
    stderr = ""
    returncode = 0


_orig_sprun = _sm_core.subprocess.run
try:
    _sm_core.subprocess.run = lambda cmd, **kw: (_sshkw.update(kw), _FakeCompleted())[1]
    _sm_core._run_via_ssh_cli(type("S", (), {"sudo_enabled": False, "linuxgsm_user": None, "port": 22,
                                       "username": "u", "host": "h", "auth_method": "tailscale"})(),
                        "echo hi", timeout=5, sudo=False)
finally:
    _sm_core.subprocess.run = _orig_sprun
check("transport (ssh cli): decodes with errors='replace' like the other two",
      _sshkw.get("errors") == "replace" and _sshkw.get("encoding") == "utf-8"
      and _sshkw.get("text") is True)

# ── cron manager (pure logic; no crontab touched) ─────────────
# schedule validation
check("cron: 5-field ok", _sm_cron._validate_cron("*/5 * * * *", "/bin/true")[0])
check("cron: @daily ok", _sm_cron._validate_cron("@daily", "/home/gm/backup.sh")[0])
check("cron: @reboot ok", _sm_cron._validate_cron("@reboot", "echo hi")[0])
check("cron: ranges/steps ok", _sm_cron._validate_cron("0-30/2 1,3 * * mon-fri", "x")[0])
check("cron: normalises inner ws", _sm_cron._validate_cron("0   5  *  *  *", "x")[2] == "0 5 * * * x")
check("cron: 4 fields rejected", not _sm_cron._validate_cron("* * * *", "x")[0])
check("cron: bad @shortcut rejected", not _sm_cron._validate_cron("@sometimes", "x")[0])
check("cron: empty command rejected", not _sm_cron._validate_cron("@daily", "")[0])
check("cron: newline in command rejected", not _sm_cron._validate_cron("@daily", "a\nb")[0])
check("cron: embedded CR rejected", not _sm_cron._validate_cron("@daily", "a\rb")[0])
check("cron: embedded CR in schedule rejected", not _sm_cron._validate_cron("0 5 *\r* *", "x")[0])
check("cron: shell metachars allowed in command", _sm_cron._validate_cron("@daily", "a && b | c")[0])
# NOTHING is locked any more — every line is editable/deletable, including the panel-installed ones.
check("cron: monitor is NOT managed (editable/deletable)",
      not _sm_cron._cron_line_managed("*/5 * * * * /home/gm/gmodserver monitor > /dev/null 2>&1", "gm", "gmodserver"))
check("cron: daily-restart flag is NOT managed (editable/deletable)",
      not _sm_cron._cron_line_managed("0 5 * * * touch /home/gm/.restart-pending", "gm", "gmodserver"))
check("cron: legacy @reboot start is NOT managed (deletable)",
      not _sm_cron._cron_line_managed("@reboot /home/gm/gmodserver start > /dev/null 2>&1", "gm", "gmodserver"))
check("cron: user backup line is NOT managed",
      not _sm_cron._cron_line_managed("0 3 * * * /home/gm/backup.sh", "gm", "gmodserver"))
# _cron_role gives panel lines a non-blocking LABEL so the admin knows what they are.
check("cron role: monitor is labelled 'autostart'",
      _sm_cron._cron_role("/home/gm/gmodserver monitor", "gm", "gmodserver") == "autostart")
check("cron role: a .restart-pending line is labelled 'daily-restart'",
      _sm_cron._cron_role("[ -f /home/gm/.restart-pending ] && /home/gm/gmodserver restart", "gm", "gmodserver") == "daily-restart")
check("cron role: update / user jobs carry no label",
      _sm_cron._cron_role("/home/gm/gmodserver update", "gm", "gmodserver") == ""
      and _sm_cron._cron_role("/home/gm/backup.sh", "gm", "gmodserver") == "")
# _wrap_cron_command keeps the monitor marker VISIBLE (inline recorder) so a reschedule doesn't hide it
# from the Autostart detection; the .restart-pending line stays verbatim; a `%` command uses base64.
_wmon = _sm_cron._wrap_cron_command(None, "gm", "/home/gm/gmodserver monitor")
check("cron wrap: a plain command (monitor) stays visible, not base64-hidden",
      "/home/gm/gmodserver monitor" in _wmon and ".lgsm-cron/run " not in _wmon)
check("cron wrap: the .restart-pending flag line is kept verbatim",
      _sm_cron._wrap_cron_command(None, "gm", "[ -f /home/gm/.restart-pending ] && x")
      == "[ -f /home/gm/.restart-pending ] && x")
_orig_wrap_rc = _sm_core.run_command
try:
    _sm_core.run_command = lambda *a, **k: ("", "", 0)   # _install_cron_runner touches SSH on the base64 path
    _wpct = _sm_cron._wrap_cron_command(None, "gm", "echo %H")
    check("cron wrap: a '%' command uses the base64 runner (cron-safe)",
          ".lgsm-cron/run " in _wpct and "%H" not in _wpct)
finally:
    _sm_core.run_command = _orig_wrap_rc

# node-tools auto-update: a weekly ROOT cron keeps npm + gamedig (player-query tools) current.
check("node-tools: the cron updates npm + gamedig weekly and logs it",
      "npm install -g npm gamedig" in _sm_hosts._NODE_TOOLS_CRON
      and _sm_hosts._NODE_TOOLS_CRON.lstrip().startswith("#")
      and "/var/log/lgsm-node-tools.log" in _sm_hosts._NODE_TOOLS_CRON
      and _privmod.WRITE_TARGETS["node-tools-cron"][0] == "/etc/cron.d/lgsm-node-tools")
_ntc = {}
_orig_ntc_rc = _sm_core.run_command
try:
    # This used to assert the command started with "sudo bash -c". It now goes through the
    # write-file verb, so what matters is the DESTINATION NAME and the content — the path is the
    # table's, not the call site's, and on a remote host the base64 form is still what is sent.
    _sm_core.run_command = lambda s, c, **k: (_ntc.__setitem__("cmd", c), ("", "", 0))[1]
    _ntc_ok = _sm_hosts.ensure_node_tools_cron(object())
    check("node-tools: ensure writes the cron.d file as root, at the table's path",
          _ntc_ok is True and "/etc/cron.d/lgsm-node-tools" in _ntc["cmd"], _ntc.get("cmd", "")[:80])
    check("node-tools: the cron body is base64-piped + chmod 644 (no quoting/`%` hazards)",
          "base64 -d" in _ntc["cmd"] and "chmod 644" in _ntc["cmd"])
    check("node-tools: the cron path has ONE definition — the write target",
          not hasattr(sm, "_NODE_TOOLS_CRON_PATH"),
          "ssh_manager still keeps a second copy of the path")
finally:
    _sm_core.run_command = _orig_ntc_rc

# ── UFW port/protocol validation (both interpolate into a ROOT shell command) ──
eq("ufw: tcp normalises", _sm_hosts._ufw_proto("tcp"), "tcp")
eq("ufw: UDP case-folds", _sm_hosts._ufw_proto("UDP"), "udp")
eq("ufw: blank -> both", _sm_hosts._ufw_proto(""), "both")
eq("ufw: None -> both", _sm_hosts._ufw_proto(None), "both")
eq("ufw: 'any' -> both", _sm_hosts._ufw_proto("any"), "both")
check("ufw: injection protocol rejected", _sm_hosts._ufw_proto("tcp; rm -rf /") is None)
check("ufw: unknown protocol rejected", _sm_hosts._ufw_proto("sctp") is None)
eq("ufw: valid port coerced to int", _sm_hosts._ufw_port_int("27015"), 27015)


def _priv_err_for(verb, args):
    """The VerbError text privileged.py produces for these arguments, or "" if it accepts them."""
    from panel.security import privileged as _p
    try:
        _p.check_args(verb, args)
        return ""
    except _p.VerbError as e:
        return str(e)


def _ufw_raises_verb(fn):
    from panel.security import privileged as _p
    try:
        fn()
        return False
    except _p.VerbError:
        return True


def _ufw_raises_fnf(fn, *a):
    try:
        fn(*a)
        return False
    except FileNotFoundError:
        return True


def _ufw_raises(fn):
    try:
        fn()
        return False
    except (TypeError, ValueError):
        return True


check("ufw: non-numeric port rejected", _ufw_raises(lambda: _sm_hosts._ufw_port_int("22; reboot")))
check("ufw: port 0 rejected", _ufw_raises(lambda: _sm_hosts._ufw_port_int(0)))
check("ufw: port 70000 rejected", _ufw_raises(lambda: _sm_hosts._ufw_port_int(70000)))
# End-to-end: a malicious protocol/port must NOT reach run_command (no shell runs).
_orig_ufw_rc, _orig_ufw_rp = _sm_core.run_command, _sm_core.run_privileged
try:
    _ufw_calls = []
    _sm_core.run_command = lambda *a, **k: (_ufw_calls.append(a), ("", "", 0))[1]
    _sm_core.run_privileged = lambda *a, **k: (_ufw_calls.append(a), ("", "", 0))[1]
    _ok, _m = _sm_hosts.remote_ufw_open_port(None, 27015, "tcp; touch /tmp/x #")
    check("ufw: open rejects injection proto, runs nothing", _ok is False and not _ufw_calls)
    _ok, _m = _sm_hosts.remote_ufw_close_port(None, "22; reboot", "tcp")
    check("ufw: close rejects injection port, runs nothing", _ok is False and not _ufw_calls)
finally:
    _sm_core.run_command, _sm_core.run_privileged = _orig_ufw_rc, _orig_ufw_rp

# ── shell-identifier validation (usernames/short_names reach ssh + shell) ──
from panel.db.models import _validate_shell_ident as _vsi
check("ident: normal value accepted", _vsi("k", "gmodserver") == "gmodserver")
check("ident: internal dash/dot/underscore ok", _vsi("k", "game-1.beta_2") == "game-1.beta_2")
check("ident: empty allowed (optional field)", _vsi("k", "") == "")
check("ident: leading dash rejected (ssh option-injection guard)",
      _ufw_raises(lambda: _vsi("k", "-oProxyCommand=x")))
check("ident: leading dot rejected", _ufw_raises(lambda: _vsi("k", ".hidden")))
check("ident: shell metachar rejected", _ufw_raises(lambda: _vsi("k", "a;b")))

# ── Tailscale bootstrap: user-supplied auth_key/routes/tags are REFUSED, not quoted ────────────
# These three used to assert that each value was shell-quoted into a root command — the best you
# can do when the value has to reach a shell. It does not any more: they are validated arguments,
# so the assertion is now the stronger one. A route that is not a network and a tag that is not
# `tag:name` never become part of anything.
_orig_ts_rc, _orig_ts_rp = _sm_core.run_command, _sm_core.run_privileged
try:
    _ts_calls = []
    _sm_core.run_command = lambda s, c, **k: ("ok", "", 0)
    _sm_core.run_privileged = lambda s, v, a=(), **k: (_ts_calls.append((v, list(a))),
                                                 ("Status: inactive", "", 0))[1]
    _sm_hosts.remote_bootstrap_tailscale(None, auth_key="tskey; touch /tmp/x",
                                  advertise_routes="1.2.3.0/24; reboot", tags="tag:x; rm -rf /")
    _ts_up = [a for v, a in _ts_calls if v == "tailscale-up-key"]
    check("tailscale: the join goes through the verb, not a composed command", _ts_up, str(_ts_calls))
    for _i, _label in ((0, "auth_key"), (2, "routes"), (3, "tags")):
        check("tailscale: an injected %s is refused by privileged.py, not quoted into a command"
              % _label,
              _ts_up and _ufw_raises_verb(
                  lambda a=_ts_up[0]: _privmod.check_args("tailscale-up-key", a)),
              str(_ts_up[:1]))
    # And the clean case is accepted, so the validators are not simply refusing everything.
    check("tailscale: a well-formed key, route and tag ARE accepted",
          _privmod.check_args("tailscale-up-key",
                           ["tskey-auth-abc123def", "yes", "10.0.0.0/24", "tag:server"])
          == ["tskey-auth-abc123def", "yes", "10.0.0.0/24", "tag:server"])
    # The probe must CONTAIN the secret-shaped text, or "the secret is absent from the error" is
    # true for the boring reason. A previous version used "bad key!", which contains no key at all
    # — so a mutation that echoed the value back passed.
    _SECRET = "tskey-auth-SUPERSECRET!"          # the "!" is what makes it invalid
    _err = _priv_err_for("tailscale-up-key", [_SECRET, "no", "-", "-"])
    check("tailscale: the rejection actually fires for this probe", _err != "", _err)
    check("tailscale: a rejected auth key is never echoed back — it is a secret",
          "SUPERSECRET" not in _err and "tskey" not in _err, _err)
finally:
    _sm_core.run_command, _sm_core.run_privileged = _orig_ts_rc, _orig_ts_rp

# ── apt dependency names parsed from LinuxGSM output get interpolated into
#    `apt-get install <pkgs>`, so parse_missing_deps is a security filter, not just a parser. ──
eq("parse_missing_deps: extracts valid package names",
   _sm_hosts.parse_missing_deps("log line\nMissing dependencies: libssl-dev lib32gcc-s1 gcc:i386  Run: x\n"),
   ["libssl-dev", "lib32gcc-s1", "gcc:i386"])
eq("parse_missing_deps: drops shell-metachar tokens (injection guard)",
   _sm_hosts.parse_missing_deps("Missing dependencies: good $(reboot) a;b `id` also-good\n"),
   ["good", "also-good"])
eq("parse_missing_deps: no marker -> []", _sm_hosts.parse_missing_deps("nothing to see here"), [])

# ── upload collisions: the browser must be able to ask "replace this?" with real facts ──────────
# stat_upload_targets lists the directory ONCE and filters locally, so the parsing is where this
# can go wrong: tab-separated fields, an epoch mtime that find prints as a float, and a filename
# that may itself contain a tab (which is why the name is last and re-joined).
class _FakeSrv:
    is_local, auth_method, sudo_enabled = True, "local", False
    host, port, username, linuxgsm_user = "127.0.0.1", 22, "u", ""


_orig_up_rc = _sm_core.run_command
try:
    _FIND_OUT = "\n".join([
        "f\t1234\t1700000000.1234567890\tserver.cfg",
        "d\t4096\t1700000100.0000000000\taddons",
        "f\t0\t1700000200.5000000000\tempty.txt",
        "f\t77\t1700000300.0000000000\ttab\tname.cfg",   # a filename containing a tab
    ])
    _sm_core.run_command = lambda *a, **k: (_FIND_OUT, "", 0)
    _hits = _sm_files.stat_upload_targets(_FakeSrv(), "csgoserver", "", ["server.cfg", "nope.txt", "addons"])
    eq("stat_upload_targets: only names that exist come back",
       [h["name"] for h in _hits], ["server.cfg", "addons"])
    _byname = {h["name"]: h for h in _hits}
    eq("stat_upload_targets: size is parsed", _byname["server.cfg"]["size"], 1234)
    eq("stat_upload_targets: a float epoch mtime becomes an int",
       _byname["server.cfg"]["mtime"], 1700000000)
    check("stat_upload_targets: a directory is flagged, so the UI can refuse to replace it",
          _byname["addons"]["is_dir"] is True and _byname["server.cfg"]["is_dir"] is False)
    eq("stat_upload_targets: a zero-byte file still counts as existing",
       [h["name"] for h in _sm_files.stat_upload_targets(_FakeSrv(), "u", "", ["empty.txt"])], ["empty.txt"])
    eq("stat_upload_targets: a filename containing a tab survives the split",
       [h["name"] for h in _sm_files.stat_upload_targets(_FakeSrv(), "u", "", ["tab\tname.cfg"])],
       ["tab\tname.cfg"])
    eq("stat_upload_targets: a duplicate name is reported once",
       len(_sm_files.stat_upload_targets(_FakeSrv(), "u", "", ["server.cfg", "server.cfg"])), 1)
    eq("stat_upload_targets: the name is basename'd, matching what upload_file writes",
       [h["name"] for h in _sm_files.stat_upload_targets(_FakeSrv(), "u", "", ["sub/server.cfg"])],
       ["server.cfg"])
    check("stat_upload_targets: a traversal attempt returns None, not a listing",
          _sm_files.stat_upload_targets(_FakeSrv(), "u", "../../etc", ["passwd"]) is None)

    # The host-side symlink guard. _safe_abspath is lexical and cannot see a symlink planted under
    # the game user's home, so every file operation now carries a realpath check that runs WHERE
    # THE PATH IS. Assert the guard is actually attached and that its sentinel is honoured.
    _cmds = []
    _sm_core.run_command = lambda s, c, **k: (_cmds.append(c), ("", "", 0))[1]
    _sm_files.browse_dir(_FakeSrv(), "csgoserver", "cfg")
    check("symlink guard: browse_dir resolves the path on the host before listing it",
          _cmds and "realpath -m" in _cmds[0] and "__OUTSIDE_HOME__" in _cmds[0], str(_cmds)[:150])
    _sm_core.run_command = lambda s, c, **k: ("__OUTSIDE_HOME__", "", 9)
    check("symlink guard: a path that escapes home is refused by browse_dir",
          _sm_files.browse_dir(_FakeSrv(), "csgoserver", "escape") is None)
    check("symlink guard: ...and by read_file",
          _sm_files.read_file(_FakeSrv(), "csgoserver", "escape/x")[1] == "Invalid path")
    check("symlink guard: ...and by delete_path",
          _sm_files.delete_path(_FakeSrv(), "csgoserver", "escape/x")[0] is False)
    check("symlink guard: ...and by stat_upload_targets",
          _sm_files.stat_upload_targets(_FakeSrv(), "csgoserver", "escape", ["x"]) is None)
    check("symlink guard: ...and no bytes are written through one",
          _sm_files.upload_file(_FakeSrv(), "csgoserver", "escape", "x", b"d", overwrite=True)[0] is False)

    # models' @validates fires on ASSIGNMENT only, so a row written before it existed reaches the
    # shell unchecked. _safe_abspath is the choke point every file op goes through, so it re-checks.
    for _bad in ("a b", "a;rm -rf /", "$(id)", "-oProxyCommand=x", "", "x" * 65):
        check("unix user %r is refused at the point of use" % _bad[:14],
              _sm_files._safe_abspath(_bad, "cfg") is None)
    check("a legitimate unix user still resolves",
          _sm_files._safe_abspath("csgoserver", "cfg") == "/home/csgoserver/cfg")
    _sm_core.run_command = lambda *a, **k: ("", "", 0)
    eq("stat_upload_targets: no output means nothing exists",
       _sm_files.stat_upload_targets(_FakeSrv(), "u", "", ["server.cfg"]), [])
    _sm_core.run_command = lambda *a, **k: (_FIND_OUT, "", 0)

    # ── upload cost is ROUND TRIPS, not bytes ─────────────────────────────────────────────────
    # Every run_command is a separate SSH exec, and writing one file used to take at least three:
    # mkdir, a base64 chunk, then the decode. Uploading a folder of several hundred small Lua files
    # is then minutes of pure latency doing almost no work — reported as "it only uploads 1 at a
    # time seems kinda slow". A file small enough for one command now takes exactly one, which is
    # essentially every config, script and Lua file a game server holds.
    _wcalls = []
    _sm_core.run_command = lambda s, c, **k: (_wcalls.append(c), ("", "", 0))[1]
    _sm_files._write_file_as_user(_FakeSrv(), "csgoserver", "/home/csgoserver/addons/gm/init.lua", b"L" * 2048)
    eq("upload: a small file costs ONE ssh round trip (was three)", len(_wcalls), 1)
    _one = _wcalls[0] if _wcalls else ""
    check("upload: ...and that single command still carries the home-dir guard",
          "realpath -m" in _one and "__OUTSIDE_HOME__" in _one, _one[:110])
    check("upload: ...still creates the parent directory", "mkdir -p" in _one, _one[:110])
    # The old form decoded straight over the destination, so a failure part-way left the real file
    # truncated. A rename inside the same directory is atomic: old file, or whole new file.
    check("upload: ...and lands the file with an atomic rename, never a partial overwrite",
          "mv -f" in _one and "base64 -d > '/home/csgoserver/addons/gm/init.lua'" not in _one,
          _one[-90:])
    check("upload: the single command stays well inside the 128 KB limit on one argv entry",
          len(_one) < 120000, "%d bytes" % len(_one))
    # A file too big for one command still streams in chunks rather than being refused.
    _wcalls.clear()
    _ok_big, _ = _sm_files._write_file_as_user(_FakeSrv(), "csgoserver", "/home/csgoserver/big.vpk", b"B" * (200 * 1024))
    check("upload: a large file still chunks (and is not refused)",
          _ok_big is True and len(_wcalls) > 1, "%r %d calls" % (_ok_big, len(_wcalls)))
    check("upload: the large path guards its FIRST command, before any byte is written",
          "realpath -m" in _wcalls[0], _wcalls[0][:110])

    # The server-side half: overwrite is opt-in. The UI asks first, but check and write are two
    # round trips, so a file that appears in between must be refused rather than clobbered.
    _calls = []
    _sm_core.run_command = lambda s, c, **k: (_calls.append(c), ("__YES__", "", 0))[1]
    _ok, _msg = _sm_files.upload_file(_FakeSrv(), "csgoserver", "", "server.cfg", b"data", overwrite=False)
    check("upload_file: refuses an existing target when overwrite was not granted",
          _ok is False and _msg == _sm_files.UPLOAD_EXISTS, "%r %r" % (_ok, _msg))
    # ".paneltmp", not "printf": the symlink guard's realpath fallback legitimately uses printf,
    # so that word no longer means "a write happened". The staging file name only ever appears on
    # the write path.
    check("upload_file: and writes nothing on that path",
          not any("base64 -d" in c or ".paneltmp" in c for c in _calls), str(_calls)[:160])
    _calls.clear()
    _sm_core.run_command = lambda s, c, **k: (_calls.append(c), ("", "", 0))[1]
    _ok2, _ = _sm_files.upload_file(_FakeSrv(), "csgoserver", "", "server.cfg", b"data", overwrite=False)
    check("upload_file: a free name still uploads with overwrite=False",
          _ok2 is True and any("base64 -d" in c for c in _calls), "%r" % _ok2)
finally:
    _sm_core.run_command = _orig_up_rc


# ── downloads: stat_path decides file-vs-archive and the Content-Length, stream_path moves bytes ──
# The editor's read is text-only, 1 MB-capped and refuses a binary. A download is the opposite
# shape, so it is a separate pair of functions — and the pair is where a path could escape the
# game user's home, so the guard and the transport choice are both pinned here.
_orig_dl_rc = _sm_core.run_command
try:
    _sm_core.run_command = lambda *a, **k: ("f 4096", "", 0)
    eq("stat_path: a file reports its type and size",
       _sm_files.stat_path(_FakeSrv(), "csgoserver", "cfg/server.cfg"),
       {"type": "f", "size": 4096, "name": "server.cfg", "rel": "cfg/server.cfg"})
    _sm_core.run_command = lambda *a, **k: ("d 0", "", 0)
    eq("stat_path: a directory is flagged, so the route knows to build an archive",
       _sm_files.stat_path(_FakeSrv(), "csgoserver", "addons")["type"], "d")
    # "." is how the route recognises the home directory itself, whatever spelling asked for it.
    for _spelling in ("", ".", "/", "cfg/.."):
        eq("stat_path: %r canonicalises to the home directory" % _spelling,
           _sm_files.stat_path(_FakeSrv(), "csgoserver", _spelling)["rel"], ".")
    _sm_core.run_command = lambda *a, **k: ("__NOFILE__", "", 0)
    check("stat_path: a missing path is None, not a zero-byte file",
          _sm_files.stat_path(_FakeSrv(), "csgoserver", "gone.cfg") is None)
    # An unreadable size must not silently become a Content-Length of 0: a wrong Content-Length
    # truncates the download at that many bytes, which is worse than no progress bar.
    _sm_core.run_command = lambda *a, **k: ("f", "", 0)
    eq("stat_path: an unreadable size falls back to 0 rather than garbage",
       _sm_files.stat_path(_FakeSrv(), "csgoserver", "odd")["size"], 0)
    _stat_cmds = []
    _sm_core.run_command = lambda s, c, **k: (_stat_cmds.append(c), ("f 1", "", 0))[1]
    _sm_files.stat_path(_FakeSrv(), "csgoserver", "cfg/server.cfg")
    check("stat_path: carries the host-side symlink guard, like every other file op",
          _stat_cmds and "realpath -m" in _stat_cmds[0] and "__OUTSIDE_HOME__" in _stat_cmds[0],
          str(_stat_cmds)[:150])
    _sm_core.run_command = lambda *a, **k: ("__OUTSIDE_HOME__", "", 9)
    check("stat_path: a path that escapes home is refused",
          _sm_files.stat_path(_FakeSrv(), "csgoserver", "escape") is None)
    check("stat_path: a traversal is refused before any command runs",
          _sm_files.stat_path(_FakeSrv(), "csgoserver", "../../etc/passwd") is None)

    class _FakeProc:
        """A Popen stand-in whose stdout hands back a fixed list of chunks."""
        def __init__(self, chunks):
            self._chunks = list(chunks)
            self.stdout = self
        def read(self, _n):
            return self._chunks.pop(0) if self._chunks else b""
        def close(self):
            pass
        def wait(self):
            return 0

    _argvs = []

    def _fake_popen(argv, **_kw):
        _argvs.append(argv)
        return _FakeProc([b"abc", b"def"])

    _orig_popen, _orig_helper = _sm_core.subprocess.Popen, _sm_core.helper_present
    try:
        _sm_core.subprocess.Popen = _fake_popen
        _sm_core.helper_present = lambda: True
        # A refusal has to mean NOTHING RAN, not just "no bytes came back": with the byte source
        # faked, an empty result would otherwise be indistinguishable from a command that ran and
        # returned nothing. So these assert the argv list stayed empty.
        check("stream_path: a traversal runs no command at all",
              list(_sm_files.stream_path(_FakeSrv(), "csgoserver", "../../etc/passwd")) == []
              and _argvs == [], str(_argvs))
        check("stream_path: an unsafe game user is refused the same way",
              list(_sm_files.stream_path(_FakeSrv(), "a;id", "server.cfg")) == []
              and _argvs == [], str(_argvs))
        # A collapsible ".." is a legitimate request — _safe_abspath normalises it — but the
        # helper's validator refuses a ".." component, so the raw string must not be what crosses.
        # Forwarding it raised VerbError out of the middle of a download.
        _argvs.clear()
        eq("stream_path: a collapsible '..' is normalised before it reaches the verb",
           b"".join(_sm_files.stream_path(_FakeSrv(), "csgoserver", "cfg/../server.cfg")), b"abcdef")
        eq("stream_path: ...and what crosses the boundary is the canonical path",
           _argvs[-1][5], "server.cfg")
        # The home directory itself is not a download: "tar up this whole game install" is never
        # what someone meant to click, and it is reachable by hand-editing ?path=.
        _argvs.clear()
        for _root_path in ("", ".", "/", "cfg/.."):
            check("stream_path: %r is not a download target" % _root_path,
                  list(_sm_files.stream_path(_FakeSrv(), "csgoserver", _root_path, as_tar=True)) == []
                  and _argvs == [], str(_argvs))
        eq("stream_path: the bytes come through in order",
           b"".join(_sm_files.stream_path(_FakeSrv(), "csgoserver", "cfg/server.cfg")), b"abcdef")
        eq("stream_path: a local file download goes through the helper verb, as argv",
           [_argvs[-1][3], _argvs[-1][4], _argvs[-1][5]],
           ["game-file-read", "csgoserver", "cfg/server.cfg"])
        list(_sm_files.stream_path(_FakeSrv(), "csgoserver", "addons", as_tar=True))
        eq("stream_path: a local folder download asks for the tar verb instead",
           _argvs[-1][3], "game-dir-tar")
        check("stream_path: no shell is involved on the helper path",
              not any(x in ("bash", "/bin/bash", "sh") for x in _argvs[-1]), str(_argvs[-1]))
        # No helper yet (a host between `git pull` and the next install.sh run): still argv, and
        # still read AS THE GAME USER — that is the property the whole design rests on.
        _sm_core.helper_present = lambda: False
        list(_sm_files.stream_path(_FakeSrv(), "csgoserver", "cfg/server.cfg"))
        eq("stream_path: the no-helper fallback reads as the game user, without a shell",
           _argvs[-1], ["sudo", "-u", "csgoserver", "cat", "--", "/home/csgoserver/cfg/server.cfg"])
        list(_sm_files.stream_path(_FakeSrv(), "csgoserver", "addons", as_tar=True))
        eq("stream_path: ...and tars the directory from its parent, so the archive has one root",
           _argvs[-1], ["sudo", "-u", "csgoserver", "tar", "czf", "-",
                        "-C", "/home/csgoserver", "--", "addons"])
        # The home-root refusal has to hold on THIS transport in particular. On the helper path
        # the verb's own validator would refuse "." anyway; here nothing else would, so a host with
        # the wide grant and no helper is where "tar up the whole game install" could actually run.
        _argvs.clear()
        for _root_path in ("", ".", "/", "cfg/.."):
            check("stream_path: %r is refused without the helper too" % _root_path,
                  list(_sm_files.stream_path(_FakeSrv(), "csgoserver", _root_path, as_tar=True)) == []
                  and _argvs == [], str(_argvs))
        # A game server writes to its console log constantly, so the file can be bigger by the time
        # it is read than when it was measured. A response longer than its own Content-Length
        # desynchronises a keep-alive connection, so the stream is capped at what was measured.
        eq("stream_path: the stream is capped at the size the route promised",
           b"".join(_sm_files.stream_path(_FakeSrv(), "csgoserver", "cod-console.log", limit=4)), b"abcd")
        eq("stream_path: a limit of 0 sends nothing at all",
           b"".join(_sm_files.stream_path(_FakeSrv(), "csgoserver", "empty.log", limit=0)), b"")
        eq("stream_path: a limit larger than the file does not pad it",
           b"".join(_sm_files.stream_path(_FakeSrv(), "csgoserver", "small.cfg", limit=999)), b"abcdef")
        # ── The SSH transports take the path on STDIN, and their command is a CONSTANT ────────
        # A download over SSH is parsed twice — once assembling the local `ssh` argv, again by the
        # remote shell — and two-level quoting is where this class of bug lives. So the command
        # text contains nothing the caller chose. The test for that is not "is it quoted" but "is
        # it the same text regardless": a hostile path and a benign one must produce byte-identical
        # commands, with the path appearing only in what is written to stdin.
        class _TsSrv:
            is_local, auth_method, sudo_enabled = False, "tailscale", False
            host, port, username, linuxgsm_user = "ts-host", 22, "ubuntu", ""

        _fed, _cmds2 = [], []

        class _FakeTsProc(_FakeProc):
            def __init__(self, chunks):
                super().__init__(chunks)
                self.stdin = self
            def write(self, b):
                _fed.append(b)
            def flush(self):
                pass

        def _fake_ts_popen(argv, **_kw):
            _cmds2.append(argv[-1])
            return _FakeTsProc([b"abc"])

        _orig_ts_host = _sm_core._resolve_ts_host
        try:
            _sm_core._resolve_ts_host = lambda s: "ts-host"
            _sm_core.subprocess.Popen = _fake_ts_popen
            _fed.clear(); _cmds2.clear()
            _HOSTILE = "addons/'; id; echo $(whoami) \"x\".cfg"
            eq("stream_path (ssh): the bytes still come through",
               b"".join(_sm_files.stream_path(_TsSrv(), "csgoserver", "cfg/server.cfg")), b"abc")
            list(_sm_files.stream_path(_TsSrv(), "csgoserver", _HOSTILE))
            eq("stream_path (ssh): a hostile path produces the IDENTICAL remote command",
               _cmds2[0], _cmds2[1])
            check("stream_path (ssh): the path is nowhere in the command — it went to stdin",
                  "server.cfg" not in _cmds2[0] and "whoami" not in _cmds2[1],
                  _cmds2[1][:120])
            eq("stream_path (ssh): ...and stdin carried it verbatim, canonicalised",
               [b.decode() for b in _fed], ["cfg/server.cfg", _HOSTILE])
            # The two shapes differ only in the verb, which is a literal either way.
            _cmds2.clear()
            list(_sm_files.stream_path(_TsSrv(), "csgoserver", "addons", as_tar=True))
            check("stream_path (ssh): the folder form is the tar verb, still constant",
                  "tar czf -" in _cmds2[0] and "addons" not in _cmds2[0], _cmds2[0][-80:])
            # And the guard is in that constant text, judging the resolved path on the host.
            check("stream_path (ssh): the command carries the host-side containment guard",
                  "realpath -m" in _cmds2[0] and "__OUTSIDE_HOME__" in _cmds2[0], _cmds2[0][:90])
        finally:
            _sm_core._resolve_ts_host = _orig_ts_host
            _sm_core.subprocess.Popen = _fake_popen

        # The SSH transports DO use a shell, so the guard rides along there — and its sentinel must
        # not be handed to the browser as if it were the file.
        _sm_core.subprocess.Popen = lambda argv, **_kw: _FakeProc([b"__OUTSIDE_HOME__\n"])
        eq("stream_path: a stream carrying the guard's sentinel yields nothing",
           list(_sm_files.stream_path(_FakeSrv(), "csgoserver", "link")), [])
    finally:
        _sm_core.subprocess.Popen, _sm_core.helper_present = _orig_popen, _orig_helper
finally:
    _sm_core.run_command = _orig_dl_rc

# The download's filename reaches the browser in a header, and whoever uploaded the file chose it.
# (`_app` is the Flask test app further down this file; the module itself is the one wanted here.)
_appmod = sys.modules["app"]
check("download header: a CR/LF in a filename cannot split the header",
      "\r" not in _appmod._attachment_header("x\r\nX-Evil: 1")
      and "\n" not in _appmod._attachment_header("x\r\nX-Evil: 1"),
      _appmod._attachment_header("x\r\nX-Evil: 1"))
check("download header: a quote cannot end the quoted filename early",
      '"' not in _appmod._attachment_header('a"b.cfg').split("filename=")[1].split(";")[0][1:-1],
      _appmod._attachment_header('a"b.cfg'))
check("download header: the exact name survives in filename*, percent-encoded",
      "filename*=UTF-8''mapa%20%C3%B1.bsp" in _appmod._attachment_header("mapa ñ.bsp"),
      _appmod._attachment_header("mapa ñ.bsp"))
check("download header: every value is latin-1 clean, as WSGI headers must be",
      _appmod._attachment_header("día ñ [v2].bsp").encode("latin-1"))
eq("download header: an empty name still has something to save as",
   _appmod._attachment_header(""), "attachment; filename=\"download\"; filename*=UTF-8''download")
