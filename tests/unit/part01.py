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
    # Every match, not the first one os.walk happens to reach. Two modules shared the basename
    # terminal.py (the ANSI renderer in panel/core and the host-terminal routes) and this returned
    # whichever the filesystem listed first — so a gate asking about the renderer read the routes
    # instead, and the fuzz-path gate passed on one machine and failed on another with no code
    # change between them. An ambiguous name is a bug in the gate; say so instead of picking one.
    hits = []
    for pkg in _PKG_DIRS:
        for dirpath, dirnames, files in os.walk(os.path.join(_root, pkg)):
            if leaf in files:
                hits.append(os.path.join(dirpath, leaf))
            if stem in dirnames and os.path.exists(os.path.join(dirpath, stem, "__init__.py")):
                hits.append(os.path.join(dirpath, stem))
    if len(hits) > 1:
        raise ValueError(
            "%r is ambiguous — %s. Pass the path from the repo root instead (e.g. %r)."
            % (leaf, " and ".join(sorted(os.path.relpath(h, _root) for h in hits)),
               os.path.relpath(sorted(hits)[0], _root)))
    if hits:
        return hits[0]
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
# password_problem / _int_or / _valid_hex_color moved to panel.core.validation when the pure
# layer came out of app.py; _valid_ip_or_cidr and _clean_console_text are still app.py's.
from panel.core.validation import (generate_password, password_problem, _int_or, _valid_hex_color)  # noqa: F401 - re-export: a later part imports this from here
from app import (_valid_ip_or_cidr, _clean_console_text)  # noqa: F401 - re-export: a later part imports this from here
from panel.services.bots.telegram import (_parse_tg_command)  # noqa: F401 - re-export: a later part imports this from here
from panel.services.bots.commands import (_command_arg)  # noqa: F401 - re-export: a later part imports this from here
from panel.db.prefs import (_apply_user_server_order)
from panel.services.monitoring import (_whitelisted)  # noqa: F401 - re-export: a later part imports this from here
from panel.db.prefs import (_apply_user_order)
from panel.security.auth import can_access_remote, client_ip  # noqa: F401 - re-export: a later part imports this from here

results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))


def skip(name, reason):
    """Record a check that did NOT run, as a SKIP — never as a pass.

    Several blocks below need something the environment may not give them (fork, a writable temp
    dir, a second group to test a permission against). Refusing to run is reasonable; reporting
    `PASS` for it is not, and that is what `check(name, True, "skipped: …")` did — a green line for
    a check that never executed, which is indistinguishable from one that did. tools/run-tests.sh
    already refuses a suite-level SKIP for exactly this reason ("a skip that exits 0 reads exactly
    like a pass"); this applies the same rule one level down, to a single check.

    A skip does not fail the run — the environment is not the code's fault — but it is printed as
    SKIP and counted separately, so a block that quietly stops running is visible rather than
    absorbed into the pass count."""
    results.append((None, name, "skipped: %s" % reason))


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

# ── generate_password: the panel issues these, so they must pass its own rules every time ──────
# Admin-created accounts and admin password resets get a generated password. If one of them could
# come out weak, the failure is a 400 on the "Add User" form with the account already half-made —
# or worse, a password the panel accepted and its own validator would not.
_gen = [generate_password() for _ in range(2000)]
check("generated: every one satisfies password_problem",
      not [p for p in _gen if password_problem(p)],
      repr([p for p in _gen if password_problem(p)][:3]))
check("generated: default length is 16", all(len(p) == 16 for p in _gen))
check("generated: a shorter request is still floored at the policy minimum",
      len(generate_password(4)) >= 10)
# Read off one screen, typed into another — so the look-alikes are out. A password nobody can
# transcribe gets "reset it again", which is the same failure as a weak one, slower.
check("generated: no look-alike characters (O0 Il1 S5 B8 Z2)",
      not [p for p in _gen if set(p) & set("O0Il1S5B8Z2")],
      repr([p for p in _gen if set(p) & set("O0Il1S5B8Z2")][:2]))
# It rides through a chat message and a shell now and then; a quote or a backslash turns it into a
# support ticket.
check("generated: no quote, backslash or backtick",
      not [p for p in _gen if set(p) & set("'\"\\`")])
check("generated: consecutive calls differ (it is not seeded per process)",
      len(set(_gen)) > 1990, "distinct=%d/2000" % len(set(_gen)))
# Built class-first then shuffled, so no position is reserved for a class.
check("generated: the first character is not always the same class",
      len({p[0].isalpha() and p[0].islower() for p in _gen}) > 1)

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
# ── a config.json that is valid JSON but not an OBJECT ───────────────────────────────────────
# config.json is explicitly a file a human can hand-edit, and load_config() is on every request
# path and in every background poller. The except caught a MALFORMED file; it did not catch
# `null`, `[1,2,3]`, `"hello"` or `123`, each of which parses fine and then raises inside
# dict.update — so a truncated file degraded to defaults while a stray `null` 500'd every page.
# CONFIG_FILE is redirected to a temp path here: these bodies must never touch the real one.
import pathlib as _pl_cfg
import tempfile as _tf_cfg
_cfg_file_saved = _cfgmod.CONFIG_FILE
_cfg_tmp = _pl_cfg.Path(_tf_cfg.mkdtemp()) / "config.json"
try:
    _cfgmod.CONFIG_FILE = _cfg_tmp
    for _body, _label in (('{"port": 5001}', "an object is read normally"),
                          ("null", "null"),
                          ("[1,2,3]", "an array"),
                          ('"hello"', "a bare string"),
                          ("123", "a bare number"),
                          ("{ truncated", "a truncated file")):
        _cfg_tmp.write_text(_body, encoding="utf-8")
        _cfgmod._cfg_cache["key"] = None
        try:
            _got = _cfgmod.load_config()
            _ok, _detail = isinstance(_got, dict), ""
        except Exception as _e:
            _ok, _detail = False, "%s: %s" % (type(_e).__name__, _e)
        check("config: %s does not raise out of load_config" % _label, _ok, _detail)
    # ...and the one that IS an object still wins, so the guard is not a blanket "always defaults".
    # Both reads go through _port(), which reports the exception as a value rather than letting it
    # abort the suite — the point of these checks is what load_config DOES with a bad file, and a
    # traceback out of the harness prints no verdict at all.
    def _port():
        _cfgmod._cfg_cache["key"] = None
        try:
            return _cfgmod.load_config().get("port")
        except Exception as _e:
            return "RAISED %s" % type(_e).__name__

    _cfg_tmp.write_text('{"port": 5001}', encoding="utf-8")
    eq("config: a real object's values still come through", _port(), 5001)
    _cfg_tmp.write_text("null", encoding="utf-8")
    eq("config: ...and a non-object falls back to the documented default",
       _port(), _cfgmod.DEFAULT_CONFIG["port"])

    # ── ...but defaults read from an unreadable file must never be WRITTEN back over it ──────
    # Every writer is read-modify-write. update_config/save_config replaced a config.json with a
    # trailing comma by DEFAULT_CONFIG plus one key, on the next background tick: the encrypted
    # backup passphrase, the whitelist, the tokens, the bind and the port all gone for good.
    _bad = '{"port": 8443, "backup_passphrase": "gAAAA-kept",}'   # one trailing comma

    def _raises_unreadable(fn):
        try:
            fn()
        except _cfgmod.ConfigUnreadable:
            return True
        except Exception as _e:
            return "RAISED %s" % type(_e).__name__
        return False

    _cfg_tmp.write_text(_bad, encoding="utf-8")
    _cfgmod._cfg_cache["key"] = None
    check("config: update_config REFUSES an unparseable config.json",
          _raises_unreadable(lambda: _cfgmod.update_config(
              lambda c: c.update({"game_schedules": {"x": 1}}))) is True)
    check("config: ...and leaves the file byte-for-byte as the operator wrote it",
          _cfg_tmp.read_text(encoding="utf-8") == _bad, _cfg_tmp.read_text(encoding="utf-8")[:80])
    _cfgmod._cfg_cache["key"] = None
    _loaded_bad = _cfgmod.load_config()
    check("config: the direct load_config()+save_config() path refuses too",
          _raises_unreadable(lambda: _cfgmod.save_config(_loaded_bad)) is True
          and _cfg_tmp.read_text(encoding="utf-8") == _bad)
    check("config: a COPY of the defaults (the mark lost) is refused on the file's own state",
          _raises_unreadable(lambda: _cfgmod.save_config(dict(_loaded_bad))) is True
          and _cfg_tmp.read_text(encoding="utf-8") == _bad)
    check("config: load_config still answers defaults for it, marked unreadable",
          _loaded_bad.get("port") == _cfgmod.DEFAULT_CONFIG["port"]
          and _cfgmod.is_unreadable(_loaded_bad))
    # A read that failed once (a transient OSError) and a file that reads fine by the time of the
    # write: the dict is still defaults, and the mark on it is the only thing that says so.
    _cfg_tmp.write_text('{"port": 8443, "site_title": "Mine"}', encoding="utf-8")
    check("config: defaults from a FAILED read are refused even once the file reads again",
          _raises_unreadable(lambda: _cfgmod.save_config(_loaded_bad)) is True
          and '"Mine"' in _cfg_tmp.read_text(encoding="utf-8"))
    # Positive controls: a readable file and a missing file still write normally.
    _cfgmod._cfg_cache["key"] = None
    _cfgmod.update_config(lambda c: c.update({"ssh_timeout": 17}))
    _cfgmod._cfg_cache["key"] = None
    _after = _cfgmod.load_config()
    check("config: a readable file is still updated, its other keys kept",
          _after.get("ssh_timeout") == 17 and _after.get("site_title") == "Mine"
          and _after.get("port") == 8443 and not _cfgmod.is_unreadable(_after), repr(_after)[:120])
    _cfg_tmp.unlink()
    _cfgmod._cfg_cache["key"] = None
    check("config: a MISSING config.json is not unreadable (a fresh install)",
          not _cfgmod.is_unreadable(_cfgmod.load_config()) and not _cfgmod.config_unreadable())
    _cfgmod.update_config(lambda c: c.update({"site_title": "Fresh"}))
    check("config: ...and update_config creates it",
          _cfg_tmp.exists() and '"Fresh"' in _cfg_tmp.read_text(encoding="utf-8"))
finally:
    _cfgmod.CONFIG_FILE = _cfg_file_saved
    _cfgmod._cfg_cache["key"] = None

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
# routes sits on top: it is allowed to import from everything below and nothing imports it back
# (app.py reaches it lazily, inside register_routes).
_LAYERS = ["core", "db", "security", "ops", "services", "routes"]
_layer_bad = []
_layer_seen = 0
for _dp, _dns, _fs in os.walk(os.path.join(_root, "panel")):
    _dns[:] = [_d for _d in _dns if _d != "__pycache__"]
    # The layer is the FIRST path component under panel/, not the directory's basename. Basename
    # silently skipped every nested package: when panel/ops/ssh_manager.py became a PACKAGE its
    # basename stopped being "ops", so its 8 modules dropped out of a gate that had been covering
    # them — and panel/routes/ (26) and panel/services/bots/ (3) were never in it at all. The gate
    # kept passing and kept saying "no panel package imports DOWN the stack" while looking at 17
    # modules out of 54.
    _rel = os.path.relpath(_dp, os.path.join(_root, "panel"))
    _sub = _rel.split(os.sep)[0]
    if _sub not in _LAYERS:
        continue
    for _f in _fs:
        if not _f.endswith(".py") or _f == "__init__.py":
            continue
        _layer_seen += 1
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
                    # The RELATIVE path, not "%s/%s" % (layer, file): with nested packages that
                    # reported panel/ops/gmod.py for a file at panel/ops/ssh_manager/gmod.py.
                    _layer_bad.append("panel/%s imports panel.%s at module level"
                                      % (os.path.join(_rel, _f).replace(os.sep, "/"), _target))
check("layering: no panel package imports DOWN the stack at module level",
      not _layer_bad, "; ".join(sorted(set(_layer_bad))))
# A count, because the failure above is silence: a gate that walks into nothing reports clean.
_layer_total = sum(1 for _d, _dn, _fl in os.walk(os.path.join(_root, "panel"))
                   for _x in _fl if _x.endswith(".py") and _x != "__init__.py"
                   and "__pycache__" not in _d)
check("layering: the gate actually inspected every module under panel/",
      _layer_seen == _layer_total, "inspected %d of %d" % (_layer_seen, _layer_total))

# ...and the module directories must hold no data dir of their own — the shape the bug leaves behind.
_stray = [os.path.relpath(os.path.join(_dp, _d), _root)
          for _dp, _dns, _ in os.walk(os.path.join(_root, "panel"))
          for _d in _dns if _d in ("data", "translations")]
check("paths: no stray data/ or translations/ dir was created inside panel/",
      not _stray, ", ".join(_stray))

# ── terminal.py: ONE renderer, because this had drifted into four incompatible ANSI regexes and two
# carriage-return rules that contradicted each other (each docstring calling the other wrong).
# ── Every security validator rejects a trailing newline ───────────────────────────────────────
# `$` matches BEFORE a final \n, so `^[a-z]+$` accepts "lgsm\n". Every one of these gates a value
# that becomes a shell argument, a filesystem path, a URL, a CSS literal or a stored column, and
# all of them were anchored that way — including _SHELL_IDENT_RE, whose docstring calls itself a
# hard guarantee that "no code path can ever store a value that could break out of a shell
# command". edit_remote does not strip its input, so `linuxgsm_user = "lgsm\n"` stored clean and
# `sudo -u lgsm\n bash -c ...` ran the panel's command as the SSH login account instead.
#
# Driven as a TABLE so the next validator added is covered by adding one line, and so a fix that
# only reaches the one that was reported cannot pass.
from panel.db.models import _SHELL_IDENT_RE as _V_SHELL, TAG_NAME_RE as _V_TAG
from panel.core import validation as _V
from panel.core.clock import valid_timezone as _v_tz
from panel.ops.ssh_manager import files as _v_files, gmod as _v_gmod, cron as _v_cron
from panel.ops import backup as _v_backup, tailscale_integration as _v_ts
from panel.services import lgsm_data as _v_lgsm

_VALIDATORS = [
    ("models._SHELL_IDENT_RE", _V_SHELL, "gmodserver"),
    ("models.TAG_NAME_RE", _V_TAG, "prod"),
    ("validation.GAME_TYPE_RE", _V.GAME_TYPE_RE, "csgo"),
    ("validation.INSTANCE_NAME_RE", _V.INSTANCE_NAME_RE, "myserver"),
    ("validation.LINUX_USER_RE", _V.LINUX_USER_RE, "lgsm"),
    ("validation.HOST_RE", _V.HOST_RE, "10.0.0.1"),
    ("validation.SAFE_LABEL_RE", _V.SAFE_LABEL_RE, "My Host"),
    ("validation._HEX_COLOR_RE", _V._HEX_COLOR_RE, "#aabbcc"),
    ("files._SAFE_UNIX_USER_RE", _v_files._SAFE_UNIX_USER_RE, "gmodserver"),
    ("gmod._CU_NAME_RE", _v_gmod._CU_NAME_RE, "gmodcontent"),
    ("cron._GAME_BACKUP_NAME", _v_cron._GAME_BACKUP_NAME, "srv-2026.tar.gz"),
    ("backup._NAME_RE", _v_backup._NAME_RE, "panel-backup-20260918-120000-manual.tar.gz"),
    ("lgsm_data._OS_SLUG_RE", _v_lgsm._OS_SLUG_RE, "ubuntu-24.04"),
    ("tailscale._PEER_HOST_RE", _v_ts._PEER_HOST_RE, "box.tail1234.ts.net"),
]
for _vname, _vrx, _vgood in _VALIDATORS:
    check("validator %s ACCEPTS its good value (the gate can still say yes)" % _vname,
          bool(_vrx.match(_vgood)), repr(_vgood))
    check("validator %s REJECTS a trailing newline" % _vname,
          not _vrx.match(_vgood + "\n"), "%r was accepted" % (_vgood + "\n"))
# The two that are FUNCTIONS, not bare patterns. Both .strip() before matching, so a trailing
# newline was never a way through them — what matters is that what they RETURN carries none,
# since one becomes a CSS custom property and the other a stored, rendered column.
check("validation._valid_hex_color returns nothing with a newline in it",
      _V._valid_hex_color("#aabbcc\n") == "#aabbcc" and "\n" not in _V._valid_hex_color("#aabbcc\n"))
check("clock.valid_timezone returns nothing with a newline in it",
      _v_tz("Europe/London\n") == "Europe/London")
# ...and the model validator must REFUSE, not merely fail to match.
from panel.db.models import _validate_shell_ident as _v_ident
_vi_raised = False
try:
    _v_ident("short_name", "gmodserver\n")
except ValueError:
    _vi_raised = True
check("models._validate_shell_ident raises on a trailing newline (the 'hard guarantee')",
      _vi_raised, "it returned the value instead")

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
# ...but only the FOUR that mean something. This module's docstring promises "control bytes do not
# reach the page", and ESC was the only one it removed: NUL, BEL, VT and FF all survived both
# renderers. A player picks their own name and chat text, so those bytes are authored rather than
# accidental, and the guarantee was a claim rather than a property.
eq("terminal: a control byte with no rendering meaning does NOT survive strip_escapes",
   _term.strip_escapes("a\x00b\x07c\x0bd\x0ce\x7ff"), "abcdef")
eq("terminal: ...nor the colour renderer, which makes the same promise",
   _term.render_line_colour("a\x00b\x07c\x0bd\x0ce\x7ff"), "abcdef")
eq("terminal: TAB is kept — it renders", _term.strip_escapes("a\tb"), "a\tb")
eq("terminal: ...through the colour renderer too", _term.render_line_colour("a\tb"), "a\tb")
eq("terminal: and colour still survives (the filter did not eat the SGR it writes)",
   _term.render_line_colour("\x1b[32mok\x1b[0m"), "\x1b[32mok\x1b[0m")
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
# Colour is KEPT now — LinuxGSM's [  OK  ]/[ FAIL ] tags are most of what makes a long update
# readable, and throwing them away was right only for the paths that PARSE this text. What reaches
# the browser is canonical: the redundant "0;" prefix is gone and the run is closed explicitly, so
# the JS has one shape to split on. `_bare` below is the same line as a reader sees it, which is
# what every assertion about CONTENT uses — colour must not be able to hide a rendering bug.
def _bare(text):
    """`text` with the colour this now keeps removed — what the words alone say."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


eq("console: ANSI colour is kept, canonicalised",
   _clean_console_text("\x1b[0;32mgreen\x1b[0m text"), "\x1b[32mgreen\x1b[0m text")
eq("console: ...and the words alone are unchanged by keeping it",
   _bare(_clean_console_text("\x1b[0;32mgreen\x1b[0m text")), "green text")
# A \r overwrite ACROSS a colour boundary is the case a naive implementation gets wrong: leave the
# escapes in the string and the overwrite counts them as columns, so it lands in the wrong place —
# silently, and only on the download-progress spool this was added to show.
eq("console: \\r overwrites by COLUMN, not by byte, when colour is present",
   _clean_console_text("\x1b[32m123456\x1b[0m\rabc"), "abc\x1b[32m456\x1b[0m")
# A code nothing renders (256-colour/truecolor) is dropped rather than passed to the page.
eq("console: an unrenderable SGR code is dropped, its text kept",
   _clean_console_text("\x1b[38;5;208morange"), "orange")
# ── 38/48 CONSUME their parameters; reading those as attributes invents formatting ────────────
# SGR 38/48/58 are extended-colour introducers: `38;5;n` is one 256-colour instruction and
# `38;2;r;g;b` one truecolor instruction. Treating each sub-parameter as its own attribute turns
# an RGB triple into arbitrary formatting — Minecraft converts a plugin's §x hex colour into
# exactly these sequences, so `48;2;1;9;3` came out as dim + bold + STRIKETHROUGH + italic and
# drew a line through an Essentials warning and the URL beneath it. Reported from a real console.
eq("console: an extended-colour sequence applies NO attributes of its own",
   _clean_console_text("\x1b[48;2;1;9;3mtext"), "text")
eq("console: ...nor does a 256-colour one",
   _clean_console_text("\x1b[38;5;208morange"), "orange")
eq("console: ...and a malformed introducer drops only itself",
   _clean_console_text("\x1b[38mtext"), "text")
# The sub-parameters must be CONSUMED, not merely filtered: a real code after them still applies.
eq("console: a real code following an extended colour is not swallowed",
   _clean_console_text("\x1b[38;2;1;9;3m\x1b[33myellow"), "\x1b[33myellow\x1b[0m")
# ...including in the SAME sequence, which is where the consumed COUNT has to be exact. Separate
# sequences cannot catch an over-consuming parser: it would eat the parameter after the triple and
# nothing would notice. `38;2;r;g;b;33` is one instruction then a colour, and both must survive.
eq("console: consuming a truecolor triple takes exactly five parameters, not six",
   _clean_console_text("\x1b[38;2;1;9;3;33myellow"), "\x1b[33myellow\x1b[0m")
eq("console: ...and a 256-colour one takes exactly three",
   _clean_console_text("\x1b[38;5;208;33myellow"), "\x1b[33myellow\x1b[0m")
# ...and the attributes themselves still work when the game genuinely asks for them.
eq("console: a genuine strikethrough is still rendered",
   _clean_console_text("\x1b[9mstruck"), "\x1b[9mstruck\x1b[0m")
eq("console: a genuine colour is still rendered",
   _clean_console_text("\x1b[33mwarn"), "\x1b[33mwarn\x1b[0m")

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
   [_bare(ln) for ln in _jline_clean.split("\n") if ln.strip()],
   ["> say hi", "[23:52:54 INFO]: [Not Secure] [Server] hi"])
check("console: ...and JLine's own syntax colour survives it",
      "\x1b[36m" in _jline_clean, repr(_jline_clean[:120]))
# The invariant NARROWED deliberately: colour now reaches the browser, and nothing else does.
# Both halves are asserted, because the dangerous direction is the second one — erase-line, OSC,
# the two-byte escapes and a stray ESC all render as visible junk (or worse) if they get through,
# and "we kept some escapes now" is exactly the change that would let them.
check("console: no control characters survive to the browser except colour",
      not any(ord(c) < 32 and c != "\n" for c in _bare(_jline_clean)), repr(_jline_clean[:80]))
check("console: the escapes that are NOT colour are still all removed",
      not any(ord(c) < 32 and c != "\n"
              for c in _bare(_clean_console_text(
                  "\x1b[K erase \x1b]0;title\x07 osc \x1b> two-byte \x1b[2C cursor \x1bZ stray"))),
      repr(_clean_console_text("\x1b[K erase \x1b]0;title\x07 osc \x1b> two-byte")))
check("console: a bare ESC that completes no sequence never reaches the page",
      "\x1b" not in _bare(_clean_console_text("player\x1b\x00name")),
      repr(_clean_console_text("player\x1b\x00name")))
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
_ssh_script = {"v": "printf 'out\\n'"}
_real_popen_ssh = _sm_core.subprocess.Popen
_ssh_srv = type("S", (), {"sudo_enabled": False, "linuxgsm_user": None, "port": 22,
                          "username": "u", "host": "h", "auth_method": "tailscale"})()


def _fake_ssh_popen(argv, **kw):
    """The REAL transport function, with `ssh ...` swapped for a local command whose output the
    check controls. Everything after the spawn — the reading, the ceiling, the decode — is real."""
    _sshkw.clear()
    _sshkw.update(kw)
    _sshkw["argv0"] = argv[0]
    return _real_popen_ssh(["/bin/bash", "-c", _ssh_script["v"]], **kw)


_real_ts_host = _sm_core._resolve_ts_host
try:
    _sm_core.subprocess.Popen = _fake_ssh_popen
    # Loopback, so a regression that stops going through Popen dials nothing off this machine.
    _sm_core._resolve_ts_host = lambda srv: "127.0.0.1"
    _ssh_script["v"] = r"printf 'caf\351: cannot start\n'"
    _sshr = _sm_core._run_via_ssh_cli(_ssh_srv, "echo hi", timeout=10, sudo=False)
    check("transport (ssh cli): decodes with errors='replace' like the other two",
          _sshr[2] == 0 and _sshr[0].startswith("caf") and "\ufffd" in _sshr[0], repr(_sshr))
    # ...and it must not hand the remote session the PANEL's stdin. capture_output= redirected
    # stdout and stderr ONLY, and there is no `-n` in the argv, so the child ssh inherited fd 0
    # and forwarded it to the far side: every command this transport runs — the transport every
    # Tailscale remote uses — was reading the panel's own input. Production survived it only
    # because the systemd unit sets StandardInput=null; run from a shell, a tmux pane or the dev
    # runner and the poller's ssh calls race to drain the operator's tty, where a stray keystroke
    # answers a LinuxGSM prompt on a live game server. _POPEN_KW gives both local paths DEVNULL
    # and files.py gives its own ssh argv the same; this was the one transport that did not.
    check("transport (ssh cli): the remote session never gets the panel's own stdin",
          _sshkw.get("stdin") == _sm_core.subprocess.DEVNULL and _sshkw.get("argv0") == "ssh",
          "stdin=%r argv0=%r — expected DEVNULL (%r)"
          % (_sshkw.get("stdin"), _sshkw.get("argv0"), _sm_core.subprocess.DEVNULL))
    # ── ...and what it KEEPS has a ceiling ───────────────────────────────────────────────────
    # capture_output= buffered everything the remote wrote until the timeout, so a hostile
    # Tailscale remote answering a metrics probe with gigabytes grew the panel until the OOM
    # killer took it — and every other host's management with it. The paramiko path has capped
    # each stream at _MAX_OUTPUT_BYTES since it was written; this transport now does too.
    _ssh_script["v"] = "head -c %d /dev/zero | tr '\\0' a; echo tail >&2" % (
        _sm_core._MAX_OUTPUT_BYTES + 3 * 1024 * 1024)
    _sshr = _sm_core._run_via_ssh_cli(_ssh_srv, "echo hi", timeout=60, sudo=False)
    check("transport (ssh cli): output past the ceiling is dropped, not buffered",
          _sshr[2] == 0 and len(_sshr[0]) == _sm_core._MAX_OUTPUT_BYTES and _sshr[1] == "tail",
          "rc=%r kept=%d err=%r" % (_sshr[2], len(_sshr[0]), _sshr[1][:40]))
    _ssh_script["v"] = "printf 'a\\r\\nb\\n'; exit 3"
    _sshr = _sm_core._run_via_ssh_cli(_ssh_srv, "echo hi", timeout=10, sudo=False)
    check("transport (ssh cli): ...while ordinary output, its newlines and its rc come through "
          "unchanged (positive control)", _sshr == ("a\nb", "", 3), repr(_sshr))
    _ssh_script["v"] = "sleep 5"
    _sshr = _sm_core._run_via_ssh_cli(_ssh_srv, "echo hi", timeout=0.5, sudo=False)
    check("transport (ssh cli): ...and a command that outlives its timeout is still cut off",
          _sshr == ("", "SSH command timed out", -1), repr(_sshr))
finally:
    _sm_core.subprocess.Popen = _real_popen_ssh
    _sm_core._resolve_ts_host = _real_ts_host

# The same ceiling on the panel host's own commands (both local paths go through _finish).
_big = _sm_core._run_local("head -c %d /dev/zero | tr '\\0' b" % (
    _sm_core._MAX_OUTPUT_BYTES + 1024 * 1024), timeout=60, sudo=False)
check("transport (local): output past the ceiling is dropped, not buffered",
      _big[2] == 0 and len(_big[0]) == _sm_core._MAX_OUTPUT_BYTES,
      "rc=%r kept=%d" % (_big[2], len(_big[0])))
check("transport (local): ...while a payload on stdin still reaches the command (positive control)",
      _sm_core._exec_local_argv(["cat"], timeout=10, stdin_text="hello\n") == ("hello", "", 0),
      repr(_sm_core._exec_local_argv(["cat"], timeout=10, stdin_text="hello\n")))
_slow = _sm_core._run_local("sleep 5", timeout=0.5, sudo=False)
check("transport (local): ...and a command that outlives its timeout is still cut off",
      _slow == ("", "Command timed out", -1), repr(_slow))

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
    # The .restart-pending branch ran BEFORE _SIMPLE_CMD_RE and before the base64 runner — which
    # is the thing that makes `%` safe — while _validate_cron permits `%`. cron truncates a line at
    # the first unescaped `%` and feeds the remainder in as stdin, so an admin's
    # `… restart >> ~/log/r-%Y.log` quietly became `… restart >> ~/log/r-` while the panel's editor
    # showed the whole thing back.
    _wpend = _sm_cron._wrap_cron_command(
        None, "gm", "rm -f /home/gm/.restart-pending; /home/gm/gmodserver restart >> /home/gm/r-%Y.log")
    check("cron wrap: a verbatim .restart-pending line still escapes % for cron",
          "\\%Y" in _wpend and not __import__("re").search(r"(?<!\\)%", _wpend), repr(_wpend))
    check("cron wrap: ...and the editor is shown the command the admin wrote, not the escaped form",
          _sm_cron._unwrap_cron_command(_wpend)[0]
          == "rm -f /home/gm/.restart-pending; /home/gm/gmodserver restart >> /home/gm/r-%Y.log",
          repr(_sm_cron._unwrap_cron_command(_wpend)[0]))
    # ORDER: the panel's OWN daily-restart line is `touch /home/<u>/.restart-pending`, a plain
    # command that set_daily_restart writes WRAPPED. list_cron_jobs unwraps it for display, and
    # rescheduling that display form in the generic editor sent it back through the
    # .restart-pending branch, which returned it bare — so the panel's own line silently stopped
    # reporting last-run and success after any edit.
    _wflag = _sm_cron._record_managed_cmd("gm", "touch /home/gm/.restart-pending")
    _wdisp, _wjid = _sm_cron._unwrap_cron_command(_wflag)
    _wagain = _sm_cron._wrap_cron_command(None, "gm", _wdisp)
    check("cron wrap: rescheduling the panel's own daily-restart line keeps its run tracking",
          _sm_cron._unwrap_cron_command(_wagain)[1] is not None, repr(_wagain))
    check("cron wrap: ...and it stays visible, which is what the flag-path grep matches on",
          "/home/gm/.restart-pending" in _wagain, repr(_wagain))
    # ── the runner write is what makes the base64 line runnable ──────────────────────────────
    # _install_cron_runner's rc was discarded. If ~/.lgsm-cron is already a regular file the
    # `mkdir -p` fails and the && chain writes nothing — and on the tailscale/local transports a
    # timeout answers ("", "…", -1) WITHOUT raising, so nothing upstream noticed either. The
    # crontab was then rewritten to call a script that is not there: the panel said "Added" with
    # a success audit row, cron mailed "No such file or directory" to a mailbox nobody reads, and
    # Last run stayed "—" forever, which is exactly what a not-yet-due job looks like.
    _sm_core.run_command = lambda *a, **k: ("", "mkdir: cannot create directory", 1)
    check("cron wrap: a failed runner install answers None, not a line pointing at nothing",
          _sm_cron._wrap_cron_command(None, "gm", "echo %H") is None)
    _add_seen = []
    _o_rw = _sm_core._rewrite_crontab
    try:
        _sm_core._rewrite_crontab = lambda *a, **k: (_add_seen.append(a), (True, "Added"))[1]
        _ok_add, _msg_add = _sm_cron.add_cron_job(None, "gm", "30 5 * * *", "echo %H")
        check("cron add: ...so the job is refused rather than reported Added",
              _ok_add is False and "nothing was scheduled" in _msg_add, repr(_msg_add))
        check("cron add: ...and the crontab was never rewritten",
              not _add_seen, str(_add_seen)[:160])
        # update_cron_job must refuse BEFORE the rewrite too — otherwise the working line it was
        # replacing is dropped in favour of one that cannot run.
        _ok_up, _msg_up = _sm_cron.update_cron_job(None, "gm", "0 6 * * * /home/gm/x.sh",
                                                   "30 5 * * *", "echo %H")
        check("cron update: ...same refusal, and the existing line is left alone",
              _ok_up is False and "nothing was scheduled" in _msg_up and not _add_seen,
              "%r / %s" % (_msg_up, str(_add_seen)[:120]))
        # POSITIVE CONTROL: a runner that installs cleanly still schedules the job.
        _sm_core.run_command = lambda *a, **k: ("", "", 0)
        _ok_good, _msg_good = _sm_cron.add_cron_job(None, "gm", "30 5 * * *", "echo %H")
        check("cron add: a host that DID take the runner still schedules the job",
              _ok_good is True and len(_add_seen) == 1
              and ".lgsm-cron/run " in str(_add_seen[0]), "%r / %s" % (_msg_good, str(_add_seen)[:160]))
    finally:
        _sm_core._rewrite_crontab = _o_rw
finally:
    _sm_core.run_command = _orig_wrap_rc

# ── `raw` is the identity for delete/update, and the transport had already changed it ─────────
# Every transport returns out.strip() — the whole crontab listing as ONE blob — so the FIRST
# line comes back without its indentation, which is legal and common in a hand-edited crontab.
# That stripped text is the `raw` the panel hands the browser and the browser hands back, and
# `grep -vxF` matches whole lines exactly: delete reported success and removed nothing, while
# update appended its rewrite beside the original so the job ran on two schedules.
#
# Driven through the REAL pipeline: the command the editor builds is captured and executed, with
# only `crontab -u <user> -l` and `crontab -u <user> <file>` redirected at files. A test that
# reimplemented the filter would pass whatever the filter happens to be.
import shlex as _cr_shlex
import shutil as _cr_shutil
import subprocess as _cr_sub
import tempfile as _cr_tmp

_CR_TAB = ("  */5 * * * * /home/gm/gmodserver monitor\n"
           "0 6 * * * /home/gm/backup.sh --re '^.*[x]$' \\n\n"
           "30 4 * * * /home/gm/other.sh   \n")
_cr_sb = _cr_tmp.mkdtemp(prefix="cron-rewrite-")


# ── ...and the account name it builds that pipeline from must be validated HERE ───────────────
# _rewrite_crontab renders `crontab -u <user>` inside a `sudo bash -c …` that it passes with
# sudo=False — a hand-built escalation none of the three ratchets can see (one counts calls to a
# function named _sudo_sh, one counts the sudo=True keyword, one looks for an argv starting with
# "sudo"). `user` went in UNQUOTED, into a pipeline that runs as ROOT. The only thing standing in
# front of it was the model's @validates hook, which fires on ASSIGNMENT and never on a row loaded
# from the database — so a pre-validator row, or one from a restored backup, was root RCE.
_rc_seen = []
_rc_o_run = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (_rc_seen.append(c), ("", "", 0))[1]
    _rc_ok, _rc_msg = _sm_core._rewrite_crontab(NS(), "gm; id > /tmp/pwned; #", "", ["x"])
    check("_rewrite_crontab: an unsafe account name is refused", _rc_ok is False, repr(_rc_msg))
    check("_rewrite_crontab: ...and no command was sent at all", not _rc_seen, str(_rc_seen)[:160])
    _rc_seen.clear()
    _sm_core._rewrite_crontab(NS(), "gmodserver", "", ["* * * * * /home/gmodserver/x"])
    check("_rewrite_crontab: a legitimate account still builds its pipeline",
          len(_rc_seen) == 1 and "sudo -u gmodserver bash -c" in _rc_seen[0], str(_rc_seen)[:160])
    # It used to be `sudo bash -c 'crontab -u <user> …'` — ROOT, for an operation that never needed
    # it, and refused outright on a host whose grant reaches root only through the helper, so every
    # cron write failed there: autostart, scheduled restarts, backup schedules.
    check("_rewrite_crontab: ...as the GAME USER, not as root",
          _rc_seen and "sudo bash -c" not in _rc_seen[0] and "crontab -u" not in _rc_seen[0],
          str(_rc_seen)[:200])
finally:
    _sm_core.run_command = _rc_o_run


# ── the cron journal is the remote's to write, so its parser has to be linear ─────────────────
# _read_cron_run_times pulled the command out of each journal line with
# `\)\s+CMD\s+\((.*)\)\s*$`, which is quadratic on a line of repeated ") CMD (" fragments with no
# closing parenthesis — 0.5 s at 42 KB, minutes at a megabyte — and it runs on the request
# greenlet, so one hostile line froze every user and host until it finished. Driven for real, with
# only the privileged read stubbed.
import time as _crj_time                                                            # noqa: E402
_crj_saved = _sm_core.run_privileged
_crj_out = {"v": ""}
try:
    _sm_core.run_privileged = lambda *a, **k: (_crj_out["v"], "", 0)
    _crj_cmd = "/home/gm/gmodserver monitor > /dev/null 2>&1"
    _crj_long = "echo " + "x" * 5000
    _crj_out["v"] = "\n".join([
        "1700000000.5 host CRON[1]: (gm) CMD (%s)" % _crj_cmd,
        "1700000100.0 host CRON[2]: (gm) CMD (%s)" % _crj_cmd,
        "1700000150.0 host CRON[3]: (other) CMD (/home/other/x start)",
        "1700000160.0 host CRON[4]: (gm) CMD (%s)" % _crj_long,
    ])
    _crj = _sm_cron._read_cron_run_times(NS(), "gm")
    check("cron journal: a normal line is read, and the LAST run wins (positive control)",
          _crj.get(_crj_cmd) == 1700000100 and len([k for k in _crj if "other" in k]) == 0,
          repr({k[:40]: v for k, v in _crj.items()}))
    check("cron journal: a line past the length ceiling is skipped before it is parsed",
          _crj_long not in _crj, "a %d-byte journal line was parsed" % len(_crj_long))
    _crj_out["v"] = "1700000200 host CRON[5]: (gm) CMD " + ") CMD (" * 20000 + "x"
    _crj_t = _crj_time.monotonic()
    _crj = _sm_cron._read_cron_run_times(NS(), "gm")
    _crj_el = _crj_time.monotonic() - _crj_t
    check("cron journal: a hostile 140 KB line costs nothing (the old regex took seconds)",
          _crj_el < 2.0 and _crj == {}, "%.2fs, %r" % (_crj_el, list(_crj)[:1]))
    # The extraction itself, on a line UNDER the ceiling: marker, "(", up to the final ")".
    check("cron journal: the command is everything between the marker's ( and the final )",
          _sm_cron._cron_log_command("1 h CRON[1]: (gm) CMD (a (b) c) ", "(gm) CMD ") == "a (b) c"
          and _sm_cron._cron_log_command("1 h CRON[1]: (gm) CMD (no close", "(gm) CMD ") is None,
          "")
finally:
    _sm_core.run_privileged = _crj_saved


def _cr_drive(fn, *a, **kw):
    """Run a cron editor for real: capture its command and execute it against files."""
    seen = {}
    _o_rc, _o_rp = _sm_core.run_command, _sm_core.run_privileged
    _o_st, _o_rt = _sm_cron._read_cron_status, _sm_cron._read_cron_run_times
    _o_icr = _sm_cron._install_cron_runner
    try:
        _sm_core.run_privileged = lambda *_a, **_k: (_CR_TAB.strip(), "", 0)
        _sm_cron._read_cron_status = lambda *_a, **_k: {}
        _sm_cron._read_cron_run_times = lambda *_a, **_k: {}
        # 0, not None: the runner install now REPORTS its rc, and a non-zero one makes the cron
        # editors refuse. A stub returning None would make every drive below refuse instead.
        _sm_cron._install_cron_runner = lambda *_a, **_k: 0
        _sm_core.run_command = lambda s, c, **k: (seen.__setitem__("cmd", c), ("", "", 0))[1]
        fn(*a, **kw)
    finally:
        _sm_core.run_command, _sm_core.run_privileged = _o_rc, _o_rp
        _sm_cron._read_cron_status, _sm_cron._read_cron_run_times = _o_st, _o_rt
        _sm_cron._install_cron_runner = _o_icr
    cmd = seen.get("cmd") or ""
    # `sudo -u gm bash -c '<pipeline>'` — it was `sudo bash -c` (root) until the pipeline stopped
    # needing root at all; the shape is asserted separately above, this only has to take it apart.
    if not cmd.startswith("sudo -u gm bash -c "):
        return None, "did not build a rewrite: %r" % cmd[:80]
    pipeline = _cr_shlex.split(cmd)[5]
    _src = os.path.join(_cr_sb, "in")
    _dst = os.path.join(_cr_sb, "out")
    with open(_src, "w", encoding="utf-8") as _fh:
        _fh.write(_CR_TAB)
    if os.path.exists(_dst):
        os.remove(_dst)
    pipeline = pipeline.replace("crontab -l 2>/dev/null", "cat %s" % _cr_shlex.quote(_src))
    pipeline = pipeline.replace('crontab "$T"', 'cp "$T" %s' % _cr_shlex.quote(_dst))
    _r = _cr_sub.run(["bash", "-c", pipeline], capture_output=True, text=True)
    return (open(_dst, encoding="utf-8").read() if os.path.exists(_dst) else None), _r.stderr


try:
    _cr_jobs = None
    _o_rp2, _o_st2, _o_rt2 = (_sm_core.run_privileged, _sm_cron._read_cron_status,
                              _sm_cron._read_cron_run_times)
    try:
        _sm_core.run_privileged = lambda *_a, **_k: (_CR_TAB.strip(), "", 0)
        _sm_cron._read_cron_status = lambda *_a, **_k: {}
        _sm_cron._read_cron_run_times = lambda *_a, **_k: {}
        _cr_jobs = _sm_cron.list_cron_jobs(None, "gm")
    finally:
        _sm_core.run_privileged, _sm_cron._read_cron_status = _o_rp2, _o_st2
        _sm_cron._read_cron_run_times = _o_rt2
    # ── a crontab that could not be READ is not an empty crontab ────────────────────────────
    # The rc was discarded, so every failure parsed to []. Three transports reach here: a local
    # helper failure, an unreachable tailscale/ssh host (which answers ("", "...", -1) rather than
    # raising), and an account with genuinely no crontab. Only the last is an ANSWER, and the
    # measured shapes of the other two are what these stubs reproduce — taken from a live host:
    # `crontab -u X -l` is rc 1 + "no crontab for X" for an account with none, rc 0 for an empty
    # but present one, and rc 1 + "user `X' unknown" for a missing account.
    def _cron_rc(out, err, rc):
        _o = _sm_core.run_privileged
        _s, _t = _sm_cron._read_cron_status, _sm_cron._read_cron_run_times
        try:
            _sm_core.run_privileged = lambda *_a, **_k: (out, err, rc)
            _sm_cron._read_cron_status = lambda *_a, **_k: {}
            _sm_cron._read_cron_run_times = lambda *_a, **_k: {}
            return _sm_cron.list_cron_jobs(None, "gm")
        finally:
            _sm_core.run_privileged = _o
            _sm_cron._read_cron_status, _sm_cron._read_cron_run_times = _s, _t

    check("cron list: a host that did not answer reads as UNKNOWN, not as no jobs",
          _cron_rc("", "ssh command error", -1) is None,
          "a failed read still parses to a list, which _sync_toggles_from_cron turns into a wipe")
    check("cron list: an account with genuinely no crontab reads as no jobs",
          _cron_rc("", "no crontab for gm", 1) == [],
          "the common empty case is being reported as a failure")
    check("cron list: an account that does not exist reads as UNKNOWN",
          _cron_rc("", "crontab:  user `gm' unknown", 1) is None,
          "'no jobs' is a claim the panel cannot make about an account it cannot see")
    check("cron list: an empty but PRESENT crontab reads as no jobs",
          _cron_rc("", "", 0) == [], "rc 0 is a successful read of an empty crontab")
    check("cron list: a crontab that read fine still parses to its jobs",
          isinstance(_cron_rc(_CR_TAB.strip(), "", 0), list)
          and len(_cron_rc(_CR_TAB.strip(), "", 0)) == len(_cr_jobs),
          "the success path changed shape")

    # ── the backup listing is three answers, not two ────────────────────────────────────────
    # It discarded the rc, so a host that did not answer parsed to [] and the Backups card said
    # "No backups yet." about a directory it had never reached — "nothing is protecting this
    # server" being the alarming half of the pair. The SENTINEL is the other half of the fix: the
    # command ends in a pipeline through `head`, which exits 0 whatever happened before it.
    # Measured on the test host — a game user with two archives prints both and then the
    # sentinel; `sudo -u <missing user>` prints "unknown user" and NO sentinel, with the rc of
    # the outer shell still 0.
    def _bk_rc(out, rc):
        _o = _sm_core.run_command
        try:
            _sm_core.run_command = lambda *_a, **_k: (out, "", rc)
            return _sm_cron.list_game_backups(None, "gm")
        finally:
            _sm_core.run_command = _o

    _BKD = _sm_cron._BACKUP_LIST_DONE
    check("backups list: a host that did not answer reads as UNKNOWN, not as no backups",
          _bk_rc("", -1) is None,
          "a failed read still parses to a list, and the card calls that 'No backups yet.'")
    check("backups list: a run cut short reads as UNKNOWN even when the rc is 0",
          _bk_rc("", 0) is None,
          "the trailing `| head` exits 0 whatever happened before it, so rc alone cannot see this")
    check("backups list: a server with genuinely no backups reads as none",
          _bk_rc(_BKD + "\n", 0) == [],
          "the common empty case is being reported as a failure")
    check("backups list: archives still parse, newest first",
          [b["name"] for b in (_bk_rc("F\ta.tar.gz\t100\t1000\nF\tb.tar.zst\t200\t2000\n" + _BKD + "\n", 0) or [])]
          == ["b.tar.zst", "a.tar.gz"],
          "the success path changed shape")
    # The sentinel has to be IN the command, or it can never come back and every read reads as
    # unknown — which would break backups everywhere rather than only mis-wording one card.
    _bk_cmd = {}

    def _bk_cap(_server, cmd, **_k):
        _bk_cmd["c"] = cmd
        return "", "", 0
    _o_rc = _sm_core.run_command
    try:
        _sm_core.run_command = _bk_cap
        _sm_cron.list_game_backups(None, "gm")
    finally:
        _sm_core.run_command = _o_rc
    check("backups list: the command actually prints the sentinel it is checked for",
          _BKD in _bk_cmd.get("c", ""),
          "the check can never be satisfied, so every listing would read as unreadable")

    _cr_raw = _cr_jobs[0]["raw"]
    check("cron identity: the browser is handed the line WITHOUT its indentation (the transport strips)",
          _cr_raw == "*/5 * * * * /home/gm/gmodserver monitor", repr(_cr_raw))
    _out, _err = _cr_drive(_sm_cron.delete_cron_job, None, "gm", _cr_raw)
    check("cron delete: an indented first line is actually removed",
          _out is not None and "gmodserver monitor" not in _out
          and len(_out.splitlines()) == 2, "%r / %r" % (_out, _err))
    _out, _err = _cr_drive(_sm_cron.update_cron_job, None, "gm", _cr_raw, "0 3 * * *",
                           "/home/gm/gmodserver monitor")
    check("cron update: rescheduling it replaces the line instead of adding a second one",
          _out is not None
          and sum(1 for ln in _out.splitlines() if "gmodserver monitor" in ln) == 1
          and _out.splitlines()[-1].startswith("0 3 * * * "), "%r / %r" % (_out, _err))
    # A line full of regex and shell metacharacters, and a backslash — the reason the comparison
    # goes through awk's ENVIRON rather than a pattern or a `-v` assignment.
    _cr_meta = _cr_jobs[1]["raw"]
    _out, _err = _cr_drive(_sm_cron.delete_cron_job, None, "gm", _cr_meta)
    check("cron delete: a line of metacharacters is matched literally, not as a pattern",
          _out is not None and "backup.sh" not in _out and len(_out.splitlines()) == 2,
          "%r / %r" % (_out, _err))
    # And a line the user did NOT name stays, trailing whitespace and all.
    check("cron delete: ...and nothing else is touched",
          _out is not None and "/home/gm/other.sh   " in _out, repr(_out))
finally:
    _cr_shutil.rmtree(_cr_sb, ignore_errors=True)

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

    # ── the CONFIG/MODS half of files.py validates its idents too ──────────────────────────────
    # _safe_abspath rejects an unsafe `user` for the eight PATH-taking functions; seven builders
    # beside them interpolated `user` into `sudo -u {user}` and `/home/{user}`, and `selfname`
    # into the bash -c script BODY, with nothing in front of them. `user` lands in the OUTER
    # shell — before sudo, as the PANEL user. Demonstrated with "x; id > /tmp/pwned; #", which
    # produced `sudo -u x; id > /tmp/pwned; # bash -c ...`. Not reachable from a request today
    # (every caller passes gs.short_name / gs.lgsm_name, pinned on assignment), which is exactly
    # the residual the note above _SAFE_UNIX_USER_RE describes.
    _hostile = "x; id > /tmp/pwned; #"
    _reached = []
    _sm_core.run_command = lambda s, c, **k: (_reached.append(c), ("", "", 0))[1]
    _sm_files.lgsm_read_config(_FakeSrv(), _hostile, "codserver")
    _sm_files.lgsm_get_values(_FakeSrv(), _hostile, "codserver", ["a"])
    _sm_files.lgsm_write_config(_FakeSrv(), _hostile, "codserver", {"a": "b"})
    _sm_files.lgsm_game_config(_FakeSrv(), "codserver", _hostile)
    _sm_files.mods_available(_FakeSrv(), _hostile, "codserver")
    _sm_files.mods_installed(_FakeSrv(), "codserver", _hostile)
    _sm_files.mods_action(_FakeSrv(), _hostile, "codserver", "install", "sourcemod")
    check("shell idents: a hostile account/script name reaches no shell at all",
          not _reached, str(_reached)[:200])
    # ...and the guard is not a blanket refusal: a legitimate name still builds its command.
    _reached.clear()
    _sm_files.lgsm_read_config(_FakeSrv(), "codserver", "codserver")
    check("shell idents: ...while a legitimate name still runs",
          len(_reached) == 1 and "sudo -u codserver" in _reached[0], str(_reached)[:120])

    # ── the CONSOLE path was the one `sudo -u <account>` builder in _core.py with NO guard ─────
    # read_as_game_user validates and _quote()s, run_as_game_user validates both names and
    # _quote()s — send_console_command did neither: `command` was quoted, `user` and `selfname`
    # were interpolated raw. `user` sits AHEAD of the `bash -c`, so it breaks out at the shell that
    # runs sudo, as the panel's SSH account — on a remote host that is the identity the panel
    # escalates with. `selfname` lands inside the script body via _tmux_live_socket_sh's grep and
    # has-session. The same row is refused by run_as_game_user and _rewrite_crontab; only the
    # console accepted it.
    _reached.clear()
    _con_bad_user = _sm_core.send_console_command(_FakeSrv(), _hostile, "status", selfname="codserver")
    _con_bad_self = _sm_core.send_console_command(_FakeSrv(), "codserver", "status", selfname=_hostile)
    check("console send: a hostile account/script name reaches no shell at all",
          not _reached, str(_reached)[:200])
    check("console send: ...and it answers the (out, err, rc) tuple every caller unpacks",
          (isinstance(_con_bad_user, tuple) and len(_con_bad_user) == 3
           and _con_bad_user[2] == 1 and _con_bad_self[2] == 1),
          "%r / %r — game.py reads out[2] as the rc and never catches a raise"
          % (_con_bad_user, _con_bad_self))
    # ...and the guard is not a blanket refusal: a legitimate name still builds its command, with
    # the account SHELL-QUOTED like read_as_game_user's.
    _reached.clear()
    _sm_core.send_console_command(_FakeSrv(), "codserver", "status", selfname="codserver")
    check("console send: ...while a legitimate name still runs, quoted",
          len(_reached) == 1 and _reached[0].startswith("sudo -u codserver bash -c "),
          str(_reached)[:160])

    # ── the editor must get the file's bytes, not a stripped copy ──────────────────────────────
    # Both transports strip: _core._finish returns (out or "").strip() and the paramiko branch
    # does out.strip(). read_file returned run_command's stdout unchanged, so the editor was handed
    # a file with its leading blank lines and its trailing newline removed — and write_file wrote
    # that back verbatim. Open any config, press Save without typing, and the file loses its
    # trailing newline; stream_path does NOT strip, so download and edit disagreed about the same
    # file. Driven through the real function with a transport that strips exactly as the real one
    # does, so the framing is what is under test and not the stub.
    #
    # The body inside the frame is BASE64 now, because framing cannot reach the OTHER way the
    # transport rewrites a file: both read paths decode in text mode, and Python's universal
    # newlines turn every CRLF into LF before read_file sees a byte. The write path is byte-exact
    # (it base64s too), so the damage was asymmetric and silent — open a CRLF config, press Save
    # without typing, and every line ending is permanently converted. Measured against a real
    # host: 'alpha\r\nbeta\r\ngamma\n' on disk came back as 'alpha\nbeta\ngamma\n'.
    import base64 as _rf_b64

    def _rf_transport(body):
        """What the host really sends: the frame, base64 inside it, then the transport's strip."""
        enc = _rf_b64.b64encode(body.encode()).decode()
        return lambda s, c, **k: (
            ("%s%s%s" % (_sm_files._READ_BEGIN, enc, _sm_files._READ_END)).strip(), "", 0)

    _ORIG_BODY = "\n\n-- header\nlocal x = 1\n\n\n"
    _sm_core.run_command = _rf_transport(_ORIG_BODY)
    _rf_body, _rf_err = _sm_files.read_file(_FakeSrv(), "csgoserver", "cfg/server.cfg")
    eq("read_file: the file's bytes survive the transport's strip", _rf_body, _ORIG_BODY)
    check("read_file: ...with no error", _rf_err is None, repr(_rf_err))
    # The regression this base64 exists for. A text-mode transport cannot carry these.
    _CRLF_BODY = "alpha\r\nbeta\r\ngamma\n"
    _sm_core.run_command = _rf_transport(_CRLF_BODY)
    eq("read_file: CRLF line endings survive, so the editor cannot silently convert them",
       _sm_files.read_file(_FakeSrv(), "csgoserver", "cfg/server.cfg")[0], _CRLF_BODY)
    _CR_BODY = "old\rmac\rendings\r"
    _sm_core.run_command = _rf_transport(_CR_BODY)
    eq("read_file: ...and so do bare CRs", 
       _sm_files.read_file(_FakeSrv(), "csgoserver", "cfg/server.cfg")[0], _CR_BODY)
    _sm_core.run_command = _rf_transport("")
    eq("read_file: a genuinely empty file reads as empty, not as a failure",
       _sm_files.read_file(_FakeSrv(), "csgoserver", "cfg/server.cfg"), ("", None))
    # A framed body that is NOT base64 means something mangled it in transit — that must read as a
    # failed read, never as content, or the editor saves the garbage back over the real file.
    _sm_core.run_command = lambda s, c, **k: (
        "%s not!base64!!%s" % (_sm_files._READ_BEGIN, _sm_files._READ_END), "", 0)
    _rf_bad, _rf_baderr = _sm_files.read_file(_FakeSrv(), "csgoserver", "cfg/server.cfg")
    check("read_file: a framed body that is not base64 is a FAILED read, not content",
          _rf_bad is None and bool(_rf_baderr), repr(_rf_bad))
    # Every check above stubs the TRANSPORT, so they all still pass if the shell side goes back to
    # a bare `cat` — the stub would keep sending base64 either way. Assert the command actually
    # ASKS the host to encode. [[test-the-caller-not-just-the-helper]]
    _rf_cmds = []
    _sm_core.run_command = lambda s, c, **k: (
        _rf_cmds.append(c),
        ("%s%s%s" % (_sm_files._READ_BEGIN, _rf_b64.b64encode(b"x").decode(), _sm_files._READ_END)),
        )[1] and (("%s%s%s" % (_sm_files._READ_BEGIN, _rf_b64.b64encode(b"x").decode(),
                               _sm_files._READ_END)), "", 0)
    _sm_files.read_file(_FakeSrv(), "csgoserver", "cfg/server.cfg")
    check("read_file: the command tells the HOST to base64 the body, not cat it raw",
          len(_rf_cmds) == 1 and "base64 " in _rf_cmds[0] and "; cat " not in _rf_cmds[0],
          _rf_cmds[0][:150] if _rf_cmds else "no command captured")
    # The 1 MB cap has to measure the FILE, not a symlink to it. GNU stat does not dereference
    # without -L, so `stat -c %s` on `latest.log -> …/errors.log` reported the link's ~45-byte
    # target string while [ -f ], [ -s ], grep and base64 all followed it — a multi-GB log sailed
    # past the refusal and was base64'd into one Python string. stat_path already uses -Lc.
    # Asserted on the COMMAND, because every check above stubs the transport and would pass either
    # way. [[test-the-caller-not-just-the-helper]]
    _rf_cmd1 = _rf_cmds[0] if _rf_cmds else ""
    check("read_file: the size cap measures the symlink's TARGET (stat -Lc), not the link",
          "stat -Lc %s" in _rf_cmd1 and "stat -c %s" not in _rf_cmd1,
          _rf_cmd1[:200] or "no command captured")
    # ...and a size that could not be READ must refuse. `[ "" -gt N ]` is a bash error whose
    # non-zero status makes the `if` false, so an unreadable size fell through to an UNCAPPED read.
    check("read_file: ...and a non-numeric/empty size stops the read instead of skipping the cap",
          'case "$sz" in ' in _rf_cmd1 and "|*[!0-9]*) exit 0;;" in _rf_cmd1,
          _rf_cmd1[:260] or "no command captured")
    # Positive control: the cap itself is still applied and still answers __TOOBIG__ (the marker
    # loop below re-checks the Python side), and the guard is not a blanket refusal.
    check("read_file: ...while the cap is still there for a size that IS a number",
          "-gt 1048576" in _rf_cmd1, _rf_cmd1[:200] or "no command captured")
    # ...and the markers the script really does emit are still recognised.
    for _mark, _want in (("__NOFILE__", "File not found"),
                         ("__TOOBIG__", "File is too large to edit in the browser"),
                         ("__BINARY__", "Binary file — download/replace via upload instead")):
        _sm_core.run_command = lambda s, c, _m=_mark, **k: (_m, "", 0)
        eq("read_file: %s is still reported" % _mark,
           _sm_files.read_file(_FakeSrv(), "csgoserver", "cfg/server.cfg")[1], _want)
    # An unframed body means the read never got as far as `cat`. It used to be returned as
    # CONTENT ("fall back rather than returning nothing"), and that is destructive rather than
    # merely wrong: run_command does not raise on the local or Tailscale transports — it returns
    # ("", "…timed out", -1) — and a `sudo -u` refusal puts its message on stderr with empty
    # stdout. Either way api_server_file answered 200 {"content": ""}, the editor showed an empty
    # file, and pressing Save wrote "" over the real config. The sentinel framing already knows
    # the difference; these pin that it SAYS so.
    _sm_core.run_command = lambda s, c, **k: ("plain contents", "", 0)
    _rf_u, _rf_uerr = _sm_files.read_file(_FakeSrv(), "csgoserver", "cfg/server.cfg")
    check("read_file: an unframed body is a FAILED read, not content", _rf_u is None, repr(_rf_u))
    check("read_file: ...and it reports the error, so the editor cannot save it back",
          bool(_rf_uerr), repr(_rf_uerr))
    # The destructive case by name: a transport that failed without raising.
    _sm_core.run_command = lambda s, c, **k: ("", "SSH command timed out", -1)
    eq("read_file: a failed transport does not read as an empty file",
       _sm_files.read_file(_FakeSrv(), "csgoserver", "cfg/server.cfg")[0], None)
    # A genuinely empty file still round-trips — it arrives FRAMED.
    _sm_core.run_command = lambda s, c, **k: (
        ("%s%s" % (_sm_files._READ_BEGIN, _sm_files._READ_END)).strip(), "", 0)
    eq("read_file: a file that really is empty still reads as empty",
       _sm_files.read_file(_FakeSrv(), "csgoserver", "cfg/server.cfg")[0], "")

    # ── lgsm_game_config: "this game has no config file" is a claim about the GAME ─────────────
    # `./<selfname> details` is a 45-second LinuxGSM run on a possibly-busy host — the most
    # timeout-prone read in the module — and the rc was discarded. When it did not run, nothing
    # matched the `config file:` regex and the panel stated as fact that LinuxGSM had reported no
    # editable config for this game. It reported nothing, because it was never asked; the admin
    # concludes their server.cfg does not exist and stops looking. A DONE marker printed after the
    # run separates "details said nothing" from "details never answered", exactly as
    # lgsm_read_config frames its sections.
    _GC_LINE = "  Config file: /home/csgoserver/serverfiles/cfg/server.cfg\n"

    def _gc_transport(details_out):
        """Answer the `details` command with `details_out`; serve read_file a real framed body."""
        _framed = "%s%s%s" % (_sm_files._READ_BEGIN,
                              _rf_b64.b64encode(b"hostname \"x\"\n").decode(), _sm_files._READ_END)
        return lambda s, c, **k: ((details_out, "", 0) if " details " in c else (_framed, "", 0))

    _sm_core.run_command = lambda s, c, **k: ("", "SSH command timed out", -1)
    _gc_dead = _sm_files.lgsm_game_config(_FakeSrv(), "csgoserver", "csgoserver")
    check("game config: a details run that never answered is not 'this game has no config file'",
          _gc_dead.get("rel") is None and "did not answer" in (_gc_dead.get("error") or ""),
          "%r — the admin is told their game has no editable config" % (_gc_dead,))
    # Output that arrived but was cut short (no marker) is the same unread state, not a reading.
    _sm_core.run_command = _gc_transport("LinuxGSM - Counter-Strike\nDistro Details\n")
    _gc_part = _sm_files.lgsm_game_config(_FakeSrv(), "csgoserver", "csgoserver")
    check("game config: ...and neither is a truncated details run",
          _gc_part.get("rel") is None and "did not answer" in (_gc_part.get("error") or ""),
          repr(_gc_part))
    # POSITIVE CONTROL 1: details really did run and really did name no config file — the original
    # message must survive, or this "fix" just replaced one wrong answer with another.
    _sm_core.run_command = _gc_transport("LinuxGSM - Call of Duty\nNo config here\n"
                                         + _sm_files._DETAILS_DONE)
    _gc_none = _sm_files.lgsm_game_config(_FakeSrv(), "csgoserver", "csgoserver")
    check("game config: a details run that COMPLETED and named none still says so",
          _gc_none.get("rel") is None
          and "No editable game config file" in (_gc_none.get("error") or ""),
          repr(_gc_none))
    # POSITIVE CONTROL 2: the normal path still finds and reads the file.
    _sm_core.run_command = _gc_transport("LinuxGSM - Counter-Strike\n" + _GC_LINE
                                         + _sm_files._DETAILS_DONE)
    _gc_ok = _sm_files.lgsm_game_config(_FakeSrv(), "csgoserver", "csgoserver")
    eq("game config: a normal details run still yields the config path",
       _gc_ok.get("rel"), "serverfiles/cfg/server.cfg")
    check("game config: ...and its contents, with no error",
          _gc_ok.get("exists") is True and _gc_ok.get("error") is None
          and "hostname" in (_gc_ok.get("content") or ""), repr(_gc_ok)[:160])
    check("game config: ...and the marker itself never reaches the editor",
          _sm_files._DETAILS_DONE not in (_gc_ok.get("content") or ""), repr(_gc_ok)[:160])

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
# It moved to panel.core.validation with the rest of the pure layer; the name `_appmod` is kept so
# the checks below read unchanged.
from panel.core import validation as _appmod
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

# ...and every route that sends a download actually USES it. The helper is only worth having if
# nothing rolls its own beside it, and something did: the game-backup download built
# `'attachment; filename="%s"' % basename(name)` by hand from a name read off the HOST's
# filesystem — list_game_backups basenames whatever sits in ~/lgsm/backup, so the panel does not
# choose it. Both ways that can go are a 500 on a download that should have worked: Werkzeug
# raises ValueError on a CR/LF in a header value, and any character outside latin-1 (an em-dash, a
# CJK name, an emoji in a map-pack archive) raises UnicodeEncodeError when the response is
# serialised. A gate, not a one-off fix, because the next download route would repeat it.
import ast as _cd_ast
_cd_sources = []
for _cd_dir in (os.path.join(_root, "panel"),):
    for _cd_base, _cd_dirs, _cd_names in os.walk(_cd_dir):
        _cd_sources += [os.path.join(_cd_base, n) for n in _cd_names if n.endswith(".py")]
_cd_sources.append(os.path.join(_root, "app.py"))
_cd_sites, _cd_bad = 0, []
for _cd_path in sorted(_cd_sources):
    _cd_tree = _cd_ast.parse(open(_cd_path, encoding="utf-8").read(), filename=_cd_path)
    for _cd_n in _cd_ast.walk(_cd_tree):
        # resp.headers["Content-Disposition"] = <value>
        if not isinstance(_cd_n, _cd_ast.Assign):
            continue
        for _cd_t in _cd_n.targets:
            if not (isinstance(_cd_t, _cd_ast.Subscript)
                    and isinstance(_cd_t.slice, _cd_ast.Constant)
                    and _cd_t.slice.value == "Content-Disposition"):
                continue
            _cd_sites += 1
            _cd_v = _cd_n.value
            _cd_ok = (isinstance(_cd_v, _cd_ast.Call)
                      and ((isinstance(_cd_v.func, _cd_ast.Name)
                            and _cd_v.func.id == "_attachment_header")
                           or (isinstance(_cd_v.func, _cd_ast.Attribute)
                               and _cd_v.func.attr == "_attachment_header")))
            if not _cd_ok:
                _cd_bad.append("%s:%d" % (os.path.relpath(_cd_path, _root), _cd_n.lineno))
check("download header: every Content-Disposition the panel sets goes through _attachment_header",
      not _cd_bad, "hand-built at: %s" % ", ".join(_cd_bad))
check("download header: ...and the scan really found the places that set one",
      _cd_sites >= 2, "found only %d Content-Disposition assignment(s)" % _cd_sites)


# ── lgsm_write_config must never write a config it could not read ───────────────────────────────
# It was `cat … 2>/dev/null` with the rc DISCARDED (`out, _, _ =`). run_command does not raise on a
# transport failure — it returns ("", "…timed out", -1) — so a hiccup made `out` empty, `lines`
# empty, and the join wrote a config containing ONLY the keys being updated, OVER the real instance
# config, returning ok=True. Measured on a live host: a 5-line, 189-byte fctrserver.cfg became one
# line, `port="34197"`. That path runs during an install, a port change, and every alert edit.
#
# `2>/dev/null` also hid the distinction that matters: a MISSING instance cfg is legitimate (a fresh
# instance has none), a failed read is not. These pin both halves.
import base64 as _wc_b64

_wc_orig = (_sm_core.run_command, _sm_files._write_file_as_user)
try:
    _wc = {"written": [], "read": None}
    _sm_files._write_file_as_user = lambda s, u, p, b: (
        _wc["written"].append((p, b.decode())), (True, ""))[1]

    def _wc_transport(resp):
        _wc["read"] = resp
        _sm_core.run_command = lambda s, c, **k: resp

    def _framed(text):
        enc = _wc_b64.b64encode(text.encode()).decode()
        return ("%s%s%s" % (_sm_files._READ_BEGIN, enc, _sm_files._READ_END), "", 0)

    EXISTING = '## header\nport="27015"\nmaxplayers="16"\n'

    # 1. THE BUG: a failed read must abort, not write a truncated file.
    _wc["written"] = []
    _wc_transport(("", "SSH command timed out", -1))
    _ok, _msg = _sm_files.lgsm_write_config(NS(), "fctrserver", "fctrserver", {"port": "34197"})
    check("lgsm_write_config: a FAILED read refuses to write", _ok is False, repr(_msg))
    check("lgsm_write_config: ...and writes nothing at all", _wc["written"] == [],
          repr(_wc["written"])[:110])
    check("lgsm_write_config: ...and says the config was not changed",
          "nothing has been changed" in (_msg or "").lower(), repr(_msg))

    # 2. A missing instance cfg is legitimate — the updates become the file.
    _wc["written"] = []
    _wc_transport(("__NOFILE__", "", 0))
    _ok, _msg = _sm_files.lgsm_write_config(NS(), "fctrserver", "fctrserver", {"port": "34197"})
    check("lgsm_write_config: a MISSING cfg still writes the updates", _ok is True, repr(_msg))
    eq("lgsm_write_config: ...as the whole file",
       _wc["written"][0][1] if _wc["written"] else None, 'port="34197"\n')

    # 3. An existing key is replaced and every other line survives.
    _wc["written"] = []
    _wc_transport(_framed(EXISTING))
    _sm_files.lgsm_write_config(NS(), "fctrserver", "fctrserver", {"port": "34197"})
    _body = _wc["written"][0][1] if _wc["written"] else ""
    check("lgsm_write_config: the changed key is replaced in place",
          'port="34197"' in _body and 'port="27015"' not in _body, repr(_body))
    check("lgsm_write_config: ...and the rest of the file survives",
          "## header" in _body and 'maxplayers="16"' in _body, repr(_body))

    # 4. A new key is appended, not substituted for the file.
    _wc["written"] = []
    _wc_transport(_framed(EXISTING))
    _sm_files.lgsm_write_config(NS(), "fctrserver", "fctrserver", {"newkey": "yes"})
    _body = _wc["written"][0][1] if _wc["written"] else ""
    check("lgsm_write_config: a NEW key is appended to the existing file",
          'newkey="yes"' in _body and "## header" in _body and 'port="27015"' in _body, repr(_body))

    # 5. A framed body that is not base64 means something mangled it — refuse.
    _wc["written"] = []
    _sm_core.run_command = lambda s, c, **k: (
        "%s not!base64!!%s" % (_sm_files._READ_BEGIN, _sm_files._READ_END), "", 0)
    _ok, _msg = _sm_files.lgsm_write_config(NS(), "fctrserver", "fctrserver", {"port": "1"})
    check("lgsm_write_config: a non-base64 framed body refuses too", _ok is False and not _wc["written"],
          repr(_msg))

    # 6. The caller side: the command must actually ask for the frame, or every check above still
    #    passes with the old `cat`. [[test-the-caller-not-just-the-helper]]
    _wc_cmds = []
    _sm_core.run_command = lambda s, c, **k: (_wc_cmds.append(c), _framed(EXISTING))[1]
    _sm_files.lgsm_write_config(NS(), "fctrserver", "fctrserver", {"port": "1"})
    check("lgsm_write_config: the read command is framed, not a bare cat",
          len(_wc_cmds) == 1 and _sm_files._READ_BEGIN in _wc_cmds[0] and "__NOFILE__" in _wc_cmds[0],
          (_wc_cmds[0][:140] if _wc_cmds else "none"))
finally:
    _sm_core.run_command, _sm_files._write_file_as_user = _wc_orig


# ── lgsm_read_config: a marker that can fuse to file content, and no failure detection ──────────
# The Raw tab read three files with `echo ===MARKER; cat file`. `echo` only lands on its own line
# if the PREVIOUS file ended with a newline — a common.cfg without one produced `a=1===INSTANCE`,
# which matches nothing, so the INSTANCE section stayed empty and `raw` came back "". The editor
# then showed an EMPTY box for a real config and Save wrote that "" over it. Measured on a live
# host: a 5-line fctrserver.cfg rendered as 0 bytes with error=None.
# rc was discarded too (`out, _, _ =`), so a timed-out read was indistinguishable from an empty one.
_rc_orig = _sm_core.run_command
try:
    def _sections(default="", common="", instance="", omit=()):
        """What the framed reader really receives, with the transport's strip applied."""
        parts = []
        for tag, text in (("DEFAULT", default), ("COMMON", common), ("INSTANCE", instance)):
            if tag in omit:
                continue
            enc = _wc_b64.b64encode(text.encode()).decode()
            parts.append("__LGSMP_%s_B__%s__LGSMP_%s_E__" % (tag, enc, tag))
        return ("".join(parts).strip(), "", 0)

    _INST = '## header\nport="27015"\n'

    # THE BUG: a common.cfg with no trailing newline used to swallow the INSTANCE marker.
    _sm_core.run_command = lambda s, c, **k: _sections(common="a=1", instance=_INST)
    _r = _sm_files.lgsm_read_config(NS(), "fctrserver", "fctrserver")
    eq("lgsm_read_config: a common.cfg with NO trailing newline still yields the instance raw",
       _r.get("raw"), _INST)
    check("lgsm_read_config: ...and reports no error", _r.get("error") is None, repr(_r.get("error")))

    # Byte fidelity, same reason read_file needed it: the editor saves what it was shown.
    _CRLF = 'a="1"\r\nb="2"\r\n'
    _sm_core.run_command = lambda s, c, **k: _sections(instance=_CRLF)
    eq("lgsm_read_config: CRLF survives into the raw editor", 
       _sm_files.lgsm_read_config(NS(), "fctrserver", "fctrserver").get("raw"), _CRLF)

    # A genuinely absent file is an empty section, not a failure.
    _sm_core.run_command = lambda s, c, **k: _sections(instance="")
    _r = _sm_files.lgsm_read_config(NS(), "fctrserver", "fctrserver")
    check("lgsm_read_config: an absent instance cfg is empty, not an error",
          _r.get("raw") == "" and _r.get("error") is None, repr(_r.get("error")))

    # A FAILED read (no frames at all) must say so, not hand the editor "".
    for _desc, _resp in (("a timed-out read", ("", "SSH command timed out", -1)),
                         ("a sudo refusal", ("", "sudo: a password is required", 1)),
                         ("a partial answer", _sections(instance=_INST, omit=("INSTANCE",)))):
        _sm_core.run_command = lambda s, c, _r=_resp, **k: _r
        _r2 = _sm_files.lgsm_read_config(NS(), "fctrserver", "fctrserver")
        check("lgsm_read_config: %s is an ERROR, not an empty config" % _desc,
              _r2.get("raw") == "" and bool(_r2.get("error")), repr(_r2)[:90])

    # The caller side: the command must actually frame, or every check above passes with `echo ===`.
    _rc_cmds = []
    _sm_core.run_command = lambda s, c, **k: (_rc_cmds.append(c), _sections(instance=_INST))[1]
    _sm_files.lgsm_read_config(NS(), "fctrserver", "fctrserver")
    check("lgsm_read_config: the command frames each section instead of echoing a marker",
          len(_rc_cmds) == 1 and "__LGSMP_INSTANCE_B__" in _rc_cmds[0]
          and "echo ===INSTANCE" not in _rc_cmds[0],
          (_rc_cmds[0][:130] if _rc_cmds else "none"))
finally:
    _sm_core.run_command = _rc_orig


# ── install.sh: the update path's stopped-service window must survive its own failures ──────────
# Two defects lived in the same stretch of install.sh, and both were invisible from the outside.
#
#  1. The data-dir tar ran TEN LINES BEFORE the service was stopped, i.e. against a live database.
#     panel.db is in WAL mode with ~10 daemon threads committing into it, so tar read panel.db,
#     panel.db-wal and panel.db-shm as three separate non-atomic reads while a writer was
#     mid-commit. tar says "file changed as we read it" and exits 1 when that happens; `2>/dev/null
#     … || true` discarded both, and snapshot_ok only asks whether the archive UNPACKS. So the
#     script printed "Snapshot saved" over a torn copy — the only copy the rollback has, and it
#     wipes data/ before unpacking it.
#
#  2. Between the stop and [5/6] there was no trap at all. Under `set -euo pipefail` a failed pip,
#     an unreadable requirements.txt or a full disk mid-fetch simply ended the script with the
#     panel stopped. The rollback block at the bottom is reachable only from a FAILED HEALTH
#     CHECK, so it ran for none of them, and the in-panel self-update (which only watches the log)
#     showed `=== installer exit 1 ===` next to a dead panel.
#
#  3. …and then the FIX for (2) reintroduced (2) for a whole class of exits: die() disarmed the
#     trap, so every `die` reached through a function call inside the window — fetch_code's
#     missing git, and the `visudo -cf` check in both sudoers grants — still ended with the panel
#     stopped. Nothing here ran that stretch of the window, so nothing noticed. The gates below
#     run it, and they ask about dies in general rather than about those three call sites, because
#     the next `die` written in there inherits whatever answer die() gives.
#
# These gates EXECUTE the real extracted window in bash rather than grepping for `trap`, because
# the question is what actually happens when a command inside it fails — and because a trap armed
# over this stretch is itself dangerous: the window is full of `[ "${RUN_AS_ROOT}" -eq 1 ] && …`
# lines, and a trap that fired on those would abort every non-root update. The controls below
# cover both directions.
import shlex as _iw_shlex        # noqa: E402
import shutil as _iw_shutil      # noqa: E402
import subprocess as _iw_sub     # noqa: E402
import tempfile as _iw_tmp       # noqa: E402

_iw_src = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
_iw_upd = _iw_src[_iw_src.index('if [ "${IS_UPDATE}" -eq 1 ]; then'):
                  _iw_src.index("    # ── Health check FAILED")]

# (1) Ordering: quiesce, THEN tar the database. The gates that MEASURE that ordering EXECUTE
# [1/6] and [2/6] further down, because comparing the offset of `svc stop` against the offset of
# the data tar is equally true of a stop moved to the WRONG side of the code snapshot, where it
# would make [1/6]'s own die message ("update ABORTED, the panel is unchanged") false again.
# This one gate stays textual because it is a property of the whole update block, which executing
# a single stretch of it cannot see: there must be exactly one stop, not a second one added later.
check("install.sh: ...and the update path still stops the service exactly once",
      _iw_upd.count("svc stop linuxgsm-panel.service") == 1,
      "found %d" % _iw_upd.count("svc stop linuxgsm-panel.service"))


def _iw_seg(start, end):
    """install.sh text from `start` through `end` inclusive — "" when either marker is gone.

    Returning "" rather than raising is deliberate: a missing trap must make the BEHAVIOUR checks
    below fail by name (the panel was never restarted), not blow the suite up with a ValueError
    that reads like a broken harness."""
    i = _iw_src.find(start)
    j = _iw_src.find(end, i) if i >= 0 else -1
    return _iw_src[i:j + len(end)] if j >= 0 else ""


def _iw_upto(start, end):
    """Same, but STOPPING at `end` instead of including it — for markers that are whole lines."""
    i = _iw_src.find(start)
    j = _iw_src.find(end, i) if i >= 0 else -1
    return _iw_src[i:j] if j >= 0 else ""


_iw_die = ([ln for ln in _iw_src.splitlines() if ln.startswith("die()")] or [""])[-1]
# The handler + its arming, exactly as install.sh has them…
_iw_window = _iw_seg("    _CODE_FETCHED=0", "trap _update_window_abort ERR EXIT")
# …the real [3/6] call site, so the marker that tells the handler the tree has been replaced is
# the one install.sh actually sets, not one this harness helpfully sets for it…
_iw_fetch = _iw_seg("    fetch_code\n", "_CODE_FETCHED=1")
# …and the whole of [5/6], which is where the window is handed back to the health check.
_iw_disarm = _iw_seg('    info "[5/6] Starting the service', "trap - ERR EXIT HUP INT TERM")
# The snapshot verifier, on its own, so the archives below can be fed to the real function…
_iw_snapfn = ([ln.strip() for ln in _iw_src.splitlines()
               if ln.strip().startswith("snapshot_ok() {")] or [""])[0]
# …[1/6] and [2/6] entire, which is what the ordering above is actually a claim about…
_iw_stage12 = _iw_upto('    info "[1/6] Snapshotting', '    info "[3/6] Fetching')
# …and the root-owned refresh at the END of the window. A leading newline anchors it to the
# 4-space-indented copy inside the window, not the 8-space one in the already-up-to-date branch.
_iw_grants = _iw_upto("\n    check_origin_trusted\n", '\n    info "[5/6]')


def _iw_run(scenario, panel_dir, backup):
    """Run install.sh's real stopped-window code in bash, then `scenario`. → (rc, output).

    Everything that would touch the host (systemctl, pip, the tuning drop-ins) is stubbed to echo,
    so this measures the control flow and nothing else."""
    script = "\n".join([
        "set -euo pipefail",
        "RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''",
        'info() { echo "INFO $*"; }',
        'ok()   { echo "OK $*"; }',
        'warn() { echo "WARN $*"; }',
        _iw_die,
        'svc() { echo "SVC $*"; }',
        "install_deps() { echo 'INSTALL_DEPS'; }",
        "fetch_code() { echo 'FETCH_CODE'; }",
        "ensure_service_tuning() { :; }",
        "ensure_system_tuning() { :; }",
        "install_recovery_command() { :; }",
        "FROM_VER='1.2.3'",
        "RUN_AS_ROOT=0",
        "PANEL_USER='nobody'",
        "PANEL_DIR=%s" % _iw_shlex.quote(panel_dir),
        "BACKUP=%s" % _iw_shlex.quote(backup),
        _iw_window,
        scenario,
        "echo 'WINDOW-COMPLETED'",
    ])
    p = _iw_sub.run(["bash", "-c", script], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def _iw_run_stage12(panel_dir, backup, evlog, data_tar_empty=False):
    """Execute install.sh's real [1/6]+[2/6] — snapshot, stop, database maintenance. → (rc, out, ev)

    Only what would touch the host is stubbed (systemctl, the maintenance tool). tar and gzip are
    REAL, so the archives are the archives install.sh would produce. The tar wrapper is there to
    record WHICH snapshot is being taken WHEN: the claim these gates make is "the database is
    copied while nothing is writing to it", and that is an ordering between two runtime events,
    not between two offsets in the source."""
    script = "\n".join([
        "set -euo pipefail",
        "RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''",
        'info() { echo "INFO $*"; }',
        'ok()   { echo "OK $*"; }',
        'warn() { echo "WARN $*"; }',
        _iw_die,
        "EVLOG=%s" % _iw_shlex.quote(evlog),
        '_ev() { echo "$*" >> "${EVLOG}"; }',
        'svc() { _ev "SVC $*"; echo "SVC $*"; }',
        "install_deps() { echo 'INSTALL_DEPS'; }",
        # [2/6] picks the ROOT-owned maintenance tool when euid is 0; pin the unprivileged shape so
        # this measures the same branch whoever runs the suite.
        'id() { if [ "${1:-}" = "-u" ]; then echo 1000; else command id "$@"; fi; }',
        "DATA_TAR_EMPTY=%s" % ("true" if data_tar_empty else "false"),
        "tar() {",
        '    case "$*" in',
        '        *--exclude=./venv*)     _ev "TAR-CODE" ;;',
        '        *--exclude=./.backups*) _ev "TAR-DATA"',
        "                                if ${DATA_TAR_EMPTY}; then return 0; fi ;;",
        '        *-tzf*)                 _ev "TAR-VERIFY" ;;',
        "    esac",
        '    command tar "$@"',
        "}",
        "FROM_VER='1.2.3'",
        "RUN_AS_ROOT=0",
        "PANEL_USER='nobody'",
        "PANEL_DIR=%s" % _iw_shlex.quote(panel_dir),
        "BACKUP=%s" % _iw_shlex.quote(backup),
        _iw_stage12,
        "trap - ERR EXIT HUP INT TERM",
        "echo 'WINDOW-COMPLETED'",
    ])
    p = _iw_sub.run(["bash", "-c", script], capture_output=True, text=True)
    _ev = []
    if os.path.exists(evlog):
        with open(evlog, encoding="utf-8") as _fh:
            _ev = [ln for ln in _fh.read().splitlines() if ln]
    return p.returncode, p.stdout + p.stderr, _ev


def _iw_evat(events, prefix):
    """Index of the first recorded event starting with `prefix`, or -1."""
    for _i, _ln in enumerate(events):
        if _ln.startswith(prefix):
            return _i
    return -1


def _iw_snapshot_ok(path):
    """install.sh's real snapshot_ok, run against one file. → its exit status."""
    return _iw_sub.run(["bash", "-c", "\n".join([
        "set -euo pipefail", _iw_snapfn, "snapshot_ok %s" % _iw_shlex.quote(path)])],
        capture_output=True, text=True).returncode


_iw_dir = _iw_tmp.mkdtemp(prefix="lgsmp-instwin-")
try:
    _iw_pd = os.path.join(_iw_dir, "linuxgsm-panel")
    _iw_bk = os.path.join(_iw_dir, "snapshot")
    os.makedirs(_iw_pd)
    os.makedirs(_iw_bk)

    # (2) THE DEFECT: a bare failure inside the window (pip could not reach PyPI) used to end the
    # script here — panel stopped, nothing said.
    _iw_rc, _iw_out = _iw_run("false   # e.g. install_deps: pip could not reach PyPI",
                              _iw_pd, _iw_bk)
    check("install.sh: a failure inside the stopped window still starts the panel back up",
          "SVC start linuxgsm-panel.service" in _iw_out, _iw_out[-300:])
    check("install.sh: ...and tells the operator where the snapshot of the attempt is",
          _iw_bk in _iw_out, _iw_out[-300:])
    check("install.sh: ...and says what happened, instead of ending the script with no message",
          "aborted unexpectedly" in _iw_out and "WINDOW-COMPLETED" not in _iw_out and _iw_rc != 0,
          "rc=%d %s" % (_iw_rc, _iw_out[-300:]))

    # …and once fetch_code has swapped the tree, the abort has to put the OLD code back, not just
    # restart the service on top of a half-installed new version. This runs the REAL [3/6] call
    # site, so it covers the line that records the swap as well as the handler that reads it — the
    # handler alone is untested code if nothing ever sets the marker.
    with open(os.path.join(_iw_pd, "old.txt"), "w") as _fh:
        _fh.write("previous version")
    _iw_sub.run(["tar", "-C", _iw_pd, "-czf", os.path.join(_iw_bk, "code.tgz"), "."], check=True)
    os.remove(os.path.join(_iw_pd, "old.txt"))
    with open(os.path.join(_iw_pd, "new.txt"), "w") as _fh:
        _fh.write("half-installed new version")
    _iw_rc, _iw_out = _iw_run(
        _iw_fetch + "\nfalse   # e.g. install_deps, AFTER fetch_code replaced the tree",
        _iw_pd, _iw_bk)
    check("install.sh: an abort after fetch_code restores the previous version from the snapshot",
          os.path.exists(os.path.join(_iw_pd, "old.txt"))
          and not os.path.exists(os.path.join(_iw_pd, "new.txt")),
          "left behind: %s" % sorted(os.listdir(_iw_pd)))
    check("install.sh: ...and starts the panel on it", "SVC start linuxgsm-panel.service" in _iw_out,
          _iw_out[-300:])

    # CONTROL A — a DELIBERATE die inside the window keeps its own, accurate message. If the trap
    # also fired on it the operator would get a second, vaguer [ERROR] stacked on top.
    _iw_rc, _iw_out = _iw_run('die "Couldn\'t snapshot the database/config — update ABORTED."',
                              _iw_pd, _iw_bk)
    check("install.sh: a deliberate die inside the window is not overwritten by the abort handler",
          "Couldn't snapshot the database/config" in _iw_out
          and "aborted unexpectedly" not in _iw_out, _iw_out[-300:])

    # CONTROL B — the ordinary path must still finish. [5/6] starts the service and disarms, so a
    # clean run reaches the health check with no abort message at all.
    _iw_rc, _iw_out = _iw_run(_iw_disarm, _iw_pd, _iw_bk)
    check("install.sh: a clean run reaches [5/6], starts the panel and hands over to the health check",
          _iw_rc == 0 and "WINDOW-COMPLETED" in _iw_out and "aborted unexpectedly" not in _iw_out,
          "rc=%d %s" % (_iw_rc, _iw_out[-300:]))

    # CONTROL C — the window is full of `[ "${RUN_AS_ROOT}" -eq 1 ] && …` guards whose test fails
    # on every non-root install. A trap that treated those as aborts would break every `--user`
    # update, which is the common case.
    _iw_rc, _iw_out = _iw_run('[ "${RUN_AS_ROOT}" -eq 1 ] && echo "ROOT-ONLY STEP"\n' + _iw_disarm,
                              _iw_pd, _iw_bk)
    check("install.sh: a skipped root-only step inside the window is not treated as an abort",
          _iw_rc == 0 and "WINDOW-COMPLETED" in _iw_out and "aborted unexpectedly" not in _iw_out,
          "rc=%d %s" % (_iw_rc, _iw_out[-300:]))

    # CONTROL C2 — the rest of the window's ordinary vocabulary. A failure that the script itself
    # is testing, or explicitly tolerating, is not an abort either.
    for _desc, _snippet in (
            ("an `if ! cmd` test", 'if ! false; then echo "BRANCH-TAKEN"; fi'),
            ("a tolerated `cmd || true`", "false || true"),
            ("a fallback command substitution", '_x="$(false || echo fallback)"; echo "X=${_x}"')):
        _iw_rc, _iw_out = _iw_run(_snippet + "\n" + _iw_disarm, _iw_pd, _iw_bk)
        check("install.sh: %s inside the window is not treated as an abort" % _desc,
              _iw_rc == 0 and "WINDOW-COMPLETED" in _iw_out
              and "aborted unexpectedly" not in _iw_out, "rc=%d %s" % (_iw_rc, _iw_out[-300:]))

    # ── The regression the FIRST version of this fix introduced ────────────────────────────────
    # That version made die() do `trap - ERR EXIT`, so the handler was skipped for every die in
    # the file, and the two dies written out in the window's own text were hand-repaired with
    # their own `svc start`. Three more are reachable through a FUNCTION CALL inside the window —
    # fetch_code's missing git, and the `visudo -cf` check in write_sudoers_grant and
    # write_terminal_sudo_grant — and each of those ended the run with the panel STOPPED: exactly
    # the outcome the trap was added for, and a bug the next die added in there would inherit.
    # So the gate is about dies in general, not about those three call sites.
    _iw_rc, _iw_out = _iw_run(
        'fetch_code() { die "git is required to fetch the panel.  apt install -y git"; }\n'
        + _iw_fetch, _iw_pd, _iw_bk)
    check("install.sh: a die raised inside a FUNCTION in the window still starts the panel back up",
          "SVC start linuxgsm-panel.service" in _iw_out, _iw_out[-400:])
    check("install.sh: ...and says the panel is back on the old version, and where the snapshot is",
          "1.2.3" in _iw_out and _iw_bk in _iw_out, _iw_out[-400:])
    check("install.sh: ...without burying the die's own accurate message under the generic one",
          "git is required to fetch the panel" in _iw_out
          and "aborted unexpectedly" not in _iw_out and _iw_rc != 0,
          "rc=%d %s" % (_iw_rc, _iw_out[-400:]))

    # …and at the END of the window, where the root-owned pieces are refreshed. This runs
    # install.sh's REAL call site (check_origin_trusted → install_root_tools → write_sudoers_grant
    # → write_terminal_sudo_grant); only the four functions are stubbed, and write_sudoers_grant
    # does what the real one does when visudo rejects the file it has just written: remove the
    # grant and die. Nothing else in the suite executes this stretch at all.
    check("install.sh: the root-owned refresh really does run inside the stopped window",
          bool(_iw_grants) and "write_sudoers_grant" in _iw_grants,
          "extracted %d chars" % len(_iw_grants))
    _iw_rc, _iw_out = _iw_run("\n".join([
        "check_origin_trusted() { ORIGIN_TRUSTED=1; }",
        "install_root_tools() { echo 'ROOT_TOOLS'; }",
        'write_sudoers_grant() { rm -f "${PANEL_DIR}/sudoers"; die "sudoers entry invalid"; }',
        "write_terminal_sudo_grant() { :; }",
        _iw_grants,
        _iw_disarm]), _iw_pd, _iw_bk)
    check("install.sh: a sudoers grant that fails its visudo check does not leave the panel down",
          "SVC start linuxgsm-panel.service" in _iw_out and "sudoers entry invalid" in _iw_out
          and "WINDOW-COMPLETED" not in _iw_out and _iw_rc != 0,
          "rc=%d %s" % (_iw_rc, _iw_out[-400:]))

    # A KILL is not an exit status. Bash runs the EXIT trap when the installer is terminated, with
    # `$?` still 0, and the handler reported that as "(exit 0)" — a false statement in the one
    # message the operator gets about a half-finished update.
    _iw_rc, _iw_out = _iw_run("kill -TERM $$\necho 'SIGNAL-IGNORED'", _iw_pd, _iw_bk)
    check("install.sh: an update killed mid-window names the signal instead of claiming exit 0",
          "SIGTERM" in _iw_out and "(exit 0)" not in _iw_out and "SIGNAL-IGNORED" not in _iw_out,
          "rc=%d %s" % (_iw_rc, _iw_out[-400:]))
    check("install.sh: ...and still restarts the panel the kill left stopped",
          "SVC start linuxgsm-panel.service" in _iw_out and _iw_rc != 0,
          "rc=%d %s" % (_iw_rc, _iw_out[-400:]))

    # ── (1, continued) The ordering, MEASURED by running [1/6] and [2/6] ───────────────────────
    def _iw_stage_fixture(tag):
        """A panel dir shaped the way [1/6]+[2/6] reads it. → (panel_dir, backup, event log)"""
        _pd = os.path.join(_iw_dir, tag)
        os.makedirs(os.path.join(_pd, "data"))
        os.makedirs(os.path.join(_pd, "venv", "bin"))
        with open(os.path.join(_pd, "data", "panel.db"), "w") as _f:
            _f.write("x" * 64)
        with open(os.path.join(_pd, "db_maintenance.py"), "w") as _f:
            _f.write("# stand-in for the installed maintenance tool\n")
        _log = os.path.join(_iw_dir, tag + ".events")
        _py = os.path.join(_pd, "venv", "bin", "python3")
        with open(_py, "w") as _f:
            _f.write('#!/bin/sh\necho DBM-UPDATE >> %s\necho "DBM $*"\n' % _iw_shlex.quote(_log))
        os.chmod(_py, 0o755)
        return _pd, os.path.join(_iw_dir, tag + "-backup"), _log

    _o_pd, _o_bk, _o_log = _iw_stage_fixture("stage12")
    _o_rc, _o_out, _o_ev = _iw_run_stage12(_o_pd, _o_bk, _o_log)
    _o_code, _o_stop = _iw_evat(_o_ev, "TAR-CODE"), _iw_evat(_o_ev, "SVC stop")
    _o_data, _o_dbm = _iw_evat(_o_ev, "TAR-DATA"), _iw_evat(_o_ev, "DBM-UPDATE")
    check("install.sh: the panel is stopped BEFORE the database is tarred, not ten lines after",
          0 <= _o_stop < _o_data, "stop@%d data@%d %r" % (_o_stop, _o_data, _o_ev))
    check("install.sh: ...and [2/6]'s offline database maintenance still runs with it stopped",
          0 <= _o_stop < _o_dbm, "stop@%d dbm@%d %r" % (_o_stop, _o_dbm, _o_ev))
    # The other side of it: moving the stop EARLIER is not automatically safer. [1/6]'s own die
    # tells the operator "the panel is unchanged", which is only true while it is still running.
    check("install.sh: ...and the CODE snapshot is taken first, with the panel still running",
          0 <= _o_code < _o_stop, "code@%d stop@%d %r" % (_o_code, _o_stop, _o_ev))
    check("install.sh: a clean [1/6]+[2/6] saves both snapshots and checks the database",
          _o_rc == 0 and "OK Snapshot saved" in _o_out and "OK Database checked" in _o_out
          and "WINDOW-COMPLETED" in _o_out, "rc=%d %s" % (_o_rc, _o_out[-400:]))
    check("install.sh: ...stopping the service exactly once while it does",
          len([_e for _e in _o_ev if _e.startswith("SVC stop")]) == 1, repr(_o_ev))

    # ── snapshot_ok: the only thing between a failed tar and a rollback that restores nothing ──
    # The rollback wipes data/ BEFORE unpacking this archive, so "it unpacks" is not enough — it
    # has to contain something. `printf '' | gzip -1` is a 20-byte file: non-empty, and GNU tar
    # lists it happily as zero members.
    _s_dir = os.path.join(_iw_dir, "archives")
    os.makedirs(os.path.join(_s_dir, "src"))
    # Several INCOMPRESSIBLE members on purpose: the truncated copy below has to be one that tar
    # lists some of before it fails, which is what tells "count the members" apart from "count the
    # members AND require tar to have finished". One small file would compress to a single deflate
    # block that lists nothing at all, and the truncation gate would pass on a count-only check.
    for _n in range(40):
        with open(os.path.join(_s_dir, "src", "chunk%02d.bin" % _n), "wb") as _fh:
            _fh.write(os.urandom(2000))
    _s_real = os.path.join(_s_dir, "real.tgz")
    _iw_sub.run(["tar", "-C", os.path.join(_s_dir, "src"), "-czf", _s_real, "."], check=True)
    _s_empty = os.path.join(_s_dir, "empty.tgz")
    with open(_s_empty, "wb") as _fh:
        _fh.write(_iw_sub.run(["gzip", "-1"], input=b"", stdout=_iw_sub.PIPE, check=True).stdout)
    _s_zero = os.path.join(_s_dir, "zero.tgz")
    open(_s_zero, "wb").close()
    _s_trunc = os.path.join(_s_dir, "truncated.tgz")
    with open(_s_real, "rb") as _fh:
        _s_head = _fh.read()
    with open(_s_trunc, "wb") as _fh:
        _fh.write(_s_head[:int(len(_s_head) * 0.7)])
    _s_listed = _iw_sub.run(["bash", "-c", 'tar -tzf "$1" 2>/dev/null | wc -l', "_", _s_trunc],
                            capture_output=True, text=True).stdout.strip()
    check("install.sh: (premise) the truncated snapshot lists members before tar gives up",
          _s_listed.isdigit() and int(_s_listed) > 0, "tar listed %r members" % _s_listed)
    check("install.sh: snapshot_ok accepts an archive that actually holds the files",
          _iw_snapshot_ok(_s_real) == 0, _s_real)
    check("install.sh: ...and REJECTS a readable, valid, completely EMPTY archive",
          _iw_snapshot_ok(_s_empty) != 0,
          "%d bytes, tar -tzf lists nothing" % os.path.getsize(_s_empty))
    check("install.sh: ...and still rejects a zero-byte file and a truncated archive",
          _iw_snapshot_ok(_s_zero) != 0 and _iw_snapshot_ok(_s_trunc) != 0,
          "zero=%d truncated=%d" % (_iw_snapshot_ok(_s_zero), _iw_snapshot_ok(_s_trunc)))

    # …and what that means at the call site: a data tar that produced NOTHING must abort the
    # update — with the panel put back up — not print "Snapshot saved" over it.
    _e_pd, _e_bk, _e_log = _iw_stage_fixture("stage12-empty")
    _e_rc, _e_out, _e_ev = _iw_run_stage12(_e_pd, _e_bk, _e_log, data_tar_empty=True)
    check("install.sh: a data snapshot that came out EMPTY aborts instead of reporting it saved",
          "Snapshot saved" not in _e_out and "Couldn't snapshot the database/config" in _e_out
          and _e_rc != 0, "rc=%d %s" % (_e_rc, _e_out[-400:]))
    check("install.sh: ...and puts the panel it had just stopped back up",
          "SVC start linuxgsm-panel.service" in _e_out and _iw_evat(_e_ev, "SVC start") >= 0,
          "%r %s" % (_e_ev, _e_out[-300:]))
finally:
    _iw_shutil.rmtree(_iw_dir, ignore_errors=True)
