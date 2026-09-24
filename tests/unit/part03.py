"""Part 3 of the unit suite. Imported for its side effects."""
from unit.part01 import (NS, SO, _root, _sm_core, _sm_cron, _sm_files, _sm_firewall, _sm_hosts, _sm_portscan, check, config, eq, os, sys)  # noqa: F401,E402
from unit.part02 import (_User, _codes, _u)  # noqa: F401,E402
check("backup: a different code still works", _u.use_backup_code(_codes[1]))
check("backup: no codes set is handled", not _User().use_backup_code("whatever"))

# ── one-click connect URI (steam://connect for Source/GoldSrc) ─
from panel.db.models import GameServer as _GS
_steam = _GS(game_type="gmod", port=27015)
eq("connect: steam game -> steam://connect", _steam.connect_uri("1.2.3.4"),
   "steam://connect/1.2.3.4:27015")
_cs16 = _GS(game_type="cs", port=27015)
eq("connect: goldsrc game -> steam://connect", _cs16.connect_uri("host.example"),
   "steam://connect/host.example:27015")
_cod = _GS(game_type="cod", port=28960)
eq("connect: non-steam game (cod) -> no URI", _cod.connect_uri("1.2.3.4"), "")
_mc = _GS(game_type="mc", port=25565)
eq("connect: minecraft -> no URI", _mc.connect_uri("1.2.3.4"), "")
eq("connect: no host -> no URI", _steam.connect_uri(""), "")

# ── install port auto-assignment: span-aware, sequential packing ──
#    Regression guard for the "increments by 2" bug — a single-port game (Call of Duty, Source,
#    Minecraft) must pack sequentially, while a multi-port game reserves its whole adjacent block.
from app import _port_span, _first_free_block
eq("port-span: cod is single-port", _port_span("cod"), 1)
eq("port-span: source game is single-port", _port_span("gmod"), 1)
eq("port-span: unknown game defaults to 1", _port_span("totally-made-up"), 1)
eq("port-span: rust reserves 2", _port_span("rust"), 2)
eq("port-span: valheim reserves 3", _port_span("valheim"), 3)
eq("port-span: case-insensitive", _port_span("RUST"), 2)


def _pack(seq_spans, desired_of):
    """Simulate installing servers in order; each reserves its span. Returns assigned ports."""
    occupied, assigned = set(), []
    for gt in seq_spans:
        span = _port_span(gt)
        p = _first_free_block(desired_of[gt], span, occupied)
        for k in range(span):
            occupied.add(p + k)
        assigned.append(p)
    return assigned

eq("port-pack: 3 cod servers are sequential (no +2 gap)",
   _pack(["cod", "cod", "cod"], {"cod": 28960}), [28960, 28961, 28962])
eq("port-pack: cod then coduo pack tightly",
   _pack(["cod", "coduo"], {"cod": 28960, "coduo": 28960}), [28960, 28961])
eq("port-pack: 2 rust servers keep a 2-port block each",
   _pack(["rust", "rust"], {"rust": 28015}), [28015, 28017])
eq("port-pack: 2 valheim servers keep a 3-port block each",
   _pack(["valheim", "valheim"], {"valheim": 2456}), [2456, 2459])
eq("port-block: a live listening port is skipped",
   _first_free_block(28960, 1, {28960, 28961}), 28962)
# NO FREE BLOCK -> None, never a best guess. It used to return the last candidate it tried after
# exhausting its limit — a port that is occupied by definition — and report `changed=True`, so the
# caller stored a colliding port and the install failed later as the GAME's "Port N was unavailable".
check("port-block: exhausting the search returns None, not an occupied port",
      _first_free_block(30000, 1, set(range(30000, 30500))) is None)
check("port-block: the walk never runs past 65535",
      _first_free_block(65400, 1, set(range(65400, 66000))) is None)
check("port-block: a span that would cross the ceiling is refused",
      _first_free_block(65535, 2, set()) is None)
check("port-block: a free block at the very top is still found",
      _first_free_block(65535, 1, set()) == 65535)
from app import resolve_free_port as _rfp  # noqa: F401 - imported to assert the contract below
import inspect as _rfp_inspect
check("resolve_free_port: propagates the None rather than inventing a port",
      "if p is None" in _rfp_inspect.getsource(_rfp))

# ── a stopped valve sibling's CONFIGURED aux ports are occupied, and the allocator must know ────
# _PORT_SPAN has no entry for any valve game, so each Source server reserved exactly ONE port here.
# Its sourcetv/client ports were covered only by the LIVE listening scan — i.e. only while it was
# running — so five STOPPED Source servers on 27015-27019 left 27020 looking free and the sixth
# install was handed the first server's SourceTV port. That install succeeded; the cost landed
# later, on whoever started the older server and got "Port 27020 was unavailable" from srcds.
import app as _app_mod                                                             # noqa: E402
_o_rlp, _o_gsq = _app_mod._remote_listening_ports, _app_mod.GameServer
_o_lgv, _o_eng = _app_mod.lgsm_get_values, _app_mod.sm_game_engine
try:
    class _FakeQuery:
        def __init__(self, rows):
            self._rows = rows

        def filter_by(self, **kw):
            return self

        def all(self):
            return list(self._rows)

    _sibs = [NS(game_type="csgo", port=27015 + i, short_name="csgo%d" % i,
                lgsm_name="csgoserver") for i in range(5)]
    _app_mod._remote_listening_ports = lambda remote: set()      # every sibling is STOPPED
    _app_mod.GameServer = NS(query=_FakeQuery(_sibs))
    _app_mod.sm_game_engine = lambda gt: "valve"
    _app_mod.lgsm_get_values = lambda remote, user, selfname, keys: {
        "clientport": "27005", "sourcetvport": str(27020 + int(user[-1]))}
    _p, _ch = _app_mod.resolve_free_port(None, 1, 27015, "csgo")
    check("free-port: a STOPPED Source sibling's configured SourceTV port is not handed out",
          _p == 27025, "picked %s" % _p)
    # The control that names the cause: with the aux read failing, the blocks are all the
    # allocator has and it goes back to 27020 — so the check above is measuring the aux ports and
    # not merely the five game-port blocks.
    _app_mod.lgsm_get_values = lambda remote, user, selfname, keys: None
    _p_noaux, _ = _app_mod.resolve_free_port(None, 1, 27015, "csgo")
    check("free-port: ...and the blocks alone would have picked 27020, which is what this fixes",
          _p_noaux == 27020, "picked %s" % _p_noaux)
    # A non-valve host is not made to pay for it, and still allocates exactly as before.
    _app_mod.sm_game_engine = lambda gt: "goldsrc"
    _app_mod.lgsm_get_values = lambda *a, **k: (_ for _ in ()).throw(AssertionError("read anyway"))
    _p_nv, _ = _app_mod.resolve_free_port(None, 1, 27015, "csgo")
    check("free-port: a non-valve sibling is not read at all, and packs as before",
          _p_nv == 27020, "picked %s" % _p_nv)
    # Positive control: a genuinely free desired port still comes back unchanged.
    _p_free, _ch_free = _app_mod.resolve_free_port(None, 1, 30000, "csgo")
    check("free-port: a free desired port is still returned unchanged",
          _p_free == 30000 and _ch_free is False, "%s/%s" % (_p_free, _ch_free))
finally:
    _app_mod._remote_listening_ports, _app_mod.GameServer = _o_rlp, _o_gsq
    _app_mod.lgsm_get_values, _app_mod.sm_game_engine = _o_lgv, _o_eng

# ── _find_game_backup: list_game_backups says None for "could not read the host" ────────────────
# It returns [] for "this server has no backups", and None for a host it never reached — a
# distinction PR #330 put there deliberately. Iterating the None raised TypeError, which on the
# download route (a plain navigation, so the JSON handler re-raises) was Werkzeug's HTML 500 page.
# Collapsing it into the callers' falsy check would be worse: both answer "Backup not found." and
# a 404, telling the operator their archive is gone when the panel simply could not ask.
from werkzeug.exceptions import HTTPException as _FGB_HE                           # noqa: E402
_o_lgb = _app_mod.list_game_backups
try:
    _fgb_gs = NS(remote=None, short_name="gmodserver")
    _app_mod.list_game_backups = lambda r, u: None
    try:
        _app_mod._find_game_backup(_fgb_gs, "b-1")
        _fgb_exc = None
    except _FGB_HE as _e:
        _fgb_exc = _e
    check("game backup: an unreadable host is refused with its own status, not 'not found'",
          _fgb_exc is not None and _fgb_exc.code == 503,
          "raised %r" % (_fgb_exc,))
    check("game backup: ...and the refusal says the host could not be reached",
          _fgb_exc is not None and "reach" in (_fgb_exc.description or "").lower(),
          repr(getattr(_fgb_exc, "description", None))[:80])
    # Positive controls: a real listing still matches, and an ABSENT backup is still a plain None
    # (the 404 the routes want) rather than the new refusal.
    _app_mod.list_game_backups = lambda r, u: [{"name": "b-1", "size": 5}]
    check("game backup: a real listing still finds the archive",
          (_app_mod._find_game_backup(_fgb_gs, "b-1") or {}).get("size") == 5)
    _app_mod.list_game_backups = lambda r, u: []
    check("game backup: a server with NO backups still answers 'not found', not a 503",
          _app_mod._find_game_backup(_fgb_gs, "b-1") is None)
finally:
    _app_mod.list_game_backups = _o_lgb

# ── the install reconcile ticker must not "reconcile" a row that already says failed ────────────
# "failed" is IN the ticker's own filter set (deliberately — a repaired install has to be picked
# up), so unlike the True branch that row comes back every tick. Writing the two values it already
# holds re-fired a `servers_changed` broadcast to every open dashboard — each one re-requesting
# /api/servers and restarting its install-progress poller — and logged "reconciled stranded
# install 'X' -> failed" 144 times a day for a reconciliation that did not happen. Read as
# structure: the ticker is a closure inside create_app(), so nothing can call it from here.
import ast as _rt_ast                                                              # noqa: E402
_rt_src = open(os.path.join(_root, "app.py"), encoding="utf-8").read()
_rt_fn = next((n for n in _rt_ast.walk(_rt_ast.parse(_rt_src))
               if isinstance(n, _rt_ast.FunctionDef) and n.name == "install_reconcile_ticker"), None)
check("reconcile ticker: the function was located for the gate", _rt_fn is not None)
_rt_false = next((n for n in _rt_ast.walk(_rt_fn or _rt_ast.parse(""))
                  if isinstance(n, _rt_ast.If) and isinstance(n.test, _rt_ast.Compare)
                  and getattr(n.test.left, "id", "") == "verdict"
                  and isinstance(n.test.ops[0], _rt_ast.Is)
                  and getattr(n.test.comparators[0], "value", None) is False), None)
check("reconcile ticker: the `verdict is False` branch was located", _rt_false is not None)
check("reconcile ticker: it commits/broadcasts/logs only when the row actually changed",
      _rt_false is not None and len(_rt_false.body) == 1
      and isinstance(_rt_false.body[0], _rt_ast.If),
      "branch body is %s" % ([type(x).__name__ for x in (_rt_false.body if _rt_false else [])]))
# ...and the guard must be about the two fields it is going to write, or it guards nothing.
_rt_guard = _rt_ast.dump(_rt_false.body[0].test) if (
    _rt_false is not None and _rt_false.body and isinstance(_rt_false.body[0], _rt_ast.If)) else ""
check("reconcile ticker: ...comparing the values it is about to write",
      "'installed'" in _rt_guard and "'status'" in _rt_guard, _rt_guard[:120])

# _dedupe_aux_ports: a 2nd Source server must move its SourceTV/client ports off any already taken,
# so -strictportbind doesn't quit it. Free ports keep their value (and are omitted from the result).
from app import _dedupe_aux_ports
eq("aux-ports: both free -> no changes",
   _dedupe_aux_ports({"clientport": 27005, "sourcetvport": 27020}, {27015}), {})
eq("aux-ports: both taken -> each bumped to the next free port",
   _dedupe_aux_ports({"clientport": 27005, "sourcetvport": 27020}, {27005, 27015, 27020}),
   {"clientport": 27006, "sourcetvport": 27021})
eq("aux-ports: only the colliding key moves",
   _dedupe_aux_ports({"clientport": 27005, "sourcetvport": 27020}, {27020}),
   {"sourcetvport": 27021})
eq("aux-ports: scans past a run of taken ports",
   _dedupe_aux_ports({"sourcetvport": 27020}, {27020, 27021, 27022}), {"sourcetvport": 27023})
eq("aux-ports: two keys never land on the same freed port",
   _dedupe_aux_ports({"clientport": 27020, "sourcetvport": 27020}, {27020}),
   {"clientport": 27021, "sourcetvport": 27022})

# _extract_start_error: turn a game's start log into a one-line reason (or "" if none is clear), so a
# failed auto-start shows WHY instead of a bare "offline".
from app import _extract_start_error
eq("start-error: pulls the -strictportbind port line, ANSI stripped",
   _extract_start_error('boot\n\x1b[38;2;255;90;90mERROR: Port 27020 was unavailable - quitting due to "-strictportbind" flag!\x1b[39m\nmore'),
   'Port 27020 was unavailable - quitting due to "-strictportbind" flag!')
eq("start-error: a clean boot log yields no reason", _extract_start_error("Loading map\nServer started"), "")
eq("start-error: catches a couldn't-load line", _extract_start_error("Couldn't open mapcycle.txt"),
   "Couldn't open mapcycle.txt")
eq("port-block: multi-port block steps past a partial overlap",
   _first_free_block(28015, 2, {28016}), 28017)

# ── panel file integrity + repair (git-based) ─────────────────
from panel.ops import system_ops as _so
# Captured at the FIRST stub, not at the later one. A stub left installed is what subsequent
# blocks in this file capture as "the original" (`_orig_isgit = _so._is_git_checkout`) — so they
# put a STUB back believing it is the real function. That is the mechanism that silently disabled
# the rest of this file once before. Restored at the end of the integrity section.
_orig_git, _orig_isgit_real = _so._git, _so._is_git_checkout
_so._is_git_checkout = lambda: True
_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"]
    else ("M\tapp.py\nD\ttemplates/base.html\n", "", 0) if list(args) == ["diff", "--name-status", "HEAD"]
    else ("", "", 0))
_intg = _so.panel_integrity(force=True)   # force: each scenario mocks a different git state
check("integrity: reports git checkout", _intg["git"] is True)
eq("integrity: counts tampered files", _intg["count"], 2)
check("integrity: not clean when files differ", _intg["clean"] is False)

# ── Backup retention: the bound the UI enforces IS the bound the server clamps to ─────────────
# Retention is TYPED now rather than picked from a list, so the number box carries min/max. A
# dropdown could not offer an out-of-range value; a text box can, which means the browser's bound
# and the server's clamp are two statements of the same rule and can drift apart. keep_limits() is
# the one the UI is handed, so drive the setters with values outside it and check they land on it.
from panel.ops import backup as _bk_lim
_lim = _bk_lim.keep_limits()
eq("keep-limits: exposes both retention bounds", sorted(_lim), ["full_keep", "keep_days"])
eq("keep-limits: panel keep_days bound", (_lim["keep_days"]["min"], _lim["keep_days"]["max"]),
   (_bk_lim.MIN_KEEP_DAYS, _bk_lim.MAX_KEEP_DAYS))
eq("keep-limits: game full_keep bound", (_lim["full_keep"]["min"], _lim["full_keep"]["max"]),
   (_bk_lim.MIN_FULL_KEEP, _bk_lim.MAX_FULL_KEEP))
check("keep-limits: a game backup ceiling well under the panel's (each one is a whole game dir)",
      _lim["full_keep"]["max"] < _lim["keep_days"]["max"])

# The controls in the template must BE number boxes carrying those bounds — the whole point of the
# change is that the value is typed. A <select> here would silently take the feature back out.
_rm_html = open(os.path.join(_root, "templates", "remote_manage.html"), encoding="utf-8").read()
import re as _re_bk
for _id, _b in (("bk-keep", _lim["keep_days"]), ("fb-keep", _lim["full_keep"])):
    _tag = _re_bk.search(r'<(\w+)[^>]*\bid="%s"[^>]*>' % _id, _rm_html)
    check("backup UI: %s is an <input>, not a <select>" % _id,
          _tag is not None and _tag.group(1) == "input", _tag.group(1) if _tag else "not found")
    _attrs = _tag.group(0) if _tag else ""
    check("backup UI: %s is type=number" % _id, 'type="number"' in _attrs)
    check("backup UI: %s carries the server's min/max" % _id,
          'min="%d"' % _b["min"] in _attrs and 'max="%d"' % _b["max"] in _attrs, _attrs[:90])
check("backup UI: the per-server override is a number box with a Default placeholder",
      'placeholder="Default"' in open(os.path.join(_root, "static", "js",
                                                   "remote_manage_backups.js"),
                                      encoding="utf-8").read())


# ── update-noise filter: only real runtime changes should raise the "update available" badge ──
check("runtime-path: app.py counts", _so._is_runtime_path("app.py") is True)
check("runtime-path: a template counts", _so._is_runtime_path("templates/base.html") is True)
check("runtime-path: static asset counts", _so._is_runtime_path("static/js/app.js") is True)
check("runtime-path: requirements counts", _so._is_runtime_path("requirements.txt") is True)
check("runtime-path: install.sh counts", _so._is_runtime_path("install.sh") is True)
check("runtime-path: README is noise", _so._is_runtime_path("README.md") is False)
check("runtime-path: any .md is noise", _so._is_runtime_path("docs/SECURITY.md") is False)
check("runtime-path: .github workflow is noise", _so._is_runtime_path(".github/workflows/ci.yml") is False)
check("runtime-path: tests are noise", _so._is_runtime_path("tests/unit_test.py") is False)
# tools/ IS noise — except for the one file in it that runs as root on the host. The helper is the
# sudo boundary, it lives outside the checkout once installed, and ONLY install.sh (as root) can
# refresh it; the update badge is what tells the operator to do that. Classified as noise, a commit
# that changed only the helper raised no badge, so the panel moved on while the installed helper
# did not — and an unknown verb then fails silently with rc 2. See the helper's own docstring.
check("runtime-path: tools/panel-helper COUNTS (it is the root-owned sudo boundary)",
      _so._is_runtime_path("tools/panel-helper") is True)
check("runtime-path: the rest of tools/ is still noise",
      _so._is_runtime_path("tools/run-tests.sh") is False
      and _so._is_runtime_path("tools/perf_bench.py") is False)
check("runtime-path: the exception list names a file that exists",
      all((_os_p3 := __import__("os")).path.exists(f) for f in _so._RUNTIME_EXCEPTIONS))
check("runtime-path: LICENSE is noise", _so._is_runtime_path("LICENSE") is False)
check("runtime-path: dotfiles are noise", _so._is_runtime_path(".gitignore") is False)
_orig_utr_git = _so._git
try:
    _so._git = lambda args, timeout=45: ("README.md\ndocs/x.md\n.github/workflows/ci.yml\n", "", 0)
    check("update-touches-runtime: docs-only diff -> no update", _so._update_touches_runtime("origin/main") is False)
    _so._git = lambda args, timeout=45: ("README.md\napp.py\n", "", 0)
    check("update-touches-runtime: any code change -> update", _so._update_touches_runtime("origin/main") is True)
    _so._git = lambda args, timeout=45: ("", "err", 1)
    check("update-touches-runtime: unknown diff -> assume update (fail safe)",
          _so._update_touches_runtime("origin/main") is True)
finally:
    _so._git = _orig_utr_git

# ── panel fail2ban: input validation rejects bad port / path before touching the host ──
check("panel-f2b: out-of-range port rejected", _so.configure_panel_fail2ban("/x", 70000)[0] is False)
check("panel-f2b: zero port rejected", _so.configure_panel_fail2ban("/x", 0)[0] is False)
check("panel-f2b: non-numeric port rejected", _so.configure_panel_fail2ban("/x", "nope")[0] is False)
check("panel-f2b: newline in log path rejected", _so.configure_panel_fail2ban("bad\npath", 5000)[0] is False)

# ── panel_commit: always a string (short SHA, or '' when not a git checkout) ──
check("panel-commit: returns a string", isinstance(_so.panel_commit(), str))

# ── change panel port: port_in_use + restart_panel dispatch ──
_orig_sorun = _so._run
try:
    _so._run = lambda c, **k: ("0.0.0.0:5000\n127.0.0.1:22\n[::]:8080\n", "", 0)
    check("port_in_use: detects a listening port", _so.port_in_use(5000) is True)
    check("port_in_use: ignores a free port", _so.port_in_use(9999) is False)
    check("port_in_use: matches bracketed IPv6 address", _so.port_in_use(8080) is True)
finally:
    _so._run = _orig_sorun

# ONE function may answer to this name. ssh_manager/hosts.py used to define a second `port_in_use`,
# taking (server, port) instead of (port) and querying a REMOTE — with nothing calling it. Two
# functions, one name, different arity, and crucially different failure meaning: system_ops returns
# False on error deliberately ("don't block a change on a flaky check"), which is right for
# refusing to move the panel's own port, and exactly wrong for the install-time use somebody would
# eventually reach for the remote one for — a failed SSH read would report a busy port as FREE and
# hand an install a port that cannot bind. The install path never used it (resolve_free_port goes
# through _remote_listening_ports and reasons about a failed scan explicitly), so the dead twin was
# only ever a trap for the next person. Deleting it is the fix; this keeps it deleted.
import panel.ops.ssh_manager as _sm_pkg
check("port_in_use: only system_ops defines it — the ssh_manager twin stays deleted",
      not hasattr(_sm_pkg, "port_in_use"),
      "ssh_manager resolves it to %s" % getattr(getattr(_sm_pkg, "port_in_use", None), "__module__", "-"))
check("port_in_use: ...and the surviving one is the single-argument local check",
      _so.port_in_use.__code__.co_argcount == 1
      and _so.port_in_use.__module__ == "panel.ops.system_ops",
      "%s arity %d" % (_so.port_in_use.__module__, _so.port_in_use.__code__.co_argcount))

_orig_sorun2 = _so._run
try:
    _so._run = lambda c, **k: ("127.0.0.1\n100.84.48.111\n45.76.63.211\n", "", 0)
    check("host_has_ip: recognises a local address", _so.host_has_ip("100.84.48.111") is True)
    check("host_has_ip: rejects an address not on the host", _so.host_has_ip("10.0.0.9") is False)
finally:
    _so._run = _orig_sorun2

# ── The Tailscale SSH toggle changes RunSSH and nothing else ─────────────────────────────────
# It ran `tailscale up --ssh --accept-routes --accept-dns --reset`. `--reset` puts every pref not
# on that command line back to its default, so turning SSH on withdrew advertised subnet routes and
# an exit node, dropped a hand-set hostname (and the Serve URL built on it) and forced accept-routes
# on — reported as "Tailscale SSH enabled". `tailscale set --ssh[=false]` touches only RunSSH.
import shlex as _tss_shlex   # noqa: E402
_tss_cmds, _tss_rc = [], {"rc": 0}
_tss_orig = _so._run
try:
    _so._run = lambda c, **k: (_tss_cmds.append(c), ("", "boom", _tss_rc["rc"]))[1]
    _tss_on = _so.tailscale_ssh_enable()
    _tss_off = _so.tailscale_ssh_disable()
    _tss_argv = [[t for t in _tss_shlex.split(c) if t != "2>&1"] for c in _tss_cmds]
    check("tailscale-ssh: enabling runs `tailscale set --ssh` and nothing that resets other prefs",
          _tss_argv[:1] == [["tailscale", "set", "--ssh"]], repr(_tss_cmds))
    check("tailscale-ssh: disabling runs `tailscale set --ssh=false` and nothing else",
          _tss_argv[1:2] == [["tailscale", "set", "--ssh=false"]], repr(_tss_cmds))
    check("tailscale-ssh: ...and a toggle that ran reports it (control)",
          _tss_on == (True, "Tailscale SSH enabled") and _tss_off == (True, "Tailscale SSH disabled"),
          repr((_tss_on, _tss_off)))
    _tss_rc["rc"] = 1
    check("tailscale-ssh: ...while one the CLI refused is reported as a failure (control)",
          _so.tailscale_ssh_enable()[0] is False and _so.tailscale_ssh_disable()[0] is False)
finally:
    _so._run = _tss_orig

# ── perf guard: the /server-management host probe (sudo ufw + tailscale + apt, ~1.2s of
#    CPU across several subprocesses) is cached for _STATUS_TTL, so a page render and its
#    follow-up poll don't each re-run it. Mock the single subprocess entrypoint and count
#    how often it's actually hit across cold call / cached call / after invalidation. ──
_orig_ss_run = _so._run
_ss = {"n": 0}
try:
    _so._run = lambda c, **k: (_ss.__setitem__("n", _ss["n"] + 1), ("", "", 0))[1]
    _so._status_cache["data"] = None
    _so.get_server_status(force=True)          # cold: must probe the host
    check("perf: get_server_status probes the host on a cold call", _ss["n"] > 0)
    _ss["n"] = 0
    _so.get_server_status()                    # within TTL: served from cache, no subprocess
    check("perf: get_server_status is cached (no host re-probe on the next render)", _ss["n"] == 0)
    _so.invalidate_server_status()
    _so.get_server_status()                    # cache dropped: must probe again
    check("perf: invalidate_server_status forces a fresh probe", _ss["n"] > 0)
finally:
    _so._run = _orig_ss_run
    _so._status_cache["data"] = None

# BOTH branches pinned, and neither may escape. restart_panel picks its path with
# _is_system_service(): a per-user unit builds its own argv and goes through subprocess.Popen
# (what this block stubs), while a SYSTEM unit goes through _run_verb -> the helper. Dev machines
# and CI runners have no system unit, so they always took the Popen branch and these assertions
# only ever covered it. On the test VPS, where the panel really is a system service, the stub
# caught nothing — and on a host whose sudoers permits the verb, running this suite could have
# scheduled a REAL panel restart. _run_verb is stubbed as the backstop.
_orig_popen = (_so.subprocess.Popen, _so.subprocess.run)
_orig_rp_verb, _orig_rp_sys = _so._run_verb, _so._is_system_service
_cap = {}
try:
    _so._run_verb = lambda v, a=(), **k: (_cap.update(verb=v, verb_args=list(a)), ("", "", 0))[1]
    _so._is_system_service = lambda: False        # the per-user branch these checks describe
    # subprocess.RUN, not Popen: the per-user branch is a CHECKED call now. It used to be
    # Popen with both streams to DEVNULL and the status never collected, so it reported only that
    # the child was spawned — and `systemd-run --on-active` schedules a timer and exits at once
    # with a real status, so a refusal (no user D-Bus session, the unit name still held) answered
    # "Panel restart scheduled." to a user whose port change then silently never took effect.
    # Popen is stubbed too, so a regression back to it cannot reach the real systemd-run.
    _so.subprocess.Popen = lambda a, **k: (_cap.update(args=a), type("P", (), {})())[1]
    _so.subprocess.run = lambda a, **k: (_cap.update(args=a),
                                         type("R", (), {"returncode": _cap.get("rc", 0),
                                                        "stderr": ""})())[1]
    _ok, _ = _so.restart_panel()
    check("restart_panel: dispatches successfully", _ok is True)
    check("restart_panel: targets the panel service via systemd-run restart",
          "systemd-run" in _cap["args"] and "restart" in _cap["args"]
          and "linuxgsm-panel.service" in _cap["args"])
    check("restart_panel: delays so the HTTP response can flush",
          any(str(x).startswith("--on-active=") for x in _cap["args"]))
    # ...and a launcher that REFUSED is not a restart that was scheduled. The status was never
    # collected, so "Panel restart scheduled." was the answer to a systemd-run that had already
    # exited non-zero.
    _cap["rc"] = 1
    _rp_bad = _so.restart_panel()
    check("restart_panel: a launcher that exits non-zero is reported as a failure, not scheduled",
          _rp_bad[0] is False and "Could not restart" in _rp_bad[1], str(_rp_bad))
    _cap.pop("rc", None)
    check("restart_panel: ...and rc 0 still schedules it (positive control)",
          _so.restart_panel()[0] is True)
    # ...and the SYSTEM-unit branch, which is what a real install actually runs. It must go
    # through the verb — never `sudo systemd-run`, since a sudoers rule permitting systemd-run is
    # equivalent to NOPASSWD:ALL — and hand it nothing but the clamped delay.
    _cap.clear()
    _so._is_system_service = lambda: True
    _ok_sys, _ = _so.restart_panel(delay_seconds=2)
    check("restart_panel: a system unit goes through the panel-restart VERB, not sudo systemd-run",
          _ok_sys is True and _cap.get("verb") == "panel-restart", str(_cap)[:120])
    check("restart_panel: ...and the verb is handed only the clamped delay",
          _cap.get("verb_args") == ["2"], str(_cap.get("verb_args")))
    _cap.clear()
    _so.restart_panel(delay_seconds=99999)
    check("restart_panel: ...with the delay clamped to the documented 1..300",
          _cap.get("verb_args") == ["300"], str(_cap.get("verb_args")))
finally:
    _so.subprocess.Popen, _so.subprocess.run = _orig_popen
    _so._run_verb, _so._is_system_service = _orig_rp_verb, _orig_rp_sys
check("integrity: parses modified status",
      {"path": "app.py", "status": "modified"} in _intg["modified"])
check("integrity: parses deleted status",
      {"path": "templates/base.html", "status": "deleted"} in _intg["modified"])

# Repair must ONLY ever check out files git itself reported as changed — a caller
# can't smuggle in an arbitrary path (path-traversal / arbitrary checkout).
_co = {}
def _repair_git(args, timeout=45):
    a = list(args)
    if a[:1] == ["checkout"]:
        _co["args"] = a
        return ("", "", 0)
    if a == ["rev-parse", "--short", "HEAD"]:
        return ("abc1234\n", "", 0)
    if a == ["diff", "--name-status", "HEAD"]:
        return ("M\tapp.py\n", "", 0)
    return ("", "", 0)
_so._git = _repair_git
_ok, _msg, _restored = _so.panel_repair(["app.py", "/etc/passwd", "../../secret"])
check("repair: restores only git-reported files", _restored == ["app.py"])
check("repair: rejects paths not in tampered set",
      "/etc/passwd" not in _co.get("args", []) and "../../secret" not in _co.get("args", []))
check("repair: uses HEAD + '--' path guard", _co["args"][:3] == ["checkout", "HEAD", "--"])

# ...and an EMPTY selection is a request to restore NOTHING. `if paths:` sent [] down the
# restore-everything branch, so a caller saying "these files" with nothing ticked got every
# modified file checked out and an audit row recording it. Only paths=None may mean all — which
# is what the UI sends ({} → None), and what the check below the next one covers.
_so._git = _repair_git
_co.clear()
_ok_empty, _msg_empty, _restored_empty = _so.panel_repair([])
check("repair: an EMPTY path list restores nothing",
      _restored_empty == [] and "checkout" not in _co.get("args", []),
      "restored %r via %r — an empty selection checked out every modified file"
      % (_restored_empty, _co.get("args")))
check("repair: ...and says so rather than reporting a restore",
      _ok_empty is False and "No files were selected" in _msg_empty,
      "ok=%r msg=%r" % (_ok_empty, _msg_empty))
_co.clear()
_ok_all, _msg_all, _restored_all = _so.panel_repair(None)
check("repair: ...while None still restores them all (positive control)",
      _restored_all == ["app.py"],
      "restore-all stopped working, so the checks above would pass with the feature removed")

_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"] else ("", "", 0))
_ok2, _msg2, _ = _so.panel_repair()
check("repair: no-op when nothing is tampered", _ok2 is True and "Nothing to repair" in _msg2)

# Fail-safe: if git itself errors we must NOT claim the files are verified-clean.
_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"] else ("", "fatal", 1))
_intgf = _so.panel_integrity(force=True)
check("integrity: fail-safe when git errors (not verified)",
      _intgf.get("verified") is False and _intgf["clean"] is True)
_okf, _msgf, _ = _so.panel_repair()
check("repair: refuses when integrity can't be verified", _okf is False)

_so._is_git_checkout = lambda: False
check("integrity: handles non-git checkout", _so.panel_integrity(force=True)["git"] is False)
_ok3, _msg3, _ = _so.panel_repair()
check("repair: refuses when not a git checkout", _ok3 is False)
_so._git, _so._is_git_checkout = _orig_git, _orig_isgit_real

# ── automatic security updates detection ──────────────────────
def _mk_run(installed_rc, apt_out):
    def _r(cmd, timeout=30, sudo=False, text=True):
        if "dpkg-query" in cmd:
            return ("", "", installed_rc)
        if "apt-config" in cmd:
            return (apt_out, "", 0)
        return ("", "", 0)
    return _r
_so._run = _mk_run(0, 'APT::Periodic::Unattended-Upgrade "1";')
_au = _so.unattended_upgrades_status()
check("auto-updates: installed + enabled detected", _au["installed"] and _au["enabled"])
_so._run = _mk_run(0, 'APT::Periodic::Unattended-Upgrade "0";')
_au = _so.unattended_upgrades_status()
check("auto-updates: installed but disabled detected", _au["installed"] and not _au["enabled"])
_so._run = _mk_run(1, "")
_au = _so.unattended_upgrades_status()
check("auto-updates: not installed detected", not _au["installed"] and not _au["enabled"])

# ── shell-identifier validation (the core injection defense) ──
from panel.db.models import _validate_shell_ident as _vsi
for _bad in ("a;b", "a b", "a`b", "a$(x)", "a|b", "../x", "a&b", "a>b", "x'y", 'x"y', "a\nb", "a/b"):
    _rej = False
    try:
        _vsi("field", _bad)
    except ValueError:
        _rej = True
    check("shell-ident rejects %r" % _bad, _rej)
for _good in ("gmodserver", "cod", "my-server_1", "a.b", ""):
    _acc = True
    try:
        _vsi("field", _good)
    except ValueError:
        _acc = False
    check("shell-ident accepts %r" % _good, _acc)

# ── _quote() must yield ONE shell word that reads back as the original string ──────────────────
# This used to assert the SPELLING — `_quote("abc") == "'abc'"` — which pinned the old hand-rolled
# implementation rather than the property anything depends on. shlex.quote leaves a string that
# needs no quoting unquoted, which is equally correct and broke those assertions while changing
# nothing a shell parses. So ask a real shell instead: whatever the quoting looks like, printf has
# to hand back the original bytes, nothing else may run, and it must stay a single argument. That
# is strictly stronger — it fails for a BROKEN quoter, which the spelling test only caught by
# accident. Every payload here is a real shape: game filenames carry brackets, quotes, spaces and
# non-ASCII, and `a\nb` is legal in a Linux filename.
import subprocess as _qsp
_QUOTE_PAYLOADS = ["abc", "a'b", "; rm -rf / #", "$(id)", "`id`", "a b\tc", "--flag", "-rf",
                   '/home/u/de_dust2 [final] "v2".bsp', "x\\y", "ñ", "*", "~root", "a\nb", ""]
_qbad = []
for _p in _QUOTE_PAYLOADS:
    _r = _qsp.run(["/bin/bash", "-c", "printf %s " + _sm_core._quote(_p)],
                  capture_output=True, text=True, timeout=30)
    if _r.stdout != _p or _r.returncode != 0 or _r.stderr:
        _qbad.append("%r -> %r rc=%d err=%r" % (_p, _r.stdout, _r.returncode, _r.stderr[:40]))
check("_quote: a real shell reads every payload back as the original string, verbatim",
      not _qbad, "; ".join(_qbad[:2]))
_qwords = []
for _p in ("a b; id", "$(id) x", "'", ""):
    _r = _qsp.run(["/bin/bash", "-c", "set -- " + _sm_core._quote(_p) + "; echo $#"],
                  capture_output=True, text=True, timeout=30)
    if _r.stdout.strip() != "1":
        _qwords.append("%r -> %s args" % (_p, _r.stdout.strip()))
check("_quote: ...and it stays ONE word — the shell never sees a second argument",
      not _qwords, "; ".join(_qwords[:2]))

# ── cron builders generate correct + safe crontab lines ───────
# Capture what would be written instead of touching a real crontab.
_cron = {}
def _cap_rewrite(server, user, grep_args, add_lines, extra_pre=""):
    _cron.update(grep=grep_args, add=list(add_lines), pre=extra_pre)
    return True, "ok"
_orig_rewrite = _sm_core._rewrite_crontab
_sm_core._rewrite_crontab = _cap_rewrite

_sm_core.set_autostart(None, "gmodserver", True)
# Autostart is now the LinuxGSM monitor cron (every 5 min), NOT a @reboot start line — monitor
# respects the server's intended state via the lockfile. The managed line runs through the inline
# recorder so the command stays VISIBLE (grep-based detection/removal still works).
check("autostart(on): adds the */5 monitor line, recorder-wrapped",
      _cron["add"][0].startswith("*/5 * * * * ")
      and "/home/gmodserver/gmodserver monitor" in _cron["add"][0]
      and ".lgsm-cron/" in _cron["add"][0] and ".status" in _cron["add"][0])
check("autostart(on): also strips any legacy @reboot start line",
      "@reboot" in _cron["grep"] and "monitor" in _cron["grep"])
_sm_core.set_autostart(None, "gmodserver", False)
eq("autostart(off): removes line, adds none", _cron["add"], [])

_sm_core.install_game_cron(None, "gmodserver", supported={"monitor", "update-lgsm"})
check("install_game_cron: monitor every 5 min (recorder-wrapped, command visible)",
      any(ln.startswith("*/5 * * * * ") and "/home/gmodserver/gmodserver monitor" in ln
          and ".status" in ln for ln in _cron["add"]))
check("install_game_cron: weekly update-lgsm (recorder-wrapped)",
      any(ln.startswith("30 5 * * 0 ") and "/home/gmodserver/gmodserver update-lgsm" in ln
          and ".status" in ln for ln in _cron["add"]))
eq("install_game_cron: only supported commands scheduled", len(_cron["add"]), 2)

_sm_core.set_daily_restart(None, "gmodserver", game_type="gmod", port=27015, enabled=True)
check("daily_restart(mapped): sets pending flag at 05:00 (recorder-wrapped)",
      _cron["add"][0].startswith("0 5 * * * ")
      and "touch /home/gmodserver/.restart-pending" in _cron["add"][0]
      and ".status" in _cron["add"][0])
check("daily_restart(mapped): queries gamedig for player count",
      "gamedig --type garrysmod 127.0.0.1:27015" in _cron["add"][1])
# The hourly line must restart only on a COUNTED zero. gamedig writes its failure to stdout as
# {"error":...}, so `.players` is null and jq prints the length of null — 0. The old condition was
# `[ -z "$P" ] || [ "$P" = 0 ] || [ "$P" = null ]`, which restarted on all three, so every dropped
# query rebooted a server full of players from an unattended cron. The `else empty end` makes jq
# print nothing unless it really saw a player array.
_dr_line = _cron["add"][1]
check("daily_restart(mapped): jq prints nothing unless gamedig really answered",
      'if (.players|type=="array") then (.players|length) else empty end' in _dr_line, _dr_line[:200])
check("daily_restart(mapped): restarts on a counted 0, not on an empty/failed read",
      '[ "$P" = 0 ]' in _dr_line
      and '-z "$P"' not in _dr_line and '"$P" = null' not in _dr_line, _dr_line[:200])
_sm_core.set_daily_restart(None, "noqueryserver", game_type="noquerygame", port=28960, enabled=True)
# The no-query case stays unconditional, and that is a different thing from a failed read: the
# panel knows at cron-writing time that this game has no gamedig type, so there is no reading to
# fail and restarting at the daily time is what the operator asked for.
check("daily_restart(unmapped game): skips gamedig, no player query",
      "gamedig" not in _cron["add"][1] and "$P" not in _cron["add"][1])
check("daily_restart(unmapped game): still restarts unconditionally when the flag is set",
      "if true; then" in _cron["add"][1], _cron["add"][1][:200])
_sm_core.set_daily_restart(None, "gmodserver", enabled=False)
check("daily_restart(disable): adds nothing and clears the flag",
      _cron["add"] == [] and "rm -f" in _cron["pre"])

_sm_core._rewrite_crontab = _orig_rewrite   # restored: see the note at the git stubs above

# ── server_live_metrics parses SSH output into a numeric dict ──
_METRICS_OUT = "\n".join([
    "cpu 100 0 100 800 0 0 0", "GJA 1000",
    "cpu 110 0 110 880 0 0 0", "GJB 1100",
    "MEM 8000000000 4000000000", "LOAD 0.5 0.4 0.3",
    "DISK 100000000000 33000000000", "CORES 4", "UPTIME 123456",
    "GAMERAM 524288 3", "GUP 3600", "PORT 1",
])
_o_metrics_rc = _sm_core.run_command
_sm_core.run_command = lambda server, cmd, timeout=30, sudo=None: (_METRICS_OUT, "", 0)
_m = _sm_core.server_live_metrics(None, "gmodserver", 27015)
_sm_core.run_command = _o_metrics_rc
eq("metrics: ram_total parsed", _m["ram_total"], 8000000000)
eq("metrics: ram_percent computed", _m["ram_percent"], 50.0)
eq("metrics: disk_percent computed", _m["disk_percent"], 33.0)
eq("metrics: cores parsed", _m["cores"], 4)
eq("metrics: uptime parsed", _m["uptime_secs"], 123456)
eq("metrics: game_ram_mb parsed", _m["game_ram_mb"], 512)
eq("metrics: game_procs parsed", _m["game_procs"], 3)
check("metrics: port_open true when a socket is listening", _m["port_open"] is True)
eq("metrics: cpu_percent from the /proc/stat delta", _m["cpu_percent"], 20.0)
eq("metrics: game_cpu_percent from the jiffie delta", _m["game_cpu_percent"], 100.0)

# ── remote_live_metrics parses CPU/MEM/DISK sections (incl. new disk fields) ──
_RLM_OUT = "\n".join([
    "===A", "cpu 100 0 100 800 0 0 0", "cpu0 25 0 25 200 0 0 0",
    "===B", "cpu 110 0 110 880 0 0 0", "cpu0 28 0 28 220 0 0 0",
    "===MEM", "MemTotal: 8000000 kB", "MemAvailable: 4000000 kB",
    "SwapTotal: 0 kB", "SwapFree: 0 kB",
    "===DISK", "Filesystem 1B-blocks Used Available Use% Mounted on",
    "/dev/vda2 100000000000 40000000000 60000000000 40% /",
])
_o_rlm_rc = _sm_core.run_command
_sm_core.run_command = lambda server, cmd, timeout=12, **k: (_RLM_OUT, "", 0)
_rlm = _sm_core.remote_live_metrics(NS(is_local=False, auth_method="tailscale", host="x", name="x"))
_sm_core.run_command = _o_rlm_rc
eq("remote metrics: disk_total parsed", _rlm["disk_total"], 100000000000)
eq("remote metrics: disk_used parsed", _rlm["disk_used"], 40000000000)
eq("remote metrics: disk_percent computed", _rlm["disk_percent"], 40.0)
eq("remote metrics: swap 0 -> no divide-by-zero", _rlm["swap_percent"], 0)

# ── pro_status is cached (don't respawn the heavy Ubuntu Pro client every page load) ──
_pro_n = {"n": 0}
_orig_pro_run = _sm_core.run_command
try:
    def _procount(s, c, **k):
        _pro_n["n"] += 1
        return ('{"attached": true, "services": []}', "", 0)
    _sm_core.run_command = _procount
    _sm_hosts._pro_status_cache.clear()
    _psrv = NS(id=42, host="h")
    _sm_hosts.pro_status(_psrv)         # primes the cache; return value isn't checked
    _r2 = _sm_hosts.pro_status(_psrv)   # served from cache — no second run_command
    check("pro_status: cached (one run_command for two reads)", _pro_n["n"] == 1 and _r2["attached"] is True)
    _sm_hosts.pro_status(_psrv, force=True)
    check("pro_status: force=True bypasses cache", _pro_n["n"] == 2)
    _sm_hosts._pro_cache_invalidate(_psrv)
    _sm_hosts.pro_status(_psrv)
    check("pro_status: invalidate forces a refetch", _pro_n["n"] == 3)

    # ── "could not read" is a third answer, and it must not be cached ────────────────────────
    # The rc was discarded here under a comment saying anything non-JSON already reads as "not
    # installed", so a timed-out read — which on the tailscale and local transports returns
    # ("", "…timed out", -1) rather than raising — said "Ubuntu Pro is not installed" about a host
    # nobody had asked. _pro_status_cached then PERSISTS that to the database and serves it for a
    # day, across restarts.
    _orig_pro_priv = _sm_core.run_privileged
    try:
        _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "SSH command timed out", -1)
        _sm_hosts._pro_status_cache.clear()
        _pu = _sm_hosts.pro_status(NS(id=43, host="h"))
        check("pro_status: a timed-out read is flagged unreadable, not 'not installed'",
              _pu.get("unreadable") is True, repr(_pu))
        # ...and `pro` genuinely absent is still a READING, which keeps its old answer.
        _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "pro: command not found", 127)
        _sm_hosts._pro_status_cache.clear()
        _pn = _sm_hosts.pro_status(NS(id=44, host="h"))
        check("pro_status: a host without the pro client is 'not installed', not unreadable",
              _pn.get("installed") is False and not _pn.get("unreadable"), repr(_pn))

        # ...and the memo is the other half of that. Flagging the non-reading was no use while
        # pro_status stored it for _PRO_STATUS_TTL (a day) regardless: one timed-out read of a
        # rebooting host pinned "unknown" on its card until the panel restarted, because nothing
        # re-probes — only attach/detach/service invalidate the memo, and the page never forces.
        # The checks above cleared the cache between reads, so they never saw this.
        _pron = {"n": 0}

        def _pro_timedout(s, v, a=(), **k):
            _pron["n"] += 1
            return ("", "SSH command timed out", -1)
        _sm_core.run_privileged = _pro_timedout
        _sm_hosts._pro_status_cache.clear()
        _psrv_u = NS(id=48, host="h")
        _sm_hosts.pro_status(_psrv_u)
        _sm_hosts.pro_status(_psrv_u)
        check("pro_status: a timed-out read is re-probed, not answered from the memo for a day",
              _pron["n"] == 2, f"run_privileged calls={_pron['n']}")
        check("pro_status: a timed-out read leaves nothing in the 24h cache",
              _sm_hosts._pro_key(_psrv_u) not in _sm_hosts._pro_status_cache,
              repr(_sm_hosts._pro_status_cache.get(_sm_hosts._pro_key(_psrv_u))))

        def _pro_back_up(s, v, a=(), **k):
            _pron["n"] += 1
            return ('{"attached": true, "services": []}', "", 0)
        _sm_core.run_privileged = _pro_back_up
        _pb = _sm_hosts.pro_status(_psrv_u)
        check("pro_status: the host coming back is believed, not the failed read before it",
              _pb.get("attached") is True and not _pb.get("unreadable"), repr(_pb))
        # Positive control, on a host that only ever reads cleanly: a GOOD read is still
        # memoised. The pro client is slow, and not re-spawning it every page load is the whole
        # point of this cache — the guard above must skip the non-reading, not the caching.
        _psrv_ok = NS(id=49, host="h")
        _pron_before_ok = _pron["n"]
        _sm_hosts.pro_status(_psrv_ok)
        _pb2 = _sm_hosts.pro_status(_psrv_ok)
        check("pro_status: a good read is still cached for the day (positive control)",
              _pron["n"] == _pron_before_ok + 1 and _pb2.get("attached") is True
              and _sm_hosts._pro_key(_psrv_ok) in _sm_hosts._pro_status_cache,
              f"run_privileged calls={_pron['n'] - _pron_before_ok} (expected 1)")

        # ── the same defect through a second door: '{' that does not parse ──────────────────
        # The memo guard above only skips a dict carrying `unreadable`, and the json.loads
        # failure branch answered {"installed": True, "attached": False, "error": …} — no such
        # key. So a reply truncated by run_command's 2 MiB cap (or any garbled stream) was still
        # pinned for a day, persisted to the DB by _pro_status_cached, and painted as "Not
        # attached" plus the attach-token pitch — `error` is rendered nowhere — on a host that
        # may be fully attached. Unparseable bytes are a non-reading, not two facts about Pro.
        _prog = {"n": 0}

        def _pro_garbled(s, v, a=(), **k):
            _prog["n"] += 1
            return ('{"attached": true, "services": [{"name": "esm-in', "", 0)  # cut mid-object
        _sm_core.run_privileged = _pro_garbled
        _sm_hosts._pro_status_cache.clear()
        _psrv_g = NS(id=50, host="h")
        _pg = _sm_hosts.pro_status(_psrv_g)
        check("pro_status: unparseable JSON is flagged unreadable, not 'not attached'",
              _pg.get("unreadable") is True and _pg.get("installed") is not True, repr(_pg))
        check("pro_status: an unparseable read leaves nothing in the 24h cache",
              _sm_hosts._pro_key(_psrv_g) not in _sm_hosts._pro_status_cache,
              repr(_sm_hosts._pro_status_cache.get(_sm_hosts._pro_key(_psrv_g))))
        _sm_hosts.pro_status(_psrv_g)
        check("pro_status: an unparseable read is re-probed, not answered from the memo for a day",
              _prog["n"] == 2, f"run_privileged calls={_prog['n']}")

        # ── fail2ban overview: installed-but-unreadable is not "no jails" ────────────────────
        # rc 127 was handled; every OTHER failure fell through to {"installed": True,
        # "jails": []}, which the Security card renders as "No fail2ban jails found." — the same
        # thing a healthy host with nothing configured shows. A host whose read timed out, or
        # where fail2ban is installed but STOPPED, is exactly the one to tell the operator about.
        _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "SSH command timed out", -1)
        _ov = _sm_hosts.remote_fail2ban_overview(NS(id=45, host="h"))
        check("f2b overview: an unreadable host is flagged, not reported as having no jails",
              _ov.get("unreadable") is True and not _ov.get("jails"), repr(_ov))
        _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "fail2ban-client: not found", 127)
        _ov = _sm_hosts.remote_fail2ban_overview(NS(id=46, host="h"))
        check("f2b overview: a host without fail2ban is 'not installed', not unreadable",
              _ov.get("installed") is False and not _ov.get("unreadable"), repr(_ov))

        def _ov_ok(s, v, a=(), **k):
            if v == "f2b-status":
                return ("Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n", "", 0)
            return ("Status for the jail: sshd\n   |- Currently banned: 2\n"
                    "   `- Banned IP list:\t203.0.113.1 203.0.113.2\n", "", 0)
        _sm_core.run_privileged = _ov_ok
        _ov = _sm_hosts.remote_fail2ban_overview(NS(id=47, host="h"))
        check("f2b overview: a real read still parses its jails (positive control)",
              _ov.get("installed") is True and not _ov.get("unreadable")
              and [d["jail"] for d in _ov.get("jails") or []] == ["sshd"], repr(_ov)[:160])
    finally:
        _sm_core.run_privileged = _orig_pro_priv
        _sm_hosts._pro_status_cache.clear()
finally:
    _sm_core.run_command = _orig_pro_run
    _sm_hosts._pro_status_cache.clear()

# ── host_specs is cached (static hardware — don't re-run lscpu every page load) ──
_hs_n = {"n": 0}
_orig_hs_run = _sm_core.run_command
try:
    def _hscount(s, c, **k):
        _hs_n["n"] += 1
        return ("OS\tUbuntu\nCORES\t1\nMEM\t0.9\n", "", 0)
    _sm_core.run_command = _hscount
    _sm_firewall._specs_cache.clear()
    _hsrv = NS(id=7, host="h")
    _sm_firewall.host_specs(_hsrv)
    _sm_firewall.host_specs(_hsrv)   # cached
    check("host_specs: cached (one run_command for two reads)", _hs_n["n"] == 1)
finally:
    _sm_core.run_command = _orig_hs_run
    _sm_firewall._specs_cache.clear()

# ── set_game_priority renices the game user's processes as ROOT (negative nice needs root) ──
_gp_calls = []
_orig_gp = _sm_core.run_privileged
try:
    # Asserts the VERB and its arguments now, not a "sudo bash -c" substring. Same guarantee, and
    # it no longer passes just because the string happened to contain the right words.
    _sm_core.run_privileged = lambda s, v, a=(), **k: (_gp_calls.append((v, list(a))), ("", "", 0))[1]
    _sm_core.set_game_priority(None, "codserver")
    check("set_game_priority: renices the game user as root, via the verb",
          _gp_calls == [("renice-users", ["-1", "codserver"])], str(_gp_calls))
    _gp_calls.clear()
    _sm_core.set_game_priority_bulk(None, ["codserver", "gmodserver"])
    check("set_game_priority_bulk: renices every game user in ONE call (keeper for cron restarts)",
          _gp_calls == [("renice-users", ["-1", "codserver", "gmodserver"])], str(_gp_calls))
    _gp_calls.clear()
    _sm_core.set_game_priority_bulk(None, [])
    check("set_game_priority_bulk: no users -> no call", _gp_calls == [])
    # The helper refuses the WHOLE argument list when one account is outside the panel's game
    # group (renice-users is Rest(v_game_account)), so one such account on the panel host left
    # every game there un-reniced. A refused batch falls back to one call per account.
    _gp_local = _sm_core.is_local_server
    try:
        _sm_core.run_privileged = lambda s, v, a=(), **k: (
            _gp_calls.append((v, list(a))), ("", "", 2 if "ubuntu" in a else 0))[1]
        _sm_core.is_local_server = lambda s: True
        _gp_calls.clear()
        _sm_core.set_game_priority_bulk(None, ["codserver", "ubuntu", "gmodserver"])
        check("set_game_priority_bulk: one refused account does not cost the others their renice",
              _gp_calls[1:] == [("renice-users", ["-1", "codserver"]),
                                ("renice-users", ["-1", "ubuntu"]),
                                ("renice-users", ["-1", "gmodserver"])], str(_gp_calls))
        _sm_core.is_local_server = lambda s: False
        _gp_calls.clear()
        _sm_core.set_game_priority_bulk(None, ["codserver", "ubuntu", "gmodserver"])
        check("set_game_priority_bulk: ...a remote host (no such gate there) is not retried",
              len(_gp_calls) == 1, str(_gp_calls))
        # renice's OWN failure is 1, and it fails whenever one listed account has no process — any
        # stopped server — after renicing the rest. That is not a refusal and is not retried.
        _sm_core.is_local_server = lambda s: True
        _sm_core.run_privileged = lambda s, v, a=(), **k: (
            _gp_calls.append((v, list(a))), ("", "renice: failed to get priority", 1))[1]
        _gp_calls.clear()
        _sm_core.set_game_priority_bulk(None, ["codserver", "ubuntu", "gmodserver"])
        check("set_game_priority_bulk: ...renice's own 'no such process' (rc 1) is not retried",
              len(_gp_calls) == 1, str(_gp_calls))
    finally:
        _sm_core.is_local_server = _gp_local
finally:
    _sm_core.run_privileged = _orig_gp

# ── remote_uptime is ONE ssh round-trip (was eight) + parses the composite output + caches ──
_orig_ru = _sm_core.run_command
try:
    _ru_n = {"n": 0}
    _ru_out = "\n".join([
        "UPTIME up 3 days, 4 hours", "LOAD 0.15 0.10 0.05", "DISK 5.0G/20G",
        "MEM 1.2G/4.0G", "MEMPCT 30.0", "KERNEL 6.1.0", "CORES 2",
        "cpu 100 0 100 800 0 0 0",   # sample A: total 1000, idle 800
        "cpu 150 0 150 900 0 0 0",   # sample B: total 1200, idle 900 → idleΔ100/totalΔ200 = 50% busy
    ])

    def _ru_fake(server, cmd, **k):
        _ru_n["n"] += 1
        return (_ru_out, "", 0)
    _sm_core.run_command = _ru_fake
    _sm_hosts._uptime_cache.clear()
    _usrv = NS(id=7)
    _ru = _sm_hosts.remote_uptime(_usrv)
    check("uptime: a SINGLE ssh round-trip (was 8 separate commands)", _ru_n["n"] == 1)
    eq("uptime: parses the uptime string", _ru["uptime"], "3 days, 4 hours")
    eq("uptime: parses cores", _ru["cpu_cores"], "2")
    eq("uptime: parses memory", _ru["memory"], "1.2G/4.0G")
    eq("uptime: cpu% from /proc/stat delta", _ru["cpu_percent"], "50.0")
    eq("uptime: cpu per-core derived", _ru["cpu_per_core"], "25.0")
    _sm_hosts.remote_uptime(_usrv)   # within TTL → served from cache, no 2nd ssh
    check("uptime: second call served from cache", _ru_n["n"] == 1)
    _sm_hosts.remote_uptime(_usrv, force=True)   # force bypasses cache
    check("uptime: force=True re-reads", _ru_n["n"] == 2)
finally:
    _sm_core.run_command = _orig_ru
    _sm_hosts._uptime_cache.clear()

# ── apt upgradable parsing: name + old→new version ──
_APT_OUT = "\n".join([
    "Listing...",
    "libssl3/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.12]",
    "curl/jammy-updates 7.81.0-1ubuntu1.16 amd64 [upgradable from: 7.81.0-1ubuntu1.15]",
    "",
])
_pu = _sm_hosts._parse_upgradable(_APT_OUT)
eq("apt parse: count (Listing/blank skipped)", len(_pu), 2)
eq("apt parse: sorted by name (curl first)", _pu[0]["name"], "curl")
eq("apt parse: new version", _pu[1]["name"] == "libssl3" and _pu[1]["version"], "3.0.2-0ubuntu1.15")
eq("apt parse: old (from) version", _pu[1]["from"], "3.0.2-0ubuntu1.12")
_pu2 = _sm_hosts._parse_upgradable("")
eq("apt parse: empty -> no packages", len(_pu2), 0)
# The suite is the ONLY field distinguishing a security update from a routine one, and the OS-update
# alert titles itself off it. Without this, dropping the field is invisible: the smoke test feeds the
# alert ready-made dicts, so nothing else exercises the parse.
eq("apt parse: suite kept (this is what marks a security update)", _pu[1]["suite"], "jammy-security")
eq("apt parse: a non-security suite is kept as-is", _pu[0]["suite"], "jammy-updates")
check("apt parse: -security is detectable from the suite",
      "-security" in _pu[1]["suite"] and "-security" not in _pu[0]["suite"])
# apt writes "N: ..." notices to stdout, and the pipeline no longer greps them out (its exit status
# was masking apt's own — see remote_os_check_updates). They must not parse as packages.
_pu3 = _sm_hosts._parse_upgradable("\n".join([
    "Listing...",
    "N: There is 1 additional version. Please use the '-a' switch to see it",
    "bash/jammy-security 5.1-6ubuntu1.1 amd64 [upgradable from: 5.1-6ubuntu1]",
]))
eq("apt parse: apt notices are not packages", [p["name"] for p in _pu3], ["bash"])
# Both hosts parse the same apt output, so they go through one parser.
check("apt parse: local and remote share one implementation",
      SO.parse_upgradable(_APT_OUT) == _pu)

# Two more shapes main's checks above don't reach. A package in BOTH pockets is listed with a
# comma, which is the real shape of most security updates — "-security" has to still be found in it.
_pu_comma = _sm_hosts._parse_upgradable(
    "libc6/jammy-updates,jammy-security 2.35-0ubuntu3.8 amd64 [upgradable from: 2.35-0ubuntu3.6]")
eq("apt parse: comma-joined suites kept whole", _pu_comma[0]["suite"], "jammy-updates,jammy-security")
check("apt parse: a comma-joined suite still reads as security",
      "-security" in _pu_comma[0]["suite"])
# And the local path end to end, through the same parser, with apt's exit status carried out as
# `ok` — a failed check must not be readable as "nothing waiting". Stub _run so this stays offline.
_sv_run = SO._run
try:
    SO._run = lambda cmd, **kw: (_APT_OUT, "", 0)
    _loc = SO.os_update_available(refresh=False)
    eq("os_update_available: count matches the shared parser", _loc["count"], 2)
    eq("os_update_available: keeps the suite too",
       [p["suite"] for p in _loc["packages"]], ["jammy-updates", "jammy-security"])
    check("os_update_available: a good check reports ok", _loc["ok"] is True)
    SO._run = lambda cmd, **kw: ("", "E: Could not get lock", 100)
    _bad = SO.os_update_available(refresh=False)
    check("os_update_available: a FAILED check is not silently 'nothing waiting'",
          _bad["ok"] is False and _bad["count"] == 0)
finally:
    SO._run = _sv_run

# ── The snapshot the login banner and the OS Updates card read ────────────────────────
# Both used to show nothing until someone pressed "Check": the panel knew what each host had
# waiting (the daily sweep asks) but never kept the answer anywhere a page could read it. This is
# that store. What it must NOT do is record a failed check — apt emits nothing when it fails, which
# is byte-for-byte what a clean host emits, so storing it would clear a real banner and state that
# the host is up to date when in fact nobody managed to ask it.
from app import (_os_update_note as _oun, _is_security_pkg as _isec)
from panel.core.panel_state import (_os_update_seen as _seen)

check("security pkg: the -security suite is what marks one",
      _isec({"suite": "jammy-security"}) and not _isec({"suite": "jammy-updates"}))
check("security pkg: a comma-joined suite still reads as security",
      _isec({"suite": "jammy-updates,jammy-security"}))
check("security pkg: a package with no suite at all is not a security update",
      not _isec({"name": "vim"}) and not _isec({}) and not _isec(None))

_host = NS(id=4242, display_name="Panel Server")
_seen.pop(_host.id, None)
try:
    _oun(_host, {"ok": True, "packages": [{"name": "vim", "suite": "jammy-updates"},
                                          {"name": "openssl", "suite": "jammy-security"}]})
    eq("os-update snapshot: records what the host has waiting", _seen[_host.id]["count"], 2)
    eq("os-update snapshot: counts the security ones separately", _seen[_host.id]["security"], 1)
    eq("os-update snapshot: keeps the package list for the card",
       [p["name"] for p in _seen[_host.id]["packages"]], ["vim", "openssl"])
    eq("os-update snapshot: names the host for the banner", _seen[_host.id]["name"], "Panel Server")

    # The guarantee: a check that FAILED leaves the last real answer standing.
    _oun(_host, {"ok": False, "packages": []})
    eq("os-update snapshot: a FAILED check does not erase what we knew",
       _seen[_host.id]["count"], 2)
    _oun(_host, None)
    eq("os-update snapshot: no result at all does not erase it either",
       _seen[_host.id]["count"], 2)

    # ...but a check that SUCCEEDS and finds nothing does clear it, which is how installing the
    # updates from the panel takes the banner down instead of leaving it up until tomorrow.
    _oun(_host, {"ok": True, "packages": []})
    eq("os-update snapshot: a clean host clears the count", _seen[_host.id]["count"], 0)
    eq("os-update snapshot: and its security count", _seen[_host.id]["security"], 0)
finally:
    _seen.pop(_host.id, None)

# ── config save/load round-trips (guards the atomic-write path) ─
# Against a TEMP file, not the install's own config.json. This used to read the real config, write
# a probe key into it with save_config() and restore the original text in a finally — i.e. it
# mutated the live configuration of whatever machine it ran on, while the panel was running and
# able to read it. Two ways that bites: the restore never happens if the process is killed
# mid-block, and when CONFIG_FILE did not exist beforehand `_cfg_backup` is None, so the finally
# left a config.json behind containing `_roundtrip_probe` on a machine that had none.
#
# Nothing here needs the real file — the point is the atomic-write path, which is the same code
# wherever CONFIG_FILE points. Found while auditing the suites for live-host-state reads, after
# four other checks turned out to read the host's config; see part06's prefix tests.
import tempfile as _cfg_tmp
import pathlib as _cfg_pl
_cfg_dir = _cfg_tmp.mkdtemp(prefix="cfg-roundtrip-")
_cfg_orig = config.CONFIG_FILE
try:
    config.CONFIG_FILE = _cfg_pl.Path(_cfg_dir, "config.json")
    _c = config.load_config()
    _c["_roundtrip_probe"] = "value-123"
    config.save_config(_c)
    check("config: value survives a save/load round-trip",
          config.load_config().get("_roundtrip_probe") == "value-123")
    check("config: file exists after atomic save", config.CONFIG_FILE.exists())
    check("config: ...and the real install's config was never the thing written to",
          config.CONFIG_FILE != _cfg_orig and str(_cfg_dir) in str(config.CONFIG_FILE))
finally:
    config.CONFIG_FILE = _cfg_orig
    _cfg_shutil = __import__("shutil")
    _cfg_shutil.rmtree(_cfg_dir, ignore_errors=True)

# ── database corruption detection + self-heal (bad drive / power loss) ─
import sqlite3 as _sqlite
import tempfile as _tempfile
import shutil as _shutil
from panel.db.models import _db_quick_check, _ensure_db_healthy
_dbdir = _tempfile.mkdtemp()
_dbp = os.path.join(_dbdir, "t.db")
try:
    _c = _sqlite.connect(_dbp)
    _c.execute("CREATE TABLE x (a INTEGER)")
    _c.executemany("INSERT INTO x VALUES (?)", [(i,) for i in range(200)])
    _c.commit()
    _c.close()
    check("corrupt: a healthy DB passes quick_check", _db_quick_check(_dbp) is True)

    # A healthy startup makes/refreshes the rolling backup.
    _ensure_db_healthy(_dbp)
    check("corrupt: a rolling backup is created for a healthy DB", os.path.exists(_dbp + ".backup"))

    # Simulate a bad drive: clobber the middle of the file (leave the 100-byte
    # header so it still 'opens' as a DB but is malformed).
    with open(_dbp, "r+b") as _f:
        _f.seek(100)
        _f.write(b"\x00" * 4000)
    check("corrupt: a malformed DB fails quick_check", _db_quick_check(_dbp) is False)

    # Self-heal: restore from the backup, preserve the corrupt file aside, keep data.
    _ensure_db_healthy(_dbp)
    check("corrupt: DB is auto-restored to a healthy state", _db_quick_check(_dbp) is True)
    check("corrupt: the corrupt file is preserved aside (not destroyed)",
          any(fn.startswith("t.db.corrupt-") for fn in os.listdir(_dbdir)))
    _r = _sqlite.connect(_dbp).execute("SELECT COUNT(*) FROM x").fetchone()[0]
    eq("corrupt: restored data is intact", _r, 200)

    # No good backup + corrupt live DB -> move the corrupt file aside so the app can
    # start fresh instead of crash-looping (the bad file is preserved, not deleted).
    _dbp2 = os.path.join(_dbdir, "u.db")
    with open(_dbp2, "wb") as _f:
        _f.write(b"this is not a database at all, just garbage bytes" * 50)
    _ensure_db_healthy(_dbp2)   # no u.db.backup exists — must not raise
    check("corrupt: with no backup, the corrupt DB is moved aside (start-fresh)",
          not os.path.exists(_dbp2) and any(fn.startswith("u.db.corrupt-")
                                            for fn in os.listdir(_dbdir)))
finally:
    _shutil.rmtree(_dbdir, ignore_errors=True)

# ── config._create_key_once: atomic create-exactly-once (race-safe key files) ──
# Guards against two concurrent first-time saves each generating a different cred_key and
# clobbering the other (which would make the first-encrypted secret undecryptable).
_kd = _tempfile.mkdtemp()
try:
    _kp = os.path.join(_kd, "k")
    config._create_key_once(_kp, lambda: b"FIRST")
    with open(_kp, "rb") as _f:
        check("keyonce: creates the file with the generated bytes", _f.read() == b"FIRST")
    config._create_key_once(_kp, lambda: b"SECOND")   # must be a no-op (O_EXCL)
    with open(_kp, "rb") as _f:
        check("keyonce: never overwrites an existing key file", _f.read() == b"FIRST")
    # And a full encrypt→decrypt round-trip still works against a created cred key.
    _sec = config.encrypt_secret("hunter2-secret")
    check("keyonce: encrypt produces an enc:v1: blob", config.is_encrypted(_sec))
    check("keyonce: decrypt round-trips the plaintext", config.decrypt_secret(_sec) == "hunter2-secret")
finally:
    _shutil.rmtree(_kd, ignore_errors=True)

# ── Ubuntu Pro status persists (set-and-forget: no re-running the slow client every visit) ──
from panel.db.models import RemoteServer as _RS
_pr = _RS()
check("pro-cache: empty -> None", _pr.cached_pro is None)
_pr.update_pro_cache({"attached": True, "installed": True, "services": []})
_pc = _pr.cached_pro
check("pro-cache: round-trips the status dict", bool(_pc) and _pc["data"]["attached"] is True)
check("pro-cache: stamps a timestamp for staleness checks", isinstance(_pc.get("ts"), int) and _pc["ts"] > 0)
_pr.pro_cache = "{not valid json"
check("pro-cache: malformed stored value -> None (never raises)", _pr.cached_pro is None)

# ── dashboard port-scan cache: concurrent polls share ONE ssh scan per remote ──
_app = sys.modules["app"]   # already imported via `from app import ...` above
# The scan and its cache live in ssh_manager now, so the stub has to replace THAT module's
# run_command — patching app's would leave the real one in place and make every assertion below
# measure nothing.
_o_ps_rc = _sm_core.run_command
try:
    _scan_n = {"n": 0}

    _scan_kw = {}

    def _fake_ss(remote, cmd, **k):
        _scan_n["n"] += 1
        _scan_kw.clear()
        _scan_kw.update(k)
        return ("127.0.0.1:22\n*:27015\n[::]:27016", "", 0)

    _sm_core.run_command = _fake_ss
    _sm_portscan._port_scan_cache.clear()
    _rem = NS(id=99)
    _p1 = _app._remote_listening_ports(_rem)
    _app._remote_listening_ports(_rem)   # within TTL → cache hit, no 2nd ssh
    check("portscan: parses listening ports", 27015 in _p1 and 22 in _p1 and 27016 in _p1)
    check("portscan: second concurrent poll served from cache (one ssh)", _scan_n["n"] == 1)
    # sudo=False EXPLICITLY, not omitted. run_command's default is None, and for a REMOTE both
    # transports read None as "the row's sudo_enabled setting" — which the Add Remote checkbox
    # ships checked. So the "no sudo" comment above this call was true only on the panel's own
    # host, and every remote ran `sudo bash -c 'ss …'` as root every few seconds. Worse, on a host
    # whose sudoers permits only named commands that fails, the scan reads as unknown, and
    # resolve_free_port then hands out a port that is already listening.
    check("portscan: the scan asks for NO sudo explicitly (None means the host's default)",
          _scan_kw.get("sudo") is False, "kwargs were %r" % (_scan_kw,))
    _sm_portscan._invalidate_port_scan(99)
    _app._remote_listening_ports(_rem)   # invalidated → re-scans
    check("portscan: invalidate forces a fresh scan", _scan_n["n"] == 2)
    # A failed scan (empty output) must NOT be cached, so a blip doesn't pin servers offline.
    _sm_core.run_command = lambda remote, cmd, **k: ("", "err", -1)
    _sm_portscan._port_scan_cache.clear()
    _app._remote_listening_ports(_rem)
    check("portscan: an empty/failed scan is not cached", 99 not in _sm_portscan._port_scan_cache)
finally:
    _sm_core.run_command = _o_ps_rc
    _sm_portscan._port_scan_cache.clear()

# ── debug report: redaction + secret-key whitelist (must not leak) ─
_rd = _so._redact
check("redact: masks email addresses", "[email]" in _rd("reach me at admin@example.com now"))
check("redact: masks long token/key strings",
      "[redacted]" in _rd("key exampletokenexampletokenexampletoken12345"))
check("redact: masks key=value secrets", "[redacted]" in _rd("password=hunter2superSecret"))
check("redact: masks token: value", "[redacted]" in _rd("auth_token: abc.def.ghi"))
check("redact: leaves ordinary text intact", "server is offline" in _rd("server is offline"))
_secret_keys = {"secret_key", "cred_key", "secret", "credentials", "auth_credential",
                "host_key", "totp_secret", "backup_codes", "password"}
check("debug whitelist excludes every secret key",
      not (set(_so._DEBUG_CONFIG_KEYS) & _secret_keys))

# ── panel self-update CI gate: don't offer an update until its CI has passed ──
# _repo_slug must parse both HTTPS and SSH remote URLs (so the check works on forks).
_orig_rslug_git = _so._git
try:
    def _slug_git(args, timeout=45):
        return ("https://github.com/FMSMITH91/linuxgsm-panel.git\n", "", 0)
    _so._git = _slug_git
    eq("update: repo slug parsed from origin URL", _so._repo_slug(), "FMSMITH91/linuxgsm-panel")
finally:
    _so._git = _orig_rslug_git

# _remote_ci_state maps GitHub's Actions API response to passing/pending/failing, and
# never raises on a network/parse error (returns 'unknown', treated leniently).
import io as _io
import json
_orig_ci_slug = _so._repo_slug
_orig_urlopen = _so.urllib.request.urlopen
try:
    _so._repo_slug = lambda: "o/r"

    def _fake_open(payload):
        def _op(req, timeout=8):
            return _io.BytesIO(payload.encode() if isinstance(payload, str) else payload)
        return _op

    # The gate now requires EVERY check-run (except 'deploy') to be completed + successful.
    _all_ok = ('{"check_runs":[{"name":"checks","status":"completed","conclusion":"success"},'
               '{"name":"Analyze (python)","status":"completed","conclusion":"success"},'
               '{"name":"lighthouse","status":"completed","conclusion":"success"}]}')
    _so.urllib.request.urlopen = _fake_open(_all_ok)
    eq("ci-gate: all checks passed -> passing", _so._remote_ci_state("a"*40), "passing")
    # CI passed but Lighthouse still running -> pending (the exact case the user hit).
    _lh_running = ('{"check_runs":[{"name":"checks","status":"completed","conclusion":"success"},'
                   '{"name":"lighthouse","status":"in_progress","conclusion":null}]}')
    _so.urllib.request.urlopen = _fake_open(_lh_running)
    eq("ci-gate: one check still running -> pending", _so._remote_ci_state("a"*40), "pending")
    # One check failed (even if the rest passed) -> failing.
    _one_fail = ('{"check_runs":[{"name":"checks","status":"completed","conclusion":"success"},'
                 '{"name":"lighthouse","status":"completed","conclusion":"failure"}]}')
    _so.urllib.request.urlopen = _fake_open(_one_fail)
    eq("ci-gate: any check failed -> failing", _so._remote_ci_state("a"*40), "failing")
    # 'deploy' is ignored: a pending deploy alongside all-passing checks is still passing.
    _deploy_pending = ('{"check_runs":[{"name":"checks","status":"completed","conclusion":"success"},'
                       '{"name":"deploy","status":"in_progress","conclusion":null}]}')
    _so.urllib.request.urlopen = _fake_open(_deploy_pending)
    eq("ci-gate: pending 'deploy' is ignored -> passing", _so._remote_ci_state("a"*40), "passing")
    _so.urllib.request.urlopen = _fake_open('{"check_runs":[]}')
    eq("ci-gate: no checks yet -> pending", _so._remote_ci_state("a"*40), "pending")

    def _boom(req, timeout=8):
        raise _so.urllib.error.URLError("offline")
    _so.urllib.request.urlopen = _boom
    eq("ci-gate: network error -> unknown (never raises)", _so._remote_ci_state("a"*40), "unknown")

    # GitHub's anonymous rate limit (403/429) is an ANSWER, not an outage, and this gate's own
    # polling reaches it during a red streak. HTTPError is a URLError, so it read 'unknown' — which
    # the caller accepts as installable — and a tip CI had marked failing was offered and installed.
    def _http_err(code):
        def _op(req, timeout=8):
            raise _so.urllib.error.HTTPError(req.full_url, code, "limit", {}, None)
        return _op
    _so.urllib.request.urlopen = _http_err(403)
    eq("ci-gate: GitHub's 403 rate limit is 'pending', not the installable 'unknown'",
       _so._remote_ci_state("a" * 40), "pending")
    _so.urllib.request.urlopen = _http_err(429)
    eq("ci-gate: ...and so is a 429", _so._remote_ci_state("a" * 40), "pending")
    _so.urllib.request.urlopen = _http_err(502)
    eq("ci-gate: ...while a GitHub outage (5xx) stays 'unknown' (control)",
       _so._remote_ci_state("a" * 40), "unknown")

    def _truncated(req, timeout=8):
        raise _so.http.client.IncompleteRead(b'{"check_runs":[', 400)
    _so.urllib.request.urlopen = _truncated
    try:
        _ir_state = _so._remote_ci_state("a" * 40)
    except Exception as _ir_e:   # noqa: BLE001 - the regression IS the raise
        _ir_state = "raised %s" % type(_ir_e).__name__
    eq("ci-gate: a truncated response (IncompleteRead) is 'unknown', it does not escape",
       _ir_state, "unknown")

    # PAGINATION. The call asked for per_page=100 and read exactly one page. That was enough for
    # the workflows that exist today, but the failure mode if it ever stopped being enough is the
    # wrong one: a check that did not fit on page 1 is simply not seen, so a commit whose only
    # FAILURE sits on page 2 reads as 'passing' and the panel offers the update — which is the one
    # thing this gate exists to prevent. A full page must be followed.
    _pages_fetched = []

    def _paged(req, timeout=8):
        _pages_fetched.append(req.full_url)
        full = [{"name": "c%d" % i, "status": "completed", "conclusion": "success"}
                for i in range(100)]
        # endswith, NOT `"page=1" in url` — the query also carries per_page=100, whose "page=100"
        # contains "page=1". The first version of this mock matched every page because of it.
        if req.full_url.endswith("page=1"):
            return _io.BytesIO(json.dumps({"check_runs": full}).encode())
        return _io.BytesIO(json.dumps({"check_runs": [
            {"name": "the-one-that-failed", "status": "completed", "conclusion": "failure"}]}).encode())

    _so.urllib.request.urlopen = _paged
    _paged_state = _so._remote_ci_state("a" * 40)
    eq("ci-gate: a failure on page 2 is seen, not truncated away", _paged_state, "failing")
    check("ci-gate: a full first page is followed by a second request", len(_pages_fetched) >= 2,
          "fetched %d page(s)" % len(_pages_fetched))

    _pages_fetched.clear()

    def _short(req, timeout=8):
        _pages_fetched.append(req.full_url)
        return _io.BytesIO(json.dumps({"check_runs": [
            {"name": "checks", "status": "completed", "conclusion": "success"}]}).encode())

    _so.urllib.request.urlopen = _short
    eq("ci-gate: a short page still means 'passing'", _so._remote_ci_state("a" * 40), "passing")
    check("ci-gate: ...and a short page stops the paging (one request, not five)",
          len(_pages_fetched) == 1, "fetched %d page(s)" % len(_pages_fetched))
finally:
    _so._repo_slug = _orig_ci_slug
    _so.urllib.request.urlopen = _orig_urlopen

# panel_self_update ENFORCES the CI gate server-side (not just by hiding the button), and
# re-checks fresh so it also catches a bad commit that landed between page-load and click.
_orig_isgit = _so._is_git_checkout
_orig_pus = _so.panel_update_status
_orig_isfile = _so.os.path.isfile
try:
    _so._is_git_checkout = lambda: True
    _so.panel_update_status = lambda force=False: {"behind": 1, "ci_state": "failing"}
    _ok, _m = _so.panel_self_update()
    check("self-update: refuses a commit that FAILED CI", _ok is False and "didn't pass" in _m)
    _so.panel_update_status = lambda force=False: {"behind": 1, "ci_state": "pending"}
    _ok, _m = _so.panel_self_update()
    check("self-update: refuses while CI is still running", _ok is False and "being verified" in _m)
    # A CI-passing commit must get PAST the gate. Make install.sh look missing so it stops
    # there (proving the gate let it through) instead of actually launching an update.
    _so.os.path.isfile = lambda p: False
    _so.panel_update_status = lambda force=False: {"behind": 1, "ci_state": "passing",
                                                   "update_available": True, "target_sha": "b" * 40}
    _ok, _m = _so.panel_self_update()
    check("self-update: a CI-passing commit is NOT blocked by the gate",
          _ok is False and "install.sh is missing" in _m)
finally:
    _so._is_git_checkout = _orig_isgit
    _so.panel_update_status = _orig_pus
    _so.os.path.isfile = _orig_isfile

# ...and a gate that could not be EVALUATED does not open. A status computation that raised (a
# truncated GitHub reply, a git read that would not decode) set st = {}, which skipped the gate and
# left no target, so install.sh reset onto the origin tip — fetched after the check, verified by
# nobody. Any status without a verified target fell back to that same tip.
_sug_saved = (_so._is_git_checkout, _so.panel_update_status, _so._launch_installer, _so.os.path.isfile)
_sug_launched = []
try:
    _so._is_git_checkout = lambda: True
    _so.os.path.isfile = lambda p: True
    _so._launch_installer = lambda **k: (_sug_launched.append(k), (True, "Update started"))[1]

    def _sug_raise(force=False):
        raise _so.http.client.IncompleteRead(b"", 10)
    _so.panel_update_status = _sug_raise
    _sug_r = _so.panel_self_update()
    check("self-update: a status check that RAISED refuses the update instead of skipping the gate",
          _sug_r[0] is False and not _sug_launched, repr((_sug_r, _sug_launched)))
    _so.panel_update_status = lambda force=False: {"git": True, "behind": 2, "ci_state": "unknown",
                                                   "update_available": True, "target_sha": ""}
    _sug_r = _so.panel_self_update()
    check("self-update: an update with no verified target is refused, not sent to the origin tip",
          _sug_r[0] is False and not _sug_launched, repr((_sug_r, _sug_launched)))
    _so.panel_update_status = lambda force=False: {"git": True, "fetched": False,
                                                   "update_available": False,
                                                   "message": "Couldn't reach the update source."}
    _sug_r = _so.panel_self_update()
    check("self-update: ...nor is one whose remote could not even be fetched",
          _sug_r == (False, "Couldn't reach the update source.") and not _sug_launched,
          repr((_sug_r, _sug_launched)))
    _so.panel_update_status = lambda force=False: {"git": True, "behind": 2, "ci_state": "passing",
                                                   "update_available": True, "target_sha": "c" * 40}
    _sug_launched.clear()
    _sug_r = _so.panel_self_update()
    check("self-update: ...while a verified target is launched, pinned to that commit (control)",
          _sug_r[0] is True and len(_sug_launched) == 1
          and _sug_launched[0].get("target_ref") == "c" * 40, repr((_sug_r, _sug_launched)))
finally:
    (_so._is_git_checkout, _so.panel_update_status, _so._launch_installer,
     _so.os.path.isfile) = _sug_saved

# ── _compute_update_status targets the newest VERIFIED commit ──
# When the tip is still verifying but an earlier commit already passed CI, the panel must
# offer that earlier verified commit (not block entirely, and not jump to the pending tip).
_cus_git = _so._git
_cus_isco = _so._is_git_checkout
_cus_ver = _so.panel_version
_cus_ci = _so._remote_ci_state
try:
    _so._is_git_checkout = lambda: True
    _so.panel_version = lambda: "1.0.0"

    def _mk_git(behind, commits):
        # commits: full SHAs, newest (tip) first.
        def _g(args, timeout=45):
            if args[0] == "fetch":
                return ("", "", 0)
            if args[:3] == ["rev-parse", "--short", "HEAD"]:
                return ("headabc", "", 0)
            if args[:2] == ["rev-list", "--count"]:
                return (str(behind), "", 0)
            if args[:3] == ["rev-parse", "--short", "origin/main"]:
                return (commits[0][:7] if commits else "", "", 0)
            if args[0] == "rev-list" and "-n" in args:
                return ("\n".join(commits), "", 0)
            if args[0] == "show" and str(args[-1]).endswith(":VERSION"):
                return ("9.9.9", "", 0)
            if args[0] == "log":
                return ("c1 a change", "", 0)
            return ("", "", 0)
        return _g

    _C = ["a" * 40, "b" * 40, "c" * 40]   # tip=a, mid=b, old=c

    # tip pending, middle passed → offer the middle (skip the pending tip).
    _so._git = _mk_git(3, _C)
    _so._remote_ci_state = lambda sha: {"a" * 40: "pending", "b" * 40: "passing",
                                        "c" * 40: "passing"}.get(sha, "unknown")
    _r = _so._compute_update_status()
    check("update-target: offers the verified commit when the tip is pending",
          _r["update_available"] and _r["target_sha"] == "b" * 40)
    eq("update-target: newer unverified counted", _r.get("newer_unverified"), 1)
    eq("update-target: behind is measured to the target, not the tip", _r["behind"], 2)

    # tip passed → target is the tip, nothing pending above it.
    _so._remote_ci_state = lambda sha: "passing"
    _r = _so._compute_update_status()
    check("update-target: tip passed -> target is the tip",
          _r["update_available"] and _r["target_sha"] == "a" * 40 and _r["newer_unverified"] == 0)

    # The card links each changelog line to its commit, which needs the repo THIS checkout tracks
    # — a fork must link to the fork, not upstream. Same source the footer's linked SHA uses.
    check("update-target: the payload carries the repo URL, so the changelog can link commits",
          _re_bk.match(r"^https://github\.com/[^/]+/[^/]+$", _r.get("repo_url") or ""),
          repr(_r.get("repo_url")))

    # The card's OTHER half, which nothing asserted: behind 0 means up to date. A mutation that
    # made every check report an available update survived a green run, so the one state the
    # operator sees most of the time was never pinned.
    _so._git = _mk_git(0, _C)
    _so._remote_ci_state = lambda sha: "passing"
    _r_cur = _so._compute_update_status()
    check("update-target: nothing behind -> NO update, which is the up-to-date line",
          _r_cur["update_available"] is False and _r_cur["behind"] == 0,
          "available=%s behind=%s" % (_r_cur.get("update_available"), _r_cur.get("behind")))
    _so._git = _mk_git(3, _C)

    # DOCS-ONLY commits still count as an update. The card is asked "am I up to date?", and
    # answering "no newer commits run in the panel" left it showing a green tick while the install
    # was several commits behind — which is what the operator sees and can check. What the commits
    # happen to touch is not the question.
    _o_touch = _so._update_touches_runtime
    try:
        _so._update_touches_runtime = lambda _ref: False
        _so._remote_ci_state = lambda sha: "passing"
        _r_docs = _so._compute_update_status()
        check("update-target: docs-only commits are STILL an available update",
              _r_docs["update_available"] is True,
              "available=%s docs_only=%s" % (_r_docs.get("update_available"),
                                             _r_docs.get("docs_only")))
        check("update-target: ...and the card is told they are docs-only, for its own wording",
              _r_docs.get("docs_only") is True)
    finally:
        _so._update_touches_runtime = _o_touch

    # Everything still verifying → offer NOTHING, and say why.
    #
    # This used to offer it. The card then read "Update available: v0.10.0-alpha (1 commit behind)"
    # and, in the same card, "This update is still being verified — try again once they've passed",
    # because _do_panel_update refuses while ci_state is "pending" or "failing". The invariant these
    # two checks hold is that the card and the installer agree: update_available is true exactly
    # when the update would be allowed to install.
    _so._remote_ci_state = lambda sha: "pending"
    _r = _so._compute_update_status()
    check("update-target: all pending -> NOT offered, because the installer would refuse it",
          _r["update_available"] is False and _r["ci_state"] == "pending",
          "available=%s ci=%s" % (_r.get("update_available"), _r.get("ci_state")))
    # No message at all: the card has two states and nothing in between, so this one falls into
    # its plain up-to-date line rather than a third wording that appears for a few minutes after
    # every push and says nothing anyone can act on.
    check("update-target: ...and carries NO in-between message for the card to show",
          not _r.get("message"), repr(_r.get("message"))[:80])
    check("update-target: ...while ci_state is still reported for the API",
          _r.get("ci_state") == "pending", _r.get("ci_state"))
    check("update-target: ...and it still reports how far behind it really is",
          _r.get("behind_tip") == 3, _r.get("behind_tip"))
    check("update-target: ...and it still names the tip, for the card's changelog",
          bool(_r.get("target_sha")), "no target_sha")

    # A tip that FAILED CI is the same: the installer refuses it, so the card must not offer it.
    _so._remote_ci_state = lambda sha: "failing"
    _rf = _so._compute_update_status()
    check("update-target: a failed tip is not offered either",
          _rf["update_available"] is False and _rf["ci_state"] == "failing",
          "available=%s ci=%s" % (_rf.get("update_available"), _rf.get("ci_state")))
    check("update-target: ...with no in-between message either",
          not _rf.get("message"), repr(_rf.get("message"))[:80])

    # The guard that makes all of this safe: a verified commit BELOW a pending tip is still
    # offered, so a slow tip never freezes the panel on an old version.
    _so._remote_ci_state = lambda sha: {"a" * 40: "pending"}.get(sha, "passing")
    _rm = _so._compute_update_status()
    check("update-target: a verified commit under a pending tip is still offered",
          _rm["update_available"] is True and _rm["target_sha"] == "b" * 40,
          "available=%s target=%s" % (_rm.get("update_available"), _rm.get("target_sha")))

    # The caller, over the REAL _remote_ci_state: once GitHub rate-limits the panel, nothing in
    # range is verified, so nothing is offered. It used to read every commit as 'unknown' and
    # offer the tip — failing CI or not.
    _rl_saved = (_so._repo_slug, _so.urllib.request.urlopen)
    try:
        _so._remote_ci_state = _cus_ci
        _so._repo_slug = lambda: "o/r"

        def _rl_open(req, timeout=8):
            raise _so.urllib.error.HTTPError(req.full_url, 403, "rate limit exceeded", {}, None)
        _so.urllib.request.urlopen = _rl_open
        _r_rl = _so._compute_update_status()
        check("update-target: a rate-limited CI read offers NO update (was: the unverified tip)",
              _r_rl["update_available"] is False and _r_rl.get("ci_state") == "pending",
              "available=%s ci=%s" % (_r_rl.get("update_available"), _r_rl.get("ci_state")))
    finally:
        _so._repo_slug, _so.urllib.request.urlopen = _rl_saved
finally:
    _so._git = _cus_git
    _so._is_git_checkout = _cus_isco
    _so.panel_version = _cus_ver
    _so._remote_ci_state = _cus_ci

# ── Tailscale: installed-but-not-authenticated (NeedsLogin) must not 500 ─
from panel.ops import tailscale_integration as _tsi
_orig_run_ts, _orig_run_ts_json = _tsi._run_ts, _tsi._run_ts_json
_tsi._run_ts = lambda args, timeout=5: (("1.0", "", 0) if args and args[0] in ("version", "--version")
                                        else ("", "", 0))
# After `tailscale up` prints a login URL the user hasn't clicked, status --json has
# null Peer/Self/TailscaleIPs — the page used to crash iterating None.
_tsi._run_ts_json = lambda args, timeout=5: {"BackendState": "NeedsLogin",
                                             "Self": None, "Peer": None, "TailscaleIPs": None}
_tsinfo = _tsi._get_tailscale_info()
check("tailscale: NeedsLogin state parses without crashing", _tsinfo.installed and not _tsinfo.running)
check("tailscale: null Peer -> no peers (no None.items())", _tsinfo.peers == [])
check("tailscale: null TailscaleIPs -> empty list", _tsinfo.tailscale_ips == [])
check("tailscale: backend_state captured as NeedsLogin", _tsinfo.backend_state == "NeedsLogin")
# The bind suggestion must point the user at linking (not "no Tailscale detected") in NeedsLogin,
# so the page can offer a clear "Link this machine" action instead of looking un-installed.
_tsi._cache["info"] = None  # bypass the 15s cache so suggest_best_bind re-reads our mock
_tssug = _tsi.suggest_best_bind(5000)
check("tailscale: NeedsLogin suggestion tells user to link, not 'not detected'",
      "not linked" in _tssug["description"].lower())
_tsi._cache["info"] = None

# REGRESSION: Tailscale up WITH a MagicDNS name but Serve NOT configured must NOT bind to loopback
# (that hid the panel on 127.0.0.1 with nothing proxying to it — a fresh install was unreachable).
from panel.ops.tailscale_integration import TailscaleInfo   # noqa: E402
_orig_gti = _tsi.get_tailscale_info
try:
    _tsi.get_tailscale_info = lambda *a, **k: TailscaleInfo(
        installed=True, running=True, backend_state="Running", tailscale_ips=["100.90.141.12"],
        dns_name="host.example.ts.net", serve_config={"services": [], "raw": "No serve config"})
    _tsi._cache["info"] = None
    _bns = _tsi.suggest_best_bind(5000)
    check("tailscale: up + DNS name but Serve NOT set up -> does NOT bind loopback",
          _bns["bind_host"] != "127.0.0.1")
    _tsi.get_tailscale_info = lambda *a, **k: TailscaleInfo(
        installed=True, running=True, backend_state="Running", tailscale_ips=["100.90.141.12"],
        dns_name="host.example.ts.net",
        serve_config={"services": [{"url": "https://host.example.ts.net", "routes": [
            {"mount": "/lgsm", "target": "http://127.0.0.1:5000"}]}], "raw": "x"})
    _tsi._cache["info"] = None
    _bys = _tsi.suggest_best_bind(5000)
    check("tailscale: up + DNS name + Serve configured -> binds loopback for Serve",
          _bys["bind_host"] == "127.0.0.1" and _bys["method"] == "tailscale-serve")
    eq("tailscale: ...and the URL it recommends is the panel's own mapping, mount included",
       _bys["url"], "https://host.example.ts.net/lgsm")
    # ANY Serve route used to count, so a node already serving another app (Grafana on :3000) bound
    # a fresh panel — whose bind_host is empty until the wizard's first step, and app._resolved_bind
    # takes this answer — to 127.0.0.1 with nothing proxying to it: the first-run wizard, the only
    # way to create the first admin, was unreachable except through an SSH tunnel.
    _tsi.get_tailscale_info = lambda *a, **k: TailscaleInfo(
        installed=True, running=True, backend_state="Running", tailscale_ips=["100.90.141.12"],
        dns_name="host.example.ts.net",
        serve_config={"services": [{"url": "https://host.example.ts.net", "routes": [
            {"mount": "/", "target": "http://127.0.0.1:3000"}]}], "raw": "x"})
    _tsi._cache["info"] = None
    _bgf = _tsi.suggest_best_bind(5000)
    check("tailscale: a Serve route to ANOTHER app does not bind the panel to loopback",
          _bgf["bind_host"] != "127.0.0.1" and _bgf["method"] == "tailscale-direct", repr(_bgf))
    # The direct URLs were hardcoded http:// while the panel serves self-signed TLS by default, so
    # the page linked the operator to plain HTTP on a port that only speaks TLS.
    eq("tailscale: the direct URL uses the scheme the panel is actually serving",
       _tsi.suggest_best_bind(5000, scheme="https")["url"], "https://100.90.141.12:5000")
    eq("tailscale: ...and http only when the panel serves http (control)",
       _tsi.suggest_best_bind(5000, scheme="http")["url"], "http://100.90.141.12:5000")
finally:
    _tsi.get_tailscale_info = _orig_gti
    _tsi._cache["info"] = None

# ── A Serve status the panel could not READ is not "nothing is configured" ───────────────────
# serve_config is {} for both, and the page stated the first as a fact: /tailscale rendered the
# daemon Online and said "No Serve routes configured yet." while the panel was, at that moment,
# being served over the very mapping it was reporting as absent. The ordinary way in is that the
# panel's own account is not the tailscale operator, so `tailscale serve status` exits non-zero
# with "Access denied: serve config denied". rc 0 with no output is a READING — the CLI prints
# "No serve config" and exits 0 when nothing is published — so only a non-zero rc is unreadable.
_tsu_json = {"BackendState": "Running", "Self": None, "Peer": None,
             "TailscaleIPs": ["100.64.0.5"]}


def _tsu_stub(serve_rc, serve_out=""):
    def _run(args, timeout=5):
        if args and args[0] in ("version", "--version"):
            return ("1.0", "", 0)
        if args[:2] == ["serve", "status"]:
            return (serve_out, "Access denied: serve config denied" if serve_rc else "", serve_rc)
        return ("", "", 0)
    _tsi._run_ts = _run
    _tsi._run_ts_json = lambda args, timeout=5: dict(_tsu_json)
    _tsi._cache["info"] = None
    return _tsi._get_tailscale_info()


_tsu_denied = _tsu_stub(1)
check("tailscale: a `serve status` that was refused is flagged unreadable, not reported empty",
      _tsu_denied.serve_unreadable is True and _tsu_denied.serve_config == {},
      "serve_unreadable=%r serve_config=%r" % (_tsu_denied.serve_unreadable,
                                               _tsu_denied.serve_config))
_tsu_empty = _tsu_stub(0, "No serve config")
check("tailscale: ...while an rc 0 that found nothing really is nothing (positive control)",
      _tsu_empty.serve_unreadable is False,
      "an ordinary host with no Serve mapping now reads as unreadable")
_tsu_ok = _tsu_stub(0, "https://host.example.ts.net (tailnet only)\n|-- /lgsm proxy http://127.0.0.1:5000")
check("tailscale: ...and a readable config still parses its routes (positive control)",
      _tsu_ok.serve_unreadable is False
      and [r["mount"] for s in _tsu_ok.serve_config.get("services", []) for r in s["routes"]]
      == ["/lgsm"],
      "serve_config=%r" % (_tsu_ok.serve_config,))

# A FUNNELLED mapping reads as one. Tailscale prints "(Funnel on)" with a capital F after the URL,
# and the parser compared case-sensitively against "funnel": info.funnel_enabled was always False,
# so /tailscale told the operator a panel on the public internet was "private - tailnet only".
_tsu_fun = _tsu_stub(0, "# Funnel on:\n#     - https://host.example.ts.net\n\n"
                        "https://host.example.ts.net (Funnel on)\n|-- / proxy http://127.0.0.1:5000")
check("tailscale: a mapping Tailscale prints as '(Funnel on)' is reported as funnelled",
      _tsu_fun.funnel_enabled is True
      and [s["funnel"] for s in _tsu_fun.serve_config.get("services", [])] == [True],
      "funnel_enabled=%r serve_config=%r" % (_tsu_fun.funnel_enabled, _tsu_fun.serve_config))
_tsu_priv = _tsu_stub(0, "https://host.example.ts.net (tailnet only)\n"
                         "|-- /funnel-stats proxy http://127.0.0.1:3000")
check("tailscale: ...while '(tailnet only)' is private, even with 'funnel' in a route (control)",
      _tsu_priv.funnel_enabled is False
      and [s["funnel"] for s in _tsu_priv.serve_config.get("services", [])] == [False],
      "funnel_enabled=%r serve_config=%r" % (_tsu_priv.funnel_enabled, _tsu_priv.serve_config))
_tsi._cache["info"] = None

# ── Disabling Serve runs a command the CLI has, and removes only the PANEL's mapping ─────────
# It ran `tailscale serve --bg --remove <mount>`. No Tailscale version has --remove: the CLI exits 2
# ("flag provided but not defined: -remove") before doing anything, so every Disable failed —
# including taking a Funnelled panel back off the internet. The CLI's removal is
# `serve --https=<port> --set-path=<mount> off`; without --set-path, `off` drops EVERY mount on
# the port. And the mount has to be the panel's: Tailscale lists "/" first, so on a node where
# another app holds "/" and the panel sits at /lgsm, "the first route" was the other app.
eq("serve-off: the removal argv is the CLI's own grammar, path always given",
   _tsi.serve_off_args("https://node.example.ts.net", "/"),
   ["serve", "--https=443", "--set-path=/", "off"])
eq("serve-off: ...on the listener the mapping is actually on",
   _tsi.serve_off_args("https://node.example.ts.net:8443", "/lgsm"),
   ["serve", "--https=8443", "--set-path=/lgsm", "off"])
_tsd_info = TailscaleInfo(
    installed=True, running=True, backend_state="Running", dns_name="node.example.ts.net",
    serve_config={"services": [{"url": "https://node.example.ts.net", "funnel": True, "routes": [
        {"mount": "/", "target": "http://127.0.0.1:3000"},
        {"mount": "/lgsm", "target": "https+insecure://127.0.0.1:5000"}]}], "raw": "x"})
_tsd_saved = (_tsi.get_tailscale_info, _tsi._run_ts, _tsi.ensure_operator)
_tsd_ran, _tsd_rc = [], {"rc": 0}
try:
    _tsi.get_tailscale_info = lambda force_refresh=False: _tsd_info
    _tsi._run_ts = lambda args, timeout=5: (_tsd_ran.append(list(args)), ("", "err", _tsd_rc["rc"]))[1]
    _tsi.ensure_operator = lambda: (True, "panel")
    eq("serve-off: the panel's route is found by its backend, not by its place in the list",
       [r["mount"] for r in _tsi.panel_serve_routes(_tsd_info.serve_config, 5000)], ["/lgsm"])
    _tsd_r = _tsi.disable_tailscale_serve("/", 5000)
    check("serve-off: asked to remove another app's '/', it removes NOTHING",
          _tsd_r[0] is False and _tsd_ran == [], repr((_tsd_r, _tsd_ran)))
    _tsd_r = _tsi.disable_tailscale_serve("/lgsm", 5000)
    check("serve-off: the panel's own mapping is removed with `serve ... off`, never --remove",
          _tsd_r[0] is True and _tsd_ran == [["serve", "--https=443", "--set-path=/lgsm", "off"]],
          repr((_tsd_r, _tsd_ran)))
    _tsd_ran.clear()
    _tsd_rc["rc"] = 2
    _tsd_r = _tsi.disable_tailscale_serve("/lgsm", 5000)
    check("serve-off: ...and a CLI that refused is a failure, not 'removed' (control)",
          _tsd_r[0] is False and len(_tsd_ran) == 1, repr((_tsd_r, _tsd_ran)))
    _tsd_ran.clear()
    _tsd_info.serve_unreadable = True
    _tsd_r = _tsi.disable_tailscale_serve("/lgsm", 5000)
    check("serve-off: an unreadable Serve config removes nothing (it can't tell whose mapping)",
          _tsd_r[0] is False and _tsd_ran == [], repr((_tsd_r, _tsd_ran)))
    _tsd_info.serve_unreadable = False
    _tsd_info.serve_config = {"services": [{"url": "https://node.example.ts.net", "funnel": False,
                                            "routes": [{"mount": "/", "target": "http://127.0.0.1:3000"}]}]}
    _tsd_r = _tsi.disable_tailscale_serve("/", 5000)
    check("serve-off: with nothing proxying the panel, disabling is done and touches nothing",
          _tsd_r[0] is True and _tsd_ran == [], repr((_tsd_r, _tsd_ran)))
finally:
    _tsi.get_tailscale_info, _tsi._run_ts, _tsi.ensure_operator = _tsd_saved
    _tsi._cache["info"] = None
_tsi._run_ts, _tsi._run_ts_json = _orig_run_ts, _orig_run_ts_json   # restored, as above

# ── Debug report: repeated tracebacks in the log tail get collapsed ───
_pfx = "Jul 05 23:44:%02d vultr python[74699]: "
_one_tb = [
    _pfx % 14 + "Traceback (most recent call last):",
    _pfx % 14 + '  File "/x.py", line 1, in main',
    _pfx % 14 + "    do()",
    _pfx % 14 + "ssl.SSLError: sslv3 alert certificate unknown",
]
# same traceback logged 3× at different timestamps, interleaved with unique lines
_noisy = "\n".join(
    _one_tb + [_pfx % 15 + "Removing descriptor: 12"]
    + _one_tb + [_pfx % 16 + "Removing descriptor: 13"]
    + _one_tb + [_pfx % 17 + "Removing descriptor: 14"]
)
_dd = _so._dedupe_log_tracebacks(_noisy)
check("log dedupe: keeps exactly one full copy of a repeated traceback",
      _dd.count("Traceback (most recent call last):") == 1)
check("log dedupe: annotates the collapsed repeats", "repeated 2× more" in _dd)
check("log dedupe: preserves the surrounding unique lines",
      "Removing descriptor: 12" in _dd and "Removing descriptor: 14" in _dd)
# distinct tracebacks must NOT be collapsed into each other
_distinct = "\n".join([
    _pfx % 14 + "Traceback (most recent call last):",
    _pfx % 14 + "ValueError: bad",
    _pfx % 15 + "Traceback (most recent call last):",
    _pfx % 15 + "KeyError: nope",
])
_dd2 = _so._dedupe_log_tracebacks(_distinct)
check("log dedupe: distinct tracebacks are both kept",
      _dd2.count("Traceback (most recent call last):") == 2
      and "ValueError" in _dd2 and "KeyError" in _dd2)

# ── mods parsing (real LinuxGSM formats, verified on a live Garry's Mod box) ──
_mods_avail_out = (
    "\x1b[1mGarry's Mod Installing Mods\x1b[0m\n"
    "=================================\n"
    "Available addons/mods\n"
    "=================================\n"
    "Metamod: Source - Plugins Framework - https://www.sourcemm.net\n"
    " * \x1b[36mmetamodsource\x1b[0m\n"
    "SourceMod - Admin Features (requires Metamod: Source) - http://www.sourcemod.net\n"
    " * \x1b[36msourcemod\x1b[0m\n"
    "Wiremod Extras - Addition to Wiremod - https://github.com/wiremod/wire-extras/\n"
    " * \x1b[36mwiremod-extras\x1b[0m\n"
)
_av = _sm_files._parse_mods_available(_mods_avail_out)
check("mods: available parses id + name from ' * <id>' format",
      [m["id"] for m in _av] == ["metamodsource", "sourcemod", "wiremod-extras"]
      and _av[0]["name"] == "Metamod: Source")
# REGRESSION: LinuxGSM lists an 'Installed addons/mods' section (bare ' * <id>' lines, no
# description) BEFORE 'Available addons/mods'. Those bare ids must NOT be emitted as phantom mods
# named after the section header, nor duplicate the real Available rows (bug: ulib/ulx showed twice).
_mods_avail_full = (
    "Garry's Mod Installing Mods\n"
    "=================================\n"
    "Installed addons/mods\n"
    "=================================\n"
    " * ulib\n"
    " * ulx\n"
    "\n"
    "Available addons/mods\n"
    "=================================\n"
    "Metamod: Source - Plugins Framework - https://www.sourcemm.net\n"
    " * metamodsource\n"
    "ULib - Complete Framework - http://ulyssesmod.net\n"
    " * ulib\n"
    "ULX - Admin Panel (requires ULib) - http://ulyssesmod.net\n"
    " * ulx\n"
    "Enter an addon/mod to install (or exit to abort):\n"
)
_avf = _sm_files._parse_mods_available(_mods_avail_full)
_avf_ids = [m["id"] for m in _avf]
check("mods: the 'Installed addons/mods' section is not emitted as phantom entries",
      not any(m["name"].lower() == "installed addons/mods" for m in _avf))
check("mods: each available id appears exactly once (ulib/ulx not duplicated)",
      _avf_ids == ["metamodsource", "ulib", "ulx"])
check("mods: the deduped ulib/ulx keep their real names, not the section header",
      {m["id"]: m["name"] for m in _avf}.get("ulib") == "ULib"
      and {m["id"]: m["name"] for m in _avf}.get("ulx") == "ULX")
_mods_inst_out = (
    "Garry's Mod Removing Mods\n"
    "=================================\n"
    "Remove addons/mods\n"
    "=================================\n"
    "metamodsource - Metamod: Source - Plugins Framework\n"
    "Enter an addon/mod to remove (or exit to abort): "
)
_in = _sm_files._parse_mods_installed(_mods_inst_out)
check("mods: installed parses '<id> - <name>' format",
      len(_in) == 1 and _in[0]["id"] == "metamodsource" and _in[0]["name"] == "Metamod: Source")
check("mods: 'No installed mods' output yields empty list",
      _sm_files._parse_mods_installed("Failure! No installed mods or addons were found") == [])
# A game with no mods installer (cod) prints 'Unknown command' + a 'LinuxGSM - <Game> - Version …'
# banner — that banner must NOT be parsed as an installed mod.
_cod_out = ("Error! Unknown command: ./codserver mods-remove\n"
            "LinuxGSM - Call of Duty - Version v26.1.0\nstart st | Start the server.")
check("mods: 'Unknown command' output -> game not supported", _sm_files._game_supports_mods(_cod_out) is False)
check("mods: version banner isn't parsed as an installed mod",
      not any(m["id"] == "LinuxGSM" for m in _sm_files._parse_mods_installed(_cod_out)))
check("mods: a real mods list is still 'supported'",
      _sm_files._game_supports_mods("metamodsource - Metamod: Source - desc") is True)
# mods_action rejects unsafe ids before ever building a shell command (injection guard)
check("mods: mods_action rejects an unsafe id",
      _sm_files.mods_action(None, "u", "u", "install", "foo; rm -rf x")[1] == "invalid mod id")

# ── a mods list the panel could not READ is not "this game has no mods" ─────────────────────────
# mods_available/mods_installed discarded the rc, and `supported` is `"unknown command" not in
# text` — True of "" as well. run_as_game_user does not raise on the local or tailscale transports
# (it returns ("", "SSH command timed out", -1)), and a refused account/script name returns
# ("", "invalid account or script name", 1) the same way. Both came back as ([], True): "this game
# has a mods installer, and it lists nothing" — which the Mods card renders as "This game doesn't
# have any LinuxGSM-installable mods." about a host that was never asked, while hiding the Remove
# button for every mod that IS installed. `supported` has no state for "we could not look", so the
# LIST gets one: None, the same third state as browse_dir's `unreadable`.
_o_rag = _sm_files._core.run_as_game_user
try:
    for _desc, _ans in (("a transport that timed out", ("", "SSH command timed out", -1)),
                        ("a refused account/script name", ("", "invalid account or script name", 1)),
                        ("a silent rc 0", ("", "", 0))):
        _sm_files._core.run_as_game_user = lambda *a, _v=_ans, **k: _v
        _ma, _ms = _sm_files.mods_available(NS(), "gmodserver", "gmodserver")
        _mi, _mis = _sm_files.mods_installed(NS(), "gmodserver", "gmodserver")
        check("mods: %s is not an empty mod list" % _desc,
              _ma is None and _mi is None,
              "available=%r installed=%r — the card claims the game has no mods" % (_ma, _mi))

    # POSITIVE CONTROL 1: a real mods-install listing still parses, and still says supported.
    _sm_files._core.run_as_game_user = lambda *a, **k: (_mods_avail_out, "", 0)
    _ma_ok, _ms_ok = _sm_files.mods_available(NS(), "gmodserver", "gmodserver")
    check("mods: ...while a real listing still comes back as a list",
          [m["id"] for m in (_ma_ok or [])] == ["metamodsource", "sourcemod", "wiremod-extras"]
          and _ms_ok is True, "%r %r" % (_ma_ok, _ms_ok))
    _sm_files._core.run_as_game_user = lambda *a, **k: (_mods_inst_out, "", 0)
    _mi_ok, _mis_ok = _sm_files.mods_installed(NS(), "gmodserver", "gmodserver")
    check("mods: ...and a real installed list too",
          [m["id"] for m in (_mi_ok or [])] == ["metamodsource"] and _mis_ok is True,
          "%r %r" % (_mi_ok, _mis_ok))
    # POSITIVE CONTROL 2: a game that genuinely HAS the installer and genuinely has nothing
    # installed must still read as an EMPTY list, not as unreadable — that is the distinction the
    # whole change exists to keep, in the other direction.
    _sm_files._core.run_as_game_user = lambda *a, **k: (
        "Garry's Mod Removing Mods\n=================================\n"
        "Failure! No installed mods or addons were found\n", "", 0)
    _mi_none, _mis_none = _sm_files.mods_installed(NS(), "gmodserver", "gmodserver")
    check("mods: a game with the installer and nothing installed is [] , not unreadable",
          _mi_none == [] and _mis_none is True, "%r %r" % (_mi_none, _mis_none))
    # POSITIVE CONTROL 3: the no-installer game (cod) still answers supported=False with a list,
    # so server_files.js can go on hiding the whole card for it.
    _sm_files._core.run_as_game_user = lambda *a, **k: (_cod_out, "", 0)
    _ma_cod, _ms_cod = _sm_files.mods_available(NS(), "codserver", "codserver")
    check("mods: a game with no installer still answers supported=False, not unreadable",
          _ma_cod == [] and _ms_cod is False, "%r %r" % (_ma_cod, _ms_cod))
finally:
    _sm_files._core.run_as_game_user = _o_rag

# game-backup download/delete validate the file name before touching any path (server=None here,
# so a passing regex would crash — proving rejection happens purely on the name)
check("game backup: delete rejects an unsafe name",
      _sm_cron.delete_game_backup(None, "u", "x; rm -rf y") is False)
check("game backup: delete rejects a path-traversal name",
      _sm_cron.delete_game_backup(None, "u", "../../etc/passwd") is False)
check("game backup: stream yields nothing for an unsafe name",
      list(_sm_cron.stream_game_backup(None, "u", "../../etc/passwd")) == [])
check("game backup: name shape accepts a real archive",
      bool(_sm_cron._GAME_BACKUP_NAME.match("gmodserver-2026-07-06-141117.tar.zst")))

# ── discover_linuxgsm_servers: parse the one-shot host scan output ──
_orig_disc_rc = _sm_core.run_command


# ── system_ops / hosts: nine things that were wrong about escalation, caching and parsing ─────
# Each is driven through the real function with only the transport stubbed.
import json as _so_json
from unit.part01 import _sm_game  # noqa: E402


def _so_stub(**kw):
    """Swap attributes on system_ops for the duration of a `with` block."""
    import contextlib

    @contextlib.contextmanager
    def _cm():
        old = {k: getattr(SO, k) for k in kw}
        for k, v in kw.items():
            setattr(SO, k, v)
        try:
            yield
        finally:
            for k, v in old.items():
                setattr(SO, k, v)
    return _cm()


# 1. A host installed the hardened way has `<user> ALL=(root) NOPASSWD: <helper>` — under which
#    `sudo -n true` is DENIED while `sudo -n <helper> apt-upgrade` works. Both of these were gated
#    on _check_sudo() alone, so they refused with a message telling the admin to configure
#    passwordless sudo: to undo the hardening install.sh had just applied. Every other privileged
#    path in the module already branches on the helper.
_so_calls = []
SO._SUDO_PROBE.update(at=0.0, ok=None)
SO._HELPER_STATE["present"] = True
with _so_stub(_run=lambda c, **k: (_so_calls.append(c), ("NOPASS", "", 0))[1],
              _run_verb=lambda v, a=(), **k: (_so_calls.append(v), ("", "", 0))[1]):
    check("system_ops: the OS update works under the NARROW sudoers grant (helper, not sudo -n true)",
          SO.os_run_update()[0] is True, str(SO.os_run_update()))
    check("system_ops: ...and so does the reboot", SO.server_reboot(0)[0] is True)
    # 13. delay_seconds arrived raw from the JSON body and went into time.sleep() in a daemon
    #     thread: a non-numeric value killed that thread with a TypeError AFTER the route had
    #     answered success and written a server_reboot audit entry. restart_panel clamps; this did
    #     not.
    _rb_ok, _rb_msg = SO.server_reboot("abc")
    check("system_ops: a non-numeric reboot delay is refused, not logged as a reboot that happens",
          _rb_ok is False and "number of seconds" in _rb_msg, str(_rb_msg))
    check("system_ops: ...and an absurd one is clamped rather than slept on",
          SO.server_reboot(99999) == (True, "Server will reboot in 300 seconds."),
          str(SO.server_reboot(99999)))
# ...and with no helper and no sudo it still refuses, which is the whole point of the gate.
SO._HELPER_STATE["present"] = False
SO._SUDO_PROBE.update(at=0.0, ok=None)
with _so_stub(_run=lambda c, **k: ("NOPASS", "", 0), _run_verb=lambda *a, **k: ("", "", 0)):
    check("system_ops: with neither helper nor sudo, both still refuse",
          SO.os_run_update()[0] is False and SO.server_reboot()[0] is False)
SO._HELPER_STATE["present"] = None

# 14. Both background workers threw the privileged verb's (out, err, rc) away. _run_verb NEVER
#     raises — it turns a refusal into a non-zero rc (a general sudoers.d rule sorting after the
#     panel's narrow NOPASSWD grant answers "a password is required" and exits 1; a helper too old
#     to know the verb exits 2) or into ("", "...", -1). So there was no exception, no log line and
#     no user-visible trace at all: the route had already answered "Server will reboot in 5
#     seconds." and written a server_reboot audit row, the host never rebooted, and an admin
#     rebooting to clear a hung game server believed it had. Same for apt-upgrade on a held dpkg
#     lock or a full disk. These threads outlive the HTTP response, so the log is where the outcome
#     has to land — and every other _run_verb call site in the module already checks rc.
import threading as _rbt  # noqa: E402

_rb_errs = []
_rb_reboot_done, _rb_apt_done = _rbt.Event(), _rbt.Event()


def _rb_err(msg, *a, **k):
    line = (str(msg) % a) if a else str(msg)
    _rb_errs.append(line)
    if line.startswith("reboot verb failed"):
        _rb_reboot_done.set()
    if line.startswith("apt-upgrade verb failed"):
        _rb_apt_done.set()


_rb_saved_log = SO._log.error
SO._HELPER_STATE["present"] = True
SO._SUDO_PROBE.update(at=0.0, ok=None)
try:
    SO._log.error = _rb_err
    with _so_stub(_run=lambda c, **k: ("NOPASS", "", 0),
                  _run_verb=lambda v, a=(), **k: ("", "sudo: a password is required", 1)):
        SO.server_reboot(0)
        # wait(), not sleep(): the worker is a daemon thread, and a leaked one lands in a later
        # check's stub. The event is set from inside the log call, which is its last statement.
        check("system_ops: a REFUSED reboot verb is logged, not dropped on the floor",
              _rb_reboot_done.wait(5) and any("reboot verb failed" in e for e in _rb_errs),
              str(_rb_errs))
        SO.os_run_update()
        check("system_ops: ...and so is a refused apt-upgrade",
              _rb_apt_done.wait(5) and any("apt-upgrade verb failed" in e for e in _rb_errs),
              str(_rb_errs))
    # Positive control: the verb still RUNS, and a successful one logs nothing.
    _rb_errs.clear()
    _rb_calls, _rb_ran = [], _rbt.Event()
    with _so_stub(_run=lambda c, **k: ("NOPASS", "", 0),
                  _run_verb=lambda v, a=(), **k: (_rb_calls.append(v), _rb_ran.set(),
                                                  ("", "", 0))[2]):
        SO.server_reboot(0)
        check("system_ops: ...while a reboot that the host ACCEPTS still runs and logs nothing",
              _rb_ran.wait(5) and "reboot" in _rb_calls and not _rb_errs,
              str((_rb_calls, _rb_errs)))
finally:
    SO._log.error = _rb_saved_log
    SO._HELPER_STATE["present"] = None

# 4. Tailscale on Linux is USERSPACE WireGuard over a TUN, so `ip link show type wireguard` can
#    never list tailscale0 — the first detection method matched any name containing "wg" and could
#    only ever return something that is not Tailscale. On a host running both, "Allow Tailscale"
#    ran `ufw allow in on wg0`: all inbound traffic on an unrelated VPN, reported as success.
def _ts_run(cmd, **k):
    if "type wireguard" in cmd:
        return "wg0\n", "", 0
    if "grep -i tailscale" in cmd:
        return "tailscale0\n", "", 0
    return "", "", 0


with _so_stub(_run=_ts_run):
    check("system_ops: a plain WireGuard interface is not mistaken for Tailscale's",
          SO.detect_tailscale_interface() == "tailscale0",
          str(SO.detect_tailscale_interface()))
# A host that really does run tailscaled against the kernel module still matches, by NAME.
with _so_stub(_run=lambda c, **k: (("tailscale-wg0\n", "", 0) if "type wireguard" in c
                                   else ("", "", 0))):
    check("system_ops: ...but a wireguard device that says tailscale still counts",
          SO.detect_tailscale_interface() == "tailscale-wg0")


# ...and the SAME bug through method 3, which was never fixed with the other three: it probed
# ["tailscale0", "wg0", "utun"] by name and returned whichever `ip link show` found first. On a
# host with plain WireGuard and no tailscale0 — Tailscale absent, or tailscaled running
# --tun=userspace-networking (the container default), where there IS no TUN device — that is wg0,
# and method 4 (`tailscale status --json`, which answers correctly) never ran. The button then
# ran `ufw allow in on wg0`: all inbound on an unrelated VPN, reported as success naming it, and
# get_server_status's substring match on that name read "Tailscale allowed" from any wg0 rule.
def _ts_wg_only(cmd, **k):
    if "type wireguard" in cmd or "grep -i tailscale" in cmd:
        return "", "", 0                      # methods 1 and 2 find no tailscale-named device
    if "ip link show wg0" in cmd or "ip link show utun" in cmd:
        return "12: wg0: <POINTOPOINT,UP>\nFOUND\n", "", 0     # plain WireGuard IS up
    return "", "", 0                          # tailscale0 absent; status --json says nothing


with _so_stub(_run=_ts_wg_only):
    _ts_wg = SO.detect_tailscale_interface()
    check("system_ops: a host with wg0 and no tailscale0 gets NO interface, not wg0",
          _ts_wg is None,
          "answered %r — 'Allow Tailscale' would open all inbound on an unrelated VPN" % (_ts_wg,))


# Positive control: method 3 must still find Tailscale's own device when it is the one present.
def _ts_tailscale0(cmd, **k):
    if "ip link show tailscale0" in cmd:
        return "9: tailscale0: <POINTOPOINT,UP>\nFOUND\n", "", 0
    return "", "", 0


with _so_stub(_run=_ts_tailscale0):
    check("system_ops: ...while method 3 still finds tailscale0 when that is what is there",
          SO.detect_tailscale_interface() == "tailscale0",
          str(SO.detect_tailscale_interface()))

# 10. The verb runs `ufw status verbose`, which has no rule numbers — only `ufw status numbered`
#     does. The branch tested parts[0][0].isdecimal() and called the result "num", so a port landed
#     in the number field and every rule whose To column is not numeric was dropped: the tailscale0
#     allow, app profiles like OpenSSH, and every panel-block DENY.
_UFW_V = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     LIMIT IN    Anywhere
27015                      ALLOW IN    Anywhere                   # codserver
Anywhere on tailscale0     ALLOW IN    Anywhere
OpenSSH                    ALLOW IN    Anywhere
Anywhere                   DENY IN     203.0.113.9                # panel-block
"""
with _so_stub(_run_verb=lambda v, a=(), **k: (_UFW_V, "", 0)):
    _ufw_parsed = SO.ufw_status()
check("system_ops: ufw_status reports every rule, not only the ones starting with a digit",
      len(_ufw_parsed["rules"]) == 5, _so_json.dumps(_ufw_parsed["rules"]))
check("system_ops: ...including the tailscale0 allow, the app profile and the panel-block DENY",
      [r["to"] for r in _ufw_parsed["rules"]]
      == ["22/tcp", "27015", "Anywhere on tailscale0", "OpenSSH", "Anywhere"],
      str([r["to"] for r in _ufw_parsed["rules"]]))
check("system_ops: ...and a DENY's source is the From column, not the To column",
      _ufw_parsed["rules"][-1]["action"] == "DENY"
      and _ufw_parsed["rules"][-1]["from"].startswith("203.0.113.9"),
      str(_ufw_parsed["rules"][-1]))

# 10b. "Tailscale interface allowed" gates the button that removes public port 22, and it was a
#      substring match over that same text: an `ALLOW OUT ... on tailscale0` row (early installs
#      added one beside the IN rule, and it outlives deleting it) or a `DENY IN` on the interface
#      read "Allowed". It is now read from the rules above, in UFW's first-match order.
_UFW_HDR = _UFW_V.split("To  ")[0] + "To                         Action      From\n--                         ------      ----\n"


def _ts_allowed_for(rows):
    """Drive the REAL get_server_status over a `ufw status verbose` holding `rows`."""
    with _so_stub(_run_verb=lambda v, a=(), **k: (_UFW_HDR + rows, "", 0),
                  tailscale_ssh_status=lambda: {"enabled": False, "running": True},
                  os_update_available=lambda refresh=False: {},
                  server_uptime=lambda: "", _check_sudo=lambda: True,
                  detect_tailscale_interface=lambda: "tailscale0"):
        return SO.get_server_status(force=True)["tailscale_ufw_allowed"]


try:
    check("ufw-tailscale: an ALLOW OUT row on tailscale0 alone does not read as 'let in'",
          _ts_allowed_for("Anywhere                   ALLOW OUT   Anywhere on tailscale0\n"
                          "22/tcp                     ALLOW IN    Anywhere\n") is False)
    check("ufw-tailscale: a DENY IN on tailscale0 is not 'allowed'",
          _ts_allowed_for("Anywhere on tailscale0     DENY IN     Anywhere\n") is False)
    check("ufw-tailscale: ...nor a DENY IN that UFW evaluates before the allow",
          _ts_allowed_for("Anywhere on tailscale0     DENY IN     Anywhere\n"
                          "Anywhere on tailscale0     ALLOW IN    Anywhere\n") is False)
    check("ufw-tailscale: a comment naming the interface is not a rule for it",
          _ts_allowed_for("27015                      ALLOW IN    Anywhere                   # tailscale0\n")
          is False)
    check("ufw-tailscale: the panel's own `allow in on tailscale0` rule reads as allowed (control)",
          _ts_allowed_for("22/tcp                     LIMIT IN    Anywhere\n"
                          "Anywhere on tailscale0     ALLOW IN    Anywhere\n"
                          "Anywhere                   ALLOW OUT   Anywhere on tailscale0\n") is True)
finally:
    SO.invalidate_server_status()

# 11. apt's history.log writes Install:/Upgrade:/Remove:/Purge:, never "Packages:" — so that list
#     was always empty. And `tail -50` almost always starts mid-record, so the first entry used to
#     be emitted with no "start" key at all.
_APT_HIST = """Install: curl:amd64 (7.81.0-1)
End-Date: 2026-09-08  04:09:59

Start-Date: 2026-09-08  04:10:01
Commandline: /usr/bin/unattended-upgrade
Upgrade: libssl3:amd64 (3.0.2-0ubuntu1, 3.0.2-0ubuntu1.1), zlib1g:amd64 (1:1.2.11, 1:1.2.12)
End-Date: 2026-09-08  04:10:30
"""
with _so_stub(_run=lambda c, **k: (_APT_HIST, "", 0)):
    _o_exists = SO.os.path.exists
    SO.os.path.exists = lambda p: True
    try:
        _apt_entries = SO.os_update_log()
    finally:
        SO.os.path.exists = _o_exists
check("system_ops: os_update_log reports the packages apt actually names",
      len(_apt_entries) == 1 and _apt_entries[0]["packages"] == ["libssl3", "zlib1g"],
      str(_apt_entries))
check("system_ops: ...and a record whose Start-Date tail cut off is dropped, not emitted keyless",
      all("start" in e for e in _apt_entries), str(_apt_entries))

# 5. "22/tcp" in low is a SUBSTRING test, so 2222/tcp, 8022/tcp and 22022/tcp all read as a rule
#    for port 22. The panel's own change_ssh_port moves sshd to 2222 and tells the operator to
#    close 22 — after which the Public SSH card still reported it open and never showed the true
#    off state, so nobody could tell from the UI whether public SSH was exposed.
_SSH_UFW = """Status: active

To                         Action      From
--                         ------      ----
2222/tcp                   LIMIT IN    Anywhere
27015                      ALLOW IN    Anywhere
2222/tcp (v6)              LIMIT IN    Anywhere (v6)
"""
_o_rp_h = _sm_hosts._core.run_privileged
try:
    _sm_hosts._core.run_privileged = lambda *a, **k: (_SSH_UFW, "", 0)
    check("hosts: a rule for 2222 is not read as a rule for port 22",
          _sm_hosts.remote_public_ssh_status(object()) == {"active": True, "mode": "off"},
          str(_sm_hosts.remote_public_ssh_status(object())))
    _SSH_UFW = _SSH_UFW.replace("2222/tcp                   LIMIT IN",
                                "22/tcp                     LIMIT IN")
    check("hosts: ...and a real rule for 22 still is",
          _sm_hosts.remote_public_ssh_status(object())["mode"] == "limit")
finally:
    _sm_hosts._core.run_privileged = _o_rp_h

# 8. Documented as returning (ok, msg), it let the verb's VerbError out instead — through
#    run_privileged, through the route, and out as a bare Flask 500 HTML page that the caller's
#    .then(r => r.json()) could not parse.
_o_rp_h = _sm_hosts._core.run_privileged
try:
    _sm_hosts._core.run_privileged = lambda *a, **k: ("", "", 0)
    _uf_raised = []
    for _src, _port in (("my-lan", "27015"), ("10.0.0.1", "not-a-port"), ("", "27015")):
        try:
            _r = _sm_hosts.remote_ufw_allow_from(object(), _src, _port)
            if _r[0]:
                _uf_raised.append("%s/%s was ACCEPTED" % (_src, _port))
        except Exception as _e:
            _uf_raised.append("%s/%s raised %s" % (_src, _port, type(_e).__name__))
    check("hosts: remote_ufw_allow_from answers (ok, msg) instead of raising out of the request",
          not _uf_raised, "; ".join(_uf_raised))
    check("hosts: ...and a real address and port range still go through",
          _sm_hosts.remote_ufw_allow_from(object(), "10.0.0.0/8", "27015:27020")[0] is True)
finally:
    _sm_hosts._core.run_privileged = _o_rp_h

# 3. _OS_SLUG_CACHE had NO expiry and was keyed ("srv", id), which forget_remote_caches could not
#    have popped even if it had been registered. SQLite reuses rowids, so the next host to take a
#    deleted one inherited its distro — and deps_for_game then loads ubuntu-22.04.csv for a Debian
#    12 box, where apt-get install (atomic) aborts on the first nonexistent package.
_o_rc_h = _sm_hosts._core.run_command
try:
    _slug = ["ubuntu-22.04"]
    _sm_hosts._core.run_command = lambda *a, **k: (_slug[0], "", 0)
    _sm_hosts._OS_SLUG_CACHE.clear()
    _srv7 = NS(id=7, host="h7")
    _first = _sm_hosts.host_os_slug(_srv7)
    _sm_core.forget_remote_caches(7)          # what the after_delete listener does
    _slug[0] = "debian-12"
    _second = _sm_hosts.host_os_slug(NS(id=7, host="h7"))
    check("hosts: a deleted host's OS slug is not inherited by the next host with its rowid",
          (_first, _second) == ("ubuntu-22.04", "debian-12"), "%s then %s" % (_first, _second))
    check("hosts: ...and it is still cached between reads for the SAME host",
          _sm_hosts.host_os_slug(NS(id=7, host="h7")) == "debian-12"
          and _sm_hosts._OS_SLUG_CACHE.get(7) == "debian-12",
          str(_sm_hosts._OS_SLUG_CACHE))
    # A FAILED read must not be memoised. The lookup was `if key in _OS_SLUG_CACHE` — a MEMBERSHIP
    # test — and the store was unconditional, so a timed-out /etc/os-release put None into a cache
    # with no TTL and every later call got that None back as a HIT for the life of the process.
    # None reaches lgsm_data.deps_name, whose default is ubuntu-24.04.csv, so a Debian 12 box got
    # Ubuntu's package list on every install from then on — and apt-get install is atomic, so one
    # nonexistent package aborts the whole batch. Nothing but deleting the host cleared it.
    _sm_hosts._OS_SLUG_CACHE.clear()
    _sm_hosts._core.run_command = lambda *a, **k: ("", "SSH command timed out", -1)
    _slug_fail = _sm_hosts.host_os_slug(NS(id=8, host="h8"))
    check("hosts: a failed os-release read answers None, not a distro",
          _slug_fail is None, repr(_slug_fail))
    check("hosts: ...and is NOT memoised, so the host is not pinned to Ubuntu's package list",
          8 not in _sm_hosts._OS_SLUG_CACHE,
          "cached %r — every later install loads the wrong distro's deps"
          % (_sm_hosts._OS_SLUG_CACHE,))
    # POSITIVE CONTROL: the very next read wins, and IS cached.
    _sm_hosts._core.run_command = lambda *a, **k: ("debian-12", "", 0)
    check("hosts: ...so one round trip later the real answer lands and is cached",
          _sm_hosts.host_os_slug(NS(id=8, host="h8")) == "debian-12"
          and _sm_hosts._OS_SLUG_CACHE.get(8) == "debian-12",
          str(_sm_hosts._OS_SLUG_CACHE))
finally:
    _sm_hosts._core.run_command = _o_rc_h
    _sm_hosts._OS_SLUG_CACHE.clear()

# ── "this host does not need a reboot" must be something the panel ESTABLISHED ──────────────────
# The probe was the negative-sentinel shape: `test -f /var/run/reboot-required && echo YES || echo
# NO` with the rc discarded, then `if "YES" not in out`. `"YES" not in ""` is True, and the
# tailscale and local transports return ("", "SSH command timed out", -1) WITHOUT raising — so a
# poll that never ran was published as the definite answer "no reboot needed", and nags.js removed
# the banner from a host running an unpatched kernel. Require rc 0 AND one of the probe's own two
# tokens, the way remote_bootstrap_vps requires EXISTS/NOTEXISTS.
_o_rb = _sm_hosts._core.run_command
try:
    for _desc, _ans in (("a transport that timed out", ("", "SSH command timed out", -1)),
                        ("a silent rc 0", ("", "", 0)),
                        ("output with neither token", ("bash: test: command not found", "", 127))):
        _sm_hosts._core.run_command = lambda *a, _v=_ans, **k: _v
        _rb = _sm_hosts.remote_reboot_required(NS(id=91, host="203.0.113.91"))
        check("reboot nag: %s answers 'we could not look', not 'no reboot needed'" % _desc,
              _rb.get("known") is False and _rb.get("required") is False,
              "%r — a failed poll retracts the banner a real one put up" % (_rb,))

    def _rb_boom(*a, **k):
        raise OSError("paramiko says no")
    _sm_hosts._core.run_command = _rb_boom
    _rb_x = _sm_hosts.remote_reboot_required(NS(id=91, host="203.0.113.91"))
    check("reboot nag: ...and so does the raising (paramiko) transport",
          _rb_x.get("known") is False and _rb_x.get("required") is False, repr(_rb_x))

    # POSITIVE CONTROL 1: a host that really does NOT need a reboot is still a known answer, or
    # the banner would never clear again.
    _sm_hosts._core.run_command = lambda *a, **k: ("NO", "", 0)
    _rb_no = _sm_hosts.remote_reboot_required(NS(id=92, host="203.0.113.92"))
    check("reboot nag: a real 'NO' is a known answer, so the banner still clears",
          _rb_no == {"required": False, "packages": [], "known": True}, repr(_rb_no))
    # POSITIVE CONTROL 2: a host that does need one still reports it, with its packages.
    _rb_seq = ["YES", "linux-image-generic\nlibc6\n"]
    _sm_hosts._core.run_command = lambda *a, **k: (_rb_seq.pop(0) if _rb_seq else "", "", 0)
    _rb_yes = _sm_hosts.remote_reboot_required(NS(id=93, host="203.0.113.93"))
    check("reboot nag: a real 'YES' still raises the banner, with its packages",
          _rb_yes.get("required") is True and _rb_yes.get("known") is True
          and _rb_yes.get("packages") == ["libc6", "linux-image-generic"], repr(_rb_yes))
finally:
    _sm_hosts._core.run_command = _o_rb

# forget_remote_caches has to reach TUPLE keys, or registering a cache keyed (remote id, port)
# would look like protection while doing nothing.
_tuple_cache = _sm_core.register_remote_cache({(7, 27015): "a", (8, 27015): "b", 7: "c"})
_sm_core.forget_remote_caches(7)
check("_core: forgetting a deleted host reaches tuple-keyed per-remote caches too",
      _tuple_cache == {(8, 27015): "b"}, str(_tuple_cache))
_sm_core._remote_caches.remove(_tuple_cache)
# Every per-remote cache in the package is registered — the list of deliberate exceptions is what
# hid _OS_SLUG_CACHE, which had no expiry at all.
_unreg = [n for n, m in (("hosts._OS_SLUG_CACHE", _sm_hosts._OS_SLUG_CACHE),
                         ("hosts._uptime_cache", _sm_hosts._uptime_cache),
                         ("hosts._pro_status_cache", _sm_hosts._pro_status_cache),
                         ("_core._host_metrics_cache", _sm_core._host_metrics_cache),
                         ("_core._live_metrics_cache", _sm_core._live_metrics_cache),
                         ("_core._gamedig_host_cache", _sm_core._gamedig_host_cache),
                         ("cron._game_map_cache", _sm_cron._game_map_cache),
                         ("game._version_cache", _sm_game._version_cache),
                         ("firewall._specs_cache", _sm_firewall._specs_cache))
          if not any(m is r for r in _sm_core._remote_caches)]
check("_core: every per-remote cache is registered for pruning", not _unreg,
      "not registered: %s" % _unreg)

# 2. sudo=True has to mean ROOT. It used to mean `sudo -u <the remote's linuxgsm_user>` whenever
#    that optional field was filled in, which silently demoted every privileged operation in
#    hosts.py — ufw, apt, fail2ban, the sshd hardening and its drop-in write, the node-tools cron
#    and the whole VPS bootstrap, which still reported "VPS bootstrap complete".
class _LgsmSrv:
    id, host, port, username, auth_method = 99, "h", 22, "u", "key"
    sudo_enabled, is_local, linuxgsm_user = True, False, "gmodserver"


_wire = []


class _FakeChan:
    """Stands in for a paramiko Channel. run_command drains the channel itself now (it must read
    both streams BEFORE asking for the exit status, or a command whose output exceeds the 2 MiB
    window can never exit), so a stub that implements only recv_exit_status no longer models the
    object under test. These tests assert what reaches the WIRE, so the streams are empty — but
    they have to be empty in the shape the real channel would present."""
    eofs = 0            # how many times run_command sent EOF on the exec channel's stdin

    def shutdown_write(self):
        type(self).eofs += 1

    def settimeout(self, _t):
        return None

    def recv_ready(self):
        return False

    def recv_stderr_ready(self):
        return False

    def recv(self, _n):
        return b""

    def recv_stderr(self, _n):
        return b""

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return 0


class _FakeStd:
    channel = _FakeChan()

    def read(self):
        return b""


_o_conn = _sm_core.get_connection
try:
    _sm_core.get_connection = lambda s: NS(exec_command=lambda c, timeout=None: (
        _wire.append(c), (_FakeStd(), _FakeStd(), _FakeStd()))[1])
    _sm_core.run_command(_LgsmSrv(), "ufw --force enable", sudo=True)
    check("_core: a remote's linuxgsm_user no longer demotes a privileged command",
          _wire and _wire[-1].startswith("sudo bash -c ") and "sudo -u" not in _wire[-1],
          str(_wire[-1:]))
    _wire.clear()
    _sm_core.run_command(_LgsmSrv(), "whoami", sudo=False)
    check("_core: ...and sudo=False is still unescalated",
          _wire == ["whoami"], str(_wire))
    # ── the exec channel's stdin must reach EOF, or a command that READS it never ends ─────────
    # `stdin` was bound and thrown away: never written to, never closed, shutdown_write never
    # called. The remote's fd 0 was an open SSH channel that receives nothing and never EOFs, so a
    # LinuxGSM action that prompts (validate, run with no `answers`) blocked there forever — and
    # nothing bounded it, because _drain_exec's settimeout(0.0) replaces the channel timeout
    # exec_command just set and its only exit is exit_status_ready(). The greenlet, its request,
    # its DB session and the channel leaked for the life of the process. files.py:911 already
    # sends this EOF, and _POPEN_KW gives the local transport the same property with stdin=DEVNULL.
    _eofs_before = _FakeChan.eofs
    _sm_core.run_command(_LgsmSrv(), "id", sudo=False)
    check("_core: the paramiko transport sends EOF on the exec channel's stdin",
          _FakeChan.eofs == _eofs_before + 1,
          "shutdown_write() was not called — a remote command that reads stdin hangs forever, "
          "and the timeout= every call site passes bounds nothing on this transport")
    check("_core: ...and the command still reaches the wire and returns its rc (positive control)",
          _wire[-1] == "id" and _sm_core.run_command(_LgsmSrv(), "id", sudo=False)[2] == 0,
          str(_wire[-1:]))
finally:
    _sm_core.get_connection = _o_conn


# ── a remote that goes SILENT must not hold the drain forever ──────────────────────────────────
# _drain_exec's only exit was exit_status_ready(), and settimeout(0.0) threw away the channel
# timeout. A remote that accepts the exec and then sends no byte and no exit status (compromised,
# or wedged by OOM) held the loop for the life of the process: the monitor sweep's ex.map() blocked
# on that one host, so alerting stopped for every host. The fake below answers after ~3 s, so a
# drain without the bound returns rc 0 late instead of hanging this suite; with it, rc -1 at once.
import time as _dtime  # noqa: E402


class _SilentChan:
    def __init__(self, trickle_until=0.0, end_after=3.0):
        self.t0 = _dtime.monotonic()
        self.trickle_until, self.end_after = trickle_until, end_after
        self.closed = False
        self._next = 0.0

    def settimeout(self, _t):
        return None

    def recv_ready(self):
        # Talks every 20 ms while trickling: a command making progress, however slowly.
        el = _dtime.monotonic() - self.t0
        if el < self.trickle_until and el >= self._next:
            self._next = el + 0.02
            return True
        return False

    def recv(self, _n):
        return b"."

    def recv_stderr_ready(self):
        return False

    def recv_stderr(self, _n):
        return b""

    def exit_status_ready(self):
        return self.closed or _dtime.monotonic() - self.t0 > self.end_after

    def recv_exit_status(self):
        return 0

    def close(self):
        self.closed = True


_sc = _SilentChan()
_sd_t = _dtime.monotonic()
_sd = _sm_core._drain_exec(_sc, idle_limit=0.1)
check("_core: a remote that sends nothing and no exit status is given up on (rc -1)",
      _sd[2] == -1 and _dtime.monotonic() - _sd_t < 2.0 and _sc.closed,
      "rc=%r after %.1fs closed=%r — the drain waits as long as the remote likes"
      % (_sd[2], _dtime.monotonic() - _sd_t, _sc.closed))
check("_core: ...and says it timed out, like the other two transports",
      b"timed out" in _sd[1], repr(_sd[1]))
# POSITIVE CONTROL: silence is what is bounded, not duration. A command that keeps talking for
# longer than the idle limit, then exits, is read to the end with its real rc.
_sc = _SilentChan(trickle_until=0.4, end_after=0.45)
_sd = _sm_core._drain_exec(_sc, idle_limit=0.1)
check("_core: ...while a command still making progress past the limit runs to its exit",
      _sd[2] == 0 and not _sc.closed and len(_sd[0]) >= 5,
      "rc=%r closed=%r read=%d" % (_sd[2], _sc.closed, len(_sd[0])))

# ...and run_command must PASS the bound: a helper that can stop is no use to a caller that
# never asks it to. The floor is shrunk for the test; the caller's timeout of 0 leaves the floor.
_o_conn2, _o_floor = _sm_core.get_connection, _sm_core._DRAIN_IDLE_FLOOR


class _SilentStd:
    def __init__(self, ch):
        self.channel = ch


try:
    _rc_chan = _SilentChan()
    _rc_chan.shutdown_write = lambda: None
    _sm_core.get_connection = lambda s: NS(exec_command=lambda c, timeout=None: (
        _SilentStd(_rc_chan), _SilentStd(_rc_chan), _SilentStd(_rc_chan)))
    _sm_core._DRAIN_IDLE_FLOOR = 0.1
    _rct = _dtime.monotonic()
    _rcr = _sm_core.run_command(_LgsmSrv(), "id", timeout=0, sudo=False)
    check("_core: run_command hands the drain its silence bound",
          _rcr[2] == -1 and _dtime.monotonic() - _rct < 2.0,
          "rc=%r after %.1fs" % (_rcr[2], _dtime.monotonic() - _rct))
finally:
    _sm_core.get_connection, _sm_core._DRAIN_IDLE_FLOOR = _o_conn2, _o_floor


# ── the repo URL the panel links to is DERIVED from the checkout's origin ───────────────────────
# The sidebar footer links "LinuxGSM Panel" to the repo and the running commit SHA to that exact
# commit, so "what is actually deployed" is one click. Both come from github_repo_url(), which
# reads remote.origin.url for the same reason the "report an issue" link already did: somebody
# running a fork must be sent to THEIR repo, not to upstream. _github_issues_url() is built on it
# now rather than repeating the regex, so the two can never disagree about which repo this is.
_orig_git_ru = _so._git
try:
    _ru_out = {"v": ("https://github.com/someone/their-fork.git", "", 0)}
    _so._git = lambda *a, **k: _ru_out["v"]

    check("repo url: derived from the checkout's own origin",
          _so.github_repo_url() == "https://github.com/someone/their-fork",
          _so.github_repo_url())
    check("repo url: ...and the issues link is built from it, not a second regex",
          _so._github_issues_url() == "https://github.com/someone/their-fork/issues/new",
          _so._github_issues_url())
    # A commit link is repo + "/commit/<sha>", so a trailing slash would produce a double slash.
    check("repo url: no trailing slash, so callers can append a path",
          not _so.github_repo_url().endswith("/"), _so.github_repo_url())

    _ru_out["v"] = ("git@github.com:someone/their-fork.git", "", 0)
    check("repo url: an SSH remote resolves to the same web URL",
          _so.github_repo_url() == "https://github.com/someone/their-fork",
          _so.github_repo_url())

    # Not GitHub, no remote, and a failed git call must all fall back rather than build nonsense.
    for _desc, _val in (("a non-GitHub remote", ("https://gitlab.com/x/y.git", "", 0)),
                        ("no remote configured", ("", "", 1)),
                        ("git itself failing", ("", "fatal: not a git repository", 128))):
        _ru_out["v"] = _val
        check("repo url: %s falls back to the canonical repo" % _desc,
              _so.github_repo_url() == _so._CANONICAL_REPO, _so.github_repo_url())

    def _ru_boom(*a, **k):
        raise OSError("git exploded")
    _so._git = _ru_boom
    check("repo url: an exception falls back too, rather than propagating into a render",
          _so.github_repo_url() == _so._CANONICAL_REPO, _so.github_repo_url())
finally:
    _so._git = _orig_git_ru

# The footer is the only place this is surfaced, so assert the template actually uses it — a
# context value nothing renders is the shape [[template-reads-a-name-the-route-never-passed]]
# warns about, in reverse.
_base_html = open(os.path.join(_root, "templates", "base.html"), encoding="utf-8").read()
check("repo url: base.html links the panel name at it",
      'href="{{ panel_repo_url }}"' in _base_html)
check("repo url: ...and the commit SHA at that exact commit",
      'href="{{ panel_repo_url }}/commit/{{ panel_commit }}"' in _base_html)
check("repo url: ...and both open in a new tab without leaking the referrer",
      _base_html.count('rel="noopener noreferrer"') >= 2,
      "%d occurrences" % _base_html.count('rel="noopener noreferrer"'))
check("repo url: ...and a checkout with no resolvable repo still renders the name",
      "{% else %}LinuxGSM Panel{% endif %}" in _base_html)
# ── sshd socket activation: the port lives on ssh.socket, not in sshd_config ────────────────────
# Ubuntu 22.10+ ships sshd socket-activated. ssh.socket owns the listening socket and sshd inherits
# it, so Port/ListenAddress in sshd_config are parsed, pass `sshd -t`, and are then IGNORED. The
# panel wrote its port to an sshd_config drop-in, restarted sshd, found the port not listening and
# reverted — safe, and the feature could never work on the current Ubuntu LTS. Measured on 24.04.5:
# ssh.socket enabled+active with ListenStream=0.0.0.0:22, `sshd -T` still saying `port 22` with the
# drop-in in place, and both ports answering as soon as the ports were written to the SOCKET.
_sl = _sm_hosts._socket_listen_lines

check("ssh.socket: the body starts by RESETTING systemd's inherited list",
      _sl(["2222"], "").startswith("[Socket]\nListenStream=\n"),
      repr(_sl(["2222"], ""))[:80])
# Without the bare ListenStream=, systemd APPENDS and the unit's own 0.0.0.0:22 survives — which
# would silently defeat a bind change while looking like it worked.
check("ssh.socket: ...which is what stops a bind change from being a no-op",
      _sl(["2222"], "10.0.0.5").count("ListenStream=\n") == 1)
check("ssh.socket: a port-only change keeps BOTH families, as the shipped unit does",
      "ListenStream=0.0.0.0:2222" in _sl(["2222"], "")
      and "ListenStream=[::]:2222" in _sl(["2222"], ""))
check("ssh.socket: ...and every port, so the old one stays reachable",
      all(("ListenStream=0.0.0.0:%s" % p) in _sl(["2222", "22"], "") for p in ("2222", "22")))
check("ssh.socket: a bind address restricts to that address only",
      _sl(["22"], "10.0.0.5").strip().endswith("ListenStream=10.0.0.5:22")
      and "0.0.0.0" not in _sl(["22"], "10.0.0.5"))
check("ssh.socket: an IPv6 bind address is bracketed",
      "ListenStream=[fd00::1]:22" in _sl(["22"], "fd00::1"), _sl(["22"], "fd00::1"))

# The detector: only a literal "active" with rc 0 counts. Everything else takes the sshd_config
# path, which is what every pre-22.10 host needs — [[empty-is-not-a-measurement]] in the safe
# direction, because guessing "socket" on an ordinary host would break a working feature.
_orig_rp = _sm_core.run_privileged
try:
    _sa = {"v": ("active", "", 0)}
    _sm_core.run_privileged = lambda *a, **k: _sa["v"]
    check("ssh.socket: 'active' + rc 0 is socket-activated", _sm_hosts._sshd_socket_activated(NS()) is True)
    for _desc, _v in (("inactive", ("inactive", "", 3)), ("unit not found", ("", "", 4)),
                      ("rc 0 but not active", ("failed", "", 0)),
                      ("an empty read", ("", "", 0))):
        _sa["v"] = _v
        check("ssh.socket: %s is NOT socket-activated" % _desc,
              _sm_hosts._sshd_socket_activated(NS()) is False, repr(_v))

    def _sa_boom(*a, **k):
        raise OSError("no systemd")
    _sm_core.run_privileged = _sa_boom
    check("ssh.socket: a failed check falls back to the sshd_config path, not an exception",
          _sm_hosts._sshd_socket_activated(NS()) is False)
finally:
    _sm_core.run_privileged = _orig_rp


# Covering the two helpers is not covering the BRANCH that picks between them — the bug was in the
# call site, which wrote to a file the OS ignores. So drive change_ssh_port itself and assert which
# destination it names. [[test-the-caller-not-just-the-helper]]
_orig = (_sm_core.run_privileged, _sm_core.write_root_file, _sm_core._restart_sshd,
         _sm_core.is_local_server, _sm_hosts.remote_ufw_open_port, _sm_hosts.remote_ufw_close_port)
try:
    _cs = {"socket": "active", "writes": [], "verbs": []}

    def _cs_priv(server, verb, args=(), timeout=30, merge_stderr=True, **k):
        _cs["verbs"].append((verb, list(args)))
        if verb == "sshd-socket-active":
            return (_cs["socket"], "", 0 if _cs["socket"] == "active" else 3)
        if verb == "listening-sockets":
            return ("LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", "", 0)
        if verb == "sshd-current-ports":
            return ("Port 22\n", "", 0)
        return ("", "", 0)

    _sm_core.run_privileged = _cs_priv
    _sm_core.write_root_file = lambda server, target, content, timeout=15: (
        _cs["writes"].append((target, content)), ("", "", 0))[1]
    _sm_core._restart_sshd = lambda *a, **k: ("", "", 0)
    _sm_core.is_local_server = lambda s: True
    _sm_hosts.remote_ufw_open_port = lambda *a, **k: (True, "")
    _sm_hosts.remote_ufw_close_port = lambda *a, **k: (True, "")

    _cs["socket"] = "active"
    _ok, _msg = _sm_hosts.change_ssh_port(NS(port=22), 2222)
    _t = [t for t, _c in _cs["writes"]]
    check("ssh.socket: a socket-activated host gets the SOCKET drop-in, not the sshd_config one",
          _ok is True and _t == ["sshd-socket-dropin"], "%r %r" % (_ok, _t))
    _body = _cs["writes"][0][1]
    check("ssh.socket: ...with the reset line and both ports",
          "ListenStream=\n" in _body and "ListenStream=0.0.0.0:2222" in _body
          and "ListenStream=0.0.0.0:22" in _body, repr(_body)[:110])
    check("ssh.socket: ...and systemd is told to re-read the unit",
          any(v == "systemd-daemon-reload" for v, _a in _cs["verbs"]))
    check("ssh.socket: ...and the SOCKET unit is the one restarted",
          ("service-restart", ["ssh.socket"]) in _cs["verbs"],
          repr([a for v, a in _cs["verbs"] if v == "service-restart"]))
    check("ssh.socket: ...and the socket snapshot is the one discarded on success",
          any(v == "sshd-socket-discard" for v, _a in _cs["verbs"]))

    _cs["writes"], _cs["verbs"], _cs["socket"] = [], [], "inactive"
    _ok2, _msg2 = _sm_hosts.change_ssh_port(NS(port=22), 2222)
    _t2 = [t for t, _c in _cs["writes"]]
    check("ssh.socket: a NON socket-activated host still gets the sshd_config drop-in",
          _ok2 is True and _t2 == ["sshd-port-dropin"], "%r %r" % (_ok2, _t2))
    check("ssh.socket: ...with Port lines, and no systemd reload it does not need",
          "Port 2222" in _cs["writes"][0][1]
          and not any(v == "systemd-daemon-reload" for v, _a in _cs["verbs"]))
    check("ssh.socket: ...and ssh.socket is NOT restarted on such a host",
          ("service-restart", ["ssh.socket"]) not in _cs["verbs"])
finally:
    (_sm_core.run_privileged, _sm_core.write_root_file, _sm_core._restart_sshd,
     _sm_core.is_local_server, _sm_hosts.remote_ufw_open_port,
     _sm_hosts.remote_ufw_close_port) = _orig


# ── change_ssh_port must not drop the port the host is LISTENING on ─────────────────────────────
# old_ports is the whole basis of this function's lockout-safety promise, and it came from
# _sshd_current_ports — i.e. `sshd -T`, i.e. sshd_config. On a socket-activated host the panel
# writes its port to the ssh.socket drop-in and sshd_config's Port is parsed and then IGNORED, so
# `sshd -T` still prints `port 22` however many times the port has moved. Moving 2222 -> 2022 read
# old_ports as ["22"] (truthy, so the stored-port fallback never fired), and the rewritten drop-in
# — whose leading bare `ListenStream=` clears everything before it — contained only 2022 and 22.
# Port 2222 stopped listening the moment ssh.socket restarted, while the success message said "The
# previous port is still available as a fallback" about a port that was already gone.
_o_sp = (_sm_core.run_privileged, _sm_core.write_root_file, _sm_core._restart_sshd,
         _sm_core.is_local_server, _sm_hosts.remote_ufw_open_port, _sm_hosts.remote_ufw_close_port)
try:
    _sp = {"socket": "active", "effective": "port 22\n", "writes": []}

    def _sp_priv(server, verb, args=(), timeout=30, merge_stderr=True, **k):
        if verb == "sshd-socket-active":
            return (_sp["socket"], "", 0 if _sp["socket"] == "active" else 3)
        if verb == "sshd-effective-config":
            return (_sp["effective"], "", 0)
        if verb == "listening-sockets":
            return ("LISTEN 0 128 0.0.0.0:2022 0.0.0.0:*\n", "", 0)
        return ("", "", 0)

    _sm_core.run_privileged = _sp_priv
    _sm_core.write_root_file = lambda server, target, content, timeout=15: (
        _sp["writes"].append((target, content)), ("", "", 0))[1]
    _sm_core._restart_sshd = lambda *a, **k: ("", "", 0)
    _sm_core.is_local_server = lambda s: True
    _sm_hosts.remote_ufw_open_port = lambda *a, **k: (True, "")
    _sm_hosts.remote_ufw_close_port = lambda *a, **k: (True, "")

    # Socket-activated, panel connected on 2222, sshd -T stuck on 22, moving to 2022.
    _sp["socket"], _sp["effective"], _sp["writes"] = "active", "port 22\n", []
    _ok_sp, _msg_sp = _sm_hosts.change_ssh_port(NS(port=2222), 2022)
    _sp_body = _sp["writes"][0][1] if _sp["writes"] else ""
    check("ssh port: a socket-activated host keeps the port the panel is CONNECTED on",
          _ok_sp is True and "ListenStream=0.0.0.0:2222\n" in _sp_body,
          "%r — 2222 stops listening the moment ssh.socket restarts, and the success message "
          "calls it a fallback: %r" % (_sp_body, _msg_sp[:80]))
    check("ssh port: ...and still adds the new one",
          "ListenStream=0.0.0.0:2022\n" in _sp_body, repr(_sp_body))
    # POSITIVE CONTROL: the sshd_config path is authoritative there, so a STALE stored port must
    # NOT be unioned in — that would re-open a port the operator had deliberately closed.
    _sp["socket"], _sp["effective"], _sp["writes"] = "inactive", "port 2222\n", []
    _ok_np, _msg_np = _sm_hosts.change_ssh_port(NS(port=22), 2022)
    _np_body = _sp["writes"][0][1] if _sp["writes"] else ""
    check("ssh port: a NON socket-activated host still takes its ports from sshd -T alone",
          _ok_np is True
          and [ln for ln in _np_body.splitlines() if ln.startswith("Port ")] == ["Port 2022",
                                                                                "Port 2222"],
          "%r — a stale stored port would re-open a port that was closed on purpose" % (_np_body,))
finally:
    (_sm_core.run_privileged, _sm_core.write_root_file, _sm_core._restart_sshd,
     _sm_core.is_local_server, _sm_hosts.remote_ufw_open_port,
     _sm_hosts.remote_ufw_close_port) = _o_sp


# ── the panel-login fail2ban jail must actually READ the panel's auth.log ───────────────────────
# Debian and Ubuntu ship /etc/fail2ban/jail.d/defaults-debian.conf with `[DEFAULT] backend = systemd`,
# and that DEFAULT applies to every jail. A jail on the systemd backend reads the JOURNAL and ignores
# `logpath` entirely. The panel's jail set logpath and never set backend, so on the distro the panel
# targets it monitored no file at all while reporting itself Active — measured on Ubuntu 24.04.5:
# `fail2ban-client get linuxgsm-panel logpath` answered "No file is currently monitored", and the
# panel writes its failures to data/auth.log, a file. Zero bans were possible, ever.
check("f2b jail: the body pins a FILE backend, so [DEFAULT] backend = systemd cannot apply",
      "backend = auto" in _so._panel_f2b_jail_body("/x/auth.log", 5000, []),
      _so._panel_f2b_jail_body("/x/auth.log", 5000, [])[:90])
check("f2b jail: ...and it is not the journal backend",
      "backend = systemd" not in _so._panel_f2b_jail_body("/x/auth.log", 5000, []))
check("f2b jail: ...and the logpath is still written",
      "logpath = /x/auth.log" in _so._panel_f2b_jail_body("/x/auth.log", 5000, []))

# ── a ban on the web port does nothing to a client that connects to the PROXY ────────────────
# Behind nginx/Caddy (trust_proxy) or Tailscale Serve, auth.log records the X-Forwarded-For client,
# whose packets go to :443. The jail's default multiport action banned them on the backend port
# only, matched nothing, and the panel still audited and notified the IP as banned.
import panel.core.config as _f2bp_cfg                                              # noqa: E402
_f2bp_saved = (_f2bp_cfg.load_config, _so.panel_fail2ban_status, _so._panel_f2b_jail_port,
               _so._panel_f2b_jail_value, _so._panel_f2b_jail_ignoreip, _so.configure_panel_fail2ban)
try:
    for _f2bp_c, _f2bp_want in (({"trust_proxy": True}, True), ({"tailscale_setup_done": True}, True),
                                ({"bind_host": "127.0.0.1"}, True),
                                ({"bind_host": "0.0.0.0"}, False), ({}, False)):
        _f2bp_cfg.load_config = lambda _c=dict(_f2bp_c): _c
        _f2bp_body = _so._panel_f2b_jail_body("/x/auth.log", 5000, [])
        check("f2b jail: %r bans on %s" % (_f2bp_c, "EVERY port" if _f2bp_want else "the web port"),
              ("banaction = iptables-allports" in _f2bp_body) is _f2bp_want, _f2bp_body[:160])
        # An all-ports ban on a tailnet peer takes its SSH over tailscale0 and every game port:
        # under Serve the forwarded client IS a tailnet address, and five mistyped passwords from an
        # admin's laptop banned it for an hour. The panel never firewall-blocks the tailnet elsewhere.
        _f2bp_ign = next((ln.split("=", 1)[1].split() for ln in _f2bp_body.splitlines()
                          if ln.startswith("ignoreip")), [])
        check("f2b jail: %r %s the tailnet (IPv4 and IPv6) from the ban"
              % (_f2bp_c, "exempts" if _f2bp_want else "(web port only, as before) does not exempt"),
              ({"100.64.0.0/10", "fd7a:115c:a1e0::/48"} <= set(_f2bp_ign)) is _f2bp_want
              and {"127.0.0.1/8", "::1"} <= set(_f2bp_ign), "ignoreip %r" % (_f2bp_ign,))
    # ...and a jail already written for the web port alone is rewritten once the panel is proxied:
    # ensure_panel_fail2ban is the only thing that would ever rewrite it, and it returned early on
    # "port, logpath, backend and whitelist all match". The stored ignoreip is what THIS config
    # writes, so only the banaction differs.
    _f2bp_calls = []
    _so.panel_fail2ban_status = lambda: {"installed": True, "enabled": True}
    _so._panel_f2b_jail_port = lambda: 5000
    _so._panel_f2b_jail_value = lambda k: {"logpath": "/x/auth.log", "backend": "auto"}.get(k)
    _so._panel_f2b_jail_ignoreip = lambda: _so._f2b_ignoreip_line(
        _so._panel_f2b_ignore([], _so._panel_login_proxied())).split()
    _so.configure_panel_fail2ban = lambda *a, **k: (_f2bp_calls.append(a), (True, "ok"))[1]
    _f2bp_cfg.load_config = lambda: {"trust_proxy": True}
    _so.ensure_panel_fail2ban("/x/auth.log", 5000, [])
    check("f2b jail: a web-port-only jail on a proxied panel is rewritten, not left as healthy",
          len(_f2bp_calls) == 1, "rewrites: %r" % (_f2bp_calls,))
    _f2bp_calls.clear()
    _f2bp_cfg.load_config = lambda: {}
    _so.ensure_panel_fail2ban("/x/auth.log", 5000, [])
    check("f2b jail: ...while the same jail on a directly-reached panel is left alone (positive control)",
          not _f2bp_calls, "rewrites: %r" % (_f2bp_calls,))
    # An all-ports jail written before the tailnet was exempted is rewritten, not read as healthy.
    _f2bp_cfg.load_config = lambda: {"tailscale_setup_done": True}
    _so._panel_f2b_jail_value = lambda k: {"logpath": "/x/auth.log", "backend": "auto",
                                           "banaction": "iptables-allports"}.get(k)
    _so._panel_f2b_jail_ignoreip = lambda: _so._f2b_ignoreip_line([]).split()
    _f2bp_calls.clear()
    _so.ensure_panel_fail2ban("/x/auth.log", 5000, [])
    check("f2b jail: an all-ports jail that bans the tailnet is rewritten, not left as healthy",
          len(_f2bp_calls) == 1, "rewrites: %r" % (_f2bp_calls,))
    _so._panel_f2b_jail_ignoreip = lambda: _so._f2b_ignoreip_line(_so._panel_f2b_ignore([], True)).split()
    _f2bp_calls.clear()
    _so.ensure_panel_fail2ban("/x/auth.log", 5000, [])
    check("f2b jail: ...while one that already exempts it is left alone (positive control)",
          not _f2bp_calls, "rewrites: %r" % (_f2bp_calls,))
finally:
    (_f2bp_cfg.load_config, _so.panel_fail2ban_status, _so._panel_f2b_jail_port,
     _so._panel_f2b_jail_value, _so._panel_f2b_jail_ignoreip, _so.configure_panel_fail2ban) = _f2bp_saved

# ensure_panel_fail2ban is the ONLY thing that would ever rewrite the jail, and it returned early
# when the port and whitelist matched — so a jail carrying a logpath from a previous install path
# (`/home/<old-user>/…`, which fail2ban tails forever without complaining) stayed broken for good.
_f2b_orig = (_so.panel_fail2ban_status, _so._panel_f2b_jail_port, _so._panel_f2b_jail_value,
             _so._panel_f2b_jail_ignoreip, _so.configure_panel_fail2ban)
try:
    _jail = {"port": 5000, "logpath": "/home/panel/data/auth.log", "backend": "auto",
             "ignoreip": ["127.0.0.1/8", "::1"], "rewrote": []}
    _so.panel_fail2ban_status = lambda: {"installed": True, "enabled": True, "banned": 0}
    _so._panel_f2b_jail_port = lambda: _jail["port"]
    _so._panel_f2b_jail_value = lambda key: _jail.get(key)
    _so._panel_f2b_jail_ignoreip = lambda: _jail["ignoreip"]
    _so.configure_panel_fail2ban = lambda a, p, i=None: (
        _jail["rewrote"].append((a, p)), (True, "rewritten"))[1]

    _ok, _msg = _so.ensure_panel_fail2ban("/home/panel/data/auth.log", 5000, [])
    check("f2b jail: a jail that already matches is left alone (no needless reload)",
          _ok is True and not _jail["rewrote"] and "already active" in _msg, _msg)

    # THE BUG: the install moved, the jail still names the old path, everything else matches.
    _jail["rewrote"] = []
    _ok, _msg = _so.ensure_panel_fail2ban("/home/newuser/data/auth.log", 5000, [])
    check("f2b jail: a STALE logpath forces a rewrite — it used to report 'already active'",
          _ok is True and _jail["rewrote"] == [("/home/newuser/data/auth.log", 5000)], _msg)

    # A jail written before the backend was pinned: present, enabled, right port and path, and
    # silently on the journal.
    _jail["rewrote"], _jail["backend"] = [], None
    _ok, _msg = _so.ensure_panel_fail2ban("/home/panel/data/auth.log", 5000, [])
    check("f2b jail: a jail with NO backend line is rewritten, not trusted",
          _ok is True and len(_jail["rewrote"]) == 1, _msg)

    _jail["rewrote"], _jail["backend"] = [], "systemd"
    _ok, _msg = _so.ensure_panel_fail2ban("/home/panel/data/auth.log", 5000, [])
    check("f2b jail: ...and so is one explicitly on the journal backend",
          _ok is True and len(_jail["rewrote"]) == 1, _msg)

    # The pre-existing reasons to rewrite must still work.
    _jail["rewrote"], _jail["backend"], _jail["port"] = [], "auto", 5001
    _ok, _msg = _so.ensure_panel_fail2ban("/home/panel/data/auth.log", 5000, [])
    check("f2b jail: a changed PORT still forces a rewrite", len(_jail["rewrote"]) == 1)
    _jail["rewrote"], _jail["port"], _jail["ignoreip"] = [], 5000, ["127.0.0.1/8"]
    _ok, _msg = _so.ensure_panel_fail2ban("/home/panel/data/auth.log", 5000, [])
    check("f2b jail: a changed WHITELIST still forces a rewrite", len(_jail["rewrote"]) == 1)
finally:
    (_so.panel_fail2ban_status, _so._panel_f2b_jail_port, _so._panel_f2b_jail_value,
     _so._panel_f2b_jail_ignoreip, _so.configure_panel_fail2ban) = _f2b_orig
# ── binding sshd to loopback is the one lockout change_ssh_port cannot undo ─────────────────────
# Every other bad bind address fails loudly: sshd cannot bind an address the host does not have,
# so it does not start, the listening check sees that, and the drop-in is reverted. 127.0.0.1 is a
# real address on every host — sshd starts perfectly, the port IS listening, verification passes,
# and remote SSH is gone. Measured on the test host before the guard: ok=True, "SSH now listens on
# port 22 on 127.0.0.1", listeners 127.0.0.1:22, nothing answering on the host's real IP. For the
# panel's OWN host there is not even a reachability test to fall back on — _tcp_reachable only runs
# for a remote.
_lb_orig = (_sm_core.run_privileged, _sm_core.write_root_file, _sm_core._restart_sshd,
            _sm_core.is_local_server, _sm_hosts.remote_ufw_open_port, _sm_hosts.remote_ufw_close_port,
            _so.host_has_ip)
try:
    _lb = {"touched": [], "host_ips": {"10.0.0.5"}}
    # The local-host pre-check asks the REAL machine otherwise, and 10.0.0.5 is not on it.
    _so.host_has_ip = lambda ip: ip in _lb["host_ips"]

    def _lb_priv(server, verb, args=(), timeout=30, merge_stderr=True, **k):
        _lb["touched"].append(verb)
        if verb == "sshd-socket-active":
            return ("inactive", "", 3)
        if verb == "listening-sockets":
            # Both ports, so the verification step is not what most of this block is testing.
            return (_lb.get("listening") or
                    ("LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n"
                     "LISTEN 0 128 10.0.0.5:22 0.0.0.0:*\n"
                     "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\n"), "", 0)
        return ("", "", 0)

    _sm_core.run_privileged = _lb_priv
    _sm_core.write_root_file = lambda *a, **k: (_lb["touched"].append("WRITE"), ("", "", 0))[1]
    _sm_core._restart_sshd = lambda *a, **k: ("", "", 0)
    _sm_core.is_local_server = lambda s: True
    _sm_hosts.remote_ufw_open_port = lambda *a, **k: (_lb["touched"].append("UFW"), (True, ""))[1]
    _sm_hosts.remote_ufw_close_port = lambda *a, **k: (True, "")

    for _addr in ("127.0.0.1", "::1", "127.0.0.53"):
        _lb["touched"] = []
        _ok, _msg = _sm_hosts.change_ssh_port(NS(port=22), 22, bind_addr=_addr)
        check("ssh bind: %s is refused — it would leave sshd reachable only from the host" % _addr,
              _ok is False and "remote SSH would stop working" in _msg, _msg[:80])
        check("ssh bind: ...and refused BEFORE anything is touched (no ufw hole, no write)",
              _lb["touched"] == [], repr(_lb["touched"]))

    # A real address must still go through, or the guard has broken the feature it protects.
    _lb["touched"] = []
    _ok, _msg = _sm_hosts.change_ssh_port(NS(port=22), 22, bind_addr="10.0.0.5")
    check("ssh bind: a non-loopback address still proceeds", _ok is True, _msg[:80])
    check("ssh bind: ...and the file is actually written", "WRITE" in _lb["touched"])
    # ListenAddress is all-or-nothing, so the port-only message's "previous port is still available
    # as a fallback" is FALSE for a bind change — and false exactly when it matters most.
    check("ssh bind: ...and the message does NOT promise a fallback that does not exist",
          "fallback" not in _msg.lower() and "10.0.0.5:22" in _msg, _msg[:110])

    _lb["touched"] = []
    _ok, _msg = _sm_hosts.change_ssh_port(NS(port=22), 2222)
    check("ssh bind: a PORT-only change still says the old port remains a fallback",
          _ok is True and "fallback" in _msg.lower(), _msg[:110])
    # The address the host does NOT have: under socket activation systemd binds it anyway, so the
    # old port-only verification passed while SSH answered nowhere. Refused up front now.
    _lb["touched"] = []
    _ok, _msg = _sm_hosts.change_ssh_port(NS(port=22), 22, bind_addr="192.0.2.99")
    check("ssh bind: an address the host does NOT have is refused, not bound in name",
          _ok is False and "isn't an address on this host" in _msg, _msg[:80])
    check("ssh bind: ...and that too is refused before anything is touched",
          _lb["touched"] == [], repr(_lb["touched"]))

    # The backstop, for an address that IS on the host but where sshd ends up somewhere else: the
    # verification must look for that ADDRESS, not merely something on that port. A port-only match
    # is satisfied by any listener on 22 — which is what let a useless bind read as success.
    _lb["host_ips"] = {"10.0.0.5"}
    _lb["listening"] = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"      # port 22, but NOT on 10.0.0.5
    _lb["touched"] = []
    _ok, _msg = _sm_hosts.change_ssh_port(NS(port=22), 22, bind_addr="10.0.0.5")
    check("ssh bind: a listener on the right PORT but the wrong ADDRESS still reverts",
          _ok is False and "isn't listening on 10.0.0.5:22" in _msg, _msg[:90])
    check("ssh bind: ...and the revert restored the drop-in",
          "sshd-restore-dropin" in _lb["touched"], repr(_lb["touched"]))
finally:
    (_sm_core.run_privileged, _sm_core.write_root_file, _sm_core._restart_sshd,
     _sm_core.is_local_server, _sm_hosts.remote_ufw_open_port,
     _sm_hosts.remote_ufw_close_port, _so.host_has_ip) = _lb_orig


# ── a tailnet address must not be firewall-blocked because the probe failed ─────────────────────
# tailnet_exempt_ips decides which candidate IPs _autoblock_reconcile must NOT deny. A missing
# exemption is not "do nothing": the address gets a UFW deny inserted at POSITION 1, which the note
# above _TAILNET_CGNAT says "would cut off tailnet access ... it would override the tailscale0 allow
# rule". So a probe that did not run has to fall the protective way — the opposite of fail-safe
# everywhere else in that file, where False means "assume no way in exists".
#
# ── a negative sentinel read against an EMPTY answer inverts the result ──────────────────────
# The probes are `cmd && echo 'FOUND' || echo 'NOTFOUND'`, and callers tested the NEGATIVE token.
# `"NOTFOUND" not in ""` is True, so a probe that never ran read as the POSITIVE answer — and
# run_command returns ("", "...timed out", -1) rather than raising for the local and Tailscale
# transports, so an unreachable host is the ordinary way to get "". One of the four sites in the
# tree already had it right and shows the idiom: `"NOTEXISTS" not in idout and "EXISTS" in idout`.
_ns_saved = _sm_core.run_command
try:
    _sm_core.run_command = lambda *a, **k: ("", "ssh: connect to host ... timed out", -1)
    check("sentinel: an unread probe does not report Tailscale as INSTALLED",
          _sm_hosts.remote_check_tailscale(NS(id=8001)).get("installed") is False,
          "a host that never answered was reported as having Tailscale installed")
    _sm_core.run_command = lambda *a, **k: ("/usr/bin/tailscale\nINSTALLED\n", "", 0)
    check("sentinel: ...while a probe that DID answer still reports it",
          _sm_hosts.remote_check_tailscale(NS(id=8002)).get("installed") is True,
          "the control failed — the check above proves nothing")
    _sm_core.run_command = lambda *a, **k: ("NOTINSTALLED\n", "", 0)
    check("sentinel: ...and a clear 'not installed' is still not installed",
          _sm_hosts.remote_check_tailscale(NS(id=8003)).get("installed") is False)
finally:
    _sm_core.run_command = _ns_saved

# ── migrating to Tailscale SSH must not burn the bridge before testing the new one ───────────
# remote_migrate_to_tailscale closes port 22, and its caller then blanks auth_credential — the
# record's ONLY credential — and sets auth_method="tailscale". That all used to happen on the
# strength of BackendState == "Running", which says tailscaled is up and nothing more: not whether
# this node runs Tailscale SSH, and not whether the panel can actually log in that way. With
# RunSSH off, or a tailnet ACL that refuses SSH to this node/user, the panel closed the only door
# and discarded the key, with no way back from the UI.
_mig_saved = (_sm_hosts.remote_check_tailscale, _sm_hosts._tailscale_conn_state,
              _sm_hosts.ssh_test_connection, _sm_hosts.remote_ufw_close_port_22)
try:
    _mig_closed = []
    _sm_hosts.remote_check_tailscale = lambda s: {
        "running": True, "dns_name": "host.tail1234.ts.net", "tailscale_ip": "100.64.0.9"}
    _sm_hosts.remote_ufw_close_port_22 = lambda s: _mig_closed.append(getattr(s, "id", "?"))
    _mig_srv = NS(); _mig_srv.id, _mig_srv.host, _mig_srv.username = 7001, "203.0.113.9", "root"

    # 1. tailscaled up but its SSH server OFF — refuse, and close nothing.
    _sm_hosts._tailscale_conn_state = lambda s: (True, False)
    _sm_hosts.ssh_test_connection = lambda *a, **k: (True, "should not be reached")
    _h, _why = _sm_hosts.remote_migrate_to_tailscale(_mig_srv)
    check("tailscale migrate: refused when the node does not run Tailscale SSH", _h is None,
          "migrated to %r with no SSH server on the far end" % (_h,))
    check("tailscale migrate: ...and port 22 was NOT closed", not _mig_closed,
          "closed the only way in on %s" % (_mig_closed,))
    check("tailscale migrate: ...and says what to do about it",
          "tailscale set --ssh" in (_why or ""), _why)

    # 2. SSH server on, but the login does not actually work (ACL, node offline) — same.
    _mig_closed.clear()
    _sm_hosts._tailscale_conn_state = lambda s: (True, True)
    _sm_hosts.ssh_test_connection = lambda *a, **k: (
        False, "Tailscale SSH denied — check the tailnet ACL allows SSH to this node/user.")
    _h2, _why2 = _sm_hosts.remote_migrate_to_tailscale(_mig_srv)
    check("tailscale migrate: refused when Tailscale SSH cannot actually log in", _h2 is None)
    check("tailscale migrate: ...and again port 22 stayed open", not _mig_closed,
          "closed on %s" % (_mig_closed,))
    check("tailscale migrate: ...and passes the real reason back", "ACL" in (_why2 or ""), _why2)

    # 3. The control: verified both ways, so the migration proceeds and closes the port.
    _mig_closed.clear()
    _sm_hosts.ssh_test_connection = lambda *a, **k: (True, "Tailscale SSH connection successful")
    _h3, _ = _sm_hosts.remote_migrate_to_tailscale(_mig_srv)
    check("tailscale migrate: a verified tailnet path DOES migrate",
          _h3 == "host.tail1234.ts.net", "got %r" % (_h3,))
    check("tailscale migrate: ...and only then closes port 22", _mig_closed == [7001],
          "closed %s" % (_mig_closed,))
finally:
    (_sm_hosts.remote_check_tailscale, _sm_hosts._tailscale_conn_state,
     _sm_hosts.ssh_test_connection, _sm_hosts.remote_ufw_close_port_22) = _mig_saved

# It used to call _tailscale_conn_state()[0], which collapses "Tailscale is not running" and "the
# probe did not run" into the same False, and whose command (`… || echo '{}'`) always exits 0 so the
# rc could not tell them apart. Note _autoblock_reconcile already guards its OTHER input this way
# ("A failed read answers None. Releasing on it would unblock every IP…") — this input did not.
_tn_orig = _sm_core.run_command
try:
    _tn = {"resp": ("", "", 0)}
    _sm_core.run_command = lambda s, c, **k: _tn["resp"]
    _CAND = {"100.101.102.103", "100.64.0.9"}
    _MIXED = _CAND | {"203.0.113.5", "10.0.0.7"}

    # Tailscale up: every CGNAT address is exempt, public ones are not.
    _tn["resp"] = ('{"BackendState": "Running"}', "", 0)
    eq("tailnet exempt: with Tailscale up, only the CGNAT addresses are exempt",
       _sm_hosts.tailnet_exempt_ips(NS(), _MIXED), _CAND)

    # Tailscale genuinely stopped, or not installed: the host ANSWERED, so blocking is allowed.
    for _desc, _r in (("a stopped backend", ('{"BackendState": "Stopped"}', "", 1)),
                      ("tailscale not installed", ("", "command not found", 127))):
        _tn["resp"] = _r
        eq("tailnet exempt: %s exempts nothing — the host answered" % _desc,
           _sm_hosts.tailnet_exempt_ips(NS(), _MIXED), set())

    # THE BUG: the probe did not run. rc -1 is the panel's sentinel for that.
    for _desc, _r in (("a timed-out probe", ("", "Command timed out", -1)),
                      ("a transport error", ("", "command execution error", -1))):
        _tn["resp"] = _r
        eq("tailnet exempt: %s protects the tailnet addresses" % _desc,
           _sm_hosts.tailnet_exempt_ips(NS(), _MIXED), _CAND)

    # An answer we cannot parse is also not a confirmation.
    _tn["resp"] = ("<html>proxy error</html>", "", 0)
    eq("tailnet exempt: an unparseable answer protects them too",
       _sm_hosts.tailnet_exempt_ips(NS(), _MIXED), _CAND)

    # ...and the probe is skipped entirely when nothing is in range (it is not free).
    _tn_calls = []
    _sm_core.run_command = lambda s, c, **k: (_tn_calls.append(c), ("", "", 0))[1]
    eq("tailnet exempt: no CGNAT candidates → no probe at all",
       _sm_hosts.tailnet_exempt_ips(NS(), {"203.0.113.5"}), set())
    check("tailnet exempt: ...and it really did not run the probe", _tn_calls == [], repr(_tn_calls))

    def _tn_boom(*a, **k):
        raise OSError("ssh down")
    _sm_core.run_command = _tn_boom
    eq("tailnet exempt: an exception protects them as well",
       _sm_hosts.tailnet_exempt_ips(NS(), _MIXED), _CAND)
finally:
    _sm_core.run_command = _tn_orig


# ── the game-port firewall write is a MANAGE_REMOTES action, like every other one ────────────────
# api_remote_game_port_open accepted MANAGE_REMOTES *or* INSTALL_SERVER, while every other firewall
# write on the same host (/firewall/open, /allow-from, /limit, /close, /delete-rule) requires
# MANAGE_REMOTES alone. `port` is entirely caller-chosen, and the GameServer lookup was cosmetic —
# it only picked the UFW comment and fell back to "Game" when no row matched. So a user with a host
# grant and only INSTALL_SERVER could open 22, 3306 or 6379 to the internet on a host whose
# firewall they otherwise have no rights over. Nothing in templates/ or static/js/ calls it.
_rv_src = open(os.path.join(_root, "panel", "routes", "remote_vps.py"), encoding="utf-8").read()
_gp_at = _rv_src.find('"/api/remote/<int:remote_id>/game-port/<int:port>/open"')
check("game-port: the route exists to be checked", _gp_at > 0)
_gp_block = _rv_src[_gp_at:_gp_at + 1800]
check("game-port: requires MANAGE_REMOTES",
      "@permission_required(MANAGE_REMOTES)" in _gp_block, _gp_block[:160])
check("game-port: ...and no longer accepts INSTALL_SERVER as an alternative",
      "permission_required(MANAGE_REMOTES, INSTALL_SERVER)" not in _gp_block)
check("game-port: ...and refuses a port no game server on the host uses",
      "if gs is None:" in _gp_block and "refusing to" in _gp_block, _gp_block[-220:])

# Every OTHER firewall write on that host must stay MANAGE_REMOTES-only, so this check keeps
# meaning if a new one is added.
for _route in ("/firewall/open", "/firewall/allow-from", "/firewall/limit"):
    _at = _rv_src.find('"/api/remote/<int:remote_id>%s"' % _route)
    check("game-port: sibling %s is MANAGE_REMOTES-only" % _route,
          _at > 0 and "@permission_required(MANAGE_REMOTES)" in _rv_src[_at:_at + 260],
          _rv_src[_at:_at + 160] if _at > 0 else "route not found")

# ── the bootstrap must not reboot a host on a probe that never answered ──────────────────────
# Step 11 reboots when an update needs one and no game servers are running. It read that second
# fact as `"YES" in (gs_out or "")` — and run_command returns ("", "...timed out", -1) rather
# than raising, so a dropped connection (right after a full-upgrade, which is when one is most
# likely) read as "no game servers are running" and the host was rebooted out from under whoever
# was playing. Unknown must count as RUNNING here: being wrong that way costs a reboot done by
# hand, the other way costs every player on the box.
_bs_saved = (_sm_core.run_command, _sm_core.run_privileged, _sm_core.write_root_file,
             _sm_core.create_game_user, _sm_core.is_local_server, _sm_core.close_connection,
             _sm_hosts._wait_for_reboot, _sm_core._wait_for_dpkg_lock)
try:
    _bs_priv = []
    _sm_core.is_local_server = lambda s: False
    # Stubbed, or step 1 polls `dpkg-lock-held` once a second for 180s per call: run_privileged
    # returning rc=0 means the lock IS held, and a blanket success stub says that forever. Five
    # calls to the bootstrap = fifteen minutes of a suite that looked hung.
    _sm_core._wait_for_dpkg_lock = lambda *a, **k: True
    _sm_core.run_privileged = lambda s, verb, args=None, **k: (_bs_priv.append(verb), ("", "", 0))[1]
    _sm_core.write_root_file = lambda *a, **k: ("", "", 0)
    _sm_core.create_game_user = lambda *a, **k: ("", "", 0)
    _sm_core.close_connection = lambda *a, **k: None
    _sm_hosts._wait_for_reboot = lambda *a, **k: True

    def _bs_run(gs_answer):
        """Every step succeeds; reboot-required says YES; the game-server probe answers as given."""
        def _run(server, cmd, **k):
            if "reboot-required" in cmd:
                return ("YES\n", "", 0)
            if "pgrep -x tmux" in cmd:
                return gs_answer
            return ("", "", 0)
        return _run

    def _bs_go(gs_answer):
        _bs_priv.clear()
        _sm_core.run_command = _bs_run(gs_answer)
        ok, msg, log = _sm_hosts.remote_bootstrap_vps(
            NS(id=9100, host="203.0.113.9", auth_method="key"), set_timezone="", enable_ufw=False,
            install_lgsm_deps=False, username="", install_fail2ban=False, do_reboot=True)
        # log is already a STRING. "\n".join(a_string) interleaves a newline between every
        # CHARACTER, which broke up the substring these checks look for and reported the fix as
        # missing while the real log said exactly the right thing.
        return "reboot-delayed" in _bs_priv, log

    _rebooted, _log = _bs_go(("", "ssh: connect to host ... timed out", -1))
    check("bootstrap: a game-server probe that never answered does not authorise a reboot",
          not _rebooted,
          "the host was rebooted on a probe that timed out — every player on it was dropped")
    check("bootstrap: ...and the log says the check could not be read",
          "did not answer the check for running game servers" in _log,
          "it is skipped silently, so nobody knows to reboot it later: %s" % _log[-300:])

    _rebooted, _ = _bs_go(("YES\n", "", 0))
    check("bootstrap: ...a host with a live tmux session is not rebooted either",
          not _rebooted, "a running game server did not stop the reboot")

    _rebooted, _ = _bs_go(("NO\n", "", 0))
    check("bootstrap: ...while an EMPTY host that needs one still reboots (positive control)",
          _rebooted,
          "nothing reboots any more, so the checks above would pass with the feature removed")

    # The other probe, same shape: an unread reboot-required check must not be announced as
    # "no reboot needed" — that is the line that stops anyone looking again.
    def _rb_unread(server, cmd, **k):
        if "reboot-required" in cmd:
            return ("", "ssh: connect to host ... timed out", -1)
        return ("NO\n", "", 0)
    _sm_core.run_command = _rb_unread
    _bs_priv.clear()
    _, _, _log2 = _sm_hosts.remote_bootstrap_vps(
        NS(id=9101, host="203.0.113.10", auth_method="key"), set_timezone="", enable_ufw=False,
        install_lgsm_deps=False, username="", install_fail2ban=False, do_reboot=True)
    check("bootstrap: an unread reboot-required check is not reported as 'no reboot needed'",
          "No reboot needed" not in _log2 and "Could not check whether a reboot is needed" in _log2,
          "a host that never answered was told it was up to date: %s" % _log2[-300:])

    # ── ...and the SSH hardening is read back from sshd, not assumed from the write ──
    # sshd keeps the FIRST value it reads and Ubuntu Includes sshd_config.d before sshd_config's
    # own body, so on a cloud image whose 50-cloud-init.conf says `PasswordAuthentication yes` the
    # edit changed nothing. The tuple was discarded and the job said "VPS bootstrap complete"
    # about a host still taking password logins from the internet.
    def _bs_harden(effective, rc=0, auth="key"):
        _bs_priv.clear()
        _sm_core.run_command = _bs_run(("NO\n", "", 0))

        def _priv(s, verb, args=None, **k):
            _bs_priv.append(verb)
            if verb == "sshd-effective-config":
                return (effective, "", rc)
            return ("", "", 0)
        _sm_core.run_privileged = _priv
        return _sm_hosts.remote_bootstrap_vps(
            NS(id=9102, host="203.0.113.11", auth_method=auth), set_timezone="", enable_ufw=False,
            install_lgsm_deps=False, username="", install_fail2ban=False, do_reboot=False)
    _eff_ok = ("port 22\nclientaliveinterval 300\nclientalivecountmax 2\n"
               "permitrootlogin without-password\npasswordauthentication no\n")
    _eff_cloud = _eff_ok.replace("passwordauthentication no", "passwordauthentication yes")
    _hok, _hmsg, _hlog = _bs_harden(_eff_cloud)
    check("bootstrap: hardening that sshd does not use is NOT reported as a complete bootstrap",
          _hok is False and "PasswordAuthentication yes" in _hmsg,
          "ok=%r msg=%r — password SSH still open and the job says it is done" % (_hok, _hmsg))
    check("bootstrap: ...and the log says password login is still on",
          "Password SSH login is still ENABLED" in _hlog and "NOT IN EFFECT" in _hlog,
          _hlog[-400:])
    check("bootstrap: ...having asked sshd for its effective configuration",
          "sshd-effective-config" in _bs_priv, "verbs run: %r" % (_bs_priv[-8:],))
    _hok, _hmsg, _hlog = _bs_harden(_eff_ok)
    check("bootstrap: ...while hardening sshd DOES use completes (positive control; "
          "without-password is prohibit-password)",
          _hok is True and _hmsg.startswith("VPS bootstrap complete (") and "NOT IN EFFECT" not in _hlog,
          "ok=%r msg=%r log=%r" % (_hok, _hmsg, _hlog[-300:]))
    _hok, _hmsg, _ = _bs_harden("", rc=1)
    check("bootstrap: an unreadable sshd -T is reported as unverified, not as hardened",
          _hok is True and "could not be verified" in _hmsg, "msg=%r" % (_hmsg,))
    _hok, _hmsg, _ = _bs_harden(_eff_cloud, auth="password")
    check("bootstrap: ...and a password-auth remote, which never asks for it off, is not failed "
          "for keeping it", _hok is True, "msg=%r" % (_hmsg,))
    # ...but "not the value the panel wrote" is not "not hardened". A host with `PermitRootLogin no`
    # in sshd_config.d — STRICTER than the prohibit-password the panel sets — was failed with "the
    # SSH hardening did not take effect" and never marked online.
    for _prl in ("no", "forced-commands-only"):
        _hok, _hmsg, _hlog = _bs_harden(_eff_ok.replace("permitrootlogin without-password",
                                                        "permitrootlogin " + _prl))
        check("bootstrap: PermitRootLogin %s, stricter than asked, is hardened, not a failure" % _prl,
              _hok is True and "NOT IN EFFECT" not in _hlog, "ok=%r msg=%r" % (_hok, _hmsg))
    _hok, _hmsg, _ = _bs_harden(_eff_ok.replace("permitrootlogin without-password", "permitrootlogin yes"))
    check("bootstrap: ...while PermitRootLogin yes still fails it (positive control)",
          _hok is False and "PermitRootLogin yes" in _hmsg, "ok=%r msg=%r" % (_hok, _hmsg))

    # The UFW step's `ufw limit 22/tcp` is appended AFTER an existing `ufw allow OpenSSH` or bare
    # `allow 22` — neither is the 22/tcp rule to ufw — so SSH stayed unthrottled on exactly the
    # hosts that had opened it the usual Ubuntu way. They go, and only after the limit is in.
    _bs_ufw = []

    def _priv_ufw(s, verb, args=None, **k):
        _bs_ufw.append((verb, list(args or [])))
        return ("", "", 0)
    _sm_core.run_privileged = _priv_ufw
    _sm_core.run_command = _bs_run(("NO\n", "", 0))
    _sm_hosts.remote_bootstrap_vps(
        NS(id=9103, host="203.0.113.12", auth_method="key"), set_timezone="", enable_ufw=True,
        install_lgsm_deps=False, username="", install_fail2ban=False, do_reboot=False)
    _i_lim = _bs_ufw.index(("ufw-limit-port", ["22/tcp"])) if ("ufw-limit-port", ["22/tcp"]) in _bs_ufw else -1
    _i_app = _bs_ufw.index(("ufw-delete-allow-app", ["OpenSSH"])) if ("ufw-delete-allow-app", ["OpenSSH"]) in _bs_ufw else -1
    _i_bare = _bs_ufw.index(("ufw-delete-allow-port", ["22"])) if ("ufw-delete-allow-port", ["22"]) in _bs_ufw else -1
    check("bootstrap: the SSH limit is not left behind an OpenSSH / bare-22 allow",
          _i_lim >= 0 and _i_app > _i_lim and _i_bare > _i_lim,
          "limit at %d, delete OpenSSH at %d, delete bare 22 at %d" % (_i_lim, _i_app, _i_bare))
    check("bootstrap: ...and with the limit in, UFW is switched on (positive control for below)",
          ("ufw-enable", []) in _bs_ufw, "ran %r" % (_bs_ufw,))
    # ...but only once the limit IS in. Its exit code was never read: when `ufw limit 22/tcp`
    # failed, the rules that DO let SSH in were deleted anyway and UFW was switched on at
    # deny-incoming — a fresh host cut off from SSH mid-bootstrap, reported as complete.
    _bs_ufw.clear()

    def _priv_ufw_nolimit(s, verb, args=None, **k):
        _bs_ufw.append((verb, list(args or [])))
        return ("", "ERROR: Could not acquire lock", 1) if verb == "ufw-limit-port" else ("", "", 0)
    _sm_core.run_privileged = _priv_ufw_nolimit
    _bnok, _bnmsg, _bnlog = _sm_hosts.remote_bootstrap_vps(
        NS(id=9104, host="203.0.113.13", auth_method="key"), set_timezone="", enable_ufw=True,
        install_lgsm_deps=False, username="", install_fail2ban=False, do_reboot=False)
    _bn_ran = [v for v, _a in _bs_ufw]
    check("bootstrap: a failed SSH limit removes no SSH allow and does not switch UFW on",
          "ufw-limit-port" in _bn_ran and not {"ufw-delete-allow-app", "ufw-delete-allow-port",
                                               "ufw-default", "ufw-enable"} & set(_bn_ran),
          "ran %r" % (_bs_ufw,))
    check("bootstrap: ...and the job says the firewall was not enabled, not 'complete'",
          _bnok is False and "NOT enabled" in _bnmsg and "Could not acquire lock" in _bnmsg
          and "NOT DONE" in _bnlog, "ok=%r msg=%r" % (_bnok, _bnmsg))
finally:
    (_sm_core.run_command, _sm_core.run_privileged, _sm_core.write_root_file,
     _sm_core.create_game_user, _sm_core.is_local_server, _sm_core.close_connection,
     _sm_hosts._wait_for_reboot, _sm_core._wait_for_dpkg_lock) = _bs_saved

# ── a live-metrics read that produced nothing is not a host sitting at 0% ────────────────────
# run_command returns ("", "...timed out", -1) and does not raise, so every number the metrics
# dict derives came out 0: cpu 0%, 0 cores, RAM 0 of 0, disk 0. The route published that and the
# card rendered an idle, healthy-looking machine — for a host that never answered. remote_uptime
# beside it already carries a read_ok flag for exactly this; this one had no way to say it.
_lm_saved = _sm_core.run_command
try:
    _sm_core.run_command = lambda *a, **k: ("", "ssh: connect to host ... timed out", -1)
    _lm_dead = _sm_core.remote_live_metrics(NS(id=9300, host="203.0.113.30"))
    check("live metrics: a read that produced nothing is not reported as a reading",
          _lm_dead.get("read_ok") is False,
          "read_ok=%r with cpu_overall=%r ram_total=%r — an unreachable host renders as idle"
          % (_lm_dead.get("read_ok"), _lm_dead.get("cpu_overall"), _lm_dead.get("ram_total")))

    _lm_good = ("===A\ncpu  100 0 100 800 0 0 0\ncpu0 50 0 50 400 0 0 0\n"
                "===B\ncpu  110 0 110 880 0 0 0\ncpu0 55 0 55 440 0 0 0\n"
                "===MEM\nMemTotal: 2048000 kB\nMemAvailable: 1024000 kB\n"
                "SwapTotal: 0 kB\nSwapFree: 0 kB\n"
                "===DISK\nFilesystem 1B-blocks Used Available Use% Mounted\n"
                "/dev/vda1 10000000 4000000 6000000 40% /\n")
    _sm_core.run_command = lambda *a, **k: (_lm_good, "", 0)
    _lm_ok = _sm_core.remote_live_metrics(NS(id=9301, host="203.0.113.31"))
    check("live metrics: ...while a host that DID answer is (positive control)",
          _lm_ok.get("read_ok") is True and _lm_ok.get("ram_total") == 2048000 * 1024,
          "read_ok=%r ram_total=%r — the control failed, so the check above proves nothing"
          % (_lm_ok.get("read_ok"), _lm_ok.get("ram_total")))
    check("live metrics: ...and it still reports the figures it read",
          _lm_ok.get("core_count") == 1 and _lm_ok.get("disk_total") == 10000000,
          "cores=%r disk_total=%r" % (_lm_ok.get("core_count"), _lm_ok.get("disk_total")))

    # A host that answers but whose memory line is missing is not a reading either: every RAM
    # figure would be 0 and the percentage with it.
    _sm_core.run_command = lambda *a, **k: ("===A\ncpu 1 0 1 8 0 0 0\n===B\ncpu 2 0 2 9 0 0 0\n", "", 0)
    check("live metrics: ...and a reply with no MemTotal is not one either",
          _sm_core.remote_live_metrics(NS(id=9302, host="203.0.113.32")).get("read_ok") is False,
          "RAM 0 of 0 was published as a reading")
finally:
    _sm_core.run_command = _lm_saved

# The panel's OWN host goes through the same helper, which delegates to system_ops.live_metrics.
# A dict without the flag reads as unreadable the moment anyone checks it — which is what the
# route now does on every poll.
check("live metrics: the panel host's own reading carries the flag too",
      _so.live_metrics().get("read_ok") is True,
      "the local delegate has no read_ok, so the panel's own live card would report unreachable")

# ── a folder the panel could not read is not an empty folder ─────────────────────────────────
# `find ... 2>/dev/null` prints nothing for an empty directory AND for a read that never ran, and
# run_command returns ("", "...timed out", -1) on the tailscale and local transports rather than
# raising. So the file browser announced "(empty folder)" about a directory full of somebody's
# game files. rc is the only thing that separates the two.
_fb_saved = _sm_core.run_command
try:
    _sm_core.run_command = lambda *a, **k: ("", "SSH command timed out", -1)
    _fb = _sm_files.browse_dir(NS(id=9400, host="203.0.113.40"), "csgoserver", "cfg")
    check("file browser: a listing that failed is not reported as an empty folder",
          isinstance(_fb, dict) and _fb.get("unreadable") is True and _fb.get("entries") == [],
          "returned %r — the browser renders '(empty folder)' for a directory it never read"
          % (_fb,))
    check("file browser: ...and not as a path-traversal attempt either",
          _fb is not None,
          "None means 'Invalid path' to the route, which is a second wrong statement")

    _sm_core.run_command = lambda *a, **k: ("", "", 0)
    _fb_empty = _sm_files.browse_dir(NS(id=9401, host="203.0.113.41"), "csgoserver", "cfg")
    check("file browser: ...while a directory that really IS empty still says so",
          isinstance(_fb_empty, dict) and not _fb_empty.get("unreadable")
          and _fb_empty.get("entries") == [],
          "returned %r — an empty folder is now reported as unreadable" % (_fb_empty,))

    _sm_core.run_command = lambda *a, **k: ("f\t120\tserver.cfg\nd\t0\tlogs\n", "", 0)
    _fb_full = _sm_files.browse_dir(NS(id=9402, host="203.0.113.42"), "csgoserver", "cfg")
    check("file browser: ...and a directory with files still lists them (positive control)",
          len((_fb_full or {}).get("entries") or []) == 2,
          "listing stopped working: %r" % (_fb_full,))

    # The upload existence check: same silence, same fix. A failed probe read as "nothing there"
    # and the upload replaced a file the caller had asked not to overwrite.
    _sm_core.run_command = lambda *a, **k: ("", "SSH command timed out", -1)
    _up_ok, _up_msg = _sm_files.upload_file(NS(id=9403, host="203.0.113.43"), "csgoserver",
                                            "cfg", "server.cfg", b"x", overwrite=False)
    # "already exists" would match BOTH this message and UPLOAD_EXISTS, so it does not
    # discriminate — assert the sentence that only the unread-probe branch produces.
    check("upload: a failed existence check does not become 'no file there'",
          _up_ok is False and "couldn't check" in _up_msg.lower(),
          "ok=%r msg=%r — the upload went ahead and overwrote a file nobody agreed to replace"
          % (_up_ok, _up_msg))
finally:
    _sm_core.run_command = _fb_saved

# ── two more bootstrap probes that answered from a read that never happened ──────────────────
# Same shape as the reboot probe beside them: run_command returns ("", "...timed out", -1) and
# does not raise, so the answer a failed read produces is whatever `""` happens to satisfy.
_sw_saved = (_sm_core.run_command, _sm_core.run_privileged, _sm_core.write_root_file,
             _sm_core.create_game_user, _sm_core.is_local_server, _sm_core.close_connection,
             _sm_hosts._wait_for_reboot, _sm_core._wait_for_dpkg_lock)
try:
    _sw_priv = []
    _sm_core.is_local_server = lambda s: False
    _sm_core.run_privileged = lambda s, verb, args=None, **k: (_sw_priv.append(verb), ("", "", 0))[1]
    _sm_core.write_root_file = lambda *a, **k: ("", "", 0)
    _sm_core.create_game_user = lambda *a, **k: ("", "", 0)
    _sm_core.close_connection = lambda *a, **k: None
    _sm_core._wait_for_dpkg_lock = lambda *a, **k: True
    _sm_hosts._wait_for_reboot = lambda *a, **k: True

    def _sw_go(swap_answer):
        _sw_priv.clear()

        def _run(server, cmd, **k):
            if "swapon" in cmd:
                return swap_answer
            if "reboot-required" in cmd:
                return ("NO\n", "", 0)
            return ("", "", 0)
        _sm_core.run_command = _run
        _ok, _msg, _log = _sm_hosts.remote_bootstrap_vps(
            NS(id=9200, host="203.0.113.20", auth_method="key"), set_timezone="", enable_ufw=False,
            install_lgsm_deps=False, username="", install_fail2ban=False, do_reboot=False)
        return "create-swapfile" in _sw_priv, _log

    _made, _log = _sw_go(("", "ssh: connect to host ... timed out", -1))
    check("bootstrap: a swap probe that never answered is not reported as 'swap already present'",
          "Swap already present" not in _log,
          "a host that never answered was recorded as having swap, and never got any")
    check("bootstrap: ...it says the check could not be read instead",
          "Could not check for swap" in _log, _log[-200:])
    check("bootstrap: ...and does not blind-create a 2G file on a disk it could not read",
          not _made, "swap was created on an unknown host")
    _made, _log = _sw_go(("0\n", "", 0))
    check("bootstrap: ...while a host that really has none gets one (positive control)",
          _made and "2G swap file created" in _log,
          "swap creation stopped working, so the checks above would pass with the step removed")
    _made, _log = _sw_go(("2\n", "", 0))
    check("bootstrap: ...and a host that already has some is left alone",
          not _made and "Swap already present" in _log, _log[-200:])
finally:
    (_sm_core.run_command, _sm_core.run_privileged, _sm_core.write_root_file,
     _sm_core.create_game_user, _sm_core.is_local_server, _sm_core.close_connection,
     _sm_hosts._wait_for_reboot, _sm_core._wait_for_dpkg_lock) = _sw_saved

# ── and the tailscale bring-up must not skip the tailscale0 allow on an unread firewall ──────
# _ufw_is_active("") is False, so an unread `ufw status` skipped `ufw allow in on tailscale0` —
# on a host whose firewall may well be active, right after moving its access onto the tailnet.
# The rule is a no-op while UFW is off, so an unknown answer must add it.
_ts_saved = (_sm_core.run_command, _sm_core.run_privileged, _sm_hosts.remote_check_tailscale)
try:
    _ts_priv = []
    _sm_hosts.remote_check_tailscale = lambda s: {"running": True, "tailscale_ip": "100.64.0.5",
                                                  "dns_name": "h.tail.ts.net", "installed": True}
    _sm_core.run_command = lambda *a, **k: ("", "", 0)

    def _ts_go(ufw_answer):
        _ts_priv.clear()

        def _priv(server, verb, args=None, **k):
            _ts_priv.append((verb, tuple(args or ())))
            if verb == "ufw-status":
                return ufw_answer
            return ("", "", 0)
        _sm_core.run_privileged = _priv
        _sm_hosts.remote_bootstrap_tailscale(NS(id=9201, host="203.0.113.21",
                                                 auth_method="key"), auth_key="tskey-probe")
        return any(v == "ufw-allow-iface" and a[:1] == ("tailscale0",) for v, a in _ts_priv)

    check("tailscale: an unread ufw status still allows tailscale0",
          _ts_go(("", "ssh: connect to host ... timed out", -1)),
          "the allow was skipped on a firewall nobody could read — if it is active, the tailnet "
          "the panel just moved onto is blocked")
    check("tailscale: ...and an ACTIVE firewall still gets it (positive control)",
          _ts_go(("Status: active\n", "", 0)),
          "the allow stopped happening at all, so the check above proves nothing")
    check("tailscale: ...while a firewall that is genuinely off is left alone",
          not _ts_go(("Status: inactive\n", "", 0)),
          "a rule was added to a firewall that reported itself off")
finally:
    (_sm_core.run_command, _sm_core.run_privileged, _sm_hosts.remote_check_tailscale) = _ts_saved

# ── a gamedig query that FAILED is not a server with nobody on it ────────────────────────────
# gamedig writes its failure as JSON on stdout ({"error":"Failed all 1 attempts"}), so `.players`
# is null — and jq reports the length of null as 0. `jq -r '.players|length'` therefore turned
# every failed query into a confident "0 players". That is the one answer player_count must never
# invent: mod_restart_decision, _host_idle_state and the reboot-when-empty poller all read 0 as
# "nobody is on, it is safe to act", so a stopped, firewalled or GSLT-less server authorised the
# same actions an empty one does. player_slots has guarded this from the start with the same
# `ok:(.players|type=="array")` test; player_count never got it.
_pcs = _sm_cron.player_count
_pc_saved = _sm_core.run_command
try:
    _sm_core.run_command = lambda *a, **k: ('{"c":0,"ok":false}', "", 0)
    check("player count: a FAILED gamedig query is unknown, not zero",
          _sm_cron.player_count(NS(id=9500), "csgoserver", "csgo", 27015, "csgo") is None,
          "a query that failed was reported as a confirmed-empty server, which is what "
          "restart-when-empty and the reboot poller act on")
    _sm_core.run_command = lambda *a, **k: ('{"c":0,"ok":true}', "", 0)
    check("player count: ...while a server that ANSWERED zero really is empty",
          _sm_cron.player_count(NS(id=9501), "csgoserver", "csgo", 27015, "csgo") == 0,
          "a genuinely empty server now reads as unknown, which blocks the empty-only actions")
    _sm_core.run_command = lambda *a, **k: ('{"c":7,"ok":true}', "", 0)
    check("player count: ...and a populated one reports its count (positive control)",
          _sm_cron.player_count(NS(id=9502), "csgoserver", "csgo", 27015, "csgo") == 7,
          "counting stopped working, so the checks above would pass with the feature removed")
    _sm_core.run_command = lambda *a, **k: ("", "ssh: connect to host ... timed out", -1)
    check("player count: ...and an unread probe is unknown too",
          _sm_cron.player_count(NS(id=9503), "csgoserver", "csgo", 27015, "csgo") is None,
          "an empty answer from a dropped connection was parsed as a reading")
    # The filter the host actually runs has to carry the ok flag, or the guard above is decided
    # by a field nothing computes.
    _pc_cmds = []
    _sm_core.run_command = lambda s, c, **k: (_pc_cmds.append(c), ('{"c":0,"ok":true}', "", 0))[1]
    _sm_cron.player_count(NS(id=9504), "csgoserver", "csgo", 27015, "csgo")
    check("player count: ...and the jq filter it sends asks whether players is an ARRAY",
          _pc_cmds and 'type==' in _pc_cmds[-1] and "players" in _pc_cmds[-1],
          "the command sent was %r" % (_pc_cmds[-1:] or None,))
finally:
    _sm_core.run_command = _pc_saved
