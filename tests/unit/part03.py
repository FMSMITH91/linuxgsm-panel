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
_orig_popen = _so.subprocess.Popen
_orig_rp_verb, _orig_rp_sys = _so._run_verb, _so._is_system_service
_cap = {}
try:
    _so._run_verb = lambda v, a=(), **k: (_cap.update(verb=v, verb_args=list(a)), ("", "", 0))[1]
    _so._is_system_service = lambda: False        # the per-user branch these checks describe
    _so.subprocess.Popen = lambda a, **k: (_cap.update(args=a), type("P", (), {})())[1]
    _ok, _ = _so.restart_panel()
    check("restart_panel: dispatches successfully", _ok is True)
    check("restart_panel: targets the panel service via systemd-run restart",
          "systemd-run" in _cap["args"] and "restart" in _cap["args"]
          and "linuxgsm-panel.service" in _cap["args"])
    check("restart_panel: delays so the HTTP response can flush",
          any(str(x).startswith("--on-active=") for x in _cap["args"]))
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
    _so.subprocess.Popen = _orig_popen
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
_sm_core.set_daily_restart(None, "noqueryserver", game_type="noquerygame", port=28960, enabled=True)
check("daily_restart(unmapped game): skips gamedig, no player query",
      "gamedig" not in _cron["add"][1] and "P=; " in _cron["add"][1])
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

    def _fake_ss(remote, cmd, **k):
        _scan_n["n"] += 1
        return ("127.0.0.1:22\n*:27015\n[::]:27016", "", 0)

    _sm_core.run_command = _fake_ss
    _sm_portscan._port_scan_cache.clear()
    _rem = NS(id=99)
    _p1 = _app._remote_listening_ports(_rem)
    _app._remote_listening_ports(_rem)   # within TTL → cache hit, no 2nd ssh
    check("portscan: parses listening ports", 27015 in _p1 and 22 in _p1 and 27016 in _p1)
    check("portscan: second concurrent poll served from cache (one ssh)", _scan_n["n"] == 1)
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
    _so.panel_update_status = lambda force=False: {"behind": 1, "ci_state": "passing"}
    _ok, _m = _so.panel_self_update()
    check("self-update: a CI-passing commit is NOT blocked by the gate",
          _ok is False and "install.sh is missing" in _m)
finally:
    _so._is_git_checkout = _orig_isgit
    _so.panel_update_status = _orig_pus
    _so.os.path.isfile = _orig_isfile

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
        serve_config={"services": [{"url": "https://host.example.ts.net", "routes": [{}]}], "raw": "x"})
    _tsi._cache["info"] = None
    _bys = _tsi.suggest_best_bind(5000)
    check("tailscale: up + DNS name + Serve configured -> binds loopback for Serve",
          _bys["bind_host"] == "127.0.0.1" and _bys["method"] == "tailscale-serve")
finally:
    _tsi.get_tailscale_info = _orig_gti
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
finally:
    _sm_hosts._core.run_command = _o_rc_h
    _sm_hosts._OS_SLUG_CACHE.clear()

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
finally:
    _sm_core.get_connection = _o_conn


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
finally:
    (_sm_core.run_command, _sm_core.run_privileged, _sm_core.write_root_file,
     _sm_core.create_game_user, _sm_core.is_local_server, _sm_core.close_connection,
     _sm_hosts._wait_for_reboot, _sm_core._wait_for_dpkg_lock) = _bs_saved
