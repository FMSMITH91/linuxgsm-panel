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

_orig_popen = _so.subprocess.Popen
_cap = {}
try:
    _so.subprocess.Popen = lambda a, **k: (_cap.update(args=a), type("P", (), {})())[1]
    _ok, _ = _so.restart_panel()
    check("restart_panel: dispatches successfully", _ok is True)
    check("restart_panel: targets the panel service via systemd-run restart",
          "systemd-run" in _cap["args"] and "restart" in _cap["args"]
          and "linuxgsm-panel.service" in _cap["args"])
    check("restart_panel: delays so the HTTP response can flush",
          any(str(x).startswith("--on-active=") for x in _cap["args"]))
finally:
    _so.subprocess.Popen = _orig_popen
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

# ── server_live_metrics parses SSH output into a numeric dict ──
_METRICS_OUT = "\n".join([
    "cpu 100 0 100 800 0 0 0", "GJA 1000",
    "cpu 110 0 110 880 0 0 0", "GJB 1100",
    "MEM 8000000000 4000000000", "LOAD 0.5 0.4 0.3",
    "DISK 100000000000 33000000000", "CORES 4", "UPTIME 123456",
    "GAMERAM 524288 3", "GUP 3600", "PORT 1",
])
_sm_core.run_command = lambda server, cmd, timeout=30, sudo=None: (_METRICS_OUT, "", 0)
_m = _sm_core.server_live_metrics(None, "gmodserver", 27015)
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
_sm_core.run_command = lambda server, cmd, timeout=12, **k: (_RLM_OUT, "", 0)
_rlm = _sm_core.remote_live_metrics(NS(is_local=False, auth_method="tailscale", host="x", name="x"))
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
_cfg_backup = config.CONFIG_FILE.read_text() if config.CONFIG_FILE.exists() else None
try:
    _c = config.load_config()
    _c["_roundtrip_probe"] = "value-123"
    config.save_config(_c)
    check("config: value survives a save/load round-trip",
          config.load_config().get("_roundtrip_probe") == "value-123")
    check("config: file exists after atomic save", config.CONFIG_FILE.exists())
finally:
    if _cfg_backup is not None:
        config.CONFIG_FILE.write_text(_cfg_backup)

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

    # everything still verifying → offer nothing, explain why.
    _so._remote_ci_state = lambda sha: "pending"
    _r = _so._compute_update_status()
    check("update-target: all pending -> no update offered",
          _r["update_available"] is False and _r["ci_state"] == "pending")
finally:
    _so._git = _cus_git
    _so._is_git_checkout = _cus_isco
    _so.panel_version = _cus_ver
    _so._remote_ci_state = _cus_ci

# ── Tailscale: installed-but-not-authenticated (NeedsLogin) must not 500 ─
from panel.ops import tailscale_integration as _tsi
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
