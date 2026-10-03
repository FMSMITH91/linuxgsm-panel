"""Part 20 of the unit suite: the debug report's core (builder B1 of the rework).

The runner and assembler (At a glance, Verdicts, the issue body, R7's "could not be read"), the
privacy pass (known names, IP classes, paths, the canaries of R72), the header (running commit vs
HEAD, clock and locale), Dependencies, Config, and the journal sections.

HOW IT RUNS. Every read is stubbed on the module that defines it, and saved and restored in a
finally. A report is generated against a Flask app of this part's own, on a throwaway SQLite file,
with canary rows in it; the section registry is cut to this builder's sections plus a stand-in
summary section, so a section another builder adds cannot reach a real host from here.
"""
import os
import tempfile as _tf20
import threading as _th20
import time as _time20
from contextlib import contextmanager

from flask import Flask as _Flask20

from unit.part01 import SO, check, config, eq
import panel.ops.debug_report as DR
from panel.db.models import GameServer, RemoteServer, ServerTag, User, db
from panel.ops.debug_report import _src_journal as SJ
from panel.ops.debug_report import _src_tailscale as STS
from panel.ops.debug_report import assemble as AS
from panel.ops.debug_report import config_section as CS
from panel.ops.debug_report import diagnostics as DG
from panel.ops.debug_report import header as HD
from panel.ops.debug_report import logs as LG
from panel.ops.debug_report import privacy as PV
from panel.ops.debug_report._base import Ctx, Result

_SAVED20 = []
_TMP20 = _tf20.mkdtemp(prefix="lgsm-unit-p20-")


def _patch(owner, name, value):
    """Replace owner.name for the rest of the part; every patch is undone by _restore_all."""
    _SAVED20.append((owner, name, owner.__dict__.get(name, _ABSENT) if isinstance(owner, type(os))
                     else getattr(owner, name)))
    setattr(owner, name, value)


_ABSENT = object()


def _restore_all():
    while _SAVED20:
        owner, name, value = _SAVED20.pop()
        if value is _ABSENT:
            owner.__dict__.pop(name, None)
        else:
            setattr(owner, name, value)


@contextmanager
def _patched():
    """Patches made inside the block are undone when it ends."""
    mark = len(_SAVED20)
    try:
        yield
    finally:
        while len(_SAVED20) > mark:
            owner, name, value = _SAVED20.pop()
            if value is _ABSENT:
                owner.__dict__.pop(name, None)
            else:
                setattr(owner, name, value)


# ── the app, the canary rows and the canary journal ─────────────────────────────────────────────
_app20 = _Flask20("p20")
_app20.config.update(SECRET_KEY="p20",  # nosec B106 - this part's throwaway app
                     SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_TMP20, "p20.db"),
                     SQLALCHEMY_TRACK_MODIFICATIONS=False, SESSION_COOKIE_SECURE=True,
                     SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", _TRUST_PROXY=False,
                     SESSION_PROTECTION="strong")
db.init_app(_app20)

_SECTIONS20 = (
    ("header", "Header", "header", "worker", "header"),
    ("diagnostics", "Diagnostics", "diagnostics", "worker", "summary"),
    ("dependencies", "Dependencies", "header", "request", "full"),
    ("config", "Config (non-secret settings only)", "config_section", "request", "full"),
    ("journal_digest", "Errors in the journal", "logs", "worker", "full"),
    ("recent_log", "Recent log (redacted)", "logs", "worker", "full"),
)
_CANARIES = ("canary-host-7731", "198.51.100.77", "CanaryServer", "canaryadmin", "canarybox",
             "canarysshacct", "canarypanelacct", "canarynode", "tail7731ab", "canaryuser@github",
             "1234567890", "canarytopic7731", "canaryntfy7731", "canaryu:canaryp4ss", "canarytag",
             "198.51.100.79", "203.0.113.9", "canaryparam7731", "7731234", "76561197960287930",
             "canarypeer7731", "canarytailnet7731", "CanaryTitle7731", "/home/canarypanelacct",
             "canaryurlacct", "pa$$w0rd!7731")


def _canary_journal():
    pfx = "Oct 02 12:00:%02d canarybox python3[1234]: "
    body = [
        "install: host canary-host-7731 unreachable while picking a port",
        "scheduled backup of CanaryServer failed for canaryadmin",
        "sudo: canarypanelacct : PWD=/home/canarypanelacct/x ; USER=root ; COMMAND=/bin/true",
        "  Tailscale: https://canarynode.tail7731ab.ts.net (peer canarypeer7731 in canarytailnet7731)",
        "login canaryuser@github ok, chat 1234567890 notified via canarytopic7731",
        "fetch https://canaryu:canaryp4ss@example.org/repo failed; tag canarytag applied",
        "push https://canaryurlacct:pa$$w0rd!7731@git.example.org/x refused",
        "peer ::ffff:198.51.100.79 connected; Open it at https://203.0.113.9:5000",
        "ban STEAM_0:1:7731234 and 76561197960287930; ssh canarysshacct@canary-host-7731",
        "Traceback (most recent call last):",
        '  File "%s/panel/ops/system_ops.py", line 3700, in generate_debug_report' % SO.PANEL_DIR,
        "sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) database is locked",
        "[parameters: ('canaryparam7731', 1)]",
        "LinuxGSM Panel starting on 0.0.0.0:5000 (site CanaryTitle7731)",
    ]
    return "\n".join(pfx % i + b for i, b in enumerate(body)) + "\n"


def _seed20():
    with _app20.app_context():
        db.create_all()
        rem = RemoteServer(name="canary-host-7731", host="198.51.100.77", username="canarysshacct",
                           auth_method="key", auth_credential="")
        db.session.add(rem)
        db.session.commit()
        db.session.add(GameServer(remote_id=rem.id, name="CanaryServer", short_name="canarysrv",
                                  game_type="csgo", port=27015))
        db.session.add(User(username="canaryadmin", password_hash="x"))  # nosec B106 - a fixture row
        db.session.add(ServerTag(name="canarytag"))
        db.session.commit()


def _cfg20(**over):
    base = dict(config.DEFAULT_CONFIG, site_title="CanaryTitle7731",
                notifications={"telegram": {"chat_id": "1234567890"},
                               "ntfy": {"topic": "canarytopic7731",
                                        "server": "https://canaryntfy7731.example.net"}})
    base.update(over)
    return base


def _fake_run(journal, calls=None):
    def _r(argv, timeout=5, cap=None):
        if calls is not None:
            calls.append(list(argv))
        if "--user" in argv:
            return journal, "", 0
        if "timedatectl" in argv:
            return "yes\n", "", 0
        return "", "", 1
    return _r


def _env(journal="", cfg=None, sections=_SECTIONS20, diag_lines=None):
    """Patch everything one generate() reads: a hermetic report."""
    _patch(DR, "SECTIONS", sections)
    _patch(SO, "_debug_run", _fake_run(journal))
    _patch(SO, "_run_verb", lambda verb, args=(), timeout=30, merge_stderr=True: ("", "", 1))
    _patch(SO, "_helper_present", lambda: True)
    _patch(SO, "_is_git_checkout", lambda: True)
    _patch(SO, "_git", lambda args, timeout=45: ("abc1234", "", 0) if list(args[:1]) == ["rev-parse"]
           else ("", "", 1))
    _patch(SO, "panel_version", lambda: "9.9.9")
    _patch(config, "load_config", lambda: dict(cfg if cfg is not None else _cfg20()))
    _patch(PV, "_os_accounts", lambda: ["canarypanelacct"])
    _patch(STS, "read", lambda: ("ok", {"dns_name": "canarynode.tail7731ab.ts.net.",
                                        "peers": [{"HostName": "canarypeer7731"}],
                                        "tailnet_name": "canarytailnet7731"}))
    _patch(DG, "section_diagnostics", lambda ctx: Result(
        lines=diag_lines if diag_lines is not None else
        ["- [warn] **X** — host canary-host-7731 at 198.51.100.77 for canaryadmin"],
        findings=[{"level": "warn", "area": "Diagnostics", "text": "one warning"}],
        verdict="**Update**: stand-in verdict"))


def _generate(app=None):
    if app is None:
        return DR.generate()
    with app.app_context():
        return SO.generate_debug_report()


# ── R72: the canaries ───────────────────────────────────────────────────────────────────────────
def _leaks(texts):
    """'<canary> in <part>' for every canary found in any of the texts, case-insensitively."""
    found = set()
    for part, text in texts.items():
        low = text.lower()
        found.update("%s in %s" % (c, part) for c in _CANARIES if c.lower() in low)
    return sorted(found)


def _p20_canaries():
    with _patched():
        _env(journal=_canary_journal())
        rep = _generate(_app20)
    texts = {k: rep.get(k, "") for k in ("report", "summary", "issue_body")}
    leaks = _leaks(texts)
    check("debug report privacy: no seeded host, IP, server, user, OS account, journal host, tailnet name, "
          "login, chat id, ntfy topic, URL credential, tag, SteamID or bound parameter survives in the "
          "report, the summary or the issue body", not leaks and "[host-1]" in texts["report"], "; ".join(leaks))
    check("debug report privacy: a traceback frame keeps its module; SQLAlchemy parameters are withheld",
          '"<panel>/panel/ops/system_ops.py", line 3700' in texts["report"]
          and "[parameters: withheld]" in texts["report"], texts["report"][-3000:])
    foot = texts["report"].split("### Privacy", 1)[-1]
    check("debug report privacy: the footer counts what was pseudonymised, and claims no completeness",
          all(("1 host" in foot, "1 game server" in foot, "panel user" in foot, "IPs (" in foot,
               "review the report before posting" in foot, "no secrets" not in texts["report"])), foot)
    return rep


def _p20_withheld():
    def _boom(text, st):
        raise RuntimeError("pattern pass")
    with _patched():
        _env(journal=_canary_journal())
        _patch(PV, "_generic", _boom)
        rep = _generate(_app20)
    leaks = [c for c in _CANARIES if c.lower() in (rep["report"] + rep["summary"]).lower()]
    check("debug report privacy: when the pattern pass fails, every body is withheld, never printed "
          "with names only", not leaks and "withheld: pseudonymisation unavailable" in rep["report"]
          and "**Pattern redaction FAILED** (RuntimeError)" in rep["report"]
          and "[fail] Privacy: pattern redaction failed" in rep["summary"], "; ".join(leaks) or rep["summary"][-400:])


def _p20_no_names():
    with _patched():
        _env(journal="Oct 02 12:00:01 canarybox p[1]: up\n")
        rep = _generate(None)                         # no app: the DB names cannot be read
    check("debug report privacy: without the DB names, At a glance and the footer say only pattern "
          "redaction covered them",
          "[warn] Privacy: some known names could not be read" in rep["summary"]
          and "database names unavailable (NoAppContext)" in rep["report"]
          and "canarybox" not in rep["report"], rep["summary"][:1200])


def _p20_cred_key():
    key = config.CRED_KEY_FILE
    saved = key.read_bytes() if key.exists() else None
    try:
        if key.exists():
            key.unlink()
        ctx = Ctx(app=_app20)
        with _patched():
            _patch(config, "load_config", _cfg20)
            st = PV.prepare(ctx)
        created = key.exists()
    finally:
        if saved is not None:
            key.write_bytes(saved)
    check("debug report privacy: with cred_key missing, the encrypted host columns are not decrypted "
          "(which would mint a new key); names come from the plain columns, and the gap is said",
          not created and st.names.get("canary-host-7731") == "[host-1]"
          and ("host addresses and accounts", "cred_key missing") in st.source_errors,
          repr((created, st.source_errors, sorted(st.names)[:8])))


def _p20_matching():
    st = PV._State()
    for name, ident in (("abc", 1), ("abcdef", 2), ("game", 3), ("my.box", 4)):
        st.add(name, "host", ident)
    st.add("Diagnostics", "host", 5)
    out = PV._known_names("abcdef abc xabc abcx ABC game my.box myXbox\n### Diagnostics _(read in 0.01 s)_",
                          st)
    eq("debug report privacy: known names match longest first, case-insensitively, never inside a longer "
       "word, never a common word, never in a heading",
       out, "[host-2] [host-1] xabc abcx [host-1] game [host-4] myXbox\n### Diagnostics _(read in 0.01 s)_")
    st2 = PV._State()
    text = PV._generic("a 100.101.102.103 b 8.8.8.8 c 127.0.0.1 d 0.0.0.0 e ::1 f fd7a:115c:a1e0::5 "
                       "g 12:00:01 h [2001:db8::1]:5000 i 10.0.0.2 j fe80::1%eth0", st2)
    eq("debug report privacy: addresses print as their class; loopback, unspecified and clock times stay",
       text, "a [ip:tailnet] b [ip:public] c 127.0.0.1 d 0.0.0.0 e ::1 f [ip:tailnet] g 12:00:01 "
             "h [[ip:private]]:5000 i [ip:private] j [ip:link-local]")


def _p20_paths():
    st = PV._State()
    text = PV._paths("%s/panel/x.py /usr/lib/python3/dist-packages/eventlet/hub.py "
                     "/home/someone/.config/y PWD=/home/acct" % SO.PANEL_DIR, st)
    eq("debug report privacy: the checkout, the packages dir and home directories are normalised",
       text, "<panel>/panel/x.py <venv>/eventlet/hub.py /home/[user]/.config/y PWD=/home/[user]")


# ── R1 / R7: At a glance, Verdicts, and a section that could not be read ───────────────────────
def _res(status, findings=(), lines=("- x",), verdict=None):
    return (status, 0.01, Result(lines=list(lines), findings=list(findings), verdict=verdict)
            if status == "ok" else "OSError")


def _fnd(lvl, text):
    return {"level": lvl, "area": "A", "text": text}


def _p20_glance():
    secs = tuple(("s%d" % i, "S%d" % i, "m", "worker", "full") for i in range(6))
    results = AS.enforce({
        "s0": _res("ok", [_fnd("warn", "w1"), _fnd("ok", "fine")]), "s1": _res("error"),
        "s2": _res("ok", [_fnd("fail", "f1"), _fnd("fail", "f2"), _fnd("warn", "w2")]),
        "s3": ("timeout", 20.0, None), "s4": _res("ok", lines=("- (none)",)),
        "s5": _res("ok", [_fnd("warn", "w3"), _fnd("warn", "w4")], lines=())})
    lines = AS.glance(secs, results)
    eq("debug report: At a glance lists fail, then warn, then unread, never an ok finding, in 8 lines at "
       "most, with the rest counted",
       lines, ["### At a glance: 6 problems, 3 unreadable", "- [fail] A: f1", "- [fail] A: f2",
               "- [warn] A: w1", "- [warn] A: w2", "- [warn] A: w3", "- [warn] A: w4",
               "- … and 3 more, every one listed under All findings in the full report"])
    check("debug report: a section that returned nothing (or only '(none)') is one that could not be "
          "read; one with findings and no body prints its findings",
          results["s4"][:1] == ("error",) and results["s4"][2] == "EmptyResult"
          and results["s5"][2].lines == ["- [warn] A: w3", "- [warn] A: w4"], repr(results["s4"]))
    eq("debug report: headings carry the read time, the exception class, or the budget",
       [AS._heading("T", "ok", 0.123, None, 20), AS._heading("T", "error", 15.0, "OperationalError", 20),
        AS._heading("T", "timeout", 20.4, None, 20)],
       ["### T _(read in 0.12 s)_", "### T _(could not be read: OperationalError after 15.0 s)_",
        "### T _(timed out after the report's 20 s budget; not shown)_"])


def _p20_glance_fallback():
    def _boom(*_a, **_k):
        raise ZeroDivisionError("glance")
    with _patched():
        _env(journal="")
        _patch(AS, "glance", _boom)
        rep = _generate(None)
    check("debug report: when At a glance cannot be assembled, the summary says so and still carries "
          "the sections and Verdicts",
          "- [unread] At a glance: could not be assembled (ZeroDivisionError)" in rep["summary"]
          and "### Verdicts\n- **Update**: stand-in verdict" in rep["summary"]
          and "### Diagnostics _(read in" in rep["summary"], rep["summary"][:1500])


# ── R2: the issue body ──────────────────────────────────────────────────────────────────────────
def _p20_issue_body():
    from urllib.parse import quote
    url = "https://example.invalid/o/r/issues/new"
    summary = "\n".join(["## head", "- a"] + ["- line %03d " % i + "é😀x" * 30 for i in range(300)])
    body = AS.issue_body(summary, url, must_keep=2, problems=4)
    full = "%s?labels=debug&title=%s&body=%s" % (url, quote("Debug report", safe=""), quote(body, safe=""))
    kept = body[len(AS.ISSUE_PROMPT):].split("\n")
    check("debug report: the issue body starts with the prompt, fits the URL budget, keeps whole lines and "
          "ends saying it was cut",
          body.startswith(AS.ISSUE_PROMPT) and len(full) <= AS.ISSUE_URL_MAX
          and all(ln in summary.split("\n") for ln in kept[:-3])
          and "_(summary truncated: " in body and len(kept) > 10, "%d: %s" % (len(full), body[-200:]))
    tiny = AS.issue_body("## h\n" + "x" * 9000, url, must_keep=2, problems=4)
    eq("debug report: when even the header does not fit, the body is the prompt and the problem count",
       tiny, AS.ISSUE_PROMPT + "Problems: 4; see the attached report.\n")
    check("debug report: lone surrogates are replaced before anything is encoded",
          AS._clean("a\udc80b") == "a?b", repr(AS._clean("a\udc80b")))


# ── R3: the runner ──────────────────────────────────────────────────────────────────────────────
def _slow_section(state):
    def _s(ctx):
        with state["lock"]:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
        _time20.sleep(0.05)
        with state["lock"]:
            state["now"] -= 1
        return Result(lines=["- ok"])
    return _s


def _p20_workers_capped():
    state = {"now": 0, "max": 0, "lock": _th20.Lock()}
    secs = tuple(("w%d" % i, "W%d" % i, "logs", "worker", "full") for i in range(9))
    with _patched():
        _patch(DR, "SECTIONS", secs)
        _patch(DR, "_section_fn", lambda module, key: _slow_section(state))
        out = DR._run_sections(Ctx())
    check("debug report: at most MAX_WORKERS worker sections run at once, and every one still runs",
          state["max"] == DR.MAX_WORKERS == 4 and all(v[0] == "ok" for v in out.values()),
          repr((state, sorted(out))))


def _p20_timeout():
    release, ended = _th20.Event(), _th20.Event()

    def _stuck(ctx):
        release.wait(5)
        ended.set()
        return Result(lines=["- late"])
    secs = (("stuck", "Stuck", "logs", "worker", "full"),)
    with _patched():
        _patch(DR, "SECTIONS", secs)
        _patch(DR, "_section_fn", lambda module, key: _stuck)
        out = DR._run_sections(Ctx(deadline_s=0.2))
    release.set()
    ended.wait(5)
    check("debug report: a worker still running at the deadline is reported as timed out, not waited for",
          out["stuck"][0] == "timeout" and out["stuck"][1] < 2.0, repr(out))


def _p20_single_flight():
    calls, gate, got = [], _th20.Event(), []

    def _build(app=None, request_info=None):
        calls.append(1)
        gate.wait(5)
        return {"report": "r%d" % len(calls)}
    with _patched():
        _patch(DR, "_build", _build)
        threads = [_th20.Thread(target=lambda: got.append(DR.generate())) for _ in range(2)]
        for t in threads:
            t.start()
            _time20.sleep(0.05)
        gate.set()
        for t in threads:
            t.join(5)
    check("debug report: a second request while one report builds waits for it and gets the same result",
          calls == [1] and got == [{"report": "r1"}, {"report": "r1"}], repr((calls, got)))


# ── R4 / R5: the header ─────────────────────────────────────────────────────────────────────────
def _header_text(app_commit=None, head="abc1234", zone="Etc/UTC", ntp=("yes\n", "", 0)):
    app = _Flask20("p20h")
    if app_commit is not None:
        app.config["PANEL_COMMIT"] = app_commit
    with _patched():
        _patch(SO, "_is_git_checkout", lambda: head is not None)
        _patch(SO, "_git", lambda args, timeout=45: (head or "", "", 0 if head else 128))
        _patch(SO, "panel_version", lambda: "9.9.9")
        _patch(SO, "_debug_run", lambda argv, timeout=5, cap=None: ntp)
        _patch(HD, "_zone_name", lambda: zone)
        _patch(config, "load_config", lambda: dict(config.DEFAULT_CONFIG))
        res = HD.section_header(Ctx(app=app))
    return "\n".join(res.lines), res.findings


def _p20_header():
    same, f_same = _header_text(app_commit="abc1234")
    moved, f_moved = _header_text(app_commit="def5678+")
    none, _ = _header_text(app_commit=None, head=None)
    check("debug report header: the running commit is the process's, compared with HEAD; a mismatch is "
          "RESTART PENDING and an At-a-glance warning",
          "- **Running commit**: abc1234 (loaded at start, " in same and "**Checkout HEAD**: abc1234, same" in same
          and not f_same and "- **RESTART PENDING**: this process runs def5678+; the checkout is at abc1234" in moved
          and [f["text"] for f in f_moved] == ["restart pending: the running code is not the checkout"]
          and "- **Running commit**: unknown (" in none and "**Checkout HEAD**: unknown" in none,
          "\n---\n".join((same, moved, none)))
    _p20_header_clock()


def _p20_header_clock():
    bad, f_bad = _header_text(zone=None, ntp=("", "timed out", -1))
    check("debug report header: an unreadable zone and NTP state say so; the zone never defaults to UTC",
          "- **Host clock**: timezone unreadable (UTC" in bad and "NTP synchronized: NTP state unknown" in bad
          and "Etc/UTC" not in bad and not f_bad, bad)
    unsynced, f_uns = _header_text(ntp=("no\n", "", 0))
    check("debug report header: NTP not synchronized is a warning; the locale line reads four keys by name",
          "NTP synchronized: no" in unsynced and [f["area"] for f in f_uns] == ["Host clock"]
          and all(k in unsynced for k in ("LANG", "LC_ALL", "LC_MESSAGES", "TZ"))
          and "PATH" not in unsynced and "HOME" not in unsynced, unsynced)


# ── R64: Dependencies ───────────────────────────────────────────────────────────────────────────
def _deps_text(pins, installed):
    with _patched():
        if isinstance(pins, Exception):
            def _raise():
                raise pins
            _patch(HD, "_pins", _raise)
        else:
            _patch(HD, "_pins", lambda: pins)
        _patch(HD, "_installed", lambda: dict(installed))
        res = HD.section_dependencies(Ctx())
    return "\n".join(res.lines), [f["text"] for f in res.findings]


def _p20_dependencies():
    import eventlet
    text, finds = _deps_text([("foo", "1.0", 'python_version < "2"'), ("bar", "2.0", None),
                              ("baz", "3.0", None), ("qux", "4.0", None)],
                             {"bar": "2.0", "baz": "3.1", "eventlet": eventlet.__version__})
    check("debug report deps: a pin whose environment marker does not apply is 'not required here', "
          "never missing; drift and missing packages are named",
          "- 1/3 match the lockfile (requirements.txt); 1 not required here (environment marker)" in text
          and "- **1 differ**: baz 3.1 installed, lock 3.0" in text and "- **1 missing**: qux (lock 4.0)" in text
          and "foo" not in text and finds == ["1 package(s) differ from the lockfile, 1 missing"], text)
    drift, dfinds = _deps_text([("eventlet", "0.0.1", None)], {"eventlet": "0.0.1"})
    check("debug report deps: a loaded module whose version differs from the one on disk is a restart "
          "pending",
          "- **loaded ≠ on disk** (pip ran after start, restart pending): eventlet loaded %s, on disk 0.0.1"
          % eventlet.__version__ in drift and len(dfinds) == 1, drift)
    gone, _ = _deps_text(OSError("ENOENT"), {"flask": "3.1.3"})
    check("debug report deps: an unreadable requirements.txt says so and falls back to the key packages, "
          "naming one that is not installed",
          "- lockfile comparison unavailable: requirements.txt not readable (OSError)" in gone
          and "- **flask**: 3.1.3" in gone and "- **eventlet**: not installed" in gone, gone)
    _p20_real_pins()


def _p20_real_pins():
    try:
        real = HD._pins()
    except (OSError, ValueError) as exc:          # a failed parse fails the check below, by name
        real = [("raised", type(exc).__name__, None)]
    check("debug report deps: the checkout's requirements.txt parses into its pins",
          len(real) >= 30 and any(n == "greenlet" and v and m is None for n, v, m in real),
          repr(real[:3]))


_ANY4 = ".".join(["0"] * 4)    # the wildcard bind, as config.json and app.config carry it


# ── R65-R67, R37, R39: Config ───────────────────────────────────────────────────────────────────
def _config_text(cfg, no_app=False, **app_config):
    app = None
    if not no_app:
        app = _Flask20("p20c")
        app.config.update(app_config)
    with _patched():
        _patch(config, "load_config", lambda: cfg)
        res = CS.section_config(Ctx(app=app))
    return "\n".join(res.lines), [f["text"] for f in res.findings]


def _p20_config():
    base = dict(config.DEFAULT_CONFIG, port=5001, bind_host=_ANY4, trust_proxy=True)
    text, finds = _config_text(base, BOOT_PORT=5000, BOOT_BIND=_ANY4, BOOT_TLS=False, _TRUST_PROXY=True,
                               SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                               SESSION_COOKIE_SAMESITE="Lax")
    check("debug report config: a startup-read key shows the file and the running value, RESTART PENDING "
          "when they differ; trust_proxy beyond loopback is warned",
          "- **port**: file 5001 · running 5000 (RESTART PENDING)" in text
          and "- **bind_host**: file all interfaces · running all interfaces\n" in text + "\n"
          and "- **trust_proxy**: file true · running true\n" in text + "\n"
          and finds == ["trust_proxy is on but the panel listens beyond loopback"], text)
    check("debug report config: the session cookie's flags and why Secure is set; an unset cookie_secure "
          "reads as auto",
          "- **Session cookie**: Secure yes (cookie_secure unset → auto from use_https true, "
          "tailscale_setup_done false, trust_proxy true) · HttpOnly yes · SameSite Lax" in text, text)
    loop, _ = _config_text(dict(config.DEFAULT_CONFIG, use_https=False), BOOT_BIND=_ANY4, BOOT_TLS=False,
                           _TRUST_PROXY=False, SESSION_COOKIE_SECURE=True)
    safe, _ = _config_text(dict(config.DEFAULT_CONFIG), BOOT_BIND="127.0.0.1", BOOT_TLS=False,
                           _TRUST_PROXY=False, SESSION_COOKIE_SECURE=True)
    check("debug report config: Secure cookies on plain HTTP served directly predict the login loop; "
          "behind loopback they do not",
          "- [!] Secure cookies while the process serves plain HTTP directly" in loop
          and "Secure cookies while" not in safe, loop)
    _p20_config_unreadable()


def _p20_config_unreadable():
    bad = config.UnreadableConfig(config.DEFAULT_CONFIG)
    text, _ = _config_text(bad, BOOT_PORT=5000)
    eq("debug report config: an unreadable config.json prints no values, not the defaults",
       text, "- config.json could not be read; values unknown")
    noapp, _ = _config_text(dict(config.DEFAULT_CONFIG, cookie_secure=False), no_app=True)
    tls, _ = _config_text(dict(config.DEFAULT_CONFIG), BOOT_TLS=False, BOOT_TLS_ERROR="OSError")
    check("debug report config: the boot record says whether TLS really started, and an unset key says "
          "what it means",
          "- **use_https**: file true · the process serves TLS itself: no (configured, but it failed to "
          "start: OSError)" in tls and "- **audit_log_retention_days**: (unset → 0: audit rows are kept "
          "forever)" in tls and "the process serves TLS itself: unknown (no app context)" in noapp, tls)
    check("debug report config: without an app the running values are unknown, never assumed",
          "- **port**: file 5000 · running value unknown (no app context)" in noapp
          and "- **Session cookie**: unknown (no app context) · cookie_secure override false" in noapp, noapp)
    _p20_config_boot_record()


def _p20_config_boot_record():
    """An app that booted no record (create_app without app.py's __main__), and an unset bind."""
    norec, _ = _config_text(dict(config.DEFAULT_CONFIG), SESSION_COOKIE_SECURE=True)
    auto, _ = _config_text(dict(config.DEFAULT_CONFIG, bind_host=""), BOOT_BIND=_ANY4, BOOT_PORT=5000)
    check("debug report config: an app with no boot record says so, and claims no restart pending",
          "- **port**: file 5000 · running value unknown (no boot record)" in norec
          and "- **bind_host**: file auto · running value unknown (no boot record)\n" in norec
          and "RESTART PENDING" not in _p20_line(norec, "port") + _p20_line(norec, "bind_host"),
          norec)
    check("debug report config: an unset bind_host is resolved at boot, so the bind it picked is "
          "shown and never called a restart pending",
          _p20_line(auto, "bind_host") == "- **bind_host**: file auto · running all interfaces "
                                            "(picked at boot)", auto)


def _p20_line(text, key):
    """The Config line for `key`, or ''."""
    return next((ln for ln in text.split("\n") if ln.startswith("- **%s**:" % key)), "")


# ── R68-R71, R73: the journal sections ──────────────────────────────────────────────────────────
_J_PFX = "Oct 02 11:%02d:%02d h7 python3[%d]: "


def _jl(i, body, pid=4121):
    return _J_PFX % (i // 60, i % 60, pid) + body


def _digest_journal():
    lines = [_jl(0, "WARNING panel.notifications: notification rejected: HTTP 401")]
    for i in range(3):
        lines += [_jl(1 + i, "Traceback (most recent call last):"),
                  _jl(1 + i, '  File "/x.py", line %d, in f' % i),
                  _jl(1 + i, "sqlite3.OperationalError: database is locked at 10.0.0.%d" % i)]
    lines += [_jl(9, "Traceback (most recent call last):"), _jl(9, "KeyError: 'k'")]
    lines += [_jl(10 + i, "remote command sent nothing for %ds; gave up" % i) for i in range(4)]
    lines += [_jl(20, "ERROR panel.app: boom")]
    return lines


def _section_text(fn, lines, source="helper"):
    ctx = Ctx()
    with _patched():
        _patch(SJ, "read", lambda max_lines=5000, timeout=10: {"source": source, "lines": list(lines),
                                                                "why": None})
        res = fn(ctx)
    return "\n".join(res.lines), res.findings


def _p20_digest():
    text, finds = _section_text(LG.section_journal_digest, _digest_journal())
    check("debug report journal digest: tracebacks are counted by exception, with the last time and a "
          "scrubbed first line",
          "- **Tracebacks**: 4, 2 distinct:" in text
          and "  - sqlite3.OperationalError ×3 (last Oct 02 11:00:03): `sqlite3.OperationalError: database "
              "is locked at [ip:private]`" in text
          and "  - KeyError ×1 (last Oct 02 11:00:09)" in text and "10.0.0." not in text
          and [f["text"] for f in finds] == ["4 traceback(s) in the journal window"], text)
    check("debug report journal digest: the window, level-tagged lines and the most repeated lines",
          "- **Window**: the last 17 lines, Oct 02 11:00:00 → Oct 02 11:00:20 host time (UTC" in text
          and "- **Logged at WARNING or above**: 1 ERROR, 1 WARNING" in text
          and "  - ×4 `remote command sent nothing for 0s; gave up`" in text, text)
    none, _ = _section_text(LG.section_journal_digest, [])
    check("debug report journal digest: no journal says so", none.startswith("_(digest unavailable: "), none)


def _recent_journal():
    lines = [_jl(0, "systemd[1]: linuxgsm-panel.service: Main process exited, code=exited, "
                    "status=1/FAILURE", pid=1)]
    lines += [_jl(1, "LinuxGSM Panel starting on 127.0.0.1:5000", pid=1203)]
    lines += [_jl(2 + i, "Removing descriptor: %d" % (10 + i), pid=1203) for i in range(5)]
    lines += [_jl(8, "kernel: Out of memory: Killed process 1203", pid=0)]
    lines += [_jl(9, "LinuxGSM Panel starting on 127.0.0.1:5000", pid=4121)]
    return lines


def _p20_recent_log():
    text, finds = _section_text(LG.section_recent_log, _recent_journal())
    check("debug report recent log: the header names the source, the line count, the span and the zone",
          "- **Source**: system journal via the privileged helper · 9 lines · Oct 02 11:00:00 → "
          "Oct 02 11:00:09 host time (UTC" in text and not finds, text)
    check("debug report recent log: starts with their pids, crashes and OOM kills in the window, and a "
          "restart marker inline",
          "- **In this window**: 2 starts (pids 1203 → 4121), 1 crash (systemd 'Main process exited' with "
          "a failure), 1 OOM kill" in text
          and text.count("—— panel (re)started: pid ") == 2 and "—— panel (re)started: pid 4121 ——" in text, text)
    check("debug report recent log: consecutive repeats that differ only in digits are folded, with when "
          "the run ended",
          text.count("Removing descriptor") == 1
          and "    ↳ (same line repeated 4× more until Oct 02 11:00:06)" in text, text)
    none, nfinds = _section_text(LG.section_recent_log, [], source=None)
    check("debug report recent log: no journal is said, and is an [unread] finding, never an empty block",
          "```\n(no journal available)\n```" in none and [f["level"] for f in nfinds] == ["unread"], none)


def _p20_budget():
    lines = [_jl(i % 3600, "routine %s %d" % ("ab"[i % 2], i) + " x" * 60) for i in range(400)]
    lines[50] = _jl(50, "Traceback (most recent call last):")
    lines[51] = _jl(51, '  File "/x.py", line 1, in f')
    lines[52] = _jl(52, "ValueError: early failure")
    with _patched():
        _patch(LG, "LOG_BUDGET", 8000)
        text, _ = _section_text(LG.section_recent_log, lines)
    body = text.split("```\n", 1)[-1]
    check("debug report recent log: over budget, tracebacks are kept first and then the newest lines, in "
          "order, with the elided spans marked",
          "ValueError: early failure" in body and "routine b 399" in body and "routine a 100" not in body
          and body.index("ValueError") < body.index("routine b 399") and "lines elided) …" in body
          and "- **Kept**: " in text and len(body) < 8000 + 2000, text[:600])


def _p20_one_journal_read():
    calls = []

    def _read(max_lines=5000, timeout=10):
        calls.append(max_lines)
        _time20.sleep(0.05)
        return {"source": "helper", "lines": _recent_journal(), "why": None}
    ctx = Ctx()
    with _patched():
        _patch(SJ, "read", _read)
        threads = [_th20.Thread(target=fn, args=(ctx,))
                   for fn in (LG.section_journal_digest, LG.section_recent_log)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
    eq("debug report: the digest and the recent log share ONE journal read of 5000 lines", calls, [5000])


def _p20_journal_source():
    calls = []
    with _patched():
        _patch(SO, "_debug_run", _fake_run("-- No entries --\n-- Boot 1a2b --\n", calls))
        _patch(SO, "_helper_present", lambda: True)
        _patch(SO, "_run_verb", lambda verb, args=(), timeout=30, merge_stderr=True:
               ("No journal files were found.\n", "", 1))
        got = SJ.read(400, timeout=5)
    eq("debug report journal source: marker-only output is empty, and a failed helper read is described "
       "in fixed words",
       (got["source"], got["lines"], got["why"]),
       (None, [], "user journal: no entries, rc 0; system journal via helper: no journal files, rc 1"))


# ── R2: the page uses the server's issue body ───────────────────────────────────────────────────
def _p20_js():
    src = open(os.path.join(SO.PANEL_DIR, "static", "js", "remote_manage_host.js"), encoding="utf-8").read()
    fn = src.split("function genDebugReport(){", 1)[-1].split("\nfunction ", 1)[0]
    check("debug report page: the issue link is built from the server's issue_body, inside a try/catch, "
          "and nothing slices the text",
          "encodeURIComponent(d.issue_body||'')" in fn and "try {" in fn and "catch(e)" in fn
          and ".slice(" not in fn and "d.summary" not in fn, fn[:600])


try:
    _seed20()
    for _fn20 in (_p20_canaries, _p20_withheld, _p20_no_names, _p20_cred_key, _p20_matching, _p20_paths,
                  _p20_glance, _p20_glance_fallback, _p20_issue_body, _p20_workers_capped, _p20_timeout,
                  _p20_single_flight, _p20_header, _p20_dependencies, _p20_config, _p20_digest,
                  _p20_recent_log, _p20_budget, _p20_one_journal_read, _p20_journal_source, _p20_js):
        _fn20()
except Exception as _e20:  # noqa: BLE001 - a harness failure must fail by name, not end the suite
    import traceback as _tb20
    check("debug report: the part20 harness ran to the end", False,
          "raised %s: %s @ %s" % (type(_e20).__name__, _e20, _tb20.format_exc()[-600:]))
finally:
    _restore_all()
    import shutil as _sh20
    _sh20.rmtree(_TMP20, ignore_errors=True)
