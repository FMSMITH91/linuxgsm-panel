"""Part 25 of the unit suite: the debug report's review fixes, each pinned by the failure it fixes.

A review of the reworked report (parts 20-24) reproduced each of these on the merged tree. Every
check here fails on that tree: the privacy pass (Tailscale names lost silently, IPv6 and reverse-DNS
addresses, names cut in half before the final pass, name-matching gaps), the self-update tail that
never printed, a raising git read that failed the whole report, single-flight, the deadline for
request sections, the memo, the hub-lag wording, a hung tailscaled blanking Hosts, the full report's
At a glance, the venv interpreter, NSS lookups on the hub, Serve and fail2ban findings, git
timeouts, the CI walk's key cap, and a missing unit file read as "unreadable".

HOW IT RUNS. Every read is stubbed on the module that defines it, and saved and restored in a
finally; part20's hermetic report environment is reused. A report is generated against a Flask app
of this part's own, on a throwaway SQLite file.
"""
import os
import sys
import tempfile as _tf25
import threading as _th25
import time as _time25

from flask import Flask as _Flask25

from unit.part01 import SO, check, config, eq
from unit.part20 import _cfg20, _env, _patch, _patched
import panel.ops.debug_report as DR
from panel.core import runtime_stats as _rs25
from panel.db.models import RemoteServer, db
from panel.ops.debug_report import _src_tailscale as STS
from panel.ops.debug_report import config_section as CS
from panel.ops.debug_report import diagnostics as DG
from panel.ops.debug_report import errors as ER
from panel.ops.debug_report import hosts as HS
from panel.ops.debug_report import install as INS
from panel.ops.debug_report import logs as LG
from panel.ops.debug_report import network as NW
from panel.ops.debug_report import privacy as PV
from panel.ops.debug_report import process as PR
from panel.ops.debug_report import updates as UP
from panel.ops.debug_report._base import Ctx, Result

_TMP25 = _tf25.mkdtemp(prefix="lgsm-unit-p25-")
_app25 = _Flask25("p25")
_app25.config.update(SECRET_KEY="p25",  # nosec B106 - this part's throwaway app
                     SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(_TMP25, "p25.db"),
                     SQLALCHEMY_TRACK_MODIFICATIONS=False)
db.init_app(_app25)


def _seed25():
    with _app25.app_context():
        db.create_all()
        db.session.add(RemoteServer(name="zephyr-row-7731", host="zephyr7731.example.org",
                                    username="zacct7731", auth_method="key", auth_credential=""))
        db.session.commit()


def _gen25():
    with _app25.app_context():
        return SO.generate_debug_report()


def _ctx_with(*names):
    """A Ctx whose privacy map holds `names` [(name, kind, id)] and nothing read from the host."""
    st = PV._State()
    for name, kind, ident in names:
        st.add(name, kind, ident)
    ctx = Ctx()
    ctx._memo["privacy"] = (True, st)
    return ctx, st


# ── the self-update tail (_guard calls fn(res, *args)) ─────────────────────────────────────────
def _p25_update_tail():
    log = os.path.join(_TMP25, "self-update.log")
    with open(log, "w", encoding="utf-8") as fh:
        fh.write("x\n")
    upd = {"exists": True, "exit_code": 1, "reason": "boom",
           "lines": ["[!] warning one", "Fetching 198.51.100.77", "[ERROR] boom", "=== installer exit 1"]}
    with _patched():
        _patch(SO, "panel_update_log", lambda: dict(upd))
        _patch(SO, "_update_log_path", lambda: log)
        text = "\n".join(UP.section_updates(Ctx()).lines)
    check("review fix updates: a self-update log prints the installer's warnings and its redacted "
          "tail, never 'tail_lines: could not be read'",
          "- **Installer said**:" in text and "  [!] warning one" in text and "=== installer exit 1" in text
          and "tail_lines" not in text and "198.51.100.77" not in text, text[-900:])


# ── P2: a Tailscale read that failed is a gap the reader is told about ─────────────────────────
def _p25_tailscale_error():
    with _patched():
        _env(journal="Oct 02 12:00:01 canarybox p[1]: host tspeer7731 dropped\n")
        _patch(STS, "read", lambda: ("error", "ValueError"))
        rep = _gen25()
    foot = rep["report"].split("### Privacy", 1)[-1]
    check("review fix privacy: a Tailscale status that could not be read is said in the footer and "
          "At a glance (none of its names was mapped)",
          "tailscale names unavailable (ValueError)" in foot
          and "[warn] Privacy: some known names could not be read" in rep["summary"], foot[:800])


# ── P3 / P7: addresses in the shapes logs really print them ────────────────────────────────────
def _p25_addresses():
    st = PV._State()
    got = [PV._generic(t, st) for t in (
        "listening on 2a01:4f8:c17:7731::1: ok", "ban 2a01:4f8:c17:7731::1:",
        "Error: 2001:db8:1234:5678:abcd:ef01:2345:6789:22 refused", "src2a01:4f8:c17:7731::1 x",
        "Type::bad e5::1:2", "peer ::ffff:198.51.100.79 up")]
    eq("review fix privacy: an IPv6 address followed by ':' or ':port', or glued to a word, is "
       "classified; a word with '::' and a mapped IPv4's prefix are left alone",
       got, ["listening on [ip:public]: ok", "ban [ip:public]:", "Error: [ip:private]:22 refused",
             "src[ip:public] x", "Type::bad [ip:public]", "peer ::ffff:[ip:private] up"])
    got = [PV._generic(t, st) for t in (
        "ipv4 zero-padded 081.002.013.077", "rDNS static.77.13.2.81.clients.your-server.de",
        "ec2-81-2-13-77.eu-west-1.compute.amazonaws.com", "ns1234.ip-51-38-12-34.eu",
        "backup-2026-10-02-12-30.tar v1.2.3")]
    eq("review fix privacy: a zero-padded IPv4 and an address inside a provider's reverse-DNS name "
       "are replaced; dates and versions are not",
       got, ["ipv4 zero-padded [ip:public]", "rDNS static.[ip:in-hostname].clients.your-server.de",
             "ec2-[ip:in-hostname].eu-west-1.compute.amazonaws.com", "ns1234.ip-[ip:in-hostname].eu",
             "backup-2026-10-02-12-30.tar v1.2.3"])


# ── P4: one raising git read is the header's problem only ──────────────────────────────────────
def _p25_git_raises():
    def _boom(args, timeout=45):
        raise TypeError("a bytes-like object is required, not 'str'")
    err = None
    with _patched():
        _env(journal="")
        _patch(SO, "_git", _boom)
        try:
            rep = _gen25()
        except Exception as exc:  # noqa: BLE001 - the failure this check is about
            err, rep = exc, {}
    check("review fix: a git read that raises fails only the header section, never the whole report "
          "(the filename falls back to 'unknown')",
          err is None and rep.get("filename", "").startswith("linuxgsm-panel-debug-unknown-")
          and "- **Header**: could not be read (TypeError)" in rep.get("report", ""),
          repr(err) if err else rep.get("report", "")[:600])


# ── P5: cut at a word, so the final pass sees whole names ──────────────────────────────────────
def _p25_cuts():
    ctx, st = _ctx_with(("Zephyrhost7731", "host", 1))
    fill = "word " * 40
    outs = {
        "Outcome": UP._failed_outcome({"exit_code": 1, "reason": fill[:UP._REASON_MAX - 8] +
                                       " Zephyrhost7731 end"}, "", "c"),
        "held": UP._ok_outcome({"outcome": "held", "reason": fill[:UP._REASON_MAX - 8] +
                                " Zephyrhost7731"}, [], "c"),
        "clean_line": UP.clean_line("[!] " + fill[:UP._LINE_MAX - 12] + " Zephyrhost7731 tail"),
        "errors cell": ER._cell(fill[:ER.SHOWN_MAX - 8] + " Zephyrhost7731"),
    }
    q = LG._quote(ctx, "RuntimeError: " + fill[:LG._QUOTE_MAX - 22] + " tspeer7731 unreachable")
    PV._names_tailscale({"peers": [{"hostname": "tspeer7731"}]}, st)    # what finish() adds later
    outs["journal quote"] = q
    left = {k: PV.scrub(ctx, v) for k, v in outs.items()}
    frags = {k: v[-30:] for k, v in left.items() if "zephyr" in v.lower() or "tspee" in v.lower()}
    check("review fix privacy: free text is cut at a word before the final pass, so a name at the cut "
          "is matched whole or dropped, never printed as a fragment",
          not frags and all(v.endswith("…") for v in outs.values()), repr(frags or outs))
    # A name of several words can be cut BETWEEN its words; where the section has the report's
    # ctx, the text is scrubbed before it is cut.
    ctx2, _st2 = _ctx_with(("Quokka Fortress 7731", "server", 5))
    many = {
        "Outcome": UP._failed_outcome({"exit_code": 1, "reason": fill[:UP._REASON_MAX - 12] +
                                       " Quokka Fortress 7731 end"}, "", "c", ctx2),
        "errors row": ER._row("ERROR|panel.x|" + fill[:ER.SHOWN_MAX - 12] + " Quokka Fortress 7731",
                              1, None, ctx2),
    }
    check("review fix privacy: the updates and errors sections scrub free text before they cut it, so "
          "a name of several words is never cut between them",
          not any("quokka" in v.lower() or "fortress" in v.lower() for v in many.values()), repr(many))


# ── P6: name-matching gaps ─────────────────────────────────────────────────────────────────────
def _p25_names():
    ctx, st = _ctx_with(("İzmir7731", "host", 2), ("Straße7731", "host", 6),
                        ("Quokka Fortress 7731", "server", 5), ("Zephyrhost7731", "host", 1),
                        ("diagnostics", "host", 9))
    PV._names_tailscale({"user_logins": ["alice7731@github", "bob7731@example.com"]}, st)
    PV._names_bot(st, {"chat_id": "-1001234567890"}, "chat_id")
    cases = {
        "login handle": "user alice7731 signed in, by bob7731",
        "dotless I": "host İzmir7731 down; host IZMIR7731 down",
        "sharp s": "host STRASSE7731 down",
        "spaces": "srv Quokka  Fortress 7731 up",
        "line break": "srv Quokka\nFortress 7731 split",
        "chat id": "chat 1001234567890 (sign dropped)",
        "hash line": "# Zephyrhost7731 at the start of a log line",
        "old host": "Oct 02 12:00:01 oldhost7731 python3[1]: sudo: unable to resolve host oldhost7731: x",
    }
    out = {k: PV.scrub(ctx, v) for k, v in cases.items()}
    canaries = ("alice7731", "bob7731", "zmir7731", "strasse7731", "quokka", "fortress",
                "1001234567890", "zephyrhost7731", "oldhost7731")
    leaks = {k: v for k, v in out.items() if any(c in v.lower() for c in canaries)}
    check("review fix privacy: login handles, dotless-I and sharp-s spellings, names split by spaces "
          "or a line break, an unsigned chat id, a log line starting with '#', and an old hostname "
          "named again in its own message are all pseudonymised",
          not leaks and out["line break"].count("\n") == 1, repr(leaks or out))
    heading = "### Diagnostics _(read in 0.01 s)_"
    eq("review fix privacy: the assembler's own headings are still never pseudonymised",
       PV.scrub(ctx, heading + "\n- diagnostics here"), heading + "\n- [host-9] here")


def _p25_host_first_label():
    with _patched():
        _patch(config, "load_config", lambda: dict(_cfg20()))
        _patch(PV, "_os_accounts", lambda: [])
        ctx = Ctx(app=_app25)
        out = PV.scrub(ctx, "short label zephyr7731 only; full zephyr7731.example.org")
    check("review fix privacy: a remote host's FQDN is mapped by its first label too, as the panel "
          "host's is", "zephyr7731" not in out.lower() and "[host-1]" in out, out)


# ── R1 / R2 / R5: single-flight, the deadline, the memo ────────────────────────────────────────
def _started(fn):
    """Start fn in a thread; the Event it returns is set when fn has returned or raised.

    Waited on through the Event, never Thread.join(timeout): under eventlet's patching a join that
    times out RAISES eventlet's Timeout, a BaseException that would end the whole unit run.
    """
    done = _th25.Event()

    def _run():
        try:
            fn()
        finally:
            done.set()
    _th25.Thread(target=_run, daemon=True).start()
    return done


def _p25_single_flight_busy():
    builds, gate, got = [], _th25.Event(), {}

    def _build(app=None, request_info=None):
        builds.append(1)
        gate.wait(5)
        return {"report": "r"}

    def _second():
        try:
            got["second"] = DR.generate()
        except DR.ReportBusy as exc:
            got["second"] = exc
    with _patched():
        _patch(DR, "_build", _build)
        _patch(DR, "WAIT_S", 0.3)
        first = _started(lambda: got.setdefault("first", DR.generate()))
        _time25.sleep(0.05)
        second = _started(_second)
        second.wait(3)
        gate.set()
        first.wait(5)
        second.wait(5)
    check("review fix: a caller still waiting when the build passes WAIT_S is told it is busy and "
          "never starts a second build",
          builds == [1] and isinstance(got.get("second"), DR.ReportBusy)
          and got.get("first") == {"report": "r"}, repr((builds, got)))


def _p25_request_deadline():
    ran = []
    secs = (("late", "Late", "logs", "request", "full"),)
    with _patched():
        _patch(DR, "SECTIONS", secs)
        _patch(DR, "_section_fn", lambda module, key: lambda ctx: ran.append(key) or Result(lines=["- x"]))
        out = DR._run_sections(Ctx(deadline_s=0.0))
    check("review fix: a request section not started by the deadline is reported as timed out, and "
          "is not run", out["late"][0] == "timeout" and not ran, repr((out, ran)))


def _p25_memo():
    ctx, calls, got = Ctx(), [], []

    def _slow():
        calls.append(1)
        _time25.sleep(0.2)
        return "v"
    dones = [_started(lambda: got.append(ctx.memo("k", _slow))) for _ in range(3)]
    for done in dones:
        done.wait(5)
    check("review fix: the report's memo is single-flight: three sections asking at once make one "
          "read and get its answer", calls == [1] and got == ["v", "v", "v"], repr((calls, got)))
    # Past the deadline a waiter may still be given a wait of its own (the privacy pass waits a
    # little longer for the Tailscale read the Network section is still making).
    late, calls2, got2 = Ctx(deadline_s=0.0), [], []
    first = _started(lambda: late.memo("t", _slow))
    _time25.sleep(0.05)
    try:
        got2.append(late.memo("t", lambda: calls2.append(1) or "second read", wait=2.0))
    except TimeoutError as exc:
        got2.append(exc)
    first.wait(5)
    check("review fix: a memo waiter given its own wait past the deadline gets the read in flight, "
          "not a TimeoutError and not a second read", got2 == ["v"] and not calls2, repr((got2, calls2)))


# ── R6 / C13: the hub-lag watch before its first tick ──────────────────────────────────────────
def _p25_hub_lag():
    saved = {g: dict(_rs25._GROUPS.get(g) or {}) for g in ("hub", "heartbeat", "hub_lag")}
    started = PR._HUB_LAG["started"]
    try:
        _rs25._GROUPS["hub"] = {}
        _rs25._GROUPS.get("heartbeat", {}).pop("hub-lag-watch", None)
        PR._HUB_LAG["started"] = True
        early = PR._lag_text(Result())
        PR._HUB_LAG["started"] = False
        never = PR._lag_text(Result())
        PR.lag_tick({"ticks": 0, "max": -1.0, "minute": None, "minute_max": -1.0}, 0.01)
        beat = _rs25.snapshot("heartbeat").get("hub-lag-watch")
    finally:
        PR._HUB_LAG["started"] = started
        for g, v in saved.items():
            _rs25._GROUPS[g] = v
    check("review fix: before its first tick, a started hub-lag watch is 'not measured yet', not "
          "'runs only under eventlet'; a tick is a heartbeat Background workers can show",
          early.startswith("not measured yet") and "only in a process" in never
          and isinstance(beat, dict) and beat.get("cadence") == 1.0, repr((early, never, beat)))


# ── R7: a hung tailscaled costs Hosts its Tailscale words only ─────────────────────────────────
def _p25_hosts_ts_hung():
    release = _th25.Event()
    ctx = Ctx(deadline_s=2.5)
    ctx._memo["b4.host_cols"] = (True, [{"transport": "tailscale"}])
    res = Result()
    with _patched():
        _patch(HS, "ts_info", lambda c: release.wait(10))
        _patch(HS, "key_present", lambda: True)
        _patch(HS, "_ts_hosts", lambda: {7: "stored"})
        t0 = _time25.monotonic()
        peers = HS.peers_by_host(ctx, res)
        took = _time25.monotonic() - t0
    release.set()
    check("review fix: a Tailscale read that does not answer leaves Hosts printing every host, with "
          "'timed out' for its Tailscale words, before the report's deadline",
          took < 2.0 and peers == {7: "tailscale status timed out"}
          and "- **Tailscale (this node)**: timed out (not shown)" in res.lines, repr((took, peers, res.lines)))


# ── C1 / C6 / C8: At a glance in the summary and the full report ───────────────────────────────
def _p25_glance():
    diag = Result(lines=["- x"], findings=[{"level": "warn", "area": "Diag", "text": "w%d" % i}
                                           for i in range(9)], verdict="**Update**: v")
    long_url = "https://example.invalid/" + "x" * 7900
    with _patched():
        _env(journal="")
        _patch(SO, "_debug_run", lambda argv, timeout=5, cap=None:
               ("no\n", "", 0) if "timedatectl" in argv else ("", "", 1))
        _patch(DG, "section_diagnostics", lambda ctx: diag)
        rep = _gen25()
        _patch(SO, "_github_issues_url", lambda: long_url)
        tight = _gen25()
    summary_glance = rep["summary"].split("### At a glance", 1)[-1].split("\n\n", 1)[0]
    every = rep["report"].split("### All findings", 1)[-1].split("\n\n", 1)[0]
    check("review fix: the full report lists EVERY finding under All findings; At a glance stays at 8 "
          "lines and says where the rest are",
          len(summary_glance.split("\n")) <= 8 and "every one listed under All findings" in summary_glance
          and all("Diag: w%d" % i in every for i in range(9)), summary_glance + "\n--\n" + every)
    ntp = "Host clock: NTP is not synchronized"
    check("review fix: a header finding (NTP not synchronized) appears once in At a glance",
          rep["report"].split("### All findings", 1)[-1].split("\n\n", 1)[0].count(ntp) == 1,
          rep["report"][:2500])
    check("review fix: the issue body's fallback counts every problem, not only the ones shown",
          "Problems: 10; see the attached report." in tight["issue_body"], tight["issue_body"][-200:])


# ── C2: the venv interpreter through install.sh's symlink ──────────────────────────────────────
def _p25_interpreter():
    panel = os.path.join(_TMP25, "panel")
    os.makedirs(os.path.join(panel, "venv", "bin"))
    exe = os.path.join(panel, "venv", "bin", "python3")
    os.symlink(os.path.realpath(sys.executable), exe)
    with open(os.path.join(panel, "venv", "pyvenv.cfg"), "w", encoding="utf-8") as fh:
        fh.write("version = %d.%d.0\n" % sys.version_info[:2])
    with _patched():
        _patch(SO, "PANEL_DIR", panel)
        _patch(sys, "executable", exe)
        _patch(sys, "prefix", os.path.join(panel, "venv"))
        line = INS._interpreter()
    check("review fix: a venv whose python3 is a symlink to the system one (as install.sh makes it) "
          "is the venv, not 'system python'",
          line.startswith("<panel>/venv/bin/python3, ") and "sys.prefix is the venv: yes" in line, line)


# ── C4: no NSS lookups that can fall through to a directory service ────────────────────────────
def _p25_nss():
    import grp
    import pwd
    asked = []

    def _no(name, answer):
        def _f(*a, **k):
            asked.append(name)
            if isinstance(answer, Exception):
                raise answer
            return answer
        return _f
    passwd = os.path.join(_TMP25, "passwd")
    group = os.path.join(_TMP25, "group")
    with open(passwd, "w", encoding="utf-8") as fh:
        fh.write("root:x:0:0::/root:/bin/sh\ncaddy:x:998:998::/:/bin/false\nalice7731:x:1000:1000::/h:/bin/sh\n")
    with open(group, "w", encoding="utf-8") as fh:
        fh.write("lgsmpanel-games:x:990:gameacct7731,other7731\n")
    with _patched():
        _patch(pwd, "getpwall", _no("getpwall", []))
        _patch(pwd, "getpwnam", _no("getpwnam", KeyError("absent")))
        _patch(grp, "getgrnam", _no("getgrnam", KeyError("absent")))
        _patch(PV, "ETC_PASSWD", passwd)
        _patch(PV, "ETC_GROUP", group)
        accts = PV._os_accounts()
        found = CS._proxy_users_existing(["caddy", "nginx", 33])
    check("review fix: OS account names and trusted proxy users come from /etc/passwd and /etc/group, "
          "never from NSS calls that can block the hub on LDAP/SSSD",
          not asked and {"alice7731", "gameacct7731", "other7731"} <= set(accts) and found == (2, 3),
          repr((asked, accts, found)))


# ── C5 / C11 / C12: Serve routes and the running port ──────────────────────────────────────────
def _ts_view(target, mount="/lgsm"):
    return {"version": "1.80.0", "backend_state": "Running", "magic_dns": True, "key_expiry": None,
            "operator_user": None, "health": [], "serve_unreadable": False, "funnel_enabled": False,
            "serve_services": [{"url": "https://n.example", "funnel": False,
                                "routes": [{"mount": mount, "target": target}]}]}


def _serve(boot, target, mount="/lgsm", **cfg):
    base = dict(config.DEFAULT_CONFIG, tailscale_setup_done=True, tailscale_mount="/lgsm", port=5000)
    base.update(cfg)
    app = _Flask25("p25s")
    app.config.update(boot)
    res, facts = Result(), {}
    with _patched():
        _patch(config, "load_config", lambda: dict(base))
        NW._tailscale_lines(Ctx(app=app), res, facts, ("ok", ("ok", _ts_view(target, mount))))
    return res


def _p25_serve():
    texts = lambda r: [f["text"] for f in r.findings]  # noqa: E731
    wrong = _serve({"BOOT_TLS": True, "BOOT_PORT": 5000}, "http://127.0.0.1:5000")
    right = _serve({"BOOT_TLS": True, "BOOT_PORT": 5000}, "https+insecure://127.0.0.1:5000")
    check("review fix: a Serve route to the panel with the wrong backend scheme (Serve answers 502) "
          "is a finding, not only a ✗",
          any("wrong scheme" in t for t in texts(wrong)) and not any("wrong scheme" in t for t in texts(right)),
          repr((texts(wrong), texts(right))))
    moved = _serve({"BOOT_TLS": False, "BOOT_PORT": 5000}, "http://127.0.0.1:5000", mount="/lgsm",
                   tailscale_mount="/")
    check("review fix: after setup, a Serve mount other than the configured tailscale_mount is a "
          "finding", any("configured tailscale_mount" in t for t in texts(moved))
          and not any("configured tailscale_mount" in t for t in texts(right)), repr(texts(moved)))
    pending = _serve({"BOOT_TLS": False, "BOOT_PORT": 5000}, "http://127.0.0.1:5000", port=5001)
    check("review fix: Serve is checked against the port the panel is running on (BOOT_PORT), not a "
          "port change still pending a restart",
          "1 route to the panel" in "\n".join(pending.lines)
          and not any("no Tailscale Serve route" in t for t in texts(pending)), repr(pending.lines))


# ── C7: fail2ban's panel jail ──────────────────────────────────────────────────────────────────
def _p25_f2b():
    status = (0, "Status\n|- Number of jail:\t1\n`- Jail list:\tlinuxgsm-panel\n")
    other = (0, "Status for the jail: linuxgsm-panel\n|- Filter\n|  |- Currently failed:\t0\n"
                "|  |- Total failed:\t0\n|  `- File list:\t/home/old/panel/data/auth.log\n"
                "`- Actions\n   |- Currently banned:\t0\n   |- Total banned:\t0\n")
    found = {}
    for label, panel in (("other", other), ("unread", (1, ""))):
        res, facts = Result(), {}
        with _patched():
            _patch(NW, "auth_log_path", lambda: os.path.join(_TMP25, "auth.log"))
            NW._f2b_runtime_lines(res, facts, {"status": status, "panel": panel, "sshd": "not-read"})
        found[label] = [(f["level"], f["text"]) for f in res.findings]
    check("review fix: a panel jail watching another file is a fail, and one whose read failed is "
          "unread, never silent",
          any(lv == "fail" and "another file" in t for lv, t in found["other"])
          and any(lv == "unread" and "jail could not be read" in t for lv, t in found["unread"]),
          repr(found))


# ── C9 / C10: git timeouts, the CI walk's keys ─────────────────────────────────────────────────
def _p25_git_timeouts():
    seen = []

    def _git(args, timeout=45):
        seen.append((args[0], timeout))
        return ("abc1234", "", 0) if args[0] == "rev-parse" else ("", "", 0)
    with _patched():
        _patch(SO, "_is_git_checkout", lambda: True)
        _patch(SO, "_update_in_progress", lambda: False)
        _patch(SO, "_git", _git)
        SO._compute_panel_integrity()
    check("review fix: the integrity check's git calls carry a timeout of 10 s or less, never _git's "
          "45 s default", len(seen) == 2 and all(t <= 10 for _a, t in seen), repr(seen))


def _p25_ci_walk():
    saved = dict(_rs25._GROUPS.get("ci_walk") or {})
    try:
        _rs25._GROUPS["ci_walk"] = {}
        for i in range(205):
            SO._ci_record("%07x" % (0xa000000 + i), "passing", {"runs": []})
        SO._ci_record("feedbee", "failing", {"runs": []})
        snap = _rs25.snapshot("ci_walk")
    finally:
        _rs25._GROUPS["ci_walk"] = saved
    check("review fix: the CI walk's per-commit answers drop the OLDEST past the cap, so the newest "
          "commit's answer is always there",
          isinstance(snap.get("feedbee"), tuple) and "_dropped" not in snap and len(snap) <= 101,
          repr((len(snap), sorted(snap)[-3:])))


# ── C14 / REG-1: no unit file is a measurement ─────────────────────────────────────────────────
def _p25_no_unit():
    unit = {"scope": None, "props": {}, "error": "unreadable", "rc": None, "why": "no-unit-file"}
    diag = SO._diag_service(unit)
    ctx = Ctx()
    ctx._memo["systemd.unit_show"] = (True, unit)
    res, facts = Result(), {"mainpid_is_me": False, "restarts": None}
    PR._service_lines(ctx, res, facts)
    verdict = PR._verdict(facts)
    check("review fix: no unit file is reported as what it is (the panel does not start at boot), "
          "never as 'systemd state unreadable' or [unread]",
          diag == ("warn", "No systemd unit found — the panel does not start at boot.")
          and "no systemd unit file" in "\n".join(res.lines)
          and [f["level"] for f in res.findings] == ["warn"] and "unread" not in verdict,
          repr((diag, res.lines, res.findings, verdict)))


# ── leads the review left unverified, reproduced and fixed ───────────────────────────────────
def _p25_leads():
    cfg = dict(config.DEFAULT_CONFIG, socketio_cors_origins=["https://proxy7731.example.org"],
               bind_host="bindhost7731.example.org")
    with _patched():
        _patch(config, "load_config", lambda: dict(cfg))
        st = PV._State()
        PV._names_config(None, st)
    ctx = Ctx()
    ctx._memo["privacy"] = (True, st)
    out = PV.scrub(ctx, "engineio: https://proxy7731.example.org is not an accepted origin; bound to "
                        "bindhost7731.example.org:5000 (bindhost7731)")
    check("review fix privacy: the panel's configured origins and a bind_host given as a name are "
          "mapped (engineio logs a refused origin verbatim)",
          "proxy7731" not in out and "bindhost7731" not in out, out)
    out = PV._generic("fetch https://a@b7731.example:tok7731@github.com/x failed", PV._State())
    eq("review fix privacy: URL userinfo holding an unencoded '@' is redacted up to the last '@'",
       out, "fetch https://[redacted]@github.com/x failed")
    foot = PV.footer(ctx)[-1]
    check("review fix privacy: the footer does not claim a deleted host NAME is still caught",
          "a host NAME deleted since is not" in foot and "their addresses are still caught" not in foot, foot)
    with _patched():
        _patch(SO, "_helper_present", lambda: False)
        _patch(SO, "_SUDO_PROBE", {"ok": True, "at": _time25.time() - 86400})
        stale = NW._sudo_cached_ok()
        _patch(SO, "_SUDO_PROBE", {"ok": True, "at": _time25.time() - 10})
        fresh = NW._sudo_cached_ok()
    check("review fix: a passwordless-sudo answer older than its TTL does not let the report run "
          "`sudo -n` (a refused one may count toward pam_faillock); a fresh one does",
          stale is False and fresh is True, repr((stale, fresh)))


# ── found on the test VPS (a system install with the helper) ───────────────────────────────────
# Every helper call writes three journal lines (sudo's COMMAND line, pam_unix's session opened and
# closed), about three calls a minute: the 400-line tail and every "most repeated" line were those.
_VPS25_LOG = "\n".join(
    ["Oct 03 02:%02d:41 vps sudo[%d]: lgsmpanel : PWD=/home/lgsmpanel/linuxgsm-panel ; USER=root ; "
     "COMMAND=/usr/local/lib/linuxgsm-panel/panel-helper restart-flags" % (i % 60, 1000 + i)
     for i in range(150)]
    + ["Oct 03 02:%02d:41 vps sudo[%d]: pam_unix(sudo:session): session opened for user root(uid=0) by "
       "(uid=999)" % (i % 60, 1000 + i) for i in range(150)]
    + ["Oct 03 02:59:49 vps sudo[2999]: lgsmpanel :  PWD=/home/x ; USER=root ; "
       "COMMAND=/usr/local/lib/linuxgsm-panel/panel-helper ufw-status plain ",
       "Oct 03 02:59:50 vps sudo[3000]: lgsmpanel : PWD=/home/x ; USER=root ; COMMAND=/usr/bin/su "
       "canarygameacct7731",
       "Oct 03 02:59:51 vps sudo[3001]: lgsmpanel : a password is required ; PWD=/home/x ; USER=root ; "
       "COMMAND=/usr/bin/true",
       "Oct 03 02:59:52 vps python3[1234]: WARNING panel.monitor: canary panel line 7731"])


def _p25_vps():
    with _patched():
        _env(journal=_VPS25_LOG)
        rep = _gen25()["report"]
    log = rep.split("### Recent log", 1)[-1]
    digest = rep.split("### Errors in the journal", 1)[-1].split("### Recent log", 1)[0]
    check("VPS fix: the panel's own sudo calls are counted by helper verb and left out of the recent "
          "log; a REFUSED sudo and the panel's own lines stay in it",
          "Privileged calls (left out below)" in log and "restart-flags ×150" in log
          and "pam_unix(sudo:session)" not in log and "COMMAND=" not in log.split("```", 1)[-1]
          .replace("a password is required ; PWD=/home/[user] ; USER=root ; COMMAND=", "")
          and "a password is required" in log and "canary panel line 7731" in log, log[:1500])
    check("VPS fix: ...the digest's 'most repeated lines' are not the panel's own sudo calls, and a "
          "sudo COMMAND's argument (an account, for su) is never printed as a verb",
          "pam_unix(sudo:session)" not in digest and "restart-flags ×150" in digest
          and "other command ×1" in digest and "canarygameacct7731" not in rep, digest[:1200])
    check("VPS fix: ...sudo-rs's spacing ('user :  PWD=... plain ', two blanks and a trailing one) "
          "is counted too, as the verb it ran",
          "ufw-status ×1" in log and "ufw-status ×1" in digest, log[:600])
    out = PV._paths("COMMAND=/usr/local/lib/linuxgsm-panel/panel-helper restart-flags", PV._State())
    check("VPS fix: the helper's path prints as <panel-lib>/panel-helper, not one long token that "
          "_redact turns into '/[redacted]'",
          out == "COMMAND=<panel-lib>/panel-helper restart-flags"
          and SO._redact(out) == out, repr(out))
    with _patched():
        _patch(sys, "prefix", "/opt/othervenv7731")
        _patch(sys, "base_prefix", "/usr")
        _patch(sys, "executable", "/opt/othervenv7731/bin/python3")
        other = INS._interpreter()
        _patch(sys, "prefix", "/usr")
        _patch(sys, "executable", "/usr/bin/python3")
        system = INS._interpreter()
    check("VPS fix: a virtualenv that is not this checkout's is named as one, not 'system python' "
          "(its python resolves to the system binary); a real system python still is",
          other.startswith("a virtualenv outside this checkout")
          and system.startswith("system python"), repr((other, system)))


try:
    _seed25()
    for _fn25 in (_p25_update_tail, _p25_tailscale_error, _p25_addresses, _p25_git_raises, _p25_cuts,
                  _p25_names, _p25_host_first_label, _p25_single_flight_busy, _p25_request_deadline,
                  _p25_memo, _p25_hub_lag, _p25_hosts_ts_hung, _p25_glance, _p25_interpreter, _p25_nss,
                  _p25_serve, _p25_f2b, _p25_git_timeouts, _p25_ci_walk, _p25_no_unit, _p25_leads,
                  _p25_vps):
        _fn25()
except Exception as _e25:  # noqa: BLE001 - a harness failure must fail by name, not end the suite
    import traceback as _tb25
    check("debug report: the part25 harness ran to the end", False,
          "raised %s: %s @ %s" % (type(_e25).__name__, _e25, _tb25.format_exc()[-600:]))
finally:
    import shutil as _sh25
    _sh25.rmtree(_TMP25, ignore_errors=True)
