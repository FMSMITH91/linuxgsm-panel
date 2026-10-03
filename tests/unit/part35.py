"""Part 35 of the unit suite: the debug report's accuracy fixes from the live report's triage (ws5).

Each check here fails on the tree before the fix, and names the line of the live report it holds:
* the email rule took systemd template units (user@1000.service in a cgroup path, getty@tty1) and
  npm package@version for addresses and printed [email];
* installer lines were redacted BEFORE their paths were normalised, so the data, helper and gamedig
  paths read '/[redacted]', a verified commit read 'verified commit [redacted]' and an address lost
  its class; the 'Installer said' block repeated key lines the tail already showed;
* the Privacy footer counted only the name and IP pass, never _redact's [email]/[redacted];
* Tailscale's health messages printed as a bare count, though the text was already read;
* a node whose key expiry is disabled read 'node key expiry not recorded';
* with nothing to verify, the CI gate line read 'ci_state=passing · target ?'; the offered commit
  printed as origin/<branch>'s tip; the announced-commit line could never say 'none';
* loops that sleep before their first pass read 'never completed a pass' at 15 s uptime (and a
  first pass long overdue read like one not due), and the host summary said 'not yet probed'
  with no reason;
* with trust_proxy off, a loopback account other than root sending X-Forwarded-For was refused but
  never counted, so 'Forwarding headers ignored, last hour: none' was not a reading.

HOW IT RUNS. Every read is stubbed on the module that defines it, through part20's _patch and
_patched (undone at the end of each block); runtime_stats groups and auth's ignored-proxy record
are saved and restored. The privacy map is built in memory (part25's _ctx_with), so nothing is read
from the host's database. The loops are driven with a sleep that raises, and their first-pass
records are also gated by an AST walk of the loop files. Nothing is written outside memory.
"""
import ast as _ast35
import logging as _logging35
import pathlib as _pathlib35
import sys as _sys35
import time as _time35
import traceback as _tb35
from types import SimpleNamespace as _NS35

from flask import Flask as _Flask35

from unit.part01 import SO, check, config, eq
from unit.part20 import _patch, _patched
from unit.part25 import _ctx_with
from panel.core import runtime_stats as _rs35
from panel.ops import tailscale_integration as _ts35
from panel.ops.debug_report import _src_tailscale as STS
from panel.ops.debug_report import config_section as CS
from panel.ops.debug_report import hosts as HS
from panel.ops.debug_report import network as NW
from panel.ops.debug_report import privacy as PV
from panel.ops.debug_report import updates as UP
from panel.ops.debug_report import workers as WK
from panel.ops.debug_report._base import Ctx, Result
from panel.security import auth as _auth35

_REPO35 = _pathlib35.Path(__file__).resolve().parents[2]
_SHA35 = "8139d8bc4f0e11223344556677889900aabbccdd"
_PIN35 = "86843af0bbbb1122334455667788990011223344"


# ── 1. the email rule and systemd template units ───────────────────────────────────────────────
_UNITS35 = ("/user.slice/user-1000.slice/user@1000.service/app.slice/linuxgsm-panel.service",
            "Started getty@tty1.service - Getty on tty1.", "Started openvpn@server.service.",
            "Reached getty@tty1.target", "No matching version found for gamedig@5.3.3",
            "inflight@1.0.6: deprecated", "gamedig@5.0.0-beta.2",
            "dbus-:1.2-org.freedesktop.systemd1@0.service")
_ADDRS35 = (("someone@example.com", "[email]"), ("a.b@mail.example.services", "[email]"),
            ("bob@host.service.example.com", "[email]"), ("mail alice@example.com.", "mail [email]"),
            ("acct@203.0.113.5", "[email]"), ("a@b.service@c.com", "a@[email]"),
            ("x@1.service then bob@example.com", "x@1.service then [email]"))


def _p35_units():
    ctx, _st = _ctx_with()
    kept = {t: (SO._redact(t), PV.scrub(ctx, t)) for t in _UNITS35}
    check("email rule: a systemd template unit (user@1000.service in a cgroup path, getty@tty1, "
          "a trailing dot, .target) and a package@version are not addresses, in _redact and in "
          "the report's privacy pass",
          all(a == t and b == t for t, (a, b) in kept.items()),
          repr({t: v for t, v in kept.items() if v != (t, t)}))
    got = [SO._redact(t) for t, _w in _ADDRS35]
    eq("email rule: ...while an address still is, at a .services domain, a unit-looking label "
       "inside a domain, a dotted quad, and one glued after (or following) a kept unit",
       got, [w for _t, w in _ADDRS35])


# ── 2. installer lines: paths before _redact, the installer's own commit ids ───────────────────
def _installer_lines35(data):
    return {
        "backup": ("→ %s/.backups/20261003-084009" % data, "<data>/.backups/20261003-084009"),
        "helper": ("  helper installed at /usr/local/lib/linuxgsm-panel/panel-helper",
                   "helper installed at <panel-lib>/panel-helper"),
        "dbm": ("running /usr/local/lib/linuxgsm-panel/db_maintenance.py",
                "<panel-lib>/db_maintenance.py"),
        "gamedig": ("gamedig: /usr/local/lib/linuxgsm-panel/gamedig/current/node_modules/.bin/gamedig",
                    "<gamedig>/current/node_modules/.bin/gamedig"),
        "pin": ("  Updating to verified commit %s" % _SHA35, "Updating to verified commit 8139d8bc4f0e"),
        "stay": ("  Keeping %s: it is on main and already contains the verified commit %s"
                 % (_SHA35, _PIN35), "Keeping 8139d8bc4f0e: it is on main and already contains the "
                                     "verified commit 86843af0bbbb"),
        "ip": ("  Panel: https://81.2.13.77:5000 (and https://127.0.0.1:5000 here)",
               "https://[ip:public]:5000 (and https://127.0.0.1:5000 here)"),
    }


def _p35_installer_paths():
    ctx, _st = _ctx_with(("zephyrhost7731", "host", 1))
    data = "/home/zephyracct/linuxgsm-panel/data"           # the live per-user layout (31 chars)
    with _patched():
        _patch(config, "DATA_DIR", _pathlib35.Path(data))
        cases = _installer_lines35(data)
        got = {k: UP.clean_line(line, "canonical", ctx) for k, (line, _w) in cases.items()}
        secret = UP.clean_line("token %s/AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMIK7MDENG/bPxRfiCYEXAMPLEKEY"
                               % data, "canonical", ctx)
    bad = {k: got[k] for k, (_l, want) in cases.items() if want not in got[k]}
    check("installer lines: the data, helper and gamedig paths print as <data>, <panel-lib> and "
          "<gamedig>, a verified commit as 12 characters, an address by its class, loopback kept",
          not bad and not any("[redacted]" in v for v in got.values()), repr(bad or got))
    check("installer lines: ...and a slash-split secret right after <data>/ is still redacted "
          "(no hold on the path after a normalised token)",
          "AKIA" not in secret and "wJalr" not in secret and "[redacted]" in secret, secret)


def _p35_installer_musts():
    ctx, _st = _ctx_with(("zephyrhost7731", "host", 1))
    musts = {"b64": "key qZ3vT8rW1yX5uA9sD2fG7hJ4kL6mN0pQ end",
             "hex": "sha 0123456789abcdef0123456789abcdef01234567 elsewhere",
             "split": "x abcdefghijklmn-zephyrhost7731-opqrstuvwxyz0123456 y"}
    out = {k: UP.clean_line(v, "canonical", ctx) for k, v in musts.items()}
    check("installer lines: a 40-character token, a 40-hex value outside the installer's own "
          "messages, and a long token holding a known name are each one [redacted] (_redact runs "
          "before the name pass, so the name cannot split the token into short fragments)",
          all("[redacted]" in v for v in out.values()) and "abcdefghijklmn" not in out["split"]
          and "0123456789abcdef" not in out["hex"] and "qZ3vT8" not in out["b64"], repr(out))
    eq("installer lines: without the report's ctx the old reduction stands ([userinfo], [ip])",
       UP.clean_line("fetch https://bob:pw@example.org/x from 81.2.13.77"),
       "fetch https://[userinfo]@example.org/x from [ip]")


def _tail35(lines, ctx):
    upd = {"exists": True, "exit_code": 0, "lines": lines}
    res = Result()
    UP._tail_lines(res, upd, "canonical", ctx)
    text = "\n".join(res.lines)
    return text.split("```", 1)[0], text


def _p35_installer_said():
    ctx, _st = _ctx_with()
    pip = ["  Collecting package%02d" % i for i in range(30)]
    said, _text = _tail35(["  Updating to verified commit %s" % _SHA35] + pip
                          + ["[!] a late warning", "✓ Code updated (abc1234 → 8139d8b)"], ctx)
    check("installer said: a key line the printed tail already shows is not repeated above it; one "
          "pushed out of the tail is kept, and a warning is always kept",
          "Updating to verified commit 8139d8bc4f0e" in said and "[!] a late warning" in said
          and "Code updated" not in said, said)


# ── 3. the Privacy footer counts every replacement ─────────────────────────────────────────────
def _redacted_line35(ctx):
    return next((ln for ln in PV.footer(ctx) if ln.startswith("- **Redacted**")), "")


def _p35_footer_counts():
    ctx, _st = _ctx_with()
    text = ("unit user@1000.service; mail someone@example.com; token "
            "qZ3vT8rW1yX5uA9sD2fG7hJ4kL6mN0pQ; password=hunter2xyz; fetch https://bob:pw@example.org/x")
    PV.scrub(ctx, text)
    PV.scrub(ctx, text)                                   # the summary and the report each scrub
    red = _redacted_line35(ctx)
    pseud = next((ln for ln in PV.footer(ctx) if ln.startswith("- **Pseudonymised**")), "")
    check("privacy footer: _redact's replacements are counted under Redacted, as distinct values "
          "(two passes over the same text count each once), never under Pseudonymised",
          all(w in red for w in ("1 email-shaped string;", "1 long token;", "1 key=value secret;",
                                 "1 URL credential or login link")) and "email" not in pseud, red)


def _p35_footer_installer():
    ctx, _st = _ctx_with()
    data = "/home/zephyracct/linuxgsm-panel/data"
    lines = ["  Updating to verified commit %s" % _SHA35, "→ %s/.backups/20261003-084009" % data,
             "  Panel: https://81.2.13.77:5000", "  key qZ3vT8rW1yX5uA9sD2fG7hJ4kL6mN0pQ"]
    with _patched():
        _patch(config, "DATA_DIR", _pathlib35.Path(data))
        _said, text = _tail35(lines, ctx)
    foot = "\n".join(PV.footer(ctx))
    check("privacy footer: installer lines through the updates section are counted too (the IP by "
          "class, the long token), and print the <data> path the footer promises",
          "1 IPs (1 public)" in foot and "1 long token" in foot and "<data>/.backups/" in text
          and "<gamedig>" in foot, foot + "\n" + text)


# ── 4. Tailscale: health messages, key expiry, the control host ─────────────────────────────────
_LONGX35 = "x " * 75


def _tinfo35(status=None, prefs=None, version="1.102.4"):
    ti = _ts35.TailscaleInfo(installed=True, running=True, backend_state="Running", version=version,
                             hostname="zephyrbox7731", dns_name="zephyrbox7731.tail7731cd.ts.net",
                             tailscale_ips=["100.77.35.1"])
    ti.status_json, ti.prefs_json = status, prefs
    return STS.as_dict(ti)


def _health_v35():
    health = ["Some peers are advertising routes but --accept-routes is false",
              "node zephyrbox7731 owned by alicezz7731@example.com",
              "likely intercepted connection; certificate is self-signed by CN=p,O=Zephyr Holdings",
              "connection to derp7731.zephyr-family.net failed:\n   dial tcp 81.2.13.77:443: timeout",
              _LONGX35 + "Alice Quokkason is logged out", "six", "seven"]
    status = {"BackendState": "Running", "Health": health,
              "Self": {"HostName": "zephyrbox7731", "InNetworkMap": True,
                       "KeyExpiry": "2099-01-01T00:00:00Z"},
              "User": {"1": {"LoginName": "alicezz7731@example.com",
                             "DisplayName": "Alice Quokkason"}}}
    return _tinfo35(status, {"OperatorUser": "nobody"})


def _p35_health():
    ctx, _st = _ctx_with()
    v = _health_v35()
    res = Result()
    with _patched():
        _patch(NW, "_load_cfg", lambda: ({"port": 5000}, True))
        NW._tailscale_lines(ctx, res, {}, ("ok", ("ok", v)))
    PV.map_tailscale(ctx, v)                 # what the assembler's finish() maps, then its pass
    final = PV.scrub(ctx, "\n".join(res.lines))
    _health_checks35(final, [ln for ln in res.lines if ln.startswith("  - health: ")], res)


def _health_checks35(final, shown, res):
    low = final.lower()
    check("tailscale health: each message prints on its own line under the count, plain text "
          "verbatim, with '+N more' past five",
          "health warnings 7" in final and len(shown) == 6 and shown[-1] == "  - health: +2 more"
          and "  - health: Some peers are advertising routes but --accept-routes is false" in final
          and not any("\n" in ln for ln in shown), final)
    check("tailscale health: ...pseudonymised: no node or login name, no self-hosted domain, no "
          "certificate issuer, an address by class, and a two-word display name at the cut never "
          "leaves a fragment",
          not any(w in low for w in ("zephyrbox", "alice", "quokkason", "zephyr-family", "holdings",
                                     "81.2.13.77")) and "[ip:public]" in final
          and "[domain]" in final, final)
    check("tailscale health: a non-empty list raises no finding (Health carries no severity)",
          not any("health" in f["text"].lower() for f in res.findings), repr(res.findings))


def _p35_control_host():
    own = _tinfo35({"Self": {}}, {"ControlURL": "https://controlplane.tailscale.com"})
    hosted = _tinfo35({"Self": {}}, {"ControlURL": "https://hs.zephyr7731.example:443"})
    ctx, st = _ctx_with()
    PV._names_tailscale(hosted, st)
    out = PV.scrub(ctx, "dial hs.zephyr7731.example failed; controlplane.tailscale.com ok")
    check("tailscale: a self-hosted control server's host is mapped (it names the operator); "
          "Tailscale's own is not",
          own["control_host"] is None and hosted["control_host"] == "hs.zephyr7731.example"
          and "zephyr7731" not in out and "controlplane.tailscale.com ok" in out, out)


def _p35_key_expiry():
    shapes = {
        "disabled": ({"BackendState": "Running", "Self": {"InNetworkMap": True,
                                                          "Tags": ["tag:server"]}}, "1.102.4"),
        "needslogin": ({"BackendState": "NeedsLogin", "Self": {"OS": "linux", "Online": False}},
                       "1.102.4"),
        "old": ({"BackendState": "Running", "Self": {"InNetworkMap": True}}, "1.34.0"),
        "expires": ({"Self": {"InNetworkMap": True, "KeyExpiry": "2099-01-01T00:00:00Z"}},
                    "1.102.4"),
        "none": (None, "1.102.4"),
    }
    heads = {k: NW._ts_head(_tinfo35(s, None, ver)) for k, (s, ver) in shapes.items()}
    check("tailscale key expiry: a node in the network map with no KeyExpiry reads 'disabled' (a "
          "tagged node, or expiry turned off)",
          "node key expiry disabled (tagged node or expiry turned off)" in heads["disabled"],
          heads["disabled"])
    check("tailscale key expiry: ...never with no netmap (NeedsLogin builds Self without it), nor "
          "on a Tailscale before 1.36 (no such field); an expiry and no status as before",
          "unknown (not in the network map)" in heads["needslogin"]
          and "unknown (this Tailscale version does not report it)" in heads["old"]
          and "node key expires in" in heads["expires"]
          and "node key expiry not recorded" in heads["none"]
          and not any("disabled" in heads[k] for k in ("needslogin", "old", "expires", "none")),
          repr(heads))


# ── 5. updates: the CI gate line, the offered commit, the announced commit ──────────────────────
_TIP35 = "25dbe36" + "0" * 33


def _status35(data):
    res = Result()
    UP._status_lines(data, res)
    return "\n".join(res.lines)


def _p35_ci_gate():
    base = {"branch": "main", "current_sha": "abc1234", "fetched": True, "update_available": False}
    shapes = {
        "current": dict(base, remote_sha="abc1234", ci_state="passing", behind=0),
        "ahead": dict(base, current_sha="784988a", remote_sha="3af77a4", ci_state="passing", behind=0),
        "nofetch": {"git": True, "fetched": False, "update_available": False,
                    "current_sha": "abc1234", "branch": "main"},
        "tip": dict(base, remote_sha="3af77a4", ci_state="pending", behind=1, behind_tip=1,
                    target_sha=_TIP35),
        "offered": dict(base, update_available=True, remote_sha="25dbe36", ci_state="passing",
                        behind=2, behind_tip=3, newer_unverified=1, docs_only=False,
                        target_sha=_TIP35),
        "failing": dict(base, remote_sha="def5678", behind=3, behind_tip=3, ci_state="failing",
                        target_sha="d" * 40, docs_only=False),
    }
    t = {k: _status35(v) for k, v in shapes.items()}
    check("updates CI gate: not behind is 'not consulted', never 'ci_state=passing · target ?', and "
          "not 'the tip' (behind 0 covers a checkout ahead of origin too)",
          all("not consulted: HEAD is not behind origin/main, nothing newer to verify" in t[k]
              and "target ?" not in t[k] and "ci_state=" not in t[k] and "is the tip" not in t[k]
              for k in ("current", "ahead")), t["current"] + "\n" + t["ahead"])
    check("updates CI gate: a check that never got that far says so, not 'unverified tip ?'",
          "not consulted (the check did not get that far)" in t["nofetch"]
          and "?" not in t["nofetch"].split("**CI gate**", 1)[1], t["nofetch"])
    check("updates CI gate: an unverified tip is named as one, and a key the status lacks is n/a",
          "ci_state=pending · newest unverified tip 25dbe36 · newer_unverified n/a · docs_only: n/a"
          in t["tip"], t["tip"])
    check("updates CI gate: the offered commit is not printed as origin/main's tip while newer "
          "commits are still verifying",
          "origin/main 25dbe36" not in t["offered"]
          and "offered 25dbe36 (1 newer on origin/main, not yet verified)" in t["offered"]
          and "ci_state=passing · target 25dbe36 · newer_unverified 1 · docs_only: no" in t["offered"],
          t["offered"])
    check("updates CI gate: a gated status reads as before (ci_state, target, behind)",
          "ci_state=failing · newest unverified tip ddddddd" in t["failing"] and "behind 3" in t["failing"],
          t["failing"])


def _p35_announced():
    from panel.routes import os_updates as _osu35
    store = {}
    with _patched():
        _patch(config, "load_config", lambda: dict(store))
        _patch(_osu35, "load_config", lambda: dict(store))
        _patch(_osu35, "update_config", lambda m: m(store))
        unset = UP._announced()
        store["panel_update_announced"] = _TIP35
        full = UP._announced()
        _osu35._update_tick(None, {"update_available": False}, _TIP35)   # the writer: "" for none
        written = (store.get("panel_update_announced"), UP._announced())
        store["panel_update_announced"] = "garbage"
        bad = UP._announced()
        store["panel_update_announced"] = ""
        _patch(SO, "_update_cache", {"ts": _time35.time(), "data": {
            "update_available": False, "branch": "main", "current_sha": "abc1234",
            "remote_sha": "abc1234", "ci_state": "passing", "behind": 0}})
        _patch(SO, "_update_in_progress", lambda: False)
        res = Result()
        UP._cache_lines(res)
    eq("updates: the announced commit reads 'none' unset and once the update check wrote '' for "
       "it; a commit as 7; '?' only for a value that is not one",
       (unset, full, written, bad), ("none", "25dbe36", ("", "none"), "?"))
    check("updates: ...and the rendered line says so",
          "- **Last 'update available' notification**: none" in res.lines, repr(res.lines))


# ── 6. workers: a first pass not yet due, from the loop's own record ────────────────────────────
class _Stop35(Exception):
    """Raised by a fake sleep to end a loop at its first sleep."""


def _groups35(fn):
    saved = {g: _rs35._GROUPS.get(g) for g in ("heartbeat", "loop_start")}
    try:
        return fn()
    finally:
        for g, v in saved.items():
            if v is None:
                _rs35._GROUPS.pop(g, None)
            else:
                _rs35._GROUPS[g] = v


def _workers35():
    now = _time35.time()
    _rs35._GROUPS["heartbeat"] = {}
    _rs35._GROUPS["loop_start"] = {"monitor": (now, 60), "update-check": (now - 300, 30)}
    with _patched():
        _patch(WK, "threads_by_name", lambda: {})
        res = WK.section_workers(Ctx())
    lines = {ln.split(":", 1)[0][2:]: ln for ln in res.lines if ln.startswith("- ")}
    check("workers: a loop whose first pass is not due yet says so, with when (live: eight loops "
          "read 'never completed a pass' at 15 s uptime)",
          "first pass not due yet (due in" in lines.get("monitor", "")
          and "never completed" not in lines.get("monitor", ""), repr(lines.get("monitor")))
    check("workers: ...one whose first pass was due long ago says when it was due, not just the "
          "cadence; a loop with no delay reads as before",
          "the first was due 30 s after the loop started, 4 m ago" in lines.get("update-check", "")
          and "every 30 m" not in lines.get("update-check", "")
          and "never completed a pass since start (" in lines.get("player-counts", ""),
          repr((lines.get("update-check"), lines.get("player-counts"))))


def _hosts35():
    now = _time35.time()
    _rs35._GROUPS["heartbeat"] = {}
    _rs35._GROUPS["loop_start"] = {"monitor": (now, 60)}
    ctx = Ctx()
    ctx._memo["b4.host_cols"] = (True, [{"id": 1, "transport": "local"}])
    with _patched():
        _patch(HS, "monitor_map", lambda name: {})
        res = Result()
        HS._brief_hosts(ctx, res)
        _rs35._GROUPS["heartbeat"] = {"monitor": {"at": now, "cadence": 60, "passes": 1}}
        later = Result()
        HS._brief_hosts(ctx, later)
    check("hosts: 'not yet probed' says the monitor has completed no pass, and when its first is "
          "due; once the monitor has passed, a host added since needs no note",
          "1 not yet probed (the monitor has completed no pass yet: first pass due in" in res.lines[0]
          and later.lines[0].endswith("1 not yet probed"), repr((res.lines, later.lines)))


def _update_cold35():
    _rs35._GROUPS["loop_start"] = {"update-check": (_time35.time(), 30)}
    with _patched():
        _patch(SO, "_update_cache", {"ts": 0.0, "data": None})
        res = Result()
        UP._cache_lines(res)
    check("updates: a status not computed yet says when the update check's first pass is due, "
          "from its own record (no second copy of its 30 s delay)",
          "not computed since the panel started; update check: first pass due in" in res.lines[0]
          and "after boot" not in res.lines[0], repr(res.lines))


def _p35_workers():
    for fn in (_workers35, _hosts35, _update_cold35):
        _groups35(fn)


def _drive35(owner, fn):
    def _sleep(_s):
        raise _Stop35()
    _rs35._GROUPS["loop_start"] = {}
    with _patched():
        _patch(owner, "time", _NS35(time=_time35.time, monotonic=_time35.monotonic, sleep=_sleep))
        try:
            fn()
        except _Stop35:
            pass
    return dict(_rs35._GROUPS.get("loop_start") or {})


def _p35_loops_record():
    from panel.services import monitoring as _mon35
    app_mod = _sys35.modules["app"]
    got = _groups35(lambda: (_drive35(app_mod, lambda: app_mod._monitor_watch(None)),
                             _drive35(_mon35, lambda: _mon35._reboot_when_empty_watch(None)),
                             _drive35(app_mod, lambda: app_mod._autoblock_watch(None))))
    check("loops: the monitor, reboot-when-empty and autoblock loops record their first pass's "
          "delay BEFORE they sleep",
          [{k: v[1] for k, v in g.items()} for g in got]
          == [{"monitor": 60}, {"reboot-when-empty": 60}, {"autoblock": 3600}], repr(got))


_LOOP_FILES35 = ("app.py", "panel/services/monitoring.py", "panel/routes/server_files.py",
                 "panel/routes/os_updates.py", "panel/routes/host_terminal.py",
                 "panel/ops/terminal_session.py", "panel/ops/debug_report/process.py")


def _call_name35(node):
    if isinstance(node, _ast35.Expr) and isinstance(node.value, _ast35.Call):
        f = node.value.func
        return getattr(f, "attr", None) or getattr(f, "id", None)
    return None


def _first_sleep35(body):
    """The delay node of a body's first statement when it is a sleep (or a while whose is)."""
    stmt = body[0] if body else None
    if isinstance(stmt, _ast35.While) and stmt.body:
        stmt = stmt.body[0]
    if _call_name35(stmt) == "sleep":
        return stmt.value.args[0] if stmt.value.args else None
    return None


def _loop_first_pass35(fn_node):
    """(records a first pass, problem or None) of one function that beats."""
    body = [s for s in fn_node.body if not (isinstance(s, _ast35.Expr)
                                            and isinstance(s.value, _ast35.Constant))]
    if _first_sleep35(body) is not None:
        return False, "sleeps before its first pass with no loop_started record"
    if _call_name35(body[0] if body else None) != "loop_started":
        return False, None
    delay = body[0].value.args[1]
    sleep = _first_sleep35(body[1:])
    if sleep is None or _ast35.dump(sleep) != _ast35.dump(delay):
        return True, "records a first-pass delay that is not the sleep that follows it"
    return True, None


def _p35_loops_gate():
    bad, recorded = [], 0
    for rel in _LOOP_FILES35:
        tree = _ast35.parse((_REPO35 / rel).read_text(encoding="utf-8"))
        for node in _ast35.walk(tree):
            if not isinstance(node, _ast35.FunctionDef):
                continue
            beats = [n for n in _ast35.walk(node) if isinstance(n, _ast35.Call)
                     and getattr(n.func, "attr", None) == "beat"]
            if not beats:
                continue
            got, problem = _loop_first_pass35(node)
            recorded += got
            if problem:
                bad.append("%s:%s %s" % (rel, node.name, problem))
    check("loops: every beating loop that sleeps before its first pass records that delay first, "
          "and the delay it records is the one it sleeps (all eight)",
          not bad and recorded == 8, repr((bad, recorded)))


# ── 7. trust_proxy off: a refused loopback account is counted, the believed basis named ────────
class _Logged35(_logging35.Handler):
    def __init__(self):
        _logging35.Handler.__init__(self)
        self.got = []

    def emit(self, record):
        self.got.append(record.getMessage())


def _p35_trust_proxy():
    app = _Flask35("p35proxy")
    app.config["_TRUST_PROXY"] = False
    saved = dict(_auth35._ignored_proxy_warned)
    log, logger = _Logged35(), _logging35.getLogger("panel.app")
    was = (logger.disabled, logger.level)
    logger.disabled = False                  # an earlier part may leave it off (or above WARNING)
    logger.setLevel(_logging35.WARNING)
    logger.addHandler(log)
    env = {"REMOTE_ADDR": "127.0.0.1"}
    try:
        _auth35._ignored_proxy_warned.clear()
        with _patched():
            _patch(_auth35, "_loopback_peer_uid_memo", lambda: 1001)
            with app.test_request_context("/", headers={"X-Forwarded-For": "81.2.13.77"},
                                          environ_base=env):
                refused = _auth35._request_came_through_proxy("127.0.0.1")
            peers = CS._ignored_peers()
            _patch(_auth35, "_loopback_peer_uid_memo", lambda: 0)
            res = Result()
            with app.test_request_context("/", headers={"X-Forwarded-For": "81.2.13.77"},
                                          environ_base=env):
                believed = _auth35._request_came_through_proxy("127.0.0.1")
                NW._request_lines(res, app.config)
    finally:
        logger.removeHandler(log)
        logger.disabled, logger.level = was
        _auth35._ignored_proxy_warned.clear()
        _auth35._ignored_proxy_warned.update(saved)
    warned = [m for m in log.got if m.startswith("ignoring X-Forwarded-For")]
    check("trust_proxy off: a loopback account other than root sending X-Forwarded-For is refused "
          "AND counted, so 'Forwarding headers ignored' is a reading; its log line names no setting "
          "that does nothing without trust_proxy",
          refused is False and peers == {"loopback non-proxy account": 1} and len(warned) == 1
          and "trusted_prox" not in warned[0], repr((refused, peers, warned)))
    check("trust_proxy off: ...root's (tailscaled's) headers are believed, and the line names that "
          "basis rather than reading as a contradiction of 'trust_proxy: false'",
          believed is True and any("forwarded headers believed: yes (a root-owned loopback peer: "
                                   "tailscaled)" in ln for ln in res.lines), repr(res.lines))


for _fn35 in (_p35_units, _p35_installer_paths, _p35_installer_musts, _p35_installer_said, _p35_footer_counts,
              _p35_footer_installer, _p35_health, _p35_control_host, _p35_key_expiry,
              _p35_ci_gate, _p35_announced, _p35_workers, _p35_loops_record, _p35_loops_gate,
              _p35_trust_proxy):
    try:
        _fn35()
    except Exception as _e35:  # noqa: BLE001 - a harness failure must fail by name, not end the suite
        check("part35: %s ran to the end" % _fn35.__name__, False,
              "raised %s: %s @ %s" % (type(_e35).__name__, _e35, _tb35.format_exc()[-800:]))
