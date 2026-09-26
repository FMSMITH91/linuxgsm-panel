"""Part 11 of the unit suite: host management, Tailscale and the remote-VPS routes.

Imported for its side effects.

Coverage-driven, but every check asserts what the code DID — the verb it sent, the value it
returned, the thing it refused — never only that it ran. The failure paths get the attention: a
read that did not happen must not come back reading as an empty or healthy host.

NOTHING HERE LEAVES THE PROCESS. Each section replaces the transport at its definition site
(panel.ops.ssh_manager._core — see that package's docstring for why the package itself is the wrong
place) and puts it back in a `finally`. A tripwire on the real exec primitives, armed for the whole
part and checked at the end, catches any path that slipped past a stub: a unit check that reached
paramiko, the ssh CLI or a local subprocess would be running against whatever machine the suite is
on. Transports differ in how they fail — paramiko RAISES, tailscale/local return ("", err, -1) — so
the failure branches below are driven both ways where the code treats them differently.
"""
from unit.part01 import (NS, SO, _sm_core, _sm_files, _sm_firewall, _sm_hosts, check, eq, os, re, sys)  # noqa: F401,E402

import json as _p8_json  # noqa: E402
import subprocess as _p8_subprocess  # noqa: E402
import time as _p8_time  # noqa: E402

from panel.ops import tailscale_integration as _tsi  # noqa: E402
from panel.security import privileged as _p8_priv  # noqa: E402

# ── the tripwire: the real exec primitives must not run during this part ────────────────────────
_p8_trips = []
_p8_real = {n: getattr(_sm_core, n) for n in
            ("get_connection", "_run_via_ssh_cli", "_run_local", "_exec_local_argv")}


def _p8_tripwire(name):
    def _t(*a, **k):
        _p8_trips.append(name)
        raise ConnectionError("unit tripwire: %s reached a real transport" % name)
    return _t


for _n in _p8_real:
    setattr(_sm_core, _n, _p8_tripwire(_n))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# tailscale_integration — the panel host's own Tailscale
# ════════════════════════════════════════════════════════════════════════════════════════════════
_ts_saved = {k: getattr(_tsi, k) for k in (
    "subprocess", "socket", "_run_ts", "_run_ts_json", "_get_tailscale_info", "get_tailscale_info",
    "ensure_operator", "allow_tailscale_ufw", "_current_os_user")}
_ts_so_saved = {"_run_verb": _tsi._so._run_verb, "ufw_allow_tailscale": SO.ufw_allow_tailscale}
_ts_cache_saved = dict(_tsi._cache)
_ts_real_run_ts = _tsi._run_ts


class _TsProc:
    def __init__(self, out="", err="", rc=0):
        self.stdout, self.stderr, self.returncode = out, err, rc


def _ts_fake_subprocess(behaviour, calls):
    """A stand-in for the `subprocess` module as tailscale_integration sees it."""
    def _run(argv, **kw):
        calls.append(list(argv))
        r = behaviour(argv)
        if isinstance(r, BaseException):
            raise r
        return r
    return NS(run=_run, TimeoutExpired=_p8_subprocess.TimeoutExpired)


try:
    # ── _run_ts: every failure is (…, -1), and an exception's TEXT never reaches the caller ─────
    _ts_calls = []
    _tsi.subprocess = _ts_fake_subprocess(lambda a: _TsProc(" 1.80.2\n  tailscale commit\n", " w ", 0),
                                          _ts_calls)
    eq("tailscale _run_ts: stdout/stderr come back stripped with the exit code",
       _ts_real_run_ts(["version"]), ("1.80.2\n  tailscale commit", "w", 0))
    eq("tailscale _run_ts: the argv is the literal binary plus the arguments, nothing else",
       _ts_calls[-1], ["tailscale", "version"])
    _tsi.subprocess = _ts_fake_subprocess(lambda a: FileNotFoundError("tailscale"), [])
    eq("tailscale _run_ts: a missing binary is ('', 'tailscale binary not found', -1)",
       _ts_real_run_ts(["status"]), ("", "tailscale binary not found", -1))
    _tsi.subprocess = _ts_fake_subprocess(
        lambda a: _p8_subprocess.TimeoutExpired(a, 5), [])
    eq("tailscale _run_ts: a hung CLI is ('', 'tailscale command timed out', -1), not a raise",
       _ts_real_run_ts(["status"]), ("", "tailscale command timed out", -1))
    _tsi.subprocess = _ts_fake_subprocess(
        lambda a: PermissionError("/root/.secret-socket-path denied"), [])
    _ts_generic = _ts_real_run_ts(["status"])
    check("tailscale _run_ts: any other error is a GENERIC message — the exception text (a "
          "stack-trace-exposure sink via /api/tailscale) is not in it",
          _ts_generic == ("", "tailscale command failed", -1) and "secret" not in repr(_ts_generic),
          repr(_ts_generic))

    # ── _run_ts_json: only a zero exit with parseable output is a reading ───────────────────────
    _ts_json_calls = []

    def _ts_json_run(resp):
        def _r(args, timeout=5):
            _ts_json_calls.append(list(args))
            return resp
        return _r
    _tsi._run_ts = _ts_json_run(('{"BackendState": "Running"}', "", 0))
    eq("tailscale _run_ts_json: a zero exit with JSON parses", _tsi._run_ts_json(["status"]),
       {"BackendState": "Running"})
    eq("tailscale _run_ts_json: ...and --json is appended to the caller's arguments",
       _ts_json_calls[-1], ["status", "--json"])
    _tsi._run_ts = _ts_json_run(('{"BackendState": "Running"}', "", 1))
    check("tailscale _run_ts_json: a NON-zero exit is None even when stdout looks like JSON",
          _tsi._run_ts_json(["status"]) is None)
    _tsi._run_ts = _ts_json_run(("", "", 0))
    check("tailscale _run_ts_json: an empty answer is None", _tsi._run_ts_json(["status"]) is None)
    _tsi._run_ts = _ts_json_run(("{not json", "", 0))
    check("tailscale _run_ts_json: unparseable output is None, not a raise",
          _tsi._run_ts_json(["status"]) is None)

    # ── _read_route_all: a pref that is not a bool is not an answer ─────────────────────────────
    _tsi._run_ts = _ts_json_run(('{"RouteAll": "yes"}', "", 0))
    check("tailscale accept-routes: a non-boolean RouteAll is unknown (None), not truthy",
          _tsi._read_route_all() is None)
    _tsi._run_ts = _ts_json_run(('["RouteAll"]', "", 0))
    check("tailscale accept-routes: prefs that are not an object are unknown, not a raise",
          _tsi._read_route_all() is None)
    _tsi._run_ts = _ts_json_run(("{broken", "", 0))
    check("tailscale accept-routes: unparseable prefs are unknown", _tsi._read_route_all() is None)

    # ── _current_os_user: pwd first, getpass when pwd cannot answer ────────────────────────────
    import pwd as _ts_pwd  # noqa: E402
    eq("tailscale: the panel's OS user is the one this process runs as",
       _tsi._current_os_user(), _ts_pwd.getpwuid(os.getuid()).pw_name)
    _ts_real_pwd = sys.modules["pwd"]
    import getpass as _ts_getpass  # noqa: E402
    _ts_real_getuser = _ts_getpass.getuser
    try:
        sys.modules["pwd"] = NS(getpwuid=lambda uid: (_ for _ in ()).throw(KeyError(uid)))
        _ts_getpass.getuser = lambda: "from-getpass"
        eq("tailscale: ...and getpass's answer when the passwd entry cannot be read",
           _tsi._current_os_user(), "from-getpass")
    finally:
        sys.modules["pwd"] = _ts_real_pwd
        _ts_getpass.getuser = _ts_real_getuser

    # ── ensure_operator: root needs nothing; anyone else goes through the VERB, not sudo ────────
    _ts_verbs = []

    def _ts_verb_rec(resp=("", "", 0)):
        def _v(verb, args=(), timeout=30, merge_stderr=True):
            _ts_verbs.append((verb, list(args)))
            if isinstance(resp, BaseException):
                raise resp
            return resp(verb, args) if callable(resp) else resp
        return _v
    _tsi._so._run_verb = _ts_verb_rec()
    _tsi._current_os_user = lambda: "root"
    eq("tailscale operator: a panel running as root is already the operator (no command)",
       (_tsi.ensure_operator(), _ts_verbs), ((True, "root"), []))
    _tsi._current_os_user = lambda: "lgsmpanel"
    eq("tailscale operator: another user is made operator through the tailscale-set-operator verb",
       (_tsi.ensure_operator(), _ts_verbs), ((True, "lgsmpanel"),
                                             [("tailscale-set-operator", ["lgsmpanel"])]))
    _tsi._current_os_user = _ts_saved["_current_os_user"]

    # ── allow_tailscale_ufw: best-effort, and an exception becomes (False, text) ───────────────
    SO.ufw_allow_tailscale = lambda *a, **k: (True, "tailscale0 allowed")
    eq("tailscale ufw: the panel host's ufw_allow_tailscale answer is passed through",
       _tsi.allow_tailscale_ufw(), (True, "tailscale0 allowed"))
    SO.ufw_allow_tailscale = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ufw exploded"))
    eq("tailscale ufw: ...and a raise is reported as a failure, not propagated",
       _tsi.allow_tailscale_ufw(), (False, "ufw exploded"))
    SO.ufw_allow_tailscale = _ts_so_saved["ufw_allow_tailscale"]

    # ── _get_tailscale_info ────────────────────────────────────────────────────────────────────
    def _ts_cli(table, calls=None):
        """_run_ts answering by argv prefix; unknown commands exit 1."""
        def _r(args, timeout=5):
            if calls is not None:
                calls.append(list(args))
            for prefix, resp in table:
                if args[:len(prefix)] == prefix:
                    return resp
            return ("", "unknown", 1)
        return _r

    _ts_c = []
    _tsi._run_ts = _ts_cli([], _ts_c)
    _ts_ni = _tsi._get_tailscale_info()
    check("tailscale info: no binary -> installed False, and nothing beyond the version probe runs",
          _ts_ni.installed is False and all(c[0] in ("version", "--version") for c in _ts_c),
          "calls=%r" % _ts_c)

    _ts_status = {
        "BackendState": "Running", "TailscaleIPs": ["100.64.0.7", "fd7a:115c:a1e0::7"],
        "Self": {"HostName": "panelbox", "DNSName": "panelbox.tail1234.ts.net."},
        "Peer": {
            "nodekey:a": {"HostName": "gamebox", "DNSName": "gamebox.tail1234.ts.net.",
                          "TailscaleIPs": ["100.64.0.9"], "OS": "linux", "Online": True,
                          "LastSeen": "2026-09-26T10:00:00Z", "Relay": "fra"},
            "nodekey:b": {"HostName": "phone", "DNSName": "", "TailscaleIPs": ["100.64.0.10"],
                          "OS": "iOS", "Online": False},
        }}
    _tsi._run_ts = _ts_cli([(["version"], ("1.80.2\ncommit", "", 0)),
                            (["status", "--json"], (_p8_json.dumps(_ts_status), "", 0)),
                            (["debug", "prefs"], ('{"RouteAll": false}', "", 0)),
                            (["serve", "status"], ("No serve config", "", 0))])
    _tsi._run_ts_json = _ts_saved["_run_ts_json"]
    _ts_ri = _tsi._get_tailscale_info()
    eq("tailscale info: version is the first line of `tailscale version`", _ts_ri.version, "1.80.2")
    check("tailscale info: a Running node reads as running with its MagicDNS name (trailing dot "
          "stripped) and both addresses",
          _ts_ri.running and _ts_ri.dns_name == "panelbox.tail1234.ts.net"
          and _ts_ri.hostname == "panelbox" and _ts_ri.magic_dns_enabled
          and _ts_ri.tailscale_ips == ["100.64.0.7", "fd7a:115c:a1e0::7"], repr(_ts_ri))
    _ts_peers = {p["hostname"]: p for p in _ts_ri.peers}
    check("tailscale info: peers carry Tailscale's own Online flag and a dot-stripped DNS name",
          _ts_peers.get("gamebox", {}).get("online") is True
          and _ts_peers["gamebox"]["dns_name"] == "gamebox.tail1234.ts.net"
          and _ts_peers["gamebox"]["relay"] == "fra"
          and _ts_peers.get("phone", {}).get("online") is False
          and _ts_peers["phone"]["dns_name"] == "", repr(_ts_ri.peers))
    check("tailscale info: 'No serve config' at rc 0 is read as nothing published, not unreadable",
          _ts_ri.serve_unreadable is False and _ts_ri.serve_config.get("services") == []
          and _ts_ri.funnel_enabled is False, repr(_ts_ri.serve_config))

    # The plain-text fallback, when status --json does not answer.
    _ts_gai = []
    _tsi.socket = NS(AF_INET=2, getaddrinfo=lambda h, p, fam: (_ts_gai.append(h), [])[1])
    _tsi._run_ts = _ts_cli([(["version"], ("1.40.0", "", 0)),
                            (["status"], ("100.64.0.3   oldbox.tail1234.ts.net   me@   linux   -",
                                          "", 0))])
    _ts_fb = _tsi._get_tailscale_info()
    check("tailscale info: without --json, a status listing with this node's 100.x line reads as "
          "Running and takes the host name from it",
          _ts_fb.running and _ts_fb.backend_state == "Running" and _ts_fb.hostname == "oldbox",
          repr(_ts_fb))
    check("tailscale info: ...and with no DNS name, MagicDNS is detected by resolving the host name",
          _ts_fb.magic_dns_enabled is True and _ts_gai == ["oldbox.tailscale.net"],
          "magic=%r lookups=%r" % (_ts_fb.magic_dns_enabled, _ts_gai))
    _tsi.socket = NS(AF_INET=2, getaddrinfo=lambda *a: (_ for _ in ()).throw(OSError("nxdomain")))
    check("tailscale info: ...a name that does not resolve leaves MagicDNS off",
          _tsi._get_tailscale_info().magic_dns_enabled is False)
    _tsi.socket = _ts_saved["socket"]
    _tsi._run_ts = _ts_cli([(["version"], ("1.40.0", "", 0)),
                            (["status"], ("Tailscale is stopped.", "", 1))])
    _ts_st = _tsi._get_tailscale_info()
    check("tailscale info: a stopped daemon reads as Stopped, not Running",
          _ts_st.installed and not _ts_st.running and _ts_st.backend_state == "Stopped",
          repr(_ts_st))
    # `--version` alone (an old CLI without the `version` subcommand) still counts as installed.
    _tsi._run_ts = _ts_cli([(["--version"], ("1.20.0", "", 0))])
    check("tailscale info: an old CLI that only answers --version is still installed",
          _tsi._get_tailscale_info().installed is True)

    # ── get_tailscale_info: cached for its TTL; force_refresh re-reads ─────────────────────────
    _ts_n = {"n": 0}

    def _ts_count_info():
        _ts_n["n"] += 1
        return _tsi.TailscaleInfo(installed=True, version=str(_ts_n["n"]))
    _tsi._get_tailscale_info = _ts_count_info
    _tsi._cache.update(info=None, ts=0)
    _ts_a, _ts_b = _tsi.get_tailscale_info(), _tsi.get_tailscale_info()
    check("tailscale info cache: two reads inside the TTL cost one CLI pass",
          _ts_n["n"] == 1 and _ts_a is _ts_b, "computed %d times" % _ts_n["n"])
    _ts_c2 = _tsi.get_tailscale_info(force_refresh=True)
    check("tailscale info cache: force_refresh reads again", _ts_n["n"] == 2 and _ts_c2.version == "2",
          "computed %d times" % _ts_n["n"])
    _tsi._cache["ts"] = _p8_time.time() - 3600
    _tsi.get_tailscale_info()
    eq("tailscale info cache: an expired entry is re-read", _ts_n["n"], 3)
    _tsi._get_tailscale_info = _ts_saved["_get_tailscale_info"]

    # ── get_magic_url / get_tailscale_ip ───────────────────────────────────────────────────────
    _ts_info = {"v": None}
    _tsi.get_tailscale_info = lambda force_refresh=False: _ts_info["v"]
    _ts_info["v"] = _tsi.TailscaleInfo(dns_name="panelbox.tail1234.ts.net",
                                       tailscale_ips=["fd7a:115c:a1e0::7", "100.64.0.7"])
    eq("tailscale magic URL: the MagicDNS name, no port for the default", _tsi.get_magic_url(),
       "https://panelbox.tail1234.ts.net")
    eq("tailscale magic URL: a non-default port is appended", _tsi.get_magic_url(8443),
       "https://panelbox.tail1234.ts.net:8443")
    eq("tailscale magic URL: ...but 443 and 80 are not", _tsi.get_magic_url(443, "https"),
       "https://panelbox.tail1234.ts.net")
    eq("tailscale IP: v4 is picked out of a list that starts with v6", _tsi.get_tailscale_ip(4),
       "100.64.0.7")
    eq("tailscale IP: v6 on request", _tsi.get_tailscale_ip(6), "fd7a:115c:a1e0::7")
    _ts_info["v"] = _tsi.TailscaleInfo(tailscale_ips=["fd7a:115c:a1e0::7"])
    eq("tailscale IP: no v4 -> the first address rather than nothing",
       _tsi.get_tailscale_ip(4), "fd7a:115c:a1e0::7")
    _ts_info["v"] = _tsi.TailscaleInfo()
    check("tailscale: no MagicDNS name and no address -> None for both",
          _tsi.get_magic_url() is None and _tsi.get_tailscale_ip() is None)

    # ── check_peer_reachability: an option-shaped host never reaches ping ──────────────────────
    _ts_ping = []
    _tsi.subprocess = _ts_fake_subprocess(
        lambda a: _TsProc("64 bytes from 100.64.0.9: icmp_seq=1 ttl=64 time=12.5 ms", "", 0), _ts_ping)
    eq("tailscale ping: an option-shaped host is refused before ping runs",
       (_tsi.check_peer_reachability("-oProxyCommand=id"), _ts_ping),
       ({"reachable": False, "latency_ms": 0}, []))
    eq("tailscale ping: a reachable peer reports ping's own latency",
       _tsi.check_peer_reachability(" 100.64.0.9 "), {"reachable": True, "latency_ms": 12.5})
    eq("tailscale ping: ...with the host stripped and as the LAST argument",
       _ts_ping[-1], ["ping", "-c", "1", "-W", "3", "100.64.0.9"])
    _tsi.subprocess = _ts_fake_subprocess(lambda a: _TsProc("", "", 1), [])
    eq("tailscale ping: a non-zero ping is unreachable",
       _tsi.check_peer_reachability("gamebox"), {"reachable": False, "latency_ms": 0})
    _tsi.subprocess = _ts_fake_subprocess(lambda a: OSError("no ping binary"), [])
    eq("tailscale ping: ping missing altogether is unreachable, not a raise",
       _tsi.check_peer_reachability("gamebox"), {"reachable": False, "latency_ms": 0})
    _tsi.subprocess = _ts_saved["subprocess"]

    # ── setup_tailscale_serve ──────────────────────────────────────────────────────────────────
    _ts_steps = []
    _tsi.ensure_operator = lambda: (_ts_steps.append("operator"), (True, "u"))[1]
    _tsi.allow_tailscale_ufw = lambda: (_ts_steps.append("ufw"), (True, ""))[1]
    _ts_cli_calls = []
    _tsi._run_ts = _ts_cli([], _ts_cli_calls)      # every unprivileged try exits 1
    del _ts_verbs[:]
    _tsi._so._run_verb = _ts_verb_rec()
    eq("tailscale serve: an option-shaped mount is refused with a message, before anything runs",
       (_tsi.setup_tailscale_serve(5000, mount="--bg"), _ts_steps, _ts_cli_calls, _ts_verbs),
       ((False, "That isn't a usable mount point. Use \"/\" or a short path like \"/lgsm\"."),
        [], [], []))
    _tsi._cache["info"] = "stale"
    _ts_ok = _tsi.setup_tailscale_serve(5000, mount="/lgsm", funnel=True)
    check("tailscale serve: when the unprivileged form fails, the root verb is the fallback and "
          "its success is reported (with Funnel)",
          _ts_ok == (True, "Tailscale Serve enabled (with Funnel)")
          and _ts_verbs == [("tailscale-serve", ["funnel", "modern", "/lgsm", "http", "5000"])],
          "result=%r verbs=%r" % (_ts_ok, _ts_verbs))
    check("tailscale serve: ...after making the panel user operator and allowing tailscale0",
          _ts_steps == ["operator", "ufw"], repr(_ts_steps))
    check("tailscale serve: ...and the cached info is dropped so the page re-reads Serve",
          _tsi._cache["info"] is None, repr(_tsi._cache["info"]))
    del _ts_verbs[:]
    _tsi._run_ts = _ts_cli([(["serve"], ("", "", 0))])
    eq("tailscale serve: an unprivileged success needs no root at all",
       (_tsi.setup_tailscale_serve(5000), _ts_verbs), ((True, "Tailscale Serve enabled"), []))
    _tsi._run_ts = _ts_cli([(["serve"], ("", "flag provided but not defined", 2))])
    _tsi._so._run_verb = _ts_verb_rec(("", "Access denied: serve config denied", 1))
    del _ts_verbs[:]
    _ts_bad = _tsi.setup_tailscale_serve(5000)
    check("tailscale serve: when both grammars fail both ways, the answer is a failure carrying the "
          "last error — and both grammars were tried",
          _ts_bad[0] is False and "Access denied" in _ts_bad[1]
          and [v[1][1] for v in _ts_verbs] == ["modern", "legacy"],
          "result=%r verbs=%r" % (_ts_bad, _ts_verbs))

    # ── install_tailscale_local ────────────────────────────────────────────────────────────────
    _tsi._so._run_verb = _ts_verb_rec(("x" * 2000, "tail-of-err", 0))
    _tsi._cache["info"] = "stale"
    _ts_inst = _tsi.install_tailscale_local()
    check("tailscale install: rc 0 is success, the log is the LAST 1500 chars, and the cache drops",
          _ts_inst[0] is True and len(_ts_inst[1]) == 1500 and _ts_inst[1].endswith("tail-of-err")
          and _tsi._cache["info"] is None, "ok=%r len=%d" % (_ts_inst[0], len(_ts_inst[1])))
    _tsi._so._run_verb = _ts_verb_rec(("", "curl: (6) could not resolve", 1))
    eq("tailscale install: a non-zero verb is a failure with its own output",
       _tsi.install_tailscale_local(), (False, "curl: (6) could not resolve"))
    _tsi._so._run_verb = _ts_verb_rec(RuntimeError("/root/internal/path"))
    _ts_ie = _tsi.install_tailscale_local()
    check("tailscale install: a raise answers a generic message — the exception text is not echoed "
          "to /api/tailscale/install",
          _ts_ie[0] is False and "/root/internal" not in _ts_ie[1] and "panel logs" in _ts_ie[1],
          repr(_ts_ie))

    # ── tailscale_up_local ─────────────────────────────────────────────────────────────────────
    _ts_url = "https://login.tailscale.com/a/1b2c3d4e5f"
    del _ts_verbs[:]
    _tsi._so._run_verb = _ts_verb_rec(("starting...\n" + _ts_url, "", 0))
    eq("tailscale up: the login URL on the last line is returned", _tsi.tailscale_up_local(),
       (True, _ts_url))
    eq("tailscale up: ...through the tailscale-up-login verb, SSH on by default",
       _ts_verbs[-1], ("tailscale-up-login", ["yes", "-"]))
    _tsi.tailscale_up_local(enable_ssh=False)
    eq("tailscale up: ...and off when asked", _ts_verbs[-1], ("tailscale-up-login", ["no", "-"]))
    _ts_info["v"] = _tsi.TailscaleInfo(installed=True, running=False)
    _tsi._so._run_verb = _ts_verb_rec((_ts_url + '"><script>alert(1)</script>', "", 0))
    _ts_inj = _tsi.tailscale_up_local()
    check("tailscale up: a URL with anything after the login path is not accepted as the login "
          "link (it is rendered into an href) — fullmatch, not a prefix test",
          _ts_inj[0] is False, repr(_ts_inj))
    del _ts_steps[:]
    _tsi._so._run_verb = _ts_verb_rec(("ALREADY_CONNECTED", "", 0))
    eq("tailscale up: an already-joined node answers ALREADY_CONNECTED and gets operator + ufw",
       (_tsi.tailscale_up_local(), _ts_steps), ((True, "ALREADY_CONNECTED"), ["operator", "ufw"]))
    _tsi._so._run_verb = _ts_verb_rec(("", "", -1))
    _ts_info["v"] = _tsi.TailscaleInfo(installed=True, running=True)
    eq("tailscale up: no URL but a Running node is also already connected",
       _tsi.tailscale_up_local(), (True, "ALREADY_CONNECTED"))
    _ts_info["v"] = _tsi.TailscaleInfo(installed=False, running=False)
    check("tailscale up: nothing at all is a failure with a message, not a blank success",
          _tsi.tailscale_up_local() == (False, "Could not get a login link — is Tailscale installed "
                                               "on this host?"))

    # ── _parse_serve_status: several listeners, each with its own routes and Funnel flag ────────
    _ts_multi = _tsi._parse_serve_status(
        "https://panelbox.tail1234.ts.net (Funnel on)\n|-- / proxy http://127.0.0.1:3000\n\n"
        "https://panelbox.tail1234.ts.net:8443 (tailnet only)\n|-- /lgsm proxy http://127.0.0.1:5000\n"
        "|-- /funnel-docs proxy http://127.0.0.1:9000\n"
        "https://empty.tail1234.ts.net (tailnet only)\n")
    eq("tailscale serve status: every listener with routes is kept, in order, with its OWN funnel "
       "flag — and one with no routes is dropped",
       [(s["url"], s["funnel"], [r["mount"] for r in s["routes"]]) for s in _ts_multi["services"]],
       [("https://panelbox.tail1234.ts.net", True, ["/"]),
        ("https://panelbox.tail1234.ts.net:8443", False, ["/lgsm", "/funnel-docs"])])

    # ── route_targets_port / _serve_port_flag / serve_off_args ──────────────────────────────────
    for _ts_t, _ts_want in (("http://127.0.0.1:5000", True), ("https+insecure://localhost:5000/", True),
                            ("http://[::1]:5000", True), ("http://10.0.0.4:5000", False),
                            ("http://127.0.0.1:5001", False), ("127.0.0.1", False),
                            ("http://localhost:abc", False), ("", False)):
        eq("tailscale route target: %r on 5000 -> %s" % (_ts_t, _ts_want),
           _tsi.route_targets_port(_ts_t, 5000), _ts_want)
    eq("tailscale serve off: https with no port is the 443 listener, with the mount always named",
       _tsi.serve_off_args("https://panelbox.tail1234.ts.net", "/"),
       ["serve", "--https=443", "--set-path=/", "off"])
    eq("tailscale serve off: an explicit http port is used as given",
       _tsi.serve_off_args("http://panelbox.tail1234.ts.net:8080/", "/lgsm"),
       ["serve", "--http=8080", "--set-path=/lgsm", "off"])
    check("tailscale serve off: an out-of-range or unreadable listener is None, not a guess",
          _tsi.serve_off_args("https://h.ts.net:70000", "/") is None
          and _tsi.serve_off_args("tcp://h.ts.net:22", "/") is None)

    # ── disable_tailscale_serve ────────────────────────────────────────────────────────────────
    _ts_ours = {"services": [
        {"url": "https://panelbox.tail1234.ts.net", "funnel": True, "routes": [
            {"mount": "/", "target": "http://127.0.0.1:3000"},
            {"mount": "/lgsm", "target": "http://127.0.0.1:5000"}]}]}
    _ts_off_calls = []
    _tsi._run_ts = _ts_cli([(["serve"], ("", "", 0))], _ts_off_calls)
    del _ts_steps[:]
    eq("tailscale disable: an option-shaped mount is refused",
       (_tsi.disable_tailscale_serve("-x", 5000), _ts_off_calls),
       ((False, "That isn't a usable mount point."), []))
    _ts_info["v"] = _tsi.TailscaleInfo(serve_unreadable=True)
    check("tailscale disable: an UNREAD Serve config removes nothing and says so",
          _tsi.disable_tailscale_serve("/", 5000)[0] is False and _ts_off_calls == [])
    _ts_info["v"] = _tsi.TailscaleInfo(serve_config=_ts_ours)
    _ts_other = _tsi.disable_tailscale_serve("/", 5000)
    check("tailscale disable: another app's mapping at the mount is never touched — the panel is "
          "at /lgsm, and the answer says so",
          _ts_other[0] is False and "/lgsm" in _ts_other[1] and _ts_off_calls == [],
          "result=%r calls=%r" % (_ts_other, _ts_off_calls))
    _ts_info["v"] = _tsi.TailscaleInfo(serve_config={"services": []})
    eq("tailscale disable: nothing proxies the panel -> done, nothing to remove",
       _tsi.disable_tailscale_serve("/", 5000),
       (True, "Tailscale Serve wasn't publishing the panel, so there was nothing to remove."))
    _ts_info["v"] = _tsi.TailscaleInfo(serve_config=_ts_ours)
    _tsi._cache["info"] = "stale"
    _ts_rm = _tsi.disable_tailscale_serve("/lgsm", 5000)
    check("tailscale disable: the panel's own mapping is removed with the listener's off-grammar",
          _ts_rm == (True, "Tailscale Serve mapping removed")
          and _ts_off_calls == [["serve", "--https=443", "--set-path=/lgsm", "off"]]
          and _ts_steps == ["operator"] and _tsi._cache["info"] is None,
          "result=%r calls=%r steps=%r" % (_ts_rm, _ts_off_calls, _ts_steps))
    _tsi._run_ts = _ts_cli([(["serve"], ("", "serve config denied", 1))])
    eq("tailscale disable: a refused removal is a failure carrying the CLI's error",
       _tsi.disable_tailscale_serve("/lgsm", 5000), (False, "Failed to remove: serve config denied"))
    _ts_info["v"] = _tsi.TailscaleInfo(serve_config={"services": [
        {"url": "gopher://weird", "routes": [{"mount": "/", "target": "http://127.0.0.1:5000"}]}]})
    check("tailscale disable: a mapping whose listener cannot be read is left alone",
          _tsi.disable_tailscale_serve("/", 5000)[0] is False)

    # ── is_tailscale_ip: anchored and parsed ───────────────────────────────────────────────────
    for _ts_h, _ts_want in (("panelbox.tail1234.ts.net", True), ("PANELBOX.TAIL1234.TS.NET", True),
                            ("evil.tailed-hosting.example", False),
                            ("100.telemetry.example.com", False), ("100.0.0.1", False),
                            ("100.64.0.1", True), ("100.127.255.254", True), ("100.128.0.1", False),
                            ("fd7a:115c:a1e0::5", True), ("fd7a:115c:a1e1::5", False),
                            ("ts.net.evil.example", False), ("", False), (None, False)):
        eq("tailscale address test: %r -> %s" % (_ts_h, _ts_want), _tsi.is_tailscale_ip(_ts_h),
           _ts_want)

    # ── suggest_best_bind: Tailscale absent altogether ─────────────────────────────────────────
    _ts_info["v"] = _tsi.TailscaleInfo()
    _ts_sb = _tsi.suggest_best_bind(8443, scheme="https")
    check("tailscale bind: no Tailscale -> bind all interfaces, on the panel's scheme and port",
          _ts_sb["method"] == "direct" and _ts_sb["bind_host"] == "0.0.0.0"
          and _ts_sb["url"] == "https://<your-server-ip>:8443"
          and "No Tailscale" in _ts_sb["description"], repr(_ts_sb))
finally:
    for _k, _v in _ts_saved.items():
        setattr(_tsi, _k, _v)
    _tsi._so._run_verb = _ts_so_saved["_run_verb"]
    SO.ufw_allow_tailscale = _ts_so_saved["ufw_allow_tailscale"]
    _tsi._cache.clear()
    _tsi._cache.update(_ts_cache_saved)
    _tsi._cache["info"] = None


# ════════════════════════════════════════════════════════════════════════════════════════════════
# ssh_manager.hosts — remote hosts, over a recorded fake transport
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Wire:
    """The transport as hosts.py sees it, recording every call and answering from a table.

    Every privileged verb, shell command and root write is RECORDED. An answer may be a tuple, a
    callable (given the args or the command), an exception (raised — the paramiko shape), or a
    list consumed in order (the last one repeats). Unlisted verbs answer ("", "", 0); unlisted
    commands answer `cmd_default`.
    """

    def __init__(self, verbs=None, cmds=None, cmd_default=("", "", 0), writes=None):
        self.verbs = dict(verbs or {})
        self.cmds = list(cmds or [])
        self.cmd_default = cmd_default
        self.writes = dict(writes or {})
        self.calls = []

    @staticmethod
    def _answer(r, arg):
        if isinstance(r, list):
            r = r.pop(0) if len(r) > 1 else r[0]
        if isinstance(r, BaseException):
            raise r
        if callable(r):
            r = r(arg)
        return r

    def run_privileged(self, server, verb, args=(), timeout=30, merge_stderr=True, sudo=True):
        self.calls.append(("verb", verb, list(args)))
        return self._answer(self.verbs.get(verb, ("", "", 0)), list(args))

    def run_command(self, server, command, timeout=30, sudo=None, stdin_text=None):
        self.calls.append(("cmd", command, sudo))
        for sub, r in self.cmds:
            if sub in command:
                return self._answer(r, command)
        return self._answer(self.cmd_default, command)

    def write_root_file(self, server, target, content, timeout=15):
        self.calls.append(("write", target, content))
        return self._answer(self.writes.get(target, ("", "", 0)), content)

    def verbs_called(self, name=None):
        return [(c[1], c[2]) for c in self.calls if c[0] == "verb" and (name is None or c[1] == name)]

    def names(self):
        return [c[1] for c in self.calls if c[0] in ("verb", "write")]


_p8_ids = iter(range(880001, 889999))


def _p8_srv(**kw):
    """A remote row. auth_method defaults to tailscale: the transport that does NOT raise."""
    d = dict(id=next(_p8_ids), name="vps", host="203.0.113.10", port=22, username="root",
             auth_method="tailscale", auth_credential="", host_key="", is_local=False,
             sudo_enabled=True)
    d.update(kw)
    return NS(**d)


_H = _sm_hosts
_h_core_saved = {n: getattr(_sm_core, n) for n in (
    "run_privileged", "run_command", "write_root_file", "close_connection", "create_game_user")}
_h_saved = {n: getattr(_H, n) for n in (
    "time", "paramiko", "decrypt_secret", "ssh_test_connection", "_wait_for_reboot",
    "_tcp_reachable", "remote_ufw_delete_rule", "remote_check_tailscale", "host_os_slug",
    "deps_for_game", "_load_deps_csv", "_tailscale_conn_state", "remote_public_ssh_status",
    "remote_fail2ban_overview", "remote_ufw_blocked_ips", "socket", "_bootstrap_node")}
_h_fw_saved = {"remote_ufw_status": _sm_firewall.remote_ufw_status}


def _wire(**kw):
    w = _Wire(**kw)
    _sm_core.run_privileged = w.run_privileged
    _sm_core.run_command = w.run_command
    _sm_core.write_root_file = w.write_root_file
    return w


try:
    # ── gamedig install + its weekly cron ──────────────────────────────────────────────────────
    _w = _wire()
    eq("gamedig: the panel's own host is install.sh's job — nothing is sent",
       (_H.install_gamedig(_p8_srv(is_local=True)), _w.calls),
       (("gamedig on the panel's own host is installed by install.sh", 0), []))
    _w = _wire(verbs={"gamedig-install": ("added 42 packages", "", 0)})
    eq("gamedig: a remote runs the gamedig-install verb and reports its output and rc",
       (_H.install_gamedig(_p8_srv()), _w.verbs_called()),
       (("added 42 packages", 0), [("gamedig-install", [])]))
    _w = _wire(verbs={"gamedig-install": ConnectionError("Command failed: socket closed")})
    eq("gamedig: a transport that RAISES (paramiko) is (message, -1), never an exception",
       _H.install_gamedig(_p8_srv(auth_method="key")),
       ("gamedig install could not be run: ConnectionError", -1))

    _w = _wire()
    check("gamedig cron: written through the node-tools-cron target with the pinned body",
          _H._write_node_tools_cron(_p8_srv()) is True
          and _w.calls == [("write", "node-tools-cron", _H._NODE_TOOLS_CRON)], repr(_w.calls))
    _wire(writes={"node-tools-cron": ("", "sudo: a password is required", 1)})
    check("gamedig cron: a refused write is False, not success",
          _H._write_node_tools_cron(_p8_srv()) is False)
    _wire(writes={"node-tools-cron": ConnectionError("down")})
    check("gamedig cron: a raising transport is False, not a raise",
          _H._write_node_tools_cron(_p8_srv(auth_method="key")) is False)
    _w = _wire(verbs={"gamedig-install": ("npm ERR! 404", "", 1)})
    _ok = _H.ensure_node_tools_cron(_p8_srv())
    check("gamedig daily pass: a remote installs FIRST and writes the cron after — even when the "
          "install failed, the cron (which only repairs) still goes in",
          _ok is True and _w.names() == ["gamedig-install", "node-tools-cron"], repr(_w.names()))
    _w = _wire()
    check("gamedig daily pass: the panel host gets only the cron",
          _H.ensure_node_tools_cron(_p8_srv(is_local=True)) is True
          and _w.names() == ["node-tools-cron"], repr(_w.names()))

    # ── Ubuntu Pro ─────────────────────────────────────────────────────────────────────────────
    _w = _wire(verbs={"pro-status": ("", "bash: pro: command not found", 127)})
    eq("pro: rc 127 is a READING — not installed, and not flagged unreadable",
       _H._compute_pro_status(_p8_srv()), {"installed": False, "attached": False, "services": []})
    _wire(verbs={"pro-status": ("", "SSH command timed out", -1)})
    check("pro: a timed-out read (tailscale/local shape) is unreadable, not 'not installed'",
          _H._compute_pro_status(_p8_srv()).get("unreadable") is True)
    _wire(verbs={"pro-status": ('{"attached": true, "services": [', "", 0)})
    _p = _H._compute_pro_status(_p8_srv())
    check("pro: JSON cut off mid-object is unreadable too — not 'installed, not attached'",
          _p.get("unreadable") is True and _p["installed"] is False, repr(_p))
    _pro_json = _p8_json.dumps({
        "attached": True, "expires": "9999-12-31T00:00:00+00:00",
        "account": {"name": "ops@example"}, "contract": {"name": "Ubuntu Pro - free personal"},
        "services": [{"name": "fips", "status": "disabled"},
                     {"name": "livepatch", "status": "enabled", "entitled": "yes",
                      "description": "Canonical Livepatch service", "available": "yes"},
                     {"name": "esm-infra", "status": "enabled", "entitled": "yes"}]})
    _wire(verbs={"pro-status": (_pro_json, "", 0)})
    _p = _H._compute_pro_status(_p8_srv())
    check("pro: an attached host reads its account, contract and ONLY the featured services, in "
          "featured order, with the perpetual 9999 expiry blanked",
          _p["installed"] and _p["attached"] and _p["account"] == "ops@example"
          and _p["contract"] == "Ubuntu Pro - free personal" and _p["expires"] == ""
          and [s["name"] for s in _p["services"]] == ["esm-infra", "livepatch"]
          and _p["services"][1]["status"] == "enabled", repr(_p))
    _wire(verbs={"pro-status": ('{"attached": false, "account": "x", "contract": [], '
                                '"expires": "2027-01-01"}', "", 0)})
    _p = _H._compute_pro_status(_p8_srv())
    check("pro: account/contract that are not objects read as blank, a real expiry is kept",
          _p["account"] == "" and _p["contract"] == "" and _p["expires"] == "2027-01-01"
          and _p["attached"] is False, repr(_p))

    _ps = _p8_srv()
    _w = _wire(verbs={"pro-status": (_pro_json, "", 0)})
    _H.pro_status(_ps)
    _H.pro_status(_ps)
    eq("pro cache: a good reading is memoised (two page loads, one `pro status`)",
       len(_w.verbs_called("pro-status")), 1)
    _H.pro_status(_ps, force=True)
    eq("pro cache: force=True asks again", len(_w.verbs_called("pro-status")), 2)
    _ps2 = _p8_srv()
    _w = _wire(verbs={"pro-status": ("", "SSH command timed out", -1)})
    _H.pro_status(_ps2)
    _H.pro_status(_ps2)
    eq("pro cache: an UNREADABLE result is not memoised — the next load asks again",
       len(_w.verbs_called("pro-status")), 2)

    _w = _wire()
    eq("pro attach: an empty token is refused before anything is sent",
       (_H.pro_attach(_p8_srv(), "  "), _w.calls), ((False, "No token provided"), []))
    _pa = _p8_srv()
    _H._pro_status_cache[_H._pro_key(_pa)] = (_p8_time.time() + 999, {"attached": False})
    _w = _wire(verbs={"pro-status": ("", "", 127),
                      "pro-attach": ("", "Invalid token C1secretToken99 for this contract", 1)})
    _pa_r = _H.pro_attach(_pa, "C1secretToken99")
    check("pro attach: a failure message NEVER carries the token", _pa_r[0] is False
          and "C1secretToken99" not in _pa_r[1] and "<token>" in _pa_r[1], repr(_pa_r))
    eq("pro attach: pro missing (rc 127) is installed first, then attach",
       [v for v, _ in _w.verbs_called()], ["pro-status", "apt-update", "apt-install", "pro-attach"])
    check("pro attach: ...and the cached status is dropped before anything changes",
          _H._pro_key(_pa) not in _H._pro_status_cache)
    _w = _wire(verbs={"pro-status": (_pro_json, "", 0),
                      "pro-attach": ("This machine is already attached to 'x'", "", 1)})
    eq("pro attach: 'already attached' is success even on a non-zero exit, and pro present means "
       "no install", (_H.pro_attach(_p8_srv(), "tok"), [v for v, _ in _w.verbs_called()]),
       ((True, "Attached to Ubuntu Pro."), ["pro-status", "pro-attach"]))

    _w = _wire()
    eq("pro service: a service outside the allowlist is refused unsent",
       (_H.pro_service(_p8_srv(), "rm -rf", "enable"), _w.calls), ((False, "Unknown service"), []))
    eq("pro service: ...and so is an action other than enable/disable",
       (_H.pro_service(_p8_srv(), "livepatch", "purge"), _w.calls), ((False, "Unknown action"), []))
    _wire(verbs={"pro-service": ("One moment, checking your subscription first\n"
                                 "Livepatch is already enabled.", "", 1)})
    check("pro service: 'already enabled' is success, reported in one trimmed line",
          _H.pro_service(_p8_srv(), "livepatch", "enable")
          == (True, "One moment, checking your subscription first Livepatch is already enabled."))
    _w = _wire(verbs={"pro-service": ("", "", 0)})
    eq("pro service: rc 0 with no output gets a sentence, via the pro-service verb",
       (_H.pro_service(_p8_srv(), "esm-apps", "disable"), _w.verbs_called()),
       ((True, "esm-apps disabled"), [("pro-service", ["disable", "esm-apps"])]))
    _wire(verbs={"pro-service": ("", "", 1)})
    eq("pro service: a silent failure says what failed",
       _H.pro_service(_p8_srv(), "esm-apps", "enable"), (False, "Could not enable esm-apps"))
    _wire(verbs={"pro-detach": ("panel-helper: pro-detach timed out", "", -1)})
    check("pro detach: a message that merely NAMES the verb is not a detach",
          _H.pro_detach(_p8_srv())[0] is False)
    _wire(verbs={"pro-detach": ("Detach will disable the following services\n"
                                "This machine is now detached.", "", 1)})
    eq("pro detach: pro's own sentence is success", _H.pro_detach(_p8_srv()),
       (True, "Detached from Ubuntu Pro."))

    # ── UFW writes: validation happens BEFORE anything reaches the host ────────────────────────
    _w = _wire()
    for _bad in ("22; rm -rf /", "0", "70000", None):
        eq("ufw open: port %r is refused unsent" % (_bad,),
           (_H.remote_ufw_open_port(_p8_srv(), _bad), _w.calls), ((False, "Invalid port"), []))
    eq("ufw open: an unknown protocol is refused unsent",
       (_H.remote_ufw_open_port(_p8_srv(), 27015, "icmp"), _w.calls),
       ((False, "Invalid protocol"), []))
    eq("ufw open: one protocol uses the proto verb, the comment stripped to its safe charset",
       (_H.remote_ufw_open_port(_p8_srv(), "27015", "UDP", "cs2 <server>; #1"), _w.verbs_called()),
       ((True, "Port 27015/udp opened on remote"),
        [("ufw-allow-proto-port", ["udp", "27015", "cs2 server 1"])]))
    _w = _wire(verbs={"ufw-allow-port": ("", "ERROR: problem running ufw-init", 1)})
    eq("ufw open: 'both' is ONE bare rule, and a refusal returns ufw's own error",
       (_H.remote_ufw_open_port(_p8_srv(), 27015, "both"), _w.verbs_called()),
       ((False, "ERROR: problem running ufw-init"), [("ufw-allow-port", ["27015", ""])]))

    _w = _wire()
    for _args, _want in (((" ", 22), "Source address required"),
                         (("10.0.0.0/24", 22, "both"), "A source rule needs a single protocol (tcp or udp)"),
                         (("10.0.0.0/24", ""), "Port required"),
                         (("home.example.net", 22), "Source must be an IP address or network (e.g. 10.0.0.0/24)"),
                         (("10.0.0.0/24", "22; id"), "Port must be a number or a range like 27015:27020")):
        eq("ufw allow-from: %r refused unsent" % (_args,),
           (_H.remote_ufw_allow_from(_p8_srv(), *_args), _w.calls), ((False, _want), []))
    eq("ufw allow-from: a range from a network, via the allow-from verb",
       (_H.remote_ufw_allow_from(_p8_srv(), "10.0.0.0/24", "27015:27020", "udp", "lan!"),
        _w.verbs_called()),
       ((True, "Port 27015:27020/udp open from 10.0.0.0/24"),
        [("ufw-allow-from-port", ["10.0.0.0/24", "27015:27020", "udp", "lan"])]))
    _w = _wire(verbs={"ufw-delete-allow-from-port": ("Could not delete non-existent rule", "", 1)})
    eq("ufw allow-from: allow=False removes the rule with the delete verb, and a failure says why",
       (_H.remote_ufw_allow_from(_p8_srv(), "203.0.113.9", 22, allow=False), _w.verbs_called()),
       ((False, "Could not delete non-existent rule"),
        [("ufw-delete-allow-from-port", ["203.0.113.9", "22", "tcp"])]))
    _wire()
    eq("ufw allow-from: a removed rule is reported as removed",
       _H.remote_ufw_allow_from(_p8_srv(), "203.0.113.9", 22, allow=False),
       (True, "Rule for 22/tcp from 203.0.113.9 removed"))

    # ── ufw rate limiting: the read-back decides, not the exit codes ────────────────────────────
    _UFW_HDR = ("Status: active\n\n     To                         Action      From\n"
                "     --                         ------      ----\n")
    _BEFORE = _UFW_HDR + (
        "[ 1] 27015                      ALLOW IN    Anywhere                   # cs2server\n"
        "[ 2] 22/tcp                     LIMIT IN    Anywhere\n"
        "[ 3] 27015 on eth1              ALLOW IN    Anywhere\n"
        "[ 4] 27015                      ALLOW IN    10.0.0.0/8\n"
        "[ 5] 27015 (v6)                 ALLOW IN    Anywhere (v6)              # cs2server\n")
    _AFTER = _UFW_HDR + (
        "[ 1] 22/tcp                     LIMIT IN    Anywhere\n"
        "[ 2] 27015/tcp                  LIMIT IN    Anywhere\n"
        "[ 3] 27015/udp                  ALLOW IN    Anywhere                   # cs2server\n")
    eq("ufw public rules: interface, source-restricted and v6 rules are not what the public meets",
       [(r["to"], r["action"]) for r in _H._ufw_public_rules(_BEFORE)],
       [("27015", "ALLOW"), ("22/tcp", "LIMIT")])
    _fr = _H._ufw_first_public_rule(_UFW_HDR + "[ 1] 27000:27030/udp   ALLOW IN   Anywhere\n",
                                     27015, "udp")
    check("ufw first rule: a udp RANGE covering the port is the first rule for udp...",
          _fr is not None and _fr["to"] == "27000:27030/udp", repr(_fr))
    check("ufw first rule: ...and not for tcp",
          _H._ufw_first_public_rule(_UFW_HDR + "[ 1] 27000:27030/udp   ALLOW IN   Anywhere\n",
                                    27015, "tcp") is None)

    _w = _wire()
    eq("ufw limit: a bad port is refused unsent",
       (_H.remote_ufw_limit_port(_p8_srv(), "x"), _w.calls), ((False, "Invalid port"), []))
    eq("ufw limit: 'both' is refused — a limit is one rule for one protocol",
       (_H.remote_ufw_limit_port(_p8_srv(), 22, "both"), _w.calls),
       ((False, "Rate limiting needs a single protocol (tcp or udp)"), []))
    _w = _wire(verbs={"ufw-status": [(_BEFORE, "", 0), (_AFTER, "", 0)]})
    _lr = _H.remote_ufw_limit_port(_p8_srv(), 27015, "tcp")
    check("ufw limit: a BARE allow ahead of the limit is split — the other protocol re-opened "
          "with its comment BEFORE the bare rule is removed — and the read-back confirms it",
          _lr == (True, "27015/tcp is now rate limited (6 connections per 30s per address)")
          and [v for v in _w.verbs_called() if v[0] != "ufw-status"]
          == [("ufw-limit-port", ["27015/tcp"]), ("ufw-allow-port", ["27015/udp", "cs2server"]),
              ("ufw-delete-allow-port", ["27015"])], "result=%r verbs=%r" % (_lr, _w.verbs_called()))
    _w = _wire(verbs={"ufw-status": [(_BEFORE, "", 0), (_BEFORE, "", 0)],
                      "ufw-allow-port": ("", "Command timed out", -1)})
    _lr = _H.remote_ufw_limit_port(_p8_srv(), 27015, "tcp")
    check("ufw limit: when re-opening the other protocol FAILS, the bare rule stays and the answer "
          "says the limit is never reached, and why it was not split",
          _lr[0] is False and "still matched first" in _lr[1] and "could not split" in _lr[1]
          and not _w.verbs_called("ufw-delete-allow-port"), "result=%r" % (_lr,))
    _wire(verbs={"ufw-status": [(_BEFORE, "", 0), ("", "SSH command timed out", -1)]})
    check("ufw limit: a read-back that did not happen is not reported as limited",
          _H.remote_ufw_limit_port(_p8_srv(), 27015, "tcp")[1].endswith(
              "could not be read back to confirm it is the rule connections meet first."))
    _wire(verbs={"ufw-status": [(_BEFORE, "", 0), ("Status: inactive\n", "", 0)]})
    check("ufw limit: an inactive firewall stores the limit but limits nothing — said so",
          "UFW is not active" in _H.remote_ufw_limit_port(_p8_srv(), 27015, "tcp")[1])
    _wire(verbs={"ufw-status": [(_BEFORE, "", 0), (_UFW_HDR + "[ 1] 27015/tcp  LIMIT IN  Anywhere\n",
                                                   "", 0)]})
    _lr = _H.remote_ufw_limit_port(_p8_srv(), 27015, "tcp")
    check("ufw limit: a split that left the OTHER protocol closed is a failure naming it",
          _lr[0] is False and "27015/udp is no longer open" in _lr[1], repr(_lr))
    _wire(verbs={"ufw-limit-port": ("", "ERROR: Could not update running firewall", 1)})
    eq("ufw limit: a refused limit returns ufw's error", _H.remote_ufw_limit_port(_p8_srv(), 22),
       (False, "ERROR: Could not update running firewall"))
    # Lifting a limit.
    _w = _wire(verbs={"ufw-status": ("", "SSH command timed out", -1)})
    check("ufw unlimit: an unread firewall changes nothing",
          _H.remote_ufw_limit_port(_p8_srv(), 22, limit=False)[0] is False
          and not _w.verbs_called("ufw-allow-port"))
    _w = _wire(verbs={"ufw-status": ("Status: inactive\n", "", 0)})
    check("ufw unlimit: an inactive firewall's stored rules cannot be read — nothing changed",
          "UFW is not active" in _H.remote_ufw_limit_port(_p8_srv(), 22, limit=False)[1]
          and not _w.verbs_called("ufw-allow-port"))
    _w = _wire(verbs={"ufw-status": (_BEFORE, "", 0)})
    eq("ufw unlimit: no LIMIT on that port -> nothing to remove, and nothing opened",
       (_H.remote_ufw_limit_port(_p8_srv(), 27015, limit=False), _w.verbs_called("ufw-allow-port")),
       ((False, "27015/tcp has no rate limit to remove."), []))
    _w = _wire(verbs={"ufw-status": (_BEFORE, "", 0)})
    eq("ufw unlimit: a LIMIT is rewritten to an allow in place (the port stays open)",
       (_H.remote_ufw_limit_port(_p8_srv(), 22, limit=False), _w.verbs_called("ufw-allow-port")),
       ((True, "Rate limit removed from 22/tcp (it stays open)"),
        [("ufw-allow-port", ["22/tcp", ""])]))
    _wire(verbs={"ufw-status": (_BEFORE, "", 0), "ufw-allow-port": ("", "locked", 1)})
    eq("ufw unlimit: ...and a refused rewrite says why",
       _H.remote_ufw_limit_port(_p8_srv(), 22, limit=False), (False, "locked"))

    # ── closing ports ──────────────────────────────────────────────────────────────────────────
    _w = _wire()
    eq("ufw close: an unknown protocol is refused unsent",
       (_H.remote_ufw_close_port(_p8_srv(), 22, "sctp"), _w.calls), ((False, "Invalid protocol"), []))
    eq("ufw close: invalid port refused", _H.remote_ufw_close_port(_p8_srv(), "22 && id"),
       (False, "Invalid port"))
    eq("ufw close: one protocol deletes the proto rule",
       (_H.remote_ufw_close_port(_p8_srv(), 22, "tcp"), _w.verbs_called()),
       ((True, "Port 22/tcp closed on remote"), [("ufw-delete-allow-proto-port", ["tcp", "22"])]))
    _wire(verbs={"ufw-delete-allow-port": ("Could not delete non-existent rule", "", 1)})
    eq("ufw close: a failed bare delete is reported", _H.remote_ufw_close_port(_p8_srv(), 27015),
       (False, "Could not delete non-existent rule"))
    _wire(verbs={"ufw-delete-allow-port": ("", "", 0)})
    eq("ufw close port 22: removes the 22/tcp allow", _H.remote_ufw_close_port_22(_p8_srv()),
       (True, "Port 22 rule removed from UFW"))
    _wire(verbs={"ufw-delete-allow-port": ("", "", 1)})
    eq("ufw close port 22: a silent failure still says it failed",
       _H.remote_ufw_close_port_22(_p8_srv()), (False, "Failed to remove port 22"))
    _w = _wire(verbs={"ufw-delete-allow-port": ("", "", 0), "ufw-delete-allow-proto-port": [
        ("", "", 1), ("", "", 0)]})
    eq("ufw close game port: the bare rule plus both legacy proto rules, counting what went",
       (_H.remote_ufw_close_game_port(_p8_srv(), 27015), _w.verbs_called()),
       ((2, "Port 27015: 2 rule(s) removed"),
        [("ufw-delete-allow-port", ["27015"]), ("ufw-delete-allow-proto-port", ["tcp", "27015"]),
         ("ufw-delete-allow-proto-port", ["udp", "27015"])]))

    # ── delete by number: an unverifiable firewall refuses ────────────────────────────────────
    _w = _wire()
    for _bad in ("x", None, 0, -3):
        check("ufw delete: rule number %r refused unsent" % (_bad,),
              _H.remote_ufw_delete_rule(_p8_srv(), _bad) == (False, "Invalid rule number")
              and _w.calls == [])
    eq("ufw delete: a non-string rule identity is refused",
       _H.remote_ufw_delete_rule(_p8_srv(), 3, expect_key=["x"]), (False, "Invalid rule identity"))
    _sm_firewall.remote_ufw_status = lambda s: (_ for _ in ()).throw(ConnectionError("down"))
    _dr = _H.remote_ufw_delete_rule(_p8_srv(auth_method="key"), 3)
    check("ufw delete: a status read that RAISES refuses — 'could not check' is not 'safe'",
          _dr[0] is False and "Couldn't read the firewall" in _dr[1] and _w.calls == [], repr(_dr))
    _sm_firewall.remote_ufw_status = lambda s: {"installed": False, "groups": [], "unreachable": True}
    check("ufw delete: an unreachable status refuses too",
          "Couldn't read the firewall" in _H.remote_ufw_delete_rule(_p8_srv(), 3)[1])
    _sm_firewall.remote_ufw_status = lambda s: {"installed": False, "groups": []}
    eq("ufw delete: ufw genuinely absent is said as itself",
       _H.remote_ufw_delete_rule(_p8_srv(), 3),
       (False, "UFW isn't installed on this host, so there's no rule 3 to delete."))
    _sm_firewall.remote_ufw_status = lambda s: {"installed": True, "groups": [
        {"key": "k-ssh", "nums": [1, 4], "protected": True, "protect_reason": "last SSH rule"},
        {"key": "k-game", "nums": [3], "protected": False}]}
    check("ufw delete: a key that no longer sits at that number removes nothing",
          "no longer the rule" in _H.remote_ufw_delete_rule(_p8_srv(), 3, expect_key="k-ssh")[1]
          and _w.calls == [])
    eq("ufw delete: a protected rule is refused with its reason",
       (_H.remote_ufw_delete_rule(_p8_srv(), 4), _w.calls), ((False, "last SSH rule"), []))
    eq("ufw delete: an unprotected rule that still matches its key is deleted by number",
       (_H.remote_ufw_delete_rule(_p8_srv(), 3, expect_key="k-game"), _w.verbs_called()),
       ((True, "Rule 3 deleted"), [("ufw-delete-num", [3])]))
    _n_status = {"n": 0}

    def _count_status(s):
        _n_status["n"] += 1
        return {"installed": True, "groups": []}
    _sm_firewall.remote_ufw_status = _count_status
    _w = _wire(verbs={"ufw-delete-num": ("", "ERROR: Could not find rule '9'", 1)})
    eq("ufw delete: force=True without a key skips the read entirely and reports ufw's refusal",
       (_H.remote_ufw_delete_rule(_p8_srv(), 9, force=True), _n_status["n"]),
       ((False, "ERROR: Could not find rule '9'"), 0))

    # ── game ports ─────────────────────────────────────────────────────────────────────────────
    _w = _wire()
    eq("game port: an out-of-range port is (0, Invalid port), unsent",
       (_H.remote_ufw_allow_game_port(_p8_srv(), 70000), _w.calls), ((0, "Invalid port"), []))
    eq("game port: one bare rule tagged with the server's safe name",
       (_H.remote_ufw_allow_game_port(_p8_srv(), "27015", "cs2`id`server"), _w.verbs_called()),
       ((1, "Port 27015: opened (TCP+UDP)"), [("ufw-allow-port", ["27015", "cs2idserver"])]))
    _w = _wire()
    _H.remote_ufw_allow_game_port(_p8_srv(), 27015, "$()")
    eq("game port: a name with nothing safe in it is tagged 'Game'", _w.verbs_called()[-1][1][1], "Game")
    _wire(verbs={"ufw-allow-port": lambda a: ("", "", 1) if a[0] == "27016" else ("", "", 0)})
    eq("game ports: the list is de-duplicated and sorted, and only what OPENED is reported",
       _H.remote_ufw_allow_game_ports(_p8_srv(), [27016, "27015", 27015, None, 0], "cs2"),
       ([27015], "opened 1 port(s): 27015"))
    _wire(verbs={"ufw-allow-port": ("", "", 1)})
    eq("game ports: nothing opened says 'none'", _H.remote_ufw_allow_game_ports(_p8_srv(), [1]),
       ([], "opened 0 port(s): none"))

    # ── close_by_name: re-read before every delete, never retry a refused rule ─────────────────
    eq("close by name: a name with nothing safe in it deletes nothing",
       _H.remote_ufw_close_by_name(_p8_srv(), "$();|&"), (0, "no name"))
    _cbn_rules = [{"comment": "cs2server", "key": "k1", "nums": [2, 6]},
                  {"comment": "cs2server", "key": "k2", "nums": [4]},
                  {"comment": "other", "key": "k3", "nums": [5]}]
    _sm_firewall.remote_ufw_status = lambda s: {"installed": True,
                                                "groups": [dict(g, nums=list(g["nums"]))
                                                           for g in _cbn_rules]}
    _cbn_del = []

    def _cbn_delete(server, n, force=False, expect_key=None):
        _cbn_del.append((n, expect_key))
        if expect_key == "k2":
            return False, "protected"
        for g in _cbn_rules:
            if n in g["nums"]:
                g["nums"].remove(n)
        return True, "deleted"
    _H.remote_ufw_delete_rule = _cbn_delete
    _cbn = _H.remote_ufw_close_by_name(_p8_srv(), "cs2server")
    check("close by name: only the tagged rules go, highest number first, each named by its key; "
          "a refused one is skipped and never retried",
          _cbn == (2, "2 rule(s) removed for cs2server")
          and _cbn_del == [(6, "k1"), (4, "k2"), (2, "k1")], "result=%r deletes=%r" % (_cbn, _cbn_del))
    _sm_firewall.remote_ufw_status = lambda s: {"installed": False, "groups": [], "unreachable": True}
    eq("close by name: an unreachable firewall deletes nothing",
       _H.remote_ufw_close_by_name(_p8_srv(), "cs2server"), (0, "0 rule(s) removed for cs2server"))
    _H.remote_ufw_delete_rule = _h_saved["remote_ufw_delete_rule"]
    _sm_firewall.remote_ufw_status = _h_fw_saved["remote_ufw_status"]

    # ── dependency lists ───────────────────────────────────────────────────────────────────────
    eq("apt names: duplicates, blanks and anything that is not a package name are dropped",
       _H._apt_pkgs(["curl", "curl", "libstdc++5:i386", "$(id)", "", None, "a;b", "jq"]),
       ["curl", "libstdc++5:i386", "jq"])
    _osrv = _p8_srv()
    _w = _wire(cmds=[("os-release", ("ubuntu-24.04", "", 0))])
    eq("os slug: read from os-release and cached (two asks, one read)",
       (_H.host_os_slug(_osrv), _H.host_os_slug(_osrv), len(_w.calls)), ("ubuntu-24.04", "ubuntu-24.04", 1))
    _osrv = _p8_srv()
    _w = _wire(cmds=[("os-release", ("", "SSH command timed out", -1))])
    check("os slug: an unread os-release is None and NOT remembered (the next ask retries)",
          _H.host_os_slug(_osrv) is None and _H.host_os_slug(_osrv) is None and len(_w.calls) == 2)
    _wire(cmds=[("os-release", ("x" * 40, "", 0))])
    check("os slug: an implausible answer is not a slug", _H.host_os_slug(_p8_srv()) is None)
    _wire(cmds=[("os-release", ConnectionError("down"))])
    check("os slug: a raising transport is None", _H.host_os_slug(_p8_srv(auth_method="key")) is None)
    _H._load_deps_csv = lambda slug=None: {"all": ["curl", "steamcmd", ""], "steamcmd": ["lib32gcc-s1"],
                                           "cs2": ["curl", "libfoo1"], "_slug": [slug]}
    eq("deps for game: all + steamcmd + the game's own, de-duplicated, steamcmd itself set apart",
       _H.deps_for_game("cs2", "ubuntu-22.04"), (["curl", "lib32gcc-s1", "libfoo1"], True))
    _H._load_deps_csv = lambda slug=None: {"all": ["curl"]}
    eq("deps for game: a game with no steamcmd need says so", _H.deps_for_game("mc"), (["curl"], False))
    _H._load_deps_csv = _h_saved["_load_deps_csv"]

    _H.host_os_slug = lambda s: "ubuntu-24.04"
    _H.deps_for_game = lambda g, slug=None: (["curl", "libfoo1", "$(touch /tmp/x)"], False)
    _w = _wire()
    _gd = _H.install_game_dependencies(_p8_srv(), "cs2", extra="steamcmd jq")
    check("game deps: i386 + universe + multiverse + update first, steamcmd because the retry "
          "named it, then ONE batch of validated names (the injected one dropped)",
          _gd[0] is True and _w.verbs_called() == [
              ("dpkg-add-arch", ["i386"]), ("apt-add-repo", ["universe"]),
              ("apt-add-repo", ["multiverse"]), ("apt-update", []), ("steamcmd-install", []),
              ("apt-install-minimal", ["curl", "libfoo1", "jq"])],
          "result=%r verbs=%r" % (_gd, _w.verbs_called()))
    _w = _wire(verbs={"apt-install-minimal": lambda a: ("", "E: Unable to locate package libfoo1", 100)
                      if len(a) > 1 or a == ["libfoo1"] else ("ok", "", 0)})
    _gd = _H.install_game_dependencies(_p8_srv(), "cs2")
    check("game deps: a failed batch falls back to one package at a time, and the batch's failure "
          "is what gets reported",
          _gd[0] is False and "Unable to locate" in _gd[1]
          and _w.verbs_called("apt-install-minimal")[1:]
          == [("apt-install-minimal", ["curl"]), ("apt-install-minimal", ["libfoo1"])],
          "result=%r verbs=%r" % (_gd, _w.verbs_called("apt-install-minimal")))
    _H.deps_for_game = lambda g, slug=None: (["p%02d" % i for i in range(60)], False)
    _w = _wire()
    eq("game deps: a long list goes in chunks the verb table accepts (48 + 12)",
       [len(a) for _, a in _w.verbs_called("apt-install-minimal")] if _H.install_game_dependencies(
           _p8_srv(), "big")[0] else None, [48, 12])
    _w = _wire(verbs={"steamcmd-install": ("", "E: debconf locked", 1)})
    _gd = _H.install_game_dependencies(_p8_srv())
    check("game deps: no game type -> the common set AND steamcmd; a failed steamcmd fails the step",
          _gd[0] is False and _w.verbs_called("steamcmd-install")
          and "tmux" in _w.verbs_called("apt-install-minimal")[0][1], repr(_gd))
    _H.deps_for_game = lambda g, slug=None: (["$(bad)"], False)
    _w = _wire()
    eq("game deps: nothing valid to install is said, and no install is sent",
       (_H.install_game_dependencies(_p8_srv(), "x"), _w.verbs_called("apt-install-minimal")),
       ((True, "no dependencies to install"), []))
    _H.host_os_slug = _h_saved["host_os_slug"]
    _H.deps_for_game = _h_saved["deps_for_game"]

    # ── OS updates ─────────────────────────────────────────────────────────────────────────────
    _w = _wire(cmds=[("apt list --upgradable",
                      ("Listing...\ncurl/noble-updates 8.5.0-2ubuntu10.6 amd64 [upgradable from: "
                       "8.5.0-2ubuntu10.5]\nN: notice line\nopenssl/noble-security 3.0.13-0ubuntu3.5 "
                       "amd64 [upgradable from: 3.0.13-0ubuntu3.4]", "", 0))])
    _cu = _H.remote_os_check_updates(_p8_srv())
    check("os check: apt update first, then the upgradable list parsed (notices skipped)",
          _cu["ok"] is True and _cu["count"] == 2
          and [p["name"] for p in _cu["packages"]] == ["curl", "openssl"]
          and _w.calls[0] == ("verb", "apt-update", []), repr(_cu))
    _wire(cmds=[("apt list --upgradable", ("", "SSH command timed out", -1))])
    eq("os check: a list that was not read is ok=False — NOT a clean host",
       _H.remote_os_check_updates(_p8_srv()), {"ok": False, "count": 0, "packages": []})
    _wire(verbs={"apt-full-upgrade": ("x" * 500 + "done", "", 0)})
    _ru = _H.remote_os_run_updates(_p8_srv())
    check("os run: success returns the tail of apt's output",
          _ru[0] is True and len(_ru[1]) == 300 and _ru[1].endswith("done"), repr(_ru)[:80])
    _wire(verbs={"apt-full-upgrade": ("", "E: Could not get lock", 100)})
    eq("os run: a failure returns the error", _H.remote_os_run_updates(_p8_srv()),
       (False, "E: Could not get lock"))
    _w = _wire(verbs={"apt-upgrade-running": ("", "", 0)})
    eq("os update start: one already running is watched, not started again",
       (_H.remote_os_update_start(_p8_srv()), _w.verbs_called("os-update-run")),
       ((True, "An update is already running — watching it."), []))
    _wire(verbs={"apt-upgrade-running": ("", "", 1),
                 "os-update-run": ("launching\n" + _p8_priv.OS_UPDATE_STARTED, "", 0)})
    eq("os update start: the job's own STARTED marker is success",
       _H.remote_os_update_start(_p8_srv()), (True, "Update started."))
    _wire(verbs={"apt-upgrade-running": ("", "", 1), "os-update-run": ("", "", 0)})
    eq("os update start: rc 0 without the marker is NOT a start",
       _H.remote_os_update_start(_p8_srv()), (False, "Couldn't start the update."))

    # ── reboot probes ──────────────────────────────────────────────────────────────────────────
    _wire(verbs={"reboot": ("sudo: a password is required\n", "", 1)})
    eq("reboot: a positive rc is the host REFUSING — reported as a failure",
       _H.remote_reboot(_p8_srv()), (False, "sudo: a password is required "))
    _wire(verbs={"reboot": ("", "SSH command timed out", -1)})
    eq("reboot: a dropped connection (-1) is what a real reboot looks like",
       _H.remote_reboot(_p8_srv()), (True, "Reboot command sent to remote"))
    _wire(cmds=[("reboot-required.pkgs", ConnectionError("dropped")), ("reboot-required", ("YES", "", 0))])
    eq("reboot required: YES with a package list that could not be read is still required",
       _H.remote_reboot_required(_p8_srv(auth_method="key")),
       {"required": True, "packages": [], "known": True})
    _wire(cmds=[("reboot-required.pkgs", ("linux-image-6.8\nlibc6\n\nlibc6\n", "", 0)),
                ("reboot-required", ("YES", "", 0))])
    eq("reboot required: the packages are de-duplicated and sorted",
       _H.remote_reboot_required(_p8_srv())["packages"], ["libc6", "linux-image-6.8"])

    # ── remote_uptime ──────────────────────────────────────────────────────────────────────────
    _up_out = ("UPTIME up 3 days, 2 hours\n\nLOAD 0.10 0.20 0.30\nDISK 5G/40G\nMEM 1.2Gi/3.8Gi\n"
               "MEMPCT 31.6\nKERNEL 6.8.0-45-generic\nCORES 0\n"
               "cpu  100 0 100 800 0 0 0 0\ncpu  160 0 160 880 0 0 0 0\n")
    _usrv = _p8_srv()
    _w = _wire(cmds=[("UPTIME", (_up_out, "", 0))])
    _u = _H.remote_uptime(_usrv)
    check("uptime: every tagged line parsed, CPU% from the /proc/stat delta",
          _u["uptime"] == "3 days, 2 hours" and _u["load"] == "0.10 0.20 0.30"
          and _u["disk"] == "5G/40G" and _u["memory"] == "1.2Gi/3.8Gi" and _u["kernel"].startswith("6.8")
          and _u["cpu_percent"] == "60.0" and _u["read_ok"] is True, repr(_u))
    eq("uptime: zero cores does not divide by zero — per-core stays blank", _u["cpu_per_core"], "")
    _H.remote_uptime(_usrv)
    eq("uptime: a good read is cached (a second viewer costs nothing)", len(_w.calls), 1)
    _H.remote_uptime(_usrv, force=True)
    eq("uptime: force re-reads", len(_w.calls), 2)

    # ── waiting out a reboot ───────────────────────────────────────────────────────────────────
    _clk = {"t": 1000.0}
    _H.time = NS(time=lambda: _clk["t"], sleep=lambda s: _clk.__setitem__("t", _clk["t"] + s))
    _H.decrypt_secret = lambda s: "decrypted:" + (s or "")
    _seen_creds = []

    def _updown(pattern):
        seq = list(pattern)

        def _t(host, port, user, method, cred, host_key=""):
            _seen_creds.append((host, port, method, cred, host_key))
            return (seq.pop(0) if len(seq) > 1 else seq[0]), "x"
        return _t
    _waits = []
    _H.ssh_test_connection = _updown([True, True, False, False, True])
    _rb_srv = _p8_srv(auth_method="key", auth_credential="enc", host_key="ssh-ed25519 AAAA", port=2222)
    check("reboot wait: up, up, DOWN, down, UP -> came back",
          _H._wait_for_reboot(_rb_srv, on_wait=_waits.append) is True)
    check("reboot wait: ...probing with the stored (decrypted) credential AND the pinned host key",
          _seen_creds[0] == ("203.0.113.10", 2222, "key", "decrypted:enc", "ssh-ed25519 AAAA"),
          repr(_seen_creds[:1]))
    check("reboot wait: ...and narrating both phases",
          "Waiting for server to go down for reboot…" in _waits
          and "Rebooting — waiting for server to come back online…" in _waits, repr(_waits))
    _H.ssh_test_connection = lambda *a, **k: (_ for _ in ()).throw(OSError("refused"))
    check("reboot wait: a host that never answers again is False after the timeout — a probe that "
          "raises counts as down",
          _H._wait_for_reboot(_rb_srv, down_timeout=20, up_timeout=30) is False)
    _H.ssh_test_connection = _updown([True])
    check("reboot wait: a host that never went down but is up is back (down phase times out)",
          _H._wait_for_reboot(_rb_srv, down_timeout=20, up_timeout=30) is True)
    _H.time = _h_saved["time"]
    _H.ssh_test_connection = _h_saved["ssh_test_connection"]
    _H.decrypt_secret = _h_saved["decrypt_secret"]

    for _t, _want in (("v22.3.0", 22), ("  v18.19.1\n", 18), ("20.1.0", 20), ("", None),
                      ("node: not found", None)):
        eq("node major: %r -> %r" % (_t, _want), _H._node_major(_t), _want)
    _w = _wire(cmds=[("node -v", ("v12.22.9", "", 0))],
               verbs={"nodesource-setup": ("repo ok", "", 0),
                      "apt-install": ("E: nodejs held", "", 100)})
    _bn = _H._bootstrap_node(_p8_srv())
    check("bootstrap node: an old Node gets NodeSource, and a failed nodejs install stops before npm",
          _bn[-1].startswith("Node.js install failed") and not any(
              c for c in _w.calls if c[0] == "cmd" and "npm" in c[1]), repr(_bn))

    # ── the full VPS bootstrap ─────────────────────────────────────────────────────────────────
    _bs_users, _bs_closed, _bs_waits = [], [], []
    # Any reboot this section does not ask for is caught here instead of polling a real host.
    _H._wait_for_reboot = lambda server, on_wait=None, **k: (_bs_waits.append(server.id), False)[1]
    _sm_core.create_game_user = lambda server, user, timeout=30: (_bs_users.append(user), ("", "", 0))[1]
    _sm_core.close_connection = lambda server: _bs_closed.append(server.id)
    _SSHD_T_OK = ("port 22\nport 2222\nclientaliveinterval 300\nclientalivecountmax 2\n"
                  "permitrootlogin without-password\npasswordauthentication no\n")

    def _bs_wire(verbs=None, cmds=None):
        v = {"dpkg-lock-held": ("", "", 1), "apt-full-upgrade": ("l1\nl2\nUpgrade done", "", 0),
             "sshd-effective-config": (_SSHD_T_OK, "", 0), "gamedig-install": ("gamedig ok", "", 0)}
        v.update(verbs or {})
        c = list(cmds or []) + [("node -v", ("v22.1.0", "", 0)), ("command -v npm", ("/usr/bin/npm", "", 0)),
                                ("swapon", ("0", "", 0)), ("echo 'EXISTS'", ("NOTEXISTS", "", 0)),
                                ("reboot-required", ("NO", "", 0)), ("pgrep -x tmux", ("NO", "", 0))]
        return _wire(verbs=v, cmds=c)

    def _bs_idx(w, verb, args=None):
        for i, c in enumerate(w.calls):
            if c[0] in ("verb", "write") and c[1] == verb and (args is None or c[2] == args):
                return i
        return -1

    _prog = []
    del _bs_users[:]
    _w = _bs_wire()
    _bs = _H.remote_bootstrap_vps(_p8_srv(), username="lgsm", progress=lambda *a: _prog.append(a))
    check("bootstrap: a clean run on a remote completes every step it counted",
          _bs[0] is True and _bs[1] == "VPS bootstrap complete (16/16 steps)."
          and _prog[-1] == (16, 16, "Bootstrap complete", "done"), "result=%r last=%r" % (_bs[:2], _prog[-1:]))
    check("bootstrap: EVERY port sshd listens on is rate-limited BEFORE the shadowing allows go and "
          "before UFW is switched on",
          -1 < _bs_idx(_w, "ufw-limit-port", ["22/tcp"]) < _bs_idx(_w, "ufw-limit-port", ["2222/tcp"])
          < _bs_idx(_w, "ufw-delete-allow-app", ["OpenSSH"]) < _bs_idx(_w, "ufw-enable"),
          repr(_w.names()))
    check("bootstrap: fail2ban's jail is written for the ports sshd really uses",
          any(c[0] == "write" and c[1] == "fail2ban-jail-local" and "port = 22,2222\n" in c[2]
              for c in _w.calls), repr([c for c in _w.calls if c[0] == "write"]))
    check("bootstrap: a key/tailscale remote gets root-password and password login switched off",
          ("sshd-set-directive", ["PermitRootLogin", "prohibit-password"]) in _w.verbs_called()
          and ("sshd-set-directive", ["PasswordAuthentication", "no"]) in _w.verbs_called()
          and _w.verbs_called("service-restart")[0] == ("service-restart", ["ssh"]))
    check("bootstrap: no swap -> one is created; the account is created and its password locked; "
          "the timezone set; the LinuxGSM deps included in the essentials",
          _w.verbs_called("create-swapfile") and _bs_users == ["lgsm"]
          and ("user-lock-password", ["lgsm"]) in _w.verbs_called()
          and ("set-timezone", ["UTC"]) in _w.verbs_called()
          and "lib32gcc-s1" in _w.verbs_called("apt-install")[0][1]
          and "2G swap file created" in _bs[2], repr(_bs_users))
    check("bootstrap: no reboot needed -> no reboot sent", _bs_idx(_w, "reboot-delayed") == -1
          and "No reboot needed" in _bs[2])

    _w = _bs_wire(verbs={"ufw-limit-port": lambda a: ("", "ERROR: problem running iptables", 1)
                         if a == ["2222/tcp"] else ("", "", 0)})
    _bs = _H.remote_bootstrap_vps(_p8_srv())
    check("bootstrap: when one SSH port's limit FAILS, nothing that lets SSH in is removed and UFW "
          "is NOT switched on — and the result is not 'complete'",
          _bs[0] is False and "firewall was NOT enabled" in _bs[1] and "2222/tcp" in _bs[1]
          and _bs_idx(_w, "ufw-enable") == -1 and _bs_idx(_w, "ufw-default") == -1
          and _bs_idx(_w, "ufw-delete-allow-app") == -1, "result=%r" % (_bs[1],))

    _w = _bs_wire(verbs={"sshd-effective-config": ("port 22\npermitrootlogin yes\n"
                                                   "passwordauthentication yes\n", "", 0)})
    _bs = _H.remote_bootstrap_vps(_p8_srv())
    check("bootstrap: sshd still reporting password login after the edit FAILS the bootstrap and "
          "names what is still on",
          _bs[0] is False and "PasswordAuthentication yes" in _bs[1] and "PermitRootLogin yes" in _bs[1]
          and "Password SSH login is still ENABLED" in _bs[2], "result=%r" % (_bs[1],))
    _w = _bs_wire(verbs={"sshd-effective-config": ("", "SSH command timed out", -1)})
    _bs = _H.remote_bootstrap_vps(_p8_srv(port=2200), set_timezone="")
    check("bootstrap: an unreadable `sshd -T` is 'could not be verified', never a bare 'complete', "
          "and UFW falls back to the port the panel connects on",
          _bs[0] is True and "could not be verified" in _bs[1]
          and _w.verbs_called("ufw-limit-port") == [("ufw-limit-port", ["2200/tcp"])]
          and not _w.verbs_called("set-timezone"), "result=%r" % (_bs[1],))

    _prog_raise = []

    def _bad_progress(*a):
        _prog_raise.append(a)
        raise RuntimeError("socket closed under the progress stream")
    _w = _bs_wire(cmds=[("swapon", ("", "SSH command timed out", -1)),
                        ("echo 'EXISTS'", ("uid=1001(lgsm) EXISTS", "", 0))])
    _w.writes["node-tools-cron"] = ("", "", 1)
    del _bs_users[:]
    _bs = _H.remote_bootstrap_vps(_p8_srv(auth_method="password"), username="lgsm",
                                  enable_ufw=False, install_fail2ban=False, install_lgsm_deps=False,
                                  progress=_bad_progress)
    check("bootstrap: a password remote keeps password login (never locked out), and a progress "
          "stream that raises does not stop the job",
          _bs[0] is True and ("sshd-set-directive", ["PasswordAuthentication", "no"]) not in _w.verbs_called()
          and "left ENABLED" in _bs[2] and not _w.verbs_called("service-restart")
          and len(_prog_raise) > 10, "result=%r" % (_bs[1],))
    check("bootstrap: an unread swap probe creates nothing; an existing account is not re-created; "
          "a failed cron write is said",
          not _w.verbs_called("create-swapfile") and _bs_users == []
          and "Could not check for swap" in _bs[2] and "User lgsm already exists" in _bs[2]
          and "could not be scheduled" in _bs[2], _bs[2][-400:])
    _w = _bs_wire()
    _bs = _H.remote_bootstrap_vps(_p8_srv(), username="bad;name")
    check("bootstrap: an invalid account name is refused, never reaching useradd",
          "isn't a valid username" in _bs[2] and not _w.verbs_called("user-lock-password"))

    # The reboot decision: unknown never reboots.
    _w = _bs_wire(cmds=[("reboot-required", ("YES", "", 0)), ("pgrep -x tmux", ("", "timed out", -1))])
    _bs = _H.remote_bootstrap_vps(_p8_srv())
    check("bootstrap: reboot needed but the running-servers probe did not answer -> NOT rebooted, "
          "and the log says why", _bs_idx(_w, "reboot-delayed") == -1
          and "did not answer the check for running game servers" in _bs[2])
    _w = _bs_wire(cmds=[("reboot-required", ("", "timed out", -1))])
    _bs = _H.remote_bootstrap_vps(_p8_srv())
    check("bootstrap: an unanswered reboot-required probe leaves the host alone",
          _bs_idx(_w, "reboot-delayed") == -1 and "Could not check whether a reboot is needed" in _bs[2])
    _w = _bs_wire(cmds=[("reboot-required", ("YES", "", 0)), ("pgrep -x tmux", ("YES", "", 0))])
    _bs = _H.remote_bootstrap_vps(_p8_srv())
    check("bootstrap: reboot needed with game servers running -> skipped to protect players",
          _bs_idx(_w, "reboot-delayed") == -1 and "once its game servers are empty" in _bs[2])
    _H._wait_for_reboot = lambda server, on_wait=None, **k: (on_wait and on_wait("waiting"), True)[1]
    del _bs_closed[:]
    _rs = _p8_srv()
    _w = _bs_wire(cmds=[("reboot-required", ("YES", "", 0))])
    _bs = _H.remote_bootstrap_vps(_rs)
    check("bootstrap: reboot needed and the host empty -> delayed reboot, the pooled connection "
          "dropped, and the job waits for it to come back",
          _bs[0] is True and _bs_idx(_w, "reboot-delayed") > -1 and _bs_closed == [_rs.id]
          and "Server is back online." in _bs[2], "result=%r" % (_bs[1],))
    _H._wait_for_reboot = lambda server, on_wait=None, **k: False
    _bs_wire(cmds=[("reboot-required", ("YES", "", 0))])
    eq("bootstrap: a host that does not come back is a failure",
       _H.remote_bootstrap_vps(_p8_srv())[:2],
       (False, "Server was rebooted but did not come back online within the timeout."))
    _H._wait_for_reboot = lambda server, on_wait=None, **k: (_bs_waits.append(server.id), False)[1]
    _w = _bs_wire()
    _bs = _H.remote_bootstrap_vps(_p8_srv(is_local=True))
    check("bootstrap: the panel's own host is never reboot-checked (and has one step fewer)",
          _bs[1] == "VPS bootstrap complete (14/14 steps)." and "Reboot check skipped" in _bs[2]
          and not any(c for c in _w.calls if c[0] == "cmd" and "reboot-required" in c[1]), _bs[1])

    # ── remote Tailscale ───────────────────────────────────────────────────────────────────────
    _TS_RUN = _p8_json.dumps({"BackendState": "Running", "Self": {
        "DNSName": "vps.tail1234.ts.net.", "TailscaleIPs": ["100.64.0.5", "fd7a:115c:a1e0::5"]}})
    _wire(cmds=[("which tailscale", ("/usr/bin/tailscale\nINSTALLED", "", 0)),
                ("tailscale status --json", (_TS_RUN, "", 0))])
    eq("remote tailscale: a running node reads its MagicDNS name and every address",
       _H.remote_check_tailscale(_p8_srv()),
       {"installed": True, "running": True, "tailscale_ip": "100.64.0.5, fd7a:115c:a1e0::5",
        "dns_name": "vps.tail1234.ts.net"})
    _wire(cmds=[("which tailscale", ("INSTALLED", "", 0)), ("tailscale status --json", ("{}", "", 0))])
    eq("remote tailscale: an ANSWERED failed status ('{}') is installed-not-running, not unreachable",
       _H.remote_check_tailscale(_p8_srv()),
       {"installed": True, "running": False, "tailscale_ip": "", "dns_name": ""})
    _wire(cmds=[("which tailscale", ("INSTALLED", "", 0)), ("tailscale status --json", ("", "", -1))])
    check("remote tailscale: a status probe that returned nothing is unreachable",
          _H.remote_check_tailscale(_p8_srv()).get("unreachable") is True)
    _wire(cmds=[("which tailscale", ("INSTALLED", "", 0)), ("tailscale status --json", ("<html>", "", 0))])
    check("remote tailscale: unparseable status is not running (and not a raise)",
          _H.remote_check_tailscale(_p8_srv())["running"] is False)
    _wire(cmds=[("which tailscale", ("NOTINSTALLED", "", 0))])
    eq("remote tailscale: NOTINSTALLED is a reading — not installed, not unreachable",
       _H.remote_check_tailscale(_p8_srv()),
       {"installed": False, "running": False, "tailscale_ip": "", "dns_name": ""})
    _wire(cmds=[("which tailscale", ("", "SSH command timed out", -1))])
    _rc = _H.remote_check_tailscale(_p8_srv())
    check("remote tailscale: an EMPTY probe is not 'installed' (NOTINSTALLED is not in '') and is "
          "flagged unreachable", _rc["installed"] is False and _rc.get("unreachable") is True, repr(_rc))

    _w = _wire(cmds=[("os-release", ("NAME=Ubuntu", "", 0)), ("install.sh", ("Installation complete!", "", 0)),
                     ("tailscale version 2>&1", ("/usr/bin/tailscale\n1.80.2", "", 0))])
    _it = _H.remote_install_tailscale(_p8_srv())
    check("remote tailscale install: curl, the install script AS ROOT, then a verify",
          _it[:2] == (True, "Tailscale installed successfully") and ("apt-install", ["curl"]) in _w.verbs_called()
          and any(c[0] == "cmd" and "install.sh" in c[1] and c[2] is True for c in _w.calls)
          and "Installed: /usr/bin/tailscale" in _it[2], repr(_it))
    _w = _wire(cmds=[("install.sh", ("curl: (22) 404", "", 22))])
    _it = _H.remote_install_tailscale(_p8_srv())
    check("remote tailscale install: a failed script stops there",
          _it[:2] == (False, "Tailscale install script failed")
          and not any(c[0] == "cmd" and "tailscale version" in c[1] for c in _w.calls), repr(_it[:2]))
    _wire(cmds=[("tailscale version 2>&1", ("", "", 1))])
    eq("remote tailscale install: no binary afterwards is a failure",
       _H.remote_install_tailscale(_p8_srv())[:2], (False, "Tailscale binary not found after install"))

    _ts_st = {"v": {"running": False}}
    _H.remote_check_tailscale = lambda s: dict(_ts_st["v"])
    _w = _wire(verbs={"tailscale-up-login": ("waiting\n" + _ts_url, "", 0)})
    _tu = _H.remote_tailscale_up_url(_p8_srv(), enable_ssh=False, advertise_routes="10.0.0.0/24")
    check("remote tailscale up: routes turn on forwarding first, then the login URL comes back",
          _tu == (True, _ts_url) and _w.names() == ["sysctl-tailscale", "sysctl-reload", "tailscale-up-login"]
          and _w.verbs_called("tailscale-up-login") == [("tailscale-up-login", ["no", "10.0.0.0/24"])],
          "result=%r calls=%r" % (_tu, _w.names()))
    _wire(verbs={"tailscale-up-login": (_ts_url + "/../evil", "", 0)})
    eq("remote tailscale up: a URL the remote padded is refused (fullmatch), falling to status",
       _H.remote_tailscale_up_url(_p8_srv()), (False, _ts_url + "/../evil"))
    _wire(verbs={"tailscale-up-login": ("", "", -1)})
    eq("remote tailscale up: nothing at all -> a message, not a blank success",
       _H.remote_tailscale_up_url(_p8_srv()),
       (False, "Could not get a Tailscale login link — is Tailscale installed on the remote?"))
    _ts_st["v"] = {"running": True}
    eq("remote tailscale up: a node that is already Running is already connected",
       _H.remote_tailscale_up_url(_p8_srv()), (True, "ALREADY_CONNECTED"))

    _w = _wire()
    eq("remote tailscale bootstrap: no auth key is refused, nothing sent",
       (_H.remote_bootstrap_tailscale(_p8_srv(), auth_key=""), _w.calls),
       ((False, "Auth key is required. Generate one at https://login.tailscale.com/admin/keys", ""), []))
    _ts_st["v"] = {"running": True, "tailscale_ip": "100.64.0.5", "dns_name": "vps.ts.net"}
    _w = _wire(verbs={"ufw-status": ("", "SSH command timed out", -1)})
    _bt = _H.remote_bootstrap_tailscale(_p8_srv(), auth_key="tskey-auth-k1", advertise_routes="10.0.0.0/24",
                                        tags="tag:server")
    check("remote tailscale bootstrap: forwarding, then up with the key + flags, then tailscale0 is "
          "allowed even though UFW could not be read (a no-op if it is off)",
          _bt[:2] == (True, "Tailscale connected! IP: 100.64.0.5 DNS: vps.ts.net")
          and _w.verbs_called("tailscale-up-key") == [
              ("tailscale-up-key", ["tskey-auth-k1", "yes", "10.0.0.0/24", "tag:server"])]
          and _w.verbs_called("ufw-allow-iface") == [("ufw-allow-iface", ["tailscale0"])]
          and "could not be read" in _bt[2], repr(_bt))
    _wire(verbs={"tailscale-up-key": ("", "invalid key: unable to validate", 1)})
    eq("remote tailscale bootstrap: a rejected key is a failure with tailscale's reason",
       _H.remote_bootstrap_tailscale(_p8_srv(), auth_key="tskey-bad")[:2],
       (False, "Tailscale auth failed: invalid key: unable to validate"))
    _ts_st["v"] = {"running": False, "tailscale_ip": "", "dns_name": ""}
    _w = _wire(verbs={"ufw-status": ("Status: inactive\n", "", 0)})
    _bt = _H.remote_bootstrap_tailscale(_p8_srv(), auth_key="tskey-auth-k1")
    check("remote tailscale bootstrap: an inactive UFW gets no rule, and not-running after auth fails",
          _bt[:2] == (False, "Tailscale installed but not running after auth")
          and not _w.verbs_called("ufw-allow-iface"), repr(_bt[:2]))

    _ts_st["v"] = {"running": False}
    eq("migrate: not running -> nothing changes",
       _H.remote_migrate_to_tailscale(_p8_srv()), (None, "Tailscale is not running on the remote"))
    _ts_st["v"] = {"running": True, "dns_name": "", "tailscale_ip": "100.64.0.5, fd7a:115c:a1e0::5"}
    _H._tailscale_conn_state = lambda s: (True, True)
    _mig_probe = []
    _H.ssh_test_connection = lambda host, port=22, username="root", auth_method="key", **k: (
        _mig_probe.append((host, port, username, auth_method)), (True, "ok"))[1]
    _w = _wire(verbs={"ufw-delete-allow-port": ConnectionError("dropped")})
    _mg = _H.remote_migrate_to_tailscale(_p8_srv(username="admin", auth_method="key"))
    check("migrate: no MagicDNS name -> the FIRST Tailscale address; the login is proven over "
          "Tailscale SSH before port 22 closes; a raising close is not fatal",
          _mg[0] == "100.64.0.5" and _mig_probe == [("100.64.0.5", 22, "admin", "tailscale")]
          and _w.verbs_called("ufw-delete-allow-port") == [("ufw-delete-allow-port", ["22/tcp"])],
          "result=%r probe=%r" % (_mg, _mig_probe))
    _H.ssh_test_connection = lambda *a, **k: (False, "Tailscale SSH denied")
    _w = _wire()
    _mg = _H.remote_migrate_to_tailscale(_p8_srv())
    check("migrate: a failed Tailscale SSH login stops BEFORE port 22 is touched",
          _mg[0] is None and "Tailscale SSH denied" in _mg[1] and not _w.calls, repr(_mg))
    _H._tailscale_conn_state = lambda s: (True, False)
    _mg = _H.remote_migrate_to_tailscale(_p8_srv())
    check("migrate: Tailscale up but its SSH server off -> refused", _mg[0] is None
          and "SSH server is not enabled" in _mg[1] and not _w.calls, repr(_mg))
    for _n in ("remote_check_tailscale", "_tailscale_conn_state", "ssh_test_connection"):
        setattr(_H, _n, _h_saved[_n])

    # ── sshd helpers ───────────────────────────────────────────────────────────────────────────
    for _k, _want, _got, _res in (("PermitRootLogin", "prohibit-password", "no", True),
                                  ("PermitRootLogin", "prohibit-password", "without-password", True),
                                  ("PermitRootLogin", "prohibit-password", "yes", False),
                                  ("PermitRootLogin", "no", "prohibit-password", False),
                                  ("PasswordAuthentication", "no", "no", True),
                                  ("PasswordAuthentication", "no", "yes", False),
                                  ("PasswordAuthentication", "no", "", False)):
        eq("sshd value: %s want %s, sshd says %r -> applied=%s" % (_k, _want, _got, _res),
           _H._sshd_value_applied(_k, _want, _got), _res)
    _wire(verbs={"sshd-effective-config": ("port 22\npasswordauthentication yes\nx\n", "", 0)})
    eq("sshd unapplied: what sshd will NOT use, as (key, wanted, effective), and readable",
       _H._sshd_unapplied_directives(_p8_srv(), [("PasswordAuthentication", "no"),
                                                 ("ClientAliveInterval", "300")]),
       ([("PasswordAuthentication", "no", "yes"), ("ClientAliveInterval", "300", "")], True))
    _wire(verbs={"sshd-effective-config": ("port 22\n", "sudo: a password is required", 1)})
    eq("sshd unapplied: a failed read is ([], unreadable) — never 'everything applied'",
       _H._sshd_unapplied_directives(_p8_srv(), [("PasswordAuthentication", "no")]), ([], False))
    _wire(verbs={"sshd-effective-config": ("Port 2222\nport 22\nport abc\n", "", 0)})
    eq("bootstrap ssh ports: sshd's own ports, plus the stored one, no duplicates, no junk",
       _H._bootstrap_ssh_ports(_p8_srv(port=2200)), ["2222", "22", "2200"])
    _wire(verbs={"sshd-effective-config": ("", "", -1)})
    eq("bootstrap ssh ports: an unread sshd -T still leaves the port the panel connects on",
       _H._bootstrap_ssh_ports(_p8_srv(port=None)), ["22"])
    for _ss, _p, _want in (("LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\n", 2222, True),
                           ("LISTEN 0 128 0.0.0.0:22222 0.0.0.0:*\n", 2222, False),
                           ("LISTEN 0 128 [::]:22 [::]:*\n", 22, True), ("", 22, False)):
        eq("listener: port %d in %r -> %s" % (_p, _ss.strip(), _want), _H._port_has_listener(_ss, _p), _want)
    eq("ssh.socket drop-in: the list is RESET first, then both families per port",
       _H._socket_listen_lines(["2222", "22"], ""),
       "[Socket]\nListenStream=\nListenStream=0.0.0.0:2222\nListenStream=[::]:2222\n"
       "ListenStream=0.0.0.0:22\nListenStream=[::]:22\n")
    eq("ssh.socket drop-in: a bound IPv6 address is bracketed",
       _H._socket_listen_lines(["2222"], "fd00::5"), "[Socket]\nListenStream=\nListenStream=[fd00::5]:2222\n")
    _w = _wire()
    _H._restart_ssh_listener(_p8_srv(), True)
    eq("ssh restart: socket activation restarts ssh.socket, then the service",
       _w.verbs_called("service-restart"), [("service-restart", ["ssh.socket"]), ("service-restart", ["ssh"])])
    _w = _wire(verbs={"service-restart": lambda a: ("", "Unit ssh.service not found.", 5)
                      if a == ["ssh"] else ("", "", 0)})
    eq("ssh restart: without it, `ssh` then `sshd` (non-Debian unit name)",
       (_H._restart_ssh_listener(_p8_srv(), False)[2], _w.verbs_called("service-restart")),
       (0, [("service-restart", ["ssh"]), ("service-restart", ["sshd"])]))

    _tcp = []

    class _TcpConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    _H.socket = NS(create_connection=lambda addr, timeout=None: (_tcp.append((addr, timeout)), _TcpConn())[1])
    check("tcp reachable: a connection that opens is True, to (host, int(port)) with the timeout",
          _H._tcp_reachable("203.0.113.10", "2222", timeout=3) is True
          and _tcp == [(("203.0.113.10", 2222), 3)], repr(_tcp))
    _H.socket = NS(create_connection=lambda addr, timeout=None: (_ for _ in ()).throw(
        ConnectionRefusedError(111, "refused")))
    check("tcp reachable: refused is False", _H._tcp_reachable("203.0.113.10", 2222) is False)
    _H.socket = _h_saved["socket"]

    # ── change_ssh_port: every failure after step 1 puts the host back ──────────────────────────
    _SS_22 = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
    _SS_BOTH = _SS_22 + "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\n"

    def _csp_wire(**v):
        base = {"sshd-socket-active": ("inactive", "", 3), "sshd-effective-config": ("port 22\n", "", 0),
                "listening-sockets": [(_SS_22, "", 0), (_SS_BOTH, "", 0)]}
        base.update(v)
        return _wire(verbs=base)
    _w = _csp_wire()
    eq("ssh port: the port sshd is already on is refused, nothing written",
       (_H.change_ssh_port(_p8_srv(), 22), [c for c in _w.calls if c[0] == "write"]),
       ((False, "SSH is already on port 22."), []))
    _w = _csp_wire(**{"sshd-validate": ("", "/etc/ssh/sshd_config.d/panel.conf: Bad port", 255)})
    _cp = _H.change_ssh_port(_p8_srv(), 2222)
    check("ssh port: a config sshd rejects is reverted — snapshot restored, the opened port CLOSED "
          "again, sshd restarted — and nothing else is touched",
          _cp[0] is False and _cp[1].startswith("sshd rejected the new config — nothing changed.")
          and ("write", "sshd-port-dropin") in [(c[0], c[1]) for c in _w.calls]
          and _w.names()[-3:] == ["sshd-restore-dropin", "ufw-delete-allow-proto-port", "service-restart"]
          and not _w.verbs_called("f2b-set-sshd-ports"), "result=%r names=%r" % (_cp, _w.names()))
    check("ssh port: ...and the drop-in it tried kept the old port beside the new one",
          any(c[0] == "write" and c[2].endswith("Port 2222\nPort 22\n") for c in _w.calls))
    _w = _csp_wire(**{"sshd-socket-active": ("active", "", 0), "sshd-validate": ("", "bad", 1)})
    _cp = _H.change_ssh_port(_p8_srv(port=2200), 2222)
    _drop = [c[2] for c in _w.calls if c[0] == "write"]
    check("ssh port (socket-activated): the ssh.socket drop-in carries the new port, sshd_config's "
          "port AND the port the panel is connected on — and a revert reloads systemd again",
          _cp[0] is False and _drop and "ListenStream=0.0.0.0:2222\n" in _drop[0]
          and "ListenStream=0.0.0.0:2200\n" in _drop[0] and "ListenStream=0.0.0.0:22\n" in _drop[0]
          and len(_w.verbs_called("systemd-daemon-reload")) == 2
          and ("service-restart", ["ssh.socket"]) in _w.verbs_called(), "drop=%r names=%r" % (_drop, _w.names()))
    _w = _csp_wire(**{"listening-sockets": [(_SS_22, "", 0), (_SS_22, "", 0)]})
    _cp = _H.change_ssh_port(_p8_srv(), 2222)
    check("ssh port: sshd not listening on the new port afterwards is reverted",
          _cp == (False, "sshd didn't come up on port 2222 — reverted. Your existing SSH still works.")
          and "sshd-restore-dropin" in _w.names() and "sshd-discard-backup" not in _w.names(), repr(_cp))
    _H._tcp_reachable = lambda host, port, timeout=8: False
    _w = _csp_wire()
    _cp = _H.change_ssh_port(_p8_srv(), 2222, bind_addr="198.51.100.4")
    check("ssh port: a bind the panel cannot reach afterwards is reverted, naming the address",
          _cp[0] is False and "couldn't reach it on 203.0.113.10:2222" in _cp[1]
          and any(c[0] == "write" and "ListenAddress 198.51.100.4:2222\n" in c[2] for c in _w.calls),
          repr(_cp))
    _H._tcp_reachable = _h_saved["_tcp_reachable"]
    _w = _csp_wire()
    _cp = _H.change_ssh_port(_p8_srv(), 2222)
    check("ssh port: a clean move ends with the snapshot discarded and fail2ban repointed at both",
          _cp[0] is True and _cp[1].startswith("SSH now listens on port 2222")
          and _w.names()[-1] == "sshd-discard-backup"
          and ("f2b-set-sshd-ports", ["2222,22"]) in _w.verbs_called(), repr(_cp))

    # ── fail2ban on a remote ───────────────────────────────────────────────────────────────────
    _wire(verbs={"f2b-status": ("Status\n|- Number of jail: 2\n`- Jail list:\tsshd, recidive, bad jail!", "", 0),
                 "f2b-status-jail": lambda a: (
                     "|- Currently failed: 1\n|  |- Total failed: 9\n`- Actions\n   |- Currently banned: 2\n"
                     "   |- Total banned: 5\n   `- Banned IP list: 198.51.100.7 203.0.113.99", "", 0)
                 if a == ["sshd"] else ("", "Sorry but the jail 'recidive' does not exist", 255)})
    eq("f2b overview: each jail's counts and bans; a jail whose status failed is left out, not zeroed",
       _H.remote_fail2ban_overview(_p8_srv()),
       {"installed": True, "jails": [{"jail": "sshd", "currently_banned": 2, "total_banned": 5,
                                      "total_failed": 9, "banned_ips": ["198.51.100.7", "203.0.113.99"]}]})
    _wire(verbs={"ufw-status": ("", "SSH command timed out", -1)})
    check("f2b/ufw blocked: an unread firewall is None, not 'nothing blocked'",
          _H.remote_ufw_blocked_ips(_p8_srv()) is None)
    _wire(verbs={"ufw-status": ("Status: inactive\n", "", 0)})
    check("f2b/ufw blocked: an INACTIVE firewall is None too (its rules drop nothing)",
          _H.remote_ufw_blocked_ips(_p8_srv()) is None)

    _F2B_LOG = ("2026-09-25 10:00:01,000 fail2ban.filter [1]: INFO [sshd] Found 198.51.100.7 - x\n"
                "2026-09-25 10:00:02,000 fail2ban.filter [1]: INFO [sshd] Found 198.51.100.7 - x\n"
                "2026-09-25 10:00:03,000 fail2ban.actions [1]: NOTICE [sshd] Ban 198.51.100.7\n"
                "2026-09-25 10:00:04,000 fail2ban.filter [1]: INFO [recidive] Found 203.0.113.99 - x\n")
    _w = _wire(verbs={"f2b-log-lines": (_F2B_LOG, "", 0)})
    _H.remote_fail2ban_overview = lambda s: (_ for _ in ()).throw(ConnectionError("down"))
    _H.remote_ufw_blocked_ips = lambda s, shadowed=None: (_ for _ in ()).throw(ConnectionError("down"))
    _top = _H.remote_fail2ban_top_ips(_p8_srv(), limit="lots", days="a week")
    check("f2b top: nonsense limit/days fall back to 20/7; the tally stands even when the ban and "
          "block annotations could not be read",
          [(r["ip"], r["attempts"], r["bans"], r["banned_now"], r["blocked"], r["jails"]) for r in _top]
          == [("198.51.100.7", 2, 1, False, False, ["sshd"]),
              ("203.0.113.99", 1, 0, False, False, ["recidive"])]
          and _w.verbs_called("f2b-log-lines")[0][1] == [_p8_time.strftime(
              "%Y-%m-%d", _p8_time.localtime(_p8_time.time() - 7 * 86400))], repr(_top))
    _H.remote_fail2ban_overview = lambda s: {"jails": [{"jail": "sshd", "banned_ips": ["198.51.100.7"]}]}
    _H.remote_ufw_blocked_ips = lambda s, shadowed=None: {"203.0.113.99": "panel-autoblock"}
    _top = _H.remote_fail2ban_top_ips(_p8_srv(), limit=1)
    eq("f2b top: the limit cuts the ranked list; banned/blocked annotate each row",
       [(r["ip"], r["banned_now"], r["blocked"]) for r in _top], [("198.51.100.7", True, False)])
    _wire(verbs={"f2b-log-lines": ("", "SSH command timed out", -1)})
    check("f2b top: a failed read is None — not 'no offenders'",
          _H.remote_fail2ban_top_ips(_p8_srv()) is None)

    _w = _wire()
    eq("f2b unban: a jail name that is not one is refused unsent",
       (_H.remote_fail2ban_unban(_p8_srv(), "sshd; rm -rf /", "1.2.3.4"), _w.calls),
       ((False, "Invalid jail name."), []))
    eq("f2b unban: a well-formed jail the host does not have is refused",
       _H.remote_fail2ban_unban(_p8_srv(), "nginx", "1.2.3.4"), (False, "Unknown jail on that host."))
    eq("f2b unban: an address that is not one is refused",
       _H.remote_fail2ban_unban(_p8_srv(), "sshd", "1.2.3"), (False, "Invalid IP address."))
    _w = _wire()
    eq("f2b unban: the address is CANONICALISED — fail2ban stores the short form",
       (_H.remote_fail2ban_unban(_p8_srv(), " sshd ", "2001:0DB8::0001"), _w.verbs_called()),
       ((True, "Unbanned 2001:db8::1 from sshd."), [("f2b-unban", ["sshd", "2001:db8::1"])]))
    _wire(verbs={"f2b-unban": ("ERROR  NOK: ('198.51.100.7 is not banned',)\n", "", 255)})
    eq("f2b unban: fail2ban's refusal comes back on one line",
       _H.remote_fail2ban_unban(_p8_srv(), "sshd", "198.51.100.7"),
       (False, "ERROR  NOK: ('198.51.100.7 is not banned',) "))
    _H.remote_fail2ban_overview = _h_saved["remote_fail2ban_overview"]
    _H.remote_ufw_blocked_ips = _h_saved["remote_ufw_blocked_ips"]

    _w = _wire(verbs={"f2b-status": ("", "fail2ban-client: command not found", 127)})
    eq("f2b ignoreip: no fail2ban -> refused, and nothing written",
       (_H.remote_set_fail2ban_ignoreip(_p8_srv(), ["203.0.113.5"]), _w.calls[1:]),
       ((False, "fail2ban not installed on this host"), []))
    _w = _wire(verbs={"f2b-status": ("`- Jail list:\tsshd, recidive, bad jail!", "", 0)})
    _ig = _H.remote_set_fail2ban_ignoreip(_p8_srv(name="vps7"), ["203.0.113.5", "not-an-ip"],
                                          unban_ip="203.0.113.5")
    check("f2b ignoreip: the whitelist drop-in is written from the shared builder, fail2ban "
          "reloaded, and the IP unbanned in each REAL jail",
          _ig == (True, "ignoreip applied on vps7")
          and ("write", "fail2ban-panel-whitelist", SO.f2b_whitelist_dropin_body(["203.0.113.5", "not-an-ip"]))
          in _w.calls and ("f2b-reload", []) in _w.verbs_called()
          and _w.verbs_called("f2b-unban") == [("f2b-unban", ["sshd", "203.0.113.5"]),
                                               ("f2b-unban", ["recidive", "203.0.113.5"])],
          "result=%r verbs=%r" % (_ig, _w.verbs_called()))
    _w = _wire(verbs={"f2b-status": ("`- Jail list:\tsshd", "", 0)})
    _H.remote_set_fail2ban_ignoreip(_p8_srv(), [], unban_ip="999.1.1.1")
    eq("f2b ignoreip: an invalid unban address unbans nothing", _w.verbs_called("f2b-unban"), [])

    _wire(verbs={"log-tail": ("x [sshd] Ban 1.2.3.4\ny [recidive] Ban 5.6.7.8\nz [sshd] Found 1.2.3.4", "", 0)})
    eq("security log: a jail narrows the fail2ban activity to that jail's lines",
       _H.remote_security_log(_p8_srv(), "fail2ban", lines=50, jail="sshd"),
       "x [sshd] Ban 1.2.3.4\nz [sshd] Found 1.2.3.4")
    _w = _wire()
    eq("security log: a log name outside the fixed set reads nothing",
       (_H.remote_security_log(_p8_srv(), "/etc/shadow"), _w.calls), ("", []))

    # ── tailnet state probes fail SAFE ─────────────────────────────────────────────────────────
    _wire(cmds=[("tailscale status --json", ConnectionError("down"))])
    eq("tailnet state: a status probe that raises is (not running, no SSH)",
       _H._tailscale_conn_state(_p8_srv(auth_method="key")), (False, False))
    _wire(cmds=[("tailscale status --json", ('{"BackendState": "Running"}', "", 0)),
                ("tailscale debug prefs", ConnectionError("down"))])
    eq("tailnet state: running, but prefs that raise -> SSH NOT assumed on",
       _H._tailscale_conn_state(_p8_srv(auth_method="key")), (True, False))
    _H._tailscale_conn_state = lambda s: (True, False)
    _wire(verbs={"ufw-status": ConnectionError("down")})
    eq("tailnet ssh state: a ufw read that raises -> the tailscale0 rule is NOT assumed present",
       _H._tailnet_ssh_state(_p8_srv(auth_method="key")), (True, False, False))
    _H._tailscale_conn_state = _h_saved["_tailscale_conn_state"]
    _w = _wire()
    eq("public ssh: an unknown mode is refused unsent",
       (_H.remote_set_public_ssh(_p8_srv(), "open-sesame"), _w.calls), ((False, "Invalid mode"), []))

    # ── ssh_test_connection ────────────────────────────────────────────────────────────────────
    _cli_seen = []

    def _cli(resp):
        def _c(server, command, timeout=30, sudo=None, stdin_text=None):
            _cli_seen.append((server.host, server.port, server.username, server.auth_method, sudo))
            return resp
        return _c
    _sm_core._run_via_ssh_cli = _cli(("ok\nroot", "", 0))
    eq("ssh test (tailscale): the system ssh client answers, unprivileged",
       (_H.ssh_test_connection("vps.ts.net", 22, "root", auth_method="tailscale"), _cli_seen),
       ((True, "Tailscale SSH connection successful"), [("vps.ts.net", 22, "root", "tailscale", False)]))
    for _err, _want in (("tailscale: Permission denied (tailnet policy)",
                         "Tailscale SSH denied — check the tailnet ACL allows SSH to this node/user."),
                        ("ssh: connect to host vps.ts.net port 22: Connection timed out",
                         "Timed out reaching vps.ts.net over Tailscale. Is the node online?"),
                        ("kex_exchange_identification: read: Connection reset",
                         "Tailscale SSH failed: kex_exchange_identification: read: Connection reset")):
        _sm_core._run_via_ssh_cli = _cli(("", _err, 255))
        eq("ssh test (tailscale): %r is explained" % _err[:30],
           _H.ssh_test_connection("vps.ts.net", auth_method="tailscale"), (False, _want))
    _sm_core._run_via_ssh_cli = _p8_tripwire("_run_via_ssh_cli")

    import paramiko as _p8_paramiko  # noqa: E402
    import socket as _p8_socket  # noqa: E402

    class _FakeSSH:
        raise_on_connect = None
        last = None

        def __init__(self):
            self.policy, self.kw, self.closed = None, None, False
            _FakeSSH.last = self

        def set_missing_host_key_policy(self, p):
            self.policy = p

        def connect(self, host, **kw):
            self.kw = dict(kw, host=host)
            if _FakeSSH.raise_on_connect is not None:
                raise _FakeSSH.raise_on_connect

        def close(self):
            self.closed = True
    _H.paramiko = NS(SSHClient=_FakeSSH, AuthenticationException=_p8_paramiko.AuthenticationException)
    _FakeSSH.last = None
    _st = _H.ssh_test_connection("203.0.113.10", 22, "root", auth_method="password", credential="")
    check("ssh test (password): no usable stored password FAILS — it never falls through to the "
          "panel user's own key", _st[0] is False and "No usable SSH password" in _st[1]
          and _FakeSSH.last.kw is None, repr(_st))
    _st = _H.ssh_test_connection("203.0.113.10", 2222, "admin", auth_method="password",
                                 credential="hunter2", host_key="ssh-ed25519 AAAApin")
    _k = _FakeSSH.last.kw
    check("ssh test (password): password only — no agent, no key files — against the PINNED key",
          _st == (True, "Connection successful") and _k["password"] == "hunter2"
          and _k["allow_agent"] is False and _k["look_for_keys"] is False and _k["port"] == 2222
          and _FakeSSH.last.policy.expected == "ssh-ed25519 AAAApin"
          and _FakeSSH.last.policy.reject_on_change is True and _FakeSSH.last.closed, repr(_k))
    _H.ssh_test_connection("203.0.113.10", auth_method="key", credential="/home/panel/.ssh/vps_key")
    check("ssh test (key): the stored key path is used, and first contact captures without a pin",
          _FakeSSH.last.kw["key_filename"] == "/home/panel/.ssh/vps_key"
          and _FakeSSH.last.policy.reject_on_change is False)
    _H.ssh_test_connection("203.0.113.10", auth_method="key")
    eq("ssh test (key): no stored path -> the panel user's default key",
       _FakeSSH.last.kw["key_filename"], os.path.expanduser("~/.ssh/id_rsa"))
    for _exc, _want in ((_p8_paramiko.AuthenticationException("bad"),
                         "SSH authentication failed. Check your credentials."),
                        (_p8_socket.timeout("t"), "Connection to 203.0.113.10:22 timed out. Is the host reachable?"),
                        (_p8_socket.gaierror("g"), "Cannot resolve hostname: 203.0.113.10"),
                        (ValueError("/home/panel/.ssh/id_rsa is not a valid key"),
                         "Connection failed. Check the host, port, credentials, and that SSH is reachable.")):
        _FakeSSH.raise_on_connect = _exc
        eq("ssh test: %s is answered, with no exception text leaking" % type(_exc).__name__,
           _H.ssh_test_connection("203.0.113.10", auth_method="key"), (False, _want))
    _FakeSSH.raise_on_connect = None
    _H.paramiko = _h_saved["paramiko"]

    # ── host_timezone ──────────────────────────────────────────────────────────────────────────
    _wire(cmd_default=ConnectionError("down"))
    eq("host timezone: a raising read is '' (never raises)", _H.host_timezone(_p8_srv(auth_method="key")), "")
    _wire(cmd_default=("\nEtc/UTC\nAmerica/Chicago\n", "", 0))
    eq("host timezone: the first line that is a real zone", _H.host_timezone(_p8_srv()), "Etc/UTC")
    _wire(cmd_default=("Mars/Olympus_Mons\n../../etc/passwd\n", "", 0))
    eq("host timezone: nothing that is a zone -> ''", _H.host_timezone(_p8_srv()), "")
finally:
    for _k, _v in _h_core_saved.items():
        setattr(_sm_core, _k, _v)
    for _k, _v in _h_saved.items():
        setattr(_H, _k, _v)
    for _k, _v in _h_fw_saved.items():
        setattr(_sm_firewall, _k, _v)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# panel/routes/remote_vps.py — driven through Flask's test client on a bare app
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The REAL view functions, registered on an app of their own. Their collaborators are stubbed on
# the route module (the closures read its globals) and the permission decorators' user on
# panel.security.auth, so what is under test is the route's own logic: what it validates, what it
# passes down, what it records, and what it answers.
import flask as _rv_flask  # noqa: E402
import panel.routes.remote_vps as _rv  # noqa: E402
import panel.security.auth as _rv_auth  # noqa: E402
from panel.core import panel_state as _rv_state  # noqa: E402

_rv_app = _rv_flask.Flask("p8_remote_vps")
_rv_app.secret_key = "unit-suite"
_rv_app.config["LOGIN_DISABLED"] = True
_rv.register(_rv_app)
_rv_app.logger.disabled = True
_rv_client = _rv_app.test_client()

_RV_NAMES = ("current_user", "get_remote", "get_game", "GameServer", "db", "log_action", "load_config",
             "change_ssh_port", "close_connection", "remote_ufw_open_port", "remote_ufw_allow_from",
             "remote_ufw_limit_port", "remote_ufw_close_port", "remote_ufw_delete_rule",
             "remote_ufw_status", "remote_ufw_allow_game_port", "remote_ufw_allow_game_ports",
             "detect_game_ports", "remote_uptime", "remote_os_run_updates", "remote_os_update_start",
             "sm_player_count", "sm_is_player_queryable", "remote_reboot_required", "can_access_remote",
             "has_permission", "host_specs", "_sm")
_rv_saved = {n: getattr(_rv, n) for n in _RV_NAMES}
_rv_auth_saved = {"current_user": _rv_auth.current_user}
_rv_rwe_ids = []


class _RvUser:
    is_authenticated = True

    def __init__(self, superadmin=True, name="admin"):
        self.is_superadmin = superadmin
        self.username = name

    def _get_current_object(self):
        return self


class _RvRemote:
    def __init__(self, rid, **kw):
        self.id, self.name, self.is_local = rid, "vps%d" % rid, False
        self.port, self.auth_method, self.host_key, self.host_key_fingerprint = 22, "tailscale", "k", "SHA256:abc"
        self.cached = []
        self.__dict__.update(kw)

    def update_cached_stats(self, stats):
        if getattr(self, "cache_raises", False):
            raise RuntimeError("stale row")
        self.cached.append(stats)


class _RvQuery:
    def __init__(self, rows):
        self.rows = rows

    def filter_by(self, **kw):
        return _RvQuery([r for r in self.rows if all(getattr(r, k, None) == v for k, v in kw.items())])

    def first(self):
        return self.rows[0] if self.rows else None

    def all(self):
        return list(self.rows)


_rv_log, _rv_db = [], {"commit": 0, "rollback": 0}
_rv_games = []


def _rv_json(resp):
    return resp.status_code, resp.get_json(silent=True)


try:
    _rv_auth.current_user = _RvUser()
    _rv.current_user = _RvUser()
    _rv_remotes = {}

    def _rv_remote(**kw):
        r = _RvRemote(next(_p8_ids), **kw)
        _rv_remotes[r.id] = r
        return r
    _rv.get_remote = lambda rid: _rv_remotes[rid]
    _rv.GameServer = NS(query=_RvQuery(_rv_games))
    _rv.db = NS(session=NS(commit=lambda: _rv_db.__setitem__("commit", _rv_db["commit"] + 1),
                           rollback=lambda: _rv_db.__setitem__("rollback", _rv_db["rollback"] + 1)))
    _rv.log_action = lambda user, action, target=None, detail=None, success=True, **k: _rv_log.append(
        (action, target, detail, success))
    _rv.can_access_remote = lambda u, rid: False
    _rv.has_permission = lambda u, p: False

    # ── retrust host key ───────────────────────────────────────────────────────────────────────
    _r = _rv_remote()
    _rv.close_connection = lambda remote: (_ for _ in ()).throw(KeyError("no pooled connection"))
    _c0 = _rv_db["commit"]
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/retrust-hostkey" % _r.id))
    check("retrust: the pinned key is CLEARED and committed, a missing pooled connection is not an "
          "error, and the audit row names the old fingerprint",
          _st == 200 and _body["success"] is True and _r.host_key == "" and _rv_db["commit"] == _c0 + 1
          and _rv_log[-1] == ("retrust_hostkey", _r.name, "cleared pinned host key (SHA256:abc)", True),
          "status=%r body=%r log=%r" % (_st, _body, _rv_log[-1:]))

    # ── firewall writes: 400 before anything is sent, and what IS sent ─────────────────────────
    _fw_calls = []
    _rv.remote_ufw_open_port = lambda remote, port, proto, comment: (
        _fw_calls.append(("open", port, proto, comment)), (True, "opened"))[1]
    _rv.remote_ufw_allow_from = lambda remote, source, port, proto, comment, allow=True: (
        _fw_calls.append(("from", source, port, proto, comment, allow)), (False, "nope"))[1]
    _rv.remote_ufw_limit_port = lambda remote, port, proto, limit=True: (
        _fw_calls.append(("limit", port, proto, limit)), (True, "limited"))[1]
    _rv.remote_ufw_close_port = lambda remote, port, proto: (
        _fw_calls.append(("close", port, proto)), (True, "closed"))[1]
    for _path, _js, _want in (("open", {"protocol": "udp"}, "Port required"),
                              ("allow-from", {"port": 22}, "Source and port required"),
                              ("allow-from", {"source": 5, "port": ""}, "Source and port required"),
                              ("limit", {}, "Port required"), ("close", {"port": 0}, "Port required")):
        _st, _body = _rv_json(_rv_client.post("/api/remote/%d/firewall/%s" % (_r.id, _path), json=_js))
        check("firewall %s: %r is a 400 and nothing is sent" % (_path, _js),
              _st == 400 and _body == {"success": False, "message": _want} and _fw_calls == [],
              "status=%r body=%r calls=%r" % (_st, _body, _fw_calls))
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/firewall/open" % _r.id,
                                          json={"port": "27015", "comment": "cs2"}))
    check("firewall open: port, default tcp and comment are passed down; the result and audit row "
          "follow the helper", _st == 200 and _body == {"success": True, "message": "opened"}
          and _fw_calls[-1] == ("open", "27015", "tcp", "cs2")
          and _rv_log[-1] == ("remote_port_open", "%s:27015/tcp" % _r.name, None, True),
          "body=%r calls=%r log=%r" % (_body, _fw_calls[-1:], _rv_log[-1:]))
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/firewall/allow-from" % _r.id,
                                          json={"source": " 10.0.0.0/24 ", "port": 22, "allow": False}))
    check("firewall allow-from: allow:false REMOVES (audited as such), with the source stripped; a "
          "failure is recorded as a failure",
          _body == {"success": False, "message": "nope"}
          and _fw_calls[-1] == ("from", "10.0.0.0/24", 22, "tcp", "", False)
          and _rv_log[-1] == ("remote_port_allow_from_remove", "%s:22/tcp" % _r.name, "from 10.0.0.0/24",
                              False), "calls=%r log=%r" % (_fw_calls[-1:], _rv_log[-1:]))
    _rv_client.post("/api/remote/%d/firewall/allow-from" % _r.id, json={"source": "10.0.0.0/24", "port": 22,
                                                                      "allow": "no"})
    check("firewall allow-from: only a literal false removes — any other value adds",
          _fw_calls[-1][-1] is True and _rv_log[-1][0] == "remote_port_allow_from")
    _rv_client.post("/api/remote/%d/firewall/limit" % _r.id, json={"port": 22, "limit": False})
    check("firewall limit: limit:false lifts the limit and is audited as an unlimit",
          _fw_calls[-1] == ("limit", 22, "tcp", False) and _rv_log[-1][0] == "remote_port_unlimit")
    _rv_client.post("/api/remote/%d/firewall/limit" % _r.id, json={"port": 2222, "protocol": "tcp"})
    check("firewall limit: by default it limits", _fw_calls[-1] == ("limit", 2222, "tcp", True)
          and _rv_log[-1][0] == "remote_port_limit")
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/firewall/close" % _r.id,
                                          json={"port": 8080, "protocol": "udp"}))
    check("firewall close: the port and protocol are passed down and audited",
          _body == {"success": True, "message": "closed"} and _fw_calls[-1] == ("close", 8080, "udp")
          and _rv_log[-1] == ("remote_port_close", "%s:8080/udp" % _r.name, None, True))

    # ── SSH port ───────────────────────────────────────────────────────────────────────────────
    _rv.current_user = _RvUser(superadmin=False, name="op")
    _csp = []
    _rv.change_ssh_port = lambda remote, port, bind: (_csp.append((port, bind)), (True, "moved"))[1]
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/ssh-port" % _r.id, json={"port": 2222}))
    check("ssh port: a user without access to THIS host is refused before anything runs",
          _st == 403 and _csp == [], "status=%r" % _st)
    _rv.current_user = _RvUser()
    _rv.change_ssh_port = lambda remote, port, bind: (_ for _ in ()).throw(RuntimeError("/etc/ssh boom"))
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/ssh-port" % _r.id, json={"port": 2222}))
    check("ssh port: a raise is a 500 with a GENERIC message, and the stored port is unchanged",
          _st == 500 and (_body or {}).get("message") == "Internal server error" and _r.port == 22,
          repr(_body))

    # ── close the panel's public port ──────────────────────────────────────────────────────────
    _rv.load_config = lambda: {"tailscale_setup_done": True, "port": 5000}
    _rv.remote_ufw_status = lambda remote: {"installed": True, "groups": [
        {"port_num": "5001", "nums": [4], "key": "k", "action": "ALLOW"}]}
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/close-panel-port" % _r.id))
    eq("close panel port: a remote is refused (it only applies to the panel host)",
       (_st, _body["message"]), (400, "Only applies to the panel host."))
    _loc = _rv_remote(is_local=True)
    _rv.load_config = lambda: {"tailscale_setup_done": False, "port": 5000}
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/close-panel-port" % _loc.id))
    check("close panel port: refused until Tailscale Serve is set up (the lockout guard)",
          _st == 400 and "Set up Tailscale Serve first" in _body["message"], repr(_body))
    _rv.load_config = lambda: {"tailscale_setup_done": True, "port": "not-a-port"}
    _rv.remote_ufw_status = lambda remote: {"installed": True, "groups": [
        {"port_num": "5001", "nums": [4], "key": "k", "action": "ALLOW"}]}
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/close-panel-port" % _loc.id))
    eq("close panel port: an unparseable configured port means 5000; no rule for it is 'already "
       "closed'", (_st, _body), (200, {"success": True, "message": "Public port 5000 is already closed."}))

    # ── one game server's port ─────────────────────────────────────────────────────────────────
    _gp = []
    _rv.remote_ufw_allow_game_port = lambda remote, port, name: (_gp.append((port, name)), (1, "opened"))[1]
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/game-port/3306/open" % _r.id))
    check("game port: a port no game server on this host uses is REFUSED, not opened",
          _st == 400 and "No game server on this host uses port 3306" in _body["message"] and _gp == [],
          repr(_body))
    _rv_games.append(NS(id=next(_p8_ids), remote_id=_r.id, port=27015, short_name="cs2server", name="CS2",
                        installed=True, game_type="cs2", query_type=None, status="online", lgsm_name="cs2server",
                        remote=_r))
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/game-port/27015/open" % _r.id))
    check("game port: a real game server's port is opened, tagged with that server's name",
          _body == {"success": True, "message": "opened", "rules_added": 1} and _gp == [(27015, "cs2server")]
          and _rv_log[-1] == ("game_port_open", "%s:27015" % _r.name, None, True), repr(_body))

    # ── sync ports ─────────────────────────────────────────────────────────────────────────────
    _gs = _rv_games[-1]
    _rv.get_game = lambda sid: _gs
    _rv.current_user = _RvUser(superadmin=False, name="viewer")
    _st, _body = _rv_json(_rv_client.post("/api/server/%d/sync-ports" % _gs.id))
    eq("sync ports: without MANAGE_REMOTES or INSTALL_SERVER -> 403", (_st, _body["message"]),
       (403, "Permission denied"))
    _rv.current_user = _RvUser()
    _rv.detect_game_ports = lambda remote, short, lgsm: {"game_port": 27016, "open_ports": [27016, 27017],
                                                         "ports": [{"port": 27016}]}
    _gpo = []
    _rv.remote_ufw_allow_game_ports = lambda remote, ports, name: (_gpo.append((list(ports), name)),
                                                                   ([27016], "x"))[1]
    _c0 = _rv_db["commit"]
    _st, _body = _rv_json(_rv_client.post("/api/server/%d/sync-ports" % _gs.id))
    check("sync ports: the detected game port is re-synced onto the row, and a PARTIAL open is "
          "reported as partial — success false, the missed port named",
          _gs.port == 27016 and _rv_db["commit"] == _c0 + 1 and _body["success"] is False
          and _body["failed_ports"] == [27017] and _body["open_ports"] == [27016]
          and "27017 could not be opened" in _body["message"] and _gpo == [([27016, 27017], "cs2server")]
          and _rv_log[-1][3] is False, "body=%r" % (_body,))
    _rv.detect_game_ports = lambda *a: (_ for _ in ()).throw(ConnectionError("down"))
    _st, _body = _rv_json(_rv_client.post("/api/server/%d/sync-ports" % _gs.id))
    eq("sync ports: a raise is a generic 500", (_st, _body),
       (500, {"success": False, "message": "Internal server error"}))

    # ── live stats: only a real reading is persisted ───────────────────────────────────────────
    _rv.remote_uptime = lambda remote: {"read_ok": True, "uptime": "3 days"}
    _st, _body = _rv_json(_rv_client.get("/api/remote/%d/live-stats" % _r.id))
    check("live stats: a reading is returned AND persisted to the row",
          _body == {"success": True, "read_ok": True, "uptime": "3 days"}
          and _r.cached == [{"read_ok": True, "uptime": "3 days"}], repr(_body))
    _r.cache_raises = True
    _rb0 = _rv_db["rollback"]
    _st, _body = _rv_json(_rv_client.get("/api/remote/%d/live-stats" % _r.id))
    check("live stats: a failed persist is rolled back and the reading still served",
          _body["success"] is True and _rv_db["rollback"] == _rb0 + 1, repr(_body))
    _r.cache_raises = False
    _rv.remote_uptime = lambda remote: {"read_ok": False, "uptime": "unknown"}
    _n_cached = len(_r.cached)
    _rv_client.get("/api/remote/%d/live-stats" % _r.id)
    eq("live stats: an unanswered read is NOT written over the last-known values", len(_r.cached), _n_cached)

    # ── OS updates ─────────────────────────────────────────────────────────────────────────────
    _rv.remote_os_run_updates = lambda remote: (False, "E: Could not get lock")
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/run-updates" % _r.id))
    check("run updates: the helper's answer is returned and audited with its success flag",
          _body == {"success": False, "message": "E: Could not get lock"}
          and _rv_log[-1] == ("remote_os_update", _r.name, None, False), repr(_body))
    _n_log = len(_rv_log)
    _rv.remote_os_update_start = lambda remote: (True, "Update started.")
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/os-update/start" % _r.id))
    check("os update start: a started update is audited as started",
          _body == {"success": True, "message": "Update started."}
          and _rv_log[-1] == ("remote_os_update", _r.name, "started", True), repr(_body))
    _rv.remote_os_update_start = lambda remote: (False, "Couldn't start the update.")
    _n_log = len(_rv_log)
    _rv_client.post("/api/remote/%d/os-update/start" % _r.id)
    eq("os update start: one that did not start writes no 'started' row", len(_rv_log), _n_log)
    _rv.remote_os_update_start = lambda remote: (_ for _ in ()).throw(ConnectionError("down"))
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/os-update/start" % _r.id))
    eq("os update start: a raise is a generic 500", (_st, _body),
       (500, {"success": False, "message": "Internal server error"}))

    # ── players before a reboot: an unreadable server is UNKNOWN, not empty ────────────────────
    _rv_games.append(NS(id=next(_p8_ids), remote_id=_r.id, port=7777, short_name="terraria", name="Terraria",
                        installed=True, game_type="terraria", query_type=None, status="online", remote=_r))
    _rv_games.append(NS(id=next(_p8_ids), remote_id=_r.id, port=2456, short_name="valheim", name="Valheim",
                        installed=True, game_type="vh", query_type=None, status="offline", remote=_r))

    def _pc(remote, short, gtype, port, qtype):
        if short == "cs2server":
            return 3
        raise ConnectionError("query timed out")
    _rv.sm_player_count = _pc
    _rv.sm_is_player_queryable = lambda gtype, qtype: gtype != "terraria"
    _st, _body = _rv_json(_rv_client.get("/api/remote/%d/players" % _r.id))
    eq("players: a query that RAISES on a running server is listed as unknown (with whether it is "
       "queryable at all); a stopped one is not a warning",
       _body, {"total": 3, "busy": [{"name": "CS2", "players": 3}],
               "unknown": [{"name": "Terraria", "queryable": False}]})

    # ── reboot ─────────────────────────────────────────────────────────────────────────────────
    _rv.remote_reboot_required = lambda remote: (_ for _ in ()).throw(ConnectionError("down"))
    _st, _body = _rv_json(_rv_client.get("/api/remote/%d/reboot-required" % _r.id))
    eq("reboot required: a raise answers not-required with the pending flag",
       _body, {"required": False, "packages": [], "pending_empty": False})
    _rv_rwe_ids.append(_r.id)
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/reboot" % _r.id, json={"when_empty": True}))
    with _rv_state._rwe_lock:
        _armed = dict(_rv_state._reboot_when_empty.get(_r.id) or {})
    check("reboot when empty: armed for this host, by this user, and nothing rebooted now",
          _body["pending"] is True and _body["success"] is True and _armed.get("by") == "admin"
          and _rv_log[-1] == ("reboot_when_empty_arm", _r.name, None, True), repr(_body))
    check("reboot when empty: the servers the panel cannot count are named in the note",
          "can't read the player count for Terraria" in _body["message"], _body["message"])
    _st, _body = _rv_json(_rv_client.get("/api/remote/%d/reboot-required" % _r.id))
    check("reboot required: ...and the pending flag now reads true", _body["pending_empty"] is True)
    _rv.GameServer = NS(query=NS(filter_by=lambda **kw: (_ for _ in ()).throw(RuntimeError("db locked"))))
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/reboot" % _r.id, json={"when_empty": True}))
    check("reboot when empty: a server list that cannot be read still arms it — just without the note",
          _st == 200 and _body["pending"] is True and "Note:" not in _body["message"], repr(_body))
    _rv.GameServer = NS(query=_RvQuery(_rv_games))
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/reboot-cancel" % _r.id))
    check("reboot cancel: a pending reboot is cancelled and audited",
          _body == {"success": True, "pending": False, "message": "Auto-reboot canceled."}
          and _r.id not in _rv_state._reboot_when_empty
          and _rv_log[-1] == ("reboot_when_empty_cancel", _r.name, None, True), repr(_body))
    _n_log = len(_rv_log)
    _st, _body = _rv_json(_rv_client.post("/api/remote/%d/reboot-cancel" % _r.id))
    check("reboot cancel: nothing pending says so and writes no row",
          _body["message"] == "Nothing was scheduled." and len(_rv_log) == _n_log)

    # ── specs ──────────────────────────────────────────────────────────────────────────────────
    _rv._sm = NS(host_os_slug=lambda remote: (_ for _ in ()).throw(ConnectionError("down")))
    _rv.host_specs = lambda remote: {"os": "Ubuntu 24.04", "cores": "4"}
    _st, _body = _rv_json(_rv_client.get("/api/remote/%d/specs" % _r.id))
    eq("specs (install picker): without MANAGE_REMOTES, only os_slug — '' when unreadable",
       (_st, _body), (200, {"os_slug": ""}))
    _rv.has_permission = lambda u, p: True
    _rv.host_specs = lambda remote: {"os": "Ubuntu 24.04", "cores": "4"}
    _st, _body = _rv_json(_rv_client.get("/api/remote/%d/specs" % _r.id))
    eq("specs: the hardware card plus os_slug, '' when the slug read raises",
       _body, {"os": "Ubuntu 24.04", "cores": "4", "os_slug": ""})
    _rv._sm = NS(host_os_slug=lambda remote: "debian-12")
    _st, _body = _rv_json(_rv_client.get("/api/remote/%d/specs" % _r.id))
    eq("specs: ...and the host's own slug when it reads", _body.get("os_slug"), "debian-12")
finally:
    for _k, _v in _rv_saved.items():
        setattr(_rv, _k, _v)
    _rv_auth.current_user = _rv_auth_saved["current_user"]
    with _rv_state._rwe_lock:
        for _rid in _rv_rwe_ids:
            _rv_state._reboot_when_empty.pop(_rid, None)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# ssh_manager.firewall — the lockout guard's inputs when config or the host misbehave
# ════════════════════════════════════════════════════════════════════════════════════════════════
from panel.core import config as _fw_cfg  # noqa: E402

_fw_saved = {n: getattr(_sm_firewall, n) for n in ("_config_unreadable",)}
_fw_cfg_saved = {"load_config": _fw_cfg.load_config, "data": _fw_cfg._cfg_cache.get("data")}
_fw_core_saved = {"run_command": _sm_core.run_command}
try:
    eq("firewall ssh ports: a stored port that is not a number adds nothing (22 stays)",
       _sm_firewall._ssh_ports(NS(port="ssh")), {22})
    eq("firewall ssh ports: a custom stored port is protected alongside 22",
       _sm_firewall._ssh_ports(NS(port="2222")), {22, 2222})
    _local = NS(is_local=True, auth_method="local")
    _sm_firewall._config_unreadable = lambda: True
    _fw_cfg._cfg_cache["data"] = {"port": 8443}
    eq("firewall panel port: an unparseable config.json answers the port the RUNNING panel parsed",
       _sm_firewall._panel_web_port(_local), 8443)
    _fw_cfg._cfg_cache["data"] = {"port": "eighty"}
    check("firewall panel port: ...and None when even that cannot be read as a port",
          _sm_firewall._panel_web_port(_local) is None)
    check("firewall tailscale rule: an unparseable config PROTECTS the tailscale0 rule",
          _sm_firewall._panel_served_over_tailscale(_local) is True)
    _sm_firewall._config_unreadable = lambda: False
    _fw_cfg.load_config = lambda *a, **k: (_ for _ in ()).throw(OSError("EACCES config.json"))
    check("firewall panel port: a config that raises on read gives no port (None)",
          _sm_firewall._panel_web_port(_local) is None)
    check("firewall tailscale rule: a config that raises on read keeps the rule protected",
          _sm_firewall._panel_served_over_tailscale(_local) is True)
    _fw_cfg.load_config = lambda *a, **k: {"port": "not-a-port", "tailscale_setup_done": True}
    eq("firewall panel port: a non-numeric configured port is the boot default, not a crash",
       _sm_firewall._panel_web_port(_local, ts_running=False), _fw_cfg.DEFAULT_CONFIG["port"])
    check("firewall panel port: Serve configured AND the tailnet up -> the public port is not the way in",
          _sm_firewall._panel_web_port(_local, ts_running=True) is None)
    check("firewall panel port: a remote host never has the panel's port", _sm_firewall._panel_web_port(
        NS(is_local=False, auth_method="key")) is None)
    _sm_firewall._specs_cache.clear()
    _sm_core.run_command = lambda s, c, timeout=30, sudo=None, stdin_text=None: (
        "OS\tUbuntu 24.04 LTS\nMAXMHZ\tunknown\nMEM\t3.8\nVIRT\tnone\nCPU\t\n", "", 0)
    _spec = _sm_firewall._compute_host_specs(_p8_srv())
    check("host specs: an unparseable CPU speed is blank (not a crash); no virt -> blank; no CPU "
          "model -> 'Unknown CPU'",
          _spec["cpu_speed"] == "" and _spec["virt"] == "" and _spec["cpu"] == "Unknown CPU"
          and _spec["ram"] == "3.8 GB" and _spec["os"] == "Ubuntu 24.04 LTS", repr(_spec))
finally:
    for _k, _v in _fw_saved.items():
        setattr(_sm_firewall, _k, _v)
    _fw_cfg.load_config = _fw_cfg_saved["load_config"]
    _fw_cfg._cfg_cache["data"] = _fw_cfg_saved["data"]
    _sm_core.run_command = _fw_core_saved["run_command"]


# ════════════════════════════════════════════════════════════════════════════════════════════════
# ssh_manager.files — reads that did not happen, refusals, and the download stream
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Asserted on what comes BACK (content, refusal, bytes yielded) and how many round trips it took —
# never on the text of the `sudo -u` command, which is being rewritten on another branch.
import base64 as _fl_b64  # noqa: E402

_F = _sm_files
_fl_saved = {n: getattr(_F, n) for n in ("_write_file_as_user", "subprocess")}
_fl_core_saved = {n: getattr(_sm_core, n) for n in (
    "run_command", "helper_present", "_resolve_ts_host", "get_connection")}
_fl_priv_saved = {"helper_argv": _p8_priv.helper_argv}


def _fl_rc(*answers):
    """run_command answering in order (the last repeats), counting the round trips."""
    seq, calls = list(answers), []

    def _rc(server, command, timeout=30, sudo=None, stdin_text=None):
        calls.append(sudo)
        r = seq.pop(0) if len(seq) > 1 else seq[0]
        if isinstance(r, BaseException):
            raise r
        return r
    _sm_core.run_command = _rc
    return calls


def _fl_frame(tag, text):
    return "__LGSMP_%s_B__%s__LGSMP_%s_E__" % (tag, _fl_b64.b64encode(text.encode()).decode(), tag)


try:
    # ── the chunked write path (files too big for one command) ─────────────────────────────────
    _big = b"x" * 70000
    _calls = _fl_rc(("", "", 0))
    eq("file write (large): chunked — two base64 chunks and a finishing decode, all unprivileged",
       (_F._write_file_as_user(_p8_srv(), "cs2server", "/home/cs2server/big.bin", _big), _calls),
       ((True, ""), [False, False, False]))
    _calls = _fl_rc((_F._OUTSIDE_HOME, "", 9))
    eq("file write (large): a target that resolves outside the home ON THE HOST is refused at the "
       "first chunk, before any more is sent",
       (_F._write_file_as_user(_p8_srv(), "cs2server", "/home/cs2server/link/x", _big), len(_calls)),
       ((False, "Invalid path"), 1))
    _calls = _fl_rc(("", "", 0), ("", "No space left on device", 1))
    eq("file write (large): a failed chunk stops the write and says why",
       (_F._write_file_as_user(_p8_srv(), "cs2server", "/home/cs2server/big.bin", _big), len(_calls)),
       ((False, "No space left on device"), 2))

    # ── LinuxGSM config read ───────────────────────────────────────────────────────────────────
    _fl_rc(("__LGSMP_DEFAULT_B__!!notbase64!!__LGSMP_DEFAULT_E__" + _fl_frame("COMMON", "")
            + _fl_frame("INSTANCE", ""), "", 0))
    _cfgr = _F.lgsm_read_config(_p8_srv(), "cs2server", "cs2server")
    check("lgsm config read: a frame that is not base64 is a failed read, not an empty config",
          _cfgr["raw"] == "" and (_cfgr.get("error") or "").startswith("Could not read the config"), repr(_cfgr))
    _dflt = ('ip="0.0.0.0"\n#### Game Server Settings ####\n\n## Predefined\nport="27015"\n'
             'maxplayers="16"\n#### Empty Section ####\n#### Alerts ####\ndiscordalert="off"\n')
    _fl_rc((_fl_frame("DEFAULT", _dflt) + _fl_frame("COMMON", 'maxplayers="24"\n')
            + _fl_frame("INSTANCE", 'discordalert="on"\n'), "", 0))
    _cfgr = _F.lgsm_read_config(_p8_srv(), "cs2server", "cs2server")
    check("lgsm config read: every setting grouped by _default.cfg's section headers, a key before "
          "any header under 'Server Settings', empty sections dropped, instance > common > default",
          [(g["section"], [(s["key"], s["value"], s["overridden"]) for s in g["settings"]])
           for g in _cfgr["groups"]]
          == [("Server Settings", [("ip", "0.0.0.0", False)]),
              ("Game Server Settings", [("port", "27015", False), ("maxplayers", "24", True)]),
              ("Alerts", [("discordalert", "on", True)])], repr(_cfgr.get("groups")))

    # ── LinuxGSM config write: an invalid key never becomes a line ──────────────────────────────
    _written = []
    _F._write_file_as_user = lambda server, user, ap, data: (_written.append((ap, data)), (True, ""))[1]
    _fl_rc(("__NOFILE__", "", 0))
    eq("lgsm config write: a key that is not an identifier is skipped; a fresh instance cfg is "
       "just the valid updates",
       (_F.lgsm_write_config(_p8_srv(), "cs2server", "cs2server",
                             {"bad key; id": "x", "port": 'x"y\nz'}), _written),
       ((True, ""), [("/home/cs2server/lgsm/config-lgsm/cs2server/cs2server.cfg",
                      b'port="x\\"y z"\n')]))

    # ── the file browser's refusals ────────────────────────────────────────────────────────────
    _calls = _fl_rc(("", "", 0))
    check("files: every path-taking entry point refuses a traversal before anything is sent",
          _F.browse_dir(_p8_srv(), "cs2server", "../../etc") is None
          and _F.read_file(_p8_srv(), "cs2server", "../other/x.cfg") == (None, "Invalid path")
          and _F.write_file(_p8_srv(), "cs2server", "/../../root/.ssh/authorized_keys", "k")
          == (False, "Invalid path")
          and _F.stat_upload_targets(_p8_srv(), "cs2server", "../..", ["x"]) is None
          and _F.upload_file(_p8_srv(), "cs2server", "../..", "x", b"") == (False, "Invalid path")
          and _F.delete_path(_p8_srv(), "cs2server", "../../etc") == (False, "Refusing to delete this path")
          and _calls == [], "calls=%r" % _calls)
    del _written[:]
    eq("files: a write under the home goes through the user write, content encoded",
       (_F.write_file(_p8_srv(), "cs2server", "serverfiles/cfg/server.cfg", "sv_cheats 0\n"), _written),
       ((True, ""), [("/home/cs2server/serverfiles/cfg/server.cfg", b"sv_cheats 0\n")]))
    _fl_rc(("f\t120\t1700000000.75\tserver.cfg\nd\t4096\tnot-a-time\tmaps\nf\t1\n", "", 0))
    eq("upload check: existing names with size and mtime; a bad mtime is 0, a short line ignored, "
       "a repeated or path-qualified name counted once",
       _F.stat_upload_targets(_p8_srv(), "cs2server", "serverfiles",
                              ["server.cfg", "maps", "absent.txt", "../server.cfg", "server.cfg\x00"]),
       [{"is_dir": False, "size": 120, "mtime": 1700000000, "name": "server.cfg"},
        {"is_dir": True, "size": 4096, "mtime": 0, "name": "maps"}])
    for _fn in ("", ".", "..", "/"):
        eq("upload: filename %r refused" % _fn, _F.upload_file(_p8_srv(), "cs2server", "", _fn, b"x"),
           (False, "Invalid filename"))
    del _written[:]
    _fl_rc((_F._OUTSIDE_HOME, "", 9))
    eq("upload (no overwrite): a target the host resolves outside the home is refused, unwritten",
       (_F.upload_file(_p8_srv(), "cs2server", "", "x.cfg", b"1", overwrite=False), _written),
       ((False, "Invalid path"), []))
    _fl_rc(("", "SSH command timed out", -1))
    check("upload (no overwrite): an existence check that did not run uploads NOTHING",
          _F.upload_file(_p8_srv(), "cs2server", "", "x.cfg", b"1", overwrite=False)[0] is False
          and _written == [])
    _fl_rc(("__YES__", "", 0))
    eq("upload (no overwrite): an existing target is the EXISTS sentinel",
       _F.upload_file(_p8_srv(), "cs2server", "", "x.cfg", b"1", overwrite=False),
       (False, _F.UPLOAD_EXISTS))
    _fl_rc(("", "", 0))
    eq("upload (no overwrite): an absent target is written",
       (_F.upload_file(_p8_srv(), "cs2server", "cfg", "x.cfg", b"1", overwrite=False), _written),
       ((True, ""), [("/home/cs2server/cfg/x.cfg", b"1")]))
    _calls = _fl_rc(("", "", 0))
    eq("delete: the home directory itself is refused unsent",
       (_F.delete_path(_p8_srv(), "cs2server", "/"), _calls), ((False, "Refusing to delete this path"), []))
    _fl_rc(("", "rm: cannot remove 'x': Permission denied", 1))
    eq("delete: a failed rm says why", _F.delete_path(_p8_srv(), "cs2server", "serverfiles/x.log"),
       (False, "rm: cannot remove 'x': Permission denied"))
    _F._write_file_as_user = _fl_saved["_write_file_as_user"]

    # ── stream_path ────────────────────────────────────────────────────────────────────────────
    # Local, helper present, the helper refusing the path: the stream ENDS, it does not raise
    # mid-response (a 200 with a truncated body).
    _sm_core.helper_present = lambda recheck=False: True
    _p8_priv.helper_argv = lambda verb, args: (_ for _ in ()).throw(_p8_priv.VerbError("refused"))
    eq("download (local): a path the helper refuses yields nothing, and does not raise",
       list(_F.stream_path(_p8_srv(is_local=True), "cs2server", "serverfiles/x.log")), [])
    _p8_priv.helper_argv = _fl_priv_saved["helper_argv"]
    _sm_core.helper_present = _fl_core_saved["helper_present"]

    # Tailscale remote: the path goes on STDIN; ssh dying before taking it just ends the stream.
    class _FlPipe:
        def __init__(self, data=b"", write_raises=False, close_raises=False):
            self.data, self.write_raises, self.close_raises = data, write_raises, close_raises
            self.written = b""

        def write(self, b):
            if self.write_raises:
                raise BrokenPipeError(32, "Broken pipe")
            self.written += b

        def read(self, n):
            b, self.data = self.data[:n], self.data[n:]
            return b

        def close(self):
            if self.close_raises:
                raise OSError("already closed")

    _popen = []

    def _fl_popen_factory(stdout, stdin):
        def _p(argv, stdout=None, stdin=None):
            _p_obj = NS(argv=list(argv), stdout=_fl_popen_factory.out, stdin=_fl_popen_factory.inp,
                        waited=[])
            _p_obj.wait = lambda: _p_obj.waited.append(True)
            _popen.append(_p_obj)
            return _p_obj
        _fl_popen_factory.out, _fl_popen_factory.inp = stdout, stdin
        return _p
    _F.subprocess = NS(Popen=_fl_popen_factory(_FlPipe(b"0123456789abcdef", close_raises=True),
                                               _FlPipe(write_raises=True)),
                       PIPE=_p8_subprocess.PIPE, DEVNULL=_p8_subprocess.DEVNULL)
    _sm_core._resolve_ts_host = lambda server: "vps.tail1234.ts.net"
    _n_popen = len(_popen)
    eq("download: the home directory itself is never streamed (nothing is even started)",
       (list(_F.stream_path(_p8_srv(), "cs2server", "serverfiles/..")), len(_popen) - _n_popen), ([], 0))
    _got = b"".join(_F.stream_path(_p8_srv(), "cs2server", "serverfiles/../console.log", limit=10, chunk=4))
    check("download (tailscale): ssh to the resolved tailnet host; ssh refusing the path on stdin "
          "and a stdout that will not close are both survived; the bytes are CAPPED at the "
          "measured size; the process is reaped",
          _got == b"0123456789" and _popen[-1].argv[0] == "ssh"
          and "root@vps.tail1234.ts.net" in _popen[-1].argv
          and "console.log" not in " ".join(_popen[-1].argv) and _popen[-1].waited == [True],
          "got=%r argv0=%r" % (_got, _popen[-1].argv[:1]))
    _F.subprocess = NS(Popen=_fl_popen_factory(_FlPipe(b"0123"), _FlPipe()),
                       PIPE=_p8_subprocess.PIPE, DEVNULL=_p8_subprocess.DEVNULL)
    list(_F.stream_path(_p8_srv(), "cs2server", "cfg/../server.cfg"))
    eq("download (tailscale): the CANONICAL relative path is what goes down stdin",
       _fl_popen_factory.inp.written, b"server.cfg")

    # paramiko remote: same fixed command, same path-on-stdin.
    class _FlChan:
        def __init__(self):
            self.shut = False

        def shutdown_write(self):
            self.shut = True

    class _FlIn:
        def __init__(self, raises=False):
            self.raises, self.buf, self.channel = raises, "", _FlChan()

        def write(self, s):
            if self.raises:
                raise EOFError("channel closed")
            self.buf += s

        def flush(self):
            pass

    _fl_exec = {}

    def _fl_conn(out_bytes, in_raises=False):
        def _gc(server, force_new=False, pooled=True):
            _in = _FlIn(in_raises)
            _fl_exec["in"] = _in
            return NS(exec_command=lambda cmd: (_in, _FlPipe(out_bytes), None))
        return _gc
    _sm_core.get_connection = _fl_conn(b"hello world")
    _got = b"".join(_F.stream_path(_p8_srv(auth_method="key"), "cs2server", "serverfiles/a.txt", chunk=3))
    check("download (paramiko): the relative path is written to the channel and EOF sent, then "
          "every byte streamed",
          _got == b"hello world" and _fl_exec["in"].buf == "serverfiles/a.txt"
          and _fl_exec["in"].channel.shut is True, "got=%r" % _got)
    _sm_core.get_connection = _fl_conn(b"partial", in_raises=True)
    eq("download (paramiko): a channel that will not take the path still ends cleanly",
       b"".join(_F.stream_path(_p8_srv(auth_method="key"), "cs2server", "a.txt")), b"partial")
    _sm_core.get_connection = _fl_conn((_F._OUTSIDE_HOME + "\n").encode())
    eq("download (paramiko): the guard's sentinel is never served as the file's contents",
       b"".join(_F.stream_path(_p8_srv(auth_method="key"), "cs2server", "link")), b"")
finally:
    for _k, _v in _fl_saved.items():
        setattr(_F, _k, _v)
    for _k, _v in _fl_core_saved.items():
        setattr(_sm_core, _k, _v)
    _p8_priv.helper_argv = _fl_priv_saved["helper_argv"]


# ── the tripwire, checked last ──────────────────────────────────────────────────────────────────
for _n, _fn in _p8_real.items():
    setattr(_sm_core, _n, _fn)
check("part11: no check reached a real transport (paramiko, the ssh CLI, a local subprocess)",
      not _p8_trips, "reached: %r" % (_p8_trips,))
