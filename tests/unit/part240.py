"""Part 240 of the unit suite: a self-hosted Tailscale control server (Headscale).

1. The privilege boundary. The two tailscale-up verbs take an optional last argument, the control
   server, checked alike in panel/security/privileged.py and tools/panel-helper; `tailscale up`
   gets --login-server; the login link must be on THAT server, on the panel side, in the helper's
   own poll and in a remote's grep.
2. What the control server offers, read through _get_tailscale_info from `tailscale status --json`
   and `tailscale debug prefs` in the shape the tailscale CLI prints them (ipnstate.Status: Self.CapMap,
   CertDomains, CurrentTailnet.MagicDNSSuffix; prefs ControlURL). The fixtures follow Headscale's
   documented behaviour: 0.29 grants no "https" capability and no CertDomains, refuses the Funnel
   node attribute, and names nodes under its dns.base_domain.
3. The callers: Connect on the panel host, a remote's login link and auth key, the Tailscale page
   and its save route, Serve and Funnel refused where not offered, tailnet names under the base
   domain, and the debug report's scrub of them.

Every host, address and key here is invented (.test names, documentation ranges).
"""
import json as _json240
import os
import shutil as _sh240
import subprocess as _sp240  # nosec B404 - runs bash and the helper's own functions on fixed test input
import tempfile as _tmp240
from types import SimpleNamespace as _NS240

from unit.part01 import check, eq
from unit.part05 import _helper
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch,
                         _p9_restore_all)
from panel.core import config as _cfg240
from panel.db.models import AuditLog as _AL240
from panel.ops import system_ops as _so240
from panel.ops import tailscale_integration as _ts240
from panel.ops.debug_report import privacy as _pv240
from panel.ops.ssh_manager import _core as _core240
from panel.ops.ssh_manager import firewall as _fw240
from panel.ops.ssh_manager import hosts as _hosts240
from panel.security import privileged as _priv240

_HS240 = "https://hs.example.test"
_SUFFIX240 = "vpn.example.test"
_LOGIN240 = _HS240 + "/register/hskey-authreq-AbCdEfGh_-1234567890abcd"
_TSLOGIN240 = "https://login.tailscale.com/a/1b2c3d4e5f"
_AKEY240 = "hskey-auth-AbCdEfGhIjKl-0123456789"


# ── 1. the boundary ──────────────────────────────────────────────────────────────────────────────
_GOOD240 = ("-", _HS240, _HS240 + ":8443", "http://10.0.0.5:8080")
_BAD240 = (_HS240 + "/", "https://HS.example.test", "https://u@hs.example.test", _HS240 + "/x",
           "ftp://hs.example.test", "https://-hs.example.test", _HS240 + ":0", _HS240 + ":99999",
           _HS240 + " --ssh", "--login-server=" + _HS240, "https://[fd7a:115c:a1e0::1]", "")


def _both_take240(value):
    """(privileged accepts, helper accepts) for `value` as tailscale-up-login's control server."""
    out = []
    for fn, err in ((lambda a: _priv240.check_args("tailscale-up-login", a), _priv240.VerbError),
                    (lambda a: _helper.validate("tailscale-up-login", a), ValueError)):
        try:
            fn(["no", "-", value])
            out.append(True)
        except err:
            out.append(False)
    return tuple(out)


def _boundary240():
    eq("headscale: both ends of the boundary take the same control-server addresses",
       [(v, _both_take240(v)) for v in _GOOD240], [(v, (True, True)) for v in _GOOD240])
    eq("headscale: ...and refuse the same ones (a path, upper case, userinfo, an option, a bad port)",
       [(v, _both_take240(v)) for v in _BAD240], [(v, (False, False)) for v in _BAD240])
    args = [_AKEY240, "no", "-", "-", _HS240]
    mine = _priv240.tool_argv("tailscale-up-key", args)
    theirs = _helper.VERBS["tailscale-up-key"][1](_helper.validate("tailscale-up-key", args[1:]))
    eq("headscale: tailscale-up-key's argv names the server, the same at both ends",
       (mine, theirs == mine), (["tailscale", "up", "--accept-routes", "--login-server=" + _HS240,
                                 "--auth-key", "file:/dev/stdin"], True))
    eq("headscale: ...and no server named is Tailscale's own: no --login-server (control)",
       any("--login-server" in a for a in _priv240.tool_argv("tailscale-up-key", args[:4])), False)


_LINKS240 = ((_LOGIN240, True), (_HS240 + ":443/register/hskey-authreq-x", True),
             ("https://hs.example.test.evil.test/register/x", False), (_TSLOGIN240, False),
             (_LOGIN240 + '"><b>', False), ("http://hs.example.test/register/x", False))


def _login_links240():
    eq("headscale: the login link must be on the named server, the same rule at both ends",
       [(u, bool(_priv240.ts_login_url_re(_HS240).fullmatch(u)), bool(_helper.ts_login_re(_HS240).fullmatch(u)))
        for u, _w in _LINKS240], [(u, w, w) for u, w in _LINKS240])
    eq("headscale: ...and with no server named it is Tailscale's link, as before (control)",
       (bool(_priv240.ts_login_url_re("-").fullmatch(_TSLOGIN240)),
        bool(_priv240.ts_login_url_re("-").fullmatch(_LOGIN240))), (True, False))
    remote = _priv240.remote_command("tailscale-up-login", ["no", "-", _HS240], merge_stderr=False)
    with _tmp240.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        fh.write("To authenticate, visit:\n\n\t%s\"><b>\n" % _LOGIN240)
    try:
        got = _sp240.run(["grep", "-oE", _priv240._r40_login_ere(_HS240), fh.name],  # nosec B603 B607
                         capture_output=True, text=True, timeout=10).stdout.strip()
    finally:
        os.unlink(fh.name)
    eq("headscale: a remote's join runs up with --login-server and its grep cuts the link on that server",
       ("tailscale up --accept-routes --login-server=" + _HS240 in remote,
        _priv240._r40_login_ere(_HS240) in remote, got), (True, True, _LOGIN240))


def _helper_up_login240(args):
    """Run the helper's own tailscale-up-login with tailscale stood in; (argv it ran, what it printed)."""
    ran, printed = [], []
    tmp = _tmp240.mkdtemp(prefix="p240-")
    log = os.path.join(tmp, "ts-up.log")

    def _popen(argv, **kw):
        ran.append(list(argv))
        os.write(kw["stdout"], ("To authenticate, visit:\n\n\t%s\n\t%s\n" % (_TSLOGIN240, _LOGIN240)).encode())

    saved = (_helper.TS_UP_LOG, _helper.TS_UP_POLL_SECONDS, _helper.subprocess, _helper.resolve,
             _helper.time, _helper.sys)
    try:
        _helper.TS_UP_LOG, _helper.TS_UP_POLL_SECONDS = log, 2
        _helper.resolve = lambda n: "/usr/bin/" + n
        _helper.time = _NS240(sleep=lambda s: None, time=lambda: 0.0)
        _helper.sys = _NS240(stdout=_NS240(write=printed.append), stderr=_NS240(write=printed.append))
        _helper.subprocess = _NS240(Popen=_popen, DEVNULL=_sp240.DEVNULL, STDOUT=_sp240.STDOUT,
                                    TimeoutExpired=_sp240.TimeoutExpired,
                                    run=lambda argv, **k: _sp240.CompletedProcess(
                                        argv, 0, '{"BackendState": "NeedsLogin"}', ""))
        _helper.do_tailscale_up_login(args, "")
    finally:
        (_helper.TS_UP_LOG, _helper.TS_UP_POLL_SECONDS, _helper.subprocess, _helper.resolve,
         _helper.time, _helper.sys) = saved
        _sh240.rmtree(tmp, ignore_errors=True)
    return ran, "".join(printed)


def _helper_verb240():
    ran, out = _helper_up_login240(["no", "-", _HS240])
    eq("headscale: the helper's tailscale-up-login runs up with --login-server and prints the link on that "
       "server, not a Tailscale one in the same output",
       (ran[:1], out), ([["/usr/bin/tailscale", "up", "--accept-routes", "--login-server=" + _HS240]], _LOGIN240))
    ran, out = _helper_up_login240(["no", "-"])
    eq("headscale: ...and without one it joins Tailscale's own and prints Tailscale's link (control)",
       (ran[:1], out), ([["/usr/bin/tailscale", "up", "--accept-routes"]], _TSLOGIN240))


# ── 2. what the control server offers ────────────────────────────────────────────────────────────
def _status240(caps=None, certs=None, suffix=_SUFFIX240):
    """`tailscale status --json` of a node on a control server granting `caps` and `certs`."""
    return {"Version": "1.104.7", "BackendState": "Running", "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
            "Self": {"ID": "n1", "HostName": "panel-host", "DNSName": "panel-host.%s." % suffix, "OS": "linux",
                     "CapMap": dict({"default-auto-update": [False]}, **(caps or {}))},
            "MagicDNSSuffix": suffix,
            "CurrentTailnet": {"Name": suffix, "MagicDNSSuffix": suffix, "MagicDNSEnabled": True},
            "CertDomains": certs, "Peer": {}}


def _read240(status, control):
    """A full _get_tailscale_info reading from `status` and prefs naming `control`; no CLI runs."""
    answers = {"version": ("1.104.7", "", 0), "status --json": (_json240.dumps(status), "", 0),
               "debug prefs": (_json240.dumps({"ControlURL": control, "RouteAll": False}), "", 0),
               "serve status": ("No serve config", "", 0)}
    _p9_patch(_ts240, "_run_ts", lambda args, timeout=5: answers.get(" ".join(args), ("", "unexpected", 1)))
    _p9_patch(_ts240, "_binary_id", lambda: ("/usr/bin/tailscale", 1, 1, 1))
    return _ts240._get_tailscale_info()


_HS029 = (_status240(), _HS240)
_HS030 = (_status240({"https": []}, ["panel-host." + _SUFFIX240]), _HS240)
_TSOWN = (_status240(suffix="tail1234.ts.net"), "https://controlplane.tailscale.com")


def _offer240():
    try:
        rows = []
        for status, control in (_HS029, _HS030, _TSOWN):
            info = _read240(status, control)
            rows.append((info.control_url, info.magic_dns_suffix, _ts240.control_is_tailscale(info),
                         _ts240.serve_https_offered(info), _ts240.funnel_offered(info)))
    finally:
        _p9_restore_all()
        _p9_arm(who="part240")
    eq("headscale: what the control server offers is read from status and prefs: Headscale 0.29 offers "
       "neither Serve's HTTPS nor Funnel; one that issues certificates offers Serve and still no Funnel; "
       "Tailscale's own both", rows, [(_HS240, _SUFFIX240, False, False, False), (_HS240, _SUFFIX240, False, True, False),
              ("https://controlplane.tailscale.com", "tail1234.ts.net", True, True, True)])


def _parse240():
    eq("headscale: the saved address is normalised (case, a trailing /, a default port) or refused",
       [_ts240.parse_control_url(v)[0] for v in ("", " HTTPS://HS.Example.test/ ", _HS240 + ":443",
                                                  "http://hs.example.test:80", _HS240 + ":8443",
                                                  "https://login.tailscale.com")],
       ["", _HS240, _HS240, "http://hs.example.test", _HS240 + ":8443", ""])
    eq("headscale: ...and what is not one says so",
       [_ts240.parse_control_url(v)[1] is not None for v in ("hs.example.test", _HS240 + "/x",
                                                               _HS240 + "?a", "https://a@hs.example.test")],
       [True, True, True, True])


# ── 3. the callers ───────────────────────────────────────────────────────────────────────────────
def _stub_info240(status, control):
    """get_tailscale_info answers the reading of `status` and `control` (made once, unforced)."""
    info = _read240(status, control)
    _p9_patch(_ts240, "get_tailscale_info", lambda force_refresh=False: info)
    return info


def _with_saved240(saved):
    _p9_patch(_cfg240, "load_config", lambda: dict(_cfg240.DEFAULT_CONFIG, setup_complete=True,
                                                    tailscale_control_url=saved))


def _verb_rec240(answer):
    calls = []

    def _rec(verb, args, **kw):
        calls.append((verb, list(args)))
        return answer
    return _rec, calls


def _connect240():
    try:
        _stub_info240(*_TSOWN)
        _with_saved240(_HS240)
        rec, calls = _verb_rec240(("waiting\n" + _LOGIN240, "", 0))
        _p9_patch(_so240, "_run_verb", rec)
        _p9_patch(_so240, "tailscale_ssh_allowed", lambda: False)
        # A join that comes back connected allows tailscale0 through UFW: answered, not run.
        _p9_patch(_so240, "ufw_allow_tailscale", lambda *a, **k: (True, "stub"))
        r = _p9_client(P9_ADMIN).post("/api/tailscale/up")
        saved_join = (r.status_code, _p9_json(r).get("auth_url"), calls[-1:])
        _p9_patch(_so240, "_run_verb", _verb_rec240(("waiting\n" + _TSLOGIN240, "", 0))[0])
        pinned = _ts240.tailscale_up_local(enable_ssh=False)[1] == _TSLOGIN240
        _with_saved240("")
        _stub_info240(*_HS029)
        rec, calls = _verb_rec240(("waiting\n" + _LOGIN240, "", 0))
        _p9_patch(_so240, "_run_verb", rec)
        followed = (_ts240.tailscale_up_local(enable_ssh=False), calls[-1:])
    finally:
        _p9_restore_all()
        _p9_arm(who="part240")
    eq("headscale: Connect on the panel host passes the saved control server and hands back its login link",
       saved_join, (200, _LOGIN240, [("tailscale-up-login", ["no", "-", _HS240])]))
    eq("headscale: ...a Tailscale link coming back from that join is not taken as the login link", pinned, False)
    eq("headscale: ...and with nothing saved, a host already on a self-hosted server joins it again",
       followed, ((True, _LOGIN240), [("tailscale-up-login", ["no", "-", _HS240])]))


def _remote240():
    srv = _NS240(name="p240-remote", host="203.0.113.7", is_local=False)
    calls = []

    def _rp(server, verb, args, **kw):
        calls.append((verb, list(args)))
        return ("waiting\n" + (_LOGIN240 if verb == "tailscale-up-login" else "Success."), "", 0)
    try:
        _stub_info240(*_TSOWN)
        _with_saved240(_HS240)
        _p9_patch(_core240, "run_privileged", _rp)
        _p9_patch(_hosts240, "remote_check_tailscale", lambda s: {"running": False, "tailscale_ip": "", "dns_name": ""})
        link = _hosts240.remote_tailscale_up_url(srv, enable_ssh=False)
        nokey = _hosts240.remote_bootstrap_tailscale(srv, auth_key="")[1]
        _hosts240.remote_bootstrap_tailscale(srv, auth_key=_AKEY240, enable_ssh=False)
    finally:
        _p9_restore_all()
        _p9_arm(who="part240")
    eq("headscale: a remote's login link and auth-key join name the control server, and the link is that "
       "server's", (link, [c for c in calls if c[0].startswith("tailscale-up")]),
       ((True, _LOGIN240), [("tailscale-up-login", ["no", "-", _HS240]),
                            ("tailscale-up-key", [_AKEY240, "no", "-", "-", _HS240])]))
    eq("headscale: ...and the auth-key hint says where a self-hosted server's keys come from",
       nokey, _hosts240.AUTH_KEY_HINT_SELF_HOSTED)


def _last_audit240(action):
    with _p9.app_context():
        r = _AL240.query.filter_by(action=action).order_by(_AL240.id.desc()).first()
        return r.detail if r else ""


def _save_route240():
    stored = {}
    try:
        _stub_info240(*_TSOWN)
        _p9_patch(_cfg240, "load_config", lambda: dict(_cfg240.DEFAULT_CONFIG, setup_complete=True, **stored))
        from panel.routes import tailscale as _rt240
        _p9_patch(_rt240, "load_config", _cfg240.load_config)
        _p9_patch(_rt240, "set_config_keys", lambda cfg, **kw: stored.update(kw))
        c = _p9_client(P9_ADMIN)
        bad = c.post("/api/tailscale/control-server", json={"control_url": _HS240 + "/admin"})
        bad_stored = dict(stored)
        good = c.post("/api/tailscale/control-server", json={"control_url": " HTTPS://HS.example.test/ "})
        audit = _last_audit240("tailscale_control_server")
        plain = _p9_json(c.post("/api/tailscale/control-server", json={"control_url": "http://hs.example.test"}))
    finally:
        _p9_restore_all()
        _p9_arm(who="part240")
    eq("headscale: the Tailscale page's save refuses what is not an address and stores nothing",
       (bad.status_code, bad_stored), (400, {}))
    eq("headscale: ...stores a usable one in its one spelling, audited old -> new",
       (good.status_code, _p9_json(good).get("control_url"), audit), (200, _HS240, "Tailscale -> " + _HS240))
    eq("headscale: ...and an http:// address is kept, with OWASP's note (never a block)",
       (plain.get("success"), stored.get("tailscale_control_url"), "OWASP" in plain.get("note", "")),
       (True, "http://hs.example.test", True))


def _wizard240():
    stored, logged = {}, []
    from panel.routes import route_helpers as _rh240
    try:
        _p9_patch(_rh240, "load_config", lambda: dict(_cfg240.DEFAULT_CONFIG, **stored))
        _p9_patch(_rh240, "set_config_keys", lambda cfg, **kw: stored.update(kw))
        _p9_patch(_rh240, "_setup_log", lambda action, **kw: logged.append((action, kw.get("detail"))))
        with _p9.test_request_context():
            none = _rh240._setup_control_server({})
            bad = _rh240._setup_control_server({"control_url": _HS240 + "/x"})
            good = _rh240._setup_control_server({"control_url": _HS240 + "/"})
            empty = _rh240._setup_control_server({"control_url": ""})
    finally:
        _p9_restore_all()
        _p9_arm(who="part240")
    eq("headscale: the setup wizard's join stores a typed control server first (audited), refuses one that is "
       "not an address, and leaves the stored one alone when the field is empty or absent",
       (none, bad[1] if isinstance(bad, tuple) else bad, good, empty, stored, logged),
       (None, 400, None, None, {"tailscale_control_url": _HS240},
        [("setup_tailscale_control_server", "Tailscale -> " + _HS240)]))


def _page240():
    try:
        _stub_info240(*_HS029)
        _with_saved240(_HS240)
        from panel.routes import tailscale as _rt240
        _p9_patch(_rt240, "load_config", _cfg240.load_config)
        page = _p9_client(P9_ADMIN).get("/tailscale").get_data(as_text=True)
        rec, calls = _verb_rec240(("", "", 0))
        _p9_patch(_so240, "_run_verb", rec)
        serve = _p9_json(_p9_client(P9_ADMIN).post("/api/tailscale/serve", json={"action": "enable", "mount": "/",
                                                                              "funnel": False}))
        _stub_info240(*_HS030)
        funnel = _ts240.setup_tailscale_serve(port=5000, mount="/", funnel=True)
    finally:
        _p9_restore_all()
        _p9_arm(who="part240")
    eq("headscale: the Tailscale page on Headscale 0.29 shows the control-server field and says Serve and "
       "Funnel are not offered, with no Enable form and no Funnel switch",
       ('id="ts-control-url"' in page, 'value="%s"' % _HS240 in page, 'id="ts-serve-not-offered"' in page,
        'id="serve-form"' in page, 'id="funnel-check"' in page, "not offered by this server" in page),
       (True, True, True, False, False, True))
    eq("headscale: ...Enable Serve is refused before anything runs on the host",
       (serve.get("success"), serve.get("message"), calls), (False, _ts240.SERVE_NOT_OFFERED, []))
    eq("headscale: ...and Funnel is refused where the server offers Serve's HTTPS but no Funnel attribute",
       (funnel[0], str(funnel[1])), (False, _ts240.FUNNEL_NOT_OFFERED))


def _names240():
    try:
        _stub_info240(*_HS029)
        rows = [_ts240.is_tailnet_name(h) for h in ("vps1." + _SUFFIX240, "VPS1.%s." % _SUFFIX240,
                                                     "vps1.%s.evil.test" % _SUFFIX240, "evil" + _SUFFIX240,
                                                     "vps.tail1234.ts.net", "100.64.0.9", _SUFFIX240)]
        callers = (_fw240._fwa_is_tailnet_host("vps1." + _SUFFIX240),
                   _hosts240._r28b_host_on_tailnet("vps1." + _SUFFIX240),
                   _core240._r20a_magicdns_host("vps1"),
                   _ts240.is_tailscale_ip("vps1." + _SUFFIX240))
    finally:
        _p9_restore_all()
        _p9_arm(who="part240")
    eq("headscale: a name under the tailnet's own base domain is a tailnet name; a look-alike is not",
       rows, [True, True, False, False, True, False, False])
    eq("headscale: ...for the firewall's and the public-SSH guard's tailnet test, the bare-name dial and "
       "the peer check alike", callers, (True, True, "vps1." + _SUFFIX240, True))


def _scrub240():
    st = _pv240._State()
    _pv240._names_tailscale({"magic_dns_suffix": _SUFFIX240, "dns_name": "panel-host." + _SUFFIX240}, st)
    out = _pv240.scrub(_NS240(memo=lambda key, fn: st), "ssh to peer7.%s timed out; base %s" % (_SUFFIX240, _SUFFIX240))
    eq("headscale: the debug report replaces a peer's name under the base domain whole, not just the suffix",
       ("peer7" in out, "[ts-name]" in out, _SUFFIX240 in out), (False, True, False))


def _part240():
    trips = len(_P9_TRIPPED)
    try:
        _p9_arm(who="part240")
        _part240_checks()
    finally:
        _p9_restore_all()
    check("part240: no check reached a real host", len(_P9_TRIPPED) == trips, repr(_P9_TRIPPED[trips:][:4]))


def _part240_checks():
    _boundary240()
    _login_links240()
    _helper_verb240()
    _offer240()
    _parse240()
    _connect240()
    _remote240()
    _save_route240()
    _wizard240()
    _page240()
    _names240()
    _scrub240()


_part240()
