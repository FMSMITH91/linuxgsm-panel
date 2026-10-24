"""Part 61 of the unit suite: review 1011d's system_ops, Tailscale Serve, ssh-core and notify fixes.

Held here, each against the code path the finding named:

* a panel route on a Tailscale Service's listener ("(svc:<name>)") is never removed with the node's
  own `serve --https=443 ... off`, which took down another app at that mount on the node;
* a Serve handler the CLI prints with no kind (a Redirect) still holds its mount;
* a firewall rule that admits only this machine (on lo or a container bridge, from or to loopback)
  or only UDP (the protocol printed in the From column) is no way in, so the host's only public
  `22/tcp` stays protected; one admitting every port on tailscale0 in any spelling is a way in;
* a rate-limited (LIMIT) panel port reads as open on the Network card;
* a numeric chat_id / channel_id / ntfy topic in config.json no longer raises from the Test
  button or stops ntfy alerts; a hand-edited `Infinity` wait does not raise; a non-string
  bind_host does not 500 the change-port form;
* JSON inside a JSON string has its secret redacted.

HOW IT RUNS. Pure functions with their outside calls stood in for (part20's _patch / _patched,
undone at the end of each block), and one route on part12's Flask app and client. Nothing touches
the network, sudo, a real host or the checkout's data/.
"""
import types as _types61

from unit.part01 import check, skip
from unit.part02 import protect as _protect61
from unit.part12 import (P9_ADMIN, _P9_CFG_PATH, _P9_TRIPPED, _p9, _p9_arm, _p9_cfg, _p9_client,
                         _p9_json, _p9_so)
from unit.part20 import _patch, _patched

from panel.ops import system_ops as _so61  # noqa: E402
from panel.ops import tailscale_integration as _ts61  # noqa: E402
from panel.ops.ssh_manager import _core as _smc61  # noqa: E402
from panel.ops.ssh_manager import hosts as _smh61  # noqa: E402
from panel.routes import tailscale as _rts61  # noqa: E402
from panel.services import host_reboot as _hr61  # noqa: E402
from panel.services import notifications as _nt61  # noqa: E402

NS = _types61.SimpleNamespace
_TRIP61_START = len(_P9_TRIPPED)


def _r15d_arm61():
    """part12's transport tripwire, armed inside the caller's _patched() block (review 1011e).

    part12 disarmed its own when it ended, and each route block here stubbed only the leaf it names:
    one more host call on a passing path (close-panel-port's local shell on P9_LOCAL, as root on
    CI's root leg) ran for real with the part green. Page renders read Tailscale state for the nav
    through `tailscale`, the real CLI on a box that has it (part12 stubbed it for that reason), so
    that is answered here and its subprocess is tripwired too.
    """
    _p9_arm(_patch, "part61")


# Addresses built from their parts, so no address literal is added: loopback, a documentation
# address (TEST-NET-2), a private LAN range, Tailscale's CGNAT range and one tailnet address.
_LB61 = ".".join(["127", "0", "0", "1"])
_ADMIN61 = ".".join(["198", "51", "100", "7"])
_LAN61 = ".".join(["192", "168", "1", "0"]) + "/24"
_CGNAT61 = ".".join(["100", "64", "0", "0"]) + "/10"
_TSIP61 = ".".join(["100", "64", "0", "9"])
_CFG61_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None


def _try61(fn, *a, **k):
    """Return fn's answer, or the NAME of the exception it raised (so a revert fails by name)."""
    try:
        return fn(*a, **k)
    except Exception as exc:  # noqa: BLE001 - which class arrives IS the check
        return type(exc).__name__


# ── A02: a Tailscale Service's route is never removed through the node's own :443 listener ──────
_SVC61 = ("https://node.tail.ts.net (tailnet only)\n"
          "|-- /     proxy http://%s:3000\n"
          "|-- /lgsm proxy http://%s:5000\n"
          "https://web.tail.ts.net (tailnet only) (svc:web)\n"
          "|-- /     proxy http://%s:5000\n") % (_LB61, _LB61, _LB61)
_svc61 = _ts61._parse_serve_status(_SVC61)
_offs61 = []


def _ts_verb61(verb, args=(), timeout=30, merge_stderr=True):
    """The helper: each `off` (tailscale-serve-off) is recorded as the argv it runs; all succeed."""
    argv = _ts61._priv.tool_argv(verb, list(args))[1:]
    if argv and argv[-1] == "off":
        _offs61.append(argv)
    return "", "", 0


def _with_svc61(fn, *a):
    """Run fn against the node+Service status above; returns (answer, the `off`s sent)."""
    del _offs61[:]
    with _patched():
        _patch(_ts61, "get_tailscale_info", lambda force_refresh=False: NS(
            installed=True, serve_unreadable=False, serve_config=_svc61))
        _patch(_ts61._so, "_run_verb", _ts_verb61)
        got = _try61(fn, *a)
    return got, list(_offs61)


_NODE_ROOT_OFF61 = ["serve", "--https=443", "--set-path=/", "off"]
_stale61, _soffs61 = _with_svc61(_ts61.remove_stale_panel_routes, 5000, "/lgsm")
check("serve: boot's leftover sweep leaves a panel route on a Tailscale Service alone (its `off` "
      "named the node's own :443 and removed the other app at /)",
      _stale61 == ("none", [], "") and _soffs61 == [], repr((_stale61, _soffs61)))
_dis61, _doffs61 = _with_svc61(_ts61.disable_tailscale_serve, "/lgsm", 5000)
check("serve: Disable removes only the node's own panel route and says the Service still publishes "
      "the panel (it sent `--set-path=/ off` too, taking the other app's / off the node)",
      _NODE_ROOT_OFF61 not in _doffs61
      and _doffs61 == [["serve", "--https=443", "--set-path=/lgsm", "off"]]
      and isinstance(_dis61, tuple) and _dis61[0] is True and "svc:web" in _dis61[1],
      repr((_dis61, _doffs61)))
_svcr61 = [r for r in _ts61.panel_serve_routes(_svc61, 5000) if r.get("svc")]
_rm61, _roffs61 = _with_svc61(_ts61.remove_panel_route, _svcr61[0] if _svcr61 else {}, 5000)
check("serve: removing a Service route by hand answers failed and runs nothing",
      isinstance(_rm61, tuple) and _rm61[0] == "failed" and "svc:web" in _rm61[1]
      and _roffs61 == [], repr((_rm61, _roffs61)))
_nodr61 = [r for r in _ts61.panel_serve_routes(_svc61, 5000) if not r.get("svc")]
_rmn61, _rnoffs61 = _with_svc61(_ts61.remove_panel_route, _nodr61[0] if _nodr61 else {}, 5000)
check("serve: ...while a node route to the panel is still removed with its own mount (control)",
      _rmn61 == ("removed", "") and _rnoffs61 == [["serve", "--https=443", "--set-path=/lgsm", "off"]],
      repr((_rmn61, _rnoffs61)))
_msvc61 = {"url": "https://web.tail.ts.net", "mount": "/lgsm", "svc": "svc:web",
           "target": "http://%s:5000" % _LB61}
_mcfg61 = {"tailscale_setup_done": True, "tailscale_mount": "/lgsm"}
check("serve: a Service route at tailscale_mount is not the route the panel manages",
      _ts61.is_managed_route(_msvc61, _mcfg61) is False
      and _ts61.is_managed_route(dict(_msvc61, svc=""), _mcfg61) is True, repr(_msvc61))
with _patched():
    _patch(_rts61.ts, "get_tailscale_info", lambda force_refresh=False: NS(
        installed=True, serve_unreadable=False, serve_config=_svc61))
    _patch(_rts61, "load_config", lambda: dict(_mcfg61))
    with _p9.test_request_context():
        _lr61 = _try61(_rts61._leftover_route, 5000, "https://web.tail.ts.net", "/")
        # (None, (response, status)) is a refusal; (route, None) would go on to remove it.
        _lr61 = ((_lr61[1][1], _p9_json(_lr61[1][0]).get("message", ""))
                 if isinstance(_lr61, tuple) and _lr61[1] else _lr61)
check("serve: the page's Remove refuses a Service route (400) before anything runs",
      isinstance(_lr61, tuple) and _lr61[0] == 400 and "svc:web" in _lr61[1], repr(_lr61))

_bare61 = _ts61._parse_serve_status("https://h.tail.ts.net (tailnet only)\n|-- /\n"
                                    "|-- /lgsm proxy http://%s:5000\n" % _LB61)
check("serve status: a handler printed with no kind (a Redirect, set with `serve set-raw`) holds its "
      "mount, so the wizard does not publish the panel over it",
      [r["mount"] for s in _bare61["services"] for r in s["routes"]] == ["/", "/lgsm"]
      and _ts61.free_panel_mount(_bare61, 5000, "/") == "/lgsm", repr(_bare61["services"]))

# ── A02 lead: JSON inside a JSON string is redacted ─────────────────────────────────────────────
_red61 = _so61._redact('body={\\"password\\": \\"hunter2 x\\", \\"user\\": \\"bob\\"}')
check("redact: a secret in escaped JSON (`{\\\"password\\\": \\\"hunter2 x\\\"}`) is redacted whole and the "
      "next key kept", _red61 == 'body={\\"password\\": [redacted], \\"user\\": \\"bob\\"}', repr(_red61))

# ── A03: what is, and is not, another way in past the host's one public SSH rule ────────────────


def _fw61(rules, **kw):
    """{To column + scope: group} of `rules` on a remote whose sshd serves 22."""
    return {(x["port_label"], x["scope"]): x
            for x in _protect61(NS(port=22), rules, sshd_ports=(22,), **kw)}


def _ssh22_61(rules, **kw):
    """(the extra rule's is_ssh, 22/tcp protected, 22/tcp warn) with `rules` beside `22/tcp ALLOW`."""
    g = _fw61(["22/tcp ALLOW IN Anywhere"] + rules, **kw)
    extra = [v for k, v in g.items() if k != ("22/tcp", "Any address")]
    ssh = g[("22/tcp", "Any address")]
    return (any(x["is_ssh"] for x in extra), ssh["protected"], ssh["warn"])


_WAY_IN61 = {
    "from an admin address": ["Anywhere ALLOW IN %s" % _ADMIN61],
    "from an admin address over tcp": ["Anywhere ALLOW IN %s/tcp" % _ADMIN61],
    "on eth0": ["Anywhere on eth0 ALLOW IN Anywhere"],
    "on br0 (an uplink bridge)": ["Anywhere on br0 ALLOW IN Anywhere"],
    "from a LAN range": ["Anywhere ALLOW IN %s" % _LAN61],
    "every tcp port": ["Anywhere/tcp ALLOW IN Anywhere"],
}
_NOT_IN61 = {
    "on lo": ["Anywhere on lo ALLOW IN Anywhere", "Anywhere (v6) on lo ALLOW IN Anywhere (v6)"],
    "on docker0": ["Anywhere on docker0 ALLOW IN Anywhere"],
    "on a docker network bridge": ["Anywhere on br-0123456789ab ALLOW IN Anywhere"],
    "on virbr0": ["Anywhere on virbr0 ALLOW IN Anywhere"],
    "from v4 loopback": ["Anywhere ALLOW IN %s" % _LB61],
    "from ::1": ["Anywhere (v6) ALLOW IN ::1"],
    "to v4 loopback": ["%s ALLOW IN Anywhere" % _LB61],
    "22/tcp on lo": ["22/tcp on lo ALLOW IN Anywhere"],
    "22 from the loopback /8": ["22 ALLOW IN %s/8" % ".".join(["127", "0", "0", "0"])],
    "udp from an address (From column)": ["Anywhere ALLOW IN %s/udp" % _ADMIN61],
    "every udp port": ["Anywhere/udp ALLOW IN Anywhere"],
    "OUT": ["Anywhere ALLOW OUT Anywhere on eth0"],
    "FWD": ["Anywhere on eth0 ALLOW FWD Anywhere"],
    "a DENY from an address": ["Anywhere DENY IN %s" % _ADMIN61],
}
_way61 = {k: _ssh22_61(v) for k, v in _WAY_IN61.items()}
check("firewall: an inbound rule admitting every port from another machine is another way in, so "
      "the public 22/tcp only warns (control: admin address, eth0, br0, a LAN range)",
      set(_way61.values()) == {(True, False, True)}, repr(_way61))
_not61 = {k: _ssh22_61(v) for k, v in _NOT_IN61.items()}
check("firewall: a rule admitting only this machine (lo, docker0, a docker or libvirt bridge, from or "
      "to loopback), only UDP (either column), OUT, FWD or a DENY is no way in: the only public "
      "22/tcp stays protected (lo and docker0 made it deletable)",
      {k: v for k, v in _not61.items() if v != (False, True, False)} == {}, repr(_not61))

_TS_RUN61 = {"tailscale": (True, False)}
_tsr61 = {}
for _k61, _rule61 in (("Anywhere/tcp", "Anywhere/tcp on tailscale0 ALLOW IN Anywhere"),
                      ("an address", "%s on tailscale0 ALLOW IN Anywhere" % _TSIP61)):
    _g61 = list(_fw61([_rule61], **_TS_RUN61).values())[0]
    _tsr61[_k61] = (_g61["is_tailscale"], _g61["protected"])
check("firewall: a tailnet-only host's one way in written `allow in on tailscale0 proto tcp` or `... to "
      "<addr>` is a Tailscale access rule and protected (an ordinary delete × before)",
      set(_tsr61.values()) == {(True, True)}, repr(_tsr61))
_g61 = _fw61(["Anywhere/tcp on tailscale0 DENY IN Anywhere", "Anywhere on tailscale0 ALLOW IN Anywhere",
              "22/tcp ALLOW IN Anywhere"], **_TS_RUN61)[("22/tcp", "Any address")]
check("firewall: a tcp DENY on tailscale0 above its allow wins (first match), so the tailnet is no "
      "way in and the public 22/tcp is protected", _g61["protected"] and not _g61["warn"],
      repr((_g61["protected"], _g61["warn"])))
_g61 = _fw61(["Anywhere on tailscale0 ALLOW IN %s/udp" % _CGNAT61, "22/tcp ALLOW IN Anywhere"],
             **_TS_RUN61)
_tsu61 = [(v["is_tailscale"], v["protected"]) for k, v in sorted(_g61.items())]
check("firewall: a UDP-only allow on tailscale0 (the protocol in the From column) is no tailnet way "
      "in: the public 22/tcp stays protected",
      _g61[("22/tcp", "Any address")]["protected"]
      and not any(v["is_tailscale"] for v in _g61.values()), repr(_tsu61))
_TSIF61 = {"to": "Anywhere on tailscale0", "action": "ALLOW", "direction": "IN"}
check("firewall: the panel host's tailnet-only lockdown is not offered on a UDP-only tailscale0 allow "
      "(ufw_allows_iface_in), and is on a plain one (control)",
      _so61.ufw_allows_iface_in([dict(_TSIF61, **{"from": _CGNAT61 + "/udp"})], "tailscale0") is False
      and _so61.ufw_allows_iface_in([dict(_TSIF61, **{"from": "Anywhere"})], "tailscale0") is True)

_UFW_HEAD61 = "\n".join(["Status: active", "", "To" + " " * 25 + "Action      From",
                         "--" + " " * 25 + "------      ----", ""])


def _panel_open61(*rows):
    with _patched():
        _patch(_smc61, "run_privileged", lambda server, verb, args, timeout=None: (
            _UFW_HEAD61 + "".join(r + "\n" for r in rows), "", 0))
        got = _try61(_smh61.remote_public_ssh_status, NS(port=22), panel_port=5000)
    return got.get("panel_port_open") if isinstance(got, dict) else got


_po61 = {k: _panel_open61(*v) for k, v in (
    ("limit", ("5000/tcp                   LIMIT       Anywhere",)),
    ("allow", ("5000/tcp                   ALLOW       Anywhere",)),
    ("v6 only", ("5000/tcp (v6)              ALLOW       Anywhere (v6)",)),
    ("tailscale comment", ("5000/tcp                   ALLOW       Anywhere    # tailscale fallback",)),
    ("tailscale0 only", ("5000/tcp on tailscale0     ALLOW       Anywhere",
                         "Anywhere on tailscale0     ALLOW       Anywhere")),
    ("deny", ("5000/tcp                   DENY        Anywhere",)),
    ("out", ("5000/tcp                   ALLOW OUT   Anywhere",)),
    ("another port", ("15000/tcp                  ALLOW       Anywhere",)))}
check("network card: a rate-limited (LIMIT) public panel port reads as open (it read closed and the "
      "card called the panel tailnet-only)", _po61["limit"] is True, repr(_po61))
check("network card: ...an IPv6-only allow and one whose comment says tailscale are open too; ALLOW is "
      "open (control); a tailscale0 rule, a DENY, an OUT rule and another port are not",
      (_po61["v6 only"], _po61["tailscale comment"], _po61["allow"], _po61["tailscale0 only"],
       _po61["deny"], _po61["out"], _po61["another port"])
      == (True, True, True, False, False, False, False), repr(_po61))

# ── A05: a numeric id saved in config.json; a hand-edited Infinity; a non-string bind_host ──────
_sent61 = []
with _patched():
    _patch(_nt61, "send_telegram", lambda tok, chat, text: (_sent61.append(("tg", chat)), (True, ""))[1])
    _patch(_nt61, "discord_bot_send", lambda tok, chan, text: (_sent61.append(("dc", chan)), (True, ""))[1])
    _patch(_nt61, "send_ntfy", lambda srv, top, tok, text: (_sent61.append(("nt", top)), (True, ""))[1])
    _tg61 = _try61(_nt61._test_send_telegram, {"telegram": {"chat_id": 123456789}},
                   "123456:" + "A" * 35, None, "t")
    _dc61 = _try61(_nt61._test_send_discord_bot, {"discord": {"channel_id": 112233445566778899}},
                   "x" * 24 + "." + "y" * 6 + "." + "z" * 27, None, "t")
    _ntt61 = _try61(_nt61._test_send_ntfy, {"ntfy": {"topic": 4242}}, None, None, None, "t")
check("notify test: Test with the Chat ID field cleared and a NUMERIC chat_id saved sends to it (a "
      "bare 500: AttributeError on int.strip)",
      _tg61 == (True, "Test message sent — check Telegram.") and ("tg", "123456789") in _sent61,
      repr((_tg61, _sent61)))
check("notify test: ...the same for a numeric Discord channel_id and a numeric ntfy topic",
      isinstance(_dc61, tuple) and _dc61[0] is True and ("dc", "112233445566778899") in _sent61
      and isinstance(_ntt61, tuple) and _ntt61[0] is True and ("nt", "4242") in _sent61,
      repr((_dc61, _ntt61, _sent61)))
_nurl61 = _try61(_nt61._ntfy_url, None, 4242)
check("notify: a numeric ntfy topic builds its URL in the alert path (it raised inside the sender's "
      "catch-all, so every ntfy alert stopped unseen)",
      _nurl61 == _nt61.NTFY_DEFAULT_SERVER.rstrip("/") + "/4242", repr(_nurl61))
with _patched():
    _patch(_hr61, "load_config", lambda: {_hr61._SETTING_WAIT_HOURS: float("inf")})
    _wm61 = _try61(_hr61.wait_max_hours)
check("reboot: a hand-edited `reboot_wait_max_hours: Infinity` reads as the default (OverflowError "
      "out of the Settings page, the wait and startup)", _wm61 == _hr61.DEFAULT_WAIT_HOURS, repr(_wm61))

try:
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), bind_host=5))
    _cur61 = int(_p9_cfg.load_config().get("port", 5000))
    with _patched():
        _r15d_arm61()
        # A regression to a 200 goes on to save, follow the binding in the firewall and fail2ban,
        # and restart the panel: stubbed as part53 does, so it fails by name and does nothing.
        from panel.routes import remote_security as _rs61   # noqa: E402
        _patch(_p9_so, "host_has_ip", lambda ip: True)
        _patch(_p9_so, "port_in_use", lambda port: False)
        _patch(_p9_so, "restart_panel", lambda: (True, "scheduled"))
        _patch(_p9_so, "ensure_panel_fail2ban", lambda *a, **k: (True, "jail updated"))
        _patch(_rs61, "remote_ufw_open_port", lambda *a, **k: (True, "ok"))
        _patch(_rs61, "remote_ufw_close_port", lambda *a, **k: (True, "ok"))
        _rb61 = _p9_client(P9_ADMIN).post("/api/panel/change-port",
                                          json={"port": _cur61, "bind_host": ".".join(["0"] * 4)})
    check("change-port: a non-string bind_host in config.json reads as unset (the form answered a bare "
          "500); asked for the binding it already has, it says so",
          _rb61.status_code == 400 and "already the panel's binding" in _p9_json(_rb61).get("message", ""),
          repr((_rb61.status_code, _p9_json(_rb61))))
finally:
    if _CFG61_SNAPSHOT is None:
        if _P9_CFG_PATH.exists():
            _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFG61_SNAPSHOT)

# ── follow-up 1: Close public panel port reads the panel port the way the Network card does ─────
from unit.part12 import P9_LOCAL  # noqa: E402
from panel.ops.ssh_manager import firewall as _fwm61  # noqa: E402
from panel.routes import remote_vps as _rv61  # noqa: E402

_DST61 = ".".join(["203", "0", "113", "61"])     # a documentation address (TEST-NET-3)
_PORT_ROWS61 = {   # row -> (what the card and the route both read it as)
    "5000/tcp ALLOW IN Anywhere": "only",
    "5000/tcp LIMIT IN Anywhere": "only",
    "5000 ALLOW IN %s" % _ADMIN61: "only",
    "%s 5000/tcp ALLOW IN Anywhere" % _DST61: "only",
    "80,443,5000/tcp ALLOW IN Anywhere": "shared",
    "5000:5010/tcp ALLOW IN Anywhere": "shared",
    "4000:6000 ALLOW IN Anywhere": "shared",
    "5000/tcp DENY IN Anywhere": "",
    "5000/tcp ALLOW OUT Anywhere": "",
    "5000/tcp on tailscale0 ALLOW IN Anywhere": "",
    "Anywhere on eth0 ALLOW IN Anywhere": "",
    "15000/tcp ALLOW IN Anywhere": "",
    "50000:50010/tcp ALLOW IN Anywhere": "",
}


def _close61(row):
    """(the route's answer, the rule numbers it deleted) for a firewall holding `row` alone."""
    rows, deleted = [row], []

    def _status(remote):
        return {"installed": True, "enabled": True, "groups": _fwm61._group_ufw_rules(
            [{"num": str(i + 1), "detail": d} for i, d in enumerate(rows)])}

    def _delete(remote, num, force=False, expect_key=None):
        deleted.append(num)
        rows[:] = [d for i, d in enumerate(rows) if i + 1 != num]
        return True, "deleted"
    with _patched():
        _r15d_arm61()
        _patch(_rv61, "remote_ufw_status", _status)
        _patch(_fwm61, "remote_ufw_default_allows_in", lambda remote: False)
        _patch(_rv61, "remote_ufw_delete_rule", _delete)
        _patch(_rv61.ts, "get_tailscale_info", lambda *a, **k: NS(serve_unreadable=False, serve_config={}))
        resp = _p9_client(P9_ADMIN).post("/api/remote/%d/close-panel-port" % P9_LOCAL)
    return _p9_json(resp), deleted


try:
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), port=5000, tailscale_setup_done=True,
                             tailscale_use_funnel=False))
    _scope61, _route61, _card61 = {}, {}, {}
    for _row61, _want61 in _PORT_ROWS61.items():
        _g61 = _fwm61._group_ufw_rules([{"num": "1", "detail": _row61}])[0]
        _scope61[_row61] = _fwm61._r14a_panel_port_scope(_g61, 5000)
        _body61, _del61 = _close61(_row61)
        _msg61 = _body61.get("message", "")
        _route61[_row61] = ("closed" if _del61 and _body61.get("success") else
                            "refused" if "opens other ports too" in _msg61 and not _del61 else
                            "already" if "already closed" in _msg61 else repr((_body61, _del61)))
        _card61[_row61] = _panel_open61(" ".join(_row61.replace(" IN ", " ").split()))
    check("panel port: a rule naming the panel port in a list or range holds it open, one that only "
          "names it is the panel's own, and a DENY / OUT / interface / other-port rule does not (both "
          "directions)", _scope61 == _PORT_ROWS61,
          repr({k: v for k, v in _scope61.items() if v != _PORT_ROWS61[k]}))
    _wroute61 = {k: {"only": "closed", "shared": "refused", "": "already"}[v] for k, v in _PORT_ROWS61.items()}
    check("close panel port: a list or range that opens the panel port is refused, naming the rule and "
          "deleting nothing (it said 'already closed' while the card said open); the panel port's own "
          "rule is deleted; nothing else reads as open",
          _route61 == _wroute61, repr({k: v for k, v in _route61.items() if v != _wroute61[k]}))
    _body61, _ = _close61("80,443,5000/tcp ALLOW IN Anywhere")
    check("close panel port: ...the refusal names the rule it would not delete",
          "80,443,5000/tcp" in _body61.get("message", ""), repr(_body61))
    check("close panel port: the Network card calls the port open exactly when the route does not say "
          "'already closed' (they never disagree)",
          {k: v is True for k, v in _card61.items()} == {k: v != "already" for k, v in _route61.items()},
          repr(_card61))
finally:
    if _CFG61_SNAPSHOT is None:
        if _P9_CFG_PATH.exists():
            _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFG61_SNAPSHOT)

# ── follow-up 2: a DENY/REJECT above an SSH ALLOW wins (UFW's first match), on the public side ──
_NET61 = ".".join(["198", "51", "100", "0"]) + "/24"
_OTHER61 = ".".join(["203", "0", "113", "9"])
_REAL61 = "22/tcp ALLOW IN Anywhere"
_SHADOWED61 = {   # the allow from the admin address is no way in: the public 22/tcp stays protected
    "DENY from it above": ["22/tcp DENY IN %s" % _ADMIN61, "22/tcp ALLOW IN %s" % _ADMIN61, _REAL61],
    "REJECT from it above": ["22/tcp REJECT IN %s" % _ADMIN61, "22/tcp ALLOW IN %s" % _ADMIN61, _REAL61],
    "DENY from its /24 above": ["22/tcp DENY IN %s" % _NET61, "22/tcp ALLOW IN %s" % _ADMIN61, _REAL61],
    "DENY every port from it": ["Anywhere DENY IN %s" % _ADMIN61, "22/tcp ALLOW IN %s" % _ADMIN61, _REAL61],
    "DENY both protocols": ["22 DENY IN %s" % _ADMIN61, "22/tcp ALLOW IN %s" % _ADMIN61, _REAL61],
}
_LIVE61 = {   # the allow from the admin address still lets SSH in: the public 22/tcp only warns
    "DENY below it": ["22/tcp ALLOW IN %s" % _ADMIN61, "22/tcp DENY IN %s" % _ADMIN61, _REAL61],
    "DENY from another address": ["22/tcp DENY IN %s" % _OTHER61, "22/tcp ALLOW IN %s" % _ADMIN61, _REAL61],
    "DENY of another port": ["2222/tcp DENY IN %s" % _ADMIN61, "22/tcp ALLOW IN %s" % _ADMIN61, _REAL61],
    "DENY of udp": ["22/udp DENY IN %s" % _ADMIN61, "22/tcp ALLOW IN %s" % _ADMIN61, _REAL61],
    "DENY on another interface": ["22/tcp on eth1 DENY IN %s" % _ADMIN61, "22/tcp ALLOW IN %s" % _ADMIN61,
                                  _REAL61],
    "DENY OUT": ["22/tcp DENY OUT %s" % _ADMIN61, "22/tcp ALLOW IN %s" % _ADMIN61, _REAL61],
    "DENY narrower than the allow": ["22/tcp DENY IN %s" % _ADMIN61, "22/tcp ALLOW IN %s" % _NET61, _REAL61],
    "auto-block DENY above an allow from Anywhere": ["Anywhere DENY IN %s" % _OTHER61, "22 ALLOW IN Anywhere",
                                                     _REAL61],
}


def _real61(rules):
    """(protected, warn) of the public `22/tcp ALLOW IN Anywhere` among `rules`."""
    got = {(x["port_label"], x["scope"]): x for x in _protect61(NS(port=22), rules, sshd_ports=(22,))}
    g = got[("22/tcp", "Any address")]
    return (g["protected"], g["warn"])


_sh61 = {k: _real61(v) for k, v in _SHADOWED61.items()}
check("firewall: an SSH allow a DENY/REJECT above it shadows (same source or wider, same port, every "
      "port, both protocols) is no other way in: the public 22/tcp is protected",
      {k: v for k, v in _sh61.items() if v != (True, False)} == {}, repr(_sh61))
_lv61 = {k: _real61(v) for k, v in _LIVE61.items()}
check("firewall: ...while a DENY below the allow, from another or a narrower source, of another port, of "
      "UDP, on another interface, OUT, or an auto-block DENY from one address, shadows nothing: the public "
      "22/tcp only warns", {k: v for k, v in _lv61.items() if v != (False, True)} == {}, repr(_lv61))
_g61 = {(x["port_label"], x["scope"]): x for x in _protect61(
    NS(port=22), ["22/tcp DENY IN %s" % _ADMIN61, "22/tcp ALLOW IN %s" % _ADMIN61, _REAL61], sshd_ports=(22,))}
check("firewall: ...and the shadowed allow itself is no way in (ssh_live False), the real one is, so "
      "the shadowed one may go with a warning",
      not _g61[("22/tcp", _ADMIN61)]["ssh_live"] and _g61[("22/tcp", "Any address")]["ssh_live"]
      and _g61[("22/tcp", _ADMIN61)]["warn"] and not _g61[("22/tcp", _ADMIN61)]["protected"],
      repr({k: v.get("ssh_live") for k, v in _g61.items()}))

# ── VPS proof follow-up: real `ufw status numbered` captures from the test VPS, verbatim ────────
# tests/unit/part61_ufw/*.numbered.txt are the box's own output with one tagged rule added each
# (comment `lgsm-fwproof`, ports 47100-47199, documentation sources). The SSH port there was
# 47122 and the panel port 47150.
import os as _os61  # noqa: E402
import re as _re61  # noqa: E402

from panel.core import config as _pcfg61  # noqa: E402
from panel.ops.debug_report import network as _drn61  # noqa: E402

_UFWDIR61 = _os61.path.join(_os61.path.dirname(_os61.path.abspath(__file__)), "part61_ufw")


def _real61_text(name):
    with open(_os61.path.join(_UFWDIR61, name + ".numbered.txt"), encoding="utf-8") as f:
        return f.read()


def _as_verbose61(text):
    """A numbered capture as `ufw status verbose` prints it: the same rows, without `[ N]`."""
    return "\n".join(_re61.sub(r"^\[\s*\d+\]\s", "", ln) for ln in text.splitlines())


def _as_plain61(text):
    """...and as `ufw status` prints it: inbound rows say ALLOW, not ALLOW IN."""
    return _re61.sub(r"\b(ALLOW|DENY|REJECT|LIMIT) IN\b", r"\1   ", _as_verbose61(text))


# 1. A rule's `# comment` is not part of its source, wherever ufw rows are read.
_iface61, _sts61, _tsr61 = {}, {}, {}
for _cap61, _if61 in (("s7b-lo-net-udp", "lo"), ("s7c-lo-net", "lo"), ("s7d-docker0-udp", "docker0")):
    _vt61 = _as_verbose61(_real61_text(_cap61))
    with _patched():
        _patch(_so61, "_run_verb", lambda verb, args, **k: (_vt61, "", 0))
        _st61 = _so61.ufw_status()
    _sts61[_cap61] = _st61
    _tsr61[_cap61] = _smh61._tsiface_ufw_rules(_vt61)
    _iface61[_cap61] = (_so61.ufw_allows_iface_in(_st61["rules"], _if61),
                        _so61.ufw_allows_iface_in(_smh61._tsiface_ufw_rules(_vt61), _if61))
check("ufw rows: a COMMENTED UDP-only whole-interface allow (the VPS's own `Anywhere on lo  ALLOW IN  "
      "<net>/udp  # lgsm-fwproof`) does not read as letting everything in, through ufw_status and "
      "the remote read (the comment hid the /udp)",
      _iface61["s7b-lo-net-udp"] == (False, False), repr(_iface61))
check("ufw rows: ...while the same commented rule without udp does, and a UDP To column does not "
      "(control, both directions)",
      _iface61["s7c-lo-net"] == (True, True) and _iface61["s7d-docker0-udp"] == (False, False),
      repr(_iface61))
_row61 = _so61._r14a_ufw_row(_as_verbose61(_real61_text("s7b-lo-net-udp")).splitlines()[8])
_drrows61 = _drn61.ufw_classify(_as_verbose61(_real61_text("s7b-lo-net-udp")), "", 0)["rules"]
check("ufw rows: no reader's `from` carries the comment (ufw_status, the remote tailnet read, the "
      "debug report)",
      _row61 and _row61["from"] == ".".join(["198", "51", "100", "0"]) + "/24/udp"
      # Every capture's rules, not the last loop's (s7d): s7b is the commented one this names.
      and len(_sts61) == 3 and all(_v["rules"] for _v in _sts61.values())
      and not any("#" in r["from"] for _v in _sts61.values() for r in _v["rules"])
      and all(_v for _v in _tsr61.values())
      and not any("#" in r["from"] for _v in _tsr61.values() for r in _v)
      and not any("#" in r["from"] for r in _drrows61), repr((_row61, _drrows61)))

# 2. The Firewall page, the Network card and Close public panel port agree on what holds the
#    panel port open: the real captures (panel port 47150), and part61's own table (5000).


def _page61(text, panel_port, sshd=47122):
    """{To column: group} as remote_ufw_status annotates `text` on the panel's own host."""
    with _patched():
        _patch(_smc61, "run_privileged", lambda *a, **k: (text, "", 0))
        _patch(_smc61, "is_local_server", lambda s: True)
        _patch(_smh61, "_sshd_current_ports", lambda s: [str(sshd)])
        _patch(_smh61, "_tailscale_conn_state", lambda s: (False, False))
        _patch(_fwm61, "_config_unreadable", lambda: False)
        _patch(_pcfg61, "load_config", lambda: {"port": panel_port, "tailscale_setup_done": True})
        st = _fwm61.remote_ufw_status(NS(port=sshd))
    return {g["port_label"]: g for g in st.get("groups", [])}


def _card61(text, panel_port):
    with _patched():
        _patch(_smc61, "run_privileged", lambda *a, **k: (_as_plain61(text), "", 0))
        got = _smh61.remote_public_ssh_status(NS(port=22), panel_port=panel_port)
    return got.get("panel_port_open")


_agree61 = {}
for _cap61, _lbl61 in (("s6b-list", "47140,47150,47160/tcp"), ("s6d-range", "47100:47199/tcp"),
                       ("s6c-only", "47150/tcp"), ("s3-udp", "47122/tcp")):
    _t61 = _real61_text(_cap61)
    _g61 = _page61(_t61, 47150)[_lbl61]
    _agree61[_cap61] = (_g61["is_panel"], _g61["protected"], _card61(_t61, 47150))
check("panel port: on the VPS's own rows, a list or range holding the panel port open is the panel's "
      "rule on the Firewall page and protected (`47140,47150,47160/tcp` had a plain delete ×), as the "
      "card says open; its own `47150/tcp` too; an unrelated SSH rule is neither (both directions)",
      _agree61 == {"s6b-list": (True, True, True), "s6d-range": (True, True, True),
                   "s6c-only": (True, True, True), "s3-udp": (False, True, False)}, repr(_agree61))
def _r15d_page_groups61(text, panel_port, sshd=47122):
    with _patched():
        _patch(_smc61, "run_privileged", lambda *a, **k: (text, "", 0))
        _patch(_smc61, "is_local_server", lambda s: True)
        _patch(_smh61, "_sshd_current_ports", lambda s: [str(sshd)])
        _patch(_smh61, "_tailscale_conn_state", lambda s: (False, False))
        _patch(_fwm61, "_config_unreadable", lambda: False)
        _patch(_pcfg61, "load_config", lambda: {"port": panel_port, "tailscale_setup_done": True})
        return _fwm61.remote_ufw_status(NS(port=sshd)).get("groups", [])


# 3. The one real capture of follow-up 2's case, s5a (read by no check before review 1011e): on the
#    VPS, a DENY of a documentation /24 sits above an ALLOW of SSH (47122) from one address in it. That allow
#    is no way in, so the public rule is the only one left and protected, and the shadowed allow
#    may go with a warning.
_s5a61 = {(_g["port_label"], _g.get("scope"), _g.get("action")): (_g.get("ssh_live"), _g.get("protected"),
                                                                  _g.get("warn"))
          for _g in _r15d_page_groups61(_real61_text("s5a-deny-above"), 47150)
          if _g["port_label"] == "47122/tcp"}
_s5a_net61 = ".".join(["198", "51", "100", "0"]) + "/24"
check("firewall: on the VPS's own rows (s5a), an SSH allow from an address a DENY of its /24 above it "
      "shadows is no way in: the public SSH rule is protected, the shadowed allow only warns",
      _s5a61 == {("47122/tcp", "Any address", "ALLOW"): (True, True, False),
                 ("47122/tcp", _s5a_net61, "DENY"): (False, False, False),
                 ("47122/tcp", _ADMIN61, "ALLOW"): (False, False, True)}, repr(_s5a61))
_pg61 = {}
for _row61, _want61 in _PORT_ROWS61.items():
    _grp61 = list(_protect61(NS(port=22), [_row61], is_local=True, sshd_ports=(22,),
                             cfg={"port": 5000, "tailscale_setup_done": False}))[0]
    _pg61[_row61] = _grp61["is_panel"]
check("panel port: the Firewall page marks as the panel's rule exactly the rows the card calls open and "
      "Close public panel port does not call already closed (part61's 13-row table)",
      _pg61 == {k: bool(v) for k, v in _PORT_ROWS61.items()}
      and _pg61 == {k: v != "already" for k, v in _route61.items()},
      repr({k: v for k, v in _pg61.items() if v != bool(_PORT_ROWS61[k])}))

# 3. The lock-out reason names a range or a list as one, not as "the SSH port".
_rs61 = _page61(_real61_text("s6d-range"), 47150)["47100:47199/tcp"]["protect_reason"]
_rl61 = _page61(_real61_text("s6b-list"), 47150)["47140,47150,47160/tcp"]["protect_reason"]
_rsr61 = _page61(_real61_text("s6d-range"), 47999)["47100:47199/tcp"]["protect_reason"]
_rpo61 = _page61(_real61_text("s6c-only"), 47150)["47150/tcp"]["protect_reason"]
_rss61 = _page61(_real61_text("s3-udp"), 47999)["47122/tcp"]["protect_reason"]
check("protect reason: a range or list holding the panel port open says it opens those ports, "
      "including the panel's; the port's own rule still says 'Port 47150 is' (control)",
      "This rule opens ports 47100:47199, including port 47150" in _rs61
      and "This rule opens ports 47140,47150,47160, including port 47150" in _rl61
      and _rpo61.startswith("Port 47150 is where"), repr((_rs61, _rl61, _rpo61)))
check("protect reason: a range that is the only SSH rule says it opens ports including the SSH port "
      "('Port 47100:47199 is the SSH port' before); a single port still says 'Port 47122 is' (control)",
      _rsr61.startswith("This rule opens ports 47100:47199, including the SSH port")
      and _rss61.startswith("Port 47122 is the SSH port"), repr((_rsr61, _rss61)))

# 4. The Firewall page's lock-out reasons are translated for es / fr viewers; the API's English
#    sentence is unchanged.
import json as _json61  # noqa: E402

from unit.part47 import _cut47, _node47  # noqa: E402
from panel.core import i18n as _i18n61  # noqa: E402


_ROOT61 = _os61.path.dirname(_os61.path.dirname(_os61.path.dirname(_os61.path.abspath(__file__))))


def _cat61(lang):
    """Every section of translations/<lang>/, merged."""
    out, d = {}, _os61.path.join(_ROOT61, "translations", lang)
    for f in sorted(_os61.listdir(d)):
        if f.endswith(".json"):
            with open(_os61.path.join(d, f), encoding="utf-8") as fh:
                out.update(_json61.load(fh))
    return out


_ph61 = _re61.compile(r"\{(\w+)\}")
_miss61 = {}
for _lang61 in ("es", "fr"):
    _c61 = _cat61(_lang61)
    _miss61[_lang61] = [k for k, v in _fwm61.R14A_REASONS.items()
                        if v not in _c61 or sorted(_ph61.findall(_c61[v])) != sorted(_ph61.findall(v))
                        or _c61[v] == v]
check("protect reason: every reason template the Firewall page can show is in the es and fr catalogs, "
      "translated, with the same placeholders", _miss61 == {"es": [], "fr": []}, repr(_miss61))
_g61 = _page61(_real61_text("s6c-only"), 47150)["47150/tcp"]
# The Spanish template with its values in: what the page's JS must render (_fwReason, below).
_es61 = _i18n61.translate("es", _g61.get("protect_reason_key", "")).format_map(
    dict(_g61.get("protect_reason_params") or {}))
check("protect reason: the API's sentence is the English one, and the page's text for es is the Spanish "
      "template with the port in it",
      _g61["protect_reason"].startswith("Port 47150 is where this panel's own web interface listens")
      and _es61.startswith("El puerto 47150 es donde escucha"), repr((_g61["protect_reason"], _es61)))
# (The standalone Firewall page rendered the tooltip server-side too; it is a redirect to the host page's
# Network tab now (ui-tidy-2), whose rules only the page's JS draws, held below.)
with open(_os61.path.join(_ROOT61, "static", "js", "remote_firewall.js"), encoding="utf-8") as _fh61:
    _jsrc61 = _fh61.read()
_cat_es61 = _cat61("es")
_js61 = _node47("const I18N = %s; const t = s => (Object.prototype.hasOwnProperty.call(I18N, s) ? I18N[s] : s);\n"
                "%s\nconsole.log(JSON.stringify([_fwReason(%s), _fwReason({protect_reason: 'plain'})]));"
                % (_json61.dumps({k: v for k, v in _cat_es61.items() if k in _fwm61.R14A_REASONS.values()}),
                   _cut47(_jsrc61, "function _fwReason"), _json61.dumps(_g61)))
_JSNAME61 = ("protect reason: the page's JS (_fwReason, used on every refresh and in the delete refusal) "
             "renders the translated template with the port, and falls back to the English sentence")
if _js61 is None:
    skip(_JSNAME61, "node is not installed")
else:
    check(_JSNAME61, isinstance(_js61, list) and _js61[0] == _es61 and _js61[1] == "plain", repr(_js61))
check("part61: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP61_START, repr(_P9_TRIPPED[_TRIP61_START:][:6]))
