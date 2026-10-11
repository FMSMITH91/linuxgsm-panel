"""Part 57 of the unit suite: review 1011c's core, system_ops, ssh-core and reboot fixes (builder A).

Held here, each against the code path the finding named:

* a non-string text setting hand-edited into config.json (accent_color, login_tagline,
  tailscale_mount, site_domain, bind_host, a socketio_cors_origins entry) reads as unset; it took
  down every page, the console's handshake, or the boot.
* (further sections are added below, one per finding)

HOW IT RUNS. Pages on part12's Flask app and client (part12 has run); every other outside call is a
stand-in (part20's _patch / _patched, undone at the end of each block). Nothing touches the
network, sudo, a real host or the checkout's data/.
"""
import types as _types57

from unit.part01 import check
from unit.part12 import _P9_CFG_PATH, _p9, _p9_cfg
from unit.part20 import _patch, _patched

import app as _app57  # noqa: E402
from panel.core import config as _cfg57  # noqa: E402
from panel.core import middleware as _mw57  # noqa: E402
from panel.core import origins as _or57  # noqa: E402
from panel.core.validation import _valid_hex_color as _hex57  # noqa: E402
from panel.ops import system_ops as _so57  # noqa: E402
from panel.ops.debug_report import process as _drp57  # noqa: E402
from panel.routes import route_helpers as _rh57  # noqa: E402

NS = _types57.SimpleNamespace
_CFG57_SNAPSHOT = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None


def _try57(fn, *a, **k):
    """fn's answer, or the NAME of the exception it raised, so a reverted fix fails its check by
    name instead of ending the part."""
    try:
        return fn(*a, **k)
    except Exception as exc:  # noqa: BLE001 - which class arrives IS the check
        return type(exc).__name__


# ── A01: a non-string text setting in config.json reads as unset ───────────────────────────────
try:
    _hexes57 = [_try57(_hex57, v) for v in (5, ["#aabbcc"], True)]
    check("config text: accent_color 5 / a list / true is no colour, not an AttributeError on every "
          "render", _hexes57 == ["", "", ""], repr(_hexes57))
    check("config text: ...and a real colour still reads (control)", _hex57("AABBCC") == "#aabbcc")

    _p9_cfg.save_config(dict(_p9_cfg.load_config(), accent_color=5, login_tagline=5))
    _r57 = _p9.test_client().get("/login")
    check("config text: /login renders with accent_color 5 and login_tagline 5 hand-edited in (every "
          "page answered 500, with no way back in through the UI)",
          _r57.status_code == 200 and b"Sign in to manage your game servers" in _r57.data,
          repr(_r57.status_code))
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), accent_color="#123abc", login_tagline="  Hi there "))
    _r57 = _p9.test_client().get("/login")
    check("config text: ...and real text values still render (control)",
          _r57.status_code == 200 and b"Hi there" in _r57.data and b"#123abc" in _r57.data,
          repr(_r57.status_code))

    def _mw57_run(mount):
        seen = {}

        def inner(environ, start_response):
            seen["script"] = environ.get("SCRIPT_NAME")
            start_response("200 OK", [])
            return [b""]
        with _patched():
            _patch(_mw57, "load_config", lambda: {"tailscale_mount": mount})
            raised = _try57(_mw57.PrefixMiddleware(inner), {"PATH_INFO": "/lgsm/x", "REQUEST_METHOD": "GET"},
                            lambda *a, **k: None)
        return raised if isinstance(raised, str) else seen.get("script")
    check("config text: tailscale_mount 5 serves the request with no prefix (prefix.rstrip raised on "
          "every request, static files and the Socket.IO handshake included)", _mw57_run(5) == "",
          repr(_mw57_run(5)))
    check("config text: ...and a real mount still prefixes (control)", _mw57_run("/lgsm") == "/lgsm")

    _socket57 = {k: _try57(_app57._explicit_socket_origins, v) for k, v in
                 (("none", [None]), ("zero", [0]), ("mixed", [None, "https://a.example"]))}
    check("config text: socketio_cors_origins [null] / [0] lists no origin (str(None) is 'None', "
          "which made the list truthy and refused every handshake)",
          _socket57 == {"none": [], "zero": [], "mixed": ["https://a.example"]}, repr(_socket57))
    with _patched():
        _patch(_app57, "load_config", lambda: {"socketio_cors_origins": [None], "site_domain": 5})
        _hs57 = _try57(_app57._socket_origin_allowed, "https://panel.example:5000",
                       {"HTTP_HOST": "panel.example:5000"})
    check("config text: the console handshake from the panel's own page is allowed with "
          "socketio_cors_origins [null] and site_domain 5 hand-edited in", _hs57 is True, repr(_hs57))
    _oc57 = _try57(_or57._origin_candidates, {"HTTP_HOST": "h:1"}, {"site_domain": 5})
    check("config text: site_domain 5 is no candidate host (it raised inside engineio's CORS "
          "callback)", _oc57 == ["h:1"], repr(_oc57))

    with _patched():
        _patch(_app57.ts, "suggest_best_bind", lambda port: {"bind_host": "100.64.0.9"})
        _app57._RESOLVED_BIND.pop(59157, None)
        _rb57 = _try57(_app57._resolved_bind, {"bind_host": 5, "port": 59157})
        _app57._RESOLVED_BIND.pop(59157, None)
    check("config text: bind_host 5 resolves as unset at boot (the boot raised: no panel at all)",
          _rb57 == "100.64.0.9", repr(_rb57))
    with _patched():
        _patch(_rh57, "current_app", NS(config={"_BOOT_BIND": "0.0.0.0"}))  # nosec B104
        _rp57 = _try57(_rh57._rebind_pending, {"bind_host": 5})
    check("config text: the Tailscale page's rebind test reads bind_host 5 as unset", _rp57 is False,
          repr(_rp57))
    with _patched():
        _patch(_cfg57, "load_config", lambda: {"bind_host": 5})
        _px57 = _try57(_so57._panel_login_proxied)
    check("config text: the fail2ban jail's proxied test reads bind_host 5 as unset", _px57 is False,
          repr(_px57))
    check("config text: the debug report reads bind_host 5 as unset (control: the helper it uses)",
          _drp57._cfg_text({"bind_host": 5}, "bind_host") == "" and _drp57._cfg_text(
              {"bind_host": "::1"}, "bind_host") == "::1")
finally:
    if _CFG57_SNAPSHOT is None:
        if _P9_CFG_PATH.exists():
            _P9_CFG_PATH.unlink()
    else:
        _P9_CFG_PATH.write_bytes(_CFG57_SNAPSHOT)
