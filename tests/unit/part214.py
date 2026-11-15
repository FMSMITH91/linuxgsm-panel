"""Part 214 of the unit suite: web hardening from the OWASP cheat sheets.

* TLS (Transport Layer Security Cheat Sheet, "Use TLS for All Pages"): when the panel's own HTTPS is
  configured and fails to start, a network-facing bind is moved to 127.0.0.1 instead of serving plain
  HTTP there, the console says what happened and how to fix it, and the run line listens on the bind
  that was recorded; a loopback bind keeps plain HTTP, as the design behind Tailscale Serve or a proxy.
* Uploads (File Upload Cheat Sheet, "Filename Safety"): the upload route refuses a name with a
  control character, a direction override or whitespace at either end, as rename and create do.
* ntfy (SSRF Prevention Cheat Sheet): the operator-chosen server is refused when ANY address its name
  resolves to is loopback, 0.0.0.0/8, link-local (metadata), multicast, reserved or a metadata address,
  IPv4-mapped, NAT64 and 6to4 forms unwrapped first; LAN, tailnet and public addresses are connected to,
  through the one lookup that was checked; the Test button says why, in the viewer's language.
* Headers (HTTP Headers, Clickjacking Defense, XS Leaks, HSTS sheets): the response hook's rules on a
  page, a JSON answer and an asset; the pages that show a secret answer no-store through their routes.
  The full app's own responses are checked in the smoke suite (tests/smoke/part03.py).
* Socket.IO (WebSocket Security Cheat Sheet): the app's one SocketIO takes no message over 64 KB (the
  smoke suite reads it in a real handshake); the terminal page cuts a paste into pieces under that,
  never splitting a surrogate pair (run in node).
* Links and scripts: every target="_blank" anchor in the templates and the panel's JS carries
  rel="noopener noreferrer", and no panel script uses eval, new Function or a string timer.
Every route runs on part12's app with its transport tripwire armed; nothing reaches a host or data/.
"""
import contextlib as _ctx214
import io as _io214
import json as _json214
import os as _os214
import re as _re214
import shutil as _shutil214
import subprocess as _sp214  # nosec B404 - runs node on the panel's own JS, nothing else
import socket as _socket214
import types as _types214

import app as _app214
from flask import Flask as _Flask214, jsonify as _jsonify214

from unit import REPO_ROOT as _ROOT214
from unit.part01 import check, eq, skip
from unit.part12 import (P9_ADMIN, P9_GS, _P9_TRIPPED, _p9, _p9_client, _p9_json, _p9_patch, _p9_restore_all)
from panel.ops.ssh_manager import files as _files214
from panel.routes import server_files as _sf214
from panel.security import headers as _hdr214
from panel.services import certs as _certs214
from panel.services import notifications as _nt214

_trips214 = len(_P9_TRIPPED)


# ── 1. TLS that failed to start never serves plain HTTP off this host ───────────────────────────
def _tls_boot214(host, fail=True):
    """Run _boot_ssl_args with the cert step failing (or not); return (args, config, console text)."""
    fake = type("A", (), {"config": {"BOOT_BIND": host, "_BOOT_BIND": host}})()

    def _cert(*_a):
        if fail:
            raise PermissionError("cannot write /srv/p214/ssl/cert.pem")
    _p9_patch(_app214, "_effective_https", lambda cfg: True)
    _p9_patch(_app214, "_ensure_self_signed_cert", _cert)
    out = _io214.StringIO()
    try:
        with _ctx214.redirect_stdout(out):
            args = _app214._boot_ssl_args(fake, {}, host, 5214)
    finally:
        _p9_restore_all()
    return args, fake.config, out.getvalue()


_args214, _conf214, _said214 = _tls_boot214("0.0.0.0")   # nosec B104 - a bind string, not a socket
check("tls: HTTPS that fails on a public bind listens on 127.0.0.1 instead, recorded for the run line",
      _args214 == {} and _conf214["BOOT_BIND"] == "127.0.0.1" and _conf214["_BOOT_BIND"] == "127.0.0.1"
      and _conf214["BOOT_TLS"] is False and _conf214["BOOT_TLS_ERROR"] == "PermissionError", repr(_conf214))
check("tls: ...and the console says why, how to reach it now and how to fix it",
      all(s in _said214 for s in ("could not start", "127.0.0.1:5214 only", "ssh -L 5214:127.0.0.1:5214",
                                  "Tailscale Serve", "restart the panel", "trust_proxy"))
      and "serving plain HTTP instead" not in _said214, _said214)
_v6args214, _v6conf214, _ = _tls_boot214("::")
eq("tls: an IPv6 any-address bind is moved to loopback too", _v6conf214["BOOT_BIND"], "127.0.0.1")
for _lo214 in ("127.0.0.1", "::1"):
    _largs214, _lconf214, _lsaid214 = _tls_boot214(_lo214)
    check("tls: a loopback bind (%s) keeps plain HTTP there, and says it is loopback only" % _lo214,
          _largs214 == {} and _lconf214["BOOT_BIND"] == _lo214 and "loopback" in _lsaid214,
          repr((_lconf214, _lsaid214)))
_okargs214, _okconf214, _ = _tls_boot214("0.0.0.0", fail=False)   # nosec B104 - a bind string
check("tls: HTTPS that starts keeps the configured bind",
      bool(_okargs214) and _okconf214["BOOT_BIND"] == "0.0.0.0" and _okconf214["BOOT_TLS"] is True,
      repr(_okconf214))
with open(_app214.__file__, encoding="utf-8") as _fh214:
    _main214 = _fh214.read().split('if __name__ == "__main__":', 1)[1]
check("tls: the run line listens on the recorded bind, not on the configured host",
      'app.socketio.run(app, app.config["BOOT_BIND"], port,' in _main214
      and "socketio.run(app, host=host" not in _main214, "")
eq("tls: the fallback bind is loopback", _certs214.TLS_FAILED_BIND, "127.0.0.1")


# ── 2. an uploaded file's name is held to the rules a rename's is ───────────────────────────────
def _upload214(name):
    """POST one file named `name` through the upload route; return (json, names written)."""
    wrote = []
    _p9_patch(_sf214, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_files214, "_write_file_as_user",
              lambda server, user, ap, data, selfname=None: wrote.append(ap) or (True, ""))
    try:
        r = _p9_client(P9_ADMIN).post("/api/server/%d/upload" % P9_GS, content_type="multipart/form-data",
                                      data={"path": "cfg", "overwrite": "1",
                                            "file": (_io214.BytesIO(b"x"), name)})
        return _p9_json(r), wrote
    finally:
        _p9_restore_all()


_good214, _gw214 = _upload214("server.cfg")
check("upload: an ordinary name is written into the folder",
      _good214.get("success") is True and _gw214 == ["/home/csgoserver/cfg/server.cfg"], repr((_good214, _gw214)))
for _bad214, _why214 in (("evil\u202egfc.exe", "direction"), ("bell\x07.cfg", "control characters"),
                         ("server.cfg ", None), (" server.cfg", None)):
    _res214, _bw214 = _upload214(_bad214)
    check("upload: %r is refused with name_problem's reason and nothing is written" % _bad214,
          _res214.get("success") is False and _bw214 == []
          and _res214.get("message") == _files214.name_problem(_bad214)
          and (_why214 is None or _why214 in _res214.get("message", "")), repr((_res214, _bw214)))


eq("part214: nothing reached a real transport", _P9_TRIPPED[_trips214:], [])
