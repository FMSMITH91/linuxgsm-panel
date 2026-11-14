"""Part 199 of the unit suite: what docs/https.md says about bans behind a proxy or tunnel.

Held here:
* The login-throttle numbers the section states (8 failed attempts in 5 minutes) are the ones the
  panel enforces (LOGIN_MAX_FAILS, LOGIN_WINDOW), and the README's link lands on the section.
* ProxiedBanGate, given X-Forwarded-For as Cloudflare's edge writes it (the address that connected
  to Cloudflare appended LAST, after whatever the visitor sent), refuses a banned visitor who
  forged a first hop, and lets through a visitor who named a banned address in a forged first hop.

HOW IT RUNS. The docs are read as text; the gate wraps a stand-in WSGI app, with the ban set
swapped in and restored. Nothing reaches the network.
"""
import ipaddress as _ip199
import os as _os199
import re as _re199

from unit.part01 import check
from unit import REPO_ROOT as _root

from app import LOGIN_MAX_FAILS as _MAX199, LOGIN_WINDOW as _WIN199  # noqa: E402
from panel.core import middleware as _mw199
from panel.security import banlist as _bl199


def _doc199(rel):
    """The text of docs/`rel`."""
    with open(_os199.path.join(_root, "docs", rel), encoding="utf-8") as fh:
        return fh.read()


def _slug199(heading):
    """The anchor GitHub gives a markdown heading: lower case, punctuation dropped, spaces to hyphens."""
    return _re199.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


_https199 = _doc199("https.md")
_readme199 = _doc199("README.md")
_m199 = _re199.search(r"(\d+) failed attempts in (\d+) minutes per address", _https199)
_said199 = (int(_m199.group(1)), int(_m199.group(2)) * 60) if _m199 else None
check("docs/https.md: the bans section states the login throttle the panel enforces "
      "(LOGIN_MAX_FAILS failures in LOGIN_WINDOW)",
      _said199 == (_MAX199, _WIN199), repr((_said199, _MAX199, _WIN199)))

_anchors199 = {_slug199(h) for h in _re199.findall(r"^#+ (.+)$", _https199, _re199.M)}
_links199 = _re199.findall(r"\(https\.md#([^)\s]+)\)", _readme199)
check("docs/README.md: its link to the bans section of https.md lands on a heading there",
      "bans-and-blocks-behind-a-proxy-or-tunnel" in _links199
      and set(_links199) <= _anchors199, repr((_links199, sorted(_anchors199))))


def _gate199(xff):
    """The status ProxiedBanGate answers a request carrying X-Forwarded-For `xff`."""
    def _inner(environ, start_response):
        start_response("200 OK", [])
        return [b"ok"]
    got = []
    _mw199.ProxiedBanGate(_inner)({"HTTP_X_FORWARDED_FOR": xff, "REMOTE_ADDR": "127.0.0.1"},
                                  lambda status, headers: got.append(status))
    return got


_saved199 = _bl199._by_len
_bl199._by_len = {(4, 32): frozenset({_ip199.ip_network("203.0.113.66/32")})}
try:
    # A banned visitor who sent a made-up header of their own: Cloudflare appends the address that
    # connected to it, so the banned one is last. An unbanned visitor naming the banned address:
    # Cloudflare appends theirs after it.
    _banned199 = _gate199("198.51.100.20, 203.0.113.66")
    _framed199 = _gate199("203.0.113.66, 198.51.100.20")
finally:
    _bl199._by_len = _saved199
check("ProxiedBanGate behind a Cloudflare Tunnel: a banned visitor is refused whatever first hop "
      "they forged, and a visitor naming a banned address first is not refused for it",
      (_banned199, _framed199) == (["403 Forbidden"], ["200 OK"]), repr((_banned199, _framed199)))
