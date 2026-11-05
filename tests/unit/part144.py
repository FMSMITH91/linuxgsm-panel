"""Part 144 of the unit suite: a dead IPv6 route to Telegram costs a bot seconds, not 30.

On the owner's box (2026-11-05) about one IPv6 connect in nine to api.telegram.org hung, and
socket.create_connection gave each address the request's whole timeout in turn, IPv6 first: a
long-poll waited 30 s for IPv4 and a reply 8 s. notifications._connect_each caps every address but
the last at _CONNECT_EACH, and _OPENER (every Telegram, Discord and ntfy request) connects through it.
Held here:

* a first address that times out is closed and the next is tried, within the cap;
* the last address keeps the request's whole timeout, so a one-address host waits as long as before;
* every address failing raises the last error; the connected socket gets the request's timeout back;
* _OPENER's https handler is the fallback one, and the stock HTTPSHandler is gone from it;
* for real: a local listener behind an address that never answers is reached in about the cap.
"""
import socket as _real_socket144
import time
import types

from unit.part01 import check

from panel.services import notifications as nt144


class _FakeSock144:
    """A socket whose connect() times out for the addresses in `dead`; records its timeouts."""

    def __init__(self, log, dead):
        self.log, self.dead, self.timeouts, self.closed = log, dead, [], False
        log.append(self)

    def settimeout(self, t):
        self.timeouts.append(t)

    def bind(self, addr):
        self.bound = addr

    def connect(self, sockaddr):
        self.addr = sockaddr
        if sockaddr in self.dead:
            raise TimeoutError("timed out")

    def close(self):
        self.closed = True


def _fake_socket_mod144(addrs, dead):
    """A stand-in for the socket module as _connect_each sees it: getaddrinfo answers `addrs`."""
    log = []
    mod = types.SimpleNamespace(
        SOCK_STREAM=_real_socket144.SOCK_STREAM,
        getaddrinfo=lambda h, p, *a, **k: [
            (_real_socket144.AF_INET6 if ":" in a_[0] else _real_socket144.AF_INET,
             _real_socket144.SOCK_STREAM, 6, "", a_) for a_ in addrs],
        socket=lambda fam, st, pr: _FakeSock144(log, dead))
    return mod, log


def _run144(addrs, dead, timeout):
    mod, log = _fake_socket_mod144(addrs, dead)
    saved = nt144.socket
    nt144.socket = mod
    try:
        try:
            sock = nt144._connect_each(("api.telegram.org", 443), timeout)
            err = None
        except OSError as e:
            sock, err = None, e
    finally:
        nt144.socket = saved
    return sock, err, log


_V6 = ("2001:db8::9", 443, 0, 0)
_V4 = ("192.0.2.10", 443)

sock, err, log = _run144([_V6, _V4], {_V6}, 30)
check("bot network: a first address that hangs is given _CONNECT_EACH, closed, and the next tried",
      err is None and len(log) == 2 and log[0].timeouts == [nt144._CONNECT_EACH] and log[0].closed
      and sock is log[1] and log[1].addr == _V4,
      [(s.timeouts, s.closed, getattr(s, "addr", None)) for s in log])
check("bot network: ...the cap is 4 s, far under the 30 s a long-poll used to wait",
      nt144._CONNECT_EACH == 4.0, nt144._CONNECT_EACH)
check("bot network: the last address connects with the request's whole timeout, and keeps it",
      err is None and log[1].timeouts == [30, 30], log[1].timeouts)

sock, err, log = _run144([_V4], set(), 30)
check("bot network: a host with one address waits the whole timeout for it, as before",
      err is None and log[0].timeouts == [30, 30], [s.timeouts for s in log])

sock, err, log = _run144([_V6, _V4], set(), 2)
check("bot network: a request timeout under the cap caps the first address at that timeout",
      err is None and len(log) == 1 and log[0].timeouts == [2, 2], [s.timeouts for s in log])

sock, err, log = _run144([_V6, _V4], {_V6, _V4}, 8)
check("bot network: every address failing raises the last error, with every socket closed",
      sock is None and isinstance(err, TimeoutError) and all(s.closed for s in log) and len(log) == 2,
      (err, [s.closed for s in log]))

sock, err, log = _run144([], set(), 8)
check("bot network: an empty address list raises OSError instead of returning None",
      sock is None and isinstance(err, OSError), err)

_https144 = [h for h in nt144._OPENER.handlers if isinstance(h, nt144.urllib.request.HTTPSHandler)]
check("bot network: _OPENER's only https handler is the fallback one",
      len(_https144) == 1 and type(_https144[0]) is nt144._FallbackHTTPS,
      [type(h).__name__ for h in _https144])
_conn144 = nt144._FallbackHTTPSConnection("api.telegram.org", timeout=5)
check("bot network: ...and its connections connect through _connect_each",
      _conn144._create_connection is nt144._connect_each)
check("bot network: ...with the redirect refusal still in the opener",
      any(isinstance(h, nt144._NoRedirect) for h in nt144._OPENER.handlers))


# For real: a listener on 127.0.0.1, listed AFTER an address that never answers (TEST-NET-1, which
# nothing routes; if this host refuses it at once instead, the check still holds, only faster).
_srv144 = _real_socket144.socket(_real_socket144.AF_INET, _real_socket144.SOCK_STREAM)
_srv144.bind(("127.0.0.1", 0))
_srv144.listen(1)
_port144 = _srv144.getsockname()[1]
_mod144 = types.SimpleNamespace(
    SOCK_STREAM=_real_socket144.SOCK_STREAM, socket=_real_socket144.socket,
    getaddrinfo=lambda h, p, *a, **k: [
        (_real_socket144.AF_INET, _real_socket144.SOCK_STREAM, 6, "", ("192.0.2.1", _port144)),
        (_real_socket144.AF_INET, _real_socket144.SOCK_STREAM, 6, "", ("127.0.0.1", _port144))])
_saved144 = (nt144.socket, nt144._CONNECT_EACH)
nt144.socket, nt144._CONNECT_EACH = _mod144, 0.5
_t0 = time.monotonic()
try:
    try:
        _s144 = nt144._connect_each(("api.telegram.org", _port144), 30)
        _peer144 = _s144.getpeername()
        _s144.close()
    except OSError as e:
        _peer144 = e
finally:
    nt144.socket, nt144._CONNECT_EACH = _saved144
    _srv144.close()
_took144 = time.monotonic() - _t0
check("bot network: for real, a listener behind a dead address is reached in about the cap, not 30 s",
      _peer144 == ("127.0.0.1", _port144) and _took144 < 5, (_peer144, round(_took144, 2)))
