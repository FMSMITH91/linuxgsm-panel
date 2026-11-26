"""Part 289 of the unit suite: the add-on page proxy's security fixes (routes/addon_web.py, services/addon_web*.py).

1. Response splitting: the add-on's reason phrase is never relayed (the status line is built from the code),
   an answer whose head holds a bare CR, a bare LF or a NUL is refused (502), and a Location or a WebSocket
   101 header value with a line break never reaches the browser, so the proxy's own sandbox policy can't
   be pushed into the body.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; the host read and the tunnel are
stand-ins (part279's scripted stream). Nothing reaches a host, /etc or data/.
"""
import threading as _th289
import types as _ty289

from unit.part01 import check, eq
from unit.part12 import P9_HOST, _p9, _p9_arm, _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all
from unit.part279 import _Stream279, _drop_member279, _member279, _open_answer279, _session_client279
from panel.routes import addon_web as _rw289
from panel.security import auth as _auth289
from panel.services import addon_web as _aw289, addon_web_http as _ht289, addons as _ad289

_PAGE289 = b"HTTP/1.1 200 Totally Fine\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi"


def _stubs289(ctx):
    """The host read (Open's, and the proxy's port checks) and the tunnel, answered from `ctx`."""
    def shell(server, user, sh, timeout=30, **_k):
        ctx["reads"].append(sh)
        return ctx["answers"].pop(0) if ctx["answers"] else ("", "", 1)

    def tunnel(server, port, timeout=30):
        s = _Stream279(ctx["page"][0])
        ctx["opened"].append((getattr(server, "id", None), port, s))
        return s
    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch_sm("open_loopback", tunnel)
    _p9_patch(_rw289, "game_account_write_refusal", lambda remote, user, reading=False: None)


def _harness289(tag, port_offset=0):
    """A server, a member with View add-on pages, and a link Open made for BlueMap: the context."""
    ctx = {"reads": [], "answers": [], "opened": [], "page": [_PAGE289]}
    _p9_arm(who="part289")
    _stubs289(ctx)
    ctx["sid"] = _p9_new_server(P9_HOST, "mcp289" + tag, "mc", 25600 + port_offset, name="p289-" + tag)
    ctx["member"] = _member279([_auth289.VIEW_SERVERS, _auth289.VIEW_ADDON_PAGES])
    ctx["port"] = _ad289.PORT_BASE + ctx["sid"]
    ctx["answers"].append(_open_answer279(ctx["sid"], ctx["port"]))
    r = _session_client279(ctx["member"][0]).post("/api/server/%d/addons/%s/web" % (ctx["sid"], _ad289.BLUEMAP))
    ctx["loc"], ctx["fresh"] = r.headers.get("Location", ""), _p9.test_client()
    ctx["token"] = ctx["loc"][len("/addon-web/"):-1]
    return ctx


def _teardown289(ctx):
    _p9_restore_all()
    _aw289._LINKS.clear()
    _drop_member279(*ctx["member"])
    _p9_delete_server(ctx["sid"])


# ── 1. response splitting ─────────────────────────────────────────────────────────────────────────
_SPLIT289 = {
    "reason with a bare LF pair": b"HTTP/1.1 200 OK\n\n<script>p289()</script>\r\nContent-Type: text/html\r\n\r\n",
    "header with a bare LF": b"HTTP/1.1 200 OK\r\nContent-Type: text/html\nX-P289: p289()\r\nContent-Length: 2\r\n\r\nhi",
    "reason with a bare CR": b"HTTP/1.1 200 OK\rSet-Cookie: p289()\r\nContent-Length: 2\r\n\r\nhi",
    "header with a NUL": b"HTTP/1.1 200 OK\r\nContent-Type: text/\x00html\r\nContent-Length: 2\r\n\r\nhi",
}


def _splitting289():
    res = {}
    ctx = {"member": (0, 0), "sid": 0}
    try:
        ctx = _harness289("sp")
        for name, page in _SPLIT289.items():
            ctx["page"][0] = page
            r = ctx["fresh"].get(ctx["loc"])
            res[name] = (r.status_code, "p289()" in r.get_data(as_text=True) + str(r.headers),
                         r.headers.get("Content-Security-Policy", "").startswith("sandbox allow-scripts"))
        for name, page in (("custom reason", _PAGE289), ("unknown code", _PAGE289.replace(b"200 Totally Fine", b"299 Nice"))):
            ctx["page"][0] = page
            r = ctx["fresh"].get(ctx["loc"])
            res[name] = (r.status, r.get_data())
    finally:
        _teardown289(ctx)
    return res


_sp289 = _splitting289()
eq("proxy: an add-on answer whose head holds a bare LF (in the reason phrase or a header), a bare CR or a NUL is "
   "refused (502, the sandbox policy on the refusal) and none of it reaches the browser",
   {k: _sp289.get(k) for k in _SPLIT289}, {k: (502, False, True) for k in _SPLIT289})
eq("proxy: the status line is built from the add-on's code alone: its own reason phrase is never relayed, an "
   "unknown code gets a fixed word, and the body still comes through",
   (_sp289.get("custom reason"), _sp289.get("unknown code")), (("200 OK", b"hi"), ("299 Unknown", b"hi")))


def _location289():
    """The proxy's answer (_answer, the caller of kept_response_headers) to a redirect whose Location has a line break."""
    started = []
    link = _ty289.SimpleNamespace(addon_id=_ad289.BLUEMAP, port=21000)
    out = []
    for value in ("/next\r\nSet-Cookie: p289=1", "/next"):
        head = _ht289.Head(302, "Found", [("Location", value), ("Content-Length", "0")], b"")
        gate = _th289.BoundedSemaphore(1)
        gate.acquire()
        body = _rw289._answer(lambda status, headers: started.append((status, headers)), _Stream279(b""), head, "GET",
                              "/", link, "/addon-web/T289", gate)
        list(body)
        out.append((started[-1][0], dict(started[-1][1]).get("Location")))
    return out


eq("proxy: a redirect's Location with a line break goes to the link's root (one line), a plain one under the link",
   _location289(), [("302 Found", "/addon-web/T289/"), ("302 Found", "/addon-web/T289/next")])


class _End289:
    """One end of the WebSocket splice: records what it is sent, ends at once."""

    def __init__(self):
        self.sent, self.closed = b"", False

    def sendall(self, data):
        self.sent += bytes(data)

    def recv(self, _n):
        return b""

    def settimeout(self, _s):
        pass

    def close(self):
        self.closed = True


def _switch289():
    sock, stream = _End289(), _End289()
    head = _ht289.Head(101, "Switching Protocols", [("Sec-WebSocket-Accept", "p289acc\r\nSet-Cookie: p289=1"),
                                                     ("Sec-WebSocket-Protocol", "p289proto")], b"")
    _p9_patch(_rw289, "_client_socket", lambda environ: sock)
    try:
        _rw289.AddonWebProxy(None, _p9)._switch({}, stream, head, "t289")
    finally:
        _p9_restore_all()
    return sock.sent.decode("latin-1")


_sw289 = _switch289()
check("proxy: the WebSocket's 101 passes the add-on's header only when its value is one line (a value with CRLF "
      "is dropped, so it can't add a header), and a plain one still passes",
      "Set-Cookie" not in _sw289 and "p289acc" not in _sw289 and "Sec-WebSocket-Protocol: p289proto\r\n" in _sw289
      and _sw289.endswith("\r\n\r\n"), repr(_sw289))
