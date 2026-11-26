"""Part 289 of the unit suite: the add-on page proxy's security fixes (routes/addon_web.py, services/addon_web*.py).

1. Response splitting: the add-on's reason phrase is never relayed (the status line is built from the code),
   an answer whose head holds a bare CR, a bare LF or a NUL is refused (502), and a Location or a WebSocket
   101 header value with a line break never reaches the browser, so the proxy's own sandbox policy can't
   be pushed into the body.
2. The HTML rewrite finds the page's <head> with a linear scan: 4 MiB of `<head` with no `>` (sent gzipped, a
   few KB) is read, decoded and rewritten as the proxy does in well under a second, in a child interpreter
   so the quadratic regex it replaced fails this check by its timeout instead of stalling the suite; the
   scan finds the same tag the regex did on ordinary pages.
3. The port, checked again: before a new connection the proxy repeats Open's read (the root-capable question
   first) once the last read is older than PORT_RECHECK_SECONDS; a port the add-on no longer holds ends the
   link (audited, nothing dialled, its cookie jar emptied), a host that does not answer refuses that request
   only; an upstream that does not answer empties the jar and forces the next read; and Stop, Update and
   Remove end the add-on's links (only that add-on's, on that server).

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; the host read and the tunnel are
stand-ins (part279's scripted stream). Nothing reaches a host, /etc or data/.
"""
import re as _re289
import subprocess as _subp289  # nosec B404 - a child interpreter over the panel's own code
import sys as _sys289
import threading as _th289
import types as _ty289

from unit.part01 import _root, check, eq
from unit.part12 import (P9_ADMIN, P9_HOST, _p9, _p9_arm, _p9_audit, _p9_client, _p9_delete_server, _p9_new_server,
                         _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part279 import _Stream279, _drop_member279, _member279, _open_answer279, _session_client279
from panel.routes import addon_web as _rw289, addons as _ra289, addons_change as _rc289
from panel.security import auth as _auth289
from panel.services import addon_web as _aw289, addon_web_http as _ht289, addons as _ad289

_PAGE289 = b"HTTP/1.1 200 Totally Fine\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi"


def _stubs289(ctx):
    """The host read (Open's, and the proxy's port checks) and the tunnel, answered from `ctx`."""
    def shell(server, user, sh, timeout=30, **_k):
        ctx["reads"].append(sh)
        return ctx["answers"].pop(0) if ctx["answers"] else ("", "", 1)

    def tunnel(server, port, timeout=30):
        if ctx["page"][0] is None:
            raise ConnectionError("p289: nothing listens")
        s = _Stream279(ctx["page"][0])
        ctx["opened"].append((getattr(server, "id", None), port, s))
        return s
    _p9_patch_sm("shell_as_game_user", shell)
    _p9_patch_sm("open_loopback", tunnel)
    _p9_patch(_rw289, "game_account_write_refusal",
              lambda remote, user, reading=False: ctx["asked"].append(reading) or ctx["why"][0])
    # Long enough that no check here reads the port again unless it sets a shorter one itself.
    _p9_patch(_aw289, "PORT_RECHECK_SECONDS", 3600)


def _harness289(tag, port_offset=0):
    """A server, a member with View add-on pages, and a link Open made for BlueMap: the context."""
    ctx = {"reads": [], "answers": [], "opened": [], "page": [_PAGE289], "asked": [], "why": [None]}
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
            # A refused answer makes the next request read the port again (section 3): its answer is queued,
            # so every request here reaches the add-on and is judged on the add-on's answer alone.
            ctx["answers"].append(_open_answer279(ctx["sid"], ctx["port"]))
            ctx["page"][0], k = page, len(ctx["opened"])
            r = ctx["fresh"].get(ctx["loc"])
            res[name] = (r.status_code, len(ctx["opened"]) > k, "p289()" in r.get_data(as_text=True) + str(r.headers),
                         r.headers.get("Content-Security-Policy", "").startswith("sandbox allow-scripts"))
        for name, page in (("custom reason", _PAGE289), ("unknown code", _PAGE289.replace(b"200 Totally Fine", b"299 Nice"))):
            ctx["answers"].append(_open_answer279(ctx["sid"], ctx["port"]))
            ctx["page"][0] = page
            r = ctx["fresh"].get(ctx["loc"])
            res[name] = (r.status, r.get_data())
    finally:
        _teardown289(ctx)
    return res


_sp289 = _splitting289()
eq("proxy: an add-on answer whose head holds a bare LF (in the reason phrase or a header), a bare CR or a NUL is "
   "refused once read (502, the sandbox policy on the refusal) and none of it reaches the browser",
   {k: _sp289.get(k) for k in _SPLIT289}, {k: (502, True, False, True) for k in _SPLIT289})
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
    sent = [("Sec-WebSocket-Accept", "p289acc\r\nSet-Cookie: p289=1"), ("Sec-WebSocket-Protocol", "p289proto")]
    head = _ht289.Head(101, "Switching Protocols", sent, b"")
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


# ── 2. the head scan ──────────────────────────────────────────────────────────────────────────────
# The child imports the services only (the routes module needs the app): the same three steps the proxy's
# _rewritten takes, the capped body read, the gzip decode and the rewrite, timed together.
_SCAN289 = r"""
import gzip, sys, time
sys.path.insert(0, sys.argv[1])
from panel.services import addon_web as aw, addon_web_http as h
packed = gzip.compress(b"<head" * (4 * 1024 * 1024 // 5))
class Stream:
    def __init__(self, left):
        self.left = left
    def recv(self, n):
        out, self.left = self.left[:n], self.left[n:]
        return out
head = h.Head(200, "OK", [("Content-Type", "text/html"), ("Content-Encoding", "gzip"),
                          ("Content-Length", str(len(packed)))], b"")
began = time.perf_counter()
raw = b"".join(h.body(Stream(packed), head, "GET", cap=aw.MAX_REWRITE))
out = aw.rewrite("html", aw.decoded(raw, head.get("Content-Encoding")), "/addon-web/T")
took = time.perf_counter() - began
print("SCAN %.3f %d %s" % (took, len(out) - len(aw.SHIM), out.startswith(aw.SHIM.encode())))
"""


def _scan289():
    try:
        p = _subp289.run([_sys289.executable, "-c", _SCAN289, _root],  # nosec B603 - own probe
                         capture_output=True, text=True, timeout=60, check=False)
    except Exception as e:  # TimeoutExpired, by name: the suite's runner may hand this module another subprocess
        if type(e).__name__ != "TimeoutExpired":
            raise
        return "timed out after 60 s"
    return next((x for x in p.stdout.splitlines() if x.startswith("SCAN ")), p.stderr[-400:])


_sc289 = _scan289()
_scp289 = _sc289.split()
check("proxy: an add-on page of 4 MiB of `<head` with no `>` (gzipped) is read, decoded and rewritten as the proxy "
      "does in well under a second (the call alone timed), the storage stand-ins first, nothing cut",
      len(_scp289) == 4 and _scp289[0] == "SCAN" and float(_scp289[1]) < 1.0 and _scp289[2:] == ["4194300", "True"],
      _sc289)
_OLD_HEAD289 = _re289.compile(rb"<head\b[^>]*>", _re289.I)
_PAGES289 = (b'<html><head><base href="/"></head>', b"<HEAD lang='en'>x", b"<header>x</header><head>", b"<head",
             b"<headx><head\n>", b"no head", b"<head/>", b"<head\tclass=a>", b"<head>", b"<HEAD\r\n data-x='y'>")


def _old_end289(page):
    m = _OLD_HEAD289.search(page)
    return m.end() if m else 0


eq("proxy: on ordinary pages the scan finds the same <head> the regex did (a tag with attributes, upper case, "
   "after a <header>, none, a lone `<head`, self-closed)",
   [_aw289.head_end(p) for p in _PAGES289], [_old_end289(p) for p in _PAGES289])


# ── 3. the port, checked again ────────────────────────────────────────────────────────────────────
def _link289(ctx):
    return _aw289._LINKS.get(_aw289._digest(ctx["token"]))


def _not_theirs289(ctx):
    """Open's read once the add-on has stopped and another account holds its port: no listener of this account's."""
    out, err, rc = _open_answer279(ctx["sid"], ctx["port"])
    return out.replace("own=127.0.0.1:%d" % ctx["port"], "own="), err, rc


def _recheck_steps289(ctx, res):
    fresh, loc = ctx["fresh"], ctx["loc"]
    n = len(ctx["reads"])
    res["cached"] = (fresh.get(loc).status_code, len(ctx["reads"]) - n)
    _p9_patch(_aw289, "PORT_RECHECK_SECONDS", 0)
    ctx["answers"].append(_open_answer279(ctx["sid"], ctx["port"]))
    n, a = len(ctx["reads"]), len(ctx["asked"])
    r = fresh.get(loc)
    res["reread"] = (r.status_code, len(ctx["reads"]) - n, "ss -Htlnp" in ctx["reads"][-1], ctx["asked"][a:])
    n, k = len(ctx["reads"]), len(ctx["opened"])
    r = fresh.get(loc)              # no answer queued: the host "did not answer"
    res["host_down"] = (r.status_code, len(ctx["opened"]) - k, _link289(ctx) is not None)
    # The add-on's own sign-in in the jar, then nothing answers on the port.
    _p9_patch(_aw289, "PORT_RECHECK_SECONDS", 3600)
    ctx["answers"].append(_open_answer279(ctx["sid"], ctx["port"]))
    ctx["page"][0] = _PAGE289.replace(b"Content-Length", b"Set-Cookie: p289jar=1\r\nContent-Length")
    first = fresh.get(loc).status_code
    jar = dict(_link289(ctx).jar)
    ctx["page"][0] = None
    gone = fresh.get(loc).status_code
    res["jar"] = (first, jar, gone, dict(_link289(ctx).jar), _link289(ctx).target() in _aw289._VERIFIED)
    ctx["page"][0] = _PAGE289
    ctx["answers"].append(_open_answer279(ctx["sid"], ctx["port"]))
    n = len(ctx["reads"])
    res["after_jar"] = (fresh.get(loc).status_code, len(ctx["reads"]) - n)


def _taken_steps289(ctx, res):
    fresh, loc = ctx["fresh"], ctx["loc"]
    link = _link289(ctx)
    link.jar["p289jar"] = "2"
    _p9_patch(_aw289, "PORT_RECHECK_SECONDS", 0)
    ctx["answers"].append(_not_theirs289(ctx))
    k = len(ctx["opened"])
    r = fresh.get(loc)
    row = _p9_audit("addon_web_refused")
    res["taken"] = (r.status_code, "link has ended" in r.get_data(as_text=True), len(ctx["opened"]) - k,
                    "no longer running on its port" in getattr(row, "detail", ""), dict(link.jar),
                    _link289(ctx) is None, fresh.get(loc).status_code)
    # A root-capable account: refused before anything is read as it, and the link ends.
    ctx["answers"].append(_open_answer279(ctx["sid"], ctx["port"]))
    r = _session_client279(ctx["member"][0]).post("/api/server/%d/addons/%s/web" % (ctx["sid"], _ad289.BLUEMAP))
    ctx["loc"] = r.headers.get("Location", "")
    ctx["token"] = ctx["loc"][len("/addon-web/"):-1]
    ctx["why"][0] = "p289: that account can become root"
    n = len(ctx["reads"])
    res["root"] = (fresh.get(ctx["loc"]).status_code, len(ctx["reads"]) - n, _link289(ctx) is None)
    ctx["why"][0] = None


def _recheck289():
    res = {}
    ctx = {"member": (0, 0), "sid": 0}
    try:
        ctx = _harness289("pc", 1)
        for step in (_recheck_steps289, _taken_steps289):
            try:
                step(ctx, res)
            except Exception as e:       # a step that raised fails its checks by name (below), not the suite
                res.setdefault("raised", []).append("%s: %r" % (step.__name__, e))
    finally:
        _teardown289(ctx)
    return res


_rc289r = _recheck289()
eq("port check: no step raised", _rc289r.get("raised", []), [])
eq("port check: a link's first requests after Open read nothing again (Open's read counts)", _rc289r.get("cached"),
   (200, 0))
eq("port check: once the last read is older than PORT_RECHECK_SECONDS the next request repeats Open's read (the "
   "account's own listeners) after asking the root-capable question as a READ, and is answered",
   _rc289r.get("reread"), (200, 1, True, [True]))
eq("port check: a host that does not answer refuses that request (502), dials nothing and keeps the link",
   _rc289r.get("host_down"), (502, 0, True))
eq("port check: an add-on that stopped and a port another account now holds ends the link: 409 with the ended "
   "sentence, nothing dialled, audited, its cookie jar emptied, and the link gone after",
   _rc289r.get("taken"), (409, True, 0, True, {}, True, 404))
eq("port check: an account that became root-capable is refused before anything is read as it, and the link ends",
   _rc289r.get("root"), (409, 0, True))
eq("proxy: a port where nothing answers empties the link's cookie jar (the add-on's sign-in is not kept for "
   "whatever binds the port next) and drops the last read",
   _rc289r.get("jar"), (200, {"p289jar": "1"}, 502, {}, False))
eq("proxy: ...so the next request reads the port again first, and is answered", _rc289r.get("after_jar"), (200, 1))


def _revoke_actions289():
    sid = _p9_new_server(P9_HOST, "mcp289rv", "mc", 25603, name="p289-rv")
    port = _ad289.PORT_BASE + sid

    def links():
        return {name: _aw289.mint("1:0:p289", 1, target, "en", 1800.0, 28800.0) for name, target in
                (("this", (sid, P9_HOST, _ad289.BLUEMAP, port)), ("other add-on", (sid, P9_HOST, _ad289.IW4MADMIN, port)),
                 ("other server", (sid + 1000, P9_HOST, _ad289.BLUEMAP, port)))}

    def alive(toks):
        return {name: _aw289.lookup(t, 1800.0, 28800.0) is not None for name, t in toks.items()}
    out = {}
    _p9_arm(who="part289")
    _p9_patch(_ra289, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch(_ra289, "_await_start", lambda *a, **k: None)
    _p9_patch(_rc289, "_worker", lambda *a, **k: None)
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: ("removed=1\nothers=1\nADDON_REMOVED\n", "", 0))
    _p9_patch_sm("run_privileged", lambda *a, **k: ("", "", 0))
    c = _p9_client(P9_ADMIN)
    try:
        for action in ("stop", "update", "remove"):
            toks = links()
            r = c.post("/api/server/%d/addons/%s/%s" % (sid, _ad289.BLUEMAP, action))
            with _ra289._JOBS_LOCK:
                _ra289._JOBS.pop((sid, _ad289.BLUEMAP), None)
            out[action] = (r.status_code, alive(toks))
    finally:
        _p9_restore_all()
        _aw289._LINKS.clear()
        _p9_delete_server(sid)
    return out


_ra289r = _revoke_actions289()
eq("Stop, Update and Remove end the links to that add-on's page on that server (its port is free until it runs "
   "again); another add-on's and another server's links are kept",
   _ra289r, {"stop": (200, {"this": False, "other add-on": True, "other server": True}),
             "update": (202, {"this": False, "other add-on": True, "other server": True}),
             "remove": (200, {"this": False, "other add-on": True, "other server": True})})
