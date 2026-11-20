"""HTTP/1.1 to an add-on's page over one tunnel stream (ssh_manager.tunnel), and a WebSocket's splice.

One request per stream, `Connection: close`: nothing is pooled, so a stream never outlives its answer.
The answer's head is read up to addon_web.MAX_HEAD; its body as Content-Length, chunked or up to the
end of the stream, at most addon_web.MAX_RESPONSE_BODY, each read giving up after the stream's own
timeout (OWASP Denial of Service Cheat Sheet: bounded sizes and timeouts on what the panel waits for).
"""
import threading
import time

from panel.services import addon_web as _aw

CHUNK = 64 * 1024


class UpstreamError(ConnectionError):
    """The add-on's page answered nothing usable (for the log; the browser sees a plain 502)."""


class Head:
    """An answer's status line and headers, and the bytes read past them."""

    def __init__(self, status, reason, headers, rest):
        """Keep the answer's status, reason phrase, headers and the bytes read past them."""
        self.status, self.reason, self.headers, self.rest = status, reason, headers, rest

    def get(self, name, default=""):
        """The first header called `name` (any case), or `default`."""
        low = name.lower()
        return next((v for k, v in self.headers if k.lower() == low), default)


def send_request(stream, method, target, headers, body=b""):
    """Write one request (its Content-Length when it has a body) to `stream`."""
    lines = ["%s %s HTTP/1.1" % (method, target)] + ["%s: %s" % kv for kv in headers]
    if body or method == "POST":
        lines.append("Content-Length: %d" % len(body))
    stream.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)


def read_head(stream):
    """The answer's Head; UpstreamError when the stream ends first or the head is too long or malformed."""
    head, rest = _head_bytes(stream)
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/1.") or not parts[1].isdecimal() or len(parts[1]) != 3:
        raise UpstreamError("not an HTTP answer")
    return Head(int(parts[1]), parts[2] if len(parts) > 2 else "", [_header_line(x) for x in lines[1:]], rest)


def _head_bytes(stream):
    """(the head up to its blank line, the bytes read past it)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > _aw.MAX_HEAD:
            raise UpstreamError("the answer's head is too long")
        piece = stream.recv(CHUNK)
        if not piece:
            raise UpstreamError("the add-on closed the connection without an answer" if not buf
                                else "the answer ended inside its head")
        buf += piece
    head, rest = buf.split(b"\r\n\r\n", 1)
    return head, rest


def _header_line(line):
    name, sep, value = line.partition(":")
    if not sep or not name or name != name.strip():
        raise UpstreamError("a malformed header line")
    return name, value.strip()


def _has_body(method, status):
    return method != "HEAD" and status >= 200 and status not in (204, 304)


def body(stream, head, method, cap=None):
    """Yield the response body, de-chunked; UpstreamError past `cap` bytes or on a broken chunk."""
    cap = _aw.MAX_RESPONSE_BODY if cap is None else cap
    if not _has_body(method, head.status):
        return
    if "chunked" in head.get("Transfer-Encoding").lower():
        yield from _chunked(stream, head.rest, cap)
        return
    length = head.get("Content-Length")
    if length:
        if not length.isdecimal() or int(length) > cap:
            raise UpstreamError("the answer is too large")
        yield from _counted(stream, head.rest, int(length))
        return
    yield from _to_end(stream, head.rest, cap)


def _counted(stream, rest, left):
    if rest:
        piece = rest[:left]
        left -= len(piece)
        yield piece
    while left > 0:
        piece = stream.recv(min(CHUNK, left))
        if not piece:
            raise UpstreamError("the answer ended early")
        left -= len(piece)
        yield piece


def _to_end(stream, rest, cap):
    total = len(rest)
    if rest:
        yield rest
    while True:
        piece = stream.recv(CHUNK)
        if not piece:
            return
        total += len(piece)
        if total > cap:
            raise UpstreamError("the answer is too large")
        yield piece


class _Reader:
    """Buffered reads of a stream, for chunked framing."""

    def __init__(self, stream, rest):
        self.stream, self.buf = stream, rest

    def line(self):
        while b"\r\n" not in self.buf:
            if len(self.buf) > 4096:
                raise UpstreamError("a chunk's size line is too long")
            self._more()
        out, self.buf = self.buf.split(b"\r\n", 1)
        return out

    def take(self, n):
        while len(self.buf) < n:
            self._more()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _more(self):
        piece = self.stream.recv(CHUNK)
        if not piece:
            raise UpstreamError("the answer ended inside a chunk")
        self.buf += piece


def _chunked(stream, rest, cap):
    r, total = _Reader(stream, rest), 0
    while True:
        size = r.line().split(b";", 1)[0].strip()
        try:
            n = int(size, 16)
        except ValueError:
            raise UpstreamError("a malformed chunk size") from None
        if n == 0:
            while r.line():          # the trailer, up to its empty line
                pass
            return
        total += n
        if total > cap:
            raise UpstreamError("the answer is too large")
        while n:
            piece = r.take(min(n, CHUNK))
            n -= len(piece)
            yield piece
        r.take(2)


def exchange(stream, method, target, headers, req_body=b""):
    """Send one request and read its answer's head: (Head) for body() to finish."""
    send_request(stream, method, target, headers, req_body)
    return read_head(stream)


# ── a WebSocket, once both sides have switched ─────────────────────────────────────────────────────
def splice(client, upstream, first=b"", still_allowed=None, recheck=None):
    """Copy bytes both ways between the browser's socket and the add-on's stream until either ends.

    `first`: bytes the add-on sent after its 101, for the browser. `still_allowed()` is asked every
    `recheck` seconds (addon_web.RECHECK_SECONDS): when it says no, both ends are closed. Frames are
    not read: the bytes go as they come (the WebSocket's own framing and masking are the two ends').
    """
    recheck = _aw.RECHECK_SECONDS if recheck is None else recheck
    done = threading.Event()
    if first:
        client.sendall(first)
    up = threading.Thread(target=_pump, args=(upstream.recv, client.sendall, done), daemon=True)
    up.start()
    down = threading.Thread(target=_pump, args=(client.recv, upstream.sendall, done), daemon=True)
    down.start()
    last = time.monotonic()
    while not done.wait(1.0):
        if still_allowed is not None and time.monotonic() - last >= recheck:
            last = time.monotonic()
            if not still_allowed():
                break
    done.set()
    _close(upstream)
    _close(client)
    up.join(5)
    down.join(5)


def _pump(src_recv, dst_send, done):
    """Copy from one end to the other until either ends or `done` is set; then set `done`."""
    try:
        while not done.is_set():
            try:
                data = src_recv(CHUNK)
            except TimeoutError:
                continue
            if not data:
                break
            dst_send(data)
    except OSError:
        pass                      # either side dropping the connection ends the splice
    finally:
        done.set()


def _close(conn):
    try:
        conn.close()
    except Exception:  # nosec B110 - an end the other side already closed
        pass  # closing an already-closed end is the normal way a splice ends
