"""A minimal, synchronous Chrome DevTools Protocol client over one page target's WebSocket.

websocket-client is already a pinned, hash-locked dependency of the panel (requirements.txt), so
this adds nothing to install. One connection, one thread: a call sends its id and reads messages
until the reply with that id arrives, keeping every event it reads on the way for the caller.

A JavaScript dialog (alert/confirm/prompt) blocks the page until something answers it — including
the Runtime.evaluate that caused it, which would then never reply. So a dialog is answered as soon
as it is read, by whatever policy the caller set, and never reaches the caller as a hang.
"""
import json
import time

import websocket


class CDPError(RuntimeError):
    """A protocol call the browser refused, or did not answer in time."""


class CDP:
    """One DevTools WebSocket: calls in order, events kept, dialogs answered as they open."""

    def __init__(self, ws_url, timeout=30):
        """Connect to the target at `ws_url`; `timeout` is the socket's, for the handshake."""
        # suppress_origin: Chrome refuses a DevTools WebSocket whose Origin it does not allow
        # (--remote-allow-origins), and a client that sends none is not a web page.
        self.ws = websocket.create_connection(ws_url, timeout=timeout, suppress_origin=True,
                                              enable_multithread=False)
        self._id = 0
        self._ignore = set()
        self._callbacks = {}      # id -> called with the reply, from whichever read receives it
        self.events = []
        self.dialog_accept = False
        self.dialogs = []
        self.on_event = None      # called with every event as it is read

    def close(self):
        """Close the socket, quietly: the browser may have dropped it already."""
        try:
            self.ws.close()
        except Exception:   # nosec B110 - closing a socket the browser may already have dropped
            pass

    def _send(self, method, params):
        self._id += 1
        self.ws.send(json.dumps({"id": self._id, "method": method, "params": params or {}}))
        return self._id

    def _read(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.ws.settimeout(remaining)
        try:
            raw = self.ws.recv()
        except websocket.WebSocketTimeoutException:
            raise TimeoutError from None
        msg = json.loads(raw)
        if msg.get("id") in self._callbacks:
            self._callbacks.pop(msg["id"])(msg)
        if "method" in msg and self.on_event is not None:
            self.on_event(msg)
        if msg.get("method") == "Page.javascriptDialogOpening":
            # "Leave site?" is always answered Leave: refusing it would cancel the next navigation
            # the caller asked for, and every later page would silently be this one.
            kind = msg["params"].get("type", "")
            self.dialogs.append((kind, msg["params"].get("message", "")))
            self.send("Page.handleJavaScriptDialog", {
                "accept": kind == "beforeunload" or bool(self.dialog_accept)})
        return msg

    def send(self, method, params=None, on_reply=None):
        """Send `method` without waiting; `on_reply`, if given, is called with the reply.

        For work that has to happen from inside an event handler, where waiting for a reply would
        re-enter the read loop that is running the handler.
        """
        mid = self._send(method, params)
        self._ignore.add(mid)
        if on_reply is not None:
            self._callbacks[mid] = on_reply

    def call(self, method, params=None, timeout=30):
        """Send `method` and return its result, keeping the events read on the way.

        Raises CDPError when the browser answers with an error or not within `timeout` seconds.
        """
        mid = self._send(method, params)
        deadline = time.monotonic() + timeout
        while True:
            try:
                msg = self._read(deadline)
            except TimeoutError:
                raise CDPError("%s: no reply in %ss" % (method, timeout)) from None
            if msg.get("id") == mid:
                if "error" in msg:
                    raise CDPError("%s: %s" % (method, msg["error"].get("message", msg["error"])))
                return msg.get("result", {})
            if "id" in msg:
                self._ignore.discard(msg["id"])
                continue
            self.events.append(msg)

    def pump(self, seconds):
        """Read events for `seconds`, answering dialogs, and keep them in .events."""
        deadline = time.monotonic() + seconds
        while True:
            try:
                msg = self._read(deadline)
            except TimeoutError:
                return
            if "id" not in msg:
                self.events.append(msg)

    def evaluate(self, expression, timeout=30, await_promise=True):
        """Run `expression` in the page and return its JSON value; a thrown error raises."""
        res = self.call("Runtime.evaluate", {"expression": expression, "returnByValue": True,
                                             "awaitPromise": await_promise, "userGesture": True},
                        timeout=timeout)
        if res.get("exceptionDetails"):
            det = res["exceptionDetails"]
            raise CDPError("evaluate: %s" % ((det.get("exception") or {}).get("description")
                                             or det.get("text")))
        return (res.get("result") or {}).get("value")
