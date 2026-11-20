"""An add-on's web page through the panel: the card's Open (a link), and the proxy that serves the link.

OPEN (`POST /api/server/<id>/addons/<addon>/web`, the card's form, CSRF-checked like every post): signed
in, the server's access, and View add-on pages or Manage add-ons (Authorization Cheat Sheet, "Deny by
Default"). One read of the host as the server's account (asked first whether that account is a plain
game account) finds the add-on running and the port its record names, in the server's own window of
add-on ports, listened on by that account itself. Then a link is made (services/addon_web.py), the
opening is audited (Logging Cheat Sheet: who, which server, which add-on; never the link), and the new
tab is sent on to it (303).

THE PROXY (/addon-web/<token>/...) is WSGI middleware in front of the app, not a Flask view: the link's
page has an opaque origin and sends no panel cookie, so the panel's session, CSRF and Fetch Metadata
steps have nothing to check, and none of them can add a panel cookie to the add-on's answers. Every
request is authorized again from the link: its sign-in still live, the permission and the server still
held (Authorization Cheat Sheet, "Validate the Permissions on Every Request"). It connects only to
127.0.0.1:<the port read at Open> on that server's host (Server-Side Request Forgery Prevention Cheat
Sheet: no destination from the request), through ssh_manager.tunnel. A refused link is audited once.
"""
import logging
import time
from html import escape
from http import HTTPStatus

from flask import redirect, render_template, request
from flask_login import current_user, login_required

from panel.core import i18n
from panel.db.models import GameServer, db, session_absolute_limits, session_idle_limits
from panel.ops import ssh_manager as _sm
from panel.routes._shared import game_account_write_refusal
from panel.security.auth import (MANAGE_ADDONS, VIEW_ADDON_PAGES, can_access_server, get_game, has_permission,
                                 live_session_user, log_action, server_access_required)
from panel.services import addon_web as _aw, addon_web_http as _http, addons as _ad

_log = logging.getLogger("panel.addon_web")

_NO_PAGE = "This add-on has no web page."
_STOPPED = "The add-on isn't running. Start it on its card, then open its page."
_NOT_LISTENING = ("The add-on's page isn't listening where its record says. Stop and start the add-on on its card, "
                  "then open its page.")
_UNREAD = "Couldn't read the add-on on its host: the host did not answer. Try again."
_ENDED = "This page's link has ended. Open the add-on's page again from its server's Add-ons tab."
_REVOKED = ("You can no longer open this page: your sign-in has ended, or your access to the server or its add-on "
            "pages was removed.")
_NO_ANSWER = "The add-on's page didn't answer. Check that the add-on is running, then open its page again."
_BUSY = "The add-on's page is busy. Try again in a moment."
_REFUSED = "That request can't be passed on to the add-on's page."
_DENIED = "Permission denied"


def may_view(user):
    """Whether `user` may open add-on pages (View add-on pages, or Manage add-ons, which includes it)."""
    return has_permission(user, VIEW_ADDON_PAGES) or has_permission(user, MANAGE_ADDONS)


def _page(status, sentence):
    """A plain page saying `sentence`, in the viewer's language (the new tab's answer when Open is refused)."""
    # A template, so Jinja's autoescape writes both values (the sentence is the panel's own; the language
    # is one of the supported codes).
    body = render_template("addon_web_refused.html", lang=i18n.request_lang(), said=i18n.tr(sentence))
    return body, status, {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}


def _refuse(gs, addon_id, status, sentence, why):
    log_action(current_user, "addon_web_refused", target=gs.name, server=gs, success=False,
               detail="%s: %s" % (addon_id, why))
    return _page(status, sentence)


def _open(server_id, addon_id):
    gs = get_game(server_id)
    # The id the shell sees is the catalog's own constant, looked up by the URL's text, never the text itself.
    addon_id = next((k for k in _aw.WEB if k == addon_id), None)
    if addon_id is None or addon_id not in _ad.offered(gs.game_type):
        return _page(404, _NO_PAGE)
    why = game_account_write_refusal(gs.remote, gs.short_name, reading=True)
    if why:
        return _refuse(gs, addon_id, 409, why, why)
    try:
        out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _aw.open_sh(addon_id), timeout=30)
    except ConnectionError:
        rc, out = -1, ""
    if rc != 0:
        return _refuse(gs, addon_id, 502, _UNREAD, "the host did not answer")
    port, why = _aw.page_port(out, gs.id)
    if port is None:
        return _refuse(gs, addon_id, 409, _STOPPED if why == "stopped" else _NOT_LISTENING,
                       "not running" if why == "stopped" else "no page on its recorded port")
    token = _aw.mint(current_user.get_id(), current_user.id, (gs.id, gs.remote_id, addon_id, port),
                     i18n.request_lang(), session_idle_limits()[0], session_absolute_limits()[0])
    log_action(current_user, "addon_web_opened", target=gs.name, server=gs,
               detail="%s page opened through the panel" % _ad.CATALOG[addon_id]["name"])
    return redirect(request.script_root + _aw.PATH_ROOT + token + "/", code=303)


def register(app):
    """Register the card's Open route and put the proxy in front of the app."""

    @app.route("/api/server/<int:server_id>/addons/<addon_id>/web", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_addon_web(server_id, addon_id):
        """Open an add-on's web page: a link for this sign-in, server and add-on, then the page (303)."""
        if not (has_permission(current_user, VIEW_ADDON_PAGES) or has_permission(current_user, MANAGE_ADDONS)):
            return _page(403, _DENIED)
        return _open(server_id, addon_id)

    app.wsgi_app = AddonWebProxy(app.wsgi_app, app)


# ── the proxy ─────────────────────────────────────────────────────────────────────────────────────────
def _plain(start_response, status, sentence, lang="en"):
    said = escape(i18n.translate(lang, sentence)).encode("utf-8")
    body = b'<!doctype html>\n<meta charset="utf-8">\n<title>' + said + b"</title>\n<p>" + said + b"</p>\n"
    start_response("%d %s" % (status, HTTPStatus(status).phrase),
                   [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(body)))]
                   + _aw.page_headers("text/html"))
    return [body]


class _Refusal(Exception):
    """A request the proxy answers itself (status, sentence)."""

    def __init__(self, status, sentence):
        super().__init__(sentence)
        self.status, self.sentence = status, sentence


class AddonWebProxy:
    """WSGI middleware: /addon-web/<token>/... goes to the link's add-on page; anything else to the app."""

    def __init__(self, wsgi_app, app):
        """Wrap `wsgi_app` (the app's own); `app` gives the database and the settings for each request."""
        self.wsgi_app, self.app = wsgi_app, app

    def __call__(self, environ, start_response):
        """Serve a link's request, or pass the request on."""
        path = environ.get("PATH_INFO", "")
        if not path.startswith(_aw.PATH_ROOT):
            return self.wsgi_app(environ, start_response)
        token, _slash, rest = path[len(_aw.PATH_ROOT):].partition("/")
        if not _slash and _aw.TOKEN_RE.fullmatch(token):
            start_response("308 Permanent Redirect", [("Location", environ.get("SCRIPT_NAME", "") + path + "/"),
                                                      ("Content-Length", "0")] + _aw.page_headers(""))
            return [b""]
        lang = "en"
        try:
            with self.app.app_context():
                link, server = self._authorized(token)
                lang = link.lang
                asked = self._forward(environ, start_response, token, link, server, "/" + rest)
        except _Refusal as r:
            return _plain(start_response, r.status, r.sentence, lang)
        if callable(asked):
            return asked()      # the add-on switched to a WebSocket: spliced outside the app context
        return asked

    # ── who is asking ──────────────────────────────────────────────────────────────────────────────
    def _authorized(self, token):
        """(the link, its server's host row) when the link's sign-in may still use it; else _Refusal."""
        with self.app.app_context():
            link = _aw.lookup(token, session_idle_limits()[0], session_absolute_limits()[0])
            if link is None:
                raise _Refusal(404, _ENDED)
            gs = db.session.get(GameServer, link.server_id)
            why = self._why_not(link, gs)
            if why:
                self._log_refusal(token, link, gs, why)
                raise _Refusal(403, _REVOKED)
            return link, gs.remote

    @staticmethod
    def _why_not(link, gs):
        user = live_session_user(link.user_key)
        if user is None:
            return "the sign-in has ended"
        if not may_view(user):
            return "no permission to open add-on pages"
        if gs is None or gs.remote_id != link.remote_id or not can_access_server(user, gs.id):
            return "no access to the server"
        return ""

    @staticmethod
    def _log_refusal(token, link, gs, why):
        if not link.refusal_logged:
            link.refusal_logged = True
            from panel.db.models import User
            user = db.session.get(User, link.user_id)
            log_action(user, "addon_web_refused", target=getattr(gs, "name", ""), server=gs, success=False,
                       detail="%s page link refused: %s" % (link.addon_id, why))
        _aw.revoke(token)

    def still_allowed(self, token):
        """Whether `token`'s link may still be used (asked during a WebSocket, without noting a use)."""
        with self.app.app_context():
            link = _aw.lookup(token, session_idle_limits()[0], session_absolute_limits()[0])
            return link is not None and not self._why_not(link, db.session.get(GameServer, link.server_id))

    # ── what is passed on ──────────────────────────────────────────────────────────────────────────
    def _forward(self, environ, start_response, token, link, server, raw_rest):
        method, target, websocket = _checked(environ, link, raw_rest)
        if method == "OPTIONS":
            return _preflight(environ, start_response)
        req_body = _request_body(environ)
        prefix = environ.get("SCRIPT_NAME", "") + _aw.PATH_ROOT + token
        gate = _aw.gate(link.remote_id, link.port, link.addon_id)
        if not gate.acquire(timeout=_aw.QUEUE_SECONDS):
            raise _Refusal(503, _BUSY)
        try:
            stream, head = _ask(server, link, method, target,
                                _aw.upstream_headers(environ, link.port, link.jar, websocket), req_body)
        except (ConnectionError, OSError):
            gate.release()
            _log.info("add-on page: no answer from %s on server %s", link.addon_id, link.server_id)
            raise _Refusal(502, _NO_ANSWER) from None
        _aw.keep_cookies(link.jar, head.headers)
        if websocket and head.status == 101:
            gate.release()
            return lambda: self._switch(environ, stream, head, token)
        return _answer(start_response, stream, head, method, raw_rest, link, prefix, gate)

    def _switch(self, environ, stream, head, token):
        """Answer the browser's upgrade with the add-on's 101, then splice the two until either ends."""
        sock = _client_socket(environ)
        lines = ["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade"]
        lines += ["%s: %s" % (k, v) for k, v in head.headers if k.lower() in _aw.SWITCH_HEADERS]
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        _http.splice(sock, stream, head.rest, still_allowed=lambda: self.still_allowed(token))
        from eventlet import wsgi as _ewsgi     # only reached under eventlet's server (_client_socket)
        _ewsgi.WSGI_LOCAL.already_handled = True
        return []


def _checked(environ, link, raw_rest):
    """(method, target, websocket) of a request the proxy may pass on; else _Refusal."""
    method = environ.get("REQUEST_METHOD", "GET")
    target = _aw.upstream_target(_quoted(raw_rest), environ.get("QUERY_STRING", ""))
    if target is None or method not in ("GET", "HEAD", "POST", "OPTIONS"):
        raise _Refusal(400 if target is None else 405, _REFUSED)
    websocket = environ.get("HTTP_UPGRADE", "").lower() == "websocket"
    if websocket and not (method == "GET" and _aw.WEB[link.addon_id]["websocket"] and _client_socket(environ)):
        raise _Refusal(400, _REFUSED)
    return method, target, websocket


def _quoted(raw_rest):
    """The path after the token, percent-encoded again (WSGI hands it over decoded, as latin-1)."""
    from urllib.parse import quote
    return quote(raw_rest.encode("latin-1", "replace"), safe="/-._~!$&'()*+,;=:@")


def _client_socket(environ):
    """The browser's socket under eventlet's server (for a WebSocket), or None elsewhere."""
    inp = environ.get("eventlet.input")
    return inp.get_socket() if inp is not None and hasattr(inp, "get_socket") else None


def _request_body(environ):
    if environ.get("REQUEST_METHOD") != "POST":
        return b""
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        raise _Refusal(400, _REFUSED) from None
    if length < 0 or length > _aw.MAX_REQUEST_BODY:
        raise _Refusal(413, _REFUSED)
    data = environ["wsgi.input"].read(length) if length else b""
    if len(data) != length:
        raise _Refusal(400, _REFUSED)
    return data


def _ask(server, link, method, target, headers, req_body):
    """(stream, Head) of one exchange; a GET the add-on dropped unanswered is asked once more.

    IW4MAdmin's server closes a connection past its one-at-a-time limit at once, before any answer
    (Kestrel's connection limit); a moment later the slot is free.
    """
    for attempt in (0, 1):
        stream = _sm.open_loopback(server, link.port, timeout=_aw.CONNECT_SECONDS)
        try:
            stream.settimeout(_aw.READ_SECONDS)
            return stream, _http.exchange(stream, method, target, headers, req_body)
        except _http.UpstreamError:
            stream.close()
            if attempt or method not in ("GET", "HEAD"):
                raise
        except Exception:
            stream.close()
            raise
        time.sleep(0.3)
    raise _http.UpstreamError("no answer")


def _preflight(environ, start_response):
    """A CORS preflight from the page itself (its origin is opaque): the allowlisted headers, answered here."""
    asked = [h.strip().lower() for h in environ.get("HTTP_ACCESS_CONTROL_REQUEST_HEADERS", "").split(",") if h.strip()]
    allowed = ", ".join(h for h in asked if h in _aw.REQUEST_HEADERS)
    start_response("204 No Content", [("Access-Control-Allow-Methods", "GET, HEAD, POST"),
                                      ("Access-Control-Allow-Headers", allowed), ("Access-Control-Max-Age", "600"),
                                      ("Content-Length", "0")] + _aw.page_headers(""))
    return [b""]


def _answer(start_response, stream, head, method, raw_rest, link, prefix, gate):
    """Start the browser's answer from the add-on's head; the body follows (rewritten, or as it comes)."""
    if head.status == 101 or head.status < 200:
        stream.close()
        gate.release()
        raise _Refusal(502, _NO_ANSWER)
    ctype = head.get("Content-Type")
    kind = _aw.rewrites(ctype, raw_rest, link.addon_id)
    headers = _aw.kept_response_headers(head.headers, prefix, link.port) + _aw.page_headers(ctype)
    status = _status(head)
    if kind and method != "HEAD" and head.status not in (204, 304):
        return _rewritten(start_response, (stream, head, gate), method, kind, prefix, headers)
    length = head.get("Content-Length")
    if length.isdecimal() and "chunked" not in head.get("Transfer-Encoding").lower():
        headers.append(("Content-Length", length))
    start_response(status, headers)
    return _Streamed(_http.body(stream, head, method), stream, gate)


def _status(head):
    return "%d %s" % (head.status, head.reason or _phrase(head.status))


def _rewritten(start_response, exchange, method, kind, prefix, headers):
    """Read the whole (capped) body, rewrite it for `kind`, and answer it with its new length."""
    stream, head, gate = exchange
    try:
        raw = b"".join(_http.body(stream, head, method, cap=_aw.MAX_REWRITE))
    except (_http.UpstreamError, OSError):
        raise _Refusal(502, _NO_ANSWER) from None
    finally:
        stream.close()
        gate.release()
    plain = _aw.decoded(raw, head.get("Content-Encoding"))
    if plain is None:
        out = raw                                    # an encoding it can't read: passed on unchanged
    else:
        out = _aw.rewrite(kind, plain, prefix)
        headers = [(k, v) for k, v in headers if k.lower() != "content-encoding"]
    start_response(_status(head), headers + [("Content-Length", str(len(out)))])
    return [out]


class _Streamed:
    """The body as it comes, as a WSGI iterable.

    Its close(), which the server calls however the answer ended (even before its first piece), closes
    the stream and releases the gate, once.
    """

    def __init__(self, chunks, stream, gate):
        """Pass on `chunks` from `stream`; `gate` is the add-on's connection slot held for it."""
        self._chunks, self._stream, self._gate, self._open = chunks, stream, gate, True

    def __iter__(self):
        """Yield the body's pieces."""
        try:
            yield from self._chunks
        finally:
            self.close()

    def close(self):
        """Close the stream and release the gate (a second call does nothing)."""
        if self._open:
            self._open = False
            self._stream.close()
            self._gate.release()


def _phrase(status):
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return "Unknown"
