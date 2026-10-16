"""How a handler answers.

JSON for an in-page fetch, flash + redirect for a browser form, and the two error shapes that keep
exception text out of a response.

WHY THIS IS ITS OWN MODULE — the same reason as panel/core/validation.py, which says it at length.
These six were defined in app.py and imported back out of it by most of panel/routes/ (_json_body
by fourteen modules, _log_and_generic by thirteen), which is the heaviest part of a cycle that is
not a cycle at runtime but is one to every static analyser that reads the tree. Moved VERBATIM.

They depend on Flask's request/response machinery and nothing else — no models, no panel state, no
app factory — so there is nothing here for app.py to own.
"""
import sys

from flask import abort, current_app, flash, jsonify, make_response, redirect, request, url_for
from flask_wtf.csrf import CSRFError
from markupsafe import escape

from panel.core import i18n


def _json_body():
    """Return the request JSON coerced to a dict.

    {} for a missing, non-object (array/scalar), or malformed body. Guards every endpoint's
    `.get(...)` from crashing on a hostile/buggy request body.
    """
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}


def _json_str(body, key, default=""):
    """A request field as a stripped string, whatever JSON type actually arrived.

    _json_body guarantees the BODY is a dict; it says nothing about the VALUES. Two dozen handlers
    read a field as `(body.get(k) or "").strip()`, which is safe against a missing key and not
    against `{"command": 5}` — int has no .strip(), so the handler raised AttributeError and the
    caller got a 500 where 400 is the honest answer. (`{"name": []}` is the same shape;
    `{"raw": 5}` died deeper, inside the write path.) A list or dict coerces to "" rather than to
    its repr, because "[1, 2]" is not a value anybody meant to send.
    """
    v = body.get(key, default)
    if v is None or isinstance(v, (dict, list)):
        return ""
    return str(v).strip()


def _r12c_json_flag(body, key, default):
    """Read a request field that must be a JSON boolean.

    The bool, `default` when the key is absent, and None for anything else (the caller refuses it
    with a 400).

    A flag read by truthiness takes the STRING "false" as yes: `{"enable_ssh": "false"}` ran
    `tailscale up --ssh`, opening a root-capable login path the caller asked not to open, and
    `{"reboot": "no"}` rebooted a bootstrapped host. tailscale.py's Funnel had the same defect and
    reads `is True`; a guess either way is wrong for one of the two meanings, so neither is guessed.
    """
    v = body.get(key, default)
    return v if isinstance(v, bool) else None


def _r13b_json_flag(body, key, default):
    """_r12c_json_flag, ending the request with a 400 when the field is not a JSON boolean.

    abort() rather than a None for the route to test: the refusal is the same at every switch,
    and a branch per route pushed the route registrars over the complexity limit.
    """
    v = _r12c_json_flag(body, key, default)
    if v is None:
        abort(make_response(jsonify({"success": False,
                                     "message": i18n.tr("{key} must be true or false.", key=key)}), 400))
    return v


def _wants_json():
    """True when the caller is an in-page fetch().

    That lets form-POST endpoints answer with JSON and let the page update in place instead of
    doing a full redirect+reload. The global fetch wrapper in base.html sets X-Requested-With; a
    real browser form navigation does not.
    """
    return (request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or "application/json" in (request.headers.get("Accept") or ""))


def _form_ok(message, endpoint, **values):
    """Success result for an action form.

    JSON for an in-page fetch (so the page updates in place), else the classic flash + redirect for
    a plain browser submit.
    """
    if _wants_json():
        return jsonify({"success": True, "message": message})
    flash(message, "success")
    return redirect(url_for(endpoint, **values))


def _form_credential(message, endpoint, username, password, kind="password", **values):
    """Success for an action that MINTED a credential.

    The plaintext rides back in the JSON so the page can show it once, and is never put anywhere it
    would persist. `kind` is what it is — "password" or "invite" (a link, shown once the same way) —
    so the page words it to fit: an invite was shown as a "One-time password", to be "reset" if lost.

    Not a flash and not the session — a flash is stored in the signed session cookie, so a generated
    password would sit in the browser's cookie jar (and any proxy log that captured the Set-Cookie)
    long after it was displayed. A non-fetch submit therefore gets the password in the redirect's
    flash ONLY as a last resort, because there is nowhere else to put it and a password the admin
    never sees is a locked-out user; every page in this panel submits these forms through fetch.
    """
    if _wants_json():
        return jsonify({"success": True, "message": message,
                        "credential": {"username": username, "password": password, "kind": kind}})
    if kind == "invite":
        flash(i18n.tr("{message} {password} — copy it now, it is not shown again.",
                      message=message, password=password), "success")
    else:
        flash(i18n.tr("{message} Temporary password for {username}: {password} — copy it now, it is "
                      "not shown again.", message=message, username=username, password=password),
              "success")
    return redirect(url_for(endpoint, **values))


def _form_err(message, endpoint, code=400, category="danger", **values):
    """Failure result for an action form: JSON (+ status) for a fetch, else flash + redirect."""
    if _wants_json():
        return jsonify({"success": False, "message": message}), code
    flash(message, category)
    return redirect(url_for(endpoint, **values))


def _log_and_generic(context):
    """Record the real exception in the server log and return a generic string.

    That way raw exception text is never sent to the client (CodeQL py/stack-trace-exposure).
    Admins read the detail in the panel logs.

    A ConnectionError is not a fault in the panel (see _unreachable), and it is the one exception
    whose sentence the viewer can act on. Routes call this from a catch-all that also catches it, so
    a host that was switched off answered "Internal server error" with a traceback, a changed host
    key lost "use Re-trust host key", and an SSH-port move cut off part-way lost "it may have run".
    Each caller keeps its own shape, status and audit row; the sentence is _unreachable's.
    """
    exc = sys.exc_info()[1]
    if isinstance(exc, ConnectionError):
        # CR and LF replaced, not left to %r (CodeQL's log-injection rule does not accept that).
        current_app.logger.warning("%s: %s: %s", context, type(exc).__name__,
                                   str(exc).replace("\r", " ").replace("\n", " "))
        return _r20a_unreachable_said(exc)[0]
    current_app.logger.exception(context)
    # In the viewer's language: the string is fixed, so a catalog entry is all it needs, but it
    # reaches the page as a helper's return value, which no literal scan of a sink can see.
    return i18n.tr("Internal server error")


def _r22b_unreachable_or_generic(context, status=500):
    """A route catch-all's answer: _unreachable's for a ConnectionError, else the generic one.

    For `except Exception:` around a host call. A host that is down, or presents a changed key, is
    not a fault in the panel and gets the 200 with `unreachable` and a `code` the pages read; any
    other raise is still `status` with "Internal server error" and the traceback logged.
    """
    exc = sys.exc_info()[1]
    if isinstance(exc, ConnectionError):
        return _unreachable(context, exc=exc)
    return jsonify({"success": False, "message": _log_and_generic(context)}), status


# What the viewer is told for the two ConnectionErrors that are NOT "the host did not answer".
# Both were answered "Host unreachable", and their cause was logged nowhere: a changed host key
# (HostKeyMismatch, matched by name: panel.core does not import the ops layer, and
# monitoring._probe_exc_token reads it the same way) is the panel REFUSING to connect, and the
# operator has a button for it; a command the connection dropped under may already have run, which
# "unreachable" says it did not.
_R20A_HOSTKEY = ("The panel refused to connect: this host's SSH key is not the one it trusts. If "
                 "you reinstalled the host, use Re-trust host key on its page.")
# "Stopped answering", not "the connection was lost": the same marked ConnectionError comes from a
# drain that gave up on a host still connected but silent past _DRAIN_IDLE_FLOOR.
_R20A_STARTED = ("The host stopped answering while the command was running, so it may have run. "
                 "Check the host before trying again.")


def _r20a_unreachable_said(exc):
    """Return (what the viewer is told, a stable `code` naming the case) for ConnectionError `exc`.

    `unreachable` itself stays true for all three (see _unreachable): the code, not the flag, is
    what tells them apart.
    """
    if type(exc).__name__ == "HostKeyMismatch":
        return i18n.tr(_R20A_HOSTKEY), "host_key_mismatch"
    if getattr(exc, "command_started", False):
        return i18n.tr(_R20A_STARTED), "command_started"
    return i18n.tr("Host unreachable"), "host_unreachable"


def _unreachable(context, status=200, exc=None):
    """Answer 200 (or `status`) with an error field when a remote host cannot be reached.

    A remote host that cannot be reached is a NORMAL condition for this panel, not a fault
    in it — hosts go down, networks blip, a VPS reboots. The 200 lets the UI say "host
    unreachable" instead of the browser logging a 500, and keeps 5xx alerting a signal that the
    PANEL is broken.

    ssh_manager raises ConnectionError for exactly this (auth failed / timed out / cannot
    resolve), which is what makes it separable from a genuine bug. Anything that is not a
    ConnectionError still returns 500, deliberately: those are ours.

    api_remote_live_stats already did this and said why in a comment; six sibling endpoints
    did not, and every one of them 500s on a host that is simply switched off.

    `exc` is the ConnectionError; by default the one being handled (every caller calls this from
    its `except ConnectionError:`). Its class and text are logged — the panel's own fixed
    sentences, naming the host the log already names — where only "host unreachable" was, so a
    changed host key, a failed login or a command cut off part-way was recorded nowhere.
    """
    if exc is None:
        exc = sys.exc_info()[1]
    if exc is None:
        current_app.logger.warning("%s: host unreachable", context)
        said, code = i18n.tr("Host unreachable"), "host_unreachable"
    else:
        current_app.logger.warning("%s: %s: %r", context, type(exc).__name__, str(exc))
        said, code = _r20a_unreachable_said(exc)
    # In the viewer's language, and as `message` too: pages write a route's `message` (close port
    # 22's dialog read it and showed nothing at all), and they write it after a mark, which the
    # page's translator only learned to look past later.
    # `unreachable` is true for EVERY ConnectionError, a changed host key and a cut-off read
    # included: what the pages key on it is "no reading was taken", which holds for all three.
    # It was false for those two, and the remote Firewall page's refresh — which reads only that
    # flag — painted "Inactive", "No open ports yet." and "No IPs are blocked." about a host the
    # panel had refused to connect to. `code` is how a page tells the three apart (a page must not
    # match the sentence: it is in the viewer's language) and shows `message` instead of its own
    # "did not answer".
    return jsonify({"success": False, "unreachable": True, "code": code,
                    "message": said, "error": said}), status


def unreachable_error(context, exc=None):
    """The app error handler's answer to a ConnectionError no route caught: _unreachable's.

    200, as every route that catches one answers. It was a 502, and Cloudflare (Tunnel, the
    deployment docs/https.md recommends) swaps an origin 502 for its own HTML page, so the JSON
    `message` never reached the page — the unparseable body this handler exists to prevent — and
    the page read "the panel is down" when only a remote host was.
    """
    return _unreachable(context, exc=exc)


# What a 4xx/5xx the panel did not word itself tells the viewer. Werkzeug's own text is English
# ("The CSRF token has expired.", "The requested URL was not found on the server. If you entered
# the URL manually…"), and both the JSON reply (which pages print after "❌ ", where the page
# translator does not look) and the plain page reached every es/fr viewer that way. The log keeps
# nothing of it either way, so only what is shown changes.
_R19A_HTTP_SENTENCES = {
    400: i18n.Sentence("The request was not valid — reload the page and try again."),
    403: i18n.Sentence("You don't have permission to do that."),
    404: i18n.Sentence("That page or item was not found — it may have been removed. Reload the page."),
    405: i18n.Sentence("That action can't be done this way — reload the page and try again."),
    413: i18n.Sentence("That upload is too large."),
}
_R19A_CSRF_SENTENCE = i18n.Sentence("This page's security token has expired — reload the page and try again.")


def http_error_sentence(e):
    """The panel's own sentence for HTTPException `e`, untranslated (the caller tr()s it)."""
    if isinstance(e, CSRFError):
        return _R19A_CSRF_SENTENCE
    return _R19A_HTTP_SENTENCES.get(e.code) or i18n.Sentence(
        "The request could not be completed (HTTP {code}).", code=e.code or 500)


def http_error_page(e):
    """A plain page's answer to HTTPException `e`, in the viewer's language.

    Werkzeug's own response — its status and headers (a 405's Allow) — with the body replaced. A
    routing redirect (308) and any other non-error status is returned untouched, as before.
    """
    if not e.code or e.code < 400:
        return e
    resp = e.get_response()
    said = escape(i18n.tr(http_error_sentence(e)))
    resp.set_data('<!doctype html>\n<html lang="%s">\n<title>%d</title>\n<h1>%d</h1>\n<p>%s</p>\n'
                  % (i18n.request_lang(), e.code, e.code, said))
    resp.content_type = "text/html; charset=utf-8"
    return resp
