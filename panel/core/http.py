"""How a handler answers: JSON for an in-page fetch, flash + redirect for a browser form,
and the two error shapes that keep exception text out of a response.

WHY THIS IS ITS OWN MODULE — the same reason as panel/core/validation.py, which says it at length.
These six were defined in app.py and imported back out of it by most of panel/routes/ (_json_body
by fourteen modules, _log_and_generic by thirteen), which is the heaviest part of a cycle that is
not a cycle at runtime but is one to every static analyser that reads the tree. Moved VERBATIM.

They depend on Flask's request/response machinery and nothing else — no models, no panel state, no
app factory — so there is nothing here for app.py to own.
"""
from flask import current_app, flash, jsonify, redirect, request, url_for


def _json_body():
    """Request JSON coerced to a dict — {} for a missing, non-object (array/scalar), or malformed
    body. Guards every endpoint's `.get(...)` from crashing on a hostile/buggy request body."""
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}


def _json_str(body, key, default=""):
    """A request field as a stripped string, whatever JSON type actually arrived.

    _json_body guarantees the BODY is a dict; it says nothing about the VALUES. Two dozen handlers
    read a field as `(body.get(k) or "").strip()`, which is safe against a missing key and not
    against `{"command": 5}` — int has no .strip(), so the handler raised AttributeError and the
    caller got a 500 where 400 is the honest answer. (`{"name": []}` is the same shape;
    `{"raw": 5}` died deeper, inside the write path.) A list or dict coerces to "" rather than to
    its repr, because "[1, 2]" is not a value anybody meant to send."""
    v = body.get(key, default)
    if v is None or isinstance(v, (dict, list)):
        return ""
    return str(v).strip()


def _wants_json():
    """True when the caller is an in-page fetch() (so form-POST endpoints can answer with JSON and
    let the page update in place instead of doing a full redirect+reload). The global fetch wrapper
    in base.html sets X-Requested-With; a real browser form navigation does not."""
    return (request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or "application/json" in (request.headers.get("Accept") or ""))


def _form_ok(message, endpoint, **values):
    """Success result for an action form: JSON for an in-page fetch (so the page updates in place),
    else the classic flash + redirect for a plain browser submit."""
    if _wants_json():
        return jsonify({"success": True, "message": message})
    flash(message, "success")
    return redirect(url_for(endpoint, **values))


def _form_credential(message, endpoint, username, password, **values):
    """Success for an action that MINTED a credential: the plaintext rides back in the JSON so the
    page can show it once, and is never put anywhere it would persist.

    Not a flash and not the session — a flash is stored in the signed session cookie, so a generated
    password would sit in the browser's cookie jar (and any proxy log that captured the Set-Cookie)
    long after it was displayed. A non-fetch submit therefore gets the password in the redirect's
    flash ONLY as a last resort, because there is nowhere else to put it and a password the admin
    never sees is a locked-out user; every page in this panel submits these forms through fetch.
    """
    if _wants_json():
        return jsonify({"success": True, "message": message,
                        "credential": {"username": username, "password": password}})
    flash("%s Temporary password for %s: %s — copy it now, it is not shown again."
          % (message, username, password), "success")
    return redirect(url_for(endpoint, **values))


def _form_err(message, endpoint, code=400, category="danger", **values):
    """Failure result for an action form: JSON (+ status) for a fetch, else flash + redirect."""
    if _wants_json():
        return jsonify({"success": False, "message": message}), code
    flash(message, category)
    return redirect(url_for(endpoint, **values))


def _log_and_generic(context):
    """Record the real exception in the server log and return a generic string,
    so raw exception text is never sent to the client (CodeQL
    py/stack-trace-exposure). Admins read the detail in the panel logs."""
    current_app.logger.exception(context)
    return "Internal server error"


def _unreachable(context):
    """A remote host that cannot be reached is a NORMAL condition for this panel, not a fault
    in it — hosts go down, networks blip, a VPS reboots. Answer 200 with an error field so the
    UI can say "host unreachable" instead of the browser logging a 500, and so 5xx alerting
    stays a signal that the PANEL is broken.

    ssh_manager raises ConnectionError for exactly this (auth failed / timed out / cannot
    resolve), which is what makes it separable from a genuine bug. Anything that is not a
    ConnectionError still returns 500, deliberately: those are ours.

    api_remote_live_stats already did this and said why in a comment; six sibling endpoints
    did not, and every one of them 500s on a host that is simply switched off."""
    current_app.logger.warning("%s: host unreachable", context)
    return jsonify({"success": False, "unreachable": True,
                    "error": "Host unreachable"}), 200
