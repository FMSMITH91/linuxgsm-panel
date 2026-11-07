"""The page shell around every screen: install as an app, colour scheme, and "What's new".

Registered from auth_routes.register() — app.py is at its size limit, and these are account-level
concerns like the language switcher that lives there.
"""
import json
import logging

from flask import has_request_context, jsonify, request, url_for
from flask_login import current_user, login_required

from panel.core import i18n, whats_new
from panel.core.config import load_config
from panel.db.models import UI_THEMES, db

_log = logging.getLogger("panel.app_shell")

# Hard-coded rather than read from panel.css: the manifest is fetched without a session, before
# any stylesheet, and is cached by the phone. These are the dark scheme's page and bar colours.
_CMPB_BG = "#0a0f1a"
_CMPB_BAR = "#111827"


def _cmpb_shell_context():
    """Template values every page reads: the colour scheme and the unseen changelog entries."""
    theme, items, more = "system", [], 0
    try:
        if has_request_context() and getattr(current_user, "is_authenticated", False):
            theme = current_user.ui_theme
            if not getattr(current_user, "must_change_password", False):
                new = whats_new.unseen(current_user.whats_new_seen, whats_new.current_entries())
                items, more = new[:whats_new.SHOW_MAX], max(0, len(new) - whats_new.SHOW_MAX)
    except Exception:
        # Cosmetic: a page must render without either rather than fail over them.
        _log.debug("app shell context failed; rendering the defaults", exc_info=True)
    # The count beside "More changes", made here so the template prints a name, not arithmetic
    # (CodeQL reads a Jinja expression as JavaScript).
    folded = len(items) - 5 + more
    return {"ui_theme": theme, "whats_new": items, "whats_new_more": more,
            "whats_new_folded": "(%d)" % folded if folded > 0 else ""}


def _cmpb_manifest():
    """The web app manifest's fields, with every URL under the prefix this request is served at."""
    try:
        name = str(load_config().get("site_title") or "").strip()[:60]
    except Exception:
        name = ""
    name = name or "LinuxGSM Panel"
    start = url_for("index")

    def _icon(file, size, purpose):
        return {"src": url_for("static", filename="icons/" + file), "sizes": size,
                "type": "image/png", "purpose": purpose}
    return {
        "name": name,
        "short_name": name if len(name) <= 12 else "LinuxGSM",
        "id": start,
        "start_url": start,
        "scope": start,
        "display": "standalone",
        "background_color": _CMPB_BG,
        "theme_color": _CMPB_BAR,
        "icons": [_icon("icon-192.png", "192x192", "any"),
                  _icon("icon-512.png", "512x512", "any"),
                  _icon("icon-maskable-512.png", "512x512", "maskable")],
    }


def register(app):
    app.context_processor(_cmpb_shell_context)

    @app.route("/manifest.webmanifest")
    def web_manifest():
        """The web app manifest, so a phone can install the panel to its home screen.

        Public: a browser fetches it without the session cookie. It carries the site title (which
        the login page's <title> already shows) and icon URLs, nothing else.
        """
        resp = app.response_class(json.dumps(_cmpb_manifest()),
                                  mimetype="application/manifest+json")
        return resp

    @app.route("/account/theme", methods=["POST"])
    @login_required
    def account_set_theme():
        """Save this account's colour scheme: system, dark or light."""
        body = request.get_json(silent=True) or {}
        theme = request.form.get("theme") or (body.get("theme") if isinstance(body, dict) else None)
        if theme not in UI_THEMES:
            return jsonify({"success": False,
                            "message": i18n.tr("Choose System, Dark or Light.")}), 400
        current_user.theme = theme
        db.session.commit()
        return jsonify({"success": True, "theme": theme})

    @app.route("/api/account/whats-new/seen", methods=["POST"])
    @login_required
    def account_whats_new_seen():
        """Record that this account has read every changelog entry there is now."""
        stamp = whats_new.stamp(whats_new.current_entries())
        if stamp:
            current_user.whats_new_seen = stamp
            db.session.commit()
        return jsonify({"success": True})
