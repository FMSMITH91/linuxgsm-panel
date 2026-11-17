"""Settings > HTTPS certificate: put in the operator's own certificate, from a paste or Let's Encrypt.

Superadmin only, and each change asks a stale sign-in for the password again (step_up_required):
the certificate and key decide who the browser believes it is talking to. Each POST answers with a
redirect back to the card, the outcome and every note in flashes. The checking and the files are
panel/services/tls_own.py; the restart that loads a new pair is system_ops.restart_panel.
"""
from flask import flash, redirect, request, url_for
from flask_login import current_user, login_required

from panel.core.config import load_config, update_config
from panel.security.account_guard import step_up_required
from panel.security.auth import log_action, superadmin_required
from panel.services import tls_own

_BACK = "panel_settings"
_ANCHOR = "sec-tls"


def _back():
    return redirect(url_for(_BACK, _anchor=_ANCHOR))


def _restart_and_say(what):
    """Restart the panel to load the new pair, and say so (or what to do when it could not)."""
    from panel.ops import system_ops as so
    ok, _msg = so.restart_panel(delay_seconds=2)
    if ok:
        flash("%s The panel is restarting to load it; reload this page in a few seconds." % what, "success")
    else:
        flash("%s Restart the panel to load it (the restart could not be started here)." % what, "warning")


def _flash_notes(notes):
    for note in notes:
        flash(note, "warning")


def _install_checked(checked, source, le_name=""):
    """Put a checked pair in, audit it and restart; the refusal is flashed instead when there is one."""
    if checked.refusal:
        flash(checked.refusal, "danger")
        log_action(current_user, "tls_cert_refused", target="panel", detail=checked.refusal[:120], success=False)
        return _back()
    tls_own.install(checked, source, le_name)
    info = tls_own.summary(checked.chain)
    log_action(current_user, "tls_cert_install", target="panel",
               detail="%s: %s, issuer %s, until %s, sha256 %s" % (
                   source, info["subject"], info["issuer"], info["not_after"], info["fingerprint"][:16]))
    _flash_notes(checked.notes)
    _restart_and_say("Certificate for %s saved." % info["subject"])
    return _back()


def register(app):
    """The HTTPS certificate card's three changes: paste, Let's Encrypt, back to the built-in one."""
    @app.route("/settings/tls/paste", methods=["POST"])
    @login_required
    @superadmin_required
    @step_up_required       # the key and certificate the panel's HTTPS serves
    def tls_cert_paste():
        f = request.form
        names = tls_own.panel_names(load_config(), request.host)
        checked = tls_own.check((f.get("cert_pem") or "").encode("utf-8", "replace"),
                                (f.get("key_pem") or "").encode("utf-8", "replace"), names)
        return _install_checked(checked, "own")

    @app.route("/settings/tls/letsencrypt", methods=["POST"])
    @login_required
    @superadmin_required
    @step_up_required       # the key and certificate the panel's HTTPS serves
    def tls_cert_letsencrypt():
        name = (request.form.get("le_name") or "").strip().lower()
        autorenew = bool(request.form.get("le_autorenew"))
        update_config(lambda cfg: cfg.update({"tls_le_autorenew": autorenew}))
        chain, key, why = tls_own.fetch_letsencrypt(name)
        if why:
            flash(why, "danger")
            return _back()
        return _install_checked(tls_own.check(chain, key, tls_own.panel_names(load_config(), request.host)),
                                "letsencrypt", name)

    @app.route("/settings/tls/remove", methods=["POST"])
    @login_required
    @superadmin_required
    @step_up_required       # the key and certificate the panel's HTTPS serves
    def tls_cert_remove():
        if load_config().get("tls_cert_source") not in tls_own.certs.OPERATOR_SOURCES:
            flash("The panel is already using its built-in certificate.", "info")
            return _back()
        if not request.form.get("confirm"):
            flash("Tick the box to confirm going back to the built-in certificate.", "danger")
            return _back()
        tls_own.remove()
        log_action(current_user, "tls_cert_remove", target="panel", detail="back to the built-in certificate")
        _restart_and_say("Your certificate was removed; the panel makes a new built-in one as it starts.")
        return _back()
