"""An account's alert devices: turn Web Push alerts on and off, list and remove devices, test, sign out.

Registered from auth_routes.register (app.py is at its size limit). Every route is the caller's own
(the object is the signed-in account): no permission beyond being signed in, and each looks rows up
by id AND the caller's user id, so one account can never touch another's device (OWASP Authorization
Cheat Sheet, "Ensure Lookup IDs are Not Accessible Even When Guessed"). The POSTs carry the CSRF token
and pass the Fetch Metadata guard like every other.

Turning alerts on needs a recent password confirmation (step_up_required): a subscription outlives
sign-out and "Sign out everywhere", so a borrowed session must not be able to leave a listener behind
(Session Management Cheat Sheet, "Reauthentication After Risk Events"). It is also recorded as a
change to the account's security, which the account's other devices are pushed and its next sign-in
shows. Turning off and removing never ask: taking alerts away is not the direction that needs proof.
"""
from flask import flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from panel.core import i18n
from panel.db.models import PushSubscription, db
from panel.security.account_guard import step_up_required
from panel.security.auth import log_action
from panel.services import push_alerts


def register(app):
    push_alerts.register(app)
    # The Account page's alerts card and the sign-out page read this (both of account.html's renders).
    app.jinja_env.globals["push_card"] = push_alerts.card
    _register_device_routes(app)
    _register_choice_routes(app)


def _json(ok, message, status=200, **extra):
    resp = jsonify(dict({"success": ok, "message": message}, **extra))
    resp.status_code = status
    return resp


def _register_device_routes(app):
    @app.route("/account/push/subscribe", methods=["POST"])
    @login_required
    @step_up_required
    def account_push_subscribe():
        """Store this browser's push subscription for the signed-in account."""
        from app import _session_label
        label = _session_label(request.headers.get("User-Agent", ""))
        row, why = push_alerts.subscribe(current_user, request.get_json(silent=True), label)
        if row is None:
            db.session.rollback()
            if why == push_alerts.TAKEN:
                # Audited without the endpoint: only that the device is another account's.
                log_action(current_user, "push_subscribe", target=current_user.username, success=False,
                           detail="%s (refused: this browser's subscription is another account's)" % label)
                return _json(False, i18n.tr(why), 409)
            return _json(False, i18n.tr(why), 400)
        db.session.commit()
        log_action(current_user, "push_subscribe", target=current_user.username, detail=label)
        return _json(True, i18n.tr("Alerts are on for this device."))

    @app.route("/account/push/unsubscribe", methods=["POST"])
    @login_required
    def account_push_unsubscribe():
        """Forget this browser's subscription (the page then unsubscribes the browser itself)."""
        body = request.get_json(silent=True)
        row = push_alerts.find(current_user, body.get("endpoint") if isinstance(body, dict) else None)
        if row is None:
            return _json(True, i18n.tr("Alerts are off for this device."))
        label = row.label or ""
        db.session.delete(row)
        db.session.commit()
        log_action(current_user, "push_unsubscribe", target=current_user.username,
                   detail="%s (turned off on that device)" % label)
        return _json(True, i18n.tr("Alerts are off for this device."))

    @app.route("/account/push/devices/<int:sub_id>/remove", methods=["POST"])
    @login_required
    def account_push_device_remove(sub_id):
        """Remove one of the signed-in account's alert devices from the Account page's list."""
        row = PushSubscription.query.filter_by(id=sub_id, user_id=current_user.id).first()
        if row is None:
            flash(i18n.tr("That device is not on your list."), "warning")
            return redirect(url_for("account") + "#sec-push")
        label = row.label or ""
        db.session.delete(row)
        db.session.commit()
        log_action(current_user, "push_unsubscribe", target=current_user.username,
                   detail="%s (removed from the device list)" % label)
        flash(i18n.tr("Device removed. It gets no more alerts."), "success")
        return redirect(url_for("account") + "#sec-push")

    @app.route("/account/push/test", methods=["POST"])
    @login_required
    def account_push_test():
        """Queue a test alert to every device of the signed-in account (rate-limited)."""
        n = current_user.push_subscriptions.count()
        if not n:
            return _json(False, i18n.tr("Turn alerts on for a device first."), 400)
        if not push_alerts.test_allowed(current_user.id):
            return _json(False, i18n.tr("That's enough test alerts for now. Try again in a few minutes."), 429)
        push_alerts.queue_test(current_user.id)
        log_action(current_user, "push_test", target=current_user.username, detail="%d device(s)" % n)
        return _json(True, i18n.tr("Test alert sent to {n} device(s). It should arrive within a minute.", n=n))


def _register_choice_routes(app):
    @app.route("/account/push/events", methods=["POST"])
    @login_required
    def account_push_events():
        """Save which alerts the signed-in account's devices get."""
        push_alerts.save_events(current_user, request.form.getlist("events"))
        db.session.commit()
        flash(i18n.tr("Alert choices saved."), "success")
        return redirect(url_for("account") + "#sec-push")

    @app.route("/account/signout")
    @login_required
    def account_signout():
        """The sign-out page a device with alerts on is sent to: sign out, and keep or stop its alerts."""
        return render_template("signout.html")


def signout_keeps_alerts(user, form):
    """At sign-out: stop this device's alerts when asked. True when this device's alerts stay on.

    `push_endpoint` is this browser's subscription, which the sign-out page posts only when the
    account has it. "Stop alerts on this device" deletes the row here; the browser's own subscription
    goes with the service worker when Clear-Site-Data clears the site's storage. Never raises.
    """
    try:
        row = push_alerts.find(user, form.get("push_endpoint"))
        if row is None:
            return False
        if form.get("stop_alerts") != "1":
            return True
        label = row.label or ""
        db.session.delete(row)
        db.session.commit()
        log_action(user, "push_unsubscribe", target=user.username, detail="%s (stopped at sign-out)" % label)
    except Exception:  # noqa: BLE001 - signing out must happen whatever this does
        db.session.rollback()
    return False
