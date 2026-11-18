"""The root cron page: root's crontab on a host, for the panel owner only (panel/services/root_cron.py).

Off until the owner turns it on, and every view and change checks, on the server, that the
signed-in account is the panel owner (Authorization Cheat Sheet, "Validate the Permissions on Every
Request", "Deny by Default"). Every change, the switch included, asks for the password and, with
2FA on, a code in the same request (Transaction Authorization Cheat Sheet 2.1, 2.4), and is
audited with the host and the old and new line (Logging Cheat Sheet). Nothing typed becomes a shell
command: the line is checked against cron's grammar and handed to root's crontab through the
helper's verbs (OS Command Injection Defense Cheat Sheet). docs/THREAT-MODEL.md has its row.
"""
from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from panel.core import i18n
from panel.db.models import RemoteServer, db
from panel.ops import ssh_manager as _sm
from panel.security import owner as _owner
from panel.security.auth import _r17c_row_id, log_action, superadmin_required
from panel.services import root_cron as _rc

NOT_OWNER = "Root's crontab is for the panel owner only."
OFF = "The root cron page is turned off. The panel owner can turn it on in Settings > Schedules."
ON_DONE = "The root cron page is on."
OFF_DONE = "The root cron page is off."
SAVED = "Root's crontab saved."
_CONFIRM_REFUSED = {
    "throttled": "Too many wrong passwords or codes for this account. Wait a few minutes and try again.",
    "wrong password": "Password incorrect. Nothing was changed.",
    "wrong code": "That authenticator code didn't match. Nothing was changed.",
    "replayed code": "That code has already been used — wait for your authenticator to show the next one.",
}


def register(app):
    """Register the root cron page, its change route and the owner's on/off switch."""
    app.jinja_env.globals["root_cron_on"] = _rc.enabled

    @app.route("/root-cron/<int:remote_id>")
    @login_required
    @superadmin_required     # and then the owner only, checked in the view
    def root_cron_page(remote_id):
        """Root's crontab and /etc/cron.d on one host (read-only for /etc/cron.d)."""
        u = current_user._get_current_object()
        if not _is_owner(u):
            _owner.refuse(u, _owner.owner(), "the root cron page", NOT_OWNER)
            abort(403)
        remote = _remote(remote_id)
        if not _rc.enabled():
            flash(i18n.tr(OFF), "warning")
            return redirect(url_for("panel_settings") + "#sec-schedules")
        opened = _rc.host_opened(_sm.is_local_server(remote), _sm.helper_present())
        got = _read(remote) if opened else None
        return render_template("root_cron.html", remote=remote, opened=opened, got=got,
                               rows=_rc.rows(got["text"]) if got else [],
                               sha=_rc.digest(got["text"]) if got else "",
                               hosts=RemoteServer.query.order_by(RemoteServer.name).all())

    @app.route("/root-cron/<int:remote_id>/change", methods=["POST"])
    @login_required
    @superadmin_required     # and then the owner only, checked in the view
    def root_cron_change(remote_id):
        """Add, edit or delete one job in root's crontab, confirmed with the password in this request."""
        u = current_user._get_current_object()
        if not _is_owner(u):
            return _owner.refuse(u, _owner.owner(), "a change to root's crontab", NOT_OWNER)
        remote = _remote(remote_id)
        back = redirect(url_for("root_cron_page", remote_id=remote.id))
        if not _rc.enabled():
            flash(i18n.tr(OFF), "warning")
            return back
        f = request.form
        op = f.get("op") if f.get("op") in ("add", "save", "delete") else ""
        n = _int(f.get("n"))
        was = f.get("was", "")
        line, why = (None, "") if op == "delete" else _rc.job_line(f.get("schedule"), f.get("command"))
        what = _what(op, n, was, line)
        why = why or _confirm_refusal(u)
        if not why:
            why = _apply(remote, op, n, was, line, f.get("sha", ""))
        # No remote=: the row holds the crontab lines, so the host's delegated viewers do not read it
        # (rbac_test _AX_PRIVATE_HOST_ROWS); its actor and superadmins do.
        log_action(u, "root_cron_change", target=remote.name,
                   detail=what + (" (refused: %s)" % why if why else ""), success=not why)
        flash(i18n.tr(why or SAVED), "danger" if why else "success")
        return back

    @app.route("/root-cron/switch", methods=["POST"])
    @login_required
    @superadmin_required     # and then the owner only, checked in the view
    def root_cron_switch():
        """Turn the root cron page on or off (owner, password in this request)."""
        u = current_user._get_current_object()
        if not _is_owner(u):
            return _owner.refuse(u, _owner.owner(), "the root cron switch", NOT_OWNER)
        on = request.form.get("on") == "1"
        why = _confirm_refusal(u)
        log_action(u, "root_cron_enabled" if on else "root_cron_disabled", target="panel",
                   detail=why or "", success=not why)
        if why:
            flash(i18n.tr(why), "danger")
        else:
            _rc.set_enabled(on)
            flash(i18n.tr(ON_DONE if on else OFF_DONE), "success")
        return redirect(url_for("panel_settings") + "#sec-schedules")


def _is_owner(u):
    return bool(getattr(u, "is_superadmin", False) and _owner.is_owner(u))


def _remote(remote_id):
    row_id = _r17c_row_id(remote_id)
    remote = db.session.get(RemoteServer, row_id) if row_id is not None else None
    if remote is None:
        abort(404)
    return remote


def _int(raw):
    raw = raw or ""
    return int(raw) if raw.isascii() and raw.isdecimal() and len(raw) <= 6 else 0


def _what(op, n, was, line):
    """The audit row's detail: the change, with the old and new line."""
    if op == "add":
        return "add: %s" % (line or "")
    if op == "save":
        return "edit line %d: %s -> %s" % (n, was, line or "")
    if op == "delete":
        return "removed line %d: %s" % (n, was)
    return "unknown change"


def _confirm_refusal(u):
    """None when the password (and 2FA code) in this request are right; else the sentence to show."""
    from panel.routes.account_security import _reauth_refusal
    key = _reauth_refusal(u, request.form.get("password", ""), (request.form.get("totp_code") or "").strip())
    if key is None:
        db.session.commit()   # a spent 2FA step is kept
        return None
    return _CONFIRM_REFUSED.get(key, _CONFIRM_REFUSED["wrong password"])


def _read(remote):
    """Root's crontab on `remote` (root_cron.parse_read), or None when it could not be read."""
    try:
        out, _err, rc = _sm.run_privileged(remote, "root-crontab-read", timeout=30)
    except Exception:  # noqa: BLE001 - a host that does not answer is "could not be read"
        return None
    got = _rc.parse_read(out)
    return got if rc == 0 and got["state"] else None


def _apply(remote, op, n, was, line, sha):
    """Make the change on `remote`; "" when saved, else the sentence to show."""
    if not _rc.host_opened(_sm.is_local_server(remote), _sm.helper_present()):
        return _rc.NOT_OPENED
    got = _read(remote)
    if got is None:
        return _rc.UNREADABLE
    if _rc.digest(got["text"]) != sha:
        return _rc.CHANGED
    new, why = _rc.changed_text(got["text"], op, n, was, line)
    if why:
        return why
    try:
        _out, _err, rc = _sm.write_root_crontab(remote, new, sha)
    except Exception:  # noqa: BLE001
        return _rc.NOT_SAVED
    if rc == 3:
        return _rc.CHANGED
    return "" if rc == 0 else _rc.NOT_SAVED
