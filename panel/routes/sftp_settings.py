"""The SFTP service's Settings card and the Account page's SFTP keys.

Settings > SFTP (superadmin; a stale sign-in confirms its password first, step_up_required): on or
off, where it listens, its port, the upload size limit and whether a password with an authenticator
code may sign in. Saving restarts the service (services/sftp_broker.restart). Values outside the
recommendation are saved, with a note (owner rule: editable, the recommendation shown beside it).

Account > SFTP: each user's own public keys. Adding one asks for the account password and, with 2FA
on, a current authenticator (or backup) code, every time, as minting an API token does: a key signs
in with no session and outlives the one it was added from, so a stolen session cookie must not be
enough to leave one behind (OWASP Authentication Cheat Sheet, "Require Re-authentication for
Sensitive Features" and "Re-authentication After Risk Events": adding a trusted device). Every path
that takes an account back removes the account's keys (User.revoke_outliving_credentials). Adding
and removing are audited, appear in the account's own security notices, and raise the
credential_change alert for an administrator's account (account_notices).
"""
from flask import current_app, flash, jsonify, redirect, request, url_for
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.config import load_config, update_config
from panel.db.models import SftpKey, db
from panel.routes._shared import REAUTH_BLOCKED_MSG, reauth_password
from panel.security import account_notices
from panel.security.account_guard import step_up_required
from panel.security.auth import log_action, superadmin_required
from panel.services import sftp_broker, sftp_common as sc

_SETTINGS_ANCHOR = "sec-sftp"
_ACCOUNT_ANCHOR = "sec-sftp"
ALL_ADDRESSES_WARNING = ("All addresses: the SFTP port is reachable from the internet, and anyone can try to "
                         "sign in. Sign-in stays limited to SSH keys unless you allow passwords below. The "
                         "panel does not open the port in the firewall: see the SFTP guide for how.")


def register(app):
    """The Settings card's save and the Account page's key routes; the service's loop; the cards' data."""
    app.jinja_env.globals["sftp_settings_card"] = settings_card
    app.jinja_env.globals["sftp_account_card"] = account_card
    sftp_broker.start_supervisor(app)

    @app.route("/settings/sftp", methods=["POST"])
    @login_required
    @superadmin_required
    @step_up_required       # who can reach the game servers' files, and how they sign in
    def sftp_settings_save():
        """Save the SFTP card and restart the service with it."""
        before = sc.settings(load_config())
        changes, why = sc.parse_form(request.form, bool(sftp_broker.tailscale_ips()), before["bind"])
        if why:
            flash(i18n.tr(why), "danger")
            return redirect(url_for("panel_settings", _anchor=_SETTINGS_ANCHOR))
        update_config(lambda cfg: cfg.update(changes))
        after = sc.settings(load_config())
        if after["enabled"]:
            from panel.core.config import decrypt_secret, encrypt_secret
            sc.ensure_host_key(update_config, load_config, encrypt_secret, decrypt_secret)
        log_action(current_user, "settings_update", target="panel", detail=change_note(before, after))
        sftp_broker.restart()
        # The jail lists the SFTP port only while it listens on every address; off, or another
        # address, has no start to rewrite it from (sftp_broker.f2b_follow).
        sftp_broker.f2b_follow(current_app._get_current_object())
        flash(i18n.tr("SFTP settings saved."), "success")
        for note in notes(after):
            flash(i18n.tr(note), "warning")
        return redirect(url_for("panel_settings", _anchor=_SETTINGS_ANCHOR))

    @app.route("/account/sftp-keys/add", methods=["POST"])
    @login_required
    def account_sftp_key_add():
        """Add one public key to the signed-in account, proved with the password (and the code with 2FA on)."""
        u = current_user._get_current_object()
        parsed, why = sc.parse_public_key(request.form.get("public_key"), request.form.get("label"))
        if why is None and current_user.sftp_keys.count() >= sc.MAX_KEYS_PER_USER:
            why = i18n.Sentence("An account can hold {n} SFTP keys. Remove one first.", n=sc.MAX_KEYS_PER_USER)
        if why is None and current_user.sftp_keys.filter_by(fingerprint=parsed.fingerprint).first():
            why = "That key is already on your account."
        if why:
            flash(i18n.tr(why), "danger")
        # The proof is checked LAST, as the API-token mint does: a one-time backup code is never
        # spent on a request that is refused for another reason.
        refused = str(why) if why else _key_add_proof_refusal(u)
        if refused:
            log_action(u, "sftp_key_add", target=u.username, detail="refused: %s" % refused, success=False)
            return redirect(url_for("account", _anchor=_ACCOUNT_ANCHOR))
        db.session.add(SftpKey(user_id=current_user.id, label=parsed.label, key_type=parsed.key_type,
                               key_blob=parsed.blob_b64, fingerprint=parsed.fingerprint))
        db.session.commit()
        log_action(current_user, "sftp_key_add", target=current_user.username,
                   detail="%s %s %s" % (sc.KEY_TYPES[parsed.key_type], parsed.fingerprint, parsed.label))
        account_notices.alert_credential_change(u, "SFTP key added (%s)" % parsed.fingerprint)
        flash(i18n.tr("SFTP key added."), "success")
        return redirect(url_for("account", _anchor=_ACCOUNT_ANCHOR))

    @app.route("/account/sftp-keys/<int:key_id>/remove", methods=["POST"])
    @login_required
    def account_sftp_key_remove(key_id):
        """Remove one of the signed-in account's own keys (the card's ajax form: a JSON answer)."""
        row = SftpKey.query.filter_by(id=key_id, user_id=current_user.id).first()
        if row is None:
            return jsonify({"success": False, "message": i18n.tr("That key is not on your account.")}), 404
        detail = "%s %s %s" % (sc.KEY_TYPES.get(row.key_type, row.key_type), row.fingerprint, row.label)
        db.session.delete(row)
        db.session.commit()
        log_action(current_user, "sftp_key_remove", target=current_user.username, detail=detail)
        account_notices.alert_credential_change(current_user, "SFTP key removed (%s)" % row.fingerprint)
        return jsonify({"success": True, "message": i18n.tr("SFTP key removed.")})


def _key_add_proof_refusal(u):
    """Why the form's password and code do not allow adding a key (for the audit row), or None.

    The same proof, budget and order as the API-token mint (auth_routes.account_api_token_generate):
    the password first under the shared per-account re-authentication budget, then the code, which
    is spent (single use) only once the password has passed. The flash saying why is already queued.
    """
    from panel.routes.auth_routes import _auth_token_totp_refusal
    pw = reauth_password(u, request.form.get("password", ""))
    if pw == "throttled":
        flash(REAUTH_BLOCKED_MSG, "danger")
        return "too many wrong passwords or codes"
    if pw != "ok":
        flash(i18n.tr("Password incorrect — no SFTP key was added."), "danger")
        return "wrong password"
    if not u.totp_enabled:
        return None
    why = _auth_token_totp_refusal(u, (request.form.get("totp_code") or "").strip(), own_mismatch=True)
    if why == "wrong authenticator code":
        flash(i18n.tr("That authenticator code didn't match — no SFTP key was added."), "danger")
    return why


def change_note(before, after):
    """The audit row's text for a save: what changed, as words."""
    words = []
    if before["enabled"] != after["enabled"]:
        words.append("SFTP service %s" % ("on" if after["enabled"] else "off"))
    for key, label in (("bind", "address"), ("port", "port"), ("cap_mb", "upload limit MiB"),
                       ("idle_min", "idle timeout min"), ("absolute_h", "absolute limit h")):
        if before[key] != after[key]:
            words.append("SFTP %s %s -> %s" % (label, before[key], after[key]))
    if before["password"] != after["password"]:
        words.append("SFTP password and code sign-in %s" % ("allowed" if after["password"] else "off"))
    return "; ".join(words) or "SFTP settings saved unchanged"


def notes(s):
    """The non-blocking notes for saved settings outside the recommendation."""
    out = []
    if s["enabled"] and s["bind"] == sc.BIND_ALL:
        out.append(ALL_ADDRESSES_WARNING)
    if s["password"]:
        out.append("Password and code sign-in is on. The recommended setting is SSH keys only: a key "
                   "cannot be guessed.")
    if s["idle_min"] == 0:
        out.append("Idle SFTP sessions are never closed. OWASP recommends closing a session after 15 to 30 "
                   "minutes without activity.")
    elif s["idle_min"] > sc.OWASP_IDLE_MAX_MINUTES:
        out.append(i18n.Sentence("The idle timeout is longer than the 30 minutes OWASP recommends at most "
                                 "({minutes} minutes).", minutes=s["idle_min"]))
    if sc.absolute_past_owasp(s["absolute_h"]):
        out.append(i18n.Sentence("The absolute SFTP session limit is longer than the 8 hours OWASP recommends at "
                                 "most ({hours} hours).", hours=s["absolute_h"]))
    if s["cap_mb"] > sc.RECOMMENDED_CAP_MB:
        out.append(i18n.Sentence("The upload size limit is above the recommended {mib} MiB.",
                                 mib=sc.RECOMMENDED_CAP_MB))
    return out


def settings_card():
    """What the Settings page's SFTP card shows: the values, the choices, the state and the host key."""
    from panel.core.config import decrypt_secret
    cfg = load_config()
    s = sc.settings(cfg)
    ts_ips = sftp_broker.tailscale_ips()
    stored = cfg.get(sc.HOST_KEY_KEY) or ""
    status = sftp_broker.status()
    return {
        "s": s, "bind": s["bind"] or sc.default_bind(bool(ts_ips)),
        "tailscale_up": bool(ts_ips), "tailscale_ip": (sc.bind_addresses(sc.BIND_TAILSCALE, ts_ips, False)
                                                       or [""])[0],
        "ipv6": sc.host_has_ipv6(), "status": status,
        "listening": [sc.listen_text(addr, port) for addr, port in status.get("bound") or []],
        "fingerprint": sc.host_fingerprint(decrypt_secret(stored)) if stored else "",
        "default_port": sc.DEFAULT_PORT, "recommended_cap": sc.RECOMMENDED_CAP_MB,
        "recommended_idle": sc.RECOMMENDED_IDLE_MINUTES, "idle_outside": sc.idle_outside_owasp(s["idle_min"]),
        "absolute_past": sc.absolute_past_owasp(s["absolute_h"]), "grace_min": sc.ABSOLUTE_GRACE_MINUTES,
        "notes": notes(s), "all_warning": ALL_ADDRESSES_WARNING,
    }


def account_card(user):
    """What the Account page's SFTP card shows `user`: their keys, how to connect, what they will see."""
    from panel.core.config import decrypt_secret
    cfg = load_config()
    s = sc.settings(cfg)
    status = sftp_broker.status()
    stored = cfg.get(sc.HOST_KEY_KEY) or ""
    keys = [{"id": k.id, "label": k.label, "type": sc.KEY_TYPES.get(k.key_type, k.key_type),
             "fingerprint": k.fingerprint, "created": k.created_at, "last_used": k.last_used}
            for k in user.sftp_keys.order_by(SftpKey.id).all()]
    folders = sorted(sftp_broker.editable(user)) if s["enabled"] else []
    bound = status.get("bound") or []
    return {"enabled": s["enabled"], "running": status["state"] == "running", "key_rows": keys,
            "max_keys": sc.MAX_KEYS_PER_USER, "port": s["port"], "password": s["password"],
            "address": _shown_address(bound), "folders": folders,
            "fingerprint": sc.host_fingerprint(decrypt_secret(stored)) if stored else ""}


def _shown_address(bound):
    """The address a user types into FileZilla: the first one listened on, or "" for all of them."""
    for addr, _port in bound:
        if addr not in ("0.0.0.0", "::"):  # nosec B104 - compared, never bound here
            return addr
    return ""
