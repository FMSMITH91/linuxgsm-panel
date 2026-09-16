"""Admin notification channels: Telegram and Discord setup and test.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (flash, jsonify, redirect, render_template, request, url_for)
from flask_login import (current_user, login_required)
from panel.core import (i18n)
from panel.core.config import (encrypt_secret, load_config, update_config)
from panel.db.models import (User, db)
from panel.security.auth import (MANAGE_USERS, grantable_groups, hash_password, log_action,
    permission_required, superadmin_required)
from panel.services import (notifications)
from panel.services.monitoring import (_AUTOBLOCK_DEFAULT_THRESHOLD, _autoblock_threshold)
from datetime import (timedelta)
from panel.core.http import (_form_credential, _form_err, _form_ok, _json_body)
from panel.core.validation import (_int_or, _valid_hex_color, generate_password, username_problem)
from app import (_new_user_language)


def register(app):
    @app.route("/settings")
    @login_required
    @superadmin_required
    def panel_settings():
        cfg = load_config()
        return render_template("settings.html", languages=i18n.LANGUAGES, settings={
            "site_title": cfg.get("site_title", "LinuxGSM Panel"),
            "site_domain": cfg.get("site_domain", ""),
            "login_tagline": cfg.get("login_tagline", ""),
            "accent_color": _valid_hex_color(cfg.get("accent_color")),
            # Always concrete — an older install may still hold "" from the removed
            # "creator's language" option, which means English.
            "default_language": (cfg.get("default_language") or "en"),
            "session_lifetime_hours": int(cfg.get("session_lifetime_hours", 8) or 8),
            "remember_days": int(cfg.get("remember_days", 3) or 3),
            "session_protection": cfg.get("session_protection", "strong"),
            "autoblock_threshold": _autoblock_threshold(),
        })

    @app.route("/settings/save", methods=["POST"])
    @login_required
    @superadmin_required
    def panel_settings_save():
        f = request.form
        title = (f.get("site_title") or "").strip()[:80] or "LinuxGSM Panel"
        domain = (f.get("site_domain") or "").strip()[:255]
        tagline = (f.get("login_tagline") or "").strip()[:200]
        accent = _valid_hex_color(f.get("accent_color"))          # "" if blank/invalid -> built-in
        lang = (f.get("default_language") or "").strip()
        lang = lang if lang in i18n.LANGUAGES else "en"           # always store a real language
        protection = f.get("session_protection") if f.get("session_protection") in ("strong", "basic") else "strong"
        hours = max(1, min(_int_or(f.get("session_lifetime_hours"), 8), 168))     # 1h .. 7d
        days = max(1, min(_int_or(f.get("remember_days"), 3), 90))                # 1 .. 90 days
        autoblock = max(1, min(_int_or(f.get("autoblock_threshold"),
                                      _AUTOBLOCK_DEFAULT_THRESHOLD), 100000))

        def _mut(cfg):
            cfg.update({
                "site_title": title, "site_domain": domain, "login_tagline": tagline,
                "accent_color": accent, "default_language": lang, "session_protection": protection,
                "session_lifetime_hours": hours, "remember_days": days,
                "autoblock_threshold": autoblock,
            })
        update_config(_mut)
        # Session/security keys are read from app.config per request, so apply them live —
        # no panel restart needed for the change to take effect.
        app.config["PERMANENT_SESSION_LIFETIME"] = hours * 3600
        app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=days)
        app.config["SESSION_PROTECTION"] = protection
        log_action(current_user, "settings_update", target="panel")
        flash("Settings saved.", "success")
        return redirect(url_for("panel_settings"))

    @app.route("/notifications")
    @login_required
    @superadmin_required
    def notifications_settings():
        return render_template("notifications.html",
                               settings=notifications.settings_for_form(),
                               events=notifications.EVENTS)

    @app.route("/notifications/save", methods=["POST"])
    @login_required
    @superadmin_required
    def notifications_save():
        f = request.form
        # A blank secret field means "keep the stored one" (None), so the real token/webhook is
        # never required to round-trip through the browser just to change a toggle.
        tg_token = f.get("telegram_token", "").strip()
        dc_webhook = f.get("discord_webhook", "").strip()
        dc_bot_token = f.get("discord_bot_token", "").strip()
        nt_token = f.get("ntfy_token", "").strip()
        notifications.save_settings(
            telegram={"enabled": bool(f.get("telegram_enabled")),
                      "chat_id": f.get("telegram_chat_id", ""),
                      "accept_commands": bool(f.get("telegram_accept_commands")),
                      "token": (tg_token or None)},
            discord={"enabled": bool(f.get("discord_enabled")),
                     "webhook": (dc_webhook or None),
                     "bot_token": (dc_bot_token or None),
                     "channel_id": f.get("discord_channel_id", ""),
                     "accept_commands": bool(f.get("discord_accept_commands"))},
            ntfy={"enabled": bool(f.get("ntfy_enabled")),
                  "server": f.get("ntfy_server", ""),
                  "topic": f.get("ntfy_topic", ""),
                  "token": (nt_token or None)},
            events={k: bool(f.get("event_" + k)) for k in notifications.EVENTS},
            thresholds={"disk_pct": f.get("threshold_disk"), "load_pct": f.get("threshold_load"),
                        "mem_pct": f.get("threshold_mem"), "load_mins": f.get("threshold_mins")},
        )
        log_action(current_user, "notifications_update", target="panel")
        flash("Notification settings saved.", "success")
        return redirect(url_for("notifications_settings"))

    @app.route("/api/notifications/test", methods=["POST"])
    @login_required
    @superadmin_required
    def notifications_test():
        b = _json_body()
        # Test the values typed into the form (so you don't have to Save first); blank fields fall
        # back to whatever's already saved.
        ok, msg = notifications.test_send(
            (b.get("channel") or "").strip(),
            token=(b.get("token") or "").strip() or None,
            chat_id=(b.get("chat_id") or "").strip() or None,
            webhook=(b.get("webhook") or "").strip() or None,
            server=(b.get("server") or "").strip() or None,
            topic=(b.get("topic") or "").strip() or None,
        )
        return jsonify({"success": ok, "message": msg})

    @app.route("/users/add", methods=["POST"])
    @login_required
    @permission_required(MANAGE_USERS)
    def add_user():
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        display_name = request.form.get("display_name", username).strip()
        is_superadmin = request.form.get("is_superadmin") == "on"
        group_ids = request.form.getlist("groups")

        # Only a superadmin may grant superadmin — otherwise a user with just MANAGE_USERS
        # could create a superadmin account and log in as it (privilege escalation).
        if is_superadmin and not current_user.is_superadmin:
            return _form_err("Only a superadmin can grant superadmin.", "manage_users")

        _uerr = username_problem(username)
        if _uerr:
            return _form_err(_uerr, "manage_users")

        existing = User.query.filter_by(username=username).first()
        if existing:
            return _form_err("Username already exists.", "manage_users")

        # New users start in the configured default UI language (Settings → Localization);
        # each user can change their own afterwards.
        new_lang = _new_user_language(load_config(), i18n.LANGUAGES)
        # The panel picks the password, not the admin. A password one person invents for another is
        # the one they will reuse for the next account, or a house pattern with the username in it;
        # and it has to be relayed anyway, so it is a handover credential from the moment it exists.
        # Generating it makes it random, and must_change_password makes it temporary.
        password = generate_password()
        user = User(
            username=username,
            password_hash=hash_password(password),
            email=encrypt_secret(email) if email else None,
            display_name=display_name,
            is_superadmin=is_superadmin,
            language=new_lang,   # already validated against i18n.LANGUAGES by _new_user_language
            must_change_password=True,
        )
        # Add to selected groups — same rule as edit_user. Creating an account in a group you
        # could not join yourself is the same escalation with an extra step (the generated
        # password is handed straight back, so the attacker just logs in as it).
        user.groups = grantable_groups({int(g) for g in group_ids if str(g).isdecimal()})

        db.session.add(user)
        db.session.commit()
        log_action(current_user, "add_user", target=username)
        notifications.notify("account_change", "New user created",
                             "%s created the user '%s'%s."
                             % (current_user.username, username, " (SUPER ADMIN)" if is_superadmin else ""))
        return _form_credential(f"User '{username}' created.", "manage_users",
                                username=username, password=password)

    @app.route("/users/<int:user_id>/edit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_USERS)
    def edit_user(user_id):
        user = User.query.get_or_404(user_id)
        want_superadmin = request.form.get("is_superadmin") == "on"
        # A user with only MANAGE_USERS must not be able to touch a superadmin account, nor
        # grant/revoke superadmin — either would be a privilege escalation (e.g. resetting a
        # superadmin's password and logging in as them, or promoting themselves).
        if not current_user.is_superadmin:
            if user.is_superadmin:
                return _form_err("Only a superadmin can modify a superadmin account.", "manage_users")
            if want_superadmin != user.is_superadmin:
                return _form_err("Only a superadmin can change superadmin status.", "manage_users")

        # Renaming. Admins could change everything about an account EXCEPT the name it signs in
        # with, so a typo at creation (or a person changing theirs) meant deleting the account and
        # making a new one — losing its groups, its 2FA and its audit history. The field is
        # optional: a form that omits it leaves the name alone.
        _new_username = (request.form.get("username") or "").strip()
        _old_username = user.username
        if _new_username and _new_username != _old_username:
            _uerr = username_problem(_new_username)
            if _uerr:
                return _form_err(_uerr, "manage_users")
            if User.query.filter(User.username == _new_username, User.id != user.id).first():
                return _form_err("Username already exists.", "manage_users")
            user.username = _new_username

        user.display_name = (request.form.get("display_name") or user.display_name or "").strip()
        _new_email = request.form.get("email", "").strip()
        user.email = encrypt_secret(_new_email) if _new_email else None
        user.is_active = request.form.get("is_active") == "on"
        user.is_superadmin = want_superadmin

        # Reset the password on request. Generated, never typed by the admin — same reasoning as
        # add_user. Resetting is an explicit tick, not a blank field that means "keep": an edit that
        # only renames someone must not quietly invalidate their login.
        new_password = None
        if request.form.get("reset_password") == "on":
            new_password = generate_password()
            # set_password, not a bare assignment: the outgoing password joins the history, so a
            # user handed a reset cannot answer the forced change by typing back the password the
            # reset just took away from them.
            user.set_password(hash_password(new_password))
            user.auth_epoch = (user.auth_epoch or 0) + 1   # revoke existing sessions
            # Only when the password now belongs to two people. An admin resetting their OWN
            # password knows it because they chose to see it, and has nobody to take it back from;
            # forcing them through a change screen would protect nothing.
            if user.id != current_user.id:
                user.must_change_password = True
            log_action(current_user, "reset_user_password", target=user.username)

        # Admin reset of a user's 2FA (for when they lose their authenticator).
        if request.form.get("reset_2fa") == "on" and user.totp_enabled:
            user.totp_enabled = False
            user.totp_secret = None
            user.backup_codes = ""
            log_action(current_user, "2fa_reset", target=user.username)

        # Update groups. Through grantable_groups, not straight from the form: a delegated
        # MANAGE_USERS admin could otherwise edit their OWN account and tick a privileged group,
        # picking up its permissions on the next request — the exact escalation _grantable_perms
        # exists to stop, reached from the membership side instead of the permission side.
        group_ids = {int(gid) for gid in request.form.getlist("groups")}
        user.groups = grantable_groups(group_ids, existing=list(user.groups or []))

        # Never let an edit leave the panel with no active superadmin (e.g. self-demotion
        # or deactivating the last one) — that would lock everyone out of the web UI.
        db.session.flush()
        if User.query.filter_by(is_superadmin=True, is_active=True).count() == 0:
            db.session.rollback()
            return _form_err("That change would leave no active superadmin — aborted.", "manage_users")

        db.session.commit()
        if _new_username and _new_username != _old_username:
            # Its own entry, and keyed on the OLD name: every earlier row for this account is filed
            # under that, so this is the only line that connects the two.
            log_action(current_user, "rename_user", target=_old_username,
                       detail="renamed to '%s'" % user.username)
        log_action(current_user, "edit_user", target=user.username)
        if new_password:
            notifications.notify("account_change", "Password reset",
                                 "%s reset the password for '%s'."
                                 % (current_user.username, user.username))
            return _form_credential(f"User '{user.username}' updated.", "manage_users",
                                    username=user.username, password=new_password)
        return _form_ok(f"User '{user.username}' updated.", "manage_users")

    @app.route("/users/<int:user_id>/delete", methods=["POST"])
    @login_required
    @permission_required(MANAGE_USERS)
    def delete_user(user_id):
        user = User.query.get_or_404(user_id)
        # Only a superadmin may delete a superadmin (else a MANAGE_USERS user could remove
        # other admins), and never the last one.
        if user.is_superadmin and not current_user.is_superadmin:
            return _form_err("Only a superadmin can delete a superadmin account.", "manage_users")
        if user.is_superadmin and User.query.filter_by(is_superadmin=True).count() <= 1:
            return _form_err("Cannot delete the last superadmin.", "manage_users")
        if user.id == current_user.id:
            return _form_err("You can't delete your own account.", "manage_users")
        username = user.username
        db.session.delete(user)
        db.session.commit()
        log_action(current_user, "delete_user", target=username)
        return _form_ok(f"User '{username}' deleted.", "manage_users")
