"""Admin notification channels: Telegram and Discord setup and test.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (flash, jsonify, redirect, render_template, request, url_for)
from flask_login import (current_user, login_required, login_user)
from panel.core import (i18n)
from panel.core.config import (encrypt_secret, load_config, update_config)
from panel.core.clock import utcnow
from panel.db.models import (Group, Invite, User, db)
from panel.security.auth import (MANAGE_USERS, accessible_remote_ids, can_administer_user,
                                 custom_command_ids,
                                 get_user_permissions, get_user_servers,
                                 grantable_groups, hash_password, log_action,
    permission_required, superadmin_required)
from panel.services import (notifications)
from panel.services.monitoring import (_AUTOBLOCK_DEFAULT_THRESHOLD, _autoblock_threshold)
from datetime import (timedelta)
from panel.core.http import (_form_credential, _form_err, _form_ok, _json_body, _json_str)
from panel.core.validation import (_int_or, _valid_hex_color, generate_password,
                                   password_problem, username_problem)
from app import (_has_remember_cookie, _new_user_language, _register_session)


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
        title = _json_str(f, "site_title")[:80] or "LinuxGSM Panel"
        domain = _json_str(f, "site_domain")[:255]
        tagline = _json_str(f, "login_tagline")[:200]
        accent = _valid_hex_color(f.get("accent_color"))          # "" if blank/invalid -> built-in
        lang = _json_str(f, "default_language")
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
        tg_token = _json_str(f, "telegram_token")
        dc_webhook = _json_str(f, "discord_webhook")
        dc_bot_token = _json_str(f, "discord_bot_token")
        nt_token = _json_str(f, "ntfy_token")
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
            _json_str(b, "channel"),
            token=_json_str(b, "token") or None,
            chat_id=_json_str(b, "chat_id") or None,
            webhook=_json_str(b, "webhook") or None,
            server=_json_str(b, "server") or None,
            topic=_json_str(b, "topic") or None,
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
            # ...and not an account that holds permissions this admin does not. The superadmin
            # flag was the ONLY actor-vs-target test, so MANAGE_USERS alone reached every other
            # account — and the branches below reset the password (handing the plaintext back)
            # and clear 2FA. See can_administer_user.
            if not can_administer_user(current_user, user):
                return _form_err("That account holds permissions you don't have — "
                                 "only a superadmin can edit it.", "manage_users")

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

        _pending_audit = []      # (action, target, detail) — written after the commit below
        user.display_name = (request.form.get("display_name") or user.display_name or "").strip()
        _new_email = request.form.get("email", "").strip()
        user.email = encrypt_secret(_new_email) if _new_email else None
        _was_active = bool(user.is_active)
        user.is_active = request.form.get("is_active") == "on"
        if _was_active and not user.is_active:
            # load_user() refuses an inactive account, so the sessions are already dead the moment
            # this commits. Clear the registry rows and bump the epoch anyway: an offboarded
            # account should not go on listing "active sessions" on its account page, and the
            # epoch is what invalidates a legacy cookie that carries no sid to delete.
            from panel.db.models import UserSession
            UserSession.query.filter_by(user_id=user.id).delete(synchronize_session=False)
            user.auth_epoch = (user.auth_epoch or 0) + 1
            user.revoke_api_token()
        user.is_superadmin = want_superadmin

        # THE LOCKOUT GUARD RUNS HERE, before anything below can commit. It used to sit at the very
        # end, after the password-reset and 2FA branches — and each of those calls log_action(),
        # which ends in db.session.commit(). So on the one edit that matters most (the sole
        # superadmin unticking "Super admin" while also ticking "Reset password", both controls in
        # the SAME form in manage_users.html) the demotion was already committed by the time the
        # guard looked. Its db.session.rollback() then had nothing to undo, and the route answered
        # "That change would leave no active superadmin — aborted." with zero superadmins left and
        # the web UI locked for everyone, recoverable only through manage.py.
        #
        # Driven end to end before this moved: superadmins before 1, route answered 400 with the
        # abort message, superadmins after 0.
        #
        # Nothing between here and the commit changes is_superadmin or is_active, so checking at
        # this point is the same question asked while the answer can still be acted on.
        db.session.flush()
        if User.query.filter_by(is_superadmin=True, is_active=True).count() == 0:
            db.session.rollback()
            return _form_err("That change would leave no active superadmin — aborted.", "manage_users")

        # Reset the password on request. Generated, never typed by the admin — same reasoning as
        # add_user. Resetting is an explicit tick, not a blank field that means "keep": an edit that
        # only renames someone must not quietly invalidate their login.
        new_password = None
        # Set only on a SELF-reset, to which cookie keeps this login alive — see the note in the
        # branch below. None means "not a self-reset"; False is a real answer, so the check after
        # the commit is `is not None`.
        _self_remember = None
        if request.form.get("reset_password") == "on":
            new_password = generate_password()
            # set_password, not a bare assignment: the outgoing password joins the history, so a
            # user handed a reset cannot answer the forced change by typing back the password the
            # reset just took away from them.
            # nosemgrep: python.django.security.audit.unvalidated-password.unvalidated-password -- a generated password, not a typed one
            user.set_password(hash_password(new_password))
            user.auth_epoch = (user.auth_epoch or 0) + 1   # revoke existing sessions
            # The API token too. It is a SECOND credential for the same account, and it did not
            # answer to any of the controls that exist to take an account back: it carries no
            # auth_epoch, so a password change did not touch it, and "sign out everywhere" deleted
            # every UserSession row and left it working. app.py's note that "cookie theft is also
            # recoverable via sign out everywhere" was not true while one existed. Minting one
            # needs only a live session (no password, no 2FA), so an attacker with a stolen cookie
            # could leave themselves a key that survived the victim's whole recovery.
            user.revoke_api_token()
            # Only when the password now belongs to two people. An admin resetting their OWN
            # password knows it because they chose to see it, and has nobody to take it back from;
            # forcing them through a change screen would protect nothing.
            if user.id != current_user.id:
                user.must_change_password = True
            else:
                # ...and a self-reset must not sign the admin out before they can READ the password
                # it just generated. The epoch bump above kills every cookie for this account
                # including the one that made this request — load_user compares the cookie's epoch
                # and returns None the moment they differ — and panel.js runs
                # refreshSection('#users-list') BEFORE it opens the credential modal, so the next
                # request lands milliseconds later, is answered 401 + X-Auth-Required, and
                # sessionExpired() replaces the tab with /login. Only the bcrypt hash is stored, so
                # the password was gone; on a single-superadmin install (the common one) the
                # account was then reachable only through manage.py reset-password on the host.
                # Carry THIS device across the bump the way account_change_password already does
                # (panel/routes/tags.py:396-403): note which cookie keeps this login alive now, and
                # re-register + re-login after the commit below.
                from panel.db.models import UserSession
                _sid = getattr(current_user, "_sid", None)
                _cur_sess = (UserSession.query.filter_by(sid=_sid, user_id=user.id).first()
                             if _sid else None)
                _self_remember = (bool(_cur_sess.remember) if _cur_sess is not None
                                  else _has_remember_cookie())
            # DEFERRED, not written here. log_action commits, and a commit in the middle of a
            # handler makes every later guard unable to undo what came before it — see the lockout
            # note above, and the group-id parse below, which could 500 after this branch had
            # already committed a password reset that nobody ever saw.
            _pending_audit.append(("reset_user_password", user.username, ""))

        # Admin reset of a user's 2FA (for when they lose their authenticator).
        if request.form.get("reset_2fa") == "on" and user.totp_enabled:
            user.totp_enabled = False
            user.totp_secret = None
            user.backup_codes = ""
            _pending_audit.append(("2fa_reset", user.username, ""))   # deferred — see above

        # Update groups. Through grantable_groups, not straight from the form: a delegated
        # MANAGE_USERS admin could otherwise edit their OWN account and tick a privileged group,
        # picking up its permissions on the next request — the exact escalation _grantable_perms
        # exists to stop, reached from the membership side instead of the permission side.
        # isdecimal() like every sibling parse (add_user, create_invite, _assign_command_groups).
        # This one was bare int(), so `groups=abc` raised straight out of the handler — a 500, and
        # worse in combination: the password-reset branch above used to have committed by now, so
        # the account was left with a reset password and revoked sessions that nobody ever saw.
        group_ids = {int(gid) for gid in request.form.getlist("groups") if str(gid).isdecimal()}
        user.groups = grantable_groups(group_ids, existing=list(user.groups or []))

        db.session.commit()
        if _self_remember is not None:
            # The self-reset re-login — see the branch above. After the commit, so a rollback on
            # any guard between here and there cannot leave this device holding a session for an
            # epoch the database never took.
            _register_session(user, _self_remember)
            login_user(user, remember=_self_remember)
        for _act, _tgt, _detail in _pending_audit:
            log_action(current_user, _act, target=_tgt, detail=_detail)
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

    @app.route("/users/invite", methods=["POST"])
    @login_required
    @superadmin_required
    def create_invite():
        """Mint a one-time link that lets someone create their OWN account.

        Superadmin only, because an invite decides what the resulting account can do. The
        alternative it replaces is an admin inventing a username and relaying a generated password
        over chat — a working credential sitting in a third place from the moment it exists. This
        carries no credential: the person opens it once, picks their own name and password, and the
        link dies."""
        hours = _int_or(request.form.get("hours"), Invite.INVITE_TTL_HOURS)
        hours = max(1, min(int(hours), 24 * 30))        # an hour to a month
        want_super = request.form.get("is_superadmin") == "on"
        group_ids = {int(g) for g in request.form.getlist("groups") if str(g).isdecimal()}
        # Through grantable_groups, exactly like add_user: a superadmin minting an invite still
        # cannot hand out a group the escalation guard would refuse them directly.
        groups = grantable_groups(group_ids)
        inv, token = Invite.mint(current_user, hours=hours, superadmin=want_super,
                                 group_ids=[g.id for g in groups],
                                 note=request.form.get("note", ""))
        db.session.add(inv)
        db.session.commit()
        log_action(current_user, "invite_created", target=inv.note or "(no note)",
                   detail="expires in %dh%s" % (hours, " — GRANTS SUPERADMIN" if want_super else ""))
        # Shown once, like a generated password: only the hash is stored, so if this is missed the
        # link is gone and a new invite has to be minted.
        return _form_credential("Invite link created — send it to them. It works once.",
                                "manage_users", username="Invite link",
                                # nosemgrep: python.flask.security.audit.flask-url-for-external-true.flask-url-for-external-true -- shown only to the superadmin who minted it, on the host they reached the panel by
                                password=url_for("redeem_invite", token=token, _external=True))

    @app.route("/users/invite/<int:invite_id>/revoke", methods=["POST"])
    @login_required
    @superadmin_required
    def revoke_invite(invite_id):
        """Take back an invite that has not been redeemed.

        Without this, a link sent to the wrong address could only be waited out — and the TTL goes
        up to 30 days. Redeemed invites are left alone: the account already exists, so there is
        nothing to take back and the row is the only record of where it came from."""
        inv = db.session.get(Invite, invite_id)
        if inv is None:
            return _form_err("That invite no longer exists.", "manage_users", code=404)
        _note, _by = inv.note, inv.created_by_id   # read before the UPDATE expires the row
        # Claimed the same way redemption claims it: one UPDATE ... WHERE used_at IS NULL, not a
        # read followed by a write. Redemption's own comment says it — "checking is_usable above
        # and trusting it would be a race" — and this side was the read-then-write half of that
        # same race: a link redeemed between the check and the commit produced a row stamped BOTH
        # used and revoked, and a flash saying the link no longer works to an admin whose invitee
        # had just created their account.
        _claimed = (Invite.query
                    .filter(Invite.id == invite_id, Invite.used_at.is_(None),
                            Invite.revoked_at.is_(None))
                    .update({"revoked_at": utcnow()}, synchronize_session=False))
        db.session.commit()
        if _claimed:
            log_action(current_user, "invite_revoked", target=_note or "(no note)",
                       detail="created by user id %s" % (_by,))
            return _form_ok("Invite revoked — the link no longer works.", "manage_users")
        # Nothing claimed: re-read to say WHICH, rather than reporting a revocation that did not
        # happen. Already-revoked stays a success — the caller wanted it gone and it is.
        inv = db.session.get(Invite, invite_id)
        if inv is not None and inv.used_at is not None:
            return _form_err("That invite was already redeemed — revoking it would change nothing.",
                             "manage_users")
        if inv is None:
            return _form_err("That invite no longer exists.", "manage_users", code=404)
        return _form_ok("Invite revoked — the link no longer works.", "manage_users")

    @app.route("/invite/<token>", methods=["GET", "POST"])
    def redeem_invite(token):
        """Create your own account from a one-time link. NO login required — that is the point.

        The invite decides what the account gets (groups, superadmin); the person decides only
        their username and password. Anything else would be a privilege they awarded themselves."""
        inv = Invite.by_token(token)
        # An invite is a delegation, and it must not outlive the authority behind it: an admin who
        # is offboarded — demoted, deactivated, deleted — would otherwise leave live invites behind
        # for up to 30 days, still handing out whatever they promised, superadmin included.
        # Checked on GET as well as POST, so a dead invite never even shows the form.
        _creator = db.session.get(User, inv.created_by_id) if (inv and inv.created_by_id) else None
        if inv is None or not inv.is_usable or not inv.authority_intact(_creator):
            # One message for missing, used and expired alike: a link that says "already used"
            # confirms it was real, which is information a stranger holding a guessed token has
            # not earned. There is nothing the person can do differently either way.
            return render_template("invite.html", invalid=True), 404
        if request.method == "GET":
            return render_template("invite.html", invalid=False, token=token, invite=inv)

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        uerr = username_problem(username)
        if uerr:
            return render_template("invite.html", invalid=False, token=token, invite=inv,
                                   error=uerr), 400
        if User.query.filter_by(username=username).first():
            return render_template("invite.html", invalid=False, token=token, invite=inv,
                                   error="That username is taken."), 400
        if password != confirm:
            return render_template("invite.html", invalid=False, token=token, invite=inv,
                                   error="The two passwords do not match."), 400
        perr = password_problem(password)
        if perr:
            return render_template("invite.html", invalid=False, token=token, invite=inv,
                                   error=perr), 400

        # Claim the invite FIRST, conditionally on it still being unused, so two submissions of the
        # same link cannot both make an account. The UPDATE ... WHERE used_at IS NULL is what makes
        # that atomic; checking is_usable above and trusting it would be a race.
        #
        # revoked_at is in the WHERE for the same reason, and it was not. is_usable asks three
        # questions (used, revoked, expired) and the claim asked one — so the race this comment
        # names was still open for the revoke half: an admin clicking Revoke between the is_usable
        # check above and this UPDATE did not stop the redemption. The account was created anyway,
        # the row ended up stamped BOTH revoked and used, and the admin was told "Invite revoked —
        # the link no longer works" about a link that had just worked. revoke_invite already claims
        # its side with exactly this pair; this is the same shape from the other end.
        claimed = (db.session.query(Invite)
                   .filter(Invite.id == inv.id, Invite.used_at.is_(None),
                           Invite.revoked_at.is_(None))
                   .update({"used_at": utcnow()}, synchronize_session=False))
        if not claimed:
            db.session.rollback()
            return render_template("invite.html", invalid=True), 404

        user = User(username=username, password_hash=hash_password(password),
                    display_name=username, is_superadmin=bool(inv.grants_superadmin),
                    is_active=True, language=_new_user_language(load_config(), i18n.LANGUAGES))
        # must_change_password stays False: they chose this password themselves, nobody handed it
        # to them, so there is nothing to rotate away from.
        # The GROUPS must still be within the creator's authority, not just the superadmin flag.
        #
        # authority_intact() covers the flag, and deliberately stays a pure predicate — it takes a
        # creator and touches no session. Groups need the database, so the re-validation belongs
        # here. Without it the delegation outlives the authority on the other axis: minting is
        # superadmin-only and the groups were checked against the minter AT MINT TIME (for a
        # superadmin, everything), so a superadmin who minted an invite into a privileged group
        # and was then DEMOTED — while staying active, so the flag check passes — left a live link
        # that still created an account holding the permissions they had just lost. Whoever kept
        # the link, including them, could redeem it.
        #
        # Same rule grantable_groups applies everywhere else: a superadmin may grant anything,
        # anyone else only a group whose permissions are a SUBSET of their own. Fail CLOSED on the
        # whole invite rather than quietly granting less than it promised — the person redeeming
        # it would otherwise get an account that silently lacks what they were told they'd have.
        #
        # ALL of that rule, though, and this copy applied a third of it. grantable_groups'
        # _within_my_reach (panel/security/auth.py) asks three questions — permissions, whole-host
        # grants (Group.servers) and per-server grants (Group.game_servers) — because a group's
        # permission set is not the only thing membership hands you. The test here was the
        # permissions subset alone, so a group whose permissions the demoted minter still held —
        # or, worse, one carrying NO permissions at all, where `set() <= _mine` is trivially true —
        # sailed through with its host and server grants intact, and the new account could reach
        # every server on a host the minter had just lost. /users (grantable_groups) and /groups
        # (grantable_object_ids) both refuse that same grant to that same person; the invite was
        # the one door left open. Both helpers take an explicit user, so ask it about the creator.
        wanted = set(inv.groups_wanted)
        if wanted:
            _groups = Group.query.filter(Group.id.in_(wanted)).all()
            if _creator is not None and not _creator.is_superadmin:
                _mine = set(get_user_permissions(_creator))
                _mine_remotes = set(accessible_remote_ids(_creator))
                _mine_servers = {gs.id for gs in get_user_servers(_creator)}
                _mine_commands = custom_command_ids(_creator)   # the fourth axis, as grantable_groups

                def _beyond_creator(g):
                    if not set(g.get_permissions()) <= _mine:
                        return True
                    if not {r.id for r in (g.servers or [])} <= _mine_remotes:
                        return True
                    if not {c.id for c in (g.custom_commands or [])} <= _mine_commands:
                        return True
                    return not {s.id for s in (g.game_servers or [])} <= _mine_servers

                if any(_beyond_creator(g) for g in _groups):
                    db.session.rollback()
                    return render_template("invite.html", invalid=True), 404
            user.groups = _groups
        db.session.add(user)
        db.session.flush()
        inv.used_by_id = user.id
        db.session.commit()
        log_action(user, "invite_redeemed", target=username,
                   detail="from an invite created by user id %s" % (inv.created_by_id,))
        notifications.notify("account_change", "Account created from invite",
                             "'%s' created their account from an invite%s."
                             % (username, " (SUPER ADMIN)" if inv.grants_superadmin else ""))
        flash("Account created — sign in with your new username and password.", "success")
        return redirect(url_for("login"))

    @app.route("/users/<int:user_id>/delete", methods=["POST"])
    @login_required
    @permission_required(MANAGE_USERS)
    def delete_user(user_id):
        user = User.query.get_or_404(user_id)
        # Only a superadmin may delete a superadmin (else a MANAGE_USERS user could remove
        # other admins), and never the last one.
        if user.is_superadmin and not current_user.is_superadmin:
            return _form_err("Only a superadmin can delete a superadmin account.", "manage_users")
        if not can_administer_user(current_user, user):
            return _form_err("That account holds permissions you don't have — "
                             "only a superadmin can delete it.", "manage_users")
        if user.is_superadmin and User.query.filter_by(is_superadmin=True).count() <= 1:
            return _form_err("Cannot delete the last superadmin.", "manage_users")
        if user.id == current_user.id:
            return _form_err("You can't delete your own account.", "manage_users")
        username = user.username
        db.session.delete(user)
        db.session.commit()
        log_action(current_user, "delete_user", target=username)
        return _form_ok(f"User '{username}' deleted.", "manage_users")
