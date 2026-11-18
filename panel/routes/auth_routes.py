"""Login, logout, two-factor and the session lifecycle.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
import collections
import re
from datetime import timedelta
from contextlib import (suppress)
from flask import (after_this_request, flash, g, jsonify, redirect, render_template, request, session, url_for)
from flask_login import (current_user, login_required, login_user, logout_user)
from panel.core import (i18n)
from panel.core.clock import (utcnow)
from panel.core.validation import (MAX_USERNAME_LEN)
from panel.core.config import (decrypt_secret, encrypt_secret)
from panel.security import banlist as _banlist
from panel.security.headers import (no_store)
from panel.db.models import (User, db)
from panel.security.auth import (backup_code_shaped, hash_password, needs_rehash, check_password, client_ip,
    dummy_password_check,
    generate_backup_codes, generate_totp_secret, log_action, totp_provisioning_uri,
    session_fingerprint, throttle_key, verify_totp_step)
from panel.services import (notifications)
from panel.security import account_guard, account_notices, device_cookie
import time
from app import (LOGIN_MAX_FAILS, LOGIN_WINDOW, _LOGIN_BLOCK_LOGGED, _LOGIN_FAILS,
    _LOGIN_FAILS_LOCK, _authlog, _log, _log_ip, _maybe_alert_admin_bruteforce,
    _has_remember_cookie, _prune_login_fails, _qr_svg, _register_session, _session_label)
from panel.routes._shared import (REAUTH_BLOCKED_MSG, reauth_password, reauth_release,
    reauth_reserve, spend_totp_step)


def _r16c_bump_epoch_everywhere(user):
    """Logout's retry: bump `user`'s auth_epoch (every device signed out) and clear their rows.

    The bump signs out every device, so every UserSession row goes too — left, they listed as live
    sessions, with Revoke buttons, on the account page until they idled out (the legacy-cookie
    branch already clears them). The rows are the cleanup, the bump is the revocation: when the
    delete is what fails, the bump is committed alone. Raises when even that cannot be committed.
    """
    from panel.db.models import UserSession
    try:
        user.auth_epoch = (user.auth_epoch or 0) + 1
        UserSession.query.filter_by(user_id=user.id).delete(synchronize_session=False)
        db.session.commit()
    except Exception:
        db.session.rollback()
        with suppress(Exception):
            _log.warning("logout: the session rows could not be cleared; revoking by epoch alone",
                         exc_info=True)
        user.auth_epoch = (user.auth_epoch or 0) + 1
        db.session.commit()


def register(app):
    _register_sign_in(app)
    _register_account(app)
    _register_language(app)
    _register_2fa_and_profile(app)
    _register_sign_out_everywhere(app)
    _register_session_list(app)
    # The manifest, colour scheme and "What's new" (app.py is at its size limit).
    from panel.routes import app_shell
    app_shell.register(app)
    # Required 2FA, step-up confirmation, denial logging and the Fetch Metadata guard.
    from panel.routes import account_security
    account_security.register(app)
    # Transferring the panel's ownership (panel/security/owner.py).
    from panel.routes import owner_transfer
    owner_transfer.register(app)
    # An account's alert devices (Web Push) and the sign-out page that keeps or stops them.
    from panel.routes import push_devices
    push_devices.register(app)


def _flash_signed_out(bye):
    """The sign-out message, carried in the URL because sign-out clears the flash cookie."""
    if bye == "1":
        flash("You have been logged out.", "info")
    elif bye == "2":
        flash("Signed out on this device, but the server could not revoke the session — "
              "change your password to revoke it everywhere.", "warning")


def _register_sign_in(app):
    """Sign in and sign out."""
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect("/")

        if request.method == "POST":
            ip = client_ip() or "unknown"
            # The throttle's bucket, not the address: an IPv6 client is counted by its /64, which
            # is what one site or phone holds. `ip` itself still goes to the logs and fail2ban.
            attempt = _LoginAttempt(ip, throttle_key(ip), time.time())
            refused = _login_throttled(attempt)
            if refused is not None:
                return refused
            # _login_throttled reserved this attempt a place in the failure count; only an
            # attempt that FAILED keeps it. Released in a finally, so a success, the 2FA prompt,
            # an expired prompt and an exception all give it back.
            g._login_failed = False
            try:
                # ── Step 2: the 2FA code for a login that passed the password step ──
                pending_id = session.get("_2fa_pending")
                if pending_id and request.form.get("totp_code"):
                    return _login_second_factor(attempt, pending_id)

                # ── Step 1: username + password ──
                return _login_password(attempt)
            finally:
                if not g.get("_login_failed"):
                    _release_login_slot(attempt)

        _flash_signed_out(request.args.get("signed_out"))
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        # POST-only so it can't be triggered cross-site via a GET (e.g. <img src=…/logout>).
        log_action(current_user, "logout", detail="User logged out")
        # Invalidate the cookie SERVER-SIDE, not just in the browser — Flask sessions and the
        # "remember me" token are signed client-side cookies with no server store, so clearing the
        # client's copy alone wouldn't stop a copy captured earlier from being replayed. With per-
        # session tracking we delete just THIS device's registry row, so its cookie fails the loader
        # while other devices stay signed in. A legacy cookie (no sid) has nothing to delete, so fall
        # back to bumping the epoch (which is global — the old all-devices behaviour).
        revoked = False
        try:
            sid = getattr(current_user, "_sid", None)
            if sid:
                from panel.db.models import UserSession
                UserSession.query.filter_by(sid=sid, user_id=current_user.id).delete()
            else:
                current_user.auth_epoch = (current_user.auth_epoch or 0) + 1
                # The bump signed out every device, so clear every row too: left, they listed as
                # live sessions on the account page until they idled out.
                from panel.db.models import UserSession
                UserSession.query.filter_by(user_id=current_user.id).delete()
            db.session.commit()
            revoked = True
        except Exception:
            db.session.rollback()
            # Do not report a revocation the rollback undid. This handler's stated purpose is the
            # server-side invalidation described above, and the except swallowed the one statement
            # that achieves it: after a rollback the UserSession row is intact and auth_epoch is
            # unchanged, so every cookie that was valid before the request is still valid after it
            # — including the captured copy the comment above names as the threat — and the user
            # was told the opposite, with nothing logged for an operator to notice. Mirrors
            # load_user's own except (panel/security/auth.py): warning, under suppress(), because
            # logging must never be what turns a failed sign-out into a 500.
            with suppress(Exception):
                _log.warning("logout: could not revoke the session server-side", exc_info=True)
            # One retry, in a FRESH transaction, on the fallback this handler already uses. The
            # epoch bump is global, so it revokes this device even when the row delete is what
            # failed — and a momentary SQLite lock (a concurrent backup, a WAL checkpoint during a
            # monitor sweep) is exactly the failure it is for.
            try:
                _r16c_bump_epoch_everywhere(current_user._get_current_object())
                revoked = True
            except Exception:
                db.session.rollback()
                with suppress(Exception):
                    _log.warning("logout: the auth_epoch fallback failed too", exc_info=True)
        from panel.routes.push_devices import signout_keeps_alerts
        keep_alerts = signout_keeps_alerts(current_user._get_current_object(), request.form)
        logout_user()
        # Clear-Site-Data (Session Management Cheat Sheet, "Web Content Caching and Clear-Site-Data":
        # "cache", "cookies", "storage" at logout): the browser drops this site's cookies, storage
        # (the console's command history among them) and its HTTP cache. The signed-in pages are
        # `no-store` (app.py), so no copy of them is kept; "cache" also drops anything an older
        # release left on disk (the dashboard, the audit log, host addresses) at sign-out, and
        # whatever else is cached for this site. The cost is one fresh download of the scripts and
        # styles at the next sign-in. The message rides the URL, not a flash: the flash is kept in
        # the session cookie this header deletes.
        # "storage" also unregisters the site's service workers, and with them this device's push
        # subscription, so a device whose alerts stay on after sign-out (by design; the sign-out page
        # says so and offers to stop them) gets "cache" and "cookies" only: that page clears localStorage and
        # sessionStorage itself before it posts.
        resp = redirect("/login?signed_out=%d" % (1 if revoked else 2))
        resp.headers["Clear-Site-Data"] = '"cache", "cookies"' if keep_alerts else '"cache", "cookies", "storage"'
        return resp


def _register_account(app):
    """The account page, forced password change and the API token."""
    @app.route("/account")
    @login_required
    def account():
        return render_template("account.html", languages=i18n.LANGUAGES)

    @app.route("/password/change")
    @login_required
    def force_password_change():
        """The only page an account with a handed-over password can reach.

        It asks for the password the admin gave them, then the one they choose — the same three
        fields as the account page's own form, posting to the same handler, because this is not a
        different operation. What it is not is a page you can decline: the gate in create_app sends
        every other request back here until the flag clears.

        Rendered without the app chrome (see show_app_chrome): the sidebar, the dashboard pollers
        and the update badge all belong to a session that can use the panel, and this one cannot
        yet — showing them would offer links that bounce straight back to this page.
        """
        if not current_user.must_change_password:
            return redirect(url_for("account"))
        return render_template("force_password.html", languages=i18n.LANGUAGES)

    @app.route("/account/api-token/generate", methods=["POST"])
    @login_required
    def account_api_token_generate():
        """Mint a fresh API token (replacing any existing one) and show it ONCE.

        Needs the password AND — when 2FA is on — a current authenticator (or backup) code: the
        same proof the password change and the 2FA switch-off on the same page already demand.

        A live session used to be the entire gate, which made this the weakest-guarded control on
        the account page while handing out the strongest thing on it. What it mints is a SECOND
        credential that outlives the session that minted it: load_user_from_request authenticates
        the bearer as its owner with that owner's whole permission set, by_api_token matches on
        the digest and is_active and nothing else — no auth_epoch, so the epoch bump that sweeps
        every session cookie does not reach it, and what takes it away instead is the explicit
        revoke_api_token() that account_revoke_sessions and account_change_password each had to
        be taught to call; no totp_enabled, so it never meets the 2FA gate, which exists only in
        the /login form flow — and bearer requests are exempt from CSRF. So one POST from a
        borrowed tab converted a minute of someone else's session into a key with no IP/UA
        binding, no second factor and no expiry, which those two controls take back only if the
        victim thinks to press them — and nothing visible went wrong to suggest they should.
        Asking for the password and the code closes that: the two things a stolen cookie does not
        carry are now the two things minting one costs.

        (The sentence next door in account_revoke_sessions is in the PAST tense deliberately — it
        describes what was true before that route started revoking. An earlier draft of this
        docstring copied it without the tense and so claimed, in the present, that a password
        change and "sign out everywhere" leave a token working. Both revoke it today, and
        smoke_test asserts they do; a rationale that contradicts a passing test is worse than no
        rationale, because the next reader believes it.)

        Revoking stays ungated on purpose (see below) — taking a credential away is not the
        direction that needs proof.
        """
        # The real row, not the proxy — last_totp_step and the backup-code list are written here,
        # exactly as in account_2fa_disable.
        u = current_user._get_current_object()

        _pw = reauth_password(u, request.form.get("password", ""))
        if _pw == "throttled":
            flash(REAUTH_BLOCKED_MSG, "danger")
            return _auth_token_refused(u, "too many wrong passwords or codes")
        if _pw != "ok":
            flash("Password incorrect — no API token was minted.", "danger")
            return _auth_token_refused(u, "wrong password")
        # Checked LAST, and in this order, for the reasons account_2fa_disable spells out: a
        # one-time backup code must never be spent on an otherwise-invalid request, and a TOTP
        # code stays valid for ~90s, so verify_totp_STEP plus the last_totp_step comparison is
        # what makes an observed code single-use rather than replayable for the rest of its window.
        code = (request.form.get("totp_code") or "").strip()
        if u.totp_enabled:
            _why = _auth_token_totp_refusal(u, code)
            if _why is not None:
                return _auth_token_refused(u, _why)
        token = u.generate_api_token()
        _days = _token_days(request.form.get("expires_days"))
        u.api_token_expires = (utcnow() + timedelta(days=_days)) if _days else None
        # The token, and with it the spent step / backup code. NOT redundant with the commit
        # inside log_action on the next line, even though that one happens to flush this same
        # session today: deleting this line left both suites entirely green, which is how it came
        # out that nothing asserted the credential being handed over is stored at all. That commit
        # belongs to the audit writer, not to this route, and is one refactor away from not being
        # there — at which point the plaintext would still be shown and the row would still be
        # empty. smoke_test now re-reads the row in a FRESH app context after the POST, so the
        # write is pinned to the database rather than to whoever commits next.
        db.session.commit()
        log_action(u, "api_token_generate", target=u.username)
        account_notices.alert_credential_change(u, "new API token created")
        # Render directly (not a redirect) so the plaintext token is shown exactly once and never
        # stored in the session cookie.
        return no_store(render_template("account.html", languages=i18n.LANGUAGES, new_token=token))

    @app.route("/account/api-token/revoke", methods=["POST"])
    @login_required
    def account_api_token_revoke():
        """Revoke the signed-in user's own API token.

        Deliberately ungated, unlike the mint above. Revoking takes a credential AWAY, so the worst
        a stolen session can do here is inconvenience the owner — and a gate would be a reason not
        to press this in the one situation it exists for.
        """
        current_user.revoke_api_token()
        db.session.commit()
        log_action(current_user, "api_token_revoke", target=current_user.username)
        account_notices.alert_credential_change(current_user, "API token revoked")
        flash("API token revoked.", "success")
        return redirect(url_for("account"))


def _token_days(value):
    """A new API token's lifetime in days from the form: 30, 90 (the default), 365, or 0 for none."""
    return {"30": 30, "90": 90, "365": 365, "0": 0}.get(str(value or "90"), 90)


def _auth_token_refused(u, why):
    """Refuse an API-token mint, and SAY SO in the audit log.

    log_action fired on the mint alone, so the one thing this gate produces that is worth
    watching — somebody in a borrowed session trying passwords against it, which is now
    the only way past it — left no trace anywhere, while the mint they were aiming at
    left a tidy one. A gate whose refusals are invisible tells you afterwards that
    nothing happened, which is exactly what it looks like when something did. Recorded
    with success=False, the shape delete_group / uninstall_server / send_command already
    use, so it reads as a refusal in the audit list rather than as a mint.

    It was recorded but NOT rate-limited, on the reasoning that the same unthrottled
    password oracle sat behind account_change_password and account_2fa_disable, so a limit
    on this route alone would only move the guessing one route over — and that the real
    limit belonged on all of them at once. It is on all of them now: every route that
    re-asks for the current password or a live code shares one per-account budget
    (_shared.reauth_reserve), so a wrong guess here and one at the password change count
    against the same allowance.
    """
    log_action(u, "api_token_generate", target=u.username, detail=why, success=False)
    return redirect(url_for("account"))


def _auth_token_totp_refusal(u, code):
    """Check the API-token mint's authenticator (or backup) code for a 2FA account.

    Returns None when the code is good (its reserved budget slot handed back), else the audit
    reason for the refusal — the flash telling the user why has already been queued.
    """
    # The code is under the same per-account budget as the password: a failure keeps
    # its slot, a match gives it back below.
    _stamp = reauth_reserve(u)
    if _stamp is None:
        flash(REAUTH_BLOCKED_MSG, "danger")
        return "too many wrong passwords or codes"
    ok_2fa = False
    _step = verify_totp_step(u.totp_secret_plain, code) if u.totp_secret_plain else None
    if _step is not None:
        # A compare-and-swap, for the reason _login_totp_code gives: two mints with one
        # code could otherwise both pass a read-then-write.
        if _step <= (u.last_totp_step or 0) or not spend_totp_step(u, _step):
            db.session.rollback()
            flash("That code has already been used — wait for your authenticator to show "
                  "the next one.", "danger")
            return "replayed authenticator code"
        ok_2fa = True
    elif u.use_backup_code(code):
        ok_2fa = True
    if not ok_2fa:
        flash("That authenticator code didn't match — no API token was minted.", "danger")
        return "wrong authenticator code"
    reauth_release(u, _stamp)
    return None


def _register_language(app):
    """UI language: the switcher and its string catalogs."""
    @app.route("/set-language/<lang>", methods=["GET", "POST"])
    def set_language(lang):
        """Switch the UI language.

        Saved to the session, and to the user's profile when logged in (so it follows them across
        devices). Usable pre-login too. The switcher calls this with ?ajax=1 and then reloads the
        current page itself, so we never redirect to a user-supplied URL (no open-redirect surface);
        a plain GET just lands on the dashboard.

        The PROFILE write needs POST. csrf.protect() is a no-op on safe methods, so while this was
        GET-only any cross-site page could permanently change a logged-in admin's stored UI
        language with <img src="https://panel/set-language/zh">. The session half stays on GET —
        it is per-session and transient, and the switcher on the login page has no token to send —
        but nothing cross-site gets to write the user row.
        """
        lang = i18n.normalize_lang(lang)
        session["lang"] = lang
        saved = True
        if request.method == "POST" and getattr(current_user, "is_authenticated", False):
            try:
                current_user.language = lang
                db.session.commit()
            except Exception:
                db.session.rollback()
                _log.debug("saving the language preference failed", exc_info=True)
                saved = False   # the session still switches; only the profile write failed
        if request.args.get("ajax"):
            return jsonify({"success": saved, "lang": lang,
                            "message": "" if saved else "Language changed for this session only."})
        return redirect(url_for("index"))

    @app.route("/api/i18n/<lang>")
    def api_i18n_catalog(lang):
        """The {english: translated} catalog for a language.

        It lets the switcher re-translate the page live without a reload. Public (the switcher is on
        the login page too) and non-sensitive — it's only UI strings, the same map already embedded
        in every rendered page for the current language.
        """
        resp = jsonify(i18n.catalog(i18n.normalize_lang(lang)))
        resp.headers["Cache-Control"] = "public, max-age=300"   # catalogs change only on deploy
        return resp


def _flash_2fa_enabled(user):
    """Rotate `user`'s sessions after turning 2FA on, and say so (account_guard.rotate_sessions)."""
    if account_guard.rotate_sessions(user):
        flash("Two-factor authentication is now enabled.", "success")
    else:
        flash("Two-factor authentication is now enabled. Every session was signed out, "
              "including this one — please sign in again.", "warning")


def _register_2fa_and_profile(app):
    """Enrolling a second factor, and the display name."""
    @app.route("/account/2fa/enable", methods=["GET", "POST"])
    @login_required
    def account_2fa_enable():
        if current_user.totp_enabled:
            flash("Two-factor authentication is already enabled.", "info")
            return redirect(url_for("account"))
        if request.method == "POST":
            # The account holder's PASSWORD, first. Enrolment used to need nothing but a live
            # session, while its mirror — /account/2fa/disable — demands the password AND a code
            # and reasons in its docstring about which direction is more dangerous. Installing a
            # factor the holder does not have is the dangerous one, and it was the open one:
            # anyone in front of a signed-in session (an unlocked workstation, a shared browser
            # profile, a session or remember cookie captured before the password was rotated)
            # could scan the QR with their own authenticator, submit the code, and own a second
            # factor whose secret only they hold — with the backup codes rendered once, to them.
            # The owner's next sign-in then stops at a prompt they cannot answer, and disable
            # refuses them because it wants that same code or a backup code, so the takeover is
            # ONE-WAY: recovery needs another superadmin's reset_2fa or shell access to the panel
            # host. Same idiom and same order as account_2fa_disable and account_change_password.
            _u = current_user._get_current_object()
            # Throttled per account and audited, as its mirror is (see account_2fa_disable).
            _pw = reauth_password(_u, request.form.get("password", ""))
            if _pw != "ok":
                log_action(_u, "2fa_enabled", target=_u.username, success=False,
                           detail=("refused: too many wrong passwords or codes"
                                   if _pw == "throttled" else "refused: wrong password"))
                flash(REAUTH_BLOCKED_MSG if _pw == "throttled" else
                      "Password incorrect — two-factor authentication was not enabled.", "danger")
                # Back to this page, not /account: the pending secret is still in the session, so
                # the QR they have already scanned stays valid and they can simply try again.
                return redirect(url_for("account_2fa_enable"))
            secret = decrypt_secret(session.get("_2fa_setup_secret", ""))
            # verify_totp_STEP, not verify_totp — the third and last route that consumes a live
            # authenticator code, and the one the earlier audit missed. Login refuses a step that
            # has already been spent (see the comment there), and last_totp_step defaults to 0, so
            # enrolling without recording the step left the very code that turned 2FA on still
            # good at /login for the rest of its ~90s window: step S vs 0 passes the guard. The
            # other two live-code routes — login step 2 and account_change_password — both switched
            # to the step form for exactly this reason.
            _enrol_step = (verify_totp_step(secret, request.form.get("totp_code", ""))
                           if secret else None)
            if _enrol_step is not None:
                # Spent through the same compare-and-swap as every other live-code route, not the
                # plain assignment this was: that wrote the step unconditionally, so two enrolment
                # POSTs with one code both passed the totp_enabled check above, both turned 2FA on
                # and each rendered its OWN set of backup codes — only the later commit's set was
                # stored, and the holder of the other page was left keeping codes that never work.
                # Now exactly one wins; the other is told the code is spent and keeps the QR.
                #
                # The eight backup-code hashes (~2-3s of bcrypt in tpool) are made BEFORE the spend:
                # the spend is an immediate UPDATE that takes SQLite's write lock, and holding it
                # across that bcrypt run froze every other writer in SQLite's hub-blocking busy
                # handler until the busy timeout. Wasted on a refused spend, which is rare.
                codes = generate_backup_codes()
                current_user.set_backup_codes(codes)
                if not spend_totp_step(_u, _enrol_step):
                    db.session.rollback()
                    flash("That code has already been used — wait for your authenticator to show "
                          "the next one.", "danger")
                    return redirect(url_for("account_2fa_enable"))
                current_user.totp_secret = encrypt_secret(secret)
                current_user.totp_enabled = True
                db.session.commit()
                session.pop("_2fa_setup_secret", None)
                log_action(_u, "2fa_enabled", target=_u.username)
                account_notices.alert_credential_change(_u, "two-factor authentication turned on")
                # A privilege-level change: every other session ends (they signed in without the
                # factor) and this one gets a new identifier (account_guard.rotate_sessions).
                _flash_2fa_enabled(_u)
                # Show the one-time backup codes once, right now — they're never shown again.
                return no_store(render_template("backup_codes.html", codes=codes, first_time=True))
            flash("That code didn't match — check your device's time and try again.", "danger")
        # (Re)issue a pending secret for this enrolment attempt. Encrypted in the session: Flask's
        # session is a SIGNED cookie, not an encrypted one, and on success this exact value becomes
        # the account's permanent TOTP seed — so a Set-Cookie captured during enrolment (a proxy log,
        # a synced browser profile) handed over a second factor that outlives password changes and
        # "sign out everywhere". Same rule panel/core/http.py applies to generated passwords.
        secret = decrypt_secret(session.get("_2fa_setup_secret", "")) or generate_totp_secret()
        session["_2fa_setup_secret"] = encrypt_secret(secret)
        uri = totp_provisioning_uri(secret, current_user.username)
        return no_store(render_template("account_2fa.html", secret=secret, qr_svg=_qr_svg(uri)))

    @app.route("/account/profile", methods=["POST"])
    @login_required
    def account_update_profile():
        """Let someone change their OWN display name.

        Only the display name. The username is what they sign in with and what every audit row is
        filed under, so renaming stays an admin action — a person quietly renaming themselves is
        exactly the move an audit trail exists to defeat. The display name carries no such weight:
        it is a label, and having to ask an admin to fix a misspelling of your own name is the kind
        of friction that has no security story behind it.
        """
        name = (request.form.get("display_name") or "").strip()
        if len(name) > 120:                      # matches the column
            flash("Display name must be at most 120 characters.", "danger")
            return redirect(url_for("account"))
        user = current_user._get_current_object()
        old = user.display_name or ""
        user.display_name = name
        db.session.commit()
        # Worth a row: it changes what other people see next to actions in the UI.
        log_action(user, "account_display_name", target=user.username,
                   detail="%r -> %r" % (old, name))
        flash("Display name updated." if name else "Display name cleared.", "success")
        return redirect(url_for("account"))


def _register_sign_out_everywhere(app):
    """Signing out every other device."""
    @app.route("/account/sessions/revoke", methods=["POST"])
    @login_required
    def account_revoke_sessions():
        """Sign out every OTHER device, and leave this one signed in.

        The point of the button is to get an intruder out. Logging the person pressing it out too
        was pure collateral damage: it dumped them on the login page, and on a phone — where the
        password is long and the 2FA app is a tab away — that is the expensive half of the action.
        The epoch bump is still what does the work (it is the only thing that can kill a legacy
        cookie that carries no sid, and it invalidates every remember cookie ever issued); this
        device is then re-admitted with a cookie carrying the NEW epoch, same as a password change
        already does.
        """
        from panel.db.models import UserSession
        user = current_user._get_current_object()
        sid = getattr(current_user, "_sid", None)
        keep = UserSession.query.filter_by(sid=sid, user_id=user.id).first() if sid else None
        # A legacy cookie has no row to read it from, so ask the browser whether it is still
        # holding a remember token — otherwise re-issuing below quietly downgrades the login.
        remember = bool(keep.remember) if keep is not None else _has_remember_cookie()
        others = UserSession.query.filter(UserSession.user_id == user.id)
        if keep is not None:
            others = others.filter(UserSession.id != keep.id)
        n = others.delete(synchronize_session=False)
        user.auth_epoch = (user.auth_epoch or 0) + 1
        # The API token too. It is a SECOND credential for the same account, and it did not
        # answer to any of the controls that exist to take an account back: it carries no
        # auth_epoch, so a password change did not touch it, and "sign out everywhere" deleted
        # every UserSession row and left it working. app.py's note that "cookie theft is also
        # recoverable via sign out everywhere" was not true while one existed. Minting one
        # needs only a live session (no password, no 2FA), so an attacker with a stolen cookie
        # could leave themselves a key that survived the victim's whole recovery.
        user.revoke_api_token()
        db.session.commit()
        if keep is None:
            # A legacy login (cookie from before per-session tracking) has no row to keep, so give
            # this device one now — otherwise the epoch bump signs it out, the exact thing this
            # route promises not to do. And ONLY with one: the answer was ignored, so a failed
            # insert still re-issued the cookie below, with no row behind it — a session the
            # account page cannot list or revoke, minted by the button that exists to end them.
            # The revocation is committed by now; this device is left signed out, and told.
            try:
                _row_ok = _register_session(user, remember)
            except Exception:
                db.session.rollback()
                _row_ok = None
            if not _row_ok:
                log_action(user, "revoke_sessions", target=user.username,
                           detail="signed out %d other session(s); this device could not be "
                                  "re-registered and was signed out too" % n)
                logout_user()
                flash("Every other session was signed out, and so was this one — the panel could "
                      "not register this device's new session. Please sign in again.", "warning")
                return redirect(url_for("login"))
        else:
            user._sid = keep.sid
        # Re-issue THIS device's cookie against the new epoch. login_user also rewrites the
        # remember cookie when remember=True, so a "remember me" login stays remembered.
        login_user(user, remember=remember)
        plural = "" if n == 1 else "s"
        log_action(current_user, "revoke_sessions", target=user.username,
                   detail="signed out %d other session%s" % (n, plural))
        if n:
            flash(_r15e_signed_out(n), "success")
        else:
            flash("No other sessions were signed in.", "info")
        return redirect(url_for("account"))


def _register_session_list(app):
    """The session probe, and listing and revoking single sessions."""
    @app.route("/api/auth/ping")
    @login_required
    def api_auth_ping():
        """Cheapest possible "am I still signed in?" — no DB work beyond the loader that already ran.

        Pages ask on wake-up (tab refocused, restored from the back/forward cache), because a page
        restored from that cache is a photograph of a signed-in panel and cannot know on its own
        that the cookie died while it was away. When it has, @login_required answers 401 and the
        client's global handler moves the tab to the login screen.

        With ?step_up=1 it also says whether a high-risk request would now be sent to confirm the
        password (account_guard.step_up_needed): step_up_form.js asks just before a guarded form is
        sent, so it can confirm in place and lose nothing typed. Only then, because a session from
        before step-up existed costs a query to answer it.
        """
        out = {"success": True, "user": current_user.username}
        if request.args.get("step_up") == "1":
            out["step_up"] = bool(account_guard.step_up_needed())
        return jsonify(out)

    @app.route("/api/account/sessions")
    @login_required
    def api_account_sessions():
        """List the user's active login sessions (devices), newest-active first.

        The current one is flagged. Scoped to current_user — a user only ever sees or manages their
        own sessions.
        """
        from panel.db.models import UserSession, prune_expired_sessions
        # Sweep first. A row outlives its cookie by nothing — but it used to outlive it by up to
        # 45 days, which is how a session that expired last week still sat on this page labelled
        # "active", with a Revoke button that revoked something already gone.
        prune_expired_sessions(current_user.id)
        cur = getattr(current_user, "_sid", None)
        # Adopt a legacy login: a cookie issued before per-session tracking has no sid, so there's no
        # row for it — which would show a confusing empty list while you're clearly logged in. Create
        # one now and re-issue the cookie WITH the sid (skip Bearer/API clients — they have no cookie
        # session to upgrade), so this device appears and becomes individually revocable.
        if not cur and not request.headers.get("Authorization", "").startswith("Bearer "):
            if _register_session(current_user):
                # Re-issue the cookie with the new sid by rewriting the login id in the session
                # (what login_user does, without re-running its machinery on the current_user proxy).
                session["_user_id"] = current_user.get_id()
                cur = getattr(current_user, "_sid", None)
        rows = (UserSession.query.filter_by(user_id=current_user.id)
                .order_by(UserSession.last_seen.desc()).all())
        return jsonify({"sessions": [_session_entry(r, cur) for r in rows]})

    @app.route("/api/account/sessions/<int:sess_id>/revoke", methods=["POST"])
    @login_required
    def api_account_session_revoke(sess_id):
        """Revoke ONE login session by deleting its registry row.

        Scoped to current_user, so you can never revoke another account's session. If it's the
        current device, log out too.
        """
        from panel.db.models import UserSession
        row = UserSession.query.filter_by(id=sess_id, user_id=current_user.id).first()
        if not row:
            return jsonify({"success": False, "message": "Session not found."}), 404
        is_current = (row.sid == getattr(current_user, "_sid", None))
        db.session.delete(row)
        db.session.commit()
        log_action(current_user, "revoke_session", target=current_user.username,
                   detail="revoked a login session" + (" (current device)" if is_current else ""))
        if is_current:
            logout_user()
        return jsonify({"success": True, "current": is_current})


def _utc_iso(value):
    """A stored naive-UTC time as ISO text with its Z (the browser reads it as UTC), or None."""
    return (value.isoformat() + "Z") if value else None


def _session_entry(r, cur):
    """One Active Sessions row: the device, and what kind of sign-in it is and when it ends.

    `ends` and `idle_minutes` come from the row's own signs_out_at / idle_signout_minutes, the
    rule is_expired and the sweep apply, so the list cannot promise a time the server does not keep.
    """
    return {
        "id": r.id,
        "device": _session_label(r.user_agent),
        "ip": r.ip or "",
        "created": _utc_iso(r.created_at),
        "last_seen": _utc_iso(r.last_seen),
        "current": (r.sid == cur),
        "remember": bool(r.remember),
        "ends": _utc_iso(r.signs_out_at()),
        "idle_minutes": r.idle_signout_minutes(),
    }


# One POST to /login: the client address, its throttle bucket (an IPv6 client is counted by its
# /64) and the moment it arrived. The login steps below all read the same three.
_LoginAttempt = collections.namedtuple("_LoginAttempt", "ip tk now")


def _login_throttled(attempt):
    """The brute-force throttle's refusal page, or None when this client may try.

    Drops stale failures, then blocks if too many remain.
    """
    ip, _tk, now = attempt
    with _LOGIN_FAILS_LOCK:
        _prune_login_fails(now)   # keep the map bounded to recently-active IPs
        fails = [t for t in _LOGIN_FAILS.get(_tk, []) if now - t < LOGIN_WINDOW]
        # ...and a day limit for the address (account_guard.IP_DAY_FAILS): a slow spray across many
        # names stays under 8 in 5 minutes for ever.
        blocked = len(fails) >= LOGIN_MAX_FAILS or account_guard.ip_day_blocked(_tk, now)
        if not blocked:
            # RESERVE the attempt as a failure now, in the same critical section as the count.
            # The failure used to be recorded only after bcrypt, which runs in tpool and yields
            # the hub — so a burst of parallel POSTs all read "under the limit" before any of
            # them had failed, and each got a full password guess. Counting in-flight attempts
            # caps a burst at LOGIN_MAX_FAILS; login() gives the slot back unless it failed.
            fails.append(now)
        if fails:
            _LOGIN_FAILS[_tk] = fails
        else:
            _LOGIN_FAILS.pop(_tk, None)
    if not blocked:
        return None
    return _login_blocked_page(ip, _tk, now)


def _login_blocked_page(ip, _tk, now):
    """Audit (once per window) and log a refused sign-in, and show the login page with the reason."""
    with _LOGIN_FAILS_LOCK:
        _first_block = (now - _LOGIN_BLOCK_LOGGED.get(_tk, 0)) >= LOGIN_WINDOW
        if _first_block:
            _LOGIN_BLOCK_LOGGED[_tk] = now
    if _first_block:   # one audit entry per block window, not per hammering request
        _who = (request.form.get("username", "") or "").strip()[:MAX_USERNAME_LEN] or "(blank)"
        log_action(None, "login_blocked", actor=_who,
                   detail="rate-limited after %d failed attempts" % LOGIN_MAX_FAILS, success=False)
    _authlog.warning("panel login blocked from %s", _log_ip(ip))   # fail2ban: counts as a hit
    flash("Too many failed attempts. Please wait a few minutes and try again.", "danger")
    return render_template("login.html")


def _release_login_slot(attempt):
    """Give back the failure-count slot _login_throttled reserved for an attempt that did not fail."""
    with _LOGIN_FAILS_LOCK:
        fails = _LOGIN_FAILS.get(attempt.tk)
        if fails and attempt.now in fails:
            fails.remove(attempt.now)
            if not fails:
                _LOGIN_FAILS.pop(attempt.tk, None)


def _login_fail(attempt, msg, attempted=None, reason="login failed", **kw):
    """Count, log and audit one failed sign-in, and show the login page again with `msg`."""
    ip, _tk, now = attempt
    # The throttle counter already holds this attempt (_login_throttled reserved it); keeping it
    # is what counts the failure.
    g._login_failed = True
    _authlog.warning("panel login failed from %s", _log_ip(ip))    # fail2ban tails data/auth.log
    # This failure may be the one that has fail2ban ban `ip`. When it came through a
    # proxy (Tailscale Funnel, say) the firewall rule never sees that client, so the
    # panel's own gate picks the ban up in seconds rather than at the next 90 s tick.
    if request.headers.get("X-Forwarded-For"):
        _banlist.refresh_soon()
    # The ATTEMPTED username (user-controlled → sanitised + capped) goes in the User
    # column via `actor`; the reason + attempt count go in detail. log_action stores the IP.
    # Cut at the longest name an account can have, not 64: a 65-80 character superadmin name was
    # cut here, matched no account, and never raised the "admin account under attack" alert.
    who = ((attempted if attempted is not None else request.form.get("username", "")) or "").strip()
    who = who[:MAX_USERNAME_LEN] or "(blank)"
    # Attempt number = failed logins from THIS IP within the window, counted from the
    # audit log — so it keeps climbing per IP (across different usernames) and, unlike the
    # in-memory throttle counter, isn't reset by a panel restart.
    try:
        from panel.db.models import AuditLog
        _since = utcnow() - timedelta(seconds=LOGIN_WINDOW)
        _cnt = 1 + AuditLog.query.filter(AuditLog.action == "login_failed",
                                         AuditLog.ip_address == ip,
                                         AuditLog.timestamp >= _since).count()
    except Exception:
        _cnt = len(_LOGIN_FAILS.get(_tk, []))
    log_action(None, "login_failed", actor=who,
               detail="%s · attempt %d in %dm" % (reason, _cnt, LOGIN_WINDOW // 60), success=False)
    _maybe_alert_admin_bruteforce(who, ip, now)   # alert if a super admin is being targeted
    account_guard.ip_day_note(_tk, now)
    _note_lockout(who, ip, now)
    flash(msg, "danger")
    return render_template("login.html", **kw)


def _note_lockout(who, ip, now):
    """When this failure paused sign-ins for `who`: one audit row and one alert for the pause.

    A failure from a browser the account has signed in from (device_cookie) pauses that browser
    only, and the row and alert say so.
    """
    slot = g.get("_login_slot")
    pause = account_guard.account_new_lockout(who, now, slot=slot)
    if not pause:
        return
    minutes = max(1, (pause + 59) // 60)
    if account_guard.is_device_slot(slot):
        log_action(None, "login_locked", target=who, actor=who, success=False,
                   detail="sign-ins for this name from one signed-in browser paused %d min after "
                          "repeated failures (last from %s)" % (minutes, ip))
        notifications.notify("account_locked", "Sign-ins paused for an account",
                             "Sign-ins for '%s' from a browser it has signed in from are paused for "
                             "%d min after repeated failed attempts (last from %s)." % (who, minutes, ip))
        return
    log_action(None, "login_locked", target=who, actor=who, success=False,
               detail="sign-ins for this name paused %d min after repeated failures (last from %s)"
                      % (minutes, ip))
    notifications.notify("account_locked", "Sign-ins paused for an account",
                         "Sign-ins for '%s' are paused for %d min after repeated failed attempts "
                         "(last from %s)." % (who, minutes, ip))


def _login_succeed(attempt, user, remember):
    """Establish the authenticated session for `user` and redirect to a same-site ?next= path."""
    ip = attempt.ip
    # The failures before this success STAY counted. Clearing the whole bucket here let anyone
    # with an account of their own reset the throttle between guesses at somebody else's password
    # (7 guesses, one real sign-in, repeat) from one address, forever. This attempt's own reserved
    # slot is given back by login()'s finally.
    # Drop everything the pre-login session carried before establishing the
    # authenticated one. Session fixation: an attacker who can get a victim to browse
    # with a cookie value of the attacker's choosing otherwise ends up holding a
    # cookie that is now authenticated as the victim. SESSION_PROTECTION="strong" and
    # the per-login server-side sid already make that hard; starting from an empty
    # session makes the whole class impossible rather than merely difficult.
    # The chosen UI language is deliberately carried across — it is set before login
    # on the login page itself, and losing it on sign-in is a visible bug.
    _lang = session.get("lang")
    session.clear()
    if _lang:
        session["lang"] = _lang
    session.permanent = True   # so PERMANENT_SESSION_LIFETIME applies
    # Server-side row (sets user._sid) BEFORE login_user, so get_id embeds the sid. A login whose
    # row could not be written is REFUSED, not issued without one: the "<id>:<epoch>" cookie that
    # fell out of it never expired server-side, never appeared on the account page, and was bound
    # to no client (see _register_session). Not a failed login either — the password was right —
    # so nothing is counted against the throttle; the person is simply asked to try again.
    if not _register_session(user, remember):
        flash("Signing in could not be completed just now — please try again in a moment.",
              "danger")
        return render_template("login.html")
    login_user(user, remember=remember)
    # A fresh device cookie for this browser (a new nonce each sign-in): from now on the name's
    # sign-in pause does not hold it (device_cookie, account_guard).
    _uid = user.id
    after_this_request(lambda resp: device_cookie.issue(resp, _uid))
    # The client this session belongs to, for "strong" protection (auth.py
    # _session_binding_ok) — flask-login's own strong mode never fires on a permanent
    # session, and this one is permanent.
    session["_bind"] = session_fingerprint()
    account_guard.mark_authenticated()      # the proof step-up re-authentication counts from
    _since = user.last_login
    user.last_login = utcnow()
    db.session.commit()
    log_action(user, "login", detail=f"User logged in from {ip}")
    account_notices.flash_changes_since(user, _since)
    if user.is_superadmin:
        notifications.notify("admin_login", "Super admin signed in",
                             "%s signed in from %s" % (user.username, ip))
    # Open-redirect-safe: same-site relative paths only. Reject absolute URLs,
    # protocol-relative "//host", an embedded scheme, and backslash tricks like
    # "/\\host" (some browsers normalise the backslash to "/", making it "//host").
    # Same shape as CodeQL #375: checking a value and passing the SAME object through
    # leaves it tainted to a tracker, so the accepted path is REBUILT here out of what
    # the pattern matched. A same-site path is "/" plus segments of an explicit safe
    # charset — which excludes the backslash, the second leading slash and the scheme
    # colon that the four rejected cases rely on.
    # The path group must not nest quantifiers. It was `(?:[seg]+/?)*`: the optional
    # slash let a run of segment characters split into segments in 2^n ways, so
    # "/"+"a"*30+"!" backtracked for ~50s — on the one eventlet hub, freezing every
    # page, console and poller for anyone holding any valid login. `(?:[seg]+/)*[seg]*`
    # accepts exactly the same strings (no leading "/", no "//") and each "/" fixes
    # the split, so it runs in linear time.
    _raw = request.args.get("next", "/")
    _m = re.fullmatch(
        r"/(?P<path>(?:[A-Za-z0-9._~\-]+/)*[A-Za-z0-9._~\-]*)"
        r"(?:\?(?P<q>[A-Za-z0-9._~\-=&%]*))?",
        _raw or "")
    _segs = [s for s in (_m.group("path").split("/") if _m else []) if s]
    next_page = "/" + "/".join(_segs)
    if _m and _m.group("q"):
        # Rebuilt too, from the same matched-and-restricted charset.
        next_page += "?" + _m.group("q")
    # nosemgrep: python.flask.security.audit.open-redirect.flask-open-redirect
    # The guard is the four lines directly above: the value must start with a single
    # "/" and may contain no backslash and no scheme, which leaves same-site relative
    # paths and nothing else. Semgrep does not model an inline check as a sanitiser —
    # it only sees request data reaching redirect(). Covered by the "?next= must stay
    # on this site" checks in tests/smoke_test.py, which drive the real endpoint with
    # an absolute URL, "//host", an embedded scheme and the backslash trick.
    return redirect(next_page)


def _login_second_factor(attempt, pending_id):
    """Step 2: the 2FA code (or a backup code) for a login that passed the password step."""
    if attempt.now - session.get("_2fa_at", 0) > 300:   # prompt expires after 5 min
        session.pop("_2fa_pending", None)
        flash("The two-factor prompt expired — please log in again.", "danger")
        return render_template("login.html")
    u = db.session.get(User, pending_id)
    entered = request.form.get("totp_code", "")
    if u and u.is_active and u.totp_enabled:
        # A per-ACCOUNT budget, the one every other live-code check spends (reauth_reserve). The
        # only limit here was _login_throttled's, per address, and the pending login lives in the
        # signed cookie, bound to no address: replayed from an IPv6 /48 (65,536 buckets of 8) it
        # bought half a million guesses per five-minute prompt, about three valid codes in a
        # million each. A wrong code keeps its slot; a code that signs in gives it back.
        stamp = reauth_reserve(u)
        if stamp is None:
            # Out of guesses: drop the pending login too, so the next try has to pass the
            # password step again (under the same per-account cap).
            session.pop("_2fa_pending", None)
            return _login_fail(attempt, REAUTH_BLOCKED_MSG, attempted=u.username,
                               reason="2FA attempts throttled")
        by_code = _login_totp_code(attempt, u, entered, stamp)
        if by_code is not None:
            return by_code
        # Fall back to a one-time backup code (for a lost authenticator) — only for
        # an entry shaped like one: trying them costs a password hash per stored code, and a
        # mistyped six-digit TOTP can never match.
        if backup_code_shaped(entered) and u.use_backup_code(entered):
            db.session.commit()
            log_action(u, "2fa_backup_code_used", target=u.username,
                       detail=f"{u.backup_codes_remaining} codes left")
            reauth_release(u, stamp)
            return _login_succeed(attempt, u, bool(session.get("_2fa_remember")))
    return _login_fail(attempt, "Invalid authentication code or backup code.",
                       attempted=(u.username if u else None), reason="wrong 2FA code", two_factor=True)


def _login_totp_code(attempt, u, entered, stamp=None):
    """Sign `u` in on a valid, unspent authenticator code; None when `entered` is not a valid one.

    `stamp` is the slot _login_second_factor reserved; it is given back only on a sign-in.
    """
    _step = verify_totp_step(u.totp_secret_plain, entered)
    if _step is None:
        return None
    # Single-use: a TOTP code is valid for ~90s (its step plus one either side
    # for skew), so accepting it on "is it valid" alone lets a code that was
    # observed once be replayed for the rest of that window. Refuse any step
    # already spent — committed BEFORE the session is granted so a crash
    # between the two can't leave the step unspent.
    #
    # The spend is a compare-and-swap in the database, not the Python compare below followed by
    # an assignment. That pair was a read-then-write: two POSTs carrying the same code could both
    # read the old step before either committed, and both sign in — one code, two sessions, which
    # is exactly what single-use exists to prevent. Today nothing between the read and the commit
    # yields to another greenlet, so the one eventlet process happens to serialise them; that is
    # a property of which calls sit in between (and of there being one worker), not of this code.
    # The conditional UPDATE is decided by SQLite under its write lock, so exactly one wins however
    # the requests interleave — the shape _claim_invite uses for the same reason.
    if _step <= (u.last_totp_step or 0):
        return _login_totp_replayed(attempt, u)
    if not spend_totp_step(u, _step):
        db.session.rollback()
        return _login_totp_replayed(attempt, u)   # another request spent this step first
    db.session.commit()
    reauth_release(u, stamp)
    return _login_succeed(attempt, u, bool(session.get("_2fa_remember")))


def _login_totp_replayed(attempt, u):
    """Refuse an authenticator code whose timestep has already been spent."""
    return _login_fail(attempt, "That code has already been used — wait for your "
                                "authenticator to show the next one.",
                       attempted=u.username, reason="replayed 2FA code", two_factor=True)


def _login_reserve(attempt, username):
    """(the named account or None, its throttle slot, None); or (None, None, the refusal) while paused.

    Counted per NAME as well as per address (account_guard), before the hash runs. A paused name is
    refused with the address throttle's own sentence and no password check at all, so the answer
    says nothing about the account, and a guess sent during the pause is not even tried. A browser
    this account has signed in from (a valid device cookie) is counted on its own and not held by
    the name's pause, so wrong guesses from elsewhere cannot lock the owner out.
    """
    user = User.query.filter_by(username=username).first()
    device = device_cookie.presented_nonce(user) if user and user.is_active else None
    slot, _left = account_guard.account_reserve(username, attempt.now, device=device)
    if slot is None:
        g._login_failed = True
        _authlog.warning("panel login blocked from %s", _log_ip(attempt.ip))   # fail2ban: a hit
        flash("Too many failed attempts. Please wait a few minutes and try again.", "danger")
        return None, None, render_template("login.html")
    g._login_slot = slot          # _note_lockout: whose pause a failure here can start
    return user, slot, None


def _login_password(attempt):
    """Step 1: username and password."""
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    remember = request.form.get("remember") == "on"

    user, slot, refused = _login_reserve(attempt, username)
    if refused is not None:
        return refused
    if user and user.is_active and check_password(password, user.password_hash):
        account_guard.account_release(slot)
        return _login_password_ok(attempt, user, password, remember)
    # For a missing/inactive user we skipped the (slow) hash compare above;
    # run a dummy one now so response time doesn't reveal whether the account
    # exists (username-enumeration by timing).
    if not (user and user.is_active):
        dummy_password_check(password)
    # Reason for the audit log only — the flash message below stays generic so a real
    # attacker still can't tell existing usernames from wrong passwords (no enumeration).
    _reason = ("no such user" if not user
               else "account disabled" if not user.is_active
               else "wrong password")
    return _login_fail(attempt, "Invalid username or password.", reason=_reason)


def _login_password_ok(attempt, user, password, remember):
    """The password was right: prompt for the second factor, or sign in when there is none."""
    # Re-encode a legacy hash now that we have the plaintext in hand and know it is
    # right. NOT set_password(): the password did not change, so this must not push a
    # hash into the reuse history or touch auth_epoch — nobody should be signed out,
    # or told they cannot reuse their own password, because of a format upgrade.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        db.session.commit()
    # `totp_enabled` alone, NOT "enabled and the secret decrypts". totp_secret_plain
    # returns "" whenever decryption fails (a cred_key that was not carried across a
    # hand-rolled migration, a truncated key file), and the old condition then fell
    # straight through to _succeed — granting a full session on the password alone for
    # an account that has 2FA switched on, silently. A second factor that turns itself
    # off when a file is unreadable is not a second factor. Backup codes are
    # hashes in their own column and do not depend on cred_key, so the prompt below is
    # still answerable and nobody is locked out.
    if user.totp_enabled:
        session["_2fa_pending"] = user.id
        session["_2fa_at"] = attempt.now
        session["_2fa_remember"] = remember
        return render_template("login.html", two_factor=True)
    return _login_succeed(attempt, user, remember)


def _r15e_signed_out(n):
    """The "Signed out of N other session(s)." flash, in the viewer's language.

    One sentence per count form, as the browser's tfn has: a spliced "s" is English's plural, not
    Spanish's or French's.
    """
    if n == 1:
        return i18n.tr("Signed out of {n} other session. This device is still signed in.", n=n)
    return i18n.tr("Signed out of {n} other sessions. This device is still signed in.", n=n)
