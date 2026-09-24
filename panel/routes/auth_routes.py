"""Login, logout, two-factor and the session lifecycle.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
import re
from contextlib import (suppress)
from flask import (flash, jsonify, redirect, render_template, request, session, url_for)
from flask_login import (current_user, login_required, login_user, logout_user)
from panel.core import (i18n)
from panel.core.clock import (utcnow)
from panel.core.config import (encrypt_secret)
from panel.db.models import (User, db)
from panel.security.auth import (hash_password, needs_rehash, check_password, client_ip, dummy_password_check,
    generate_backup_codes, generate_totp_secret, log_action, totp_provisioning_uri,
    session_fingerprint, verify_totp_step)
from panel.services import (notifications)
import time
from app import (LOGIN_MAX_FAILS, LOGIN_WINDOW, _LOGIN_BLOCK_LOGGED, _LOGIN_FAILS,
    _LOGIN_FAILS_LOCK, _authlog, _log, _log_ip, _maybe_alert_admin_bruteforce,
    _has_remember_cookie, _prune_login_fails, _qr_svg, _register_session, _session_label)


def register(app):
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect("/")

        if request.method == "POST":
            ip = client_ip() or "unknown"
            now = time.time()
            # Brute-force throttle: drop stale failures, block if too many remain.
            with _LOGIN_FAILS_LOCK:
                _prune_login_fails(now)   # keep the map bounded to recently-active IPs
                fails = [t for t in _LOGIN_FAILS.get(ip, []) if now - t < LOGIN_WINDOW]
                if fails:
                    _LOGIN_FAILS[ip] = fails
                else:
                    _LOGIN_FAILS.pop(ip, None)
                blocked = len(fails) >= LOGIN_MAX_FAILS
            if blocked:
                with _LOGIN_FAILS_LOCK:
                    _first_block = (now - _LOGIN_BLOCK_LOGGED.get(ip, 0)) >= LOGIN_WINDOW
                    if _first_block:
                        _LOGIN_BLOCK_LOGGED[ip] = now
                if _first_block:   # one audit entry per block window, not per hammering request
                    _who = (request.form.get("username", "") or "").strip()[:64] or "(blank)"
                    log_action(None, "login_blocked", actor=_who,
                               detail="rate-limited after %d failed attempts" % LOGIN_MAX_FAILS, success=False)
                _authlog.warning("panel login blocked from %s", _log_ip(ip))   # fail2ban: counts as a hit
                flash("Too many failed attempts. Please wait a few minutes and try again.", "danger")
                return render_template("login.html")

            def _fail(msg, attempted=None, reason="login failed", **kw):
                with _LOGIN_FAILS_LOCK:
                    _LOGIN_FAILS.setdefault(ip, []).append(now)   # throttle counter (resets on success)
                _authlog.warning("panel login failed from %s", _log_ip(ip))    # fail2ban tails data/auth.log
                # The ATTEMPTED username (user-controlled → sanitised + capped) goes in the User
                # column via `actor`; the reason + attempt count go in detail. log_action stores the IP.
                who = ((attempted if attempted is not None else request.form.get("username", "")) or "").strip()[:64] or "(blank)"
                # Attempt number = failed logins from THIS IP within the window, counted from the
                # audit log — so it keeps climbing per IP (across different usernames) and, unlike the
                # in-memory throttle counter, isn't reset by a successful login or a panel restart.
                try:
                    from panel.db.models import AuditLog
                    from datetime import timedelta
                    _since = utcnow() - timedelta(seconds=LOGIN_WINDOW)
                    _cnt = 1 + AuditLog.query.filter(AuditLog.action == "login_failed",
                                                     AuditLog.ip_address == ip,
                                                     AuditLog.timestamp >= _since).count()
                except Exception:
                    _cnt = len(_LOGIN_FAILS.get(ip, []))
                log_action(None, "login_failed", actor=who,
                           detail="%s · attempt %d in %dm" % (reason, _cnt, LOGIN_WINDOW // 60), success=False)
                _maybe_alert_admin_bruteforce(who, ip, now)   # alert if a super admin is being targeted
                flash(msg, "danger")
                return render_template("login.html", **kw)

            def _succeed(user, remember):
                with _LOGIN_FAILS_LOCK:
                    _LOGIN_FAILS.pop(ip, None)   # clear on success
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
                _register_session(user, remember)   # server-side row (sets user._sid) BEFORE
                login_user(user, remember=remember)   # login_user, so get_id embeds the sid
                # The client this session belongs to, for "strong" protection (auth.py
                # _session_binding_ok) — flask-login's own strong mode never fires on a permanent
                # session, and this one is permanent.
                session["_bind"] = session_fingerprint()
                user.last_login = utcnow()
                db.session.commit()
                log_action(user, "login", detail=f"User logged in from {ip}")
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

            # ── Step 2: the 2FA code for a login that passed the password step ──
            pending_id = session.get("_2fa_pending")
            if pending_id and request.form.get("totp_code"):
                if now - session.get("_2fa_at", 0) > 300:   # prompt expires after 5 min
                    session.pop("_2fa_pending", None)
                    flash("The two-factor prompt expired — please log in again.", "danger")
                    return render_template("login.html")
                u = db.session.get(User, pending_id)
                entered = request.form.get("totp_code", "")
                if u and u.is_active and u.totp_enabled:
                    _step = verify_totp_step(u.totp_secret_plain, entered)
                    if _step is not None:
                        # Single-use: a TOTP code is valid for ~90s (its step plus one either side
                        # for skew), so accepting it on "is it valid" alone lets a code that was
                        # observed once be replayed for the rest of that window. Refuse any step
                        # already spent — committed BEFORE the session is granted so a crash
                        # between the two can't leave the step unspent.
                        if _step <= (u.last_totp_step or 0):
                            return _fail("That code has already been used — wait for your "
                                         "authenticator to show the next one.",
                                         attempted=u.username, reason="replayed 2FA code",
                                         two_factor=True)
                        u.last_totp_step = _step
                        db.session.commit()
                        return _succeed(u, bool(session.get("_2fa_remember")))
                    # Fall back to a one-time backup code (for a lost authenticator).
                    if u.use_backup_code(entered):
                        db.session.commit()
                        log_action(u, "2fa_backup_code_used", target=u.username,
                                   detail=f"{u.backup_codes_remaining} codes left")
                        return _succeed(u, bool(session.get("_2fa_remember")))
                return _fail("Invalid authentication code or backup code.",
                             attempted=(u.username if u else None), reason="wrong 2FA code", two_factor=True)

            # ── Step 1: username + password ──
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            remember = request.form.get("remember") == "on"

            user = User.query.filter_by(username=username).first()
            if user and user.is_active and check_password(password, user.password_hash):
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
                # off when a file is unreadable is not a second factor. Backup codes are bcrypt
                # hashes in their own column and do not depend on cred_key, so the prompt below is
                # still answerable and nobody is locked out.
                if user.totp_enabled:
                    session["_2fa_pending"] = user.id
                    session["_2fa_at"] = now
                    session["_2fa_remember"] = remember
                    return render_template("login.html", two_factor=True)
                return _succeed(user, remember)
            # For a missing/inactive user we skipped the (slow) bcrypt compare above;
            # run a dummy one now so response time doesn't reveal whether the account
            # exists (username-enumeration by timing).
            if not (user and user.is_active):
                dummy_password_check(password)
            # Reason for the audit log only — the flash message below stays generic so a real
            # attacker still can't tell existing usernames from wrong passwords (no enumeration).
            _reason = ("no such user" if not user
                       else "account disabled" if not user.is_active
                       else "wrong password")
            return _fail("Invalid username or password.", reason=_reason)

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
                _u = current_user._get_current_object()
                _u.auth_epoch = (_u.auth_epoch or 0) + 1
                db.session.commit()
                revoked = True
            except Exception:
                db.session.rollback()
                with suppress(Exception):
                    _log.warning("logout: the auth_epoch fallback failed too", exc_info=True)
        logout_user()
        if revoked:
            flash("You have been logged out.", "info")
        else:
            flash("Signed out on this device, but the server could not revoke the session — "
                  "change your password to revoke it everywhere.", "warning")
        return redirect("/login")


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

        def _refused(why):
            """Refuse, and SAY SO in the audit log.

            log_action fired on the mint alone, so the one thing this gate produces that is worth
            watching — somebody in a borrowed session trying passwords against it, which is now
            the only way past it — left no trace anywhere, while the mint they were aiming at
            left a tidy one. A gate whose refusals are invisible tells you afterwards that
            nothing happened, which is exactly what it looks like when something did. Recorded
            with success=False, the shape delete_group / uninstall_server / send_command already
            use, so it reads as a refusal in the audit list rather than as a mint.

            Recorded but NOT rate-limited, and that is a decision: the same unthrottled password
            oracle already sits behind account_change_password and account_2fa_disable, which any
            session holder can hit, so a limit on this route alone moves the guessing one route
            over instead of closing it — while adding a way to lock somebody out of minting their
            own token. Each attempt costs a bcrypt compare, which is its own floor on the rate. A
            real limit belongs on all three at once, beside the login and bearer-token throttles
            in panel/security/auth.py; what was missing here was the record of the attempt, and
            that is what this is."""
            log_action(u, "api_token_generate", target=u.username, detail=why, success=False)
            return redirect(url_for("account"))

        if not check_password(request.form.get("password", ""), u.password_hash):
            flash("Password incorrect — no API token was minted.", "danger")
            return _refused("wrong password")
        # Checked LAST, and in this order, for the reasons account_2fa_disable spells out: a
        # one-time backup code must never be spent on an otherwise-invalid request, and a TOTP
        # code stays valid for ~90s, so verify_totp_STEP plus the last_totp_step comparison is
        # what makes an observed code single-use rather than replayable for the rest of its window.
        code = (request.form.get("totp_code") or "").strip()
        if u.totp_enabled:
            ok_2fa = False
            _step = verify_totp_step(u.totp_secret_plain, code) if u.totp_secret_plain else None
            if _step is not None:
                if _step <= (u.last_totp_step or 0):
                    flash("That code has already been used — wait for your authenticator to show "
                          "the next one.", "danger")
                    return _refused("replayed authenticator code")
                u.last_totp_step = _step
                ok_2fa = True
            elif u.use_backup_code(code):
                ok_2fa = True
            if not ok_2fa:
                flash("That authenticator code didn't match — no API token was minted.", "danger")
                return _refused("wrong authenticator code")
        token = u.generate_api_token()
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
        # Render directly (not a redirect) so the plaintext token is shown exactly once and never
        # stored in the session cookie.
        return render_template("account.html", languages=i18n.LANGUAGES, new_token=token)

    @app.route("/account/api-token/revoke", methods=["POST"])
    @login_required
    def account_api_token_revoke():
        """Deliberately ungated, unlike the mint above. Revoking takes a credential AWAY, so the
        worst a stolen session can do here is inconvenience the owner — and a gate would be a
        reason not to press this in the one situation it exists for."""
        current_user.revoke_api_token()
        db.session.commit()
        log_action(current_user, "api_token_revoke", target=current_user.username)
        flash("API token revoked.", "success")
        return redirect(url_for("account"))

    @app.route("/set-language/<lang>", methods=["GET", "POST"])
    def set_language(lang):
        """Switch the UI language. Saved to the session, and to the user's profile when logged in
        (so it follows them across devices). Usable pre-login too. The switcher calls this with
        ?ajax=1 and then reloads the current page itself, so we never redirect to a user-supplied
        URL (no open-redirect surface); a plain GET just lands on the dashboard.

        The PROFILE write needs POST. csrf.protect() is a no-op on safe methods, so while this was
        GET-only any cross-site page could permanently change a logged-in admin's stored UI
        language with <img src="https://panel/set-language/zh">. The session half stays on GET —
        it is per-session and transient, and the switcher on the login page has no token to send —
        but nothing cross-site gets to write the user row."""
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
        """The {english: translated} catalog for a language, so the switcher can re-translate the page
        live without a reload. Public (the switcher is on the login page too) and non-sensitive — it's
        only UI strings, the same map already embedded in every rendered page for the current language."""
        resp = jsonify(i18n.catalog(i18n.normalize_lang(lang)))
        resp.headers["Cache-Control"] = "public, max-age=300"   # catalogs change only on deploy
        return resp

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
            if not check_password(request.form.get("password", ""), _u.password_hash):
                flash("Password incorrect — two-factor authentication was not enabled.", "danger")
                # Back to this page, not /account: the pending secret is still in the session, so
                # the QR they have already scanned stays valid and they can simply try again.
                return redirect(url_for("account_2fa_enable"))
            secret = session.get("_2fa_setup_secret", "")
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
                current_user.totp_secret = encrypt_secret(secret)
                current_user.totp_enabled = True
                current_user.last_totp_step = _enrol_step      # spend it, in the same commit
                codes = generate_backup_codes()
                current_user.set_backup_codes(codes)
                db.session.commit()
                session.pop("_2fa_setup_secret", None)
                log_action(current_user, "2fa_enabled", target=current_user.username)
                flash("Two-factor authentication is now enabled.", "success")
                # Show the one-time backup codes once, right now — they're never shown again.
                return render_template("backup_codes.html", codes=codes, first_time=True)
            flash("That code didn't match — check your device's time and try again.", "danger")
        # (Re)issue a pending secret for this enrolment attempt.
        secret = session.get("_2fa_setup_secret") or generate_totp_secret()
        session["_2fa_setup_secret"] = secret
        uri = totp_provisioning_uri(secret, current_user.username)
        return render_template("account_2fa.html", secret=secret, qr_svg=_qr_svg(uri))

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
            # route promises not to do.
            _register_session(user, remember)
        else:
            user._sid = keep.sid
        # Re-issue THIS device's cookie against the new epoch. login_user also rewrites the
        # remember cookie when remember=True, so a "remember me" login stays remembered.
        login_user(user, remember=remember)
        plural = "" if n == 1 else "s"
        log_action(current_user, "revoke_sessions", target=user.username,
                   detail="signed out %d other session%s" % (n, plural))
        if n:
            flash("Signed out of %d other session%s. This device is still signed in."
                  % (n, plural), "success")
        else:
            flash("No other sessions were signed in.", "info")
        return redirect(url_for("account"))

    @app.route("/api/auth/ping")
    @login_required
    def api_auth_ping():
        """Cheapest possible "am I still signed in?" — no DB work beyond the loader that already
        ran. Pages ask on wake-up (tab refocused, restored from the back/forward cache), because a
        page restored from that cache is a photograph of a signed-in panel and cannot know on its
        own that the cookie died while it was away. When it has, @login_required answers 401 and
        the client's global handler moves the tab to the login screen."""
        return jsonify({"success": True, "user": current_user.username})

    @app.route("/api/account/sessions")
    @login_required
    def api_account_sessions():
        """This user's active login sessions (devices), newest-active first, with the current one
        flagged. Scoped to current_user — a user only ever sees or manages their own sessions."""
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
        return jsonify({"sessions": [{
            "id": r.id,
            "device": _session_label(r.user_agent),
            "ip": r.ip or "",
            "created": (r.created_at.isoformat() + "Z") if r.created_at else None,
            "last_seen": (r.last_seen.isoformat() + "Z") if r.last_seen else None,
            "current": (r.sid == cur),
        } for r in rows]})

    @app.route("/api/account/sessions/<int:sess_id>/revoke", methods=["POST"])
    @login_required
    def api_account_session_revoke(sess_id):
        """Revoke ONE login session by deleting its registry row (scoped to current_user, so you can
        never revoke another account's session). If it's the current device, log out too."""
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
