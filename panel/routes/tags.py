"""Server tags: install-wide labels for grouping, bulk actions and alert routing.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (flash, jsonify, redirect, request, url_for)
from flask_login import (current_user, login_required, login_user)
from panel.core.config import (update_config)
from panel.db.models import (db)
from panel.db.prefs import (_clean_panel_map)
from panel.security.auth import (_can_edit_tags, check_password, get_game, get_user_servers,
    hash_password, log_action, server_access_required, verify_totp_step)
from panel.core.http import (_json_body, _json_str, _log_and_generic)
from panel.core.validation import (_valid_hex_color, password_problem)
from app import (_has_remember_cookie, _log, _register_session, _tag_json)


def register(app):
    @app.route("/api/tags")
    @login_required
    def api_tags_list():
        """Every tag, with the servers carrying it that the CALLER can access. Readable by any
        signed-in user — tags are how the UI groups and filters.

        The server ids were every server's. The UI only uses them to decorate rows the caller can
        already see, but the response is the caller's to read, and it listed the ids of servers
        they cannot access and which tags those carry (an inventory server_access_required's
        blanket 403 is careful not to give)."""
        from panel.db.models import ServerTag
        from sqlalchemy.orm import selectinload
        tags = ServerTag.query.options(selectinload(ServerTag.servers)).order_by(ServerTag.name).all()
        out = [_tag_json(t) for t in tags]
        if not current_user.is_superadmin:
            visible = {gs.id for gs in get_user_servers(current_user)}
            for t in out:
                t["server_ids"] = [i for i in t["server_ids"] if i in visible]
        return jsonify({"success": True, "tags": out})

    @app.route("/api/tags", methods=["POST"])
    @login_required
    def api_tags_create():
        """Create a tag. The name's charset is enforced by the model (@validates), so a bad one
        raises before it can be stored — caught here and returned as a 400 rather than a 500."""
        from panel.db.models import ServerTag
        if not _can_edit_tags():
            return jsonify({"success": False, "message": "Permission denied"}), 403
        from panel.db.models import TAG_NAME_RE, TAG_NAME_HELP
        data = _json_body()
        name = _json_str(data, "name")
        if not name:
            return jsonify({"success": False, "message": "A tag needs a name."}), 400
        # Check the shared rule here so the caller gets a helpful, FIXED message. The model's
        # validator still guards the data layer, but its exception text is never echoed back —
        # returning str(exc) is how internals leak into an API response.
        if not TAG_NAME_RE.match(name):
            return jsonify({"success": False, "message": TAG_NAME_HELP}), 400
        if ServerTag.query.filter(db.func.lower(ServerTag.name) == name.lower()).first():
            return jsonify({"success": False, "message": "A tag with that name already exists."}), 409
        try:
            tag = ServerTag(name=name, color=_valid_hex_color(data.get("color")),
                            notify=bool(data.get("notify", True)),
                            created_by=current_user.username)
            db.session.add(tag)
            db.session.commit()
        except ValueError:
            # Unreachable for the name (checked above); still handled so a validator added to
            # another column later cannot turn a bad request into a 500.
            db.session.rollback()
            return jsonify({"success": False, "message": TAG_NAME_HELP}), 400
        except Exception:
            db.session.rollback()
            return jsonify({"success": False, "message": _log_and_generic("create tag failed")}), 500
        log_action(current_user, "tag_create", target=tag.name)
        return jsonify({"success": True, "tag": _tag_json(tag)})

    @app.route("/api/tags/<int:tag_id>/delete", methods=["POST"])
    @login_required
    def api_tags_delete(tag_id):
        """Delete a tag. Its association rows go too — SQLAlchemy clears the secondary table for a
        deleted parent, and nothing here relies on database FK enforcement (this app never sets
        PRAGMA foreign_keys, so an orphan would otherwise outlive the tag and get inherited by a
        future server reusing the rowid)."""
        from panel.db.models import ServerTag
        if not _can_edit_tags():
            return jsonify({"success": False, "message": "Permission denied"}), 403
        tag = db.session.get(ServerTag, tag_id)
        if not tag:
            return jsonify({"success": False, "message": "Tag not found."}), 404
        name = tag.name
        try:
            tag.servers = []          # drop the association rows explicitly, then the tag itself
            db.session.delete(tag)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"success": False, "message": _log_and_generic("delete tag failed")}), 500
        log_action(current_user, "tag_delete", target=name)
        return jsonify({"success": True})

    @app.route("/api/server/<int:server_id>/tags", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_tags_set(server_id):
        """Replace one server's tag set. @server_access_required covers visibility (server_id is a
        URL kwarg here, so the decorator applies), and MANAGE_SERVERS is still required to write."""
        from panel.db.models import ServerTag
        if not _can_edit_tags():
            return jsonify({"success": False, "message": "Permission denied"}), 403
        gs = get_game(server_id)
        data = _json_body()
        raw = data.get("tag_ids")
        if not isinstance(raw, list):
            return jsonify({"success": False, "message": "tag_ids must be a list."}), 400
        ids = []
        for ident in raw[:100]:
            try:
                ids.append(int(ident))
            except (TypeError, ValueError):
                continue
        try:
            # Assign through the relationship, never a raw INSERT: unknown ids are dropped, and a
            # repeated id can't create a duplicate association row.
            gs.tags = [t for t in (db.session.get(ServerTag, i) for i in dict.fromkeys(ids)) if t]
            db.session.commit()
        except Exception:
            db.session.rollback()
            return jsonify({"success": False, "message": _log_and_generic("set server tags failed")}), 500
        log_action(current_user, "server_tags_set", target=gs.name,
                   detail="tags: " + (", ".join(t.name for t in gs.tags) or "(none)"))
        return jsonify({"success": True, "tags": [{"id": t.id, "name": t.name,
                                                   "color": t.color or ""} for t in gs.tags]})

    @app.route("/api/account/ui-order", methods=["POST"])
    @login_required
    def api_account_ui_order():
        """Save THIS user's preferred dashboard order. Scoped to current_user: the body carries ids
        only and never a user id, so there is no way to write someone else's layout.

        Ids the caller can't see, ids that no longer exist, and non-numeric junk are DROPPED rather
        than rejected — a stale tab or a hand-edited body should still produce a sane layout, and a
        rejection here would leave the user's screen and their saved order disagreeing.

        Deliberately NOT audit-logged: log_action commits its own session and /logs rebuilds its
        filter dropdowns with SELECT DISTINCT over the whole table, so logging a preference nobody
        can be attacked through would cost every reorder a second commit. set_language does the
        same. The reset endpoint below IS logged, because it discards state.
        """
        try:
            data = _json_body()
            visible = get_user_servers(current_user)
            ok_hosts = {gs.remote_id for gs in visible}
            ok_servers = {gs.id for gs in visible}

            def _clean(raw, allowed):
                """Ids from `raw`, keeping only ones in `allowed`, deduped, order preserved."""
                out, seen = [], set()
                for ident in (raw or [])[:200]:
                    try:
                        num = int(ident)
                    except (TypeError, ValueError):
                        continue
                    if num in allowed and num not in seen:
                        seen.add(num)
                        out.append(num)
                return out

            saved = []
            if isinstance(data.get("host_order"), list):
                current_user.set_ui_pref("host_order", _clean(data["host_order"], ok_hosts))
                saved.append("host_order")
            if isinstance(data.get("server_order"), dict):
                per_host = {}
                for host_id, ids in list(data["server_order"].items())[:100]:
                    if not isinstance(ids, list):
                        continue
                    try:
                        host_key = str(int(host_id))
                    except (TypeError, ValueError):
                        continue
                    if int(host_key) in ok_hosts:
                        per_host[host_key] = _clean(ids, ok_servers)
                current_user.set_ui_pref("server_order", per_host)
                saved.append("server_order")
            # MERGE regions rather than replacing the whole map: a page only ever knows its own
            # regions (the dashboard sends dash_tiles, a server page sends detail_console), so a
            # whole-map write from one page would silently delete the other page's layout.
            stored = current_user.get_ui_prefs()
            declared = _clean_panel_map(data.get("declared"))
            for field in ("panels", "hidden"):
                if field not in data:
                    continue
                merged = dict(stored.get(field) or {})
                for region, keys in _clean_panel_map(data.get(field)).items():
                    # Within a region, keep keys this page could not have sent. server_detail's
                    # gated panels (commands, content) are absent on servers that don't offer them,
                    # and dropping them here would erase that placement for every OTHER server.
                    known = declared.get(region)
                    if known is not None:
                        keys = keys + [k for k in (merged.get(region) or [])
                                       if k not in keys and k not in known]
                    merged[region] = keys
                current_user.set_ui_pref(field, dict(list(merged.items())[:20]))
                saved.append(field)
            if not saved:
                return jsonify({"success": False, "message": "Nothing to save."}), 400
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                _log.debug("ui-order commit failed", exc_info=True)
                return jsonify({"success": False, "message": "Could not save your layout."}), 500
            return jsonify({"success": True, "saved": saved})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("save layout failed")}), 500

    @app.route("/api/settings/ui-default", methods=["POST"])
    @login_required
    def api_ui_default_publish():
        """Publish THIS superadmin's current layout as the install default, so new accounts (and
        anyone who resets) land on the house arrangement instead of bare defaults.

        Takes no body on purpose: it copies the caller's own saved layout, which they arranged by
        using the same controls as everyone else. That means there is nothing to validate here that
        was not already validated on the way in, and no way to publish a layout nobody has seen."""
        if not current_user.is_superadmin:
            return jsonify({"success": False, "message": "Permission denied"}), 403
        try:
            mine = current_user.get_ui_prefs()
            if not mine:
                return jsonify({"success": False,
                                "message": "Arrange your own layout first, then publish it."}), 400
            update_config(lambda cfg: cfg.__setitem__("default_ui_prefs", mine))
        except Exception:
            return jsonify({"success": False,
                            "message": _log_and_generic("publish default layout failed")}), 500
        log_action(current_user, "ui_default_publish", target="install",
                   detail="published a default dashboard layout for all users")
        return jsonify({"success": True})

    @app.route("/api/settings/ui-default/clear", methods=["POST"])
    @login_required
    def api_ui_default_clear():
        """Drop the install default so everyone falls back to the layout the templates ship."""
        if not current_user.is_superadmin:
            return jsonify({"success": False, "message": "Permission denied"}), 403
        try:
            update_config(lambda cfg: cfg.pop("default_ui_prefs", None))
        except Exception:
            return jsonify({"success": False,
                            "message": _log_and_generic("clear default layout failed")}), 500
        log_action(current_user, "ui_default_clear", target="install",
                   detail="removed the install default dashboard layout")
        return jsonify({"success": True})

    @app.route("/api/account/ui-order/reset", methods=["POST"])
    @login_required
    def api_account_ui_order_reset():
        """Drop this user's saved order so the default layout applies again. A separate endpoint
        rather than a sentinel value in the save payload, so "never customised" and "reset back to
        default" end up as the SAME stored state (no keys) instead of two states to reason about."""
        try:
            for key in ("host_order", "server_order", "panels", "hidden"):
                current_user.set_ui_pref(key, None)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                _log.debug("ui-order reset commit failed", exc_info=True)
                return jsonify({"success": False, "message": "Could not reset your layout."}), 500
            log_action(current_user, "ui_layout_reset", target=current_user.username,
                       detail="restored the default dashboard order")
            return jsonify({"success": True})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("reset layout failed")}), 500

    @app.route("/account/2fa/disable", methods=["POST"])
    @login_required
    def account_2fa_disable():
        """Turn 2FA off. Needs the password AND a current authenticator (or backup) code.

        The password alone used to be enough — a weaker gate than the one on CHANGING the password
        in the same file, which demands both. That is backwards: removing the second factor is the
        change that makes every later login easier, and a session that someone else is sitting in
        front of could strip it with a password they already knew. The account holder always has
        one of the two codes (a backup code works, and is what the card below tells them to use),
        and an admin can clear 2FA for someone who has lost both — so nobody is stranded by this.
        """
        # The real row, not the proxy — same as the password change below, because
        # last_totp_step and the backup-code list are written here.
        u = current_user._get_current_object()
        if not check_password(request.form.get("password", ""), u.password_hash):
            flash("Password incorrect — two-factor authentication was not changed.", "danger")
            return redirect(url_for("account"))
        # Checked LAST, and in this order, for the same reasons the password change gives: a
        # one-time backup code must never be spent on an otherwise-invalid request, and a TOTP
        # code stays valid for ~90s, so accepting it on validity alone lets an observed code be
        # replayed within that window. verify_totp_STEP + last_totp_step is what makes it single
        # use, and it is committed below with the rest.
        code = (request.form.get("totp_code") or "").strip()
        if u.totp_enabled:
            ok_2fa = False
            _step = verify_totp_step(u.totp_secret_plain, code) if u.totp_secret_plain else None
            if _step is not None:
                if _step <= (u.last_totp_step or 0):
                    flash("That code has already been used — wait for your authenticator to show "
                          "the next one.", "danger")
                    return redirect(url_for("account"))
                u.last_totp_step = _step
                ok_2fa = True
            elif u.use_backup_code(code):
                ok_2fa = True
            if not ok_2fa:
                flash("That authenticator code didn't match — two-factor authentication was not "
                      "turned off.", "danger")
                return redirect(url_for("account"))
        u.totp_enabled = False
        u.totp_secret = None
        u.backup_codes = ""   # 2FA off → its backup codes no longer apply
        db.session.commit()
        log_action(u, "2fa_disabled", target=u.username)
        flash("Two-factor authentication disabled.", "success")
        return redirect(url_for("account"))

    @app.route("/account/password", methods=["POST"])
    @login_required
    def account_change_password():
        """Self-service password change. The user must prove they're really the account holder:
        their CURRENT password, plus — when 2FA is on — a valid authenticator code (or a one-time
        backup code). On success the new password is set and every OTHER session is signed out
        (auth_epoch bump); this session is refreshed so the user stays logged in here.
        (Superadmins change other people's passwords on the Users page, which needs neither.)"""
        # The real User row, NOT the current_user proxy. login_user() below re-logs this same user
        # in to refresh the session, and handing it the proxy makes flask-login store the proxy as
        # the logged-in user — every later `current_user` then resolves through it, recurses, and
        # the request dies with a RecursionError. The password change itself had already been
        # committed by then, so the symptom was a 500 page (and no audit entry) after a change that
        # actually worked, which is the worst way for this particular action to fail.
        u = current_user._get_current_object()
        old = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        code = request.form.get("totp_code", "").strip()
        # Where a message goes back to. This is the SAME handler for a voluntary change and for the
        # forced one after an admin handed over a password: a user who must change theirs has no
        # account page to be redirected to (the gate bounces them straight back), so every branch
        # below returns to whichever page they came from.
        _back = url_for("force_password_change") if u.must_change_password else url_for("account")

        if not check_password(old, u.password_hash):
            flash("Your current password is incorrect.", "danger")
            return redirect(_back)
        if new != confirm:
            flash("The new passwords don't match.", "danger")
            return redirect(_back)
        pw_err = password_problem(new)
        if pw_err:
            flash(pw_err, "danger")
            return redirect(_back)
        # LAST of the free-ish checks, and deliberately after password_problem: this is up to four
        # bcrypt comparisons, so a password that fails the cheap rules never pays for it. Covers the
        # current password — which on the forced-change page is the one the admin handed over, so
        # "set it to the password you were given" is refused here — and the last few before it.
        if u.password_reused(new):
            flash("That is a password you have used before — please choose a new one.", "danger")
            return redirect(_back)
        # 2FA is checked LAST so a one-time backup code is never spent on an otherwise-invalid
        # request. A matching authenticator code passes; otherwise a valid backup code is consumed.
        #
        # verify_totp_STEP, not verify_totp: a code stays valid for ~90 seconds (its step plus one
        # either side for skew), so accepting it on "is it valid" alone lets one that was observed
        # once be replayed for the rest of that window. The login path has recorded the spent step
        # since single-use was introduced; this — the panel's other route that accepts a live code —
        # was still asking the yes/no question. The step is committed below with the new password.
        if u.totp_enabled:
            ok_2fa = False
            _step = verify_totp_step(u.totp_secret_plain, code) if u.totp_secret_plain else None
            if _step is not None:
                if _step <= (u.last_totp_step or 0):
                    flash("That code has already been used — wait for your authenticator to show "
                          "the next one.", "danger")
                    return redirect(_back)
                u.last_totp_step = _step
                ok_2fa = True
            elif u.use_backup_code(code):
                ok_2fa = True                    # committed below alongside the new password
            if not ok_2fa:
                flash("That authenticator code didn't match — password not changed.", "danger")
                return redirect(_back)

        u.set_password(hash_password(new))   # remembers the outgoing one; see password_reused
        # Whatever it was before, the password is now the account holder's own and nobody else's —
        # which is the entire condition the forced-change gate is waiting on.
        _was_forced = bool(u.must_change_password)
        u.must_change_password = False
        u.auth_epoch = (u.auth_epoch or 0) + 1   # sign out every other session/remember cookie
            # The API token too. It is a SECOND credential for the same account, and it did not
            # answer to any of the controls that exist to take an account back: it carries no
            # auth_epoch, so a password change did not touch it, and "sign out everywhere" deleted
            # every UserSession row and left it working. app.py's note that "cookie theft is also
            # recoverable via sign out everywhere" was not true while one existed. Minting one
            # needs only a live session (no password, no 2FA), so an attacker with a stolen cookie
            # could leave themselves a key that survived the victim's whole recovery.
        u.revoke_api_token()
        from panel.db.models import UserSession
        # Carry this device's "remember me" across the re-login, or changing a password would
        # silently downgrade a remembered login to one that expires in hours.
        _sid = getattr(current_user, "_sid", None)
        _cur = UserSession.query.filter_by(sid=_sid, user_id=u.id).first() if _sid else None
        _remember = bool(_cur.remember) if _cur is not None else _has_remember_cookie()
        UserSession.query.filter_by(user_id=u.id).delete()   # epoch bump killed them all; clear rows
        db.session.commit()
        _register_session(u, _remember)          # fresh session row for THIS device
        login_user(u, remember=_remember)        # refresh THIS session (new epoch + sid) so we stay in
        log_action(u, "password_changed", target=u.username)
        if _was_forced:
            flash("Password set — this account is yours now. Welcome.", "success")
            return redirect(url_for("index"))
        flash("Your password has been changed. Any other sessions were signed out.", "success")
        return redirect(_back)

    @app.route("/account/2fa/dismiss-nag", methods=["POST"])
    @login_required
    def account_dismiss_otp_nag():
        """Permanently stop showing the 'your admin account has no 2FA' banner for this user."""
        current_user.otp_nag_dismissed = True
        db.session.commit()
        log_action(current_user, "otp_nag_dismissed", target=current_user.username)
        return jsonify({"success": True})
