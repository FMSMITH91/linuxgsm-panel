"""Finding LinuxGSM servers already installed on a host and importing them.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
import collections

from flask import (jsonify)
from flask_login import (current_user, login_required)
from panel.db.models import (GameServer, db)
from panel.ops.ssh_manager import (content_box_users, discover_linuxgsm_servers)
from panel.security.auth import (MANAGE_SERVERS, can_access_remote, get_remote, log_action,
    permission_required)
from panel.core.http import (_json_body, _log_and_generic)
from panel.core.validation import (INSTANCE_NAME_RE)
from app import (lgsm_name_to_game_type, load_game_list)
from panel.routes._shared import (_bg_cache_commands)


def register(app):
    @app.route("/api/remote/<int:remote_id>/discover")
    @login_required
    @permission_required(MANAGE_SERVERS)
    def api_remote_discover(remote_id):
        """Scan a host for LinuxGSM servers already installed under any user account and return
        the ones NOT yet in the panel, mapped to a known game. Read-only — imports nothing."""
        if not (current_user.is_superadmin or can_access_remote(current_user, remote_id)):
            return jsonify({"error": "You don't have access to that host."}), 403
        remote = get_remote(remote_id)
        try:
            found = discover_linuxgsm_servers(remote)
        except Exception:
            return jsonify({"error": _log_and_generic("server discovery failed")}), 200
        existing = {gs.short_name for gs in GameServer.query.filter_by(remote_id=remote_id).all()}
        games = {g["shortname"]: g["name"] for g in load_game_list()}
        # A GMod content box installs each mountable game through LinuxGSM, so every one of them
        # looks exactly like an installed server to the scan. They are not servers — see
        # content_box_users — and the panel cannot even represent them, since a host's servers are
        # keyed on the Linux user. Report them separately so the card can say what it left out
        # rather than silently showing one account seven times.
        content_users = content_box_users(found)
        content = {}
        out = []
        for f in found:
            user = f.get("user") or ""
            if user in existing:
                continue   # already in the panel
            gt = lgsm_name_to_game_type(f.get("lgsm_name") or "")
            # Classify BEFORE the supported-game filter. Whether an install is mountable content
            # has nothing to do with whether the panel can run that game, and testing it second
            # meant a content game the panel doesn't list vanished as "unsupported" instead of
            # being reported — so the note undercounted exactly the boxes it exists to explain.
            if user in content_users:
                content.setdefault(user, []).append(
                    games.get(gt) or f.get("lgsm_name") or gt or "?")
                continue
            if not gt or gt not in games:
                continue   # a game the panel doesn't support — don't offer a broken import
            out.append({"user": user, "game_type": gt, "game_name": games.get(gt, gt),
                        "port": f.get("port") or 0,
                        "backups": f.get("backups", 0), "mods": f.get("mods", 0),
                        "cron": f.get("cron", 0), "autostart": bool(f.get("autostart"))})
        return jsonify({"servers": out,
                        "content": [{"user": u, "games": sorted(g)}
                                    for u, g in sorted(content.items())]})

    @app.route("/api/remote/<int:remote_id>/import", methods=["POST"])
    @login_required
    @permission_required(MANAGE_SERVERS)
    def api_remote_import(remote_id):
        """Create panel records for selected discovered servers. Each user/game_type is validated
        with the SAME strict rules as a fresh install (so an imported short_name can never carry
        shell metacharacters), and duplicates/unknowns are skipped."""
        if not (current_user.is_superadmin or can_access_remote(current_user, remote_id)):
            return jsonify({"error": "You don't have access to that host."}), 403
        remote = get_remote(remote_id)
        items = _json_body().get("servers") or []
        if not isinstance(items, list) or not items:
            return jsonify({"success": False, "message": "Nothing selected."}), 400
        existing = {gs.short_name for gs in GameServer.query.filter_by(remote_id=remote_id).all()}
        game_names = {g["shortname"]: g["name"] for g in load_game_list()}
        valid_games = set(game_names)
        # A host's servers are keyed on the Linux user (short_name), so two games under ONE account
        # cannot both become servers. The loop below would take the first and drop the rest as
        # duplicates — picking a game essentially at random and reporting partial success as
        # success. That is what a GMod content box looked like when it reached this endpoint.
        # Refuse the whole account instead: an arbitrary winner is not a better answer than none.
        items = [it for it in items[:100] if isinstance(it, dict)]
        per_user = collections.Counter((str(it.get("user") or "")).strip() for it in items)
        added, skipped = [], []
        for it in items:
            user = (str(it.get("user") or "")).strip()
            gt = (it.get("game_type") or "").strip().lower()
            if (not INSTANCE_NAME_RE.match(user) or gt not in valid_games
                    or user in existing or per_user.get(user, 0) > 1):
                skipped.append(user or "?")
                continue
            try:
                port = int(it.get("port") or 0)
            except (TypeError, ValueError):
                port = 0
            # Import NEVER starts or reconfigures a discovered server — it's left exactly as it
            # is (its own cron/backups/mods are read live by the panel once imported). Autostart
            # is off until you enable it here, which is what sets up the panel's monitor cron, so
            # the panel never takes over a server you didn't ask it to manage.
            db.session.add(GameServer(
                remote_id=remote_id, name=user, short_name=user, game_type=gt,
                game_display=game_names.get(gt, ""),
                port=(port if 1 <= port <= 65535 else 27015), installed=True, status="offline",
                autostart=False))
            existing.add(user)
            added.append(user)
        if added:
            db.session.commit()
            log_action(current_user, "import_servers", target=remote.name,
                       detail="added=%s" % ",".join(added))
            # Populate the imported servers' command lists so "Supported Commands" is ready
            # without a manual refresh (install caches these; import didn't).
            new_ids = [gs.id for gs in GameServer.query.filter(
                GameServer.remote_id == remote_id,
                GameServer.short_name.in_(added)).all()]
            _bg_cache_commands(app, new_ids)
        return jsonify({"success": bool(added), "added": added, "skipped": skipped})
