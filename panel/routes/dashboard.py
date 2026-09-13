"""The dashboard: the at-a-glance server and host grid.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (Response, jsonify, redirect, render_template)
from flask_login import (current_user, login_required)
from panel.db.models import (RemoteServer, db)
from panel.db.prefs import (_apply_user_order, _apply_user_server_order, _effective_prefs)
from panel.security.auth import (RESTART_SERVER, START_SERVER, STOP_SERVER,
    get_user_permissions, get_user_servers)
from panel.services.monitoring import (_cached_player_count)
from sqlalchemy import (text)
from app import (_cached_player_max, _cached_player_name, is_setup_complete)


def register(app):
    @app.route("/robots.txt")
    def robots_txt():
        """Tell well-behaved crawlers not to index the panel. Advisory only (the
        X-Robots-Tag header is the enforceable part), but keeps the management UI
        out of search results."""
        return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")

    @app.route("/healthz")
    def healthz():
        """Unauthenticated liveness probe for monitors / an external watchdog. Confirms
        the process is serving AND the database is reachable; returns no sensitive data.
        A hung/deadlocked worker or a wedged DB makes this fail, so a watchdog can act."""
        try:
            db.session.execute(text("SELECT 1"))
            return jsonify({"status": "ok"}), 200
        except Exception:
            return jsonify({"status": "degraded"}), 503

    @app.route("/")
    @login_required
    def index():
        if not is_setup_complete():
            return redirect("/setup")

        # This user's own host-card order. Applied server-side, NOT in JS: the dashboard swaps
        # #server-cards' innerHTML from its poll and from a cross-user servers_changed broadcast,
        # so a DOM-only order would silently revert (and reordering after paint is layout shift,
        # which Lighthouse CI gates). With no saved order this is a no-op, so the default stands.
        _prefs = _effective_prefs(current_user)
        remotes = _apply_user_order(RemoteServer.query.all(), _prefs.get("host_order"))
        remote_count = RemoteServer.query.filter_by(is_local=False).count()
        servers = _apply_user_server_order(get_user_servers(current_user), _prefs)
        uperms = get_user_permissions(current_user)
        can_control = current_user.is_superadmin or bool(
            {START_SERVER, STOP_SERVER, RESTART_SERVER} & uperms
        )
        player_counts = {gs.id: _cached_player_count(gs.id) for gs in servers}
        player_max = {gs.id: _cached_player_max(gs.id) for gs in servers}
        server_names = {gs.id: _cached_player_name(gs.id) for gs in servers}
        total_players = sum(c for c in player_counts.values() if isinstance(c, int))
        total_max = sum(m for m in player_max.values() if isinstance(m, int))
        return render_template("dashboard.html", remotes=remotes, servers=servers,
                               server_list=servers, can_control=can_control,
                               remote_count=remote_count, player_counts=player_counts,
                               player_max=player_max, server_names=server_names,
                               total_players=total_players, total_max=total_max)
