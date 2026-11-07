"""The install page's game icons, served from the panel's own origin (panel/services/game_icons.py)."""
from flask import abort, make_response
from flask_login import login_required

from panel.security.auth import INSTALL_SERVER, MANAGE_SERVERS, permission_required
from panel.services import game_icons as _gi
from panel.services import lgsm_data


def _cmpd_known_scripts():
    """Every LinuxGSM script name the panel knows: the cached serverlist's, plus retired games'."""
    names = {(row.get("gameservername") or "").strip()
             for row in lgsm_data.serverlist(allow_fetch=False)}
    names.update(g["gameservername"] for g in lgsm_data.RETIRED_GAMES.values())
    names.discard("")
    return names


def register(app):
    """Register GET /game-icon/<script>."""
    @app.route("/game-icon/<script>")
    @login_required
    @permission_required(INSTALL_SERVER, MANAGE_SERVERS)
    def game_icon(script):
        """One game's icon (PNG/JPEG/WEBP), or 404 when it has none; the page then shows initials.

        Same permission pair as the install page it is drawn on. The name must be a LinuxGSM script
        the serverlist knows, so it can never address a file or a URL of the caller's choosing.
        """
        got = _gi.icon(script, _cmpd_known_scripts())
        if got is None:
            abort(404)
        resp = make_response(got[0])
        resp.headers["Content-Type"] = got[1]
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "private, max-age=86400"
        return resp
