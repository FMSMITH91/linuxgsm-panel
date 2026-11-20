"""The Add-ons tab's B3 players section: B3's players and penalties, read from B3's own database.

PERMISSION. Every route takes MANAGE_ADDONS (the B3 add-on's own permission, granted to no group by
default) and access to the server, checked in the route itself on every request (Authorization Cheat
Sheet: "Deny by Default", "Validate the Permissions on Every Request"). A player's IP addresses and
GUID are shown only to a viewer who also holds MANAGE_DATABASES, which can already read B3's tables
whole in the Databases manager; for anyone else they are never read (services/b3_players.py).

WHICH DATABASE. B3's own, as its add-on record on the host names it (the Add-ons tab's status read;
kept CACHE_SECONDS), and only when it is one of this server's databases in the Databases tab. It is
read the Databases manager's way (routes/databases_data.py): one db-query verb signed in as that
database's own account, in a READ ONLY transaction, from where its other commands run. No port is
opened and nothing is written.

AUDIT. A search, a player opened and the latest-penalties list each write an audit row with the
server (Logging Cheat Sheet, "Which events to log": access to sensitive data): what was looked at
(a player by B3 id, the kind of search and how many it found), never the text searched for.

TABLE LAYOUT. Every read starts with data.b3_schema_version (B3 writes it at each start); anything
but "1", the layout these statements are written for, is refused with a sentence, unread.

ACTIONS. Unban, kick and warn go through B3 itself, over its control socket, while B3's Panel actions
setting is on (routes/addons_b3_actions.py): the reads here never change anything.
"""
import re
import time

from flask import jsonify, request
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.http import _json_body
from panel.db.models import GameDatabase
from panel.ops import ssh_manager as _sm
from panel.routes import addons as _ra, databases_data as _ddr
from panel.security import privileged as _sm_priv
from panel.security.auth import MANAGE_ADDONS, MANAGE_DATABASES, has_permission, log_action, server_access_required
from panel.services import addons as _ad, b3_players as _b3

_DENIED = "Permission denied"
S_UNREAD_HOST = "Couldn't read this server's add-ons: the host did not answer. Try again."
S_NOT_INSTALLED = "B3 is not installed on this server."
S_NO_DB = "B3's database ({db}) is not one of this server's databases in the Databases tab, so the panel can't open it."
S_NO_TABLES = "B3's tables are not in its database yet: B3 makes them the first time it starts."
S_DB_ERROR = "B3's database answered with an error (code {code}), so nothing can be shown."
S_UNREAD = "B3's database answer could not be read. Try again."
S_BAD_QUERY = "Type a name, an alias, a B3 id (@12) or a GUID: up to {n} characters."
S_BAD_PAGE = "That page mark is not one this list gave."
S_NO_PLAYER = "There is no player with that B3 id in B3's database."
S_SCHEMA_NONE = ("B3's database doesn't say which table layout it has: B3 2.0.2 or newer writes it when it starts. "
                 "Update B3 on its card and start it, then open Players again.")
S_SCHEMA_OTHER = ("B3's database has table layout {layout}, which this panel doesn't read (it reads layout 1). "
                  "Update the panel.")
_BEFORE_RE = re.compile(r"[0-9]{1,10}")   # ASCII digits only: str.isdigit() also takes "²", which int() refuses


def _say(status, sentence):
    said = i18n.tr(sentence)
    return jsonify({"success": False, "error": said, "message": said}), status


def unmasked():
    """Whether this viewer sees players' IP addresses and GUIDs: Manage a server's databases as well."""
    return has_permission(current_user, MANAGE_DATABASES)


def _database(gs):
    """(B3's database row on `gs`, None) or (None, the sentence why there is none)."""
    name = _b3.database_name(gs.id)
    if name is None:
        out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, _ad.status_sh(), timeout=30)
        if rc != 0:
            return None, S_UNREAD_HOST
        name = _b3.remember(gs.id, _ad.parse_status(out)["addons"])
    if not name:
        return None, S_NOT_INSTALLED
    r = GameDatabase.query.filter_by(game_server_id=gs.id, remote_id=gs.remote_id, name=name).first()
    if r is None:
        return None, i18n.Sentence(S_NO_DB, db=name)
    return r, None


def _read(gs, statements, want):
    """(the `want` finished statements, None) or (None, (status, sentence)) for a read of B3's database.

    The table layout is read first: a layout other than b3_players.SCHEMA is refused before any of
    `statements` is looked at. It goes in the same call when that stays within the helper's statement
    cap (privileged.DB_QUERY_MAX_STATEMENTS), else in a call of its own just before: a player's view
    is four reads, and five in one call were refused (rc 2) on a real host.
    """
    r, why = _database(gs)
    if why:
        return None, (200, why)
    statements = list(statements)
    if len(statements) + 1 <= _sm_priv.DB_QUERY_MAX_STATEMENTS:
        ans = _ddr._query(gs, r, "ro", [_b3.schema_statement()] + statements)
    else:
        ans = _ddr._query(gs, r, "ro", [_b3.schema_statement()])
        if not _ddr._problem(gs, ans) and not (ans.get("error") or {}).get("code"):
            rest = _ddr._query(gs, r, "ro", statements)
            ans = rest if (_ddr._problem(gs, rest) or (rest.get("error") or {}).get("code")) else \
                dict(rest, statements=list(ans.get("statements") or [])[:1] + list(rest.get("statements") or []))
    bad = _ddr._problem(gs, ans)
    if bad:
        return None, bad
    code = (ans.get("error") or {}).get("code")
    if code == _b3.TABLES_MISSING:
        return None, (200, S_NO_TABLES)
    if code:
        return None, (502, i18n.Sentence(S_DB_ERROR, code=code))
    if len(ans.get("statements") or []) < want + 1:
        return None, (502, S_UNREAD)
    layout = _b3.schema_of(ans["statements"][0])
    if layout != _b3.SCHEMA:
        return None, (200, i18n.Sentence(S_SCHEMA_OTHER, layout=layout) if layout else S_SCHEMA_NONE)
    return ans["statements"][1:], None


def _search_answer(gs):
    body = _json_body()
    q = _b3.clean_query(body.get("q"))
    after = _b3.parse_after(body.get("after"))
    if q is None:
        return _say(400, i18n.Sentence(S_BAD_QUERY, n=_b3.QUERY_MAX))
    if after is False:
        return _say(400, S_BAD_PAGE)
    show = unmasked()
    got, bad = _read(gs, [_b3.search_statement(q, show, after)], 1)
    if bad:
        return _say(*bad)
    found = _b3.players(got[0], show)
    kind = _b3.query_kind(q, show)
    log_action(current_user, "b3_player_search", target=gs.name, server=gs,
               detail="B3 players searched (%s): %d found" % (kind, len(found["players"])))
    return jsonify(dict(found, success=True, masked=not show))


def _player_answer(gs, client_id):
    if client_id > _b3.ID_MAX:
        return _say(404, S_NO_PLAYER)
    show = unmasked()
    got, bad = _read(gs, _b3.detail_statements(client_id, show), 4)
    if bad:
        return _say(*bad)
    p = _b3.detail(got, show, int(time.time()))
    if p is None:
        return _say(404, S_NO_PLAYER)
    log_action(current_user, "b3_player_view", target=gs.name, server=gs,
               detail="B3 player @%d opened%s" % (client_id, ", addresses and GUID shown" if show else ""))
    from panel.routes import addons_b3_actions as _act   # it imports this module
    return jsonify({"success": True, "player": p, "masked": not show, "actions": _act.offered(gs)})


def _penalties_answer(gs):
    kind = request.args.get("kind", "all")
    before = request.args.get("before", "")
    if kind not in _b3.KINDS or not (before == "" or _BEFORE_RE.fullmatch(before)):
        return _say(400, S_BAD_PAGE)
    got, bad = _read(gs, [_b3.recent_statement(kind, int(before) if before else None)], 1)
    if bad:
        return _say(*bad)
    out = _b3.recent(got[0], int(time.time()))
    log_action(current_user, "b3_penalties_view", target=gs.name, server=gs,
               detail="B3 latest penalties (%s)%s" % (kind, ", older page" if before else ""))
    return jsonify(dict(out, success=True))


def register(app):
    """Register the B3 players section's routes (called by routes/addons.py's register)."""

    @app.route("/api/server/<int:server_id>/addons/b3/players/search", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_b3_players_search(server_id):
        """Search B3's players by the start of a name or alias, a B3 id or a GUID (POST: the text stays out of URLs)."""
        if not has_permission(current_user, MANAGE_ADDONS):
            return _say(403, _DENIED)
        return _ra._guarded(server_id, _ad.B3, _search_answer, reading=True)

    @app.route("/api/server/<int:server_id>/addons/b3/players/<int:client_id>")
    @login_required
    @server_access_required
    def api_server_b3_player(server_id, client_id):
        """One B3 player: aliases, connections, first and last seen, and penalties."""
        if not has_permission(current_user, MANAGE_ADDONS):
            return _say(403, _DENIED)
        return _ra._guarded(server_id, _ad.B3, lambda gs: _player_answer(gs, client_id), reading=True)

    from panel.routes import addons_b3_actions   # it imports this module
    addons_b3_actions.register(app)

    @app.route("/api/server/<int:server_id>/addons/b3/penalties")
    @login_required
    @server_access_required
    def api_server_b3_penalties(server_id):
        """B3's latest penalties: warnings, kicks and bans (or bans only), newest first."""
        if not has_permission(current_user, MANAGE_ADDONS):
            return _say(403, _DENIED)
        return _ra._guarded(server_id, _ad.B3, _penalties_answer, reading=True)
