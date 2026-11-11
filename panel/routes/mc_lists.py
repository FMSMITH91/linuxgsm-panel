"""A Minecraft (Java edition) server's operators, whitelist and bans, on its server page.

Four lists the server keeps beside its jar, in LinuxGSM's serverfiles directory: ops.json,
whitelist.json, banned-players.json and banned-ips.json, plus `white-list` in server.properties.

READ through the file manager's reader (ssh_manager.files.read_file), with its permission
(_can_manage_files) and its refusal of a root-capable game account (_read_refused). A file that is
not there is an empty list: the server writes each one the first time it has something to keep. A
read that failed is "could not be read", never empty (read_file's error, or a body that is not a
JSON list).

CHANGED only by console command, while the server runs: op/deop, whitelist add/remove/on/off,
ban/pardon, ban-ip/pardon-ip. The server rewrites its own files, so nothing here writes them, and an
edit can never race the server's own write of the same file. The command goes through the function
the console's command box sends with (ssh_manager.send_console_command, /api/command), with that
box's permission (SEND_COMMAND), and every attempt is audited against the server.

EVERYTHING sent is built here from values checked first: a player name is Mojang's 3-16 letters,
digits and underscores; an address is an IPv4 address (Java's ban-ip takes one single word of
letters, digits and `-+._`, so an IPv6 address, which has colons, cannot be given to it, and a CIDR
range is not an address); a reason is at most _MCL_REASON_MAX printable characters. Anything else is
refused before the console sees it.

Which games: LinuxGSM's mcserver (mc) and pmcserver (pmc, PaperMC), the Java servers. Not mcbserver
(Bedrock keeps allowlist.json and permissions.json, with other commands), and not the proxies
vpmcserver (Velocity) and wmcserver (Waterfall), which keep no such lists.
"""
import ipaddress
import json
import re

from flask import (jsonify)
from flask_login import (current_user, login_required)
from panel.core import i18n
from panel.core.http import (_json_body, _json_str, _log_and_generic, _unreachable)
from panel.ops import ssh_manager as _sm
from panel.routes._shared import (_console_send_failure, _r20b_audit_on_raise)
from panel.security.auth import (SEND_COMMAND, _can_manage_files, get_game, has_permission, log_action,
                                 server_access_required)

MCL_GAMES = frozenset({"mc", "pmc"})
# Each list: its file under the game account's home, and the console verbs that add and remove.
_MCL_LISTS = {
    "ops": ("serverfiles/ops.json", "op", "deop"),
    "whitelist": ("serverfiles/whitelist.json", "whitelist add", "whitelist remove"),
    "bans": ("serverfiles/banned-players.json", "ban", "pardon"),
    "ipbans": ("serverfiles/banned-ips.json", "ban-ip", "pardon-ip"),
}
_MCL_ACTIONS = ("add", "remove", "on", "off")
_MCL_PROPS = "serverfiles/server.properties"
_MCL_NAME = re.compile(r"[A-Za-z0-9_]{3,16}")
_MCL_REASON_MAX = 100
# Rows one reply carries, so a list of many thousands cannot size the reply.
_MCL_ROWS_MAX = 1000
_MCL_FIELD_MAX = 120
# read_file's answer for a file that is not there, which is an empty list here.
_MCL_NO_FILE = "File not found"

MCL_UNREADABLE = "This list could not be read from the server, so it is not shown."
MCL_STOPPED = "The server is stopped. These lists can be changed while it is running."
_MCL_BAD_NAME = "A player name is 3 to 16 letters, digits or underscores."
_MCL_BAD_IP = "Enter an IPv4 address, such as 203.0.113.7."
_MCL_IPV6 = "Minecraft's ban-ip cannot take an IPv6 address. Ban the player by name instead."
_MCL_BAD_REASON = ("A reason is at most 100 characters, on one line, with no control "
                   "characters.")
_MCL_BAD_ACTION = "Unknown action."
_MCL_NOT_JAVA = "This server is not a Minecraft Java edition server."


def mcl_supported(game_type):
    """Does this LinuxGSM game keep the four lists (a Java Minecraft server)?"""
    return (game_type or "").lower() in MCL_GAMES


def _mcl_can_change():
    return current_user.is_superadmin or has_permission(current_user, SEND_COMMAND)


def _mcl_field(value):
    """One value from a list file as display text: a string, capped; anything else is ''."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return ""
    return str(value)[:_MCL_FIELD_MAX]


def _mcl_row(item):
    """The fields the card shows for one entry of a list file, or None for one that is not an object."""
    if not isinstance(item, dict):
        return None
    return {k: _mcl_field(item.get(k)) for k in ("name", "ip", "uuid", "level", "reason", "source",
                                                  "created", "expires")}


def mcl_parse(content):
    """(rows, truncated) from one list file's text; None when it is not a JSON list.

    An empty file is an empty list (the reader confirmed it is empty); text that is not JSON, or JSON
    that is not a list, is a file this cannot read, never an empty one.
    """
    if not (content or "").strip():
        return [], False
    try:
        data = json.loads(content)
    except ValueError:
        return None
    if not isinstance(data, list):
        return None
    rows = [r for r in (_mcl_row(i) for i in data) if r is not None]
    return rows[:_MCL_ROWS_MAX], len(rows) > _MCL_ROWS_MAX


def mcl_whitelist_on(props):
    """`white-list` from server.properties: True, False, or None when it is not there."""
    for line in (props or "").splitlines():
        key, sep, val = line.partition("=")
        if sep and key.strip() == "white-list" and not line.lstrip().startswith("#"):
            return val.strip().lower() == "true"
    return None


def _mcl_read(gs, relpath):
    """(content, error) from the file reader; a file that is not there reads as empty."""
    content, err = _sm.read_file(gs.remote, gs.short_name, relpath)
    if err == _MCL_NO_FILE:
        return "", None
    return content, err


def mcl_ip(value):
    """(canonical IPv4 text, None), or (None, why it is refused)."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None, _MCL_BAD_IP
    if addr.version != 4:
        return None, _MCL_IPV6
    return str(addr), None


def mcl_reason(value):
    """(reason, None), or (None, why it is refused). Empty is allowed: the server's own default."""
    if len(value) > _MCL_REASON_MAX or not value.isprintable():
        return None, _MCL_BAD_REASON
    return value, None


def _mcl_target(which, value):
    """(the checked name or address, None), or (None, why it is refused)."""
    if which == "ipbans":
        return mcl_ip(value)
    if not _MCL_NAME.fullmatch(value):
        return None, _MCL_BAD_NAME
    return value, None


def mcl_command(which, action, value="", reason=""):
    """(the console line for one change, None), or (None, why it is refused). Builds nothing unchecked."""
    if which not in _MCL_LISTS:
        return None, _MCL_BAD_ACTION
    if action in ("on", "off"):
        return ("whitelist " + action, None) if which == "whitelist" else (None, _MCL_BAD_ACTION)
    if action not in _MCL_ACTIONS:
        return None, _MCL_BAD_ACTION
    target, why = _mcl_target(which, value)
    if why:
        return None, why
    _path, add_verb, remove_verb = _MCL_LISTS[which]
    line = "%s %s" % (add_verb if action == "add" else remove_verb, target)
    if action == "add" and which in ("bans", "ipbans"):
        return _mcl_with_reason(line, reason)
    return line, None


def _mcl_with_reason(line, reason):
    """(a ban line with its checked reason after it, None), or (None, why the reason is refused)."""
    if not reason:
        return line, None
    reason, why = mcl_reason(reason)
    if why:
        return None, why
    return line + " " + reason, None


def _mcl_list_reply(gs, which):
    """The GET's answer for one list: its rows, or that it could not be read."""
    content, err = _mcl_read(gs, _MCL_LISTS[which][0])
    parsed = None if err else mcl_parse(content)
    out = {"running": gs.status == "online", "can_change": bool(_mcl_can_change())}
    if parsed is None:
        return dict(out, success=False, error=i18n.tr(MCL_UNREADABLE))
    rows, truncated = parsed
    out.update(success=True, entries=rows, truncated=truncated)
    if which == "whitelist":
        props, perr = _mcl_read(gs, _MCL_PROPS)
        out["whitelist_on"] = None if perr else mcl_whitelist_on(props)
    return out


def _mcl_send(gs, line):
    """Send one checked line to the server's console and audit it: the POST's JSON answer."""
    with _r20b_audit_on_raise("mc_list_change", detail=line, target=gs.name, server=gs):
        _out, err, rc = _sm.send_console_command(gs.remote, gs.short_name, line, timeout=10,
                                                 selfname=gs.lgsm_name)
    log_action(current_user, "mc_list_change", target=gs.name, detail=line, success=(rc == 0), server=gs)
    if rc != 0:
        return jsonify({"success": False, "message": _console_send_failure(rc, err)})
    return jsonify({"success": True, "message": i18n.tr("Sent to the server: {command}", command=line)})


def _mcl_refused(gs, line, why, status):
    """Audit a change that was refused before the console, and answer it."""
    log_action(current_user, "mc_list_change", target=gs.name, detail="%s (refused: %s)" % (line, why),
               success=False, server=gs)
    return jsonify({"success": False, "message": i18n.tr(why)}), status


def _mcl_read_answer(gs, which):
    """The list read's answer once its permission and the file manager's refusals have passed."""
    try:
        return jsonify(_mcl_list_reply(gs, which))
    except ConnectionError:
        return _unreachable("read a Minecraft list")
    except Exception:
        return jsonify({"success": False, "error": _log_and_generic("request failed")}), 500


def _mcl_change_answer(gs, which, data):
    """The change's answer once its permission has passed: checked, refused or sent, and audited."""
    action = _json_str(data, "action")
    line, why = mcl_command(which, action, _json_str(data, "value"), _json_str(data, "reason"))
    if why:
        # The list and the action, never the refused value: it is what failed the checks.
        return _mcl_refused(gs, "%s %s" % (which, action if action in _MCL_ACTIONS else "?"), why, 400)
    if gs.status != "online":
        return _mcl_refused(gs, line, MCL_STOPPED, 409)
    try:
        return _mcl_send(gs, line)
    except ConnectionError:
        return _unreachable("send console command")
    except Exception:
        return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500


def register(app):
    """The list read and the change route, and the template's `mc_lists_supported`."""
    app.jinja_env.globals["mc_lists_supported"] = mcl_supported

    @app.route("/api/server/<int:server_id>/mc-lists/<any(ops, whitelist, bans, ipbans):which>")
    @login_required
    @server_access_required
    def api_server_mc_list(server_id, which):
        """One of a Minecraft server's four lists, read from its file, with whether it can be changed."""
        from panel.routes import server_files as _sf
        gs = get_game(server_id)
        if not _can_manage_files():
            return jsonify({"error": "Permission denied"}), 403
        if not mcl_supported(gs.game_type):
            return jsonify({"success": False, "error": i18n.tr(_MCL_NOT_JAVA)}), 400
        refused = _sf._read_refused(gs, "mc_list_read", _MCL_LISTS[which][0])
        return refused if refused is not None else _mcl_read_answer(gs, which)

    @app.route("/api/server/<int:server_id>/mc-lists/<any(ops, whitelist, bans, ipbans):which>",
               methods=["POST"])
    @login_required
    @server_access_required
    def api_server_mc_list_change(server_id, which):
        """Add to or remove from one list, or turn the whitelist on or off, by console command."""
        gs = get_game(server_id)
        # Inline, not _mcl_can_change(): rbac_test reads each mutating view's own gate.
        if not (current_user.is_superadmin or has_permission(current_user, SEND_COMMAND)):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        if not mcl_supported(gs.game_type):
            return jsonify({"success": False, "message": i18n.tr(_MCL_NOT_JAVA)}), 400
        return _mcl_change_answer(gs, which, _json_body())
