"""CodeQL canary for build ws7. NEVER MERGE.

Each tagged line is where the probe PR expects an alert, or expects none. The tags, the expected
rule at each, and how to read the result are in work/build-1003/ws7-canary-README.md.
"""
import logging
import shlex

from flask import request
from flask_socketio import emit

from panel.ops import ssh_manager as _canary_sm
from panel.ops.ssh_manager import _core as _canary_core

_log = logging.getLogger("panel.routes.zz_codeql_canary")


def register(app):
    """A route at register(app)'s depth (23 routes today), then the _register_* depth."""
    @app.route("/__canary/a/<path:canary_a>")
    def canary_direct(canary_a):
        _log.warning("canary A1 %s", canary_a)                          # A1
        try:
            int(request.args.get("n", "x"))
        except ValueError as e:
            return "canary A2: " + str(e)                                # A2
        return request.args.get("q", "")                                 # A3
    _register_canary_nested(app)


def _register_canary_nested(app):
    """The depth of the 201 routes #366 moved into _register_* helpers."""
    @app.route("/__canary/b/<path:canary_b>")
    def canary_nested(canary_b):
        _log.warning("canary B0 %s", request.args.get("c", ""))          # B0 control (flask.request)
        _log.warning("canary B1 %s", canary_b)                           # B1
        try:
            int(request.args.get("n", "x"))
        except ValueError as e:
            return "canary B2: " + str(e)                                # B2
        return request.args.get("q", "")                                 # B3

    @app.route("/__canary/e")
    def canary_entry_points():
        cmd = request.args.get("cmd", "")
        out, _, _ = _canary_sm.run_command(None, "echo " + cmd)          # L1 (entry + own-host shell)
        _canary_sm.run_command(None, "echo " + cmd, sudo=True)           # E1 (sudo: below it, quoted)
        _canary_sm.shell_as_game_user(None, "u", "echo " + cmd)          # E2 (game account)
        _canary_sm.read_as_game_user(None, "u", "echo " + cmd)           # E3
        _canary_sm.game_user_cmd("u", "echo " + cmd)                     # E4
        _canary_core.run_command(None, "echo " + cmd, sudo=True)         # E5 (the _core path)
        _canary_sm.run_command(None, "echo " + shlex.quote(cmd), sudo=True)    # Q1 (quoted word)
        _canary_sm.run_command(None, "bash -c " + shlex.quote("echo " + cmd))  # D1 (known blind spot)
        return {"a": len(out)}


def register_sockets(socketio):
    """A handler on the app's one SocketIO instance, under an event name nothing else uses.

    A second @socketio.on for an EXISTING event would replace that event's real handler.
    """
    @socketio.on("zz_canary")
    def on_zz_canary(data):
        _log.warning("canary S0 %s", request.args.get("c", ""))          # S0 control (flask.request)
        _log.warning("canary S1 %s", data)                               # S1 (the source model)
        _canary_sm.run_command(None, "echo " + str(data["cmd"]), sudo=True)    # S4 (source + sink models)
        try:
            int(data["n"])
        except (ValueError, KeyError, TypeError) as e:
            emit("zz_canary", {"m": str(e)})                             # S2 (emit: no sink)
            return str(e)                                                # S3 (not an HTTP response)
        return None
