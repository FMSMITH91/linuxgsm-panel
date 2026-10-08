"""Remote host management: ports, OS updates, reboots and diagnostics.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (jsonify, render_template, request, url_for)
from flask_login import (current_user, login_required)
from panel.core.config import (load_config)
from panel.core.panel_state import (_os_update_seen)
from panel.db.models import (GameServer, RemoteServer, db)
from panel.ops import (system_ops as so)
from panel.ops.ssh_manager import (change_ssh_port, close_connection, detect_game_ports,
    host_specs, remote_os_run_updates, remote_os_update_start, remote_os_update_status,
    remote_public_ssh_status, remote_reboot_required, remote_set_public_ssh,
    remote_ufw_allow_game_port, remote_ufw_allow_game_ports, remote_ufw_close_port,
    remote_ufw_allow_from, remote_ufw_delete_rule, remote_ufw_limit_port,
    remote_ufw_open_port, remote_ufw_status, remote_uptime)
# Reached through the MODULE, not bound by name: these are the seams the test suite
# monkeypatches. `from x import f` copies the function object, so a stub on the source
# module would never be seen — attribute access resolves at call time and is stable
# however the handler moves.
from panel.ops import ssh_manager as _sm
# The firewall verbs' own port and protocol parse, read by the audit rows (_fw_audit_rule). The
# module, not its functions: a stub on hosts is seen, and one of `_sm` above is not in the way.
from panel.ops.ssh_manager import hosts as _fw_hosts
from panel.security.auth import (INSTALL_SERVER, MANAGE_REMOTES, MANAGE_SERVERS,
    accessible_remote_ids, can_access_remote, get_game,
    get_host_remote, get_remote, has_permission, log_action, permission_required, server_access_required)
import collections
import threading
from panel.core.http import (_json_body, _json_str, _log_and_generic, _unreachable)
from panel.core.validation import (NOT_AN_IP)
from panel.security import privileged as _priv
from panel.services import host_reboot as _hr
from app import (_log, _os_update_born, _os_update_current, _os_update_note)
from panel.routes.manage_servers import (withheld_game_ports)


# One SSH port change per host at a time. The move snapshots and restores ONE fixed drop-in path
# per host, so two overlapping changes (a double-submit is enough) interleave: one's revert restored
# or deleted the drop-in the other had just written and verified, and the panel stored a port sshd
# no longer served while reporting success. The panel is one process, so an in-process lock per
# host id is the whole fix; threading is green under eventlet's monkey-patching. Registered so a
# deleted host's lock is forgotten with its other per-host state.
_ssh_port_locks = _sm._core.register_remote_cache(collections.defaultdict(threading.Lock))


def _resync_game_port(gs, info, withheld=()):
    """Store the game port LinuxGSM reports when it differs from the stored one; return that port.

    Not a port in `withheld` (withheld_game_ports: another server's block, SSH, the panel). The
    report is `details` run as the game account, over a config that account can write, and the
    stored port is what every later firewall step, the monitor and the uninstall act on — "Game
    22" made them all act on SSH. A refused port leaves the row as it was, and that is returned.
    """
    gp = info.get("game_port")
    if gp and gp in withheld:
        return gs.port
    if gp and gp != gs.port:
        gs.port = gp
        db.session.commit()
    return gp


def _ports_to_sync(gs, info):
    """Re-sync `gs`'s stored port from `info` and split its ports. -> (port, to_open, refused).

    Refused: every reported port withheld_game_ports names — another server's block on the host,
    SSH, the panel — which is neither stored on the row nor opened.
    """
    withheld = withheld_game_ports(GameServer.query.filter_by(remote_id=gs.remote_id).all(), gs,
                                   _sm.protected_host_ports(gs.remote))
    gp = _resync_game_port(gs, info, withheld)
    wanted = info.get("open_ports") or ([gs.port] if gs.port else [])
    return (gp, [p for p in wanted if p not in withheld],
            sorted({p for p in wanted if p in withheld}))


def _sync_ports_detail(opened, missed, refused=()):
    """Audit detail for a port sync: what opened, and what FAILED or was REFUSED when anything was."""
    detail = (("opened %s" % (opened or "none")) if not missed
              else "opened %s; FAILED %s" % (opened or "none", missed))
    if refused:
        detail += "; REFUSED %s" % sorted(refused)
    return detail


def _sync_ports_message(opened, missed, refused=()):
    """Word a port sync's result for the user: what opened, what did not, and what was refused.

    Refused: the ports it would not open because another server, SSH or the panel has them.
    """
    msg = (_sync_ports_plain_message(opened, missed) if (opened or missed or not refused)
           else "No ports were opened.")
    if refused:
        # A helper, not a route: the text goes out inside jsonify(), and the ports are ints.
        # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string
        msg += (" Not opened: %s — another game server on this host, SSH or the panel uses it."
                % ", ".join(map(str, refused)))
    return msg


def _sync_ports_plain_message(opened, missed):
    """_sync_ports_message's wording for what the firewall took and did not take."""
    if not missed:
        # A helper, not a route: the text goes out inside jsonify(), and the ports are ints.
        # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string
        return "Ports %s opened." % (", ".join(map(str, opened)) or "—")
    if opened:
        # A helper, not a route: the text goes out inside jsonify(), and the ports are ints.
        # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string
        return ("Opened %s, but %s could not be opened — check the host's firewall."
                % (", ".join(map(str, opened)), ", ".join(map(str, missed))))
    # A helper, not a route: the text goes out inside jsonify(), and the ports are ints.
    # nosemgrep: python.flask.security.audit.directly-returned-format-string.directly-returned-format-string
    return ("No ports could be opened (%s) — the host's firewall did not accept the "
            "rules." % ", ".join(map(str, missed)))


def register(app):
    """Register a host's firewall, SSH, port, stats, OS-update and reboot routes on `app`."""
    _register_firewall_view(app)
    _register_firewall_rules(app)
    _register_ssh_settings(app)
    _register_panel_port(app)
    _register_game_ports(app)
    _register_host_stats(app)
    _register_os_update_checks(app)
    _register_os_update_jobs(app)
    _register_host_players(app)
    _register_reboot(app)
    _register_host_pages(app)


def _register_firewall_view(app):
    """Firewall: the page, its rule list, and re-trusting a changed host key."""
    @app.route("/remote/<int:remote_id>/firewall")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def remote_firewall(remote_id):
        """Remote VPS firewall management page."""
        # get_host_remote: on the panel's own host this read is superadmin-only, as its write twins
        # and its /server-management page are; a delegable whole-host grant does not reach it.
        remote = get_host_remote(remote_id)
        try:
            status = remote_ufw_status(remote)
        except ConnectionError:
            # A host that is down, rebooting or behind a dropped tunnel raises here, and this
            # view rendered a 500 for it — while the API twin below, calling the same function,
            # has always caught ConnectionError and answered "unreachable". A page whose whole
            # job is managing a remote must survive that remote being off.
            #
            # This is the same shape remote_ufw_status() returns when the command runs but fails,
            # so the template has one unreachable state to render rather than two.
            # remote.id, not the raw remote_id path segment: get_remote() has already looked the
            # host up and enforced access, so this is the integer primary key off the row rather
            # than request input reaching a log sink (py/log-injection). Same shape as the other
            # id-logging sites in panel/routes/_shared.py.
            _log.info("remote firewall page: remote %s unreachable", remote.id, exc_info=True)
            status = {"installed": False, "enabled": False, "rules": [], "groups": [],
                      "unreachable": True}
        games = GameServer.query.filter_by(remote_id=remote_id).all()
        return render_template("remote_firewall.html", remote=remote, status=status, games=games)

    @app.route("/api/remote/<int:remote_id>/firewall")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall(remote_id):
        # get_host_remote: on the panel's own host this read is superadmin-only, as its write twins
        # and its /server-management page are; a delegable whole-host grant does not reach it.
        remote = get_host_remote(remote_id)
        try:
            return jsonify(remote_ufw_status(remote))
        except ConnectionError:
            return _unreachable("remote firewall status")

    @app.route("/api/remote/<int:remote_id>/retrust-hostkey", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_retrust_hostkey(remote_id):
        # Clear the pinned SSH host key so the next connection re-pins it (TOFU). Use
        # after legitimately reinstalling a server, when its host key has changed and
        # connections are being rejected as a mismatch.
        remote = get_remote(remote_id)
        old_fp = remote.host_key_fingerprint
        remote.host_key = ""
        db.session.commit()
        try:
            close_connection(remote)   # drop any cached client → reconnect fresh
        except Exception:
            _log.debug("no cached connection to drop, or it's already gone", exc_info=True)
        log_action(current_user, "retrust_hostkey", target=remote.name,
                   detail="cleared pinned host key (%s)" % (old_fp or "none"), remote=remote)
        return jsonify({"success": True,
                        "message": "Host key cleared — it will be re-pinned on the next connection."})


# What a firewall audit row names in place of a port or protocol that did not validate: a fixed
# text, never the request's own.
_FW_AUDIT_NOT_A_PORT = "(not a port)"
_FW_AUDIT_NOT_A_PROTOCOL = "(not a protocol)"
_FW_AUDIT_NOT_A_RULE = "(not a rule number)"


def _fw_port_arg(value):
    """A firewall route's `port` as the firewall helpers may be handed it; "" when it is not one.

    The helpers parse it with `int(port)` under `except (TypeError, ValueError)`, and Python's json
    reads `Infinity` (or `1e400`) as a float whose int() raises OverflowError — so
    `{"port": Infinity}` was a 500 from every firewall route. A whole finite float is its int, a
    fractional one is not a port (int() truncated 22.9 to 22), and anything else that is not a
    string or an int is not one either. "" is what the routes already refuse as "Port required".
    """
    if isinstance(value, bool):
        return ""
    if isinstance(value, float):
        return int(value) if value.is_integer() else ""
    return value if isinstance(value, (int, str)) else ""


def _fw_proto_arg(value, default="tcp"):
    """A firewall route's `protocol` as text. `(protocol or "").strip()` raised on `5`.

    Stringified rather than dropped: a dropped protocol reads as "" and _ufw_proto maps "" to BOTH,
    which would widen the rule; "5" is refused as not a protocol, which is the honest answer.
    """
    if value is None:
        return default
    return value if isinstance(value, str) else str(value)


def _fw_audit_rule(port, proto, ranges=False):
    """The (port, protocol) a firewall audit row names: each as validated, or a fixed text.

    The request's own port and protocol went into the row's target, and the row is written
    whether or not the command refused them, so a MANAGE_REMOTES admin could put any text in the
    audit trail. Each is read the way the command reads it: a port as one number
    (_ufw_port_int), or with `ranges` as the number or lo:hi spec allow-from takes; a protocol as
    _ufw_proto makes it (tcp, udp or both).
    """
    kind = _fw_hosts._ufw_proto(None if proto is None else str(proto)) or _FW_AUDIT_NOT_A_PROTOCOL
    if ranges:
        spec = str(port or "").strip()
        return (spec if _fw_hosts._UFW_PORT_SPEC_RE.match(spec) else _FW_AUDIT_NOT_A_PORT), kind
    try:
        return str(_fw_hosts._ufw_port_int(port)), kind
    except (TypeError, ValueError, OverflowError):
        return _FW_AUDIT_NOT_A_PORT, kind


def _fw_audit_rule_number(num):
    """The rule number a delete-rule audit row names, read as the delete reads it, or a fixed text.

    The request's own `num` went into the target whatever it held.
    """
    try:
        n = int(num)
    except (TypeError, ValueError, OverflowError):     # OverflowError: {"num": Infinity}
        return _FW_AUDIT_NOT_A_RULE
    return str(n) if n >= 1 else _FW_AUDIT_NOT_A_RULE


def _fw_audit_source(source):
    """The source an allow-from audit row names: the spelling the rule was sent with, or NOT_AN_IP.

    canonical_cidr, the same parse remote_ufw_allow_from sends and reports, so the audit, the
    message and the rule agree — an IPv6 source keeps its host bits there, as ufw stores it.
    """
    try:
        return _priv.canonical_cidr((source or "").strip())
    except _priv.VerbError:
        return NOT_AN_IP


def _register_firewall_rules(app):
    """Firewall: open, allow-from, limit, close and delete rules."""
    @app.route("/api/remote/<int:remote_id>/firewall/open", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_open(remote_id):
        remote = get_host_remote(remote_id)
        data = _json_body()
        port = _fw_port_arg(data.get("port", ""))
        proto = _fw_proto_arg(data.get("protocol", "tcp"))
        if not port:
            return jsonify({"success": False, "message": "Port required"}), 400
        success, msg = remote_ufw_open_port(remote, port, proto, data.get("comment", ""))
        a_port, a_proto = _fw_audit_rule(port, proto)
        log_action(current_user, "remote_port_open", target=f"{remote.name}:{a_port}/{a_proto}",
                   success=success, remote=remote)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/firewall/allow-from", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_allow_from(remote_id):
        """Open a port only from one address or network (`allow: false` removes the rule).

        The gap this fills: every other allow here opens a port to the internet, so a port that
        only you or only your LAN should reach had no way to say so.
        """
        remote = get_host_remote(remote_id)
        data = _json_body()
        source = _json_str(data, "source")
        port = _fw_port_arg(data.get("port", ""))
        proto = _fw_proto_arg(data.get("protocol", "tcp"))
        on = data.get("allow", True) is not False
        if not source or not port:
            return jsonify({"success": False, "message": "Source and port required"}), 400
        success, msg = remote_ufw_allow_from(remote, source, port, proto,
                                             data.get("comment", ""), allow=on)
        # The rule as it was sent, never the request's text (an IPv6 zone id parsed).
        a_port, a_proto = _fw_audit_rule(port, proto, ranges=True)
        log_action(current_user, "remote_port_allow_from" if on else "remote_port_allow_from_remove",
                   target=f"{remote.name}:{a_port}/{a_proto}",
                   detail="from %s" % _fw_audit_source(source),
                   success=success, remote=remote)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/firewall/limit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_limit(remote_id):
        """Rate-limit a port, or lift the limit (`limit: false`).

        UFW has done this since forever and the panel has used it on every bootstrap to harden
        SSH — it just had no way to ask for it on a port you choose.
        """
        remote = get_host_remote(remote_id)
        data = _json_body()
        port = _fw_port_arg(data.get("port", ""))
        proto = _fw_proto_arg(data.get("protocol", "tcp"))
        on = data.get("limit", True) is not False
        if not port:
            return jsonify({"success": False, "message": "Port required"}), 400
        success, msg = remote_ufw_limit_port(remote, port, proto, limit=on)
        a_port, a_proto = _fw_audit_rule(port, proto)
        log_action(current_user, "remote_port_limit" if on else "remote_port_unlimit",
                   target=f"{remote.name}:{a_port}/{a_proto}", success=success, remote=remote)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/firewall/close", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_close(remote_id):
        remote = get_host_remote(remote_id)
        data = _json_body()
        port = _fw_port_arg(data.get("port", ""))
        proto = _fw_proto_arg(data.get("protocol", "tcp"))
        if not port:
            return jsonify({"success": False, "message": "Port required"}), 400
        success, msg = remote_ufw_close_port(remote, port, proto)
        a_port, a_proto = _fw_audit_rule(port, proto)
        log_action(current_user, "remote_port_close", target=f"{remote.name}:{a_port}/{a_proto}",
                   success=success, remote=remote)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/firewall/delete-rule", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_firewall_delete_rule(remote_id):
        """Delete a UFW rule by its number (the reliable way to remove any rule)."""
        remote = get_host_remote(remote_id)
        num = _fw_port_arg(_json_body().get("num"))   # the same int() in the helper: see there
        # The rule's identity, when the page sends it: the number is a position, and anything
        # inserted since the page re-read the firewall (the auto-block inserts at 1) moves it onto
        # another rule. The delete then happens only if `num` is still that rule.
        key = _json_body().get("key")
        success, msg = remote_ufw_delete_rule(remote, num,
                                              expect_key=key if isinstance(key, str) and key else None)
        log_action(current_user, "remote_ufw_delete_rule",
                   target=f"{remote.name}:#{_fw_audit_rule_number(num)}", success=success,
                   remote=remote)
        return jsonify({"success": success, "message": msg})


def _register_ssh_settings(app):
    """SSH: status, public exposure through UFW (allow / limit / off), and port."""
    @app.route("/api/remote/<int:remote_id>/ssh-status")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_ssh_status(remote_id):
        # get_host_remote: on the panel's own host this read is superadmin-only, as its write twins
        # and its /server-management page are; a delegable whole-host grant does not reach it.
        remote = get_host_remote(remote_id)
        try:
            # On the panel host, also report whether the panel's own public web port is
            # still open, so the UI can disable "Close public panel port" once it's closed.
            panel_port = load_config().get("port", 5000) if remote.is_local else None
            st = remote_public_ssh_status(remote, panel_port=panel_port)
            st["auth_method"] = remote.auth_method
            return jsonify(st)
        except Exception:
            return jsonify({"error": _log_and_generic("ssh-status failed")}), 200

    @app.route("/api/remote/<int:remote_id>/ssh-mode", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_ssh_mode(remote_id):
        """Set public SSH via UFW: allow / limit / off (tailnet-only)."""
        remote = get_host_remote(remote_id)
        mode = _json_body().get("mode", "")
        success, msg = remote_set_public_ssh(remote, mode)
        log_action(current_user, "remote_ssh_mode", target=f"{remote.name}:{mode}", success=success,
                   remote=remote)
        return jsonify({"success": success, "message": msg})

    @app.route("/api/remote/<int:remote_id>/ssh-port", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_ssh_port(remote_id):
        """Move this host's sshd to a new port, lockout-safe.

        The old port stays open as a fallback, and UFW + fail2ban are updated with it. Works for a
        remote and the panel host itself.
        """
        if not (current_user.is_superadmin or can_access_remote(current_user, remote_id)):
            return jsonify({"success": False, "message": "You don't have access to that host."}), 403
        remote = get_host_remote(remote_id)
        body = _json_body()
        try:
            new_port = int(body.get("port"))
        except (TypeError, ValueError, OverflowError):     # OverflowError: {"port": Infinity}
            return jsonify({"success": False, "message": "Enter a valid port number."}), 400
        if not (1 <= new_port <= 65535):
            return jsonify({"success": False, "message": "Port must be between 1 and 65535."}), 400
        bind = _json_str(body, "bind")
        old = remote.port
        # Held across the move AND the port commit that follows it, so a second change cannot read
        # the port the first is about to replace.
        lock = _ssh_port_locks[remote_id]
        if not lock.acquire(blocking=False):
            return jsonify({"success": False,
                            "message": "An SSH port change is already running for this host."}), 409
        try:
            try:
                ok, msg = change_ssh_port(remote, new_port, bind)
            except Exception:
                return jsonify({"success": False,
                                "message": _log_and_generic("SSH port change failed")}), 500
            if ok:
                # Point the panel at the new port for future connections (cosmetic for the local
                # host, which doesn't SSH). Same host, so the pinned host key still applies — leave
                # it. The old port stays open, so any connection the panel is using right now
                # survives.
                remote.port = new_port
                db.session.commit()
        finally:
            lock.release()
        log_action(current_user, "change_ssh_port", target=remote.name,
                   detail=f"{old} -> {new_port}", success=ok, remote=remote)
        return jsonify({"success": ok, "message": msg})


def _register_panel_port(app):
    """Close the panel's public web port so the UI is reachable only over the tailnet."""
    @app.route("/api/remote/<int:remote_id>/close-panel-port", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_close_panel_port(remote_id):
        """Close the panel's public web port on the panel host so the UI is reachable only over the tailnet.

        Refuses unless Tailscale Serve is configured — otherwise this would remove your only way
        into the panel.
        """
        remote = get_host_remote(remote_id)
        if not remote.is_local:
            return jsonify({"success": False, "message": "Only applies to the panel host."}), 400
        cfg = load_config()
        if not cfg.get("tailscale_setup_done"):
            return jsonify({"success": False, "message": "Set up Tailscale Serve first — "
                            "otherwise closing the public port would lock you out of the panel."}), 400
        try:
            port = int(cfg.get("port", 5000))
        except (TypeError, ValueError):
            port = 5000

        def _panel_port_rule_nums():
            """([(rule number, rule key)], read_ok). An unread firewall is NOT an empty one."""
            st = remote_ufw_status(remote)
            # remote_ufw_status answers {"installed": False, ..., "groups": []} when ufw is
            # missing, and adds "unreachable": True when the command failed or printed no
            # "Status:" line — its own docstring says it does that so a down remote is not shown
            # as an installed firewall with no rules. Reading only .get("groups") threw that away:
            # a host that never answered produced nums == [], which this route reported as
            # "already closed" with success=True and no audit row, while the panel was still
            # listening on 0.0.0.0. The sibling hardening path already refuses an unverifiable
            # firewall — remote_set_public_ssh returns "UFW is not active on this host, so public
            # SSH cannot be controlled from here", after an earlier version of THAT produced "an
            # audit row saying the hardening succeeded, and port 22 open to the internet".
            if st.get("unreachable") or not st.get("installed"):
                return [], False
            nums = []
            for g in st.get("groups", []):
                # ...and only rules that actually HOLD THE PORT OPEN. The action test matches the
                # is_panel classifier in firewall.py; without it a DENY on this port was collected
                # and force-deleted as though it were letting traffic in.
                if (not g.get("is_iface") and str(g.get("port_num", "")) == str(port)
                        and g.get("action", "ALLOW") in ("ALLOW", "LIMIT")
                        and g.get("direction", "IN") != "OUT"):
                    nums.extend((n, g.get("key")) for n in g.get("nums", []))
            return sorted(set(nums), reverse=True), True   # highest first so numbering stays valid

        nums, read_ok = _panel_port_rule_nums()
        if not read_ok:
            return jsonify({"success": False, "message": (
                f"Couldn't read the firewall on this host, so port {port} can't be closed from "
                f"here. Check the host is reachable and that UFW is installed, then try again.")})
        if not nums:
            return jsonify({"success": True, "message": f"Public port {port} is already closed."})
        # Delete by rule NUMBER (reliable across any rule format), force=True since this is
        # the intentional guided close and Serve is already confirmed as the way in.
        # Each with the rule's KEY: highest-first keeps the numbers valid only against this loop's
        # own deletes, and the auto-block reconcile inserts its denies at 1 from another thread —
        # one insert mid-loop and a forced delete by number took the rule above the panel port's
        # (an attacker's deny, a game port). A moved number is refused; the verify read reports it.
        for n, key in nums:
            remote_ufw_delete_rule(remote, n, force=True, expect_key=key)
        _left, _verify_ok = _panel_port_rule_nums()
        # A verify read that FAILED cannot say the port is closed either.
        ok = _verify_ok and not _left
        log_action(current_user, "close_panel_port", target=str(port), success=ok, remote=remote)
        return jsonify({"success": ok, "message": (
            f"Public port {port} closed — the panel is now reachable only over your tailnet."
            if ok else f"Couldn't remove every rule for port {port}; check the firewall page.")})


def _rv_on_panel_host(gs):
    """Whether this server lives on the PANEL host (the inline test get_host_remote uses)."""
    return (getattr(gs.remote, "is_local", False)
            or getattr(gs.remote, "auth_method", None) == "local")


def _rv_sync_ports_run(gs):
    """Detect the server's ports, open what may be opened, audit it, and report what landed."""
    info = detect_game_ports(gs.remote, gs.short_name, gs.lgsm_name)
    gp, to_open, refused = _ports_to_sync(gs, info)
    # Report what the firewall ACTUALLY took, not what was asked for. The return value
    # used to be discarded on the reasoning that "the firewall page reports a partially
    # applied rule set" — but this said "Ports 27015, 27016 opened." and wrote an audit
    # row with success=True whether or not a single rule landed. An audit row that
    # records an action which did not happen is worse than no row.
    opened, _ = remote_ufw_allow_game_ports(gs.remote, to_open, gs.short_name)
    opened = sorted(set(opened or []))
    missed = [p for p in to_open if p not in set(opened)]
    # The verdict lives in the reply itself rather than a local: CodeQL reported `success=ok`
    # one line after `ok`'s only assignment as possibly unset (alerts 512 and 542), whatever
    # came before it.
    reply = {"success": not (missed or refused)}
    log_action(current_user, "sync_ports", target=gs.name, success=reply["success"],
               detail=_sync_ports_detail(opened, missed, refused), server=gs)
    reply.update({"message": _sync_ports_message(opened, missed, refused),
                  "ports": info.get("ports", []), "open_ports": opened,
                  "requested_ports": to_open, "failed_ports": missed,
                  "refused_ports": refused, "game_port": gp})
    return jsonify(reply)


def _register_game_ports(app):
    """Game ports: open one, or sync a server's ports into the firewall."""
    @app.route("/api/remote/<int:remote_id>/game-port/<int:port>/open", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_game_port_open(remote_id, port):
        """Open ONE game server's port in the host firewall.

        MANAGE_REMOTES only. This used to accept MANAGE_REMOTES *or* INSTALL_SERVER, while every
        other firewall write on the same host (/firewall/open, /allow-from, /limit, /close,
        /delete-rule) requires MANAGE_REMOTES alone — so a user with a host grant and only
        INSTALL_SERVER could open any port on that host to the internet, on a firewall they
        otherwise have no rights over. `port` is entirely caller-chosen: 22, 3306, 6379 are as
        valid to the route as 27015.

        And the port must actually BELONG to a game server on this host, which is what the route's
        name has always claimed. The row was looked up only to pick the UFW comment, falling back
        to "Game" when it did not exist — so a port nothing serves was opened just as readily. This
        now refuses rather than guessing. (Its sibling api_server_sync_ports was called the safe
        one because its ports come from detect_game_ports() — but that is the game account's own
        config talking, so it is MANAGE_REMOTES-only now as well.)
        """
        remote = get_host_remote(remote_id)   # the PANEL host's firewall: superadmins (see below)
        gs = GameServer.query.filter_by(remote_id=remote_id, port=port).first()
        if gs is None:
            return jsonify({"success": False,
                            "message": "No game server on this host uses port %d — refusing to "
                                       "open it." % port}), 400
        count, msg = remote_ufw_allow_game_port(remote, port, gs.short_name)
        success = count >= 1
        log_action(current_user, "game_port_open", target=f"{remote.name}:{port}", success=success,
                   remote=remote)
        return jsonify({"success": success, "message": msg, "rules_added": count})

    @app.route("/api/server/<int:server_id>/sync-ports", methods=["POST"])
    @login_required
    @server_access_required
    def api_server_sync_ports(server_id):
        """Detect ALL of a game server's ports from LinuxGSM and open every one in the firewall.

        That covers game/query/rcon/etc. Also re-syncs the stored port. Fixes servers
        that were installed before multi-port support, or whose ports changed.

        MANAGE_REMOTES, on THIS host, like every other write to a host's firewall — the same
        correction api_remote_game_port_open had. It accepted INSTALL_SERVER too, on the reasoning
        that its ports come from detect_game_ports rather than the caller. They come from
        `details`, run as the game account, over a config that account — and anyone with
        MANAGE_SERVERS, through the file manager — can write. The stock "admin" group has
        INSTALL_SERVER and MANAGE_SERVERS and not MANAGE_REMOTES, so it could put persistent
        root-owned allow rules on a firewall it has no rights over, and re-tag (then, uninstalling,
        delete) other servers' rules. Its only caller is the Firewall page, which already needs
        MANAGE_REMOTES on the host.

        And whoever calls it, a port another game server on the host holds, or SSH's, or the
        panel's, is neither opened nor stored (withheld_game_ports).
        """
        gs = get_game(server_id)
        # ...and on the PANEL host, a superadmin. Every firewall write there is superadmin-only
        # (get_host_remote), because that firewall guards the panel itself; the five /firewall/*
        # routes and game-port/open above take it through get_host_remote, but this one is keyed
        # on a SERVER, and a delegated MANAGE_REMOTES admin whose group covered the panel host
        # could still put allow rules on it from here. Same inline test get_host_remote uses.
        _panel_host = _rv_on_panel_host(gs)
        if not (current_user.is_superadmin
                or (has_permission(current_user, MANAGE_REMOTES)
                    and can_access_remote(current_user, gs.remote_id)
                    and not _panel_host)):
            return jsonify({"success": False, "message": "Permission denied"}), 403
        try:
            return _rv_sync_ports_run(gs)
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("request failed")}), 500


def _register_host_stats(app):
    """Host stats: live usage and uptime."""
    @app.route("/api/remote/<int:remote_id>/live-stats")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_live_stats(remote_id):
        """Real-time CPU, RAM, disk, uptime from the remote VPS.

        Also persisted to the remote so the card can render the last-known values instantly on the
        next load instead of showing a spinner.
        """
        remote = get_remote(remote_id)
        try:
            stats = remote_uptime(remote)
            # Only persist a reading that actually happened. remote_uptime does not raise when the
            # host says nothing — it returns its placeholder dict ("uptime": "unknown", load/disk/
            # memory/cpu all "?") — and it refuses to put that in its OWN cache: see the
            # `if server is not None and out:   # don't cache a failed/empty read` at the end of
            # it. Writing the same dict to the database was strictly worse than the thing the
            # helper declines to do: one unreachable poll replaced the row's last-known values
            # with "?" for good, which is what the card renders on the next load.
            if stats.get("read_ok"):
                try:
                    remote.update_cached_stats(stats)
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            return jsonify({"success": True, **stats})
        except Exception:
            # Unreachable host is expected — 200 with an error field, not a console 500.
            return jsonify({"success": False, "error": _log_and_generic("remote live-stats failed")}), 200

    @app.route("/api/remote/<int:remote_id>/uptime")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_uptime(remote_id):
        remote = get_remote(remote_id)
        try:
            return jsonify(remote_uptime(remote))
        except ConnectionError:
            return _unreachable("remote uptime")


def _current_os_updates(snapshot):
    """([(id, entry)] for each cached check that belongs to the row holding its id NOW, the local id).

    An entry noted for an earlier host with the same id is not this one's (see _os_update_current)
    — nor is one for an id no row holds any more. ONE query for the whole snapshot, which also
    answers which of these hosts is the panel's own: that used to be a query of its own
    (_local_remote_id), so the identity check costs the banner nothing — it is on every page load,
    and its query budget is asserted.
    """
    rows = (db.session.query(RemoteServer.id, RemoteServer.created_at, RemoteServer.is_local)
            .filter(RemoteServer.id.in_(list(snapshot))).all())
    born = {rid: created for rid, created, _local in rows}
    local_id = next((rid for rid, _created, is_local in rows if is_local), None)
    return ([(rid, seen) for rid, seen in sorted(snapshot.items())
             if rid in born and _os_update_current(seen, born[rid])], local_id)


def _register_os_update_checks(app):
    """OS updates: check, summarise, read the cache, run."""
    @app.route("/api/remote/<int:remote_id>/check-updates")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_check_updates(remote_id):
        """Force a fresh check on one host.

        The panel host runs it locally rather than over SSH to itself, which is what the daily sweep
        does too.
        """
        # get_host_remote: on the panel's own host this read is superadmin-only, as its write twins
        # and its /server-management page are; a delegable whole-host grant does not reach it.
        remote = get_host_remote(remote_id)
        born = _os_update_born(remote)   # before any SSH — see _os_update_born
        try:
            result = (so.os_update_available(refresh=True) if remote.is_local
                      else _sm.remote_os_check_updates(remote))
        except ConnectionError:
            # Same reasoning as the "ok" flag below — a host we could not ask is not a host that is
            # up to date. The difference is that this one could not be asked at all.
            return _unreachable("remote check-updates")
        # "ok" travels to the UI: a check that failed (apt locked by unattended-upgrades, host mid
        # reboot) returns an empty list, and without this the card would report "System is up to
        # date" for a host nobody managed to ask.
        _os_update_note(remote, result, born)
        return jsonify({"ok": bool(result.get("ok")), "count": result["count"],
                        "packages": result["packages"]})

    @app.route("/api/os-updates/summary")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_os_updates_summary():
        """What every host had waiting as of its last check — served from memory, never probing.

        This is what the login banner and the OS Updates card render. Page loads must not trigger
        `apt update` (a network fetch per host, 60s timeout each), so they read the daily sweep's
        answer instead; the Check button is there for anyone who wants it re-asked now.
        """
        # .copy() rather than iterating the live dict: the daily sweep writes to it from its own
        # thread, and a resize mid-iteration would 500 the page this banner sits on.
        snapshot = _os_update_seen.copy()
        if not snapshot:
            return jsonify({"hosts": []})     # nothing known yet — don't spend a query finding out
        hosts = []
        current, local_id = _current_os_updates(snapshot)
        # The accessible set, resolved ONCE. can_access_remote per host is the same answer and
        # costs a query set each time it is asked — fine when the grants were lazily cached on the
        # user, and three queries per host now that they are eagerly loaded. Same check, same
        # result, asked once instead of once per host in the snapshot.
        _allowed = None if current_user.is_superadmin else accessible_remote_ids(current_user)
        for rid, seen in current:
            if not seen.get("count"):
                continue
            # MANAGE_REMOTES is scoped per host (see get_remote): a user who can manage one remote
            # must not learn the name or patch state of another's from this summary.
            if _allowed is not None and rid not in _allowed:
                continue
            hosts.append({"id": rid, "name": seen["name"], "count": seen["count"],
                          "security": seen["security"], "at": seen["at"],
                          # The panel host has a dedicated page, but it is superadmin-only — anyone
                          # else reaching it through the banner would land on a 403, so send them
                          # to the same host's ordinary manage page (it is just a remote row).
                          "url": url_for("server_management")
                                 if rid == local_id and current_user.is_superadmin
                                 else url_for("remote_manage", remote_id=rid)})
        return jsonify({"hosts": hosts})

    @app.route("/api/remote/<int:remote_id>/updates-cached")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_updates_cached(remote_id):
        """One host's last-known package list, as {known:false} when nothing has checked it yet.

        It fills the OS Updates card on page load without making the page wait on apt.
        """
        remote = get_remote(remote_id)
        seen = _os_update_seen.get(remote.id)
        if not _os_update_current(seen, remote.created_at):
            return jsonify({"known": False})
        return jsonify({"known": True, "count": seen["count"], "security": seen["security"],
                        "at": seen["at"], "packages": seen["packages"]})

    @app.route("/api/remote/<int:remote_id>/run-updates", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_run_updates(remote_id):
        remote = get_host_remote(remote_id)
        if _hr.reboot_busy(remote.id):
            return jsonify({"success": False, "message": _hr.BUSY_MESSAGE % remote.display_name}), 409
        success, msg = remote_os_run_updates(remote)
        log_action(current_user, "remote_os_update", target=remote.name, success=success,
                   remote=remote)
        return jsonify({"success": success, "message": msg})


def _register_os_update_jobs(app):
    """OS updates: start a background upgrade and poll it."""
    @app.route("/api/remote/<int:remote_id>/os-update/start", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_os_update_start(remote_id):
        """Start a detached, watchable OS update; the popup polls .../os-update/status for live output."""
        remote = get_host_remote(remote_id)
        if _hr.reboot_busy(remote.id):
            return jsonify({"success": False, "message": _hr.BUSY_MESSAGE % remote.display_name}), 409
        try:
            ok, msg = remote_os_update_start(remote)
            if ok:
                log_action(current_user, "remote_os_update", target=remote.name, detail="started",
                           remote=remote)
            return jsonify({"success": ok, "message": msg})
        except Exception:
            return jsonify({"success": False, "message": _log_and_generic("couldn't start update")}), 500

    @app.route("/api/remote/<int:remote_id>/os-update/status")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_os_update_status(remote_id):
        """Live output + running/done state of the OS update, for the watch popup."""
        remote = get_remote(remote_id)
        try:
            return jsonify(remote_os_update_status(remote))
        except Exception:
            # NOT done. A status read that raised (a dropped paramiko session mid-upgrade) said
            # done:true, and the popup declared the update finished with errors and stopped
            # watching while apt was still running on the host.
            return jsonify({"running": None, "done": False, "rc": None, "unread": True,
                            "log": "", "error": _log_and_generic("status read failed")}), 200


def _register_host_players(app):
    """Players online across a host's servers."""
    @app.route("/api/remote/<int:remote_id>/players")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_players(remote_id):
        """Players connected across ALL installed game servers on this host, before a reboot.

        host_reboot.host_player_state, the one census the reboot gate, the wait and this dialog all
        read: {state: idle|busy|unknown|blocked|unreachable, total, running, busy:[{id, name,
        players}], unknown:[{id, name, reason, queryable}], blockers:[{kind, name, detail}]}.

        `unknown` is the whole point: a count that could not be read (or a server whose state
        could not be) is NOT an empty server. Verified on the test box: an online server the panel
        could not read answered {"busy":[],"total":0}, and the reboot confirm then said nothing
        about it and disconnected whoever was on. A server that is not running is not listed: it
        has nobody on it, which is not a warning.
        """
        remote = get_remote(remote_id)
        census = _hr.host_player_state(remote)
        census.pop("probes", None)
        return jsonify(census)


def _register_reboot(app):
    """Reboot: whether one is needed, ask for one, see it run, cancel it."""
    @app.route("/api/remote/<int:remote_id>/reboot-required")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_reboot_required(remote_id):
        """Whether this host needs a reboot, and whether one is pending or running for it.

        {required, packages[], known, pending_empty, wait, job}: `wait` is a pending "reboot when
        everyone has left", `job` a reboot the panel is running now. Either keeps the banner up even
        when no reboot is required, so a wait is never invisible (or uncancellable).
        """
        remote = get_remote(remote_id)
        try:
            info = dict(remote_reboot_required(remote))
        except Exception:
            info = {"required": False, "packages": []}
        st = _hr.status(remote)
        info["pending_empty"] = st["wait"] is not None
        info["wait"], info["job"] = st["wait"], st["job"]
        return jsonify(info)

    @app.route("/api/remote/<int:remote_id>/reboot-plan")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_reboot_plan(remote_id):
        """The Power card's state: {wait, job, rows, last}; with ?preview=1, what a reboot would do.

        The preview reads every installed server (read-only) and answers per server who brings it
        back: [{id, name, session, owner, why, text}], plus `panel_wont_return` on the panel host.
        """
        remote = get_host_remote(remote_id)
        if request.args.get("preview") == "1":
            pv = _hr.preview(remote)
            warn = _hr.preflight_warning(remote, pv)
            return jsonify({"servers": pv, "panel_wont_return": warn is not None, "warning": warn,
                            "wait_hours": _hr.wait_max_hours()})
        return jsonify(_hr.status(remote))

    @app.route("/api/remote/<int:remote_id>/reboot", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_reboot(remote_id):
        """Reboot a host cleanly: its game servers are stopped first and brought back as planned.

        Body {mode}: 'now', or 'when_empty' (reboot once nobody is on any of its game servers).
        With no mode, a host with players on — or with a count nobody can read — answers 409
        {error: "players_online", needs_choice, choices, players} instead of rebooting, and the
        caller asks again with the mode the person chose. The older {when_empty: true|false} and
        {force: true} still work. 202 when the reboot is under way, 200 when the wait is armed.
        """
        remote = get_host_remote(remote_id)
        mode, err = _hr.parse_mode(_json_body())
        if err:
            return jsonify({"success": False, "error": "bad_mode", "message": err}), 400
        code, body = _hr.request_reboot(remote, mode, current_user, "web")
        return jsonify(body), code

    @app.route("/api/remote/<int:remote_id>/reboot-cancel", methods=["POST"])
    @login_required
    @permission_required(MANAGE_REMOTES)
    def api_remote_reboot_cancel(remote_id):
        """Cancel this host's pending wait, or a reboot that has not been sent yet."""
        remote = get_host_remote(remote_id)
        code, body = _hr.cancel(remote, current_user)
        return jsonify(body), code


def _register_host_pages(app):
    """Register the host management page and its hardware specs."""
    @app.route("/remote/<int:remote_id>/manage")
    @login_required
    @permission_required(MANAGE_REMOTES)
    def remote_manage(remote_id):
        """Rich management page for a remote server, the same experience as the Panel Server.

        Live per-core resources plus OS updates, reboot and firewall.
        """
        remote = get_remote(remote_id)
        games = GameServer.query.filter_by(remote_id=remote_id).all()
        # config=, because remote_manage.html reads config.port / config.bind_host /
        # config.tailscale_setup_done for the panel-host card. Without it Jinja fell back to
        # FLASK'S app.config — truthy, but with no lowercase keys — so every read was empty and
        # every `if config else <default>` fallback was dead code that could not fire. The page
        # said "Public panel access (port )" with the number missing, claimed Serve was not set
        # up when it was, and pre-filled the binding form with 0.0.0.0 and a blank port next to an
        # "Apply & restart" button. server_management passes it; this route did not.
        #
        # status=, for exactly the same reason, on the same call. The Connection & SSH card reads
        # `status` six times inside `{% if remote.is_local and current_user.is_superadmin %}`, and
        # Jinja's Undefined is silently falsy — so `ts_up` and `ssh_lockdown_safe` were both false
        # and every gate read as if Tailscale were absent. On a panel host with Tailscale SSH
        # running, reaching this page (the Terminal's "Back to host" link lands here) said
        # "Tailscale SSH: Disabled" and "Not allowed", greyed out both setup buttons, and gave
        # "Disable (tailnet-only)" `data-lockdown="1" disabled` — which remote_manage_host.js
        # deliberately never re-enables, so the control was unreachable on that page by JS or by
        # reload. Four false statements and three dead controls; /server-management, which passes
        # status, renders the same card correctly.
        #
        # Only for the local host: get_server_status() reads THIS machine, and the card that
        # consumes it is local-only. The template's `{% if status and … %}` / `… if status else …`
        # forms already handle an explicit None for every remote.
        status = so.get_server_status() if remote.is_local else None
        return render_template("remote_manage.html", remote=remote, games=games,
                               status=status, config=load_config())

    @app.route("/api/remote/<int:remote_id>/specs")
    @login_required
    @permission_required(MANAGE_REMOTES, INSTALL_SERVER, MANAGE_SERVERS)
    def api_remote_specs(remote_id):
        """Static hardware/OS specs for a remote host (loaded once, not polled).

        Also the install picker's OS filter (manage_servers.js filterGamesForHost), which is on a
        page for INSTALL_SERVER / MANAGE_SERVERS. Gated on MANAGE_REMOTES alone, this answered
        those users 403, the filter read that as "OS unknown" and left every game selectable —
        the ones this host cannot run included — so they learned it only from the install
        refusal. They get os_slug and nothing else: the hardware card stays MANAGE_REMOTES.
        """
        remote = get_remote(remote_id)
        if not has_permission(current_user, MANAGE_REMOTES):
            try:
                return jsonify({"os_slug": _sm.host_os_slug(remote) or ""})
            except Exception:
                return jsonify({"os_slug": ""})
        # os_slug alongside the pretty OS name: LinuxGSM's own "<id>-<version>", which is what
        # decides whether this host can install a game LinuxGSM caps at an older release. That is
        # a property of THIS host — a 20.04 remote under a 24.04 panel runs those games fine — so
        # the install picker asks here rather than guessing from the catalogue.
        #
        # Added in the ROUTE, not inside host_specs: that helper's contract is ONE probe per host
        # and a unit check pins it ("host_specs: cached (one run_command for two reads)").
        # host_os_slug keeps its own per-host cache, so this is one extra read the first time a
        # host is looked at and nothing thereafter.
        _specs = dict(host_specs(remote) or {})
        try:
            _specs["os_slug"] = _sm.host_os_slug(remote) or ""
        except Exception:
            _specs["os_slug"] = ""          # unreadable: the picker leaves everything selectable
        return jsonify(_specs)
