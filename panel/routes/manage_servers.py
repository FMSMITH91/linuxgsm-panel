"""Adding, installing, editing and uninstalling game servers.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from flask import (flash, jsonify, redirect, render_template, request, url_for)
from flask_login import (current_user, login_required)
from panel.core.panel_state import (_game_backup_status, _install_jobs, _install_lock)
from panel.db.models import (GameServer, RemoteServer, db)
from panel.ops import (backup as bk)
from panel.services import (lgsm_data)
from panel.ops.ssh_manager import (GMOD_CONTENT_GAMES, GMOD_CONTENT_SIZES,
    _remote_listening_ports, detect_game_ports, ensure_content_user, ensure_persistent_bans,
    game_engine as sm_game_engine, gmod_mount_setup, install_game_cron,
    install_game_dependencies, install_gmod_content, lgsm_write_config, parse_missing_deps,
    remote_ufw_allow_game_ports, remote_ufw_close_by_name, remote_ufw_close_game_port,
    set_autostart)
# Reached through the MODULE, not bound by name: these are the seams the test suite
# monkeypatches. `from x import f` copies the function object, so a stub on the source
# module would never be seen — attribute access resolves at call time and is stable
# however the handler moves.
from panel.ops import ssh_manager as _sm
from panel.security.auth import (INSTALL_SERVER, MANAGE_SERVERS, UNINSTALL_SERVER,
    accessible_remote_ids, get_game, get_remote, log_action, permission_required,
    server_access_required)
import threading
import time
from panel.core.http import (_form_err, _form_ok, _log_and_generic, _wants_json)
from panel.core.validation import (GAME_TYPE_RE, INSTANCE_NAME_RE, MAX_PORT, MIN_PORT,
    SAFE_LABEL_RE, _port_or)
from app import (_extract_start_error, _log, _prune_jobs,
    _resolve_source_aux_ports, load_game_list, resolve_free_port)
from panel.routes._shared import (_looks_installed, _notify_servers_changed)

# Serializes the install "slot" allocation (pick a free port → reject a duplicate name → create the
# row). resolve_free_port yields on an SSH scan, so without this two concurrent installs on the same
# remote could both pick the same port or both pass the duplicate-name check before either commits.
#
# Defined here, not in app.py: this module is the only thing that takes it, and a module-private
# name with no use inside its OWN module reads as dead to CodeQL however many other modules import
# it (py/unused-global-variable). The lock is only correct as a single shared object, so there is
# exactly one definition and no one else may make another.
_install_alloc_lock = threading.Lock()


def register(app):
    @app.route("/servers/manage")
    @login_required
    @permission_required(MANAGE_SERVERS, INSTALL_SERVER)
    def manage_servers():
        """Kept as a REDIRECT, not deleted.

        The server list folded into the dashboard: the two pages showed seven of the same eight
        columns and shared no code at all — doAction vs msrvAction, sortDashCol vs sortServers —
        so one of them was a second implementation of the other, drifting on its own.

        The route stays because the URL is in people's bookmarks, in the sidebar's muscle memory,
        and in any link anyone has shared. A 302 costs nothing; a 404 is a support question.
        """
        return redirect(url_for("index"))

    @app.route("/servers/install")
    @login_required
    @permission_required(INSTALL_SERVER, MANAGE_SERVERS)
    def install_server_page():
        """The install form, on its own page.

        It used to sit on /servers/manage above the list of servers you already have — 631px of
        mostly-empty selects for a thing you do once, ahead of the thing you came for. Same
        permission pair as the POST it submits to, so reaching the form and using it are one
        decision rather than two that can drift.
        """
        _my = accessible_remote_ids(current_user)
        remotes = [r for r in RemoteServer.query.all() if r.id in _my]
        # Only downloadable games: the target host is not chosen yet, so mount-only content that
        # may already be present cannot be known here. Same reasoning as the old inline form.
        gmod_games = [{"key": k, "label": v[0], "size": GMOD_CONTENT_SIZES.get(k, "")}
                      for k, v in GMOD_CONTENT_GAMES.items() if v[1] is not None]
        # lgsm_status so the "no games" warning can say WHY rather than guessing at GitHub —
        # a DNS failure, an HTTP 403, a response that was not a CSV and a read-only data/ all
        # look identical from the template otherwise.
        return render_template("install_server.html", remotes=remotes,
                               games=load_game_list(), gmod_games=gmod_games,
                               lgsm_status=lgsm_data.status())

    @app.route("/servers/add", methods=["POST"])
    @login_required
    @permission_required(INSTALL_SERVER, MANAGE_SERVERS)
    def install_game_server():
        remote_id = request.form.get("remote_id", type=int)
        game_type = request.form.get("game_type", "").strip().lower()
        server_name = request.form.get("server_name", "").strip()
        port = request.form.get("port", "27015").strip()
        remote = get_remote(remote_id)

        # SECURITY: game_type and server_name become Linux users / paths / root shell
        # arguments during install — validate strictly to prevent command injection.
        if not GAME_TYPE_RE.match(game_type) or game_type not in {g["shortname"] for g in load_game_list()}:
            return _form_err("Invalid or unknown game type.", "manage_servers")
        if server_name:
            server_name = server_name.lower()
            if not INSTANCE_NAME_RE.match(server_name):
                return _form_err("Server name must be lowercase letters, numbers, - or _ and start with "
                                 "a letter (it becomes a Linux user on the host).", "manage_servers")

        # Canonical LinuxGSM server name — always "{shortname}server".
        lgsm_name = f"{game_type}server"
        short_name = server_name or lgsm_name

        # Best-effort default port per game for the install form. This is only a
        # pre-install HINT — after install the panel reads LinuxGSM's real port(s)
        # via `details` and opens every one, so an imperfect default self-corrects.
        KNOWN_PORTS = {
            # Source engine — default 27015
            "gmod": 27015, "cs": 27015, "css": 27015, "cs2": 27015, "csgo": 27015,
            "tf2": 27015, "hl2dm": 27015, "hldm": 27015, "hldms": 27015, "dods": 27015,
            "ins": 27015, "insurgency": 27015, "nmrih": 27015, "l4d": 27015, "l4d2": 27015,
            "zps": 27015, "fof": 27015, "gesource": 27015, "cscz": 27015, "tfc": 27015,
            "ns": 27015, "ricochet": 27015, "dmc": 27015, "sfc": 27015, "bb2": 27015,
            "unturned": 27015, "bt": 27015,
            # Call of Duty — 28960
            "cod": 28960, "coduo": 28960, "cod2": 28960, "cod4": 28960, "codwaw": 28960,
            # Minecraft family
            "mc": 25565, "pmc": 25565, "spigot": 25565, "paper": 25565, "bukkit": 25565,
            "mcbe": 19132, "mcb": 19132,
            # Survival / sandbox
            "rust": 28015, "sdtd": 26900, "7d2d": 26900, "valheim": 2456, "vh": 2456,
            "ark": 7777, "pz": 16261, "projectzomboid": 16261, "terraria": 7777,
            "tshock": 7777, "factorio": 34197, "avorion": 27000, "eco": 3000, "vs": 42420,
            # Mil-sim / shooters
            "arma3": 2302, "squad": 7787, "mordhau": 7777, "kf": 7707, "kf2": 7777,
            "q2": 27910, "q3": 27960, "ql": 27960, "et": 27960, "etl": 27960, "rtcw": 27960,
            "xonotic": 26000, "ut99": 7777, "ut2k4": 7777,
            # Voice / misc
            "mumble": 64738, "ts3": 9987, "samp": 7777, "mta": 22003, "openttd": 3979,
        }
        if not port or port == "27015":
            port = str(KNOWN_PORTS.get(game_type, 27015))
        # _port_or, not int(): a port has a RANGE, and `int(port)` carried none — so 0, -5 and
        # 99999 all reached the row below, the firewall verbs that take it, and the LinuxGSM
        # config written from it. A typo is corrected to the game's default; nothing out of range
        # is stored. (/api/free-port next door has always range-checked its input; this is the
        # endpoint that actually writes a server.)
        desired_port = _port_or(port, None)
        if desired_port is None:
            return _form_err("Port must be a number between %d and %d." % (MIN_PORT, MAX_PORT),
                             "manage_servers")

        # Allocate the install "slot" atomically: pick a free port, reject a duplicate name and
        # create the row under one lock. resolve_free_port yields on an SSH scan, so without the
        # lock two concurrent installs on the same remote could pick the same port or both clear the
        # duplicate-name check before either committed.
        with _install_alloc_lock:
            # Port-conflict handling: auto-pick the next free port if taken.
            # resolve_free_port SCANS the host's listening ports over SSH, so it raises when the
            # host is simply switched off — and that propagated as a 500. A host being unreachable
            # is a normal condition for this panel, not a fault in it (see _unreachable's docstring,
            # which lists the sibling endpoints this was already true of); it just needs the form
            # shape rather than the JSON one. Caught here, before any row exists.
            try:
                final_port, port_changed = resolve_free_port(remote, remote_id, desired_port,
                                                             game_type)
            except (ConnectionError, OSError):
                _log.warning("install: host %s unreachable while picking a port", remote.name)
                return _form_err("Can't reach %s right now, so the panel can't check which ports "
                                 "are free. Check the host is up and try again." % remote.name,
                                 "manage_servers")
            # None = the allocator found nothing free near the requested port. Refusing names the
            # real problem; storing its old best-guess handed the install a port already in use and
            # let it fail later as the GAME's error.
            if final_port is None:
                return _form_err("No free port near %d on this host — every port in the search "
                                 "range is taken. Pick a different port." % desired_port,
                                 "manage_servers")

            # Name conflict: if the user TYPED the name it's a real conflict; if they left it blank
            # (using the "{game}server" default), auto-suffix a number so leaving it blank always
            # works — the same courtesy the port gets above.
            def _name_taken(n):
                return GameServer.query.filter_by(short_name=n, remote_id=remote_id).first() is not None
            name_changed = False
            if _name_taken(short_name):
                if server_name:
                    return _form_err(f"A server named '{short_name}' already exists on this remote — "
                                     f"pick a different name.", "manage_servers")
                _n = 2
                while _name_taken(f"{lgsm_name}{_n}") and _n < 100:
                    _n += 1
                short_name = f"{lgsm_name}{_n}"
                name_changed = True

            # Create the DB row up-front in the "installing" state, then run the WHOLE
            # install in a background job with live step-by-step progress (polled by the
            # Game Servers page — mirrors the VPS bootstrap progress). The route returns
            # immediately so the browser never waits on the long download.
            gs = GameServer(
                remote_id=remote_id, name=server_name or short_name, short_name=short_name,
                game_type=game_type, game_display=game_type, port=final_port,
                installed=False, status="installing",
            )
            db.session.add(gs)
            db.session.commit()
        # Start the server's scheduled-backup clock now, so a brand-new install isn't seen as
        # immediately "due" and backed up mid-install (its first scheduled backup is one interval
        # out). Without this, last=0 makes game_backup_due() true the moment installed flips True.
        bk.record_game_backup(gs.id)

        # GMod is the one game that needs mounted content to render maps/props — offer the picked
        # games (validated against the known set). This adds a content step to the install job.
        content_games = ([g for g in request.form.getlist("content_games") if g in GMOD_CONTENT_GAMES]
                         if game_type == "gmod" else [])
        _prune_jobs(_install_jobs, _install_lock)
        with _install_lock:
            _install_jobs[gs.id] = {
                "status": "running", "step": 0, "total": (9 if content_games else 8),
                "step_name": "Queued",
                "message": "", "log": [], "started": time.time(), "updated": time.time(),
                "name": gs.name,
            }
        _run_install_job(gs.id, remote_id, short_name, game_type, lgsm_name, final_port, content_games)
        _notify_servers_changed(app)   # new "installing" row → appears live on other sessions

        log_action(current_user, "install_server", target=gs.name,
                   detail=f"Type: {game_type}, port: {final_port}")
        port_note = (f" (port {desired_port} was busy — using {final_port})" if port_changed else "")
        name_note = (f" (the default name was taken — using '{short_name}')" if name_changed else "")
        return _form_ok(f"Installing {short_name} on port {final_port}{port_note}{name_note}. "
                        f"Progress is shown live below.", "manage_servers")

    def _run_install_job(gs_id, remote_id, short_name, game_type, lgsm_name, final_port, content_games=None):
        """Full game-server install as a tracked background job with step progress.
        Steps (8, or 9 for GMod-with-content): user → LinuxGSM → deps → game files → config →
        port/firewall → autostart → [GMod content] → start. Progress → _install_jobs[gs_id]."""
        content_games = content_games or []
        _app = app

        def _p(step, name, status="running", message=""):
            with _install_lock:
                j = _install_jobs.get(gs_id)
                if j is None:
                    return
                j["step"], j["step_name"], j["status"], j["updated"] = step, name, status, time.time()
                if message:
                    j["message"] = message
                j["log"].append(f"[{step}/{j['total']}] {name}")

        def _fail(name, detail=""):
            with _install_lock:
                j = _install_jobs.get(gs_id)
                cur = j["step"] if j else 0
            _p(cur, name, status="failed", message=detail)

        def _finish(msg, warn=False):
            with _install_lock:
                j = _install_jobs.get(gs_id)
                if j is not None:
                    j["status"], j["step"] = "done", j["total"]
                    j["step_name"], j["message"], j["updated"] = "Complete", msg, time.time()
                    j["warn"] = bool(warn)   # done, but with a caveat (e.g. installed yet didn't start)

        def _run():
            try:
                from panel.db.models import db, RemoteServer, GameServer
                with _app.app_context():
                    remote = db.session.get(RemoteServer, remote_id)
                    gs = db.session.get(GameServer, gs_id)
                    if not remote or not gs:
                        return
                    # Hard stop before any destructive root command below: an empty short_name
                    # would turn `rm -rf /home/{short_name}` into `rm -rf /home/` (every home dir).
                    # It's always set upstream (server_name or lgsm_name), but never trust that here.
                    if not short_name:
                        _fail("Preparing user account", "internal error: missing instance name")
                        return

                    # 1. User account (clean any half-finished leftover first).
                    _p(1, "Preparing user account")
                    chk, _, _ = _sm.run_command(remote, f"test -x /home/{short_name}/linuxgsm.sh && echo EXISTS || echo NOTEXISTS", timeout=10)
                    if "NOTEXISTS" in chk:
                        # Was one root shell running `userdel -r X; rm -rf /home/X`. Two verbs
                        # now, and the home path is built by the helper from the validated name
                        # rather than interpolated into an `rm -rf`.
                        _sm.run_privileged(remote, "user-delete", [short_name], timeout=15,
                                       merge_stderr=False)
                        _sm.run_privileged(remote, "user-remove-home", [short_name], timeout=15,
                                       merge_stderr=False)
                    idout, _, _ = _sm.run_command(remote, f"id {short_name} 2>/dev/null && echo EXISTS || echo NOTEXISTS", timeout=10)
                    if "NOTEXISTS" in idout:
                        _sm.create_game_user(remote, short_name, timeout=15)
                        time.sleep(0.3)

                    # 2. Download & set up LinuxGSM (canonical script name).
                    _p(2, "Downloading LinuxGSM")
                    install_cmd = (f"sudo -u {short_name} bash -c 'cd /home/{short_name} && "
                                   f"wget -q -O linuxgsm.sh https://linuxgsm.sh && chmod +x linuxgsm.sh && "
                                   f"bash linuxgsm.sh {lgsm_name}' 2>&1")
                    out = err = ""; rc = -1
                    for attempt in range(10):
                        out, err, rc = _sm.run_command(remote, install_cmd, timeout=300, sudo=False)
                        if "unknown user" not in (out + err):
                            break
                        time.sleep(0.5 * (attempt + 1))
                    if "Unknown game server" in out:
                        _fail("Invalid game type", f"'{game_type}' is not a valid LinuxGSM shortname."); return
                    if rc != 0:
                        _fail("LinuxGSM setup failed", (out or err)[-300:]); return

                    # 3. System dependencies (as root — the game user has no sudo).
                    _p(3, "Installing dependencies")
                    try:
                        install_game_dependencies(remote, game_type)
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)

                    # 4. Download the game server files (the long step). A truncated / corrupt archive
                    #    can leave LinuxGSM "done" — even with exit code 0 — but with NO game files
                    #    (exactly how a bad cod2 download failed silently). So DON'T trust the exit
                    #    code: after each attempt verify the files actually landed (_looks_installed),
                    #    and on failure wipe LinuxGSM's cached download and retry from scratch.
                    auto = f"sudo -u {short_name} bash -c 'cd /home/{short_name} && ./{lgsm_name} auto-install' 2>&1"
                    installed_ok = False
                    last_out = ""
                    for attempt in range(3):
                        _p(4, "Downloading game server files (this can take a while)"
                              + ("" if attempt == 0 else " — retry %d" % attempt))
                        out, err, rc = _sm.run_command(remote, auto, timeout=1800, sudo=False)
                        last_out = out or err or last_out
                        missing = parse_missing_deps((out or "") + "\n" + (err or ""))
                        if missing:
                            try:
                                install_game_dependencies(remote, game_type, extra=" ".join(missing))
                                out, err, rc = _sm.run_command(remote, auto, timeout=1800, sudo=False)
                                last_out = out or err or last_out
                            except Exception:
                                _log.debug("_run: ignored non-fatal error", exc_info=True)
                        # The real test — did the game files actually install? rc alone lies on a
                        # corrupt/truncated download.
                        if _looks_installed(app, remote, short_name, lgsm_name) is True:
                            installed_ok = True
                            break
                        # Not really installed: wipe LinuxGSM's cached (likely corrupt) archive so the
                        # next attempt re-downloads fresh instead of reusing the bad file.
                        try:
                            _sm.run_command(remote, f"sudo -u {short_name} bash -c "
                                        f"'rm -rf /home/{short_name}/lgsm/tmp/* 2>/dev/null; echo cleared'",
                                        timeout=30, sudo=False)
                        except Exception:
                            _log.debug("_run: ignored non-fatal error", exc_info=True)
                    if not installed_ok:
                        gs.installed = False; gs.status = "failed"; db.session.commit()
                        _fail("Game files didn't install after 3 tries — the download may be corrupt or "
                              "the mirror unreachable. Try again shortly.", last_out[-300:]); return
                    # Files have landed — the server IS installed, but it still needs configuring
                    # and starting (steps 5-8). Use a distinct "configuring" status (NOT "installing")
                    # so the state model is honest: the status poller skips it just like "installing"
                    # (it isn't fully up yet), and if the panel restarts before step 8 the reconciler
                    # heals it instead of it sitting stuck.
                    gs.installed = True; gs.status = "configuring"; db.session.commit()

                    # 5. Configure: cache command list + maintenance cron + Minecraft EULA.
                    _p(5, "Configuring server")

                    # Make LinuxGSM actually use the free port we reserved at request time
                    # (resolve_free_port already skipped ports taken by another server or listening
                    # on the host). auto-install used the game's DEFAULT port, which can collide with
                    # another server — so write our port into the instance config. Step 6 then reads
                    # it back via `details` and opens it, instead of overwriting with the default.
                    try:
                        lgsm_write_config(remote, short_name, lgsm_name, {"port": final_port})
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)
                    # Source games also bind a SourceTV + client port; if a sibling Source server
                    # already holds the defaults (27020/27005), -strictportbind makes this one QUIT
                    # on start. Move ours to free ports before the first start so it can come up.
                    try:
                        aux = _resolve_source_aux_ports(remote, remote_id, short_name, lgsm_name, final_port)
                        if aux:
                            lgsm_write_config(remote, short_name, lgsm_name, aux)
                            _log.info("install %s: reassigned Source aux ports %s", short_name, aux)
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)
                    try:
                        cmds = _sm.list_server_commands(remote, short_name, gs.lgsm_name)
                        if cmds:
                            gs.set_commands(cmds); db.session.commit()
                            try:
                                supported = {c["cmd"] for c in cmds}
                                install_game_cron(remote, short_name, gs.lgsm_name, supported)
                                # install_game_cron schedules `monitor` when the game has it, and
                                # that line IS the Autostart switch — record it, or the Details
                                # page shows Off while monitor is scheduled and running.
                                if "monitor" in supported and not gs.autostart:
                                    gs.autostart = True
                                    db.session.commit()
                            except Exception:
                                _log.debug("_run: ignored non-fatal error", exc_info=True)
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)
                    if gs.game_type in ("mc", "mcbe", "pmc", "spigot", "paper"):
                        try:
                            _sm.run_command(remote, f"sudo -u {short_name} bash -c \"echo 'eula=true' > /home/{short_name}/serverfiles/eula.txt 2>/dev/null; true\"", timeout=15, sudo=False)
                        except Exception:
                            _log.debug("_run: ignored non-fatal error", exc_info=True)
                    # Source/GoldSrc: make the server reload its ban list on every start, so a banid
                    # ban actually survives a restart (without this the engine drops it on reboot and
                    # the player rejoins). Best-effort.
                    if sm_game_engine(gs.game_type) == "valve":
                        try:
                            ensure_persistent_bans(remote, short_name, lgsm_name)
                        except Exception:
                            _log.debug("_run: ignored non-fatal error", exc_info=True)

                    # 6. Sync to LinuxGSM's real port(s) and open ALL of them (many
                    #    games need game+query+rcon+etc., not just the main port).
                    _p(6, "Detecting ports & opening firewall")
                    try:
                        info = detect_game_ports(remote, short_name, gs.lgsm_name)
                        real_port = info.get("game_port")
                        if real_port and real_port != gs.port:
                            old_port = gs.port; gs.port = real_port; db.session.commit()
                            try:
                                remote_ufw_close_game_port(remote, old_port)
                            except Exception:
                                _log.debug("_run: ignored non-fatal error", exc_info=True)
                        to_open = info.get("open_ports") or ([gs.port] if gs.port else [])
                        remote_ufw_allow_game_ports(remote, to_open, short_name)
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)

                    # 7. Enable autostart by default (the LinuxGSM monitor cron; install_game_cron
                    #    above already adds it when supported — this ensures it either way).
                    _p(7, "Enabling autostart (monitor)")
                    try:
                        set_autostart(remote, short_name, True, gs.lgsm_name)
                    except Exception:
                        _log.debug("_run: ignored non-fatal error", exc_info=True)

                    # 8 (GMod only, if requested). Mountable content: reuse an existing content user's
                    # games or download them (SteamCMD), grant read access, and write GMod's mount.cfg —
                    # BEFORE start, so the server comes up with content already mounted and the content
                    # group in effect. Best-effort: a content failure never fails the install.
                    start_step = 8
                    if content_games and game_type == "gmod":
                        start_step = 9
                        labels = ", ".join(GMOD_CONTENT_GAMES[g][0]
                                           for g in content_games if g in GMOD_CONTENT_GAMES)
                        _p(8, "Installing GMod content (%s)" % (labels or "content"))
                        try:
                            cu = ensure_content_user(remote)
                            if cu:
                                install_gmod_content(remote, cu["user"], content_games,
                                                     on_progress=lambda m: _p(8, m))
                                ok_m, msg_m = gmod_mount_setup(remote, short_name, cu["user"], content_games)
                                if not ok_m:
                                    _log.warning("gmod content mount for %s: %s", short_name, msg_m)
                            else:
                                _log.warning("gmod content: no content user could be prepared on %s", remote.name)
                        except Exception:
                            _log.warning("gmod content setup failed for %s", short_name, exc_info=True)

                    # Start the server — then VERIFY it actually came up. LinuxGSM's `start` exit
                    # code alone can lie: a port taken under -strictportbind, or a crash-on-boot, can
                    # still exit 0 or just flap. So capture the start log and confirm the game port is
                    # really listening a few seconds later; if it isn't, mark it offline and surface
                    # the reason from the log instead of a bare "offline".
                    _p(start_step, "Starting server")
                    start_out = ""
                    try:
                        start_out, _, s_rc = _sm.run_as_game_user(remote, short_name, "start", timeout=120, selfname=gs.lgsm_name)
                    except Exception:
                        s_rc = 1
                        _log.debug("_run: start command failed", exc_info=True)
                    really_up = False
                    try:
                        for _ in range(5):                    # poll ~15s: give a heavy first boot time to bind
                            time.sleep(3)
                            _sm._invalidate_port_scan(remote.id)  # force a fresh scan each try
                            if gs.port and gs.port in (_remote_listening_ports(remote)
                                                       or set()):
                                really_up = True
                                break
                    except Exception:
                        really_up = (s_rc == 0)               # host unreachable — fall back to the exit code
                    gs.status = "online" if really_up else "offline"
                    db.session.commit()

                    # Now that it's actually run once, re-read the ports and open any that only
                    # become visible at runtime. A no-op for the static-config majority (step 6 already
                    # opened them before start); future-proofs a game whose effective ports settle on
                    # first start. Best-effort — ufw allow is idempotent.
                    try:
                        info2 = detect_game_ports(remote, short_name, gs.lgsm_name)
                        extra = info2.get("open_ports") or []
                        if extra:
                            remote_ufw_allow_game_ports(remote, extra, short_name)
                    except Exception:
                        _log.debug("_run: post-start port re-detect failed", exc_info=True)

                    if really_up:
                        _finish(f"{short_name} installed and started")
                        log_action(None, "install_complete", target=gs.name, success=True)
                    else:
                        reason = _extract_start_error(start_out)
                        note = f"{short_name} installed, but it didn't start"
                        note += (" — " + reason) if reason else " — check the console for the reason."
                        _finish(note, warn=True)
                        log_action(None, "install_complete", target=gs.name, success=False,
                                   detail=(("start failed: " + reason) if reason else "start failed")[:300])
            except Exception as e:
                with _install_lock:
                    j = _install_jobs.get(gs_id)
                    if j is not None:
                        j["status"], j["message"], j["updated"] = "failed", str(e), time.time()
                app.logger.exception("install job failed")

        threading.Thread(target=_run, daemon=True).start()

    @app.route("/servers/<int:server_id>/delete", methods=["POST"])
    @login_required
    @permission_required(UNINSTALL_SERVER)
    @server_access_required   # get_game() does NOT check access; the permission alone is not enough
    def uninstall_server(server_id):
        gs = get_game(server_id)
        name = gs.name   # capture before the row is deleted (used in the success/error message)
        # Refuse to uninstall while an install is in progress — deleting the user/files out from
        # under the running install job corrupts it (and can orphan processes). The UI disables the
        # button too, but guard the endpoint as well (belt and suspenders).
        with _install_lock:
            _installing = (server_id in _install_jobs
                           and _install_jobs[server_id].get("status") == "running")
        if _installing or (gs.status == "installing" and not gs.installed):
            _m = "'%s' is still installing — wait for it to finish before uninstalling." % name
            if _wants_json():
                return jsonify({"success": False, "message": _m}), 409
            flash(_m, "warning")
            return redirect(url_for("manage_servers"))
        remote = gs.remote
        short_name = gs.short_name
        game_port = gs.port
        selfname = gs.lgsm_name

        try:
            # Stop the game server and kill any lingering processes BEFORE deleting the user.
            # Otherwise userdel removes the user + home while the game process is still running —
            # leaving it orphaned under a now-deleted uid: not manageable from the panel, and still
            # eating CPU/RAM and holding its port. Graceful LinuxGSM stop first, then a hard kill of
            # anything left, then delete.
            try:
                _sm.run_as_game_user(remote, short_name, "stop", timeout=60, selfname=selfname)
            except Exception:
                _log.debug("uninstall: graceful stop failed; force-killing next", exc_info=True)
            try:
                _sm.run_privileged(remote, "user-kill-processes", [short_name], timeout=20,
                               merge_stderr=False)
                time.sleep(1)   # the `; sleep 1` that used to ride along inside the root shell
            except Exception:
                _log.debug("uninstall: pkill failed; proceeding to userdel", exc_info=True)

            # Close ALL of this server's firewall rules (multi-port games tag every
            # rule with the server name), then also the legacy single-port cleanup.
            fw_note = ""
            try:
                count, _ = remote_ufw_close_by_name(remote, short_name)
                remote_ufw_close_game_port(remote, game_port)
                if count > 0:
                    fw_note = f" {count} firewall rule(s) removed."
            except Exception:
                _log.debug("uninstall_server: ignored non-fatal error", exc_info=True)

            # Remove LinuxGSM user and home.
            #
            # THE EXIT CODE DECIDES WHETHER THE ROW GOES. run_privileged RETURNS rc rather than
            # raising, and this used to feed it to log_action and nothing else — so a userdel that
            # FAILED still deleted the panel's row and still answered "Server 'x' uninstalled."
            # The account, its home and every game file stayed on the host, now with no row to
            # manage them from, the firewall rules already removed, and the next install of that
            # game colliding with the surviving user. The audit log was the only trace.
            #
            # userdel's codes, which is why this is not a bare `rc == 0`:
            #   0   removed
            #   6   no such user — already gone, so there is nothing to orphan and the row SHOULD go
            #   12  the account was removed but its home could not be — partial, worth saying out loud
            #   *   the account is still there; keeping the row is what lets the operator retry
            out, err, rc = _sm.run_privileged(remote, "user-delete-force", [short_name], timeout=30)
            _gone = rc in (0, 6, 12)
            log_action(current_user, "uninstall_server", target=gs.name, success=_gone)
            if not _gone:
                _em = ("Could not remove the '%s' account on %s, so '%s' has been left in place — "
                       "nothing was deleted from the panel. %s"
                       % (short_name, remote.display_name, name,
                          (err or out or "userdel exited %d" % rc).strip()[:200]))
                if _wants_json():
                    return jsonify({"success": False, "message": _em}), 500
                flash(_em, "danger")
                return redirect(url_for("manage_servers"))
            if rc == 12:
                fw_note += (" The account was removed but its home directory could not be — "
                            "check /home/%s on the host." % short_name)

            # Remove from DB
            db.session.delete(gs)
            db.session.commit()
            # Clean up this server's per-server backup schedule + status so nothing is orphaned
            # (and can't be inherited if SQLite reuses the row id for a future server).
            try:
                bk.remove_game_schedule(server_id)
                _game_backup_status.pop(server_id, None)
                # ...and this server's install job. Same reason as the schedule beside it: the row
                # id is handed to the next server created, and /install-status would answer for it
                # with THIS one's outcome. The monitor sweep also prunes it, one pass later.
                with _install_lock:
                    _install_jobs.pop(server_id, None)
            except Exception:
                _log.debug("uninstall: schedule cleanup failed", exc_info=True)
            _notify_servers_changed(app)   # row disappears live on other sessions
            _m = f"Server '{name}' uninstalled.{fw_note}"
            if _wants_json():
                return jsonify({"success": True, "message": _m})
            flash(_m, "success")
            return redirect(url_for("manage_servers"))

        except Exception:
            _em = _log_and_generic("uninstall failed")
            log_action(current_user, "uninstall_server", target=name, success=False)
            if _wants_json():
                return jsonify({"success": False, "message": _em}), 500
            flash(_em, "danger")
            return redirect(url_for("manage_servers"))

    @app.route("/servers/<int:server_id>/edit", methods=["POST"])
    @login_required
    @permission_required(MANAGE_SERVERS)
    @server_access_required   # same: MANAGE_SERVERS is not a grant for EVERY server
    def edit_server(server_id):
        """Rename a game server's DISPLAY labels. Nothing here touches the host.

        Two things were wrong with the previous version, and both only ever showed up through a
        direct API call — no template or script references this route.

        `name` and `game_display` were written straight from the form. Every other label the panel
        stores goes through SAFE_LABEL_RE first (add_remote / edit_remote do), and SQLite does not
        enforce VARCHAR length, so this was the one write that accepted any bytes at any size.

        `port` was worse: it moved the panel's RECORD of the port and nothing else. The firewall
        rule stays on the old port, LinuxGSM keeps listening there, and the monitor — which decides
        a server is up by `gs.port in <listening ports>` — then reports it permanently offline. A
        port really does change in three places at once, which is what the install flow and the
        Firewall page's "Open all ports" (sync-ports) do together. So this refuses rather than
        silently desyncing: a refusal names the right mechanism, a silent write hides it.
        """
        gs = get_game(server_id)
        new_port = (request.form.get("port") or "").strip()
        # Compared as TEXT. Parsing it first meant an unparseable value read as "unchanged" and
        # was silently ignored rather than refused — and it put a port through _int_or, the parser
        # that carries no range. Any submitted port that is not exactly the stored one is refused.
        if new_port and new_port != str(gs.port):
            return _form_err(
                "The port can't be changed here — it would only move the panel's record, leaving "
                "the game server and the firewall on the old port. Change it in the server's "
                "LinuxGSM config, then use 'Open all ports' on the Firewall page.",
                "manage_servers")
        name = (request.form.get("name") or gs.name or "").strip() or gs.name
        game_display = (request.form.get("game_display") or gs.game_display or "").strip()
        for _label, _value in (("Name", name), ("Game", game_display)):
            if _value and not SAFE_LABEL_RE.match(_value):
                return _form_err("%s can't be empty, longer than 120 characters, or contain "
                                 "< > \" ' ` or backslashes." % _label, "manage_servers")
        gs.name = name
        gs.game_display = game_display
        db.session.commit()
        log_action(current_user, "edit_server", target=gs.name)
        return _form_ok(f"Server '{gs.name}' updated.", "manage_servers")
