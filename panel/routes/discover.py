"""Finding LinuxGSM servers already installed on a host and importing them.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
import collections

from flask import (jsonify)
from flask_login import (current_user, login_required)
from panel.db.models import (GameServer, db, row_birth)
from panel.ops.ssh_manager import (content_box_users, discover_linuxgsm_servers,
                                  enrol_game_user, run_command)
from panel.security.auth import (MANAGE_SERVERS, can_access_remote, get_remote, log_action,
    permission_required)
from panel.core.http import (_json_body, _json_str, _log_and_generic)
from panel.core.validation import (INSTANCE_NAME_RE)
from app import (lgsm_name_to_game_type, load_game_list)
from panel.routes._shared import (_bg_cache_commands, privileged_accounts)
from panel.ops import ssh_manager as _sm
from panel.services import game_ports as _gp


# "Could not read" is not "nothing is there", and discover_linuxgsm_servers cannot tell its caller
# which one it meant: it returns [] for both (panel/ops/ssh_manager/_core.py — "Best-effort —
# returns [] on any failure"). Until it can, confirm separately that the host answered at all, and
# confirm it with a POSITIVE token: `rc == 0` on its own is satisfied by a transport that never ran
# the command, and an empty stdout is what every failed read looks like.
#
# Deliberately NOT sudo, although the scan escalates. A sudo probe on the panel's OWN host fails
# under the narrow helper grant — see run_command's note, `run_command(local, "echo ok")` answered
# "sudo: a password is required" — so escalating here would turn a working local scan into
# "unreadable", which is the same class of false statement pointing the other way.
_PROBE_MARKER = "LGSM_SCAN_OK"


def _host_answered(remote):
    """True when the host answered a trivial command.

    Only then does an empty scan really mean 'nothing here'. False when the panel could not reach it
    — paramiko raises, while the tailscale and local transports return ("", "…timed out", -1)
    without raising.
    """
    try:
        out, _err, rc = run_command(remote, "echo %s" % _PROBE_MARKER, timeout=15, sudo=False)
    except Exception:
        return False
    return rc == 0 and _PROBE_MARKER in (out or "")


def _enrol_imported(remote, users):
    """Put each imported account inside the panel's grant; return the ones refused.

    This is the step create_game_user takes for an account the panel makes. The ones the helper
    would not take come back with its reason.

    Without it, on a narrow-grant install the helper refuses every per-account verb for an imported
    server (start, stop, update, downloads, the command-list read) until the next root install.sh
    run, and nothing says why. The helper still refuses an account that can already reach root;
    that refusal is REPORTED to the importer rather than left for each later action to trip over.
    Runs BEFORE the background command-list read, which needs the membership it grants.
    """
    out = []
    for user in users:
        reason = enrol_game_user(remote, user)
        if reason:
            out.append({"user": user, "reason": reason})
    return out


def register(app):
    @app.route("/api/remote/<int:remote_id>/discover")
    @login_required
    @permission_required(MANAGE_SERVERS)
    def api_remote_discover(remote_id):
        """Find the LinuxGSM servers installed on a host that are NOT yet in the panel.

        It scans under any user account and returns each one mapped to a known game. Read-only —
        imports nothing.
        """
        if not (current_user.is_superadmin or can_access_remote(current_user, remote_id)):
            return jsonify({"error": "You don't have access to that host."}), 403
        remote = get_remote(remote_id)
        try:
            found = discover_linuxgsm_servers(remote)
        except Exception:
            return jsonify({"error": _log_and_generic("server discovery failed")}), 200
        if not found and not _host_answered(remote):
            # An empty scan used to be reported as a fact: the card printed a green tick and "No
            # new LinuxGSM servers found", and an admin stopped looking. It is not a fact.
            # discover_linuxgsm_servers is best-effort and returns [] for BOTH "the scan ran and
            # there is nothing new" and "the scan never ran" — the except branch above is dead
            # because it swallows everything itself, and the tailscale and local transports do not
            # raise at all: a host that is off gives ("", "SSH command timed out", -1), rc != 0,
            # []. So when the list comes back empty, ask the host one question with a POSITIVE
            # answer before saying anything about it. Only on an empty scan, so a host that does
            # have servers pays nothing.
            return jsonify({"error": "Couldn't read %s — the scan didn't run, so whether there are "
                                     "LinuxGSM servers on it is unknown. Check the host is up and "
                                     "reachable, then scan again." % remote.name}), 200
        existing = {gs.short_name for gs in GameServer.query.filter_by(remote_id=remote_id).all()}
        games = {g["shortname"]: g["name"] for g in load_game_list()}
        out, content = _discovered_listing(found, existing, games)
        return jsonify({"servers": out,
                        "content": [{"user": u, "games": sorted(g)}
                                    for u, g in sorted(content.items())]})

    @app.route("/api/remote/<int:remote_id>/import", methods=["POST"])
    @login_required
    @permission_required(MANAGE_SERVERS)
    def api_remote_import(remote_id):
        """Create panel records for selected discovered servers.

        Each user/game_type is validated with the SAME strict rules as a fresh install (so an
        imported short_name can never carry shell metacharacters), and duplicates/unknowns are
        skipped.
        """
        if not (current_user.is_superadmin or can_access_remote(current_user, remote_id)):
            return jsonify({"error": "You don't have access to that host."}), 403
        remote = get_remote(remote_id)
        items = _json_body().get("servers") or []
        if not isinstance(items, list) or not items:
            return jsonify({"success": False, "message": "Nothing selected."}), 400
        # Re-scan, and import ONLY what the scan just found. The list arrives from the client and
        # the account name is checked against INSTANCE_NAME_RE — which "root", "ubuntu" and
        # "postgres" all satisfy, since it is a Linux-username grammar, not an allowlist. Nothing
        # here contacted the host, so a POST naming any account created a GameServer row for it;
        # a whole-host grant then makes every GameServer on that host accessible (auth.py's
        # can_access_server), and every game op builds `sudo -u <short_name> bash -c ...`. That is
        # a non-superadmin turning a host grant into root on that host. The scan is the authority
        # on what exists: an account it did not report cannot be imported.
        try:
            _found = discover_linuxgsm_servers(remote)
        except Exception:
            return jsonify({"success": False,
                            "message": _log_and_generic("server discovery failed")}), 200
        discovered = _scanned_game_types(_found)
        # The scan says the account holds a LinuxGSM install; it does not say the account is one
        # the panel may BECOME. Ask the host, and take the ones it names out of what may be
        # imported — see privileged_accounts for the host's login turned into root that this is.
        refused = _privileged_selection(remote, items, discovered)
        if refused is None:
            return jsonify({"success": False, "message": (
                "Couldn't check the selected accounts on %s — the host did not answer, and the "
                "panel only imports an account it has confirmed is not an administrator or root "
                "account. Nothing was imported; try again." % remote.name)}), 200
        picked, skipped = _import_selection(remote_id, items, discovered)
        added, not_enrolled, unread = [], [], []
        if picked:
            added, not_enrolled, unread, raced = _import_picked(app, remote, remote_id, picked)
            skipped += raced
        return jsonify(_discover_import_outcome(remote, added, skipped, not_enrolled, refused,
                                                unread))


def _discover_import_outcome(remote, added, skipped, not_enrolled, refused, unread=()):
    """The import route's JSON answer, once the selected rows are in (or are not).

    `unread` are the servers left out because their port could not be read, each with the reason.
    `shared_ports` (see _shared_ports) names each port an imported server shares with another.
    """
    # On the panel's own host an account the helper would not enrol was imported ANYWAY: the
    # row was committed first, and only then was the helper asked. The helper refuses an
    # account that can already reach root, so its refusal is the same verdict as the probe's
    # and is now acted on the same way — _finish_import did not keep the row.
    if _sm.is_local_server(remote):
        refused += not_enrolled
        not_enrolled = []
    unread = list(unread)
    skipped += [r["user"] for r in refused + unread if r["user"] not in skipped]
    out = {"success": bool(added), "added": added, "skipped": skipped,
           "not_enrolled": not_enrolled, "refused": refused, "unread": unread,
           "shared_ports": _shared_ports(remote.id, added)}
    if (refused or unread) and not added:
        out["message"] = "Not imported: " + "; ".join(
            "%s (%s)" % (r["user"], r["reason"]) for r in refused + unread) + "."
    return out


def _shared_ports(remote_id, added):
    """[{"port", "servers", "note"}]: each port an imported server shares with another of the host's.

    Imported anyway: the port is the one its config sets, and Minecraft and PaperMC both default
    to 25565. But a port-only monitor then reads a STOPPED one online while the other runs (found
    on the test box: pmcsrv beside mcserver), so the reply says so. Read from the host's rows after
    the commit: another server imported in the same batch counts, as does one already in the panel
    (its display name), and a server on another host does not. `servers` are in the order the rows
    were made; `note` is game_ports.shared_port_note.
    """
    if not added:
        return []
    new, by_port = set(added), collections.defaultdict(list)
    for port, name, short in (GameServer.query.filter_by(remote_id=remote_id)
                              .order_by(GameServer.id)
                              .with_entities(GameServer.port, GameServer.name,
                                             GameServer.short_name)):
        by_port[port].append((name, short in new))
    return [{"port": port, "servers": [n for n, _new in held],
             "note": _gp.shared_port_note([n for n, _new in held], port)}
            for port, held in sorted(by_port.items())
            if len(held) > 1 and any(is_new for _n, is_new in held)]


def _privileged_selection(remote, items, discovered):
    """Refuse the selected accounts that are root-capable on the host; drop them from `discovered`.

    -> [{"user", "reason"}] for the ones refused, or None when the host could not be asked. Only
    accounts the scan reported are probed — a name it did not report is skipped anyway — and only
    names that pass INSTANCE_NAME_RE, the rule _add_imported_rows imports by. That check used to
    run AFTER this one, so the probe (shell text, run as root on a sudo-enabled remote) was handed
    the /home listing's names exactly as the scan read them; a name the import would refuse is
    skipped there, and never needs asking about.
    """
    picked = [(str(it.get("user") or "")).strip() for it in items[:100] if isinstance(it, dict)]
    picked = [u for u in dict.fromkeys(picked) if u in discovered and INSTANCE_NAME_RE.match(u)]
    verdict = privileged_accounts(remote, picked)
    if verdict is None:
        return None
    refused = []
    for user, why in verdict.items():
        discovered.pop(user, None)
        refused.append({"user": user,
                        "reason": "it is not a game account the panel may run as: %s" % why})
    return refused


def _discovered_listing(found, existing, games):
    """(importable servers, {content-box account: [game names]}) from a scan, minus `existing`."""
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
            content.setdefault(user, []).append(_content_game_label(f, gt, games))
            continue
        if not gt or gt not in games:
            continue   # a game the panel doesn't support — don't offer a broken import
        out.append(_importable_entry(f, user, gt, games))
    return out, content


def _content_game_label(f, gt, games):
    """How the discover card names one content-box game."""
    return games.get(gt) or f.get("lgsm_name") or gt or "?"


def _importable_entry(f, user, gt, games):
    """One importable server as the discover card lists it.

    `port` 0 is "not in its LinuxGSM config": the import reads it from LinuxGSM's `details`.
    """
    return {"user": user, "game_type": gt, "game_name": games.get(gt, gt),
            "port": f.get("port") or 0,
            "backups": f.get("backups", 0), "mods": f.get("mods", 0),
            "cron": f.get("cron", 0), "autostart": bool(f.get("autostart"))}


def _scanned_game_types(found):
    """{account: {game type: the port the scan read, or None}} a scan found.

    Content boxes are left out, as discover leaves them. The port is the import's to store: the
    one LinuxGSM's own config gives the game (discover_linuxgsm_servers), or None when it gives
    none and the import has to ask LinuxGSM's `details`.
    """
    _content = content_box_users(found)
    discovered = {}
    for _f in found:
        _u = _f.get("user") or ""
        if _u in _content:
            continue      # a GMod content box is not a server — api_remote_discover skips it
        _gt = lgsm_name_to_game_type(_f.get("lgsm_name") or "")
        if _gt:
            discovered.setdefault(_u, {})[_gt] = _f.get("port") or None
    return discovered


def _import_selection(remote_id, items, discovered):
    """The selected servers the scan confirmed. -> ([(account, game type, scanned port)], skipped).

    The scanned port is None where the scan read none. Nothing the client sent about a port is
    kept: the import stores a port read on the host or no row at all (see _import_ports).
    """
    existing = {gs.short_name for gs in GameServer.query.filter_by(remote_id=remote_id).all()}
    valid_games = {g["shortname"] for g in load_game_list()}
    # A host's servers are keyed on the Linux user (short_name), so two games under ONE account
    # cannot both become servers. The loop below would take the first and drop the rest as
    # duplicates — picking a game essentially at random and reporting partial success as
    # success. That is what a GMod content box looked like when it reached this endpoint.
    # Refuse the whole account instead: an arbitrary winner is not a better answer than none.
    items, per_user = _selected_items(items)
    rules = (valid_games, discovered, existing, per_user)
    picked, skipped = [], []
    for it in items:
        user = (str(it.get("user") or "")).strip()
        gt = _json_str(it, "game_type").lower()
        if _import_refused(user, gt, rules):
            skipped.append(user or "?")
            continue
        existing.add(user)
        picked.append((user, gt, discovered[user][gt]))
    return picked, skipped


def _selected_items(items):
    """The selection as dicts (at most 100), and how many times each account is named in it."""
    items = [it for it in items[:100] if isinstance(it, dict)]
    per_user = collections.Counter((str(it.get("user") or "")).strip() for it in items)
    return items, per_user


def _import_refused(user, gt, rules):
    """Whether one selected server must be skipped; `rules` is _import_selection's tuple."""
    valid_games, discovered, existing, per_user = rules
    return bool(not INSTANCE_NAME_RE.match(user) or gt not in valid_games
                or gt not in discovered.get(user, ())
                or user in existing or per_user.get(user, 0) > 1)


def _import_picked(app, remote, remote_id, picked):
    """Enrol the picked accounts, read the ports the scan could not, then add and commit the rows.

    -> (accounts imported, accounts the helper would not enrol (with its reason), servers left out
    because their port could not be read (with the reason), accounts another import added first).

    Enrolment runs FIRST, before any row exists. It ran after the rows were added, and before that
    after the commit, so on the panel host an account the helper refused — one that can already
    reach root — was a committed GameServer row by the time the refusal came back. And it has to
    precede the port read now: on a narrow-grant install the helper runs `details` only as an
    enrolled account. An account enrolled here whose port then cannot be read is left out of the
    import but stays enrolled; importing it again needs that anyway.
    """
    not_enrolled = _enrol_imported(remote, [user for user, _gt, _port in picked])
    if not_enrolled and _sm.is_local_server(remote):
        drop = {n["user"] for n in not_enrolled}
        picked = [p for p in picked if p[0] not in drop]
    ready, unread = _import_ports(remote, picked)
    added, raced = _add_imported_rows(remote_id, ready)
    if not added:
        db.session.rollback()
        return added, not_enrolled, unread, raced
    db.session.commit()
    ports = {user: port for user, _gt, port in ready}
    log_action(current_user, "import_servers", target=remote.name,
               detail="added=%s" % ",".join("%s:%s" % (u, ports[u]) for u in added), remote=remote)
    _discover_cache_imported(app, remote_id, added, not_enrolled)
    return added, not_enrolled, unread, raced


def _import_ports(remote, picked):
    """The port each picked server is stored on, READ on the host. -> (ready, unread).

    ready: [(account, game type, port)]. unread: [{"user", "reason"}] — the servers no row is made
    for, because no port could be read for them.

    The scan's port where it read one: LinuxGSM's own config, and only when the game's start line
    uses it. Otherwise LinuxGSM's `details`, which reads the game's own config for the 46 games that
    keep their port there (Minecraft's server.properties, ...). Never the port the browser sent and
    never a default: the import stored the client's port, and 27015 when it sent none — so a
    Minecraft server imported on the test box was stored on Garry's Mod's port, read as up
    whenever Garry's Mod was, and its crash never paged. A port that cannot be read is no port; a
    row on a guessed one is worse than no row, because every consumer treats it as a fact.
    """
    if not picked:
        return [], []
    readings = _gp.read_reported_ports(
        remote, [(user, user, "%sserver" % gt) for user, gt, port in picked if not port])
    protected = _sm.protected_host_ports(remote)
    ready, unread = [], []
    for user, gt, port in picked:
        answered = True
        if not port:
            port, answered = readings.get(user, _gp.NO_READING)[:2]
        why = _import_port_problem(port, answered, protected)
        if why:
            unread.append({"user": user, "reason": why})
        else:
            ready.append((user, gt, port))
    return ready, unread


def _import_port_problem(port, answered, protected):
    """Why a server cannot be imported on `port` (None: no port was read), or None when it can."""
    if port is None and not answered:
        return ("its game port is not set in its LinuxGSM config, and LinuxGSM's details did not "
                "answer, so its port could not be read — try the import again")
    if port is None:
        # What was SEEN, not a guess at why: most games get a default config at install that
        # already sets the port (Minecraft's server.properties says 25565), so "never started" was
        # wrong for them, and starting such a server changes nothing.
        return ("its game port is not set in its LinuxGSM config, and LinuxGSM's details reports "
                "none either: the game's own config (the file details names under \"Change ports "
                "by editing\") is missing or does not set the port. Set it there, then import it "
                "again. A game that writes that file itself the first time it starts needs one "
                "start with LinuxGSM first")
    why = _gp.port_refusal(port, protected)
    return ("its port could not be used: %s — correct it in the game's config, then import it"
            % why) if why else None


def _add_imported_rows(remote_id, ready):
    """Add a GameServer row per server in `ready`. -> (added, accounts another import added first).

    The panel's rows are read again here: the port reads take seconds, and an import running
    alongside this one could have added the same account meanwhile.
    """
    existing = {gs.short_name for gs in GameServer.query.filter_by(remote_id=remote_id).all()}
    game_names = {g["shortname"]: g["name"] for g in load_game_list()}
    added, raced = [], []
    for user, gt, port in ready:
        if user in existing:
            raced.append(user)
            continue
        # Import never starts or stops a discovered server, and leaves its game files, backups
        # and mods as they are (they are read live once imported). It does turn Autostart on,
        # as an install does: the background step below writes LinuxGSM's `monitor` cron once
        # the command list shows the game has it, and sets the flag then. monitor keeps a
        # server in its intended state, so a running one comes back after a reboot or a crash
        # and a stopped one stays down. It starts False here because nothing is written yet.
        db.session.add(GameServer(
            remote_id=remote_id, name=user, short_name=user, game_type=gt,
            game_display=game_names.get(gt, ""),
            port=port, installed=True, status="offline",
            autostart=False))
        existing.add(user)
        added.append(user)
    return added, raced


def _discover_cache_imported(app, remote_id, added, not_enrolled):
    """Populate the imported servers' command lists.

    So "Supported Commands" is ready without a manual refresh (install caches these; import
    didn't).
    """
    new_rows = GameServer.query.filter(
        GameServer.remote_id == remote_id, GameServer.short_name.in_(added)).all()
    refused = {n["user"] for n in not_enrolled}
    # Autostart only where the panel can write the account's crontab: an account the
    # helper refused to enrol is one the panel cannot become on a narrow-grant host.
    _bg_cache_commands(app, [gs.id for gs in new_rows],
                       autostart_ids=[gs.id for gs in new_rows
                                      if gs.short_name not in refused],
                       births={gs.id: row_birth(gs) for gs in new_rows})
