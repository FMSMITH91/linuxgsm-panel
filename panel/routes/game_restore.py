"""Restore a game server from one of its LinuxGSM backups: the route and its background run.

The route checks the permission (RESTORE_BACKUP, per server), the typed server name, that the
archive is one of THIS server's (from the panel's own listing) and that nothing else runs on the
server, then answers at once. The run, registered as "restore" for its whole length (so a host
reboot, a backup, a wipe, a queued stop/restart and the server page's actions all wait or refuse:
_shared._R39A_WIPE_KINDS), in order:

1. the checks, one command as the game account (services/game_restore.vet_script): nothing has
   changed if one refuses;
2. LinuxGSM `stop` when the server was running, the monitor's quiet window opened first;
3. a LinuxGSM backup of the stopped server through the panel's backup path, kept from pruning
   the archive being restored: the undo. If it fails nothing is restored and a server that was
   running is started again;
4. the clear and the extraction, one command as the game account (restore_script);
5. LinuxGSM `start`, only when the server was running before.

Every outcome is audited (`game_backup_restore`: actor, server, archive, undo archive) and a failure
alerts; the card shows the progress and the outcome (`/info`'s "restore").
"""
import threading
import time

from flask import jsonify
from flask_login import current_user, login_required

from panel.core import i18n, terminal
from panel.core.http import _json_body, _log_and_generic
from panel.core.panel_state import (_full_backup_lock, _game_backup_status, r36j_route_job, r36j_route_jobs,
                                    register_server_state)
from panel.db.models import GameServer, claim_row, db, row_birth, still_held
from panel.ops import backup as bk
from panel.ops.ssh_manager import list_game_backups, shell_as_game_user
from panel.ops import ssh_manager as _sm
from panel.routes import _shared
from panel.security.auth import RESTORE_BACKUP, get_game, log_action, permission_required, server_access_required
from panel.services import game_restore as grs, lgsm_players as _lgp
from panel.services.monitoring import _end_offline_window, _mark_expected_offline

_GRS_NOT = i18n.Sentence("Not restored: nothing was changed.")
# server id -> {"running", "ok", "msg", "msg_i18n", "step", "ts"}: what the Backups card shows.
_grs_status = register_server_state({})
_grs_claim_lock = threading.Lock()      # one restore per server: the test and the set are one step
_GRS_VET_TIMEOUT = 900          # reading a large archive through its decompressor takes minutes
_GRS_RESTORE_TIMEOUT = 3600     # clearing and unpacking a large server


def status_for_view(sid):
    """The server's restore status for the Backups card, its message in the viewer's language."""
    st = _grs_status.get(sid)
    if not st:
        return None
    built = i18n.sentence_restored(st.get("msg_i18n")) if st.get("msg_i18n") is not None else None
    msg = i18n.tr(built) if isinstance(built, (i18n.Sentence, i18n.Sentences)) else st.get("msg", "")
    return {"running": bool(st.get("running")), "ok": st.get("ok"), "step": st.get("step", ""), "msg": msg}


def _grs_set(sid, **kw):
    _grs_status[sid] = dict(_grs_status.get(sid) or {}, ts=time.time(), **kw)


def _grs_claim(sid):
    """Mark server `sid` as being restored, unless it already is. True when this call marked it."""
    with _grs_claim_lock:
        if (_grs_status.get(sid) or {}).get("running"):
            return False
        _grs_set(sid, running=True, ok=None, step="checking", msg="", msg_i18n=None)
        return True


def _grs_other_work(gs):
    """Why the restore cannot start beside what runs on `gs` now (a sentence), or None.

    Asked by the route for its answer, and again by the run once it has registered.
    """
    from panel.services import host_reboot as _hr
    if _hr.reboot_busy(gs.remote_id) or _shared._reboot_holds(gs):
        return _hr.busy_message(gs.remote.display_name)
    if _shared._backup_in_progress(gs.id) or _full_backup_lock.locked():
        return i18n.Sentence("A backup is running. Try again once it has finished.")
    others = [k for k in r36j_route_jobs(gs.id) if k != _shared.GRS_KIND]
    if others or _hr._q_live_actions(gs.id):
        return i18n.Sentence("Another action on this server is running. Try again once it has finished.")
    return None


def _grs_find(gs, name):
    """(listing, match) for `name` among the server's own archives; listing None when unreadable."""
    try:
        listing = list_game_backups(gs.remote, gs.short_name)
    except Exception:
        listing = None
    if listing is None:
        return None, None
    return listing, next((b for b in listing if b.get("name") == name and not b.get("in_progress")), None)


def _grs_refuse(gs, name, why, code=409):
    log_action(current_user, "game_backup_restore", target=gs.name, success=False, server=gs,
               detail="refused: %s (%s)" % (why, str(name)[:120]))
    return jsonify({"success": False, "message": i18n.tr(why)}), code


def _grs_request_refusal(gs, body, name):
    """The route's answer when the request itself is refused (before the listing is read), else None."""
    if not gs.installed or not gs.remote_id:
        return jsonify({"success": False, "message": i18n.tr("Server is not installed.")}), 400
    if body.get("confirm") != gs.name:
        return jsonify({"success": False, "message": i18n.tr(
            "Type the server's name exactly to confirm the restore.")}), 400
    bad = grs.archive_problem(name)
    if bad is not None:
        return _grs_refuse(gs, name, bad, 400)
    if (_grs_status.get(gs.id) or {}).get("running"):
        return _grs_refuse(gs, name, i18n.Sentence("This server is already being restored."))
    busy = _grs_other_work(gs)
    return None if busy is None else _grs_refuse(gs, name, busy)


def register(app):
    """The restore route (called from panel_backup.register, beside the other game backup routes)."""
    @app.route("/api/panel/backup/game/<int:server_id>/restore", methods=["POST"])
    @login_required
    @permission_required(RESTORE_BACKUP)
    @server_access_required
    def api_panel_backup_game_restore(server_id):
        """Start restoring the server from one of its backups; the work runs in the background."""
        gs = get_game(server_id)
        body = _json_body()
        name = body.get("name") if isinstance(body.get("name"), str) else ""
        refused = _grs_request_refusal(gs, body, name)
        if refused is not None:
            return refused
        listing, match = _grs_find(gs, name)
        if listing is None:
            return _grs_refuse(gs, name, i18n.Sentence("Couldn't read this server's backups — the host didn't "
                                                       "answer."), 200)
        if match is None:
            return jsonify({"success": False, "message": i18n.tr("Backup not found.")}), 404
        if not _grs_claim(gs.id):
            return _grs_refuse(gs, name, i18n.Sentence("This server is already being restored."))
        try:
            threading.Thread(target=_grs_worker, daemon=True,
                             args=(app, gs.id, row_birth(gs), current_user.id, name, listing)).start()
        except Exception:
            _grs_set(gs.id, running=False, ok=False, msg="could not start the restore", msg_i18n=None)
            return jsonify({"success": False, "message": _log_and_generic("could not start restore")}), 500
        return jsonify({"success": True, "running": True, "message": i18n.tr(
            "Restoring {name} from {archive}: a backup of its current state is taken first.",
            name=gs.name, archive=name)})


def _grs_worker(app, sid, born, actor_id, name, listing):
    """The background run: registered for its whole length, and every way out records an outcome."""
    with app.app_context():
        gs = claim_row(GameServer, sid, born)
        if gs is None:
            _grs_status.pop(sid, None)
            return
        run = _GrsRun(app, gs, actor_id, name, listing)
        try:
            with r36j_route_job(sid, _shared.GRS_KIND):
                run.go()
        except Exception:
            app.logger.warning("restore of %s failed", gs.name, exc_info=True)
            run.put_back()
            run.finish(False, i18n.Sentence("The restore stopped on an error: check the server."), run.undo_note())


class _GrsRun:
    """One restore: the steps, and the facts each later one needs (was it running, the undo archive)."""

    def __init__(self, app, gs, actor_id, name, listing):
        """Hold the server row, who asked, the archive and the listing it was found in."""
        self.app, self.gs, self.actor_id, self.name, self.listing = app, gs, actor_id, name, listing
        self.up, self.t0, self.need, self.undo, self.done = False, 0, 0, None, False

    def undo_note(self):
        """The sentence that names the pre-restore archive to go back to, once there is one ("" before)."""
        return i18n.Sentence("To go back, restore {undo}.", undo=self.undo) if self.undo else ""

    def shell(self, script, timeout):
        """One command as the game account: its output and exit status."""
        gs = self.gs
        out, err, rc = shell_as_game_user(gs.remote, gs.short_name, script, timeout=timeout, selfname=gs.lgsm_name)
        return (out or "") + "\n" + (err or ""), rc

    def go(self):
        """The steps in order; each returns False once it has recorded how the restore ended."""
        why = _grs_other_work(self.gs)
        if why is not None:
            return self.finish(False, _GRS_NOT, why)
        if not _full_backup_lock.acquire(blocking=False):
            return self.finish(False, _GRS_NOT, i18n.Sentence("A backup is running. Try again once it has finished."))
        try:
            ok = self.vet() and self.stop() and self.backup()
        finally:
            _full_backup_lock.release()
        if ok:
            self.restore()
        return None

    def vet(self):
        """Step 1: the checks, and the archive held aside. True when the restore may go on."""
        gs = self.gs
        est = int(max((b.get("size", 0) for b in self.listing), default=0) * 1.15)
        out, _rc = self.shell(grs.vet_script(gs.short_name, gs.lgsm_name or gs.short_name, self.name, est),
                              _GRS_VET_TIMEOUT)
        state, val = grs.vet_outcome(out)
        if state == "unread":
            self.shell(grs.leftovers_script(gs.short_name), 60)     # it may have held the archive aside
        if state != "ready":
            return self.finish(False, _GRS_NOT, i18n.Sentence("Its checks refused: {why}.", why=val))
        self.up, self.t0, self.need = val["up"], val["t0"], val["need"]
        return True

    def stop(self):
        """Step 2: LinuxGSM `stop` when it was running. True when the backup may follow."""
        gs = self.gs
        if not self.up:
            return True
        _grs_set(gs.id, step="stopping")
        extra = _lgp.allowance_seconds(gs.remote, gs.short_name, gs.lgsm_name, "stop")
        _mark_expected_offline(gs.id, "restart", extra)
        try:
            out, err, rc = _sm.run_as_game_user(gs.remote, gs.short_name, "stop", selfname=gs.lgsm_name,
                                                timeout=180 + extra)
        except Exception:
            self.put_back()
            return self.finish(False, _GRS_NOT, i18n.Sentence("The connection dropped while LinuxGSM stopped the "
                                                              "server."), self.start_again())
        oc = _lgp.outcome_of((out or "") + "\n" + (err or ""), rc, "stop")
        if oc is not None:
            # LinuxGSM kept it running (players on): the quiet window opened above ends, as a refused Stop's does.
            _end_offline_window(gs.id)
            self.put_back()
            return self.finish(False, _GRS_NOT, i18n.Sentence("LinuxGSM did not stop the server: {players} player(s) "
                                                              "online.", players=oc.get("players", "?")))
        if rc != 0:
            self.put_back()
            return self.finish(False, _GRS_NOT, i18n.Sentence("LinuxGSM's stop exited {rc}.", rc=rc),
                               self.start_again())
        return True

    def backup(self):
        """Step 3: the undo, a LinuxGSM backup of the stopped server. True when it is in the backup folder.

        Pruning keeps every archive there now plus the new one (keep = their count + 1), so neither the
        panel's prune nor its headroom prune removes an archive the operator may want next; the one
        being restored is held aside under a name and time no prune matches (vet_script).
        """
        gs = self.gs
        _grs_set(gs.id, step="backing_up")
        keep = max(len(self.listing) + 1, bk.game_prune_keep(gs.id)[0])
        try:
            ok, why, _skipped = _shared._marked_backup(
                gs.id, gs.remote, gs.short_name, gs.lgsm_name, keep, game_type=gs.game_type, port=gs.port,
                force=True, query_type=gs.query_type, held=lambda: still_held(gs), wipe_ok=True)
        except Exception as exc:        # a host that dropped: the server must still be started again
            ok, why, _skipped = False, i18n.Sentence("the connection failed ({error})", error=type(exc).__name__), False
        if still_held(gs):
            _game_backup_status[gs.id] = _shared._lg264_bk_status(ok, why, _skipped)
        self.undo = self.new_archive() if ok else None
        if not self.undo:
            self.put_back()
            reason = (why or "") if not ok else i18n.Sentence("its archive is not in the backup folder")
            return self.finish(False, _GRS_NOT, i18n.Sentence("The backup of its current state failed: {reason}.",
                                                              reason=reason), self.start_again())
        return True

    def new_archive(self):
        """The archive the undo backup made: in the listing now, not before, finished and not empty."""
        before = {b.get("name") for b in self.listing}
        try:
            after = list_game_backups(self.gs.remote, self.gs.short_name) or []
        except Exception:
            return None
        made = [b for b in after if b.get("name") not in before and b.get("size", 0) > 0
                and not b.get("in_progress")]
        return made[0]["name"] if made else None

    def restore(self):
        """Step 4 and 5: clear and extract, then start it if it was running."""
        gs = self.gs
        _grs_set(gs.id, step="restoring")
        if self.up:
            _mark_expected_offline(gs.id, "restart")    # the backup took its time: the window starts again
        script = grs.restore_script(gs.short_name, gs.lgsm_name or gs.short_name, self.name, self.t0, self.need,
                                    self.undo)
        try:
            out, rc = self.shell(script, _GRS_RESTORE_TIMEOUT)
            state, said = grs.restore_outcome(out, rc)
        except Exception:
            state, said = "unread", i18n.Sentence("the connection dropped during the restore")
        if state == "unread":
            self.put_back()     # the script's own trap puts it back on every exit it reached
        if state == "refused":
            return self.finish(False, _GRS_NOT, i18n.Sentence("Its checks refused: {why}.", why=said),
                               self.start_again())
        if state != "done":
            # Left stopped: its files are now neither what the archive holds nor what they were.
            return self.finish(False, i18n.Sentence("The restore did not complete ({why}); the server's files may "
                                                    "be partly replaced.", why=said), self.undo_note(),
                               i18n.Sentence("The server is left stopped.") if self.up else "")
        return self.finish(True, i18n.Sentence("Restored from {archive}.", archive=self.name), self.undo_note(),
                           self.start_again())

    def put_back(self):
        """Put the held archive back under its name and time (a restore that ended before its last step)."""
        if not self.t0:
            return
        try:
            self.shell(grs.putback_script(self.gs.short_name, self.name, self.t0), 60)
        except Exception:
            self.app.logger.warning("could not put back the held archive %s", self.name, exc_info=True)

    def start_again(self):
        """LinuxGSM `start` when the restore stopped the server; the sentence that says what became of it ("" else)."""
        if not self.up:
            return ""
        gs = self.gs
        try:
            out, err, rc = _sm.run_as_game_user(gs.remote, gs.short_name, "start", selfname=gs.lgsm_name,
                                                timeout=180)
        except Exception:
            return i18n.Sentence("The connection dropped while LinuxGSM started the server: check it.")
        if rc == 0:
            return i18n.Sentence("The server was started again.")
        last = [ln.strip() for ln in terminal.strip_escapes((out or "") + "\n" + (err or "")).splitlines()
                if ln.strip()]
        return i18n.Sentence("LinuxGSM's start exited {rc}: {last}", rc=rc,
                             last=(last[-1] if last else "no output")[:200])

    def finish(self, ok, *parts):
        """Record the outcome once: the card's status, the audit row, and an alert when it failed.

        `parts`: whole sentences said one after another (an empty one is left out). Returns False, so
        a step can end with `return self.finish(...)`.
        """
        if self.done:
            return False
        self.done = True
        gs = self.gs
        said = i18n.Sentences(*parts)
        english, record = str(said), i18n.sentence_record(said)
        if still_held(gs):
            _grs_set(gs.id, running=False, ok=bool(ok), step="", msg=english, msg_i18n=record)
        else:
            _grs_status.pop(gs.id, None)
        detail = "%s -> %s (pre-restore backup: %s)" % (self.name, english, self.undo or "none")
        try:
            from panel.db.models import User
            actor = db.session.get(User, self.actor_id) if self.actor_id else None
            log_action(actor, "game_backup_restore", target=gs.name, detail=detail[:500], success=bool(ok), server=gs)
        except Exception:
            db.session.rollback()
            self.app.logger.warning("could not audit the restore of %s", gs.name, exc_info=True)
        if not ok:
            _shared._alert_backup(self.app, gs, "Restore from a backup did not complete", "%s: %s" % (gs.name, detail))
        return False
