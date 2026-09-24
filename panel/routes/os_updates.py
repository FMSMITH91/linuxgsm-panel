"""Per-host OS package update checks and runs.

Moved out of register_routes() verbatim — see panel/routes/__init__.py for why.
"""
from panel.core.panel_state import (_os_update_seen, _os_update_state)
from panel.db.models import (RemoteServer)
from panel.ops import (system_ops as so)
from panel.services import (notifications)
from panel.services.certs import (_maybe_alert_cert_expiring)
from panel.services.monitoring import (_MONITOR_HOST_WORKERS)
import concurrent.futures
import time
from panel.core.clock import utcnow
from app import (_is_security_pkg, _log, _os_update_note, _os_updates_for)

_OS_UPDATE_EVERY = 24 * 3600
# When this process started, as the stored created_at columns are (naive UTC). A host that existed
# before it may already have been told about what it has waiting; one added since cannot have been.
_PROCESS_STARTED = utcnow()


def _os_update_seeds(remote, seeding, first_read):
    """Whether this host's reading only SEEDS the alert state (recorded, never announced).

    Seeding was process-wide: only the first sweep after a restart seeded, so a host that did not
    answer THAT sweep (rebooting, apt locked) got no entry, read (0, 0) on the next day's sweep,
    and had the list it already had before the restart — already announced — announced again. Any
    host's first reading in this process seeds, unless the host was added after the process
    started: its first batch is news to everyone."""
    if seeding:
        return True
    if not first_read:
        return False
    created = getattr(remote, "created_at", None)
    return created is None or created < _PROCESS_STARTED


def register(app, supervise):
    def _maybe_alert_os_updates(force=False):
        """Check every reachable host once a day and alert when updates appear. Never raises.

        Pushes its own app context: the update-check ticker runs in a bare thread and doesn't have
        one, and this is the only DB-touching thing on it."""
        try:
            now = time.time()
            if not force and now - _os_update_state["last_run"] < _OS_UPDATE_EVERY:
                return
            # The first pass after a restart SEEDS; it does not announce. `hosts` is a plain
            # in-memory dict (panel_state.py) and nothing persists it, so after a restart
            # `had_count, had_sec` reads (0, 0) for every host and the edge test below fires for
            # every update already pending — the identical list, re-announced ~30 s after boot.
            # Any restart did it: a click on "Update now", a reboot, a config change. Same
            # reasoning as app.py's refusal to re-arm on a failed check.
            seeding = _os_update_state["last_run"] == 0.0
            with app.app_context():
                remotes = RemoteServer.query.all()
                # Armed only once the host list is actually in hand: a failure before this point
                # (a locked DB, no context) must retry on the next tick rather than burn the whole
                # day's throttle window on an attempt that did no work.
                _os_update_state["last_run"] = now
                if not remotes:
                    return
                # `apt update` is a network fetch with a 60s timeout, on top of a reachability
                # probe; serially that is minutes of a shared ticker thread. Probe concurrently and
                # decide serially — as _monitor_pass does — so the alert logic stays single-threaded.
                checks = {}
                with concurrent.futures.ThreadPoolExecutor(
                        max_workers=min(_MONITOR_HOST_WORKERS, len(remotes))) as ex:
                    for r, got in zip(remotes, ex.map(_os_updates_for, remotes)):
                        checks[r.id] = got
                for remote in remotes:
                    got = checks.get(remote.id)
                    if got is None:
                        continue          # couldn't tell — say nothing rather than guess
                    # The banner and the OS Updates card read this: the sweep is the only thing that
                    # asks every host, and its answer is what they show until someone forces a check.
                    _os_update_note(remote, got)
                    pkgs = got.get("packages") or []
                    count = len(pkgs)
                    sec = sum(1 for p in pkgs if _is_security_pkg(p))
                    names = [p.get("name", "?") for p in
                             ([p for p in pkgs if _is_security_pkg(p)] or pkgs)][:5]
                    first_read = remote.id not in _os_update_state["hosts"]
                    had_count, had_sec = _os_update_state["hosts"].get(remote.id) or (0, 0)
                    _os_update_state["hosts"][remote.id] = (count, sec)
                    # Security updates get their own arm: they routinely land on a host that already
                    # has ordinary updates pending, and keying on the total alone would swallow them.
                    # `seeding` first: the counts above are now recorded, the banner and the card
                    # have their answer, and only a transition THIS process witnessed alerts.
                    if (_os_update_seeds(remote, seeding, first_read)
                            or not ((count and not had_count) or (sec and not had_sec))):
                        continue
                    what = ("%d security update%s of %d waiting"
                            % (sec, "" if sec == 1 else "s", count)) if sec else \
                           ("%d update%s waiting" % (count, "" if count == 1 else "s"))
                    notifications.notify(
                        "os_updates",
                        "Security updates on %s" % remote.display_name if sec
                        else "Updates available on %s" % remote.display_name,
                        "%s on %s: %s%s"
                        % (what, remote.display_name, ", ".join(names),
                           ", …" if count > len(names) else ""))
                # Forget hosts that no longer exist: SQLite hands a deleted remote's row id to the
                # next one added, and inheriting its count would swallow the new host's first batch.
                ids = {r.id for r in remotes}
                for gone in [i for i in _os_update_state["hosts"] if i not in ids]:
                    del _os_update_state["hosts"][gone]
                for gone in [i for i in _os_update_seen.copy() if i not in ids]:
                    _os_update_seen.pop(gone, None)   # same reason: a freed row id gets reused
        except Exception:
            _log.debug("os-update sweep failed", exc_info=True)

    # Refresh the panel's "update available" status on the SERVER, on its own schedule — so the
    # check happens whether or not anyone has the panel open. The browser badge only polls while a
    # tab is looking at it; this keeps the server's own knowledge current (warms the shared cache in
    # system_ops), so the badge is correct the INSTANT someone loads a page instead of waiting on a
    # first client-side check. Each tick does a `git fetch` (+ a CI-state lookup only when actually
    # behind), and it logs once when a newly verified update first appears — a server-side record
    # even with nobody watching. Half-hourly is plenty for a code update.
    def update_check_ticker():
        time.sleep(30)   # let boot settle before the first network fetch
        last_logged_sha = None
        while True:
            try:
                st = so.panel_update_status(force=True)
                if st.get("update_available"):
                    tgt = (st.get("target_sha") or st.get("remote_sha") or "")
                    if tgt and tgt != last_logged_sha:
                        last_logged_sha = tgt
                        app.logger.info(
                            "panel update available: version %s (%s), %s commit(s) behind",
                            st.get("remote_version", "?"), tgt[:7], st.get("behind", "?"))
                        # Mirror the panel's update widget: name the target commit AND list the
                        # changes (commit subjects) so you can see what's in the update.
                        changes = [c[:100] for c in (st.get("changes") or [])][:10]
                        change_lines = ("\n" + "\n".join("• " + c for c in changes)) if changes else ""
                        notifications.notify(
                            "update_available", "Panel update available",
                            "%s (%s) — %s commit(s) behind:%s\nRe-run the installer, or send /update in Telegram."
                            % (st.get("remote_version", "?"), tgt[:7], st.get("behind", "?"), change_lines))
                else:
                    last_logged_sha = None   # up to date — let a future update log again
            except Exception:
                app.logger.debug("update-check tick failed", exc_info=True)
            # Deliberately OUTSIDE that try. These two only ride this thread for its cadence and
            # have nothing to do with the panel-update check — but sharing its `try` meant any
            # raise above skipped them, and panel_update_status shells out to git (`_git` catches
            # only TimeoutExpired, so a checkout on a host with no `git` binary raises straight
            # through). A persistent failure there would have silently disabled both alerts, which
            # is the exact way the OS-update alert was dead before. Each swallows its own errors.
            _maybe_alert_cert_expiring()   # periodic TLS-cert expiry check
            _maybe_alert_os_updates()      # ...and the once-a-day OS package check
            time.sleep(1800)

    # This module owns both the ticker and the helper the tests drive, so it supervises and
    # publishes them itself. register_routes() passes its supervisor in rather than reaching back
    # into here for the names — which is what broke when the section first moved: the
    # _supervise(...) call and the `app._maybe_alert_os_updates = ...` export were left behind,
    # still naming functions that had gone.
    supervise("update-check", update_check_ticker)
    app._maybe_alert_os_updates = _maybe_alert_os_updates
