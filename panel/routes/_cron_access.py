"""Who may change a game server's Scheduled Tasks, and what the card shows those who may not.

A scheduled task runs ANY command as the game account (`bash -c` through the recorder), so the four
Scheduled Tasks writes (add, update, delete, Run now) need EDIT_FILES as well as MANAGE_SERVERS:
EDIT_FILES is the panel's bar for changing what that account runs, and MANAGE_SERVERS alone
(schedule, alerts, mods) would otherwise read every secret in its configs and plant a login key. A
failed task's recorded output is whatever the command printed, so it needs VIEW_FILES. Run now runs
only a line read back from the account's crontab. OWASP Authorization Cheat Sheet, "Enforce Least
Privileges" and "Validate the Permissions on Every Request".
"""
from flask import jsonify
from flask_login import current_user

from panel.core import i18n
from panel.ops import ssh_manager as _sm
from panel.security.auth import _can_manage_files, _fpm_can_edit, _fpm_can_view, log_action

# The card (templates/server_files.html, #cron-ro) prints the same sentence.
CRON_NEEDS_EDIT_FILES = ("Adding, changing, deleting or running a scheduled task also needs the \"Change game "
                         "server files\" permission, because a task can run any command as this server's account.")
CRON_OUTPUT_NEEDS_VIEW_FILES = "This task's output needs the \"View game server files\" permission."


def withhold_output(jobs):
    """`jobs` with each failed task's output replaced by why, for a viewer without VIEW_FILES."""
    if not _fpm_can_view():
        for job in jobs:
            if job.get("error"):
                job["error"] = i18n.tr(CRON_OUTPUT_NEEDS_VIEW_FILES)
    return jobs


def write_refused():
    """The 403 for a Scheduled Tasks write by someone without MANAGE_SERVERS and EDIT_FILES, else None."""
    if not _can_manage_files():
        return jsonify({"error": "Permission denied"}), 403
    if not _fpm_can_edit():
        return jsonify({"success": False, "error": "Permission denied",
                        "message": i18n.tr(CRON_NEEDS_EDIT_FILES)}), 403
    return None


def line_refused(gs, raw):
    """A refusal when `raw` is not a line read back from the account's crontab now, else None.

    Run now runs the command taken from `raw`; a line the request typed, never scheduled, would run
    as the account without ever being in the crontab the card lists.
    """
    jobs = _sm.list_cron_jobs(gs.remote, gs.short_name, gs.lgsm_name)
    if jobs is None:
        why = i18n.tr("Couldn't read the scheduled tasks to check that one, so it was not run.")
    elif not raw.strip() or raw.strip() not in {(j.get("raw") or "").strip() for j in jobs}:
        why = i18n.tr("That task has changed since the page loaded — reload Scheduled Tasks and try again.")
    else:
        return None
    # Audited: a refused Run now is an attempt to run a command as the account.
    log_action(current_user, "cron_run_now", target=gs.name, success=False,
               detail="not run: not a task in the crontab", server=gs)
    return jsonify({"success": False, "message": why})
