"""Settings -> Schedules: the card's data and its save (panel/services/schedules.py).

Its own form and route beside the Settings form, like the HTTPS certificate card, so a save here
changes only these keys. Superadmin, step-up (it can switch the OS-update alert off), audited as a
settings_update naming each change.
"""
import time

from flask import flash, redirect, request, url_for
from flask_login import current_user, login_required

from panel.core import i18n
from panel.core.config import update_config
from panel.core.panel_state import _os_update_state
from panel.ops import backup as _bk
from panel.security import owner as _owner
from panel.security.account_guard import step_up_required
from panel.security.auth import log_action, superadmin_required
from panel.services import root_cron as _rc
from panel.services import schedules as _sched

SAVED = "Schedules saved."


def register(app):
    """Register the Schedules save and the card's data (a template global, read by the Settings page)."""
    app.jinja_env.globals["schedules_card"] = card

    @app.route("/settings/schedules", methods=["POST"])
    @login_required
    @superadmin_required
    @step_up_required       # it can switch the OS-update alert off
    def settings_schedules_save():
        """Save the changeable schedules: the backup time, the update check's interval, the OS check."""
        new, why = _sched.parse_form(request.form)
        if why:
            flash(i18n.tr(why), "danger")
            return redirect(url_for("panel_settings") + "#sec-schedules")
        note = []

        def _mut(cfg):
            note[:] = [_sched.change_note(cfg, new)]
            cfg.update(new)
        update_config(_mut)
        log_action(current_user, "settings_update", target="schedules", detail=note[0] if note else "")
        flash(i18n.tr(SAVED), "success")
        return redirect(url_for("panel_settings") + "#sec-schedules")


def _newest_daily_backup():
    """The newest daily panel backup's time (epoch), or 0."""
    try:
        return next((b["created"] for b in _bk.list_backups() if b["kind"] == "daily"), 0)
    except OSError:
        return 0


def card():
    """What the Schedules card shows: the three changeable jobs, the read-only loops, the root cron state."""
    from panel.routes import os_updates as _osu
    now = time.time()
    backup_on = bool(_bk.get_settings().get("enabled"))
    b_last, b_next = _sched.backup_times(_newest_daily_backup(), backup_on, now)
    u_last = _osu._UPDATE_RAN["at"] or None
    o_last, o_next = _sched.os_check_times(_os_update_state["last_run"], now)
    workers = _sched.worker_rows()
    for w in workers:
        w["often"] = i18n.tr(_sched.every_words(w["every"]))
    return {
        "backup_on": backup_on, "backup_at": _sched.utc_hhmm(_sched.backup_at()),
        "backup_last": _sched._naive(b_last), "backup_next": _sched._naive(b_next),
        "update_every": _sched.update_every() // 60, "update_choices": _sched.UPDATE_CHOICES,
        "update_last": _sched._naive(u_last),
        "update_next": _sched._naive(u_last + _sched.update_every()) if u_last else None,
        "os_on": _sched.os_check_on(), "os_at": _sched.utc_hhmm(_sched.os_check_at()),
        "os_last": _sched._naive(o_last), "os_next": _sched._naive(o_next),
        "workers": workers,
        "owner": _owner.is_owner(current_user) and bool(getattr(current_user, "is_superadmin", False)),
        "root_cron_on": _rc.enabled(),
    }
