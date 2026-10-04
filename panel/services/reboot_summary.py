"""The words of a clean reboot's notices: the summary after it, and the notices on the way.

Split out of panel/services/host_reboot.py, which runs the reboot and the restore. Nothing here
reads a host, the database or the clock: each function is handed the plan rows' records (the
`reboot_restore` dicts) and answers text. Every sentence must be true of every case it prints in:
a rollback is not a reboot, a server found already running was not started by the panel, and one
the plan could not read is not "not running".
"""


def _host_label(remote):
    try:
        return remote.display_name
    except Exception:  # noqa: BLE001 - a label must never be what raises
        return "the host"


def _unread_note(n, verbs):
    """' N server(s) could not be read, so the panel did not <verbs> it/them.', or '' for none.

    The running servers whose session the plan could not read: no plan holds them, so the panel
    neither stops nor brings them back, and the notices must not count them as "not running".
    """
    if not n:
        return ""
    return " %d server%s could not be read, so the panel did not %s %s." % (
        n, "" if n == 1 else "s", verbs, "it" if n == 1 else "them")


def _late_text(remote, recs, secs):
    """'X hasn't come back after N min', and how many of its servers come back when it does."""
    text = "%s hasn't come back after %d min" % (_host_label(remote), secs // 60)
    # Only the ones that do: a queued stop, or no Autostart with restoring off, stays stopped.
    back = sum(1 for _g, d in recs if d.get("owner") in ("monitor", "panel"))
    if back:
        text += "; its %d server%s come%s back when it does" % (
            back, "" if back == 1 else "s", "s" if back == 1 else "")
    return text + "."


# The results a summary counts as running again: brought back by Autostart, started by the panel,
# found already running when the panel went to start it, or (a rollback) never stopped at all.
_BACK_RESULTS = ("autostart", "panel", "running", "kept")


def _tally(recs):
    """({result: count} for every result a row can end with, [(name, why) of the failed rows])."""
    results = [d.get("result") for _g, d in recs]
    failed = [(gs.name, d.get("result")) for gs, d in recs if d.get("restore") == "failed"]
    return {k: results.count(k) for k in _BACK_RESULTS + ("stopped",)}, failed


def _who(n):
    """'2 by Autostart, 1 started by the panel' (and ', 1 found already running' when there is one)."""
    text = "%d by Autostart, %d started by the panel" % (n["autostart"], n["panel"])
    if n["running"]:
        text += ", %d found already running" % n["running"]
    return text


def _within(secs):
    """A duration rounded UP, so "within" it is true: seconds under 2 min, else whole minutes."""
    secs = max(0, int(-(-secs // 1)))
    return "%d s" % secs if secs < 120 else "%d min" % -(-secs // 60)


def _boot_clause(boot, sent):
    """The clause saying when the host's new boot started after the send, or '' when that is not known.

    `boot` is the host's own boot time (the moment the panel first read its uptime, minus that
    uptime), so it holds even when the panel was down and saw the host back minutes later.
    """
    if not sent or not boot or boot <= sent:
        return ""
    return ": its new boot started within %s of the reboot being sent" % _within(boot - sent)


def _reboot_head(remote, recs, now, n, failed):
    """The summary's first sentences after a reboot: when the host booted, and how many are back within what.

    The servers' time runs to when the restore CONFIRMED the last of them (each row's back_at, taken
    when its probe or its start returned), no earlier than it came back. None back: no time at all.
    """
    meta = recs[0][1]
    sent = meta.get("sent")
    text = "%s rebooted%s." % (_host_label(remote), _boot_clause(meta.get("boot_seen"), sent))
    back = n["autostart"] + n["panel"] + n["running"]
    if back + failed:
        when = ""
        if sent and back:
            last = max(d.get("back_at") or now for _g, d in recs if d.get("result") in _BACK_RESULTS)
            when = " within %s of the reboot being sent" % _within(last - sent)
        text += " %d/%d running again%s (%s)." % (back, back + failed, when, _who(n))
    return text


# Why a server stayed stopped, by its row's "queued": a queued stop (True), no Autostart with
# restoring turned off (False), or a plan recorded before "queued" was (None): either of the two.
# A rollback restarts the False case, so only the reasons the rows really have are named.
_STAYED_WHY = {True: "a queued stop", False: "no Autostart, and restoring is turned off",
               None: "a queued stop, or no Autostart with restoring turned off"}


def _queued_kind(q):
    """A row's "queued" as True, False or None (anything else is read as not recorded)."""
    return q if q is True or q is False else None


def _stayed_why(whys):
    """The reasons for these _queued_kind values: one reason alone, else each with its count."""
    named = [(k, whys.count(k)) for k in (True, False, None) if k in whys]
    if len(named) == 1:
        return _STAYED_WHY[named[0][0]]
    return "; ".join("%d: %s" % (n, _STAYED_WHY[k]) for k, n in named)


def _stayed_note(recs):
    """The 'N stayed stopped, as planned (why).' sentence, naming only the reasons these rows have, or ''."""
    whys = [_queued_kind(d.get("queued")) for _g, d in recs if d.get("result") == "stopped"]
    if not whys:
        return ""
    # They were RUNNING before the reboot (a stopped server is never in a plan): not "as before".
    return " %d stayed stopped, as planned (%s)." % (len(whys), _stayed_why(whys))


def _rollback_head(remote, meta, n):
    """The summary's first sentences when the reboot did not happen: how many are coming back, and how.

    Only the rows that are: one whose start failed is named after, as not back, and the panel's
    starts can be minutes apart (a failed one is tried three times), so none is said to be "now".
    One never stopped is said after, as kept running.
    """
    back = n["autostart"] + n["panel"] + n["running"]
    text = ("Reboot of %s did not happen (%s): %d server%s coming back. %d started by the panel, %d "
            "by Autostart within 5 min" % (_host_label(remote), meta.get("reason") or "?", back,
                                           "" if back == 1 else "s", n["panel"], n["autostart"]))
    if n["running"]:
        text += ", %d found already running" % n["running"]
    return text + "."


def _summary(remote, recs, now, rollback_):
    n, failed = _tally(recs)
    if rollback_:
        text = _rollback_head(remote, recs[0][1], n)
    else:
        text = _reboot_head(remote, recs, now, n, len(failed))
    text += _stayed_note(recs)
    if n["kept"]:
        # Only in a rollback: the plan was undone before its stop took, so it never stopped.
        text += " %d kept running (%s not stopped)." % (n["kept"], "it was" if n["kept"] == 1 else "they were")
    for name, why in failed:
        text += " %s didn't come back: %s." % (name, why)
    text += _unread_note(recs[0][1].get("unread"), "stop or start")
    return text, not failed
