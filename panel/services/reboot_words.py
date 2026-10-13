"""The words of a clean host reboot that are both recorded and shown (host_reboot).

Each is an i18n.Sentence: English in the audit rows, the job's record and the chat bots, and
translated whole by the route that answers the page (shown). Kept apart from host_reboot, which
is the plan and the job, so that module stays within the size the code-quality gate allows.
"""
from panel.core import i18n


def busy_message(host):
    """Why an action on `host` (its display name) is refused while the host is being rebooted.

    An i18n.Sentence: English wherever it is recorded, translated whole by the route that shows it.
    """
    return i18n.Sentence("{host} is being rebooted: its game servers are being stopped first. Try "
                         "again once it is back.", host=host)


# Each phrase is a Sentence too, so a list of them is translated item by item inside the sentence
# that names them (blocked_sentence).
_BLOCKER_WORDS = {"install": i18n.Sentence("an install of {name}"),
                  "backup": i18n.Sentence("a backup of {name}"),
                  "action": i18n.Sentence("a LinuxGSM action on {name}"),
                  "content": i18n.Sentence("a content install on {name}"),
                  "maintenance": i18n.Sentence("LinuxGSM maintenance on {name}"),
                  "bootstrap": i18n.Sentence("a bootstrap of {name}"),
                  "dpkg": i18n.Sentence("a package install on {name}"),
                  "apt": i18n.Sentence("a package install on {name}"),
                  "self_update": i18n.Sentence("an update of {name}"),
                  "restore": i18n.Sentence("a restore of {name}"),
                  "full_backup": i18n.Sentence("a full backup of {name}")}
_BLOCKER_OTHER = i18n.Sentence("work on {name}")


# The panel's own blockers name it with a phrase, not a host label: the English "the panel" went
# into the translated blocker phrase as written ("una actualización de the panel").
PANEL_NAME = i18n.Sentence("the panel")
# ...and are said whole: "the panel" slotted into "of {name}" read "una actualización de el panel"
# and "une mise à jour de le panneau", where Spanish says "del" and French "du" (review 1012b).
_PANEL_BLOCKER_WORDS = {"self_update": i18n.Sentence("an update of the panel"),
                        "restore": i18n.Sentence("a restore of the panel"),
                        "full_backup": i18n.Sentence("a full backup of the panel")}

# A running job's phase as words. The raw token ("stopping", "arming") went into the translated
# "{host} is already being rebooted ({phase})." as written.
_PHASE_WORDS = {"preflight": i18n.Sentence("getting ready"),
                "warning": i18n.Sentence("warning the players"),
                "stopping": i18n.Sentence("stopping its game servers"),
                "arming": i18n.Sentence("about to restart"),
                "rebooting": i18n.Sentence("restarting")}


def phase_words(phase):
    """A reboot job's phase token as a translatable phrase ("in progress" for any other)."""
    return _PHASE_WORDS.get(phase) or i18n.Sentence("in progress")


def state_word(blockers, busy, unknown):
    """The host's census state as its token: blocked, busy, unknown or idle (host_player_state).

    Kept here, with the other words of a reboot, so host_reboot stays within the size the
    code-quality gate allows.
    """
    if blockers:
        return "blocked"
    if busy:
        return "busy"
    return "unknown" if unknown else "idle"


# A row whose account cannot be read (removed outside the panel, a name that fails game_idents_ok)
# never resolves: every owner's step waits on a read that will not come, and nothing aged it out
# while the host answered (STALE_PLAN is for a silent host). The plan never finished, and
# _pending_conflict refused every later reboot of that host, silently. Here, beside the other
# words of a reboot, so host_reboot stays within the size the code-quality gate allows.
ROW_GIVE_UP = 3600     # a plan row its host answers for but that never resolves: reported failed


def row_gave_up(d, now, rollback=False, after=ROW_GIVE_UP):
    """None while an unresolved plan row may still resolve; ("failed", why) once `after` s have passed.

    The clock runs only while the row's host answers and nothing known holds it: host_reboot drops
    `pending_since` while a rollback's host is silent and while a LinuxGSM command is in flight,
    so it starts again from the next pass that has no such reason. `rollback`: the reboot never
    happened, so the reason does not say "after the reboot".
    """
    d.setdefault("pending_since", now)
    if now - d["pending_since"] < after:
        return None
    if rollback:
        # "Or did not happen": _same_boot rolls back a reboot that was sent and never took, too.
        return "failed", ("it could not be read or restored for an hour after the reboot was called "
                          "off or did not happen; check the server")
    return "failed", "it could not be read or restored for an hour after the reboot; check the server"


def blocked_sentence(blockers):
    """Why a reboot may not run now: the work in flight, each piece named in a phrase of its own."""
    what = [_PANEL_BLOCKER_WORDS[b["kind"]] if b["name"] == PANEL_NAME and b["kind"] in _PANEL_BLOCKER_WORDS
            else i18n.Sentence(_BLOCKER_WORDS.get(b["kind"], _BLOCKER_OTHER).template, name=b["name"])
            for b in blockers[:4]]
    return i18n.Sentence("Not now: {what} is running, and a reboot would cut it off.", what=what)


def shown(body):
    """A reboot answer for the page: its message, warning and reason translated whole (i18n.tr)."""
    return dict(body, **{k: i18n.tr(body[k]) for k in ("message", "warning", "reason")
                         if isinstance(body.get(k), str)})


def blocker(kind, name, detail=""):
    """One piece of work a reboot would cut off: its kind, the name it is shown by, and a detail."""
    return {"kind": kind, "name": name, "detail": detail}


def panel_blocker(kind):
    """A blocker that is the panel's own work, marked `panel` for the reboot dialog.

    The dialog shows a blocker's name as a name, never translated; `panel` tells it this one is the
    phrase "the panel" (in the viewer's language), without matching the English words.
    """
    return dict(blocker(kind, PANEL_NAME), panel=True)


def hold_clock(recs, save, commit):
    """Stop each pending row's give-up clock while its host is silent. -> True (the fast tick).

    `save(gs, d)` each row changed, then `commit()`.

    A rollback acts without asking whether the host answers, and row_gave_up is for a host that
    answers but cannot resolve a row: through an outage longer than an hour every row was reported
    failed and the plan cleared, so the monitor's locks stayed aside and nothing was started when
    the host came back. row_gave_up starts the clock afresh on the next pass the host answers.
    """
    for gs, d in recs:
        if d.get("restore") == "pending" and d.pop("pending_since", None) is not None:
            save(gs, d)
    commit()
    return True


# An "inflight" wait pauses ROW_GIVE_UP, but not for ever: a LinuxGSM update stuck on a steamcmd
# download that never ends (it has no timeout of its own), or a `debug` left running in the panel's
# terminal, held the row pending for good. Then no summary was sent, and _pending_conflict refused
# every later reboot of that host. A day is STALE_SENT's "not a reboot in progress".
INFLIGHT_GIVE_UP = 86400


def start_waits(d, detail, now, rollback=False):
    """The row's step when its panel start must wait (`detail`, safe_start's reason).

    None while still pending, ("failed", why) once a LinuxGSM command has held it for
    INFLIGHT_GIVE_UP. "inflight" is a LinuxGSM update or backup running for the server, and a start never goes over
    one: a known wait, however long the download takes, not a row that cannot resolve, so its
    give-up clock starts again once nothing holds it. `inflight_since` is that wait's own clock,
    which the reset does not touch; any other wait ends it.
    """
    if detail != "inflight":
        d.pop("inflight_since", None)
        return None
    d.pop("pending_since", None)
    if now - d.setdefault("inflight_since", now) < INFLIGHT_GIVE_UP:
        return None
    if rollback:
        return "failed", ("a LinuxGSM command for it was still running a day after the reboot was "
                          "called off or did not happen; check the server")
    return "failed", "a LinuxGSM command for it was still running a day after the reboot; check the server"
