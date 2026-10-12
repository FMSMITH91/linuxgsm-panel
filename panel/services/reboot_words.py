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
        return "failed", ("it could not be read or restored for an hour after the reboot was called "
                          "off; check the server")
    return "failed", "it could not be read or restored for an hour after the reboot; check the server"


def blocked_sentence(blockers):
    """Why a reboot may not run now: the work in flight, each piece named in a phrase of its own."""
    what = [i18n.Sentence(_BLOCKER_WORDS.get(b["kind"], _BLOCKER_OTHER).template, name=b["name"])
            for b in blockers[:4]]
    return i18n.Sentence("Not now: {what} is running, and a reboot would cut it off.", what=what)


def shown(body):
    """A reboot answer for the page: its message, warning and reason translated whole (i18n.tr)."""
    return dict(body, **{k: i18n.tr(body[k]) for k in ("message", "warning", "reason")
                         if isinstance(body.get(k), str)})
