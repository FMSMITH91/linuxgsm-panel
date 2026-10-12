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


def blocked_sentence(blockers):
    """Why a reboot may not run now: the work in flight, each piece named in a phrase of its own."""
    what = [i18n.Sentence(_BLOCKER_WORDS.get(b["kind"], _BLOCKER_OTHER).template, name=b["name"])
            for b in blockers[:4]]
    return i18n.Sentence("Not now: {what} is running, and a reboot would cut it off.", what=what)


def shown(body):
    """A reboot answer for the page: its message, warning and reason translated whole (i18n.tr)."""
    return dict(body, **{k: i18n.tr(body[k]) for k in ("message", "warning", "reason")
                         if isinstance(body.get(k), str)})
