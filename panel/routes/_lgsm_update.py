"""What an update-lgsm run did, in plain words, and the LinuxGSM release notes the server page shows.

update-lgsm (LinuxGSM's command_update_linuxgsm.sh) prints which files it checked and replaced but
never the release it moved to, so the release is read before and after the run: the instance
script's `version=` line (hosts.lgsm_versions), the same read the server page's LinuxGSM line uses.
The reply then says "updated from v26.5.0 to v26.6.0", "already up to date" or why it failed, and
carries the new state for the page's LinuxGSM line and the notes of every release in between.
"""
import logging

from panel.core import i18n
from panel.ops import ssh_manager as _sm
from panel.services import lgsm_data, lgsm_releases

_log = logging.getLogger(__name__)

ACTION = "update-lgsm"


class LgsmUpdated(i18n.Sentence):
    """update-lgsm's outcome; `lgsm` is the page's new LinuxGSM state and the release notes."""

    __slots__ = ("lgsm",)


def script_release(remote, account, selfname):
    """The release an instance script says it runs ('v26.6.0'), or None when it could not be read."""
    try:
        release, _modules = _sm.lgsm_versions(remote, account, selfname)
    except Exception:
        _log.debug("LinuxGSM version read failed", exc_info=True)
        return None
    return release


def _older(release, latest):
    """Whether `release` is known and older than `latest` (also known)."""
    return bool(release and latest and not lgsm_data.release_at_least(
        release, tuple(int(p) for p in latest[1:].split("."))))


def state(release):
    """{"release", "latest", "behind"} for the page's LinuxGSM line: behind only when both are read."""
    latest = lgsm_data.latest_release()
    return {"release": release or "", "latest": latest or "", "behind": _older(release, latest)}


def notes_behind(info):
    """The notes of the releases a server is behind by: from its release up to the latest ([] if none)."""
    if not info.get("behind"):
        return []
    return lgsm_releases.between(info["release"], info["latest"])


def _said(name, before, after, latest):
    """(ok, template, values) for an update-lgsm that exited 0."""
    if not after:
        return True, ("update-lgsm finished on '{name}', but the panel could not read which LinuxGSM "
                      "release it is on now."), {"name": name}
    if before and before != after:
        return True, "LinuxGSM on '{name}' updated from {old} to {new}.", {"name": name, "old": before,
                                                                         "new": after}
    if _older(after, latest):
        return False, "LinuxGSM on '{name}' is still on {version}: {latest} was not installed.", {
            "name": name, "version": after, "latest": latest}
    return True, "LinuxGSM on '{name}' is already up to date ({version}).", {"name": name, "version": after}


def _failed(name, rc, reason):
    """(False, template, values) for an update-lgsm that exited non-zero: the line that says why."""
    if reason:
        return False, "LinuxGSM could not be updated on '{name}': {reason}", {"name": name, "reason": reason}
    return False, ("LinuxGSM could not be updated on '{name}': update-lgsm exited with code {rc} and "
                   "printed nothing."), {"name": name, "rc": rc}


def outcome(name, before, after, rc, reason):
    """(ok, LgsmUpdated) for one update-lgsm run.

    `before` / `after`: the script's release read before and after the run (None when unread);
    `reason`: the LinuxGSM line that names a failure ("" when it printed nothing). A failed run
    still carries the release read after it, so the page's line shows where it is.
    """
    info = state(after)
    ok, template, vals = _said(name, before, after, info["latest"]) if rc == 0 else _failed(name, rc, reason)
    msg = LgsmUpdated(template, **vals)
    moved = bool(after and before and after != before)
    info["before"] = before or ""
    info["notes"] = lgsm_releases.between(before, after) if moved else []
    info["notes_url"] = lgsm_releases.RELEASES_PAGE
    msg.lgsm = info
    return ok, msg
