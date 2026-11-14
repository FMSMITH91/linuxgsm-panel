r"""Arma 3 and DayZ: the local mod folders LinuxGSM's `mods` and `servermods` settings load.

LINUXGSM (master 98be8a98, 2026-11-13): arma3server's and dayzserver's _default.cfg
(lgsm/config-default/config-lgsm/<game>server/_default.cfg) set `mods=""` and `servermods=""` and
start the server with `-mod=${mods} -servermod=${servermods}`. The comment above `mods` says how
it is written: paths relative to serverfiles, separated by `\;` (`mods="mods/@ace\;mods/@cba_a3"`).
The backslash is needed because LinuxGSM hands the start line to tmux, whose shell would end the
command at a bare `;`. The server runs in serverfiles (executabledir="${serverfiles}"), so `@x`
names serverfiles/@x and `mods/@x` names serverfiles/mods/@x.

STEAM WORKSHOP mods are another setting, `workshopmods`, edited by the Workshop card
(routes/workshop.py). LinuxGSM's workshop-update (lgsm/modules/workshop_core.sh) installs them in
serverfiles/workshop/@<id> and never writes `mods`: at start, fn_workshop_mods_startparameters
appends them to the `mods` value it passes (`mods="${mods:+${mods}\;}workshop/@<id>..."`), after
the folders here. So this card lists only the folders in serverfiles and serverfiles/mods, never
serverfiles/workshop, and leaves the Workshop's own list alone.

A FOLDER is offered only when it is a real folder (not a link) whose name is `@` and then letters,
digits and `._+-` (no separator, no `..`), in a serverfiles that resolves inside the home: the
value is passed unquoted on the start line, so nothing that a shell would split or expand is
written. A value already in the config that is not such a folder (a path the operator typed, a
folder that is gone) is kept where it is and may be moved or removed, never added anew.

THE SAVE is LinuxGSM's own config write (ssh_manager/files.py lgsm_write_config: under the
instance cfg's lock, keeps every other line, refuses a key secrets-<selfname>.cfg sets). The read
it checks against runs under the same lock, so a settings save cannot land between them.
"""
import re

from panel.ops.ssh_manager import _core as _smc, files as _smf

GAMES = frozenset({"arma3", "dayz"})
KEYS = ("mods", "servermods")
# A mod folder's name, as listed and as accepted.
_NAME_RE = re.compile(r"@[A-Za-z0-9_+-][A-Za-z0-9._+-]{0,63}\Z")
_SEP_RE = re.compile(r"\\?;")
MAX_LISTED = 200
_LIST_B, _LIST_E = "__ARMAM_LIST_B__", "__ARMAM_LIST_E__"

UNREAD = "Couldn't read this server's config and mod folders — the host didn't answer. Nothing was changed."
NOT_A_FOLDER = "That isn't one of this server's mod folders. Refresh the list and pick again."
BOTH_LISTS = "A folder can be in Mods or in Server mods, not in both."
DUPLICATE = "Each folder can be in a list once."
TOO_MANY = "A list holds at most 200 folders."
IN_SECRETS = ("This list is set in this server's secrets file, which LinuxGSM reads last. "
              "Change it there — nothing has been changed.")
REASONS = (UNREAD, NOT_A_FOLDER, BOTH_LISTS, DUPLICATE, TOO_MANY, IN_SECRETS)


def supported(game_type):
    """Whether the game loads LinuxGSM's `mods` and `servermods` folders (Arma 3, DayZ)."""
    return (game_type or "").lower() in GAMES


def valid_name(name):
    """Whether `name` is a mod folder name the card lists and writes."""
    return isinstance(name, str) and bool(_NAME_RE.match(name)) and ".." not in name


def split_value(value):
    r"""The folders of a `mods` value in order: split at `\;` (or a bare `;`), blanks dropped."""
    return [t.strip() for t in _SEP_RE.split(value or "") if t.strip()]


def join_value(folders):
    r"""A `mods` value LinuxGSM passes as one -mod= word: the folders joined with `\;`."""
    return "\\;".join(folders)


def list_sh(user):
    """Shell listing the mod folders: "T @x" for serverfiles/@x, "M @x" for serverfiles/mods/@x.

    serverfiles must resolve inside the home; find -P lists real folders only, and a `mods` that
    is a link is not looked in.
    """
    home = _smc._quote("/home/%s" % user)
    pick = "-mindepth 1 -maxdepth 1 -type d -name '@*' ! -name '*[!A-Za-z0-9._@+-]*'"
    return ("h=$(cd -P -- %s 2>/dev/null && pwd -P) || h=; " % home
            + "sf=$(cd -P -- %s/serverfiles 2>/dev/null && pwd -P) || sf=; " % home
            + 'case "$sf" in "$h"/?*) [ -n "$h" ] || sf= ;; *) sf= ;; esac; '
            + "printf '%s\\n' " + _LIST_B + "; "
            + '[ -n "$sf" ] && find -P "$sf" %s -printf "T %%f\\n" 2>/dev/null | head -n %d; '
            % (pick, MAX_LISTED)
            + '[ -n "$sf" ] && [ -d "$sf/mods" ] && [ ! -L "$sf/mods" ] && find -P "$sf/mods" %s '
            '-printf "M %%f\\n" 2>/dev/null | head -n %d; ' % (pick, MAX_LISTED)
            + "printf '%s\\n' " + _LIST_E)


def parse_listing(out):
    """The folder values list_sh printed, sorted, or None when its frame is missing."""
    body = out or ""
    i, j = body.find(_LIST_B), body.find(_LIST_E)
    if i == -1 or j < i:
        return None
    found = set()
    for line in body[i + len(_LIST_B):j].splitlines():
        kind, _, name = line.strip().partition(" ")
        if kind in ("T", "M") and valid_name(name):
            found.add(name if kind == "T" else "mods/" + name)
    return sorted(found, key=str.lower)


def _merged(texts):
    merged = {}
    for t in texts:
        merged.update(_smf._parse_cfg(t))
    return merged


def read_state(server, user, selfname):
    """{"folders", "mods", "servermods", "secrets", "workshop"} from ONE command, or None.

    `secrets`: the keys secrets-<selfname>.cfg sets (the card does not edit those); `workshop`:
    whether workshopmods is set, so the card can say LinuxGSM adds those after the folders.
    """
    if not _smc.game_idents_ok(user, selfname):
        return None
    sh = _smf.lgsm_cfg_texts_sh(user, selfname) + list_sh(user)
    out, _, _ = _smc.shell_as_game_user(server, user, sh, timeout=30, selfname=selfname)
    texts = _smf.lgsm_cfg_texts_from(out)
    folders = parse_listing(out)
    if texts is None or folders is None:
        return None
    merged, secrets = _merged(texts), _smf._parse_cfg(texts[4])
    state = {"folders": folders, "secrets": [k for k in KEYS if k in secrets],
             "workshop": bool((merged.get("workshopmods") or "").strip())}
    for k in KEYS:
        state[k] = split_value(merged.get(k, ""))
    return state


def _list_problem(values, allowed):
    """Why one posted list is refused, else None."""
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        return NOT_A_FOLDER
    if len(values) > MAX_LISTED:
        return TOO_MANY
    if len(set(values)) != len(values):
        return DUPLICATE
    if any(v not in allowed for v in values):
        return NOT_A_FOLDER
    return None


def check_lists(state, posted):
    """({key: [folders]} to save, None) or (None, why). Each folder must be listed, or already in that key."""
    lists = {}
    for k in KEYS:
        values = posted.get(k, state[k]) if isinstance(posted, dict) else None
        allowed = set(state["folders"]) | set(state[k])
        why = _list_problem(values, allowed)
        if why:
            return None, why
        lists[k] = values
    if set(lists["mods"]) & set(lists["servermods"]):
        return None, BOTH_LISTS
    return lists, None


def save(server, user, selfname, posted):
    """Write `mods` / `servermods` from `posted`. -> (ok, why, before, after).

    `before` / `after`: {key: [folders]}. Only a key that changes is written; nothing changing
    writes nothing (ok, why "", before == after).
    """
    with _smc.lgc_config_lock(server, user, selfname):
        state = read_state(server, user, selfname)
        if state is None:
            return False, UNREAD, {}, {}
        return _save_checked(server, user, selfname, state, posted)


def _save_checked(server, user, selfname, state, posted):
    """Run save()'s checks and write once the state is read: (ok, why, before, after)."""
    before = {k: state[k] for k in KEYS}
    lists, why = check_lists(state, posted)
    if why:
        return False, why, before, before
    changed = {k: join_value(lists[k]) for k in KEYS if lists[k] != before[k]}
    if any(k in state["secrets"] for k in changed):
        return False, IN_SECRETS, before, before
    if not changed:
        return True, "", before, before
    ok, msg = _smf.lgsm_write_config(server, user, selfname, changed)
    return ok, ("" if ok else msg), before, (lists if ok else before)
