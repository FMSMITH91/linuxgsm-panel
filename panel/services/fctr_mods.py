"""Factorio: the mods in the server's mods folder, and turning each on or off in mod-list.json.

WHERE (LinuxGSM master 98be8a98, 2026-11-13): lgsm/modules/update_fctr.sh extracts Factorio's
headless package into serverfiles, and fctrserver's _default.cfg starts the server with
`--bind ... --start-server-load-latest --server-settings ... --port ... --rcon-port ...`: no
--mod-directory, so Factorio uses its default, the mods folder of its write-data directory. The
package's config-path.cfg keeps that inside the package folder (Factorio wiki, "Application
directory": a zip/tar install keeps saves, mods and config in its own folder), so the folder is
serverfiles/mods. A start line that passes --mod-directory itself is shown and not edited.

WHAT (Factorio's mod structure, lua-api.factorio.com/latest/auxiliary/mod-structure.html): a mod is
a zip named `{name}_{version}.zip`, or a folder named `{name}_{version}` or `{name}`; a name is
letters, digits, `-` and `_` (the mod portal's rule), at most 100 characters. Which mods load is
mods/mod-list.json, `{"mods": [{"name": ..., "enabled": true|false}, ...]}`, which the game writes on
its first start and adds new mods to (enabled) when it finds them. base and the expansion's built-in
mods (elevated-rails, quality, space-age) ship in serverfiles/data, not in mods/.

THE CHANGE sets one entry's `enabled` in mod-list.json and keeps everything else in the file (other
keys, other entries, their order), written as the game account through the file editor's own write
(ssh_manager.write_file: inside the home, atomic, the file's mode kept). base is never turned off.
The read and the write run under the instance's config lock, so two changes cannot cross. The
server reads the file when it starts, and WRITES IT BACK when it stops (measured on the test host:
a change made while it ran was undone by the next stop, a restart included). So a change is refused
while the server runs: the same read looks for a process of the account running
serverfiles/bin/*/factorio. Stopped, changed, started: the change holds.

Downloading from the Factorio mod portal needs a player's username and token, so the panel does not:
a mod is uploaded through the file manager.
"""
import base64
import json
import re

from panel.ops.ssh_manager import _core as _smc, files as _smf

GAMES = frozenset({"fctr"})
MODS_DIR = "serverfiles/mods"
MOD_LIST = MODS_DIR + "/mod-list.json"
BASE = "base"
BUILTIN = ("base", "elevated-rails", "quality", "space-age")
_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,100}\Z")
_VERSIONED_RE = re.compile(r"(?P<name>[A-Za-z0-9_-]{1,100})_(?P<version>\d{1,5}\.\d{1,5}\.\d{1,5})\Z")
_ENTRY_RE = re.compile(r"[A-Za-z0-9._-]{1,120}\Z")
MAX_LISTED = 500
_LIST_MAX = 1024 * 1024
_B, _E, _LB, _LE = "__FCTRM_B__", "__FCTRM_E__", "__FCTRM_LIST_B__", "__FCTRM_LIST_E__"

UNREAD = "Couldn't read this server's mods folder — the host didn't answer. Nothing was changed."
NOT_A_MOD = "That isn't one of this server's mods. Refresh the list and pick again."
NO_LIST = ("mods/mod-list.json is not there yet: Factorio writes it the first time the server starts. "
           "Start the server once, then change mods here.")
BAD_LIST = "mods/mod-list.json isn't the list Factorio writes, so the panel won't change it."
BASE_ON = "The base game can't be turned off."
ELSEWHERE = ("This server's start line passes --mod-directory, so its mods are somewhere the panel does not "
             "look. Change them there — nothing has been changed.")
RUNNING = ("Stop the server first: Factorio writes its mod list back when it stops, which would undo this "
           "change. Stop it, change the mods, then start it — nothing has been changed.")
REASONS = (UNREAD, NOT_A_MOD, NO_LIST, BAD_LIST, BASE_ON, ELSEWHERE, RUNNING)


def supported(game_type):
    """Whether the game is Factorio."""
    return (game_type or "").lower() in GAMES


def valid_name(name):
    """Whether `name` is a mod name the card turns on or off."""
    return isinstance(name, str) and bool(_NAME_RE.match(name))


def list_sh(user):
    """Shell printing mods/mod-list.json (base64, framed; "N" when absent) and the folder's entries.

    serverfiles must resolve inside the home and its mods folder must not be a link; nothing is
    followed through a link.
    """
    home = _smc._quote("/home/%s" % user)
    return ("h=$(cd -P -- %s 2>/dev/null && pwd -P) || h=; " % home
            + "sf=$(cd -P -- %s/serverfiles 2>/dev/null && pwd -P) || sf=; " % home
            + 'case "$sf" in "$h"/?*) [ -n "$h" ] || sf= ;; *) sf= ;; esac; '
            + 'md=; [ -n "$sf" ] && [ -d "$sf/mods" ] && [ ! -L "$sf/mods" ] && md="$sf/mods"; '
            + "printf '%s\\n' " + _B + "; "
            + 'if [ -n "$md" ] && [ -f "$md/mod-list.json" ] && [ ! -L "$md/mod-list.json" ]; then '
            + "printf '%s' " + _LB + '; head -c %d "$md/mod-list.json" | base64 | tr -d "\\n"; ' % _LIST_MAX
            + "printf '%s\\n' " + _LE + "; else printf 'N\\n'; fi; "
            + '[ -n "$md" ] && find -P "$md" -mindepth 1 -maxdepth 1 \\( -type f -name "*.zip" -o -type d \\) '
            + "! -name '*[!A-Za-z0-9._-]*' -printf '%%y %%f\\n' 2>/dev/null | head -n %d; " % MAX_LISTED
            # The game running: a process of this account whose program is serverfiles/bin/*/factorio.
            + '[ -n "$sf" ] && for p in /proc/[0-9]*; do [ -O "$p" ] || continue; '
            + 'case "$(readlink "$p/exe" 2>/dev/null)" in "$sf"/bin/*/factorio) printf "R\\n"; break ;; esac; done; '
            + "printf '%s\\n' " + _E)


def _mod_of(kind, entry):
    """(name, the entry) for one listed zip or folder that is a mod, else None."""
    if not _ENTRY_RE.match(entry):
        return None
    stem = entry[:-4] if kind == "f" and entry.lower().endswith(".zip") else entry
    if kind == "f" and stem == entry:
        return None
    m = _VERSIONED_RE.match(stem)
    if m:
        return m.group("name"), entry
    return (stem, entry) if kind == "d" and _NAME_RE.match(stem) else None


def _decoded_list(body):
    """mod-list.json's text from its frame: "" when it was not there, None when unreadable."""
    i, j = body.find(_LB), body.find(_LE)
    if i == -1:
        return ""
    if j < i:
        return None
    try:
        return base64.b64decode(body[i + len(_LB):j].strip(), validate=True).decode("utf-8")
    except ValueError:
        return None


def parse_listing(out):
    """({name: [entries]}, mod-list text or "" when absent, whether the game runs) from list_sh's output, or None."""
    body = out or ""
    i, j = body.find(_B), body.find(_E)
    if i == -1 or j < i:
        return None
    body = body[i + len(_B):j]
    text = _decoded_list(body)
    if text is None:
        return None
    files = {}
    for line in body.splitlines():
        kind, _, entry = line.strip().partition(" ")
        mod = _mod_of(kind, entry) if kind in ("f", "d") else None
        if mod:
            files.setdefault(mod[0], []).append(mod[1])
    return files, text, any(line.strip() == "R" for line in body.splitlines())


def mod_list(text):
    """mod-list.json's parsed answer when it is Factorio's shape ({"mods": [{"name", ...}]}), else None."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    mods = data.get("mods") if isinstance(data, dict) else None
    if not isinstance(mods, list) or not all(isinstance(m, dict) and isinstance(m.get("name"), str) for m in mods):
        return None
    return data


def rows(files, data):
    """The card's rows: built-in mods first, then the rest by name; each {name, enabled, files, builtin, listed}."""
    listed = {}
    for m in (data or {}).get("mods", []):
        listed[m["name"]] = m.get("enabled") is not False
    names = set(files) | set(listed)
    order = [n for n in BUILTIN if n in names or n == BASE] + sorted((n for n in names if n not in BUILTIN),
                                                                    key=str.lower)
    return [{"name": n, "enabled": listed.get(n, True), "files": sorted(files.get(n, [])),
             "builtin": n in BUILTIN, "listed": n in listed} for n in order if valid_name(n)]


def _elsewhere(texts):
    """Whether the merged start line passes --mod-directory."""
    merged = {}
    for t in texts:
        merged.update(_smf._parse_cfg(t))
    return "--mod-directory" in "%s %s" % (merged.get("startparameters", ""), merged.get("extraparams", ""))


def _read(server, user, selfname):
    """(config texts, files, mod-list text, running) from ONE command as the account, or None."""
    if not _smc.game_idents_ok(user, selfname):
        return None
    sh = _smf.lgsm_cfg_texts_sh(user, selfname) + list_sh(user)
    out, _, _ = _smc.shell_as_game_user(server, user, sh, timeout=30, selfname=selfname)
    texts, listing = _smf.lgsm_cfg_texts_from(out), parse_listing(out)
    if texts is None or listing is None:
        return None
    return (texts,) + listing


def read(server, user, selfname):
    """The card's state, or None when the host did not answer.

    {"mods": rows, "mod_list": "ok" | "missing" | "bad", "where": "" | "mod-directory", "dir": MODS_DIR,
    "running": whether the game runs (changes are refused then)}.
    """
    got = _read(server, user, selfname)
    if got is None:
        return None
    texts, files, text, running = got
    data = mod_list(text) if text else None
    return {"mods": rows(files, data), "mod_list": "missing" if not text else ("ok" if data else "bad"),
            "where": "mod-directory" if _elsewhere(texts) else "", "dir": MODS_DIR, "running": running}


def with_enabled(data, name, enabled):
    """`data` (mod-list.json, parsed) with `name` turned on or off: every entry of that name, else one appended."""
    hit = False
    for m in data["mods"]:
        if m["name"] == name:
            m["enabled"], hit = bool(enabled), True
    if not hit:
        data["mods"].append({"name": name, "enabled": bool(enabled)})
    return data


def _refusal(texts, files, text, name, enabled):
    """Why turning `name` on or off is refused, or (None, parsed mod-list)."""
    if _elsewhere(texts):
        return ELSEWHERE, None
    if not text:
        return NO_LIST, None
    data = mod_list(text)
    if data is None:
        return BAD_LIST, None
    known = {r["name"] for r in rows(files, data)}
    if not valid_name(name) or name not in known:
        return NOT_A_MOD, None
    if name == BASE and not enabled:
        return BASE_ON, None
    return None, data


def set_enabled(server, user, selfname, name, enabled):
    """Turn mod `name` on or off in mod-list.json. -> (ok, why, changed, before).

    `before`: whether it was on ("" when the read did not answer or the mod is not listed).
    """
    with _smc.lgc_config_lock(server, user, selfname):
        got = _read(server, user, selfname)
        if got is None:
            return False, UNREAD, False, ""
        texts, files, text, running = got
        why, data = (RUNNING, None) if running else _refusal(texts, files, text, name, enabled)
        if why:
            return False, why, False, ""
        before = next((r["enabled"] for r in rows(files, data) if r["name"] == name), "")
        if any(m["name"] == name for m in data["mods"]) and before == bool(enabled):
            return True, "", False, before
        new = json.dumps(with_enabled(data, name, enabled), indent=2, ensure_ascii=False) + "\n"
        ok, msg = _smf.write_file(server, user, MOD_LIST, new, selfname=selfname)
        return ok, ("" if ok else msg), ok, before
