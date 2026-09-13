"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import re
import subprocess
from panel.core import terminal
from panel.security import privileged as _priv
import posixpath as _pp
from panel.ops.ssh_manager import (_core, cron)  # noqa: E402,F401  (module objects: the
# reference resolves at CALL time, which is what keeps a stub on the definition site
# visible to every caller — see the package docstring.



# ── LinuxGSM config + file management ──────────────────────────
# All operations run AS THE GAME USER (`sudo -u <user>`) and are confined to that
# user's home dir, so they can never touch the panel host or other accounts.

# Curated "common settings" surfaced as a form (only those present in the game's
# _default.cfg are shown). Everything else is editable via the raw config editor.
_COMMON_CFG_KEYS = [
    ("servername", "Server name"), ("hostname", "Hostname"),
    ("ip", "Bind IP"), ("port", "Game port"), ("queryport", "Query port"),
    ("clientport", "Client port"), ("rconport", "RCON port"),
    ("maxplayers", "Max players"), ("slots", "Slots"), ("maxclients", "Max clients"),
    ("defaultmap", "Default map"), ("map", "Map"), ("gamemode", "Game mode"),
    ("gametype", "Game type"), ("tickrate", "Tickrate"),
    ("serverpassword", "Server password"), ("rconpassword", "RCON password"),
    ("adminpassword", "Admin password"), ("steamuser", "Steam user"),
]
_CFG_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _parse_cfg(text):
    """Parse LinuxGSM-style `key="value"` lines (uncommented only) into a dict."""
    out = {}
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _CFG_LINE_RE.match(line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
                val = val[1:-1]
            out[key] = val
    return out


# Same charset models._validate_shell_ident enforces. Repeated here because that validator is a
# SQLAlchemy @validates hook: it fires on ASSIGNMENT, and never on rows loaded from the database.
# A row written before the validator existed, or restored from a tampered backup, reaches this
# code unchecked — and `user` is interpolated into `sudo -u {user}` and into /home/{user}.
_SAFE_UNIX_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")


def _safe_abspath(user, relpath):
    """Resolve a user-supplied relative path under /home/<user>, rejecting any
    traversal outside it. Returns the absolute path or None.

    Also rejects an unsafe `user`: every file operation funnels through here, so this is the one
    place that can refuse a malformed identifier before it reaches a shell command."""
    if not _SAFE_UNIX_USER_RE.match(str(user or "")):
        return None
    home = f"/home/{user}"
    rel = str(relpath) if relpath else ""   # tolerate non-str input without crashing
    ap = _pp.normpath(_pp.join(home, rel.lstrip("/")))
    if ap == home or ap.startswith(home + "/"):
        return ap
    return None


# Sentinel a guarded command prints when the path escaped the home dir on the HOST.
_OUTSIDE_HOME = "__OUTSIDE_HOME__"


def _guarded(user, abspath, inner):
    """Prefix `inner` with a check that `abspath` still resolves inside /home/<user> ON THE HOST.

    _safe_abspath is lexical. normpath collapses '..' correctly, but it cannot see symlinks,
    because the path lives on the remote machine and Python is not there. A symlink planted under
    the game user's home — by a malicious mod, by the game itself, or by anyone with shell as that
    user — therefore passes the Python check and resolves somewhere else entirely by the time the
    command runs. The only place that can be settled is where the path actually exists.

    Folded into the existing command rather than run as its own probe: the file browser issues one
    of these per navigation, and a second SSH round trip per keystroke-ish action is a real cost.

    `realpath -m` resolves a path whose last component does not exist yet, which uploads to a new
    filename need. If realpath is absent the check falls back to the unresolved path and the guard
    degrades to the lexical answer — no worse than before this existed, and never a hard failure on
    a minimal image.
    """
    home = f"/home/{user}"
    hq = _core._quote(home)
    return (f"p=$(realpath -m {_core._quote(abspath)} 2>/dev/null || printf %s {_core._quote(abspath)}); "
            f'case "$p" in {hq}|{hq}/*) : ;; *) echo {_OUTSIDE_HOME}; exit 9 ;; esac; ' + inner)


# Biggest base64 payload we will put in a single command. The whole `bash -c '<script>'` is ONE
# argv entry, and Linux caps a single argument at MAX_ARG_STRLEN (131072 bytes) — so this stays
# comfortably below that with room for the surrounding script. 80k of base64 is ~60 KB of file,
# which covers essentially every config, script and Lua file a game server holds.
_ONE_SHOT_B64 = 80000
_CHUNK_B64 = 50000


def _write_file_as_user(server, user, abspath, data_bytes):
    """Write bytes to a file as the game user, via base64.

    Round trips are the whole cost here. Every run_command is a separate SSH exec, and this used to
    make at least THREE per file — mkdir, one per base64 chunk, then the decode — which is what made
    uploading a folder of several hundred small Lua files take minutes: the work is nothing, the
    latency is everything. A file small enough to fit one command now takes ONE, and that is almost
    every file anyone uploads. Large files still stream in chunks, with the mkdir folded into the
    first one.

    Both paths write to a temp file and `mv` it into place. The previous form decoded straight over
    the destination, so a failure part-way left the real file truncated; a rename within the same
    directory is atomic, so the destination is either the old file or the whole new one.
    """
    import base64 as _b64
    b64 = _b64.b64encode(data_bytes).decode()
    tmp = abspath + ".paneltmp"
    parent = _pp.dirname(abspath)
    mk = "mkdir -p " + _core._quote(parent)
    # The guard rides whichever command goes first, so a target that resolves outside the home dir
    # is refused before any byte is written.
    if len(b64) <= _ONE_SHOT_B64:
        inner = (f"{mk} && printf %s {_core._quote(b64)} | base64 -d > {_core._quote(tmp)} "
                 f"&& mv -f {_core._quote(tmp)} {_core._quote(abspath)}")
        out, e, rc = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(_guarded(user, abspath, inner))}",
                                 timeout=60, sudo=False)
        if _OUTSIDE_HOME in (out or ""):
            return False, "Invalid path"
        return (rc == 0), (e or out or "")

    op = ">"
    first = True
    for i in range(0, max(len(b64), 1), _CHUNK_B64):
        chunk = b64[i:i + _CHUNK_B64]
        inner = f"printf %s {_core._quote(chunk)} {op} {_core._quote(tmp)}"
        if first:
            inner = f"{mk} && {inner}"
            inner = _guarded(user, abspath, inner)
        out, e, rc = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(inner)}", timeout=60, sudo=False)
        if first and _OUTSIDE_HOME in (out or ""):
            return False, "Invalid path"
        if rc != 0:
            return False, e or "write failed"
        op = ">>"
        first = False
    fin = f"base64 -d {_core._quote(tmp)} > {_core._quote(abspath)}.new && mv -f {_core._quote(abspath)}.new {_core._quote(abspath)} && rm -f {_core._quote(tmp)}"
    o, e, rc = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(fin)}", timeout=60, sudo=False)
    return (rc == 0), (e or o or "")


def _lgsm_cfg_dir(user, selfname):
    return f"/home/{user}/lgsm/config-lgsm/{selfname}"


def lgsm_read_config(server, user, selfname):
    """Read a game's LinuxGSM config: the curated common settings (merged from
    _default.cfg < common.cfg < instance <selfname>.cfg) plus the raw instance cfg
    text for the advanced editor."""
    d = _lgsm_cfg_dir(user, selfname)
    inst = f"{d}/{selfname}.cfg"
    inner = (f"echo ===DEFAULT; cat {_core._quote(d + '/_default.cfg')} 2>/dev/null; "
             f"echo ===COMMON; cat {_core._quote(d + '/common.cfg')} 2>/dev/null; "
             f"echo ===INSTANCE; cat {_core._quote(inst)} 2>/dev/null")
    out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(inner)}", timeout=20, sudo=False)
    sec = {"DEFAULT": [], "COMMON": [], "INSTANCE": []}
    cur = None
    for line in (out or "").splitlines():
        if line in ("===DEFAULT", "===COMMON", "===INSTANCE"):
            cur = line[3:]
            continue
        if cur is not None:
            sec[cur].append(line)
    defaults = _parse_cfg("\n".join(sec["DEFAULT"]))
    common = _parse_cfg("\n".join(sec["COMMON"]))
    instance_text = "\n".join(sec["INSTANCE"])
    instance = _parse_cfg(instance_text)
    merged = dict(defaults); merged.update(common); merged.update(instance)
    # Curated "common" quick list.
    settings = []
    for key, label in _COMMON_CFG_KEYS:
        if key in merged:
            settings.append({
                "key": key, "label": label, "value": merged[key],
                "default": defaults.get(key, ""),
                "overridden": key in instance or key in common,
            })
    # EVERY setting, grouped by _default.cfg's "#### Section ####" headers, so any
    # LinuxGSM setting is editable (not just the curated ones).
    groups = []
    cur = None
    for line in sec["DEFAULT"]:
        h = re.match(r"^#{3,}\s+(.+?)\s+#{3,}\s*$", line.strip())
        if h:
            cur = {"section": h.group(1), "settings": []}
            groups.append(cur)
            continue
        if line.strip().startswith("#"):
            continue
        m = _CFG_LINE_RE.match(line)
        if m:
            key = m.group(1)
            if cur is None:
                cur = {"section": "Server Settings", "settings": []}
                groups.append(cur)
            cur["settings"].append({
                "key": key, "value": merged.get(key, ""),
                "default": defaults.get(key, ""),
                "overridden": key in instance or key in common,
            })
    groups = [g for g in groups if g["settings"]]
    return {"path": inst, "raw": instance_text, "settings": settings, "groups": groups}


def lgsm_game_config(server, user, selfname):
    """Locate and read the game's OWN server config file (e.g. a Source server.cfg
    or cod's serverfiles/main/<name>.cfg) by parsing LinuxGSM `details`. This is the
    file where in-game settings like sv_maxclients actually live for many games.
    Returns {rel, content, exists, error}."""
    o, _, _ = _core.run_command(
        server, f"sudo -u {user} bash -c {_core._quote(f'cd /home/{user} && ./{selfname} details 2>&1')}",
        timeout=45, sudo=False,
    )
    text = terminal.strip_escapes(o or "")
    home = f"/home/{user}/"
    path = None
    for line in text.splitlines():
        m = re.search(r"config file[^:]*:\s*(/\S+\.cfg)", line, re.I)
        if m:
            path = m.group(1)
            break
    if not path or not path.startswith(home):
        return {"rel": None, "content": "", "exists": False,
                "error": "No editable game config file was reported for this game."}
    rel = path[len(home):]
    content, err = read_file(server, user, rel)
    return {"rel": rel, "content": content or "", "exists": err is None, "error": err}


def lgsm_get_values(server, user, selfname, keys):
    """Return {key: value} for `keys` from the merged LinuxGSM config (_default < common <
    instance — instance wins). Missing keys come back as "". Used by focused editors (alerts)."""
    d = _lgsm_cfg_dir(user, selfname)
    inner = (f"cat {_core._quote(d + '/_default.cfg')} 2>/dev/null; "
             f"cat {_core._quote(d + '/common.cfg')} 2>/dev/null; "
             f"cat {_core._quote(d + '/' + selfname + '.cfg')} 2>/dev/null")
    out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(inner)}", timeout=20, sudo=False)
    merged = _parse_cfg(out or "")
    return {k: merged.get(k, "") for k in keys}


def lgsm_write_config(server, user, selfname, updates):
    """Apply key→value updates to the instance <selfname>.cfg (replace an existing
    uncommented line, else append). Other files (_default/common) are left alone."""
    d = _lgsm_cfg_dir(user, selfname)
    inst = f"{d}/{selfname}.cfg"
    out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote('cat ' + _core._quote(inst) + ' 2>/dev/null')}", timeout=15, sudo=False)
    lines = (out or "").splitlines()
    for key, val in (updates or {}).items():
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key or ""):
            continue
        val = str(val).replace('"', '\\"').replace("\n", " ")
        newline = f'{key}="{val}"'
        pat = re.compile(r"^\s*" + re.escape(key) + r"\s*=")
        replaced = False
        for i, ln in enumerate(lines):
            if pat.match(ln) and not ln.strip().startswith("#"):
                lines[i] = newline
                replaced = True
                break
        if not replaced:
            lines.append(newline)
    content = "\n".join(lines).rstrip("\n") + "\n"
    return _write_file_as_user(server, user, inst, content.encode())


# --- Mods / addons (LinuxGSM mods-install / mods-remove) --------------------
# LinuxGSM's mods-install/mods-remove print a list of mods and `read` one selection — the mod's
# text id (e.g. "sourcemod"), NOT a number. Typing "abort"/"exit" makes the command print the
# list then exit cleanly, so we list by feeding "abort" and act by feeding the chosen id — via a
# bash here-string. The two lists use DIFFERENT formats (verified on a live Garry's Mod server):
#   mods-install (available): a description line, then a " * <id>" line under it.
#   mods-remove  (installed):  one line per mod, "<id> - <name> - <desc>".
_MOD_AVAIL_RE = re.compile(r"^\s*\*\s+(\S+)\s*$")               # available: " * <id>"
_MOD_INST_RE = re.compile(r"^([A-Za-z0-9._-]+)\s+-\s+(.+)$")    # installed: "<id> - <name> - …"
_MOD_ID_OK = re.compile(r"^[A-Za-z0-9._-]+$")                   # safe id charset (guards here-string)


def _strip_ansi(s):
    return terminal.strip_escapes(s or "")


def _parse_mods_available(out):
    """Parse the mods-install list: id is on a ' * <id>' line, name from the description line above.

    LinuxGSM prints TWO sections: an 'Installed addons/mods' block of bare ' * <id>' lines (already
    installed, NO description above them) and then 'Available addons/mods' where each ' * <id>' is
    preceded by a 'Name - desc - url' line. Only the Available block carries real, named entries — the
    Installed block's ids would otherwise be emitted named after the section header ('Installed
    addons/mods') AND duplicate the real Available rows, so we skip that section and de-dupe by id."""
    mods = []
    prev = ""
    in_installed = False
    seen = set()
    for raw in (out or "").splitlines():
        line = _strip_ansi(raw).rstrip()
        low = line.strip().lower()
        if low == "installed addons/mods":   # enter the skip section (its ' * <id>' lines have no name)
            in_installed, prev = True, ""
            continue
        if low == "available addons/mods":    # back to the real, described list
            in_installed, prev = False, ""
            continue
        m = _MOD_AVAIL_RE.match(line)
        if m and _MOD_ID_OK.match(m.group(1)):
            mod_id = m.group(1)
            if not in_installed and mod_id not in seen:
                seen.add(mod_id)
                name = prev.split(" - ")[0].strip() if prev else mod_id
                mods.append({"id": mod_id, "name": name or mod_id, "desc": prev})
        else:
            t = line.strip()
            if t and set(t) != {"="}:   # remember the latest real description line, skip === rules
                prev = t
    return mods


def _game_supports_mods(text):
    """False for games with no LinuxGSM mods installer (e.g. cod): running mods-install/-remove
    on them prints 'Error! Unknown command' followed by a usage banner ('LinuxGSM - <Game> -
    Version v…') that would otherwise be misparsed as an installed mod."""
    return "unknown command" not in (text or "").lower()


def _parse_mods_installed(out):
    """Parse the mods-remove list: one '<id> - <name> - <desc>' line per installed mod."""
    mods = []
    for raw in (out or "").splitlines():
        m = _MOD_INST_RE.match(_strip_ansi(raw).strip())
        if m and m.group(1) != "LinuxGSM":   # skip the 'LinuxGSM - <Game> - Version …' banner line
            name = m.group(2).split(" - ")[0].strip()
            mods.append({"id": m.group(1), "name": name or m.group(1), "desc": m.group(2)})
    return mods


def mods_available(server, user, selfname, timeout=60):
    """Returns (available_mods, supported). `supported` is False for games with no LinuxGSM mods
    installer (e.g. cod), where mods-install answers 'Unknown command' — so the UI can hide the
    whole card rather than show an empty one."""
    out, err, _ = _core.run_as_game_user(server, user, 'mods-install <<< "abort"', timeout=timeout, selfname=selfname)
    text = (out or "") + "\n" + (err or "")
    supported = _game_supports_mods(text)
    return (_parse_mods_available(text) if supported else []), supported


def mods_installed(server, user, selfname, timeout=60):
    """Returns (installed_mods, supported). See mods_available for `supported`."""
    out, err, _ = _core.run_as_game_user(server, user, 'mods-remove <<< "abort"', timeout=timeout, selfname=selfname)
    text = (out or "") + "\n" + (err or "")
    supported = _game_supports_mods(text)
    return (_parse_mods_installed(text) if supported else []), supported


def mods_action(server, user, selfname, which, mod_id, timeout=600):
    """Install or remove a mod by its LinuxGSM id (e.g. "sourcemod"). `which` is 'install' or
    'remove'. Returns (out, err, rc). We feed the id then a "Y": mods-remove always asks
    "Continue?" before deleting files, and mods-install asks it too when the mod is already
    installed (both default to Y). The id is validated to a safe charset first, so nothing but a
    bare id + Y is ever fed to the command. Verified install+remove on a live Garry's Mod box."""
    if not _MOD_ID_OK.match(mod_id or ""):
        return "", "invalid mod id", 1
    cmd = "mods-install" if which == "install" else "mods-remove"
    out, err, rc = _core.run_as_game_user(server, user, f"{cmd} <<< $'{mod_id}\\nY'", timeout=timeout, selfname=selfname)
    return out, err, rc


# Files/dirs whose deletion would break LinuxGSM or the game install — protected
# from the file browser's delete (they can still be edited where that makes sense).
def _is_protected_path(relpath, selfname):
    """True if `relpath` (relative to the game user's home) must not be deleted."""
    # Normalise BEFORE inspecting. delete_path deletes the resolved absolute path, so a guard that
    # reads the raw string is judging a different path than the one `rm -rf` receives: "./lgsm" and
    # "x/../serverfiles" look like ordinary sub-paths here while resolving onto the LinuxGSM control
    # tree and the whole game install. Anything that climbs out collapses to "" and is refused.
    r = _pp.normpath("/" + str(relpath or "")).strip("/")
    if not r or r == ".":
        return True  # the home dir itself
    parts = r.split("/")
    top = parts[0]
    # The whole LinuxGSM control tree (script data, module cache, configs).
    if top == "lgsm":
        return True
    # Critical top-level entries (deleting these bricks the server or your login).
    if len(parts) == 1 and r in {
        "serverfiles", "linuxgsm.sh", selfname or "",
        ".ssh", ".bashrc", ".profile", ".bash_logout", ".bash_history", ".wget-hsts",
    }:
        return True
    return False


def browse_dir(server, user, relpath="", selfname=None):
    """List a directory in the game user's home (dirs first). Each entry is flagged
    `protected` when deleting it would break LinuxGSM/the game. Returns None on a
    path-traversal attempt."""
    ap = _safe_abspath(user, relpath)
    if ap is None:
        return None
    inner = f"find {_core._quote(ap)} -maxdepth 1 -mindepth 1 -printf '%y\\t%s\\t%f\\n' 2>/dev/null"
    out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(_guarded(user, ap, inner))}",
                            timeout=20, sudo=False)
    if _OUTSIDE_HOME in (out or ""):
        return None
    base = (relpath or "").strip("/")
    entries = []
    for line in (out or "").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            typ, size = parts[0], parts[1]
            name = "\t".join(parts[2:])
            rel = f"{base}/{name}" if base else name
            entries.append({"name": name, "is_dir": typ == "d",
                            "size": int(size) if size.isdecimal() else 0,
                            "protected": _is_protected_path(rel, selfname)})
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    return {"path": base, "entries": entries}


def read_file(server, user, relpath, max_bytes=1048576):
    """Read a text file from the game user's home. Returns (content, error).
    Refuses binaries and files larger than max_bytes."""
    ap = _safe_abspath(user, relpath)
    if ap is None:
        return None, "Invalid path"
    inner = (
        f"if [ ! -f {_core._quote(ap)} ]; then echo __NOFILE__; exit 0; fi; "
        f"sz=$(stat -c %s {_core._quote(ap)} 2>/dev/null); "
        f"if [ \"$sz\" -gt {int(max_bytes)} ]; then echo __TOOBIG__; exit 0; fi; "
        f"if [ ! -s {_core._quote(ap)} ] || grep -qI . {_core._quote(ap)} 2>/dev/null; then cat {_core._quote(ap)}; else echo __BINARY__; fi"
    )
    out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(_guarded(user, ap, inner))}",
                            timeout=20, sudo=False)
    if _OUTSIDE_HOME in (out or ""):
        return None, "Invalid path"
    stripped = (out or "").strip()
    if stripped == "__NOFILE__":
        return None, "File not found"
    if stripped == "__TOOBIG__":
        return None, "File is too large to edit in the browser"
    if stripped == "__BINARY__":
        return None, "Binary file — download/replace via upload instead"
    return (out or ""), None


def write_file(server, user, relpath, content):
    """Write text content to a file in the game user's home."""
    ap = _safe_abspath(user, relpath)
    if ap is None:
        return False, "Invalid path"
    return _write_file_as_user(server, user, ap, (content or "").encode())


# upload_file returns this as its message when the target exists and overwrite wasn't granted.
# A sentinel rather than prose so the route can answer with a machine-readable conflict instead of
# the UI having to pattern-match an error string.
UPLOAD_EXISTS = "__EXISTS__"


def stat_upload_targets(server, user, reldir, names):
    """For each requested filename, the existing entry's size + mtime — omitted if the name is free.

    Lists the directory ONCE and filters locally rather than stat-ing each name: the names come
    straight from a browser file picker, so this keeps them out of the remote shell command
    entirely. Returns None on a path-traversal attempt, matching browse_dir.
    """
    apdir = _safe_abspath(user, reldir)
    if apdir is None:
        return None
    inner = (f"find {_core._quote(apdir)} -maxdepth 1 -mindepth 1 "
             f"-printf '%y\\t%s\\t%T@\\t%f\\n' 2>/dev/null")
    out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(_guarded(user, apdir, inner))}",
                            timeout=20, sudo=False)
    if _OUTSIDE_HOME in (out or ""):
        return None
    present = {}
    for line in (out or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        typ, size, mtime = parts[0], parts[1], parts[2]
        # Name last and re-joined: a filename may legitimately contain a tab.
        nm = "\t".join(parts[3:])
        try:
            mt = int(float(mtime))
        except (TypeError, ValueError):
            mt = 0
        present[nm] = {"is_dir": typ == "d",
                       "size": int(size) if size.isdecimal() else 0, "mtime": mt}
    hits = []
    seen = set()
    for n in (names or []):
        # Same normalisation upload_file applies, so the check and the write agree on the name.
        base = _pp.basename(str(n or "").replace("\x00", ""))
        if base and base not in seen and base in present:
            seen.add(base)
            hits.append(dict(present[base], name=base))
    return hits


def upload_file(server, user, reldir, filename, data_bytes, overwrite=True):
    """Upload a file into a directory in the game user's home.

    overwrite=False refuses when the target already exists, returning UPLOAD_EXISTS. The UI asks
    first, but the check and the write are two round trips — without a server-side refusal a file
    created in between is silently clobbered, and a caller that never checks never asks at all.
    """
    apdir = _safe_abspath(user, reldir)
    if apdir is None:
        return False, "Invalid path"
    fn = _pp.basename((filename or "").replace("\x00", ""))
    if not fn or fn in (".", ".."):
        return False, "Invalid filename"
    target = _pp.join(apdir, fn)
    if not (target.startswith(f"/home/{user}/")):
        return False, "Invalid path"
    if not overwrite:
        chk = f"test -e {_core._quote(target)} && echo __YES__ || true"
        out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(_guarded(user, target, chk))}",
                                timeout=15, sudo=False)
        if _OUTSIDE_HOME in (out or ""):
            return False, "Invalid path"
        if "__YES__" in (out or ""):
            return False, UPLOAD_EXISTS
    return _write_file_as_user(server, user, target, data_bytes)


def delete_path(server, user, relpath, selfname=None):
    """Delete a file or directory (recursively) in the game user's home. Refuses
    the home root, anything outside it, and protected LinuxGSM/game paths."""
    ap = _safe_abspath(user, relpath)
    home = f"/home/{user}"
    if ap is None or ap == home or not (relpath or "").strip("/"):
        return False, "Refusing to delete this path"
    if _is_protected_path(relpath, selfname):
        return False, "This file/folder is protected — deleting it would break the server."
    inner = f"rm -rf -- {_core._quote(ap)} && echo __OK__"
    # The most destructive of the six, so it gets the same host-side resolution check: a symlink
    # under the home dir must not turn `rm -rf` loose on whatever it points at.
    out, e, rc = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(_guarded(user, ap, inner))}",
                             timeout=30, sudo=False)
    if _OUTSIDE_HOME in (out or ""):
        return False, "Refusing to delete this path"
    if rc == 0 and "__OK__" in (out or ""):
        return True, "Deleted"
    return False, e or out or "Delete failed"


# ── Downloads: the read side of the file browser ───────────────────────────────────────────────
# read_file() serves the EDITOR — text only, 1 MB cap, whole body in memory — and deliberately
# refuses a binary. A download is the opposite shape: any file the game user can read, at any size,
# so the bytes are streamed rather than buffered, exactly as a backup download already is.

def stat_path(server, user, relpath):
    """Type and size of one entry under the game user's home, for a download.

    Returns {"type": "f"|"d", "size": int, "name": str, "rel": str}, or None when the path escapes
    the home directory, does not exist, or is neither a regular file nor a directory. The route
    needs all four: the type picks file-vs-archive, the size becomes a Content-Length so the
    browser can show real progress instead of a spinner, the name is what the file is saved as,
    and `rel` is the CANONICAL relative path — "." for the home directory itself, which is the
    one thing the route has to recognise and turn down with an explanation.
    """
    ap = _safe_abspath(user, relpath)
    if ap is None:
        return None
    # `[ -d ]` / `[ -f ]` rather than `stat -c %F`: both dereference symlinks (which the guard has
    # already confirmed stay inside the home dir), and neither depends on coreutils' locale — %F
    # prints a TRANSLATED string, so parsing it would work on an English host and fail elsewhere.
    inner = (f"if [ -d {_core._quote(ap)} ]; then echo d 0; "
             f"elif [ -f {_core._quote(ap)} ]; then echo f $(stat -Lc %s {_core._quote(ap)} 2>/dev/null); "
             f"else echo __NOFILE__; fi")
    out, _, _ = _core.run_command(server, f"sudo -u {user} bash -c {_core._quote(_guarded(user, ap, inner))}",
                            timeout=20, sudo=False)
    if _OUTSIDE_HOME in (out or ""):
        return None
    parts = (out or "").strip().split()
    if not parts or parts[0] not in ("d", "f"):
        return None
    size = int(parts[1]) if len(parts) > 1 and parts[1].isdecimal() else 0
    return {"type": parts[0], "size": size, "name": _pp.basename(ap),
            "rel": _pp.relpath(ap, f"/home/{user}")}


def _remote_read_command(user, as_tar):
    """The remote command that reads a download over SSH. It takes the PATH ON STDIN.

    Everywhere else in this module a path is shell-quoted into the command. That is correct, but a
    download over SSH parses the string TWICE — once when the local `ssh` argv is assembled, again
    by the remote shell — and two-level quoting is exactly where this kind of bug hides. So no part
    of what the caller chose appears in the command at all: the text below is fixed, the relative
    path arrives on stdin as data, and the shell only ever handles it as a variable.

    `user` is still interpolated. It is a game-server account name from the panel's own database,
    not request input, and `_safe_abspath` has already refused anything that is not a plain Unix
    user name — and the home directory is BUILT from it here rather than taken from `$HOME`, which
    sudo may or may not reset.

    The containment check is the same one `_guarded` makes, against the resolved path: a relative
    path cannot climb out with `..` (the panel sends a canonical one), but a symlink under the home
    directory can still point anywhere, and only the host can resolve that.
    """
    home = "/home/%s" % user
    hq = _core._quote(home)
    # `rel=$(cat)` rather than `read -r`: command substitution strips only TRAILING newlines, so a
    # filename containing one survives. -- everywhere, so a name can never be read as an option.
    body = (f"rel=$(cat); home={hq}; "
            'p=$(realpath -m "$home/$rel" 2>/dev/null || printf %s "$home/$rel"); '
            f'case "$p" in {hq}|{hq}/*) : ;; *) echo {_OUTSIDE_HOME}; exit 9 ;; esac; ')
    body += ('tar czf - -C "$(dirname "$p")" -- "$(basename "$p")"' if as_tar
             else 'cat -- "$p"')
    return f"sudo -u {user} bash -c {_core._quote(body)}"


def stream_path(server, user, relpath, as_tar=False, limit=None, chunk=262144):
    """Yield the bytes of a file under the game user's home — or of a .tar.gz of a directory.

    Works for local, paramiko and Tailscale-CLI remotes, and reads AS THE GAME USER on every one
    of them: a symlink planted under that home can then only reach what that user could already
    read. Uses the (green, eventlet-patched) subprocess/paramiko IO so a multi-gigabyte download
    does not block the event hub.

    The caller stat_path's the path first — that is what decides `as_tar` and supplies the
    Content-Length — and stat_path is where the host-side symlink guard runs for this download.
    Every transport then re-checks containment in its own way: the SSH forms carry `_guarded`, and
    the helper redoes it after dropping credentials, which is the only place the answer accounts
    for a symlink. A shell stream that comes back carrying the guard's sentinel yields nothing at
    all, rather than handing the browser a small file whose contents are an error message.

    `limit` caps the bytes yielded, and the route passes the size stat_path measured. A game server
    writes to its console log CONSTANTLY, so "stat, then read" is a real race here rather than a
    theoretical one: without the cap a growing file yields more than the declared Content-Length,
    and a response longer than its own header desynchronises a keep-alive connection. Capped, the
    download is a snapshot of the file as it was measured. A file that SHRANK (log rotation) still
    ends short — the browser reports an incomplete download, which is the honest answer.
    """
    ap = _safe_abspath(user, relpath)
    if ap is None:
        return
    # The CANONICAL relative path, recomputed from the resolved absolute one. Two reasons it is not
    # the caller's string: "cfg/../server.cfg" is a legitimate request that _safe_abspath collapses
    # to "cfg/server.cfg", and the helper's validator refuses a ".." component outright — so
    # forwarding the raw string would turn a valid download into a VerbError mid-stream. And ".."
    # aside, it keeps what crosses the boundary in one shape.
    rel = _pp.relpath(ap, f"/home/{user}")
    if rel in (".", "", "/"):
        return   # the home directory itself: archiving a whole game install is not a download
    shell = _remote_read_command(user, as_tar)

    def _raw():
        if _core.is_local_server(server) or getattr(server, "auth_method", "") == "tailscale":
            if _core.is_local_server(server):
                # The helper opens the file only after dropping supplementary groups, gid and uid
                # to the game user, and redoes the containment check there — the same reasoning as
                # game-backup-read. The fallback for a host that has no helper yet keeps the one
                # property that matters, reading AS THE GAME USER, and stays an argv: no shell is
                # involved on either branch, so the caller's path is never text anything parses.
                if _core.helper_present():
                    try:
                        argv = _priv.helper_argv("game-dir-tar" if as_tar else "game-file-read",
                                                 [user, rel])
                    except _priv.VerbError:
                        # Unreachable while `rel` is canonical and non-root, which the lines above
                        # guarantee — but this is a GENERATOR, and an exception raised in one comes
                        # out of the middle of a streaming response, where Flask can no longer turn
                        # it into an error page. The browser would get a truncated file and a 200.
                        # A refusal has to end the stream, not corrupt it.
                        _core._log.debug("download: the helper refused the path", exc_info=True)
                        return
                elif as_tar:
                    argv = cron._as_user_argv(user, "tar", "czf", "-",
                                         "-C", _pp.dirname(ap), "--", _pp.basename(ap))
                else:
                    argv = cron._as_user_argv(user, "cat", "--", ap)
            else:
                host = _core._resolve_ts_host(server)
                argv = ["ssh", "-T", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
                        "-p", str(server.port or 22), f"{server.username}@{host}", shell]
            # stdin is a pipe only for the SSH form, which expects the path there. The local forms
            # take it in argv (helper) or already resolved (the pre-helper fallback), and inherit
            # stdin as before.
            feed = rel.encode() if argv[0] == "ssh" else None
            p = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                 stdin=subprocess.PIPE if feed is not None else None)
            if feed is not None:
                try:
                    p.stdin.write(feed)
                    p.stdin.close()
                except OSError:
                    # ssh died before it could take the path — a dead host, a refused key. The
                    # read below then sees EOF and the download ends empty, which is what every
                    # other unreachable-host path in this module does.
                    _core._log.debug("download: could not hand the path to ssh", exc_info=True)
            try:
                while True:
                    b = p.stdout.read(chunk)
                    if not b:
                        break
                    yield b
            finally:
                try:
                    p.stdout.close()
                except Exception:  # nosec B110
                    pass
                p.wait()
            return
        # paramiko remote — same fixed command, same path-on-stdin.
        client = _core.get_connection(server)
        _in, out, _err = client.exec_command(shell)
        try:
            _in.write(rel)
            _in.flush()
            _in.channel.shutdown_write()   # the remote `cat` needs EOF before it will return
        except Exception:
            _core._log.debug("download: could not hand the path to the remote shell", exc_info=True)
        while True:
            b = out.read(chunk)
            if not b:
                break
            yield b

    first, sent = True, 0
    for block in _raw():
        if first:
            first = False
            # The guard prints its sentinel and exits 9. On the shell paths that text IS the body,
            # so without this the browser would save a small file containing __OUTSIDE_HOME__ and
            # call it a download. Nothing was read either way — this only stops the pretence.
            if block.startswith(_OUTSIDE_HOME.encode()):
                return
        if limit is not None:
            if sent >= limit:
                return
            block = block[:limit - sent]
            sent += len(block)
        yield block
