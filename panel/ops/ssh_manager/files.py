"""LinuxGSM config read/write, the file browser and downloads.

Part of the SSH connection manager for remote LinuxGSM servers, which also supports local
execution for running on the panel's own machine (see the package docstring for how names
resolve across its submodules).
"""
import re
import subprocess  # nosec B404 - every call site below passes an argv LIST, never a shell string
from panel.core import terminal
from panel.security import privileged as _priv
import posixpath as _pp
import unicodedata as _ud
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
# The value is `(?:\S.*)?` rather than `.*`: after `\s*`, a `.*` that may also start on a blank
# let the two split a run of blanks every possible way before failing, which is quadratic in the
# run. Starting on a non-blank leaves one way, and the groups are the ones `\s*(.*)$` gave.
_CFG_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*((?:\S.*)?)$")

# LinuxGSM settings the "every setting" form must not offer. With `logtimestamp="on"` LinuxGSM
# pipes the console through gawk, which block-buffers, and the panel's live console freezes (see
# routes/server_files.py's log-timestamps route, which only ever turns it OFF). _default.cfg
# carries both keys, so the grouped form rendered them as text inputs and a save posted "on"
# straight past that route's refusal. The format means nothing without the switch.
_CFGFORM_HIDDEN_KEYS = frozenset({"logtimestamp", "logtimestampformat"})


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
                dq, val = val[0] == '"', val[1:-1]
                if dq:
                    # What bash makes of a double-quoted value: `\` before one of \ " ` $ is
                    # removed, before anything else it stays. The inverse of _cfg_dq_escape, so a
                    # value the form saved reads back as typed (it used to come back with its
                    # escaping, and saving it again escaped the escapes).
                    val = re.sub(r'\\([\\"`$])', r"\1", val)
            out[key] = val
    return out


# The account check is _core.game_idents_ok — the same one the command builder applies — and not
# a copy of its pattern here. models._validate_shell_ident is a SQLAlchemy @validates hook: it
# fires on ASSIGNMENT, and never on rows loaded from the database, so a row written before the
# validator existed, or restored from a tampered backup, reaches this code unchecked — and `user`
# is interpolated into `sudo -u {user}` and into /home/{user}. This module kept its own copy of
# the pattern until the builders moved behind one check (GHSA-hh39-76g3-wxcx); two copies of a
# security rule is how one of them stops being the rule.


def _safe_abspath(user, relpath):
    """Resolve a user-supplied relative path under /home/<user>, rejecting any traversal outside it.

    Returns the absolute path or None.

    Also rejects an unsafe `user`: every file operation funnels through here, so this is the one
    place that can refuse a malformed identifier before it reaches a shell command. The SAME test
    the command builder applies (_core.game_idents_ok), so a name this lets through is never one
    the builder then raises on in the middle of a download.
    """
    if not _core.game_idents_ok(user):
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


def _keep_mode(dest, staged):
    """Shell fragment copying `dest`'s permission bits onto `staged`.

    For a write that renames `staged` over `dest`. True when `dest` does not exist yet. When it
    exists and the chmod fails, the fragment removes `staged` and fails, so the save is refused
    rather than landing with a silently changed mode.
    """
    d, s = _core._quote(dest), _core._quote(staged)
    return f"{{ [ ! -e {d} ] || chmod --reference={d} {s} || {{ rm -f {s}; false; }}; }}"


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

    A rename also replaces the destination's INODE, and the temp file was created under the game
    user's umask — so without _keep_mode every save reset the file to 0644. Editing LinuxGSM's own
    0755 launch script stripped its exec bit (start and the monitor cron then fail with "permission
    denied", silently, long after the save said "Saved"), and a hand-placed 0600 file became
    world-readable. The destination's mode is copied onto the temp file before the rename; a new
    file keeps the umask default, which is what `>` gave it before.
    """
    import base64 as _b64
    b64 = _b64.b64encode(data_bytes).decode()
    tmp = abspath + ".paneltmp"
    parent = _pp.dirname(abspath)
    mk = "mkdir -p " + _core._quote(parent)
    # The guard rides whichever command goes first, so a target that resolves outside the home dir
    # is refused before any byte is written.
    if len(b64) <= _ONE_SHOT_B64:
        return _write_one_shot(server, user, abspath, b64, tmp, mk)
    return _write_chunked(server, user, abspath, b64, tmp, mk)


def _write_one_shot(server, user, abspath, b64, tmp, mk):
    """Write a small base64 payload in ONE guarded command: decode to `tmp`, keep mode, rename."""
    # `mv -T`: the destination is the file's own name, never a directory to move INTO. Plain
    # `mv -f tmp cfg`, with a folder named cfg there, put the file inside it as cfg/cfg.paneltmp
    # and exited 0 — "Uploaded", a success audit row, and no file at `cfg`. -T refuses instead,
    # and the staged copy is removed rather than left beside it.
    inner = (f"{mk} && printf %s {_core._quote(b64)} | base64 -d > {_core._quote(tmp)} "
             f"&& {_keep_mode(abspath, tmp)} && {{ mv -f -T {_core._quote(tmp)} {_core._quote(abspath)} "
             f"|| {{ rm -f {_core._quote(tmp)}; false; }}; }}")
    out, e, rc = _core.shell_as_game_user(server, user, _guarded(user, abspath, inner), timeout=60)
    if _OUTSIDE_HOME in (out or ""):
        return False, "Invalid path"
    return (rc == 0), (e or out or "")


def _write_chunked(server, user, abspath, b64, tmp, mk):
    """Stream a large base64 payload to `tmp` in chunks (guard + mkdir on the first), then decode."""
    op = ">"
    first = True
    for i in range(0, max(len(b64), 1), _CHUNK_B64):
        chunk = b64[i:i + _CHUNK_B64]
        inner = f"printf %s {_core._quote(chunk)} {op} {_core._quote(tmp)}"
        if first:
            inner = f"{mk} && {inner}"
            inner = _guarded(user, abspath, inner)
        out, e, rc = _core.shell_as_game_user(server, user, inner, timeout=60)
        if first and _OUTSIDE_HOME in (out or ""):
            return False, "Invalid path"
        if rc != 0:
            return False, e or "write failed"
        op = ">>"
        first = False
    # `mv -T` for the reason _write_one_shot gives; a refused rename removes both staged copies.
    fin = (f"base64 -d {_core._quote(tmp)} > {_core._quote(abspath)}.new "
           f"&& {_keep_mode(abspath, abspath + '.new')} "
           f"&& {{ mv -f -T {_core._quote(abspath)}.new {_core._quote(abspath)} "
           f"|| {{ rm -f {_core._quote(abspath)}.new {_core._quote(tmp)}; false; }}; }} "
           f"&& rm -f {_core._quote(tmp)}")
    o, e, rc = _core.shell_as_game_user(server, user, fin, timeout=60)
    return (rc == 0), (e or o or "")


# Applied at the top of every config/mods entry point below. _safe_abspath already rejects an
# unsafe `user` for the eight PATH-taking functions, and this is the other half of the same
# module: seven builders interpolated `user` into `sudo -u {user}` and `/home/{user}`, and
# `selfname` into the bash -c script BODY, with no validation at all. Demonstrated with
# user="x; id > /tmp/pwned; #": the injection lands in the OUTER shell, before sudo, as the panel
# user. Not reachable from a request today — every caller passes gs.short_name / gs.lgsm_name,
# which models._validate_shell_ident pins on assignment — which is exactly the residual threat the
# note above _safe_abspath describes, left open on seven of this module's fifteen builders.
def _idents_ok(*names):
    """True when every name is a safe Unix ident (so it can be interpolated into a command)."""
    return _core.game_idents_ok(*names)


def _lgsm_cfg_dir(user, selfname):
    return f"/home/{user}/lgsm/config-lgsm/{selfname}"


def _lgsm_frame(path, tag):
    """Shell printing `path` base64'd between this tag's begin/end sentinels (see lgsm_read_config)."""
    b, e = "__LGSMP_%s_B__" % tag, "__LGSMP_%s_E__" % tag
    return (f"printf %s {_core._quote(b)}; base64 {_core._quote(path)} 2>/dev/null | tr -d '\n'; "
            f"printf %s {_core._quote(e)}; ")


def _unframe_lgsm_sections(body, inst):
    """Decode the DEFAULT/COMMON/INSTANCE frames into {tag: text}, or None if any is missing/bad."""
    sect = {}
    for tag in ("DEFAULT", "COMMON", "INSTANCE"):
        b, e = "__LGSMP_%s_B__" % tag, "__LGSMP_%s_E__" % tag
        i, j = body.find(b), body.find(e)
        if i == -1 or j < i:
            _core._log.warning("lgsm_read_config: no %s frame for %s — reporting a failed read", tag, inst)
            return None
        enc = body[i + len(b):j].strip()
        try:
            import base64 as _b64
            sect[tag] = _b64.b64decode(enc, validate=True).decode("utf-8", "replace") if enc else ""
        except Exception:
            _core._log.warning("lgsm_read_config: %s frame for %s was not valid base64", tag, inst)
            return None
    return sect


def _curated_cfg_settings(merged, defaults, instance, common):
    """The curated "common" quick list: each _COMMON_CFG_KEYS entry the merged config carries."""
    settings = []
    for key, label in _COMMON_CFG_KEYS:
        if key in merged:
            settings.append({
                "key": key, "label": label, "value": merged[key],
                "default": defaults.get(key, ""),
                "overridden": key in instance or key in common,
            })
    return settings


def _cfg_section_title(line):
    r"""Return the title of a `#### Section ####` header of _default.cfg, or None for any other line.

    It answers what `^#{3,}\s+(.+?)\s+#{3,}\s*$` answered on the stripped line. That pattern
    tried its closing `\s+#{3,}` at every character of the title, and a title holding a long run of
    blanks made each try walk the run again: quadratic. Here the leading and trailing runs of '#'
    are cut off and what lies between is read once. It has to open and close on a blank; the title
    is it with the blanks trimmed, and when it is ONLY blanks (three or more), the old pattern's
    answer was the one blank next to its last, which is kept rather than quietly changed.
    """
    s = line.strip()
    body = s.lstrip("#")
    lead = len(s) - len(body)
    body = body.rstrip("#")
    trail = len(s) - lead - len(body)
    if lead < 3 or trail < 3 or len(body) < 3 or not (body[0].isspace() and body[-1].isspace()):
        return None
    return body.strip() or body[-2]


def _grouped_cfg_settings(default_text, merged, defaults, instance, common):
    """EVERY setting, grouped by _default.cfg's "#### Section ####" headers.

    So any LinuxGSM setting is editable (not just the curated ones). Empty sections are dropped.
    """
    groups = []
    cur = None
    for line in default_text.splitlines():
        title = _cfg_section_title(line)
        if title is not None:
            cur = {"section": title, "settings": []}
            groups.append(cur)
            continue
        if line.strip().startswith("#"):
            continue
        m = _CFG_LINE_RE.match(line)
        if m and m.group(1) not in _CFGFORM_HIDDEN_KEYS:
            key = m.group(1)
            if cur is None:
                cur = {"section": "Server Settings", "settings": []}
                groups.append(cur)
            cur["settings"].append({
                "key": key, "value": merged.get(key, ""),
                "default": defaults.get(key, ""),
                "overridden": key in instance or key in common,
            })
    return [g for g in groups if g["settings"]]


def lgsm_read_config(server, user, selfname):
    """Read a game's LinuxGSM config: the curated common settings plus the raw instance cfg.

    The settings are merged from _default.cfg < common.cfg < instance <selfname>.cfg; the raw
    instance cfg text is for the advanced editor.
    """
    if not _idents_ok(user, selfname):
        return {"settings": {}, "raw": "", "error": "Invalid account or script name"}
    d = _lgsm_cfg_dir(user, selfname)
    inst = f"{d}/{selfname}.cfg"
    # Each section is FRAMED and base64'd (_lgsm_frame), for two reasons a plain
    # `echo ===MARKER; cat file` could not give.
    #
    # 1. The marker was emitted with `echo` AFTER a `cat`, so it only landed on its own line if the
    #    previous file ended with a newline. A common.cfg without one produced `a=1===INSTANCE`,
    #    which matches nothing — `cur` stayed COMMON, sec["INSTANCE"] stayed empty, and `raw` came
    #    back "". The Raw tab then showed an EMPTY editor for a real config, and Save wrote that ""
    #    straight over it. Measured on a live host: a 5-line fctrserver.cfg rendered as 0 bytes with
    #    error=None. A sentinel that cannot fuse to file content is the fix; base64 guarantees it,
    #    because the encoded body cannot contain the marker's characters.
    # 2. The same byte fidelity read_file needed: the transport decodes in text mode, so CRLF became
    #    LF on the way to an editor whose Save writes the result back byte-exact.
    #
    # And a section whose frame is MISSING means the read never ran — not "an empty file". That is
    # the destructive case read_file already names: rc was discarded here (`out, _, _ =`), so a
    # timed-out or sudo-refused read returned {"raw": "", "error": None} and the editor offered to
    # save it back.
    inner = (_lgsm_frame(d + "/_default.cfg", "DEFAULT") + _lgsm_frame(d + "/common.cfg", "COMMON")
             + _lgsm_frame(inst, "INSTANCE"))
    out, _, _ = _core.shell_as_game_user(server, user, inner, timeout=20, selfname=selfname)
    sect = _unframe_lgsm_sections(out or "", inst)
    if sect is None:
        return {"settings": {}, "raw": "", "merged": {}, "instance": {},
                "error": "Could not read the config — the host did not answer."}
    defaults = _parse_cfg(sect["DEFAULT"])
    common = _parse_cfg(sect["COMMON"])
    instance_text = sect["INSTANCE"]
    instance = _parse_cfg(instance_text)
    merged = dict(defaults)
    merged.update(common)
    merged.update(instance)
    settings = _curated_cfg_settings(merged, defaults, instance, common)
    groups = _grouped_cfg_settings(sect["DEFAULT"], merged, defaults, instance, common)
    return {"path": inst, "raw": instance_text, "settings": settings, "groups": groups}


# Printed by the `details` script AFTER LinuxGSM has finished, so its presence is the one thing
# that separates "details ran and named no config file" from "details never ran".
_DETAILS_DONE = "__LGSMP_DETAILS_DONE__"


def lgsm_game_config(server, user, selfname):
    """Locate and read the game's OWN server config file by parsing LinuxGSM `details`.

    E.g. a Source server.cfg or cod's serverfiles/main/<name>.cfg. This is the
    file where in-game settings like sv_maxclients actually live for many games.
    Returns {rel, content, exists, error}. A `details` run that never completed answers
    "the host did not answer" — NOT "this game has no config file", which is a claim about
    the game that a failed read never established.
    """
    if not _idents_ok(user, selfname):
        return {"rel": "", "content": "", "exists": False,
                "error": "Invalid account or script name"}
    # SENTINEL, for the same reason lgsm_read_config frames its sections and list_game_backups
    # requires its DONE marker: `./<selfname> details` is a 45-second LinuxGSM invocation on a
    # possibly-busy host, and when it does NOT run the tailscale and local transports return
    # ("", "…timed out", -1) without raising. No output then matches the `config file:` regex, and
    # this used to answer "No editable game config file was reported for this game." — a statement
    # about the GAME made from a read that never reached the host. The admin concludes their
    # server.cfg does not exist and stops looking. The sentinel only lands if the script ran to
    # the end, so "details said nothing" and "details never answered" stay tellable apart.
    inner = (f"cd /home/{_core._quote(user)} && {{ ./{_core._quote(selfname)} details 2>&1; "
             f"printf %s {_core._quote(_DETAILS_DONE)}; }}")
    o, _, _ = _core.shell_as_game_user(server, user, inner, timeout=45, selfname=selfname)
    text = terminal.strip_escapes(o or "")
    if _DETAILS_DONE not in text:
        _core._log.warning("lgsm_game_config: no DONE marker for %s — reporting a failed read", selfname)
        return {"rel": None, "content": "", "exists": False,
                "error": "Could not read the game config — the host did not answer."}
    text = text.replace(_DETAILS_DONE, "")
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
    """Return {key: value} for `keys` from the merged LinuxGSM config.

    Merged as _default < common < instance — instance wins. Missing keys come back as "". Used by
    focused editors (alerts).

    Returns **None when the config could not be read at all**, which is a different answer from
    "every one of these settings is unset" and has to stay tellable apart.

    This was `out, _, _ = run_command(...)` with `2>/dev/null` and the rc discarded. run_command
    does not raise on the tailscale or local transports — it returns ("", "…timed out", -1) — so a
    hiccup produced an empty `out`, an empty `merged`, and a confident dict of "" for every key.
    The Alerts card (panel/routes/server_files.py) renders exactly that as "every provider off, no
    webhook, no token", and its Save posts the form back, so ONE failed read followed by one Save
    wrote those blanks over the operator's real Discord/Telegram credentials. The write half of
    this pair already learned it: lgsm_write_config below FRAMES its read and aborts the write when
    the frame is missing, with a comment describing the same measured data loss.

    The frame is what makes the two cases distinguishable. `cat … 2>/dev/null` on three files that
    are all legitimately absent (a fresh instance) and a read that never happened both produce "";
    the trailing sentinel only appears if the command really ran to the end.

    An `echo` follows each file. The three were concatenated with nothing between them, so a file
    whose last line had no newline FUSED with the next file's first line: common.cfg ending in
    `discordalert="on"` followed by an instance cfg opening with its webhook read back as
    discordalert=`on"discordwebhook="https://…` and NO discordwebhook at all. The Alerts card then
    showed an empty webhook, and its Save wrote "" over the real one. lgsm_read_config met the same
    fusion and frames each file; a blank line between them is all this parser needs.
    """
    if not _idents_ok(user, selfname):
        return None
    d = _lgsm_cfg_dir(user, selfname)
    inner = (f"cat {_core._quote(d + '/_default.cfg')} 2>/dev/null; echo; "
             f"cat {_core._quote(d + '/common.cfg')} 2>/dev/null; echo; "
             f"cat {_core._quote(d + '/' + selfname + '.cfg')} 2>/dev/null; echo; "
             f"printf %s {_core._quote(_READ_END)}")
    out, _, _ = _core.shell_as_game_user(server, user, inner, timeout=20, selfname=selfname)
    body = out or ""
    if _READ_END not in body:
        return None
    merged = _parse_cfg(body[:body.rfind(_READ_END)])
    return {k: merged.get(k, "") for k in keys}


def lgsm_write_config(server, user, selfname, updates):
    """Apply key→value updates to the instance <selfname>.cfg.

    Replaces an existing uncommented line, else appends. Other files (_default/common) are left
    alone.
    """
    if not _idents_ok(user, selfname):
        return False, "Invalid account or script name"
    # Every writer of the instance cfg comes through here, so this is where "logtimestamp is only
    # ever turned off" holds whichever form or request asked.
    if "logtimestamp" in (updates or {}) and \
            str(updates["logtimestamp"]).strip().strip('"').lower() != "off":
        return False, ("Turning LinuxGSM's log timestamps on freezes the live console, so the "
                       "panel only turns them off — nothing has been changed.")
    d = _lgsm_cfg_dir(user, selfname)
    inst = f"{d}/{selfname}.cfg"
    lines = _read_instance_cfg_lines(server, user, selfname, inst)
    if lines is None:
        return False, "Could not read the current config — nothing has been changed."
    _apply_cfg_updates(lines, updates)
    content = "\n".join(lines).rstrip("\n") + "\n"
    return _write_file_as_user(server, user, inst, content.encode())


def _read_instance_cfg_lines(server, user, selfname, inst):
    """The instance cfg's lines ([] when it does not exist yet), or None when the read failed.

    None means the caller must not write: see the comment below for the data loss that caused.
    """
    # The read is FRAMED, and a read that did not happen ABORTS the write.
    #
    # This was `cat … 2>/dev/null` with the rc discarded (`out, _, _ =`). run_command does not raise
    # on a transport failure — it returns ("", "…timed out", -1) — so a hiccup made `out` empty,
    # `lines` empty, and the join below wrote a config containing ONLY the keys being updated,
    # OVER the real instance config, and returned ok=True. Measured on a live host: a 5-line,
    # 189-byte fctrserver.cfg became one line, `port="34197"`. That runs during an install, a port
    # change and every alert/config edit.
    #
    # `2>/dev/null` also hid the difference that matters: a MISSING instance cfg is legitimate (a
    # fresh instance has none, and appending the updates is the right thing), while a failed read
    # is not. The sentinels tell those apart — the same fix, for the same reason, as read_file.
    _probe = (
        f"if [ ! -f {_core._quote(inst)} ]; then echo __NOFILE__; else "
        f"printf %s {_core._quote(_READ_BEGIN)}; base64 {_core._quote(inst)} | tr -d '\n'; "
        f"printf %s {_core._quote(_READ_END)}; fi"
    )
    out, _, _ = _core.shell_as_game_user(server, user, _probe, timeout=15, selfname=selfname)
    body = out or ""
    if body.strip() == "__NOFILE__":
        return []                       # no instance cfg yet — the updates become the file
    i, j = body.find(_READ_BEGIN), body.rfind(_READ_END)
    if i == -1 or j <= i:
        _core._log.warning("lgsm_write_config: could not read %s — refusing to write", inst)
        return None
    try:
        import base64 as _b64
        _framed = body[i + len(_READ_BEGIN):j].strip()
        _cur = _b64.b64decode(_framed, validate=True).decode("utf-8", "replace") if _framed else ""
    except Exception:
        _core._log.warning("lgsm_write_config: framed body for %s was not valid base64", inst)
        return None
    return _cur.splitlines()


# A parameter reference LinuxGSM's own configs write inside a value — `${port}`, `$ip` in
# startparameters — which a value saved from the settings form must keep live. Nothing else that
# starts with `$` is: `$(…)` and `$((…))` run, and `${x@P}` / `${x:-$(…)}` run too, so only the
# plain braced or bare NAME form is let through.
_CFG_PARAM_REF_RE = re.compile(r"\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)")


def _cfg_dq_escape(val):
    r"""`val` escaped for the inside of a bash double-quoted string, `${name}` / `$name` kept live.

    LinuxGSM SOURCES its cfg files as bash, as the game account, on every start, update and
    monitor run. The writer escaped `"` and nothing else, so a value was live shell: a password
    with a backslash at the end escaped the closing quote and broke the whole file (LinuxGSM then
    failed to start the server with a syntax error nothing on the page explained), `$1x` and
    `a$b` lost the part after the `$`, and `$(…)` or a backtick ran a command from the cron
    monitor every five minutes. `\`, `"`, backtick and every `$` that does not begin a plain
    parameter reference are escaped now; _parse_cfg undoes exactly this, so the settings form
    reads back what it saved.
    """
    out, i = [], 0
    for m in _CFG_PARAM_REF_RE.finditer(val):
        out.append(re.sub(r'([\\"`$])', r"\\\1", val[i:m.start()]))
        out.append(m.group(0))
        i = m.end()
    out.append(re.sub(r'([\\"`$])', r"\\\1", val[i:]))
    return "".join(out)


def _apply_cfg_updates(lines, updates):
    """Set each valid key in `lines` IN PLACE: replace its uncommented lines, else append one.

    EVERY uncommented line for the key, not the first: LinuxGSM sources the file, so the LAST
    assignment wins (and _parse_cfg reads it the same way). A hand-edited cfg holding the key twice
    had only its first line rewritten — the save said "Saved", the server kept the old value, and
    the form read the old value back.
    """
    for key, val in (updates or {}).items():
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*\Z", key or ""):
            continue
        val = str(val).replace("\r", " ").replace("\n", " ")
        newline = f'{key}="{_cfg_dq_escape(val)}"'
        pat = re.compile(r"^\s*" + re.escape(key) + r"\s*=")
        replaced = False
        for i, ln in enumerate(lines):
            if pat.match(ln) and not ln.strip().startswith("#"):
                lines[i] = newline
                replaced = True
        if not replaced:
            lines.append(newline)


# --- Mods / addons (LinuxGSM mods-install / mods-remove) --------------------
# LinuxGSM's mods-install/mods-remove print a list of mods and `read` one selection — the mod's
# text id (e.g. "sourcemod"), NOT a number. Typing "abort"/"exit" makes the command print the
# list then exit cleanly, so we list by feeding "abort" and act by feeding the chosen id — via a
# bash here-string. The two lists use DIFFERENT formats (verified on a live Garry's Mod server):
#   mods-install (available): a description line, then a " * <id>" line under it.
#   mods-remove  (installed):  one line per mod, "<id> - <name> - <desc>".
_MOD_AVAIL_RE = re.compile(r"^\s*\*\s+(\S+)\s*$")               # available: " * <id>"
# installed: "<id> - <name> - …". The rest starts on a non-blank (`\S.*`, not `.+`) so the blanks
# after the dash cannot be split between two quantifiers; its only caller strips the line first,
# so the rest never ends in a blank and this answers what `.+` did.
_MOD_INST_RE = re.compile(r"^([A-Za-z0-9._-]+)\s+-\s+(\S.*)$")
_MOD_ID_OK = re.compile(r"^[A-Za-z0-9._-]+\Z")                   # safe id charset (guards here-string)


def _strip_ansi(s):
    return terminal.strip_escapes(s or "")


def _parse_mods_available(out):
    """Parse the mods-install list: id is on a ' * <id>' line, name from the description line above.

    LinuxGSM prints TWO sections: an 'Installed addons/mods' block of bare ' * <id>' lines (already
    installed, NO description above them) and then 'Available addons/mods' where each ' * <id>' is
    preceded by a 'Name - desc - url' line. Only the Available block carries real, named entries — the
    Installed block's ids would otherwise be emitted named after the section header ('Installed
    addons/mods') AND duplicate the real Available rows, so we skip that section and de-dupe by id.
    """
    mods = []
    prev = ""
    in_installed = False
    seen = set()
    for raw in (out or "").splitlines():
        line = _strip_ansi(raw).rstrip()
        low = line.strip().lower()
        if low in _MODS_SECTIONS:   # a section header: which one decides whether rows count
            in_installed, prev = _MODS_SECTIONS[low], ""
            continue
        m = _MOD_AVAIL_RE.match(line)
        if m and _MOD_ID_OK.match(m.group(1)):
            mod_id = m.group(1)
            if not in_installed and mod_id not in seen:
                seen.add(mod_id)
                mods.append(_available_mod(mod_id, prev))
        else:
            prev = _mod_description_line(line, prev)
    return mods


# The two mods-install section headers, and whether each one is the skip section. "Installed"
# rows are bare ' * <id>' lines with no name; "Available" is back to the real, described list.
_MODS_SECTIONS = {"installed addons/mods": True, "available addons/mods": False}


def _available_mod(mod_id, prev):
    """One available mod, named from the description line above its ' * <id>' line."""
    name = prev.split(" - ")[0].strip() if prev else mod_id
    return {"id": mod_id, "name": name or mod_id, "desc": prev}


def _mod_description_line(line, prev):
    """The latest real description line: `line` unless it is blank or an === rule, else `prev`."""
    t = line.strip()
    if t and set(t) != {"="}:   # remember the latest real description line, skip === rules
        return t
    return prev


def _game_supports_mods(text):
    """False for games with no LinuxGSM mods installer (e.g. cod).

    Running mods-install/-remove on them prints 'Error! Unknown command' followed by a usage banner
    ('LinuxGSM - <Game> - Version v…') that would otherwise be misparsed as an installed mod.
    """
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


# Tokens the mods menus really print — taken from the live Garry's Mod and Call of Duty captures
# in tests/unit/part03.py, not guessed: the command's own title ("<Game> Installing/Removing
# Mods"), the section headers ("Available/Remove addons/mods"), the empty-install answer ("No
# installed mods or addons were found"), and the no-installer answer ("Unknown command" + the
# "LinuxGSM - <Game> - Version …" usage banner). Any ONE of them proves the host answered.
_MODS_ANSWERED_RE = re.compile(
    r"addons/mods|installing mods|removing mods|no installed mods|unknown command|linuxgsm", re.I)


def _mods_read_ok(text):
    """True when the mods menu really answered — a positive token, never the absence of one.

    `supported` (below) is `"unknown command" not in text`, which is True of "" as well, so a read
    that NEVER HAPPENED came back as ([], True): "this game has a mods installer, and it lists
    nothing". run_as_game_user does not raise on the local or tailscale transports — it returns
    ("", "SSH command timed out", -1) — and a refused account/script name returns
    ("", "invalid account or script name", 1) the same way. Both parsed to "no mods", which the
    Mods card renders as "This game doesn't have any LinuxGSM-installable mods." — a claim about
    the GAME, made from a read that never reached the host, that simultaneously hides the Remove
    button for every mod that IS installed. `supported` has no state for "we could not look", so
    the mods list gets one: None. (Same third state as browse_dir's `unreadable` and
    list_game_backups' None.)
    """
    return bool(_MODS_ANSWERED_RE.search(text or ""))


def mods_available(server, user, selfname, timeout=60):
    """Return (available_mods, supported).

    `supported` is False for games with no LinuxGSM mods installer (e.g. cod), where mods-install
    answers 'Unknown command' — so the UI can hide the whole card rather than show an empty one.

    The list is **None when the host did not answer at all**, which is a different thing from "this
    game has no mods" and has to stay tellable apart — see _mods_read_ok.
    """
    out, err, _ = _core.run_as_game_user(server, user, "mods-install", timeout=timeout,
                                         selfname=selfname, answers=["abort"])
    text = (out or "") + "\n" + (err or "")
    supported = _game_supports_mods(text)
    if not _mods_read_ok(text):
        return None, supported
    return (_parse_mods_available(text) if supported else []), supported


def mods_installed(server, user, selfname, timeout=60):
    """Return (installed_mods, supported).

    See mods_available for `supported` and for why the list is None when the read did not happen.
    """
    out, err, _ = _core.run_as_game_user(server, user, "mods-remove", timeout=timeout,
                                         selfname=selfname, answers=["abort"])
    text = (out or "") + "\n" + (err or "")
    supported = _game_supports_mods(text)
    if not _mods_read_ok(text):
        return None, supported
    return (_parse_mods_installed(text) if supported else []), supported


def mods_action(server, user, selfname, which, mod_id, timeout=600):
    """Install or remove a mod by its LinuxGSM id (e.g. "sourcemod").

    `which` is 'install' or 'remove'. Returns (out, err, rc). We feed the id then a "Y":
    mods-remove always asks "Continue?" before deleting files, and mods-install asks it too when
    the mod is already installed (both default to Y). The id is validated to a safe charset first,
    so nothing but a bare id + Y is ever fed to the command. Verified install+remove on a live
    Garry's Mod box.
    """
    if not _MOD_ID_OK.match(mod_id or ""):
        return "", "invalid mod id", 1
    cmd = "mods-install" if which == "install" else "mods-remove"
    out, err, rc = _core.run_as_game_user(server, user, cmd, timeout=timeout, selfname=selfname,
                                          answers=[mod_id, "Y"])
    return out, err, rc


# Files/dirs whose deletion would break LinuxGSM or the game install — protected
# from the file browser's delete (they can still be edited where that makes sense).
def _is_protected_path(relpath, selfname):
    """True if `relpath` (relative to the game user's home) must not be deleted."""
    # Normalise BEFORE inspecting. delete_path deletes the resolved absolute path, so a guard that
    # reads the raw string is judging a different path than the one `rm -rf` receives: "./lgsm" and
    # "x/../serverfiles" look like ordinary sub-paths here while resolving onto the LinuxGSM control
    # tree and the whole game install.
    #
    # Normalised RELATIVE to the home, and anything that climbs out of it is refused. This used to
    # normalise against "/", where ".." is swallowed: "x/../../gs/lgsm" became "gs/lgsm", top "gs",
    # not protected — while _safe_abspath resolved the same string under /home/gs to /home/gs/lgsm,
    # the LinuxGSM control tree, and delete_path ran `rm -rf` on it. A path that leaves the home
    # and walks back in by name is never one the file browser builds.
    r = _pp.normpath(str(relpath or "").lstrip("/"))
    if r == ".." or r.startswith("../"):
        return True  # climbs out of the home dir, whatever it names on the way back in
    r = r.strip("/")
    if not r or r == ".":
        return True  # the home dir itself
    parts = r.split("/")
    top = parts[0]
    # The whole LinuxGSM control tree (script data, module cache, configs).
    if top == "lgsm":
        return True
    # Critical top-level entries (deleting these bricks the server or your login).
    if len(parts) == 1 and r in _protected_top_names(selfname):
        return True
    return False


def _protected_top_names(selfname):
    """The top-level entries of a game home that _is_protected_path protects by name.

    Plus `lgsm`, which it protects with everything under it. One list, for it and for
    delete_path's host-side check, so the two cannot disagree.
    """
    return {"serverfiles", "linuxgsm.sh", selfname or "",
            ".ssh", ".bashrc", ".profile", ".bash_logout", ".bash_history", ".wget-hsts"} - {""}


_PROTECTED_MARK = "__PROTECTED__"
# What _protected_resolved prints on stderr when the parent directory is not there to resolve.
_NO_SUCH_DIR = "No such directory"


def _protected_resolved(user, ap, selfname, inner):
    """Prefix `inner` with delete_path's protected-path check, made ON THE HOST.

    The check is made against the path `rm` will actually remove.

    _is_protected_path reads the TEXT of the path, and _guarded only asks whether the resolved
    path stays inside the home. Neither sees a symlinked DIRECTORY on the way: with `x -> lgsm`
    (or `x -> .`) planted in the home by the game account, a mod, or anything else running as it,
    "x/config-lgsm" is not protected by name, resolves inside the home, and `rm -rf` walked the
    link and removed the LinuxGSM config tree — or "x/lgsm", the whole control tree.

    The parent is resolved with `cd -P`/`pwd -P` and the last component is NOT: `rm` removes a
    symlink itself rather than what it points at, so the path that matters is "real parent + the
    name as given". The same check as _is_protected_path runs on that, in the same command as the
    delete, so nothing can be re-pointed between them.
    """
    home = f"/home/{user}"
    hq = _core._quote(home)
    names = "|".join(_core._quote(n) for n in sorted(_protected_top_names(selfname)))
    return (f"d=$(cd -P -- {_core._quote(_pp.dirname(ap))} 2>/dev/null && pwd -P) "
            f"|| {{ echo '{_NO_SUCH_DIR}' >&2; exit 1; }}; "
            f't="$d"/{_core._quote(_pp.basename(ap))}; '
            f'case "$t" in {hq}/*) r=${{t#{hq}/}} ;; *) echo {_OUTSIDE_HOME}; exit 9 ;; esac; '
            f'case "$r" in lgsm|lgsm/*|{names}) echo {_PROTECTED_MARK}; exit 8 ;; esac; '
            + inner)


def browse_dir(server, user, relpath="", selfname=None):
    """List a directory in the game user's home (dirs first).

    Each entry is flagged `protected` when deleting it would break LinuxGSM/the game. Returns None
    on a path-traversal attempt.
    """
    ap = _safe_abspath(user, relpath)
    if ap is None:
        return None
    # `-H` and `%Y`: a symlinked folder is a folder. Plain find does not descend a symlinked
    # starting point — it printed nothing and exited 0, so `log/server` (LinuxGSM's own link) or a
    # serverfiles moved to a bigger disk read as "this folder is empty" — and `%y` types a link
    # `l`, so the parent listed it as a file whose editor said "File not found". `%Y` is the
    # target's type (`N` for a dangling link, which stays a file). prune_game_backups fixed the
    # same find trap with the same `-H`.
    inner = f"find -H {_core._quote(ap)} -maxdepth 1 -mindepth 1 -printf '%Y\\t%s\\t%f\\0' 2>/dev/null"
    out, _, rc = _core.shell_as_game_user(server, user, _guarded(user, ap, inner), timeout=20)
    if _OUTSIDE_HOME in (out or ""):
        return None
    # A read that FAILED prints nothing, and so does a genuinely empty directory — rc is the only
    # thing that tells them apart, and without it the browser rendered "this folder is empty"
    # about a folder it never reached. That is the most alarming possible way to be wrong about
    # somebody's game files. `unreadable` rather than None: None already means path traversal and
    # the route answers it with "Invalid path", which would be a second wrong statement.
    if rc != 0:
        return {"path": (relpath or "").strip("/"), "entries": [], "unreadable": True}
    base = (relpath or "").strip("/")
    return {"path": base, "entries": _browse_entries(out, base, selfname)}


def _listing_records(out):
    """The records of a `find -printf` listing whose format ends in NUL, split on that NUL.

    NUL, because no filename can hold one, and because every transport strips its whole stdout
    (_core._finish, the Tailscale ssh path and the paramiko path all return `out.strip()`).
    Records ended with a newline lost whatever whitespace ended the name `find` printed LAST,
    along with the newline: `server.cfg ` was listed as `server.cfg`, so its row named a different
    path — Rename said "no longer there", Delete said "Deleted" and left it, and beside a real
    `server.cfg` both rows carried the same path and acted on the real file. strip() leaves a NUL
    alone, so the last record keeps its name whole. A newline, U+2028, U+0085 or any other line
    break a name holds is part of the name now, not the end of a record (str.splitlines() breaking
    on those cut a name short the same way).
    """
    return (out or "").split("\0")


def _browse_entries(out, base, selfname):
    """The tab-separated `find -printf` listing (type, size, name) as entries, dirs first."""
    entries = []
    for line in _listing_records(out):
        parts = line.split("\t")
        if len(parts) >= 3:
            typ, size = parts[0], parts[1]
            name = "\t".join(parts[2:])
            rel = f"{base}/{name}" if base else name
            entries.append({"name": name, "is_dir": typ == "d",
                            "size": int(size) if size.isdecimal() else 0,
                            "protected": _is_protected_path(rel, selfname)})
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    return entries


# Sentinels framing a file's bytes on the wire — see read_file for why they are needed.
_READ_BEGIN = "__LGSMP_FILE_BEGIN__"
_READ_END = "__LGSMP_FILE_END__"


def read_file(server, user, relpath, max_bytes=1048576):
    """Read a text file from the game user's home. Returns (content, error).

    Refuses binaries and files larger than max_bytes.
    """
    ap = _safe_abspath(user, relpath)
    if ap is None:
        return None, "Invalid path"
    # The body is FRAMED, because both transports strip: _core._finish returns
    # (out or "").strip() and the paramiko branch does out.strip(). So the editor was handed a
    # copy of the file with its leading blank lines and its trailing newline removed, and
    # write_file wrote that back verbatim — open any config, press Save without typing, and the
    # file loses its trailing newline. (stream_path does NOT strip, so download and edit
    # disagreed about the same file.) Framing keeps the fix inside this function: the strip can
    # only reach the whitespace OUTSIDE the sentinels.
    #
    # ...and it is BASE64 inside the frame, because framing cannot reach the other way the
    # transport rewrites a file: both read paths decode in TEXT mode, and Python's universal
    # newlines turn every CRLF into LF before this function ever sees the bytes. The write path is
    # byte-exact (it base64s too), so the damage was asymmetric and silent — open a CRLF config in
    # the editor, press Save without typing, and every line ending in the file is permanently
    # converted. Measured against a real host: 'alpha\r\nbeta\r\ngamma\n' on disk came back as
    # 'alpha\nbeta\ngamma\n'. UT2004's .ini files and anything pasted from Windows are CRLF.
    # Encoding on the host means no byte can be altered in transit, which is the same reason
    # _write_file_as_user has always done it in the other direction.
    inner = (
        f"if [ ! -f {_core._quote(ap)} ]; then echo __NOFILE__; exit 0; fi; "
        # `stat -Lc`, matching stat_path below. Every OTHER operator in this script — [ -f ],
        # [ -s ], grep, base64 — dereferences a symlink; `stat -c %s` does not, it reports the
        # length of the link's own target string (tens of bytes). So for a symlink the cap was
        # applied to the LINK while the read followed it to the target, and the 1 MB refusal this
        # whole line exists for simply did not apply: a convenience link like
        # `latest.log -> serverfiles/.../errors.log` pointing at a multi-GB log was base64'd
        # whole, buffered as one Python string and serialised into a JSON response.
        f"sz=$(stat -Lc %s {_core._quote(ap)} 2>/dev/null); "
        # ...and a size we could not READ must refuse, not pass. `[ "" -gt N ]` is a bash
        # "integer expression expected" error whose non-zero status makes the `if` false, so an
        # unreadable size fell through to the uncapped read. Exiting with no output at all puts it
        # on the unframed path below, which already says "could not read" rather than guessing.
        f"case \"$sz\" in ''|*[!0-9]*) exit 0;; esac; "
        f"if [ \"$sz\" -gt {int(max_bytes)} ]; then echo __TOOBIG__; exit 0; fi; "
        f"if [ ! -s {_core._quote(ap)} ] || grep -qI . {_core._quote(ap)} 2>/dev/null; then "
        f"printf %s {_core._quote(_READ_BEGIN)}; base64 {_core._quote(ap)} | tr -d '\\n'; "
        f"printf %s {_core._quote(_READ_END)}; else echo __BINARY__; fi"
    )
    out, _err, _rc = _core.shell_as_game_user(server, user, _guarded(user, ap, inner), timeout=20)
    return _read_file_reply(out, ap, _rc)


# What read_file's script prints INSTEAD of a frame, and what each one tells the editor.
_READ_REFUSALS = {
    "__NOFILE__": "File not found",
    "__TOOBIG__": "File is too large to edit in the browser",
    "__BINARY__": "Binary file — download/replace via upload instead",
}


def _decode_read_frame(framed, ap):
    """The (content, error) for the base64 text between read_file's sentinels."""
    if not framed:
        return "", None          # a genuinely empty file, framed and confirmed
    try:
        import base64 as _b64
        # errors="replace" matches what the text transport did for a file that is not valid
        # UTF-8: grep -qI calls it text, and the editor still has to show something.
        return _b64.b64decode(framed, validate=True).decode("utf-8", "replace"), None
    except Exception:
        _core._log.warning("read_file: framed body for %s was not valid base64", ap)
        return None, "Could not read that file — the host did not answer. Nothing has been changed."


def _read_file_reply(out, ap, _rc):
    """Turn read_file's script output into (content, error) — see read_file."""
    if _OUTSIDE_HOME in (out or ""):
        return None, "Invalid path"
    stripped = (out or "").strip()
    if stripped in _READ_REFUSALS:
        return None, _READ_REFUSALS[stripped]
    # First BEGIN, LAST end: a file that happens to contain a sentinel still round-trips unless it
    # contains both, in that order, which no real config does.
    body = out or ""
    i = body.find(_READ_BEGIN)
    j = body.rfind(_READ_END)
    if i != -1 and j > i:
        return _decode_read_frame(body[i + len(_READ_BEGIN):j].strip(), ap)
    # No frame, and none of the three sentinels above: the read never got as far as `cat`. This
    # used to `return body, None` — i.e. "" with no error — and that is destructive, not merely
    # wrong. run_command does not raise on the local or Tailscale transports; it returns
    # ("", "…timed out", -1), and a `sudo -u` refusal puts its message on stderr with empty stdout.
    # So a transient failure reached api_server_file as 200 {"content": ""}, the editor showed an
    # empty file, and pressing Save wrote "" over the real config.
    #
    # The sentinel framing already distinguishes "got as far as cat" from "did not"; it just has to
    # say so. (The repo's own "empty is not a measurement", with a destructive consequence rather
    # than a merely wrong readout.)
    _core._log.warning("read_file: no sentinel frame for %s (rc=%s) — reporting a failed read", ap, _rc)
    return None, "Could not read that file — the host did not answer. Nothing has been changed."


# ── logtimestamp through the file browser ──────────────────────────────────────────────────────
# lgsm_write_config refuses turning LinuxGSM's `logtimestamp` on (it freezes the live console —
# see _CFGFORM_HIDDEN_KEYS), but the raw editor, the Config card's Raw tab and an upload write a
# whole file and never came through it. These refuse the same thing on those paths.
#
# WHICH FILES. linuxgsm.sh sources lgsm/config-lgsm/<gameservername>/ _default.cfg, common.cfg,
# secrets-common.cfg, <instance>.cfg and secrets-<instance>.cfg (_core.LGSM_CFG_ORDER), and on
# every run copies lgsm/config-default/config-lgsm/<gameservername>/_default.cfg over the first
# when the two differ — so that template is a way in too. Any `.cfg` under either tree is refused:
# a name that is not sourced today becomes the instance cfg of the next instance installed.
#
# WHAT COUNTS AS ON. LinuxGSM tests `[ "${logtimestamp}" == "on" ]`. A value that reads "on" once
# bash's quotes and backslashes are gone is refused, in any case (`On` does not turn it on, but it
# is one keystroke from doing so and nobody means it), and so is a value with `$` or a backtick,
# which this cannot evaluate. "off", "" and a commented-out line are allowed; spaces around `=`
# (which bash would run as a command, not an assignment) are judged like an assignment.
_RAWLTS_REFUSED = ("This file sets LinuxGSM's logtimestamp on, which freezes the panel's live "
                   "console, so it can't be saved into a LinuxGSM config. Set it to \"off\" or "
                   "comment the line out — nothing has been changed.")
_RAWLTS_UNCHECKED = ("This file sets LinuxGSM's logtimestamp on, which freezes the panel's live "
                     "console, and the host could not be asked whether the file is a LinuxGSM "
                     "config — nothing has been changed.")
_RAWLTS_ASSIGN_RE = re.compile(
    r"(?<![\w$])logtimestamp\s*=\s*((?:\"[^\"]*(?:\"|$)|'[^']*(?:'|$)|[^\s;&|\"'])*)", re.IGNORECASE)
_RAWLTS_CFG_RE = re.compile(r"/lgsm/config-(?:lgsm|default/config-lgsm)/.*\.cfg\Z")
_RAWLTS_HOST_PATTERNS = "*/lgsm/config-lgsm/*.cfg|*/lgsm/config-default/config-lgsm/*.cfg"
_RAWLTS_HIT, _RAWLTS_CLEAR = "__RAWLTS_CFG__", "__RAWLTS_NOTCFG__"


def _rawlts_code(line):
    """`line` without its comment: from the first `#` that starts a word outside quotes, as bash."""
    quote, prev = None, " "
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "#" and (prev.isspace() or prev in ";&|("):
            return line[:i]
        prev = c
    return line


def _rawlts_turns_on(data):
    """True when the text (str or bytes) has an uncommented line that sets logtimestamp on."""
    if isinstance(data, bytes):
        # An upload can be 50 MB of anything: only decode one that names the key at all.
        if not re.search(rb"(?i)logtimestamp", data):
            return False
        data = data.decode("utf-8", "replace")
    for line in (data or "").splitlines():
        for m in _RAWLTS_ASSIGN_RE.finditer(_rawlts_code(line)):
            val = re.sub(r"[\"'\\]", "", m.group(1)).strip().lower()
            if val == "on" or "$" in val or "`" in val:
                return True
    return False


def _rawlts_host_says_cfg(server, user, ap):
    """Whether `ap`, resolved ON THE HOST, is a LinuxGSM config: True / False, None when unknown.

    A path that does not read as one can still land in one through a symlinked folder (the write
    replaces the last name, so its real parent counts) or a link at the name itself (counted too:
    refusing that is the safe side). One round trip, made only for a file that turns the key on.
    """
    q = _core._quote
    inner = (f"a=$(realpath -m {q(ap)} 2>/dev/null) || a={q(ap)}; "
             f"b=$(realpath -m {q(_pp.dirname(ap))} 2>/dev/null)/{q(_pp.basename(ap))} "
             f"|| b={q(ap)}; "
             f'for p in "$a" "$b"; do case "$p" in {_RAWLTS_HOST_PATTERNS}) '
             f"echo {_RAWLTS_HIT}; exit 0 ;; esac; done; echo {_RAWLTS_CLEAR}")
    out, _, rc = _core.shell_as_game_user(server, user, inner, timeout=15)
    out = out or ""
    if rc != 0 or (_RAWLTS_HIT in out) == (_RAWLTS_CLEAR in out):
        return None                 # it did not run, or said both or neither: not an answer
    return _RAWLTS_HIT in out


def _rawlts_refusal(server, user, ap, data):
    """Why writing `data` at `ap` is refused for turning logtimestamp on, else None."""
    if not _rawlts_turns_on(data):
        return None
    if _RAWLTS_CFG_RE.search(ap):
        return _RAWLTS_REFUSED
    is_cfg = _rawlts_host_says_cfg(server, user, ap)
    if is_cfg is None:
        return _RAWLTS_UNCHECKED
    return _RAWLTS_REFUSED if is_cfg else None


def write_file(server, user, relpath, content):
    """Write text content to a file in the game user's home."""
    ap = _safe_abspath(user, relpath)
    if ap is None:
        return False, "Invalid path"
    refusal = _rawlts_refusal(server, user, ap, content or "")
    if refusal:
        return False, refusal
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
             f"-printf '%y\\t%s\\t%T@\\t%f\\0' 2>/dev/null")
    out, err, rc = _core.shell_as_game_user(server, user, _guarded(user, apdir, inner), timeout=20)
    if _OUTSIDE_HOME in (out or ""):
        return None
    # A listing that did not RUN is not a listing with nothing in it. rc was discarded here, so an
    # unreachable host produced out="" -> no matches -> the caller answered {"existing": [],
    # "checked": true}: "we looked, nothing conflicts". That is the false clear the upload-check
    # route exists to prevent, and its own except branch already handles this correctly ("An
    # unreachable host is the ordinary case here ... it must not answer 'nothing exists'") — it
    # was simply never reached, because run_command returns ("", "...", -1) instead of raising for
    # the local and Tailscale transports. An empty directory still exits 0, so this only fires
    # when the command itself failed.
    if rc != 0:
        raise ConnectionError((err or out or "could not list the upload directory").strip()[:200])
    return _upload_conflicts(names, _upload_dir_entries(out))


def _upload_dir_entries(out):
    """Map each name to {is_dir, size, mtime}, from the tab-separated `find -printf` listing.

    Read as _browse_entries reads it (_listing_records), or a name ending in whitespace, or holding
    a line break, is never found here and an upload onto it is not flagged as a conflict.
    """
    present = {}
    for line in _listing_records(out):
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
    return present


def _upload_conflicts(names, present):
    """The requested names that already exist in `present`, each once, in request order."""
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
    refusal = _rawlts_refusal(server, user, target, data_bytes or b"")
    if refusal:
        return False, refusal
    if not overwrite:
        refusal = _existing_target_refusal(server, user, target)
        if refusal:
            return False, refusal
    return _write_file_as_user(server, user, target, data_bytes)


def _existing_target_refusal(server, user, target):
    """Why a no-overwrite upload must not proceed (UPLOAD_EXISTS, or a failed check), else None."""
    chk = f"test -e {_core._quote(target)} && echo __YES__ || true"
    out, _, rc = _core.shell_as_game_user(server, user, _guarded(user, target, chk), timeout=15)
    if _OUTSIDE_HOME in (out or ""):
        return "Invalid path"
    # The probe prints NOTHING when the file is absent, so silence is its ordinary success —
    # rc is what separates that from a read that never ran. Without it, a failed check read as
    # "no file there" and the upload went ahead and replaced a file the caller had explicitly
    # asked not to overwrite.
    if rc != 0:
        return ("Couldn't check whether that file already exists on the host — "
                "nothing was uploaded. Try again.")
    if "__YES__" in (out or ""):
        return UPLOAD_EXISTS
    return None


def _delete_refusal(user, relpath, selfname, ap):
    """Why delete_path must refuse this path (the home root, outside it, protected), else None."""
    home = f"/home/{user}"
    if ap is None or ap == home or not (relpath or "").strip("/"):
        return "Refusing to delete this path"
    if _is_protected_path(relpath, selfname):
        return "This file/folder is protected — deleting it would break the server."
    return None


def delete_path(server, user, relpath, selfname=None):
    """Delete a file or directory (recursively) in the game user's home.

    Refuses the home root, anything outside it, and protected LinuxGSM/game paths.
    """
    ap = _safe_abspath(user, relpath)
    refusal = _delete_refusal(user, relpath, selfname, ap)
    if refusal:
        return False, refusal
    # `"$t"`: the path _protected_resolved checked — the real parent plus this name — so what is
    # removed is exactly what was judged.
    inner = 'rm -rf -- "$t" && echo __OK__'
    # The most destructive of the six, so it gets a host-side resolution check: a symlink under
    # the home dir must not turn `rm -rf` loose on whatever it points at — nor on a protected tree
    # reached through a symlinked directory. _protected_resolved is that check, and its containment
    # test is made on what `rm` removes: the real parent plus the name, the LINK itself when the
    # name is one. It used to run inside _guarded too, whose `realpath -m` follows the final link,
    # so a link in the home pointing out of it (`bin/libstdc++.so.6 -> /usr/lib/...`, a mod's
    # stale link) could not be deleted at all — "Refusing to delete this path" for a file the
    # account owns, although only the link was ever going to be touched.
    out, e, rc = _core.shell_as_game_user(
        server, user, _protected_resolved(user, ap, selfname, inner), timeout=30)
    return _files_delete_outcome(out, e, rc)


def _files_delete_outcome(out, e, rc):
    """delete_path's (ok, message) from what its guarded host-side `rm -rf` printed."""
    if _OUTSIDE_HOME in (out or ""):
        return False, "Refusing to delete this path"
    if _PROTECTED_MARK in (out or ""):
        return False, "This file/folder is protected — deleting it would break the server."
    if rc == 0 and "__OK__" in (out or ""):
        return True, "Deleted"
    return False, e or out or "Delete failed"


# ── Renaming a file or folder, within its own folder ───────────────────────────────────────────
# rename_path's message when the new name is already taken, before the move or by something that
# appeared between the check and the move. A sentinel, like UPLOAD_EXISTS, so the route answers a
# machine-readable conflict rather than the page pattern-matching prose.
RENAME_EXISTS = "__RENAME_EXISTS__"
# Linux's NAME_MAX: the most one path component holds on ext4, xfs and btrfs. Counted in UTF-8
# BYTES, because that is what the filesystem counts — 128 two-byte characters are already too many.
RENAME_NAME_MAX = 255
# The fixed text for a rename the host never confirmed. It is said the same way whichever transport
# failed: paramiko raises, the Tailscale and local transports return ("", "...", -1), and neither
# says whether `mv` ran before the link went — so this does not claim that nothing changed.
RENAME_UNCONFIRMED = ("The host didn't confirm the rename. Reload the file browser to see whether "
                      "it happened before trying again.")
RENAME_PROTECTED = "This file/folder is protected — renaming it would break the server."
RENAME_REFUSED = "Refusing to rename this path."
RENAME_CONSOLE = ("The live console reads this path — renaming it would stop the console until the "
                  "server restarts.")
_RENAME_CONSOLE_MARK = "__RENAME_CONSOLE__"
RENAME_EDGE_SPACE = ("A name can't start or end with a space — it would look just like the name "
                     "without one.")
# Unicode's Bidi_Control characters. Each makes the text after it display in another order, so a
# name holding one shows as something else: "\u202egnp.sh" displays as "hs.png".
_BIDI_CONTROLS = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
                           "\u2066\u2067\u2068\u2069")
_RENAME_LINKED = "__RENAME_LINKED__"
_RENAME_GONE = "__RENAME_GONE__"
_RENAME_TAKEN = "__RENAME_TAKEN__"
_RENAME_MVFAIL = "__RENAME_MVFAIL__"
_RENAME_DONE = "__RENAME_DONE__"
_RENAME_GONE_MSG = "That file or folder is no longer there. Reload the file browser."


def rename_name_problem(name):
    """Why `name` cannot be the new name of a file or folder, or None when it can.

    One path component of a Linux filename: not empty, not '.' or '..', no '/', valid UTF-8, at
    most RENAME_NAME_MAX bytes, and nothing that makes the name read as something else: no control
    character (Cc: NUL, newline, DEL, U+0085...), no line or paragraph separator (U+2028, U+2029),
    no text-direction control, and no whitespace at either end. upload_file's rules ('', '.', '..',
    the '/' basename() removes and the NUL it strips) are the subset of these an upload could meet;
    a rename is TYPED, so it gets a reason for each instead of having its name quietly changed into
    one that passes.
    """
    if not isinstance(name, str) or not name:
        return "Enter a new name."
    if name in (".", ".."):
        return "'.' and '..' are not names a file or folder can have."
    if "/" in name:
        return "A name can't contain a slash (/) — renaming never moves anything to another folder."
    return _rename_char_problem(name) or _rename_edge_problem(name)


def _rename_edge_problem(name):
    """Refuse whitespace at either end of a new name (whatever str.strip() would remove).

    `server.cfg ` shows exactly as `server.cfg` does: a trailing space typed by mistake (a phone
    keyboard's autocomplete adds one) made a second "server.cfg" row, and the one the user meant to
    delete or edit was easy to confuse with the real config. The name is not trimmed into one that
    passes: it is refused with the reason, as every other rule here is.
    """
    if name != name.strip():
        return RENAME_EDGE_SPACE
    return None


def _rename_char_problem(name):
    """rename_name_problem's character and length rules, for a name that is one component."""
    kinds = {_ud.category(c) for c in name}
    if "Cc" in kinds:
        return "A name can't contain control characters."
    if kinds & {"Zl", "Zp"}:
        return "A name can't contain a line or paragraph separator."
    if not _BIDI_CONTROLS.isdisjoint(name):
        return ("A name can't contain text-direction characters — they make a name display as "
                "something it isn't.")
    try:
        size = len(name.encode("utf-8"))
    except UnicodeEncodeError:          # a lone surrogate: JSON can carry one, no filename can
        return "That name isn't valid text."
    if size > RENAME_NAME_MAX:
        return "That name is too long (255 bytes at most)."
    return None


def rename_refusal(user, relpath, new_name, selfname=None):
    """Why renaming `relpath` to `new_name` is refused before the host is asked, else None.

    The home itself, anything outside it, a path that is not valid text, a protected path (by
    delete_path's rules: renaming `lgsm` or `serverfiles` away breaks the server exactly as deleting
    it does), the live console's log or a folder above it (_console_paths), a bad new name, the name
    it already has, and a new name that is itself protected where it would land.
    """
    ap = _safe_abspath(user, relpath) if isinstance(relpath, str) else None
    if ap is None or ap == f"/home/{user}" or not relpath.strip("/") or not _is_text(relpath):
        return RENAME_REFUSED
    return (rename_name_problem(new_name)
            or _rename_ends_refusal(user, relpath, ap, new_name, selfname))


def _rename_ends_refusal(user, relpath, ap, new_name, selfname):
    """rename_refusal's rules about the two ends — what is renamed, and the name it would take."""
    home = f"/home/{user}"
    if _is_protected_path(relpath, selfname):
        return RENAME_PROTECTED
    if _pp.relpath(ap, home) in _console_paths(selfname):
        return RENAME_CONSOLE
    if new_name == _pp.basename(ap):
        return "That is already its name."
    if _is_protected_path(_pp.relpath(_pp.join(_pp.dirname(ap), new_name), home), selfname):
        return "That name is reserved for LinuxGSM or the game's account — choose another."
    return None


def _is_text(s):
    """True when `s` can be written as UTF-8, as a filename on the host and an audit row are."""
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:          # a lone surrogate: JSON can carry one, no filename can
        return False
    return True


def _console_paths(selfname):
    """The paths, relative to the home, that the live console reads: its log and the two folders.

    GameServer.console_log is log/console/<lgsm_name>-console.log, a fixed path. tmux pipe-pane
    keeps appending to the file it opened, so renaming the log or a folder above it while the
    server runs leaves the console reading a path nothing writes to, until the next restart.
    Delete has the same reach; this is rename's own refusal, and leaves delete's rules unchanged.
    """
    paths = {"log", "log/console"}
    if selfname:
        paths.add(f"log/console/{selfname}-console.log")
    return paths


def _console_guard(user, selfname):
    """Host-side: refuse when "$t" is the console's path, or a folder above it, once RESOLVED.

    rename_refusal's check reads the path's text, and a home can move its logs through a symlink
    (`log -> disk/logs`): renaming disk/logs breaks the console as surely as renaming log, and
    only the host can see that. realpath -m resolves each console path, and "$t" (the real parent
    plus the name, pinned by the linked-parent refusal before this) is refused when it is one of
    them or above one.
    """
    q = _core._quote
    paths = " ".join(q(f"/home/{user}/{p}") for p in sorted(_console_paths(selfname)))
    return (f'for c in {paths}; do c=$(realpath -m "$c" 2>/dev/null || printf %s "$c"); '
            f'case "$c" in "$t"|"$t"/*) echo {_RENAME_CONSOLE_MARK}; exit 11 ;; esac; done; ')


def _rename_inner(ap, new_name, user, selfname=None):
    """The host-side rename, run after _protected_resolved has set "$d" (real parent) and "$t".

    * "$d" is the source's folder resolved with `cd -P`. Anything but the folder the browser named
      means a symlink on the way, and the rename is refused rather than followed: delete_path's
      check only asks where the link LEADS, and a rename has two ends to keep in one place.
    * The live console's log, or a folder it is in, reached by its resolved path (_console_guard).
    * The new name is joined to "$d", the same real folder, so the two ends cannot part.
    * `mv -T` takes the destination as a name, never as a folder to move INTO — a symlink to a
      folder sitting at the new name would otherwise swallow the source — and `-n` never replaces.
      GNU mv (coreutils 8.29 and later) does `-n -T` as one renameat2(RENAME_NOREPLACE), so a name
      appearing during the move is refused by the kernel. uutils' mv, the default from Ubuntu
      25.10, checks and then renames; where GNU's is installed beside it, as `gnumv`, that is used.
    * Whether it moved is read from the filesystem, by the source's device:inode turning up at the
      new name, never from mv's exit status: coreutils 9.2 changed what `mv -n` returns when it
      skips, and uutils is another implementation again. A name that appeared between the check
      and the move is reported as taken, never clobbered.
    """
    q = _core._quote
    taken = '[ -e "$n" ] || [ -L "$n" ]'
    return (f'[ "$d" = {q(_pp.dirname(ap))} ] || {{ echo {_RENAME_LINKED}; exit 10; }}; '
            + _console_guard(user, selfname) +
            f'si=$(stat -c %d:%i -- "$t" 2>/dev/null) || {{ echo {_RENAME_GONE}; exit 7; }}; '
            f'n="$d"/{q(new_name)}; '
            f'if {taken}; then echo {_RENAME_TAKEN}; exit 6; fi; '
            'm=mv; command -v gnumv >/dev/null 2>&1 && m=gnumv; '
            '"$m" -n -T -- "$t" "$n"; '
            f'if [ "$(stat -c %d:%i -- "$n" 2>/dev/null)" = "$si" ]; then echo {_RENAME_DONE}; exit 0; fi; '
            f'if {taken}; then echo {_RENAME_TAKEN}; exit 6; fi; '
            f'echo {_RENAME_MVFAIL}; exit 1')


def rename_path(server, user, relpath, new_name, selfname=None):
    """Rename a file or folder in the game user's home to `new_name`, in the same folder.

    -> (ok, message); message is RENAME_EXISTS when the new name is taken. Never overwrites.

    Guarded as delete_path is — _safe_abspath, then _protected_resolved on the host, in the same
    command as the move — plus _rename_inner's own refusals: a source reached through a symlinked
    folder, and a destination that exists (even as a dangling symlink). Not _guarded: `mv` moves
    a link, not its target, and following the final link refused renaming one that points out of
    the home (see delete_path).
    """
    refusal = rename_refusal(user, relpath, new_name, selfname)
    if refusal:
        return False, refusal
    ap = _safe_abspath(user, relpath)
    inner = _rename_inner(ap, new_name, user, selfname)
    out, e, rc = _core.shell_as_game_user(
        server, user, _protected_resolved(user, ap, selfname, inner), timeout=30)
    return _rename_outcome(out, e, rc)


# Sentinel -> (ok, message), first match wins. _OUTSIDE_HOME and _PROTECTED_MARK are delete_path's
# own, printed by the guards rename_path shares with it.
_RENAME_OUTCOMES = (
    (_OUTSIDE_HOME, RENAME_REFUSED),
    (_PROTECTED_MARK, RENAME_PROTECTED),
    (_RENAME_CONSOLE_MARK, RENAME_CONSOLE),
    (_RENAME_LINKED, "Refusing to rename through a symbolic link: open the folder it points to "
                     "and rename it there."),
    (_RENAME_GONE, _RENAME_GONE_MSG),
    (_RENAME_TAKEN, RENAME_EXISTS),
    (_RENAME_MVFAIL, "The host refused the rename — the file may belong to another account or "
                     "be in use. Nothing was renamed."),
)


def _rename_outcome(out, e, rc):
    """rename_path's (ok, message) from what its guarded host-side command printed.

    Fixed text only: the host's stderr is logged, never returned, and an answer with no sentinel
    in it — a timeout or a dropped link on the transports that return rather than raise — is
    RENAME_UNCONFIRMED.
    """
    out = out or ""
    if rc == 0 and _RENAME_DONE in out:
        return True, "Renamed"
    for mark, message in _RENAME_OUTCOMES:
        if mark in out:
            return False, message
    if _NO_SUCH_DIR in (e or ""):
        return False, _RENAME_GONE_MSG
    _core._log.warning("rename_path: the host did not confirm the rename (rc=%s): %s",
                       rc, (e or "")[:200])
    return False, RENAME_UNCONFIRMED


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
    out, _, _ = _core.shell_as_game_user(server, user, _guarded(user, ap, inner), timeout=20)
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
    return _core.game_user_cmd(user, body)


def _local_download_argv(user, rel, ap, as_tar):
    """The argv that reads a download on the panel's own host AS THE GAME USER, or None if refused.

    The helper opens the file only after dropping supplementary groups, gid and uid
    to the game user, and redoes the containment check there — the same reasoning as
    game-backup-read. The fallback for a host that has no helper yet keeps the one
    property that matters, reading AS THE GAME USER, and stays an argv: no shell is
    involved on either branch, so the caller's path is never text anything parses.
    """
    if _core.helper_present():
        try:
            return _priv.helper_argv("game-dir-tar" if as_tar else "game-file-read", [user, rel])
        except _priv.VerbError:
            # Unreachable while `rel` is canonical and non-root, which stream_path guarantees —
            # but this feeds a GENERATOR, and an exception raised in one comes
            # out of the middle of a streaming response, where Flask can no longer turn
            # it into an error page. The browser would get a truncated file and a 200.
            # A refusal has to end the stream, not corrupt it.
            _core._log.debug("download: the helper refused the path", exc_info=True)
            return None
    if as_tar:
        return cron._as_user_argv(user, "tar", "czf", "-",
                                  "-C", _pp.dirname(ap), "--", _pp.basename(ap))
    return cron._as_user_argv(user, "cat", "--", ap)


def _ssh_download_argv(server, shell):
    """The `ssh` argv for a Tailscale-CLI remote's download, or None when its login is refused.

    The login and host are stored data handed to ssh as an argument — see
    _core.ssh_destination. A refusal ends the download empty, as a refused path does.
    """
    # ConnectTimeout: without it a host that stops answering mid-dial held the download, and its
    # green thread, for the kernel's TCP connect timeout. (No -n: this ssh carries the path on
    # stdin — see _remote_read_command.)
    try:
        return ["ssh", "-T", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=%d" % _core._ssh_connect_timeout(),
                "-p", _core._ssh_port_arg(server), _core.SSH_DEST_SEP,
                _core.ssh_destination(server.username, _core._resolve_ts_host(server)),
                shell]
    except (TypeError, ValueError):
        _core._log.warning("download: refusing the host's stored ssh login or address")
        return None


def _hand_path_to_ssh(p, feed):
    """Write the path to the ssh reader's stdin and close it, so the remote `cat` sees EOF."""
    try:
        p.stdin.write(feed)
        p.stdin.close()
    except OSError:
        # ssh died before it could take the path — a dead host, a refused key. The read in
        # _stream_argv then sees EOF and the download ends empty, which is what every other
        # unreachable-host path in this module does.
        _core._log.debug("download: could not hand the path to ssh", exc_info=True)


def _close_and_wait(p):
    """Close the reader's stdout and reap it. -> its exit status."""
    try:
        p.stdout.close()
    except Exception:  # nosec B110
        pass
    return p.wait()


def _stream_argv(argv, rel, chunk, ok=(0,)):
    """Yield the stdout of `argv` in `chunk`-sized blocks, handing the SSH form the path on stdin."""
    # stdin is a pipe only for the SSH form, which expects the path there. The local forms
    # take it in argv (helper) or already resolved (the pre-helper fallback), and get
    # DEVNULL -- never the panel's own stdin, which a helper verb would read to EOF.
    feed = rel.encode() if argv[0] == "ssh" else None
    p = subprocess.Popen(argv, stdout=subprocess.PIPE,  # nosec B603  # nosemgrep - argv list, no shell; argv[0] is a literal
                         stdin=subprocess.PIPE if feed is not None else subprocess.DEVNULL)
    if feed is not None:
        _hand_path_to_ssh(p, feed)
    at_eof, rc = False, None
    try:
        while True:
            b = p.stdout.read(chunk)
            if not b:
                at_eof = True
                break
            yield b
    finally:
        rc = _close_and_wait(p)
    # A reader that failed partway (the host dropped, the helper refused) used to end the stream
    # quietly, and the browser saved the truncated file under a 200. See _core.StreamFailed.
    if at_eof and rc not in ok:
        _core._log.warning("download: the reader exited %s — aborting the download", rc)
        raise _core.StreamFailed("download failed (exit %s)" % rc)


def _stream_paramiko(server, shell, rel, chunk, ok=(0,)):
    """Yield a paramiko remote's download — same fixed command, same path-on-stdin."""
    client = _core.get_connection(server)
    # An idle timeout, the channel closed however the stream ends, and the exit status checked at
    # EOF — see _core.stream_channel for what each of those cost when missing.
    # exec_bounded: the wait for the exec reply has a bound too, which exec_command lacks.
    _in, out, _err = _core.exec_bounded(client, shell, _core.STREAM_IDLE_TIMEOUT,
                                        _core.STREAM_IDLE_TIMEOUT)
    try:
        _in.write(rel)
        _in.flush()
        _in.channel.shutdown_write()   # the remote `cat` needs EOF before it will return
    except Exception:
        _core._log.debug("download: could not hand the path to the remote shell", exc_info=True)
    yield from _core.stream_channel(out, chunk, "download", ok=ok)


def _download_blocks(server, user, rel, ap, as_tar, chunk):
    """Yield the raw download bytes over whichever transport this host uses."""
    shell = _remote_read_command(user, as_tar)
    # The reader exit statuses that mean the download is whole: 0, and for an archive also 1 —
    # GNU tar exits 1 when a file changed while it was being read (a running server's live logs,
    # every time), and that archive is complete and valid.
    ok = (0, 1) if as_tar else (0,)
    if _core.is_local_server(server):
        argv = _local_download_argv(user, rel, ap, as_tar)
    elif getattr(server, "auth_method", "") == "tailscale":
        argv = _ssh_download_argv(server, shell)
    else:
        yield from _stream_paramiko(server, shell, rel, chunk, ok=ok)
        return
    if argv is None:
        return
    yield from _stream_argv(argv, rel, chunk, ok=ok)


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

    first, sent = True, 0
    for block in _download_blocks(server, user, rel, ap, as_tar, chunk):
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
