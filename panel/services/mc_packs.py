"""Minecraft: a Java server's datapacks, and a Bedrock server's behavior and resource packs.

JAVA (mc, pmc). A world's datapacks are the .zip files and folders in <world>/datapacks, the world
being the folder `level-name` in server.properties names (Minecraft Wiki, "Data pack": "placed in
the datapacks folder of a world"; Paper loads them the same way). Which folder that is, and whether
the start line could move it, is decided as the world reset decides it (services/world_reset.py:
level_name, java_pre_problem, mc_start_problem / pmc_start_problem, and Paper's bukkit.yml
world-container), so a pack is never put in a folder the server does not load. The server applies
datapacks when it loads the world, so a change applies at the next restart. Installing from
Modrinth is services/modrinth.py's datapack kind (the API's own file URL on its CDN, a size cap, the
sha512 checked) written into the datapacks folder without replacing a file; a vanilla server's
Minecraft version comes from version.json in minecraft_server.jar, read with `unzip -p` as
LinuxGSM's own update_mc.sh reads it, a Paper server's from version_history.json.

BEDROCK (mcb). Microsoft Learn, "Getting Started with Bedrock Dedicated Server": packs shared by
every world go in the behavior_packs and resource_packs folders at the top of the server, and
worlds/<level-name> is the world the server runs. Each pack folder has a manifest.json whose
header holds the pack's uuid and version ([major, minor, patch]). A world applies a pack when its
world_behavior_packs.json / world_resource_packs.json lists it as {"pack_id": <uuid>, "version":
[...]}. Turning a pack on adds that entry; off removes every entry with that uuid; every other entry
and key is kept. The world folder must exist (the server makes it on its first start). The level
name is read as the world reset reads it (bedrock_level_name), with its start-line check.

Everything the card shows comes from ONE command as the game account; a change is one more (the
file editor's write, upload or delete, each inside the home and never through a link out of it),
under the instance's config lock.
"""
import base64
import json
import re

from panel.ops.ssh_manager import _core as _smc, files as _smf
from panel.services import modrinth as _mr, world_reset as _wr

JAVA_GAMES = frozenset({"mc", "pmc"})
BEDROCK_GAMES = frozenset({"mcb"})
PACK_TYPES = {"behavior": "behavior_packs", "resource": "resource_packs"}
MAX_LISTED = 300
_FILE_MAX = 256 * 1024
# A datapack the card removes: what an install writes, and the names people give their own packs.
_DP_NAME = re.compile(r"[A-Za-z0-9_+()-][A-Za-z0-9 ._+()-]{0,127}\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_JAVA_KEYS = ["startparameters", "extraparams", "executabledir", "executable", "preexecutable"]
_MCB_KEYS = ["startparameters", "extraparams", "executabledir", "preexecutable"]
_B, _E = "__MCPK_B__", "__MCPK_E__"
# For each top folder of serverfiles ($w, named $n): its name, then its datapacks folder's entries.
_JAVA_WORLD_SH = ('printf "W %s\\n" "$n"; [ -d "$w/datapacks" ] && [ ! -L "$w/datapacks" ] || continue; '
                  'find -P "$w/datapacks" -mindepth 1 -maxdepth 1 \\( -type f -o -type d \\) ! -name "*[[:cntrl:]]*" '
                  "-printf 'E %y %s %f\\n' 2>/dev/null | head -n " + str(MAX_LISTED) + "; ")

UNREAD = "Couldn't read this server's packs — the host didn't answer. Nothing was changed."
NO_WORLD = "The panel can't tell which world folder this server uses: {why}. Nothing was changed."
NOT_A_PACK = "That isn't one of this world's packs. Refresh the list and pick again."
NO_WORLD_DIR = ("The world folder isn't there yet: the server makes it the first time it starts. "
                "Start the server once, then turn packs on here.")
BAD_WORLD_FILE = "The world's pack list isn't the list Bedrock writes, so the panel won't change it."
EXISTS = "A file named {name} is already in the datapacks folder. Remove it first to install this build."
REASONS = (UNREAD, NOT_A_PACK, NO_WORLD_DIR, BAD_WORLD_FILE)


def kind(game_type):
    """The kind of card a game gets: "java" (datapacks), "bedrock" (packs) or ""."""
    g = (game_type or "").lower()
    return "java" if g in JAVA_GAMES else ("bedrock" if g in BEDROCK_GAMES else "")


# ── the one read ────────────────────────────────────────────────────────────────────────────────
def _sf_sh(user):
    """Shell setting $sf to serverfiles when it resolves inside the home, else ""."""
    home = _smc._quote("/home/%s" % user)
    return ("h=$(cd -P -- %s 2>/dev/null && pwd -P) || h=; " % home
            + "sf=$(cd -P -- %s/serverfiles 2>/dev/null && pwd -P) || sf=; " % home
            + 'case "$sf" in "$h"/?*) [ -n "$h" ] || sf= ;; *) sf= ;; esac; ')


def _file_sh(tag, path):
    """Shell printing `tag`, then the file at `path` (a shell word) as base64, or N when it is not a plain file."""
    return ("printf '\\n%s ' %s; if [ -n \"$sf\" ] && [ -f %s ] && [ ! -L %s ]; then head -c %d %s | base64 | "
            "tr -d '\\n'; else printf N; fi; printf '\\n'; " % ("%s", tag, path, path, _FILE_MAX, path))


def java_sh(user):
    """Shell for a Java server: server.properties, bukkit.yml, the version files, each world's datapacks."""
    return (_sf_sh(user) + "printf '%s\\n' " + _B + "; "
            + _file_sh("F:props", '"$sf/server.properties"') + _file_sh("F:bukkit", '"$sf/bukkit.yml"')
            + _file_sh("F:paper", '"$sf/version_history.json"')
            + "printf 'F:vanilla '; [ -n \"$sf\" ] && unzip -p \"$sf/minecraft_server.jar\" version.json 2>/dev/null "
            "| head -c %d | base64 | tr -d '\\n'; printf '\\n'; " % _FILE_MAX
            # Paper's jar carries the same version.json: read when version_history.json is not written.
            + "printf 'F:paperjar '; [ -n \"$sf\" ] && unzip -p \"$sf/paper.jar\" version.json 2>/dev/null "
            "| head -c %d | base64 | tr -d '\\n'; printf '\\n'; " % _FILE_MAX
            + '[ -n "$sf" ] && { ' + _dirs_sh('"$sf"', "w", _JAVA_WORLD_SH) + "}; "
            + "printf '%s\\n' " + _E)


def _dirs_sh(parent, var, body):
    """Shell running `body` for each real folder in `parent` (a shell word), its path in $<var> and name in $n.

    A link, a name holding a control character and the glob's own text when nothing matches are
    skipped; at most MAX_LISTED folders.
    """
    return ('c=0; for %s in %s/*/; do %s=${%s%%/}; n=${%s##*/}; [ -d "$%s" ] && [ ! -L "$%s" ] || continue; '
            'case "$n" in *[[:cntrl:]]*) continue ;; esac; c=$((c+1)); [ "$c" -le %d ] || break; %s done; '
            % (var, parent, var, var, var, var, var, MAX_LISTED, body))


def bedrock_sh(user):
    """Shell for a Bedrock server: server.properties, each shared pack's manifest, each world's two pack lists."""
    packs = "".join(
        '[ -n "$sf" ] && [ -d "$sf/%s" ] && [ ! -L "$sf/%s" ] && { %s }; ' % (folder, folder, _dirs_sh(
            '"$sf/%s"' % folder, "p", "printf 'P %s %%s\\n' \"$n\"; " % t
            + _file_sh("M:" + t, '"$p/manifest.json"'))) for t, folder in PACK_TYPES.items())
    worlds = ('[ -n "$sf" ] && [ -d "$sf/worlds" ] && [ ! -L "$sf/worlds" ] && { '
              + _dirs_sh('"$sf/worlds"', "w", "printf 'W %s\\n' \"$n\"; "
                         + "".join(_file_sh("J:%s" % t, '"$w/world_%s_packs.json"' % t) for t in PACK_TYPES))
              + "}; ")
    return (_sf_sh(user) + "printf '%s\\n' " + _B + "; "
            + _file_sh("F:props", '"$sf/server.properties"') + packs + worlds + "printf '%s\\n' " + _E)


def _b64(text):
    """A file's text from its base64, "" for N (not there), None when it is not valid base64 or UTF-8."""
    text = text.strip()
    if text == "N":
        return ""
    try:
        return base64.b64decode(text, validate=True).decode("utf-8")
    except ValueError:
        return None


def _frame(out):
    """The lines between the read's marks, or None when the read did not run to the end."""
    body = out or ""
    i, j = body.find(_B), body.find(_E)
    return None if i == -1 or j < i else body[i + len(_B):j].split("\n")


def parse_java(out):
    """{"files": {tag: text}, "worlds": {name: [entries]}} from java_sh's output, or None."""
    lines = _frame(out)
    if lines is None:
        return None
    files, worlds, world = {}, {}, None
    for line in lines:
        head, _, rest = line.partition(" ")
        if head.startswith("F:"):
            files[head[2:]] = _b64(rest)
        elif head == "W":
            world = rest
            worlds[world] = []
        elif head == "E" and world is not None:
            entry = _java_entry(rest)
            if entry:
                worlds[world].append(entry)
    return {"files": files, "worlds": worlds}


def _java_entry(rest):
    """One datapacks entry: {"name", "folder", "size", "managed"}, or None."""
    kind_, size, name = (rest.split(" ", 2) + ["", ""])[:3]
    if kind_ not in ("f", "d") or not size.isdecimal() or not name:
        return None
    return {"name": name, "folder": kind_ == "d", "size": int(size), "managed": removable(name)}


def removable(name):
    """Whether `name` is a datapack the card may remove: a plain name, no path, never `.` or `..`."""
    return isinstance(name, str) and bool(_DP_NAME.match(name)) and ".." not in name and name == name.strip()


def parse_bedrock(out):
    """{"props": text, "packs": [{type, folder, manifest text}], "worlds": {name: {type: text}}}, or None."""
    lines = _frame(out)
    if lines is None:
        return None
    got = {"props": None, "packs": [], "worlds": {}}
    world = None
    for line in lines:
        head, _, rest = line.partition(" ")
        if head == "F:props":
            got["props"] = _b64(rest)
        elif head == "P":
            t, _, folder = rest.partition(" ")
            got["packs"].append({"type": t, "folder": folder, "manifest": ""})
        elif head.startswith("M:") and got["packs"]:
            got["packs"][-1]["manifest"] = _b64(rest)
        elif head == "W":
            world = rest
            got["worlds"][world] = {}
        elif head.startswith("J:") and world is not None:
            got["worlds"][world][head[2:]] = _b64(rest)
    return got


def _texts_and(server, user, selfname, sh):
    """(config texts, out) of the config read and `sh` as one command, or None."""
    if not _smc.game_idents_ok(user, selfname):
        return None
    out, _, _ = _smc.shell_as_game_user(server, user, _smf.lgsm_cfg_texts_sh(user, selfname) + sh,
                                        timeout=30, selfname=selfname)
    texts = _smf.lgsm_cfg_texts_from(out)
    return None if texts is None else (texts, out)


# ── Java datapacks ──────────────────────────────────────────────────────────────────────────────
def java_world(texts, files, game_type):
    """The world folder a Java server loads: (name, None), or (None, why)."""
    why = _java_start_problem(texts, game_type) or _java_files_problem(files, game_type)
    if why is not None:
        return None, why
    name, why = _wr.level_name(files.get("props") or "")
    if name is not None and name.lower() in _wr._WWR_JAVA_SERVER_DIRS:
        name, why = None, "level-name names one of the server's own folders"
    return name, why


def _java_start_problem(texts, game_type):
    """Why the LinuxGSM config may move the world (as the world reset judges it), else None."""
    values, why = _wr.cfg_values(texts, _JAVA_KEYS)
    if why is not None:
        return why
    judge = _wr.pmc_start_problem if game_type == "pmc" else _wr.mc_start_problem
    return _wr.java_pre_problem(values.get("preexecutable") or "", judge) or judge(values)


def _java_files_problem(files, game_type):
    """Why server.properties (or, for Paper, bukkit.yml) does not settle the world folder, else None."""
    if files.get("props") is None:
        return "server.properties could not be read"
    if game_type != "pmc":
        return None
    if files.get("bukkit") is None:
        return "bukkit.yml could not be read"
    return _wr.bukkit_problem(files.get("bukkit") or "")


def _jar_id(text):
    """The "id" of a server jar's version.json text, or None."""
    try:
        data = json.loads(text or "")
    except ValueError:
        data = None
    return data.get("id") if isinstance(data, dict) else None


def java_mc_version(files, game_type):
    """The server's Minecraft release (N.N or N.N.N), or None when it cannot be told.

    Paper: its version_history.json, else the version.json inside paper.jar (a build that writes no
    version_history.json, seen on the test host with Paper 26.3-249).
    """
    if game_type == "pmc":
        v = _mr.paper_mc_version(files.get("paper") or "") or _jar_id(files.get("paperjar"))
    else:
        v = _jar_id(files.get("vanilla"))
    return v if _mr.valid_mc_version(v) else None


def read_java(server, user, selfname, game_type):
    """The datapack card's state, or None when the host did not answer.

    {"world": name | None, "why": "" | why, "datapacks": [...], "world_dir": bool, "mc_version": str | None,
    "dir": "serverfiles/<world>/datapacks" | ""}.
    """
    got = _texts_and(server, user, selfname, java_sh(user))
    parsed = parse_java(got[1]) if got else None
    if parsed is None:
        return None
    world, why = java_world(got[0], parsed["files"], game_type)
    packs = parsed["worlds"].get(world, []) if world else []
    return {"world": world, "why": str(why or ""), "datapacks": sorted(packs, key=lambda p: p["name"].lower()),
            "world_dir": bool(world) and world in parsed["worlds"],
            "mc_version": java_mc_version(parsed["files"], game_type),
            "dir": "serverfiles/%s/datapacks" % world if world else ""}


def remove_target(state, name):
    """The path (relative to the home) of datapack `name` in `state`'s world, or None when it is not one."""
    if not state or not state.get("world") or not removable(name):
        return None
    if name not in {p["name"] for p in state["datapacks"]}:
        return None
    return "%s/%s" % (state["dir"], name)


# ── Bedrock packs ───────────────────────────────────────────────────────────────────────────────
def manifest_header(text):
    """(uuid, version list, name) from a manifest.json's text, or None when it does not read as one."""
    try:
        data = json.loads(text or "")
    except ValueError:
        return None
    header = data.get("header") if isinstance(data, dict) else None
    if not isinstance(header, dict) or not _valid_header(header.get("uuid"), header.get("version")):
        return None
    name = header.get("name") if isinstance(header.get("name"), str) else ""
    return header["uuid"].lower(), header["version"], name[:100]


def _valid_header(uuid, version):
    """Whether a manifest header's uuid is a UUID and its version three whole numbers."""
    return (isinstance(uuid, str) and bool(_UUID.match(uuid)) and isinstance(version, list) and len(version) == 3
            and all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in version))


def world_list(text):
    """A world_*_packs.json's entries ("" or missing: []), or None when it is not a JSON list."""
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, list) else None


def _on_ids(entries):
    """The pack ids a world list turns on, lower-cased."""
    return {str(e.get("pack_id", "")).lower() for e in (entries or []) if isinstance(e, dict)}


def bedrock_world(texts, props):
    """The world folder Bedrock runs: (name, None), or (None, why)."""
    values, why = _wr.cfg_values(texts, _MCB_KEYS)
    why = why or _wr.mcb_start_problem(values)
    if why is None and props is None:
        why = "server.properties could not be read"
    if why is not None:
        return None, why
    return _wr.bedrock_level_name(props or "")


def bedrock_rows(packs, lists):
    """The card's rows: each pack with a readable manifest, and whether the world turns it on."""
    rows = []
    for p in packs:
        if p["type"] not in PACK_TYPES:
            continue
        head = manifest_header(p["manifest"]) if p["manifest"] else None
        on = _on_ids(lists.get(p["type"])) if lists.get(p["type"]) is not None else set()
        rows.append({"type": p["type"], "folder": p["folder"], "uuid": head[0] if head else "",
                     "version": head[1] if head else [], "name": head[2] if head else "",
                     "enabled": bool(head) and head[0] in on, "ok": bool(head)})
    return sorted(rows, key=lambda r: (r["type"], r["folder"].lower()))


def _bedrock_state(server, user, selfname):
    """(world, why, rows, the world's lists or None, world folder exists), or None when the read failed."""
    got = _texts_and(server, user, selfname, bedrock_sh(user))
    parsed = parse_bedrock(got[1]) if got else None
    if parsed is None:
        return None
    world, why = bedrock_world(got[0], parsed["props"])
    raw = parsed["worlds"].get(world) if world else None
    lists = {t: world_list(raw.get(t, "")) if raw.get(t) is not None else None for t in PACK_TYPES} if raw else {}
    return world, why, bedrock_rows(parsed["packs"], lists), lists, raw is not None


def read_bedrock(server, user, selfname):
    """The pack card's state, or None. {"world", "why", "packs", "world_dir", "bad_lists"}."""
    state = _bedrock_state(server, user, selfname)
    if state is None:
        return None
    world, why, rows, lists, has_dir = state
    return {"world": world, "why": str(why or ""), "packs": rows, "world_dir": has_dir,
            "bad_lists": [t for t in PACK_TYPES if has_dir and lists.get(t) is None]}


def _bedrock_refusal(state, pack_type, uuid):
    """(why, None) when the change is refused, else (None, the pack's row)."""
    world, why, rows, lists, has_dir = state
    if why or not world:
        return _smf_sentence(NO_WORLD, why), None
    row = next((r for r in rows if r["type"] == pack_type and r["ok"] and r["uuid"] == str(uuid).lower()), None)
    if row is None:
        return NOT_A_PACK, None
    if not has_dir:
        return NO_WORLD_DIR, None
    if lists.get(pack_type) is None:
        return BAD_WORLD_FILE, None
    return None, row


def _smf_sentence(text, why):
    from panel.core import i18n
    return i18n.Sentence(text, why=str(why or "no level-name"))


def with_pack(entries, row, enabled):
    """A world list with the pack's entries removed, then (turning it on) one appended: other entries kept."""
    kept = [e for e in entries if not (isinstance(e, dict) and str(e.get("pack_id", "")).lower() == row["uuid"])]
    if enabled:
        present = [e for e in entries if e not in kept]
        kept.append(present[0] if present else {"pack_id": row["uuid"], "version": row["version"]})
    return kept


def set_pack(server, user, selfname, pack_type, uuid, enabled):
    """Turn one shared pack on or off for the server's world. -> (ok, why, changed, label)."""
    if pack_type not in PACK_TYPES:
        return False, NOT_A_PACK, False, ""
    with _smc.lgc_config_lock(server, user, selfname):
        state = _bedrock_state(server, user, selfname)
        if state is None:
            return False, UNREAD, False, ""
        why, row = _bedrock_refusal(state, pack_type, uuid)
        if why:
            return False, why, False, ""
        label = "%s %s (%s)" % (pack_type, row["folder"], row["uuid"])
        entries = state[3][pack_type]
        new = with_pack(entries, row, enabled)
        if new == entries:
            return True, "", False, label
        rel = "serverfiles/worlds/%s/world_%s_packs.json" % (state[0], pack_type)
        ok, msg = _smf.write_file(server, user, rel, json.dumps(new, indent="\t") + "\n", selfname=selfname)
        return ok, ("" if ok else msg), ok, label
