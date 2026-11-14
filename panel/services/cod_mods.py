"""Which games have a Mods tab, and the Call of Duty mod folder switch.

LINUXGSM'S MODS INSTALLER (mods-install / mods-remove / mods-update) is offered by LinuxGSM's
lgsm/modules/core_getopt.sh ("## Mods commands") only when the game's `engine` is "source", or its
shortname is cs2, rust, hq, sdtd, cs, dod, tfc, ns, ts, hldm or vh (LinuxGSM master 98be8a98,
2026-11-13). "hq" is in that test and in no LinuxGSM game (lgsm/data/serverlist.csv), so it is not
listed here. The "source" games are the 30 whose lgsm/config-default/config-lgsm/<game>server/
_default.cfg says engine="source". Every other game answers "Unknown command" to mods-install, so
the panel shows no LinuxGSM mods card for it.

CALL OF DUTY (cod, coduo, cod2, cod4, codwaw) has no LinuxGSM installer, but the game loads a mod
itself: the server is started with `+set fs_game <folder>`, a folder the engine looks for under
fs_basepath (and fs_homepath), and loads that folder's .pk3/.iwd (and CoD4/WaW's mod.ff) on top of
the base game. LinuxGSM starts every CoD server with `+set fs_basepath ${serverfiles}` in
`startparameters` (CoD4 also sets fs_homepath to the same folder), and keeps no fs_game setting of
its own. So switching the mod is one token in `startparameters`, which this module edits.

Where the folders are, per game:
* cod4, codwaw: "mods/<name>" only. The engine looks for a mod in the `mods` folder, and LinuxGSM's
  Call of Duty 4 guide (docs.linuxgsm.com/game-servers/call-of-duty-4) sets `+set fs_game
  "mods/<name>"`.
* cod2: "mods/<name>" (the form LinuxGSM cod2server guides use), and a folder directly in serverfiles
  that holds an .iwd, the older form.
* cod, coduo: a folder directly in serverfiles that holds a .pk3 (fs_game "awe", not "mods/awe"):
  the classic layout of Call of Duty 1 and United Offensive mods.
The base game's own folders (main, and uo for United Offensive) are never a mod.

A CoD1 server loads its game module (game.mp.i386.so, which LinuxGSM installs in main/) from the
fs_game folder only: started with a folder that holds just .pk3 files, it stops at
"Sys_Error: Sys_LoadDll(game) failed" (measured on a LinuxGSM codserver, 2026-11-14), and a mod
folder works once that file is copied into it. So when the base game's folders hold a
game.mp*.so, a top folder without a file of each of those names is listed as missing it, and the
switch refuses it: the server would not start.

Players get the mod's files from the server when its game config allows downloads (sv_allowDownload,
or sv_wwwDownload with sv_wwwBaseURL for a web redirect); the card says so and does not change those.

THE EDIT goes through the same steps as every other LinuxGSM config write (ssh_manager/files.py
lgsm_write_config): under the instance cfg's lock, from a framed read that aborts when it did not
happen, written atomically with the file's mode kept and the live console's log refused. It is a
text edit of the one `startparameters` line rather than a key=value rewrite, so nothing else in the
line changes (CoD4's `+set sv_authorizemode "-1"` keeps its quotes), and switching back to "none"
removes a line the switch added: the instance cfg reads back byte for byte as it was.
"""
import re

from panel.ops.ssh_manager import _core as _smc, files as _smf

# lgsm/config-default/config-lgsm/*/_default.cfg with engine="source" (LinuxGSM master 98be8a98).
_LGSM_SOURCE_ENGINE = frozenset({
    "ahl2", "bb2", "bmdm", "bs", "cc", "csgo", "css", "dab", "doi", "dods", "dys", "em", "fof", "gmod",
    "hl2dm", "hldms", "ins", "ios", "jbep3", "l4d", "l4d2", "mcv", "nd", "nmrih", "pvkii", "sfc", "tf2",
    "tf2c", "zmr", "zps",
})
# ...and the shortnames core_getopt.sh names besides the engine.
LGSM_MODS_GAMES = _LGSM_SOURCE_ENGINE | frozenset({
    "cs2", "rust", "sdtd", "cs", "dod", "tfc", "ns", "ts", "hldm", "vh",
})

# Per CoD game: the pack extension that makes a folder directly in serverfiles a mod ("" for none),
# and whether serverfiles/mods/<name> folders are offered.
_COD = {
    "cod": (".pk3", False),
    "coduo": (".pk3", False),
    "cod2": (".iwd", True),
    "cod4": ("", True),
    "codwaw": ("", True),
}
COD_GAMES = frozenset(_COD)
# The base game's folders, and the mods folder itself: never a mod of their own.
_NOT_A_MOD = frozenset({"main", "uo", "mods"})
# A mod folder's name: what the listing passes (find's `! -name` below keeps the rest out) and what a
# switch accepts. No separators, no leading dot, so never "." or ".." or a hidden folder.
_NAME = r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}"
_NAME_RE = re.compile(_NAME + r"\Z")
_VALUE_RE = re.compile(r"(?:mods/)?" + _NAME + r"\Z")
# At most this many folders are listed (a mods folder is a handful).
_MAX_LISTED = 200

# What a byte the config file holds that is not UTF-8 reads as: such a file is not rewritten.
_UNDECODABLE = chr(0xFFFD)
_LIST_B, _LIST_E = "__CODM_LIST_B__", "__CODM_LIST_E__"

# `+set fs_game <value>` as the server receives it (a parsed, merged value) and as a cfg file spells
# it (raw text, where the value may be "quoted" or \"escaped\" inside the line's double quotes).
_FSG_VALUE = r'(?:\\?"[^"\s]*\\?"|[^\s"]+)'
_FSG_RE = re.compile(r"\+set\s+fs_game\s+(" + _FSG_VALUE + ")")
_FSG_RAW_MID = re.compile(r"\+set[ \t]+fs_game[ \t]+" + _FSG_VALUE + r"[ \t]+")
_FSG_RAW_END = re.compile(r"[ \t]*\+set[ \t]+fs_game[ \t]+" + _FSG_VALUE)
_SP_LINE = re.compile(r"^\s*startparameters\s*=(.*)\Z")

# Why a switch was not made. Whole sentences, translated by the route.
UNREAD = "Couldn't read this server's config and mod folders — the host didn't answer. Nothing was changed."
NOT_A_MOD = "That folder isn't one of this server's mods. Refresh the list and pick again."
IN_EXTRAPARAMS = ("This server's fs_game is set in extraparams, which LinuxGSM adds after startparameters. "
                  "Change it there in the LinuxGSM config — nothing has been changed.")
IN_SECRETS = ("startparameters is set in this server's secrets file, which LinuxGSM reads last. "
              "Change the mod there — nothing has been changed.")
NOT_PLAIN = ("This server's startparameters isn't one plain double-quoted line, so the panel won't edit it. "
             "Change fs_game in the LinuxGSM config — nothing has been changed.")
NO_GAME_MODULE = ("That mod folder has no copy of the game's server module (the game.mp*.so file in main), and "
                  "the server won't start with it. Copy that file into the mod folder, then pick it again — "
                  "nothing has been changed.")
REASONS = (UNREAD, NOT_A_MOD, IN_EXTRAPARAMS, IN_SECRETS, NOT_PLAIN, NO_GAME_MODULE)


def mods_kind(game_type):
    """The Mods tab a game gets: "lgsm" (LinuxGSM's installer), "cod" (the fs_game switch) or ""."""
    gt = (game_type or "").lower()
    if gt in LGSM_MODS_GAMES:
        return "lgsm"
    if gt in COD_GAMES:
        return "cod"
    return ""


def upload_dir(game_type):
    """The folder (relative to the account's home) a mod is uploaded into for this CoD game."""
    return "serverfiles/mods" if _COD.get(game_type, ("", True))[1] else "serverfiles"


def list_sh(user, game_type):
    """Shell listing the mod folders of `user`'s serverfiles: "M <name>" for mods/<name>, "T <name>" for a top folder.

    serverfiles must resolve inside the home (no link out of it), and nothing is followed through a
    link: find -P lists real folders only, and a `mods` that is a link is not looked in. A top
    folder that lacks one of the base game's game.mp*.so files also gets "X <name>".
    """
    ext, sub = _COD[game_type]
    home = _smc._quote("/home/%s" % user)
    safe = "! -name '*[!A-Za-z0-9._-]*' ! -name '.*'"
    sh = ("h=$(cd -P -- %s 2>/dev/null && pwd -P) || h=; " % home
          + "sf=$(cd -P -- %s/serverfiles 2>/dev/null && pwd -P) || sf=; " % home
          + 'case "$sf" in "$h"/?*) [ -n "$h" ] || sf= ;; *) sf= ;; esac; '
          + "printf '%s\\n' " + _LIST_B + "; ")
    if sub:
        sh += ('[ -n "$sf" ] && [ -d "$sf/mods" ] && [ ! -L "$sf/mods" ] && { printf "D\\n"; '
               'find -P "$sf/mods" -mindepth 1 -maxdepth 1 -type d %s -printf "M %%f\\n" 2>/dev/null '
               "| head -n %d; }; " % (safe, _MAX_LISTED))
    if ext:
        pat = "".join("[%s%s]" % (c.lower(), c.upper()) if c.isalpha() else c for c in ext)
        sh += ('bm=; [ -n "$sf" ] && for f in "$sf"/main/game.mp*.so "$sf"/uo/game.mp*.so; do '
               '[ -f "$f" ] && bm="$bm ${f##*/}"; done; '
               '[ -n "$sf" ] && bm="$bm" find -P "$sf" -mindepth 1 -maxdepth 1 -type d %s -exec sh -c '
               '\'for d; do for f in "$d"/*%s; do [ -f "$f" ] && { printf "T %%s\\n" "${d##*/}"; '
               'for m in $bm; do [ -f "$d/$m" ] || { printf "X %%s\\n" "${d##*/}"; break; }; done; break; }; '
               "done; done' x {} + 2>/dev/null | head -n %d; " % (safe, pat, 2 * _MAX_LISTED))
    return sh + "printf '%s\\n' " + _LIST_E


def _parse_listing(out):
    """(mods, mods folder exists) from list_sh's output, or None when its frame is missing."""
    body = out or ""
    i, j = body.find(_LIST_B), body.find(_LIST_E)
    if i == -1 or j < i:
        return None
    lines = body[i + len(_LIST_B):j].splitlines()
    mods = {}
    for line in lines:
        mod = _listed_mod(line)
        if mod is not None:
            mods.setdefault(mod["value"], mod)
    for line in lines:
        kind, _, name = line.strip().partition(" ")
        if kind == "X" and name in mods:
            mods[name]["no_module"] = True
    has_dir = any(line.strip() == "D" for line in lines)
    return sorted(mods.values(), key=lambda m: m["value"].lower()), has_dir


def _listed_mod(line):
    """One list_sh line as {"value", "name"}, or None for anything that is not a mod folder."""
    kind, _, name = line.strip().partition(" ")
    if kind not in ("M", "T") or not _NAME_RE.match(name):
        return None
    if kind == "T" and name.lower() in _NOT_A_MOD:
        return None
    return {"value": "mods/" + name if kind == "M" else name, "name": name}


def _merged(texts):
    """The five config texts merged as linuxgsm.sh sources them."""
    merged = {}
    for t in texts:
        merged.update(_smf._parse_cfg(t))
    return merged


def fs_game_of(params):
    """The fs_game a start line gives the server ("" for none): the last `+set fs_game`, unquoted."""
    found = _FSG_RE.findall(params or "")
    return found[-1].replace("\\", "").strip('"') if found else ""


def read(server, user, selfname, game_type):
    """The CoD mods card's state in ONE command, or None when the host did not answer.

    {"mods": [{"value", "name"}], "active": fs_game value, "where": "" | "extraparams" | "secrets",
    "mods_dir": whether serverfiles/mods exists}.
    """
    state = _read_state(server, user, selfname, game_type)
    if state is None:
        return None
    texts, mods, has_dir = state
    merged = _merged(texts)
    return {"mods": mods, "active": fs_game_of(merged.get("startparameters", "") + " "
                                               + merged.get("extraparams", "")),
            "where": _locked_where(texts, merged), "mods_dir": has_dir}


def _read_state(server, user, selfname, game_type):
    """(config texts, mods, mods folder exists) from one command as the account, or None."""
    if game_type not in _COD or not _smc.game_idents_ok(user, selfname):
        return None
    sh = _smf.lgsm_cfg_texts_sh(user, selfname) + list_sh(user, game_type)
    out, _, _ = _smc.shell_as_game_user(server, user, sh, timeout=30, selfname=selfname)
    texts = _smf.lgsm_cfg_texts_from(out)
    listing = _parse_listing(out)
    if texts is None or listing is None:
        return None
    return (texts,) + listing


def _locked_where(texts, merged):
    """Where the start line is held so the panel must not switch it: "extraparams", "secrets" or ""."""
    if _FSG_RE.search(merged.get("extraparams", "")):
        return "extraparams"
    if "startparameters" in _smf._parse_cfg(texts[4]):
        return "secrets"
    return ""


def _raw_rhs(text):
    """The right-hand side of the last uncommented startparameters line in `text`, or None."""
    rhs = None
    for line in (text or "").split("\n"):
        m = _SP_LINE.match(line)
        if m:
            rhs = m.group(1)
    return rhs


def with_fs_game(rhs, value):
    """A startparameters right-hand side with its fs_game set to `value` ("" removes it); None if not plain.

    Only a single "…" value is edited. `+set fs_game <value>` goes first in it, where the engine
    reads its +set lines before anything else runs.
    """
    body = (rhs or "").strip()
    if len(body) < 2 or body[0] != '"' or body[-1] != '"':
        return None
    body = _FSG_RAW_END.sub("", _FSG_RAW_MID.sub("", body))
    if value:
        body = '"+set fs_game %s%s%s' % (value, " " if len(body) > 2 else "", body[1:])
    return body


def _inherited_rhs(texts):
    """The start line _default.cfg, common.cfg and secrets-common.cfg give (the last one that sets it), or None."""
    inherited = None
    for t in texts[:3]:
        r = _raw_rhs(t)
        inherited = r if r is not None else inherited
    return inherited


def _with_line(inst, new):
    """The instance cfg's text with every startparameters line set to `new`, or `new` appended."""
    lines, found = inst.split("\n"), False
    for n, ln in enumerate(lines):
        m = _SP_LINE.match(ln)
        if m:
            lines[n], found = ln[:m.start(1)] + new, True
    if found:
        return "\n".join(lines)
    sep = "" if not inst or inst.endswith("\n") else "\n"
    return inst + sep + "startparameters=" + new + "\n"


def new_instance_text(texts, value):
    """(the instance cfg's new text, None) or (None, why not)."""
    inherited, inst = _inherited_rhs(texts), texts[3]
    own = _raw_rhs(inst)
    new = with_fs_game(own if own is not None else inherited, value)
    if new is None or _UNDECODABLE in inst:
        return None, NOT_PLAIN
    if inherited is not None and new == inherited.strip():
        # The line now says what the files LinuxGSM reads first already say: take it out.
        return "\n".join(ln for ln in inst.split("\n") if not _SP_LINE.match(ln)), None
    return _with_line(inst, new), None


def switch(server, user, selfname, game_type, value):
    """Start the server with mod folder `value` ("" for none) from now on. -> (ok, why, changed, before).

    Read (one command) and write (one command) under the instance cfg's lock, so a settings save
    cannot land between them. `value` must be a folder the read listed, or "". `before` is the fs_game
    the read found ("" when it found none or did not answer); `why` is one of REASONS, or the write's
    own answer when the write failed.
    """
    if value and not _VALUE_RE.match(value):
        return False, NOT_A_MOD, False, ""
    with _smc.lgc_config_lock(server, user, selfname):
        state = _read_state(server, user, selfname, game_type)
        if state is None:
            return False, UNREAD, False, ""
        texts, mods, _has_dir = state
        merged = _merged(texts)
        before = fs_game_of(merged.get("startparameters", "") + " " + merged.get("extraparams", ""))
        why = _switch_refusal(texts, merged, mods, value)
        text = None
        if not why:
            text, why = new_instance_text(texts, value)
        if why:
            return False, why, False, before
        if text == texts[3]:
            return True, "", False, before
        inst = "%s/%s.cfg" % (_smf._lgsm_cfg_dir(user, selfname), selfname)
        ok, msg = _smf._write_file_as_user(server, user, inst, text.encode(), selfname)
        return ok, ("" if ok else msg), ok, before


def _switch_refusal(texts, merged, mods, value):
    """Why switching to `value` is refused before anything is written, or ""."""
    listed = {m["value"]: m for m in mods}
    if value and value not in listed:
        return NOT_A_MOD
    if value and listed[value].get("no_module"):
        return NO_GAME_MODULE
    where = _locked_where(texts, merged)
    if where:
        return IN_EXTRAPARAMS if where == "extraparams" else IN_SECRETS
    return ""
