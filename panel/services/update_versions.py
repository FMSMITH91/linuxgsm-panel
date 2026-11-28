"""What an Updates row updates and which version it moves from and to, in plain words.

Every row of the Updates page opens with its kind and what it updates (row_title: "Game update: PaperMC",
"LinuxGSM update: ...", "Add-on update: B3"), then its two versions as two labelled lines ("Installed: ..." and
"Available: ..."). A version the panel does not know is said in words, never as a bare "?".

A GAME'S BUILDS are LinuxGSM's own "* Local build:" and "* Remote build:" lines (services/game_updates.parse), read
per updater family from LinuxGSM's modules (v26.6.0):
    update_pmc.sh (pmc Paper, vpmc Velocity, wmc Waterfall): "<version>-<build>", the version being the project's
        (Minecraft's for Paper) and the build PaperMC's number within it; "0" when build.txt is missing.
    update_mc.sh: version.json's id ("1.21.5", a pre-release "1.21.5-pre1", a release candidate "1.21.5-rc1", a
        snapshot "25w14a") and "* Branch: release" or "snapshot"; "0" when it could not read the jar.
    update_mcb.sh: the version the console log printed ("1.21.70.03"); "0" when none.
    core_steamcmd.sh: Steam's build ids and "* Branch: <b>".
    every other update_<game>.sh: its own local and remote strings, shown as printed.
The game's name is LinuxGSM's own (serverlist.csv's gamename for the server's shortname, the cached copy only:
opening the page fetches nothing), else the name the panel holds for the server.
"""
import re

from panel.core import i18n

# PaperMC's projects, by LinuxGSM shortname (update_pmc.sh's paperproject).
PAPER_PROJECTS = {"pmc": "Paper", "vpmc": "Velocity", "wmc": "Waterfall"}
_PAPER_RE = re.compile(r"(.{1,48})-([0-9]{1,9})")
_SNAPSHOT_RE = re.compile(r"[0-9]{2}w[0-9]{2}[a-z]")
_PRE_RE = re.compile(r".{1,40}-pre[0-9]{1,3}")
_RC_RE = re.compile(r".{1,40}-rc[0-9]{1,3}")
_UNREAD = ("", "0")

S_INSTALLED = "Installed: {version}"
S_AVAILABLE = "Available: {version}"
S_NOT_READ = "not known (LinuxGSM could not read the installed build)"
S_REMOTE_NOT_READ = "a newer build (LinuxGSM did not print which)"
S_PAPER = "Minecraft {version}, Paper build {build}"
S_PROXY = "{project} {version}, build {build}"
S_PAPER_SAME = "Same Minecraft version: a new Paper build (fixes). Players are not locked out."
S_PROXY_SAME = "Same {project} version: a new build (fixes). Players are not locked out."
S_PAPER_NEW = ("A new Minecraft version: players whose game is older cannot join until they update it, and plugins "
               "may need updating.")
S_PROXY_NEW = "A new {project} version: check that your proxy's plugins support it."
S_MC = "Minecraft {version}"
S_MC_SNAPSHOT = "Minecraft {version} (a snapshot: a test version)"
S_MC_PRE = "Minecraft {version} (a pre-release: a test version)"
S_MC_RC = "Minecraft {version} (a release candidate: a test version)"
S_MCB = "Minecraft Bedrock {version}"
S_MC_NEW = "A new Minecraft version: players whose game is older cannot join until they update it."
S_BUILD = "build {build}"
S_BUILD_BRANCH = "build {build} (branch {branch})"
WHY_PAPER_BUILD = ("Off by default for Minecraft servers. A new {project} build of the same version keeps every player "
                   "able to join, but can change how plugins behave.")


def _tr(sentence, **vals):
    return i18n.tr(i18n.Sentence(sentence, **vals)) if vals else i18n.tr(sentence)


def paper_split(build):
    """(version, build number) of a PaperMC build as LinuxGSM prints it ("26.3-257"), or None when it is not one."""
    m = _PAPER_RE.fullmatch(build or "")
    return (m.group(1), m.group(2)) if m else None


def _paper_label(project, parts):
    if project == "Paper":
        return _tr(S_PAPER, version=parts[0], build=parts[1])
    return _tr(S_PROXY, project=project, version=parts[0], build=parts[1])


def _paper(game_type, local, remote):
    """([installed, available], notes) of a Paper, Velocity or Waterfall server."""
    project = PAPER_PROJECTS[game_type]
    old, new = paper_split(local), paper_split(remote)
    have = _paper_label(project, old) if old else (local if local not in _UNREAD else _tr(S_NOT_READ))
    want = _paper_label(project, new) if new else (remote or _tr(S_REMOTE_NOT_READ))
    notes = []
    if old and new:
        if old[0] == new[0]:
            notes.append(_tr(S_PAPER_SAME) if project == "Paper" else _tr(S_PROXY_SAME, project=project))
        else:
            notes.append(_tr(S_PAPER_NEW) if project == "Paper" else _tr(S_PROXY_NEW, project=project))
    return [have, want], notes


def _mc_label(version, branch):
    """A Minecraft: Java Edition version, marked when it is a snapshot, a pre-release or a release candidate."""
    if branch == "snapshot" or _SNAPSHOT_RE.fullmatch(version):
        return _tr(S_MC_SNAPSHOT, version=version)
    if _PRE_RE.fullmatch(version):
        return _tr(S_MC_PRE, version=version)
    if _RC_RE.fullmatch(version):
        return _tr(S_MC_RC, version=version)
    return _tr(S_MC, version=version)


def _minecraft(game_type, local, remote, branch):
    """([installed, available], notes) of a vanilla Minecraft or Minecraft Bedrock server."""
    if game_type == "mc":
        have = _mc_label(local, branch) if local not in _UNREAD else _tr(S_NOT_READ)
        want = _mc_label(remote, branch) if remote else _tr(S_REMOTE_NOT_READ)
    else:
        have = _tr(S_MCB, version=local) if local not in _UNREAD else _tr(S_NOT_READ)
        want = _tr(S_MCB, version=remote) if remote else _tr(S_REMOTE_NOT_READ)
    known = local not in _UNREAD and remote
    return [have, want], ([_tr(S_MC_NEW)] if known and local != remote else [])


def _other(local, remote, branch, steam):
    """([installed, available], notes) of a Steam game (build ids) or another updater's own strings."""
    if steam:
        have = _tr(S_BUILD, build=local) if local not in _UNREAD else _tr(S_NOT_READ)
        if not remote:
            want = _tr(S_REMOTE_NOT_READ)
        else:
            want = _tr(S_BUILD_BRANCH, build=remote, branch=branch) if branch else _tr(S_BUILD, build=remote)
        return [have, want], []
    have = local if local not in _UNREAD else _tr(S_NOT_READ)
    return [have, remote or _tr(S_REMOTE_NOT_READ)], []


def game_versions(game_type, got, steam):
    """{"versions": [Installed line, Available line], "notes": [...]} of a game row (`got`: game_updates.seen).

    `steam`: the game updates through SteamCMD (game_updates.family). Every text is in the viewer's language.
    """
    gt = (game_type or "").lower()
    local, remote, branch = got.get("local") or "", got.get("remote") or "", got.get("branch") or ""
    if gt in PAPER_PROJECTS:
        pair, notes = _paper(gt, local, remote)
    elif gt in ("mc", "mcb"):
        pair, notes = _minecraft(gt, local, remote, branch)
    else:
        pair, notes = _other(local, remote, branch, steam)
    return {"versions": labelled(pair[0], pair[1]), "notes": notes}


def paper_same_version(game_type, got):
    """The PaperMC project's name when `got` moves a Paper/Velocity/Waterfall server to a new build of the SAME version.

    "" otherwise (another game, a new version, or a build LinuxGSM did not print in its usual shape).
    """
    gt = (game_type or "").lower()
    old, new = paper_split(got.get("local") or ""), paper_split(got.get("remote") or "")
    return PAPER_PROJECTS[gt] if gt in PAPER_PROJECTS and old and new and old[0] == new[0] else ""


def auto_reason(game_type, got, family_reason):
    """Why automatic updates are on or off for a game row, fitted to this update.

    The family's reason (game_updates.default_auto), except a new Paper, Velocity or Waterfall build of the same
    version: a new Minecraft release locks players out, a new build of the same one does not, so that row says so.
    The default itself never changes here.
    """
    project = paper_same_version(game_type, got)
    return _tr(WHY_PAPER_BUILD, project=project) if project else _tr(family_reason)


def labelled(installed, available):
    """[the "Installed: ..." line, the "Available: ..." line], each translated whole."""
    return [_tr(S_INSTALLED, version=installed), _tr(S_AVAILABLE, version=available)]


def game_name(game_type, fallback=""):
    """LinuxGSM's own name of a game (serverlist.csv's gamename, or a retired game's), else `fallback`, else the type.

    Reads the cached copy only, so the Updates page asks no outside service anything.
    """
    from panel.services import lgsm_data
    gt = (game_type or "").strip()
    for row in lgsm_data.serverlist(allow_fetch=False):
        if (row.get("shortname") or "").strip() == gt and (row.get("gamename") or "").strip():
            return row["gamename"].strip()
    retired = lgsm_data.RETIRED_GAMES.get(gt)
    return retired["gamename"] if retired else (fallback or gt)


# ── each row's title: its kind and what it updates ───────────────────────────────────────────────
S_TITLE_GAME = "Game update: {game}"
S_TITLE_LGSM = "LinuxGSM update: the scripts that run the server"
S_TITLE_PANEL = "Panel update"
S_TITLE_OS = "Host system update: packages"
S_TITLE_ADDON = "Add-on update: {addon}"
S_TITLE_SITE = "Website update: {kind}"
S_TITLE_APP = "Website app update: {app}"
# A website's kind, in the words the Websites page uses (static/js/websites_common.js WS.KIND).
SITE_KINDS = {"static": "Plain site", "php": "PHP site", "wordpress": "WordPress", "phpbb": "phpBB forum",
              "app": "Node.js app"}


def site_title(site):
    """A website row's title: the app it runs (an app site's recipe), else its kind."""
    if site.kind == "app" and site.app_recipe:
        return _tr(S_TITLE_APP, app=site.app_recipe)
    return _tr(S_TITLE_SITE, kind=_tr(SITE_KINDS.get(site.kind, "Website")))
