"""SSH connection manager for remote LinuxGSM servers.
Also supports local execution for running on the panel's own machine."""
import re
from panel.ops.ssh_manager import (_core)  # noqa: E402,F401  (module objects: the
# reference resolves at CALL time, which is what keeps a stub on the definition site
# visible to every caller — see the package docstring.



# ── GMod mountable game content ────────────────────────────────────────────────────────────────
# Garry's Mod renders another Source game's maps/props only if that game's content is present AND
# mounted. We keep ONE shared copy per host under a "content user" and mount it read-only into each
# GMod server via garrysmod/cfg/mount.cfg (+ mountdepots.txt), so multiple GMod servers share it
# instead of each carrying gigabytes. Content is fetched with SteamCMD using the game's dedicated-
# content app id. Counter-Strike: Source is the essential one (the vast majority of GMod maps/addons
# expect it); more can be added to this map later.
GMOD_CONTENT_GAMES = {
    # mount-folder -> (label, LinuxGSM game name or None). We install content the same way a normal
    # LinuxGSM content box does — one shared content user with each game installed via LinuxGSM (so
    # SteamCMD, validation and a weekly `update` cron all come for free). A game NAME means the panel
    # can install it; None means MOUNT-ONLY: an owned single-player title with no LinuxGSM dedicated
    # server, mounted only when its content is already on the host.
    "cstrike":    ("Counter-Strike: Source", "cssserver"),
    "tf":         ("Team Fortress 2", "tf2server"),
    "dod":        ("Day of Defeat: Source", "dodsserver"),
    "hl2mp":      ("Half-Life 2: Deathmatch", "hl2dmserver"),
    "hl1mp":      ("Half-Life Deathmatch: Source", "hldmsserver"),
    "left4dead":  ("Left 4 Dead", "l4dserver"),
    "left4dead2": ("Left 4 Dead 2", "l4d2server"),
    "insurgency": ("Insurgency", "insserver"),
    "nmrih":      ("No More Room in Hell", "nmrihserver"),
    "fof":        ("Fistful of Frags", "fofserver"),
    "zps":        ("Zombie Panic! Source", "zpsserver"),
    "pvkii":      ("Pirates, Vikings & Knights II", "pvkiiserver"),
    "dystopia":   ("Dystopia", "dysserver"),
    "empires":    ("Empires Mod", "emserver"),
    "cure":       ("Codename CURE", "ccserver"),
    "dab":        ("Double Action: Boogaloo", "dabserver"),
    # Mount-only — owned single-player titles (no LinuxGSM dedicated server); mounted when already on
    # the host. (CS:GO is deliberately NOT here: since CS2 there's no GMod-usable download for it.)
    "hl1":        ("Half-Life: Source", None),
    "hl2":        ("Half-Life 2", None),
    "episodic":   ("Half-Life 2: Episode One", None),
    "ep2":        ("Half-Life 2: Episode Two", None),
    "lostcoast":  ("Half-Life 2: Lost Coast", None),
    "portal":     ("Portal", None),
    "portal2":    ("Portal 2", None),
}
# Rough download sizes for the UI so nobody accidentally pulls 13GB (installable games only).
GMOD_CONTENT_SIZES = {"cstrike": "~1.6 GB", "tf": "~13 GB", "dod": "~1.1 GB", "hl2mp": "~2 GB",
                      "hl1mp": "~1 GB", "left4dead": "~3 GB", "left4dead2": "~9 GB",
                      "insurgency": "~7 GB", "nmrih": "~6 GB", "fof": "~2 GB", "zps": "~2 GB",
                      "pvkii": "~3 GB", "dystopia": "~1.5 GB", "empires": "~2 GB", "cure": "~2 GB",
                      "dab": "~3 GB"}
_CONTENT_USER = "gmodcontent"                         # panel-managed content user, created if none exists
_CU_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]*$")   # Linux username charset (reaches root-run cmds)


def _valid_content_games(games):
    """Keep only known content keys (each a constant [a-z] folder name), de-duped, order preserved."""
    seen, out = set(), []
    for g in (games or []):
        if g in GMOD_CONTENT_GAMES and g not in seen:
            seen.add(g)
            out.append(g)
    return out


def _user_primary_group(server, user):
    grp, _, _ = _core.run_command(server, f"id -gn {_core._quote(user)} 2>/dev/null", timeout=10)
    return (grp or "").strip() or user


def detect_content_user(server, games=("cstrike",)):
    """Find a host user whose serverfiles already hold the wanted game content (e.g. an existing
    srcds / LinuxGSM cssserver). Returns {"user", "group", "present": {game: path}} for the user with
    the MOST wanted games present, else None — so a GMod install can reuse content already on the host
    instead of re-downloading gigabytes. One sudo scan; only constant game keys reach the shell."""
    wanted = _valid_content_games(games) or list(GMOD_CONTENT_GAMES)
    try:
        # Was a shell loop over /home building its inner list by interpolating the game keys. The
        # verb takes the keys as arguments and walks the directories itself.
        out, _, _ = _core.run_privileged(server, "content-scan", wanted, timeout=30, merge_stderr=False)
    except Exception:
        _core._log.debug("detect_content_user scan failed", exc_info=True)
        return None
    by_user = {}
    for line in (out or "").splitlines():
        parts = line.strip().split("|")
        if len(parts) == 3 and parts[0] == "HIT" and _CU_NAME_RE.match(parts[1]) and parts[2] in GMOD_CONTENT_GAMES:
            by_user.setdefault(parts[1], set()).add(parts[2])
    if not by_user:
        return None
    user = max(by_user, key=lambda u: len(by_user[u]))
    return {"user": user, "group": _user_primary_group(server, user),
            "present": {g: f"/home/{user}/serverfiles/{g}" for g in sorted(by_user[user])}}


def ensure_content_user(server):
    """Return an existing content user (reuse), else create a locked, non-login content user with an
    empty serverfiles dir to install content into. Returns {"user", "group", "present"} or None on
    failure. Never downloads here — just guarantees a home."""
    found = detect_content_user(server, tuple(GMOD_CONTENT_GAMES))
    if found:
        return found
    u = _CONTENT_USER
    exists, _, _ = _core.run_command(server, f"id {_core._quote(u)} >/dev/null 2>&1 && echo Y || echo N", timeout=10)
    if "Y" not in (exists or ""):
        # Was one root shell: useradd && passwd -l ; install -d. Three verbs, and the
        # serverfiles path is built by the helper from the validated name.
        _, err, rc = _core.run_privileged(server, "user-create", [u], timeout=30)
        if rc == 0:
            _core.run_privileged(server, "user-lock-password", [u], timeout=10, merge_stderr=False)
            _, err, rc = _core.run_privileged(server, "content-dir-create", [u], timeout=30)
        if rc != 0:
            _core._log.warning("ensure_content_user: could not create %s: %s", u, (err or "")[:200])
            return None
    return {"user": u, "group": _user_primary_group(server, u), "present": {}}


_DF_PATH_RE = re.compile(r"^/[\w./-]*$")   # absolute path, no shell metacharacters


def path_disk_free(server, path="/home"):
    """Free + total bytes of the filesystem holding `path` (where game content is stored). Returns
    (free_bytes, total_bytes) or (None, None). Best-effort; falls back to /home for a bad path."""
    p = path if _DF_PATH_RE.match(path or "") else "/home"
    # Was `df -PB1 <path> | awk 'NR==2{print $2, $4}'`. Same two fields, read in Python.
    out, _, _ = _core.run_privileged(server, "disk-free", [p], timeout=10, merge_stderr=False)
    rows = (out or "").splitlines()
    if len(rows) < 2:
        return None, None
    fields = rows[1].split()
    try:
        return int(fields[3]), int(fields[1])      # available, total
    except (IndexError, ValueError):
        return None, None


def content_present(server, content_user, game):
    """True if <content_user>/serverfiles/<game> already exists on the host."""
    if not (_CU_NAME_RE.match(content_user or "") and game in GMOD_CONTENT_GAMES):
        return False
    # `test -d … && echo Y || echo N` only turned an exit status into text so this could match a
    # substring. The verb's own rc says the same thing.
    _out, _err, rc = _core.run_privileged(server, "content-game-present", [content_user, game],
                                    timeout=10, merge_stderr=False)
    return rc == 0 or "Y" in (_out or "")




def _content_update_cron_body(content_user, lgsm_names):
    """Pure: the /etc/cron.d text that weekly-updates each content game as the content user. Mirrors a
    standard LinuxGSM content box — `update-lgsm` (refresh scripts) Sunday 1AM then `update` (refresh
    content) Sunday 2AM, staggered so they don't all run at once. content_user is validated upstream;
    lgsm_names are constant script names, so the output is safe to write verbatim."""
    lines = ["# LinuxGSM Panel - weekly GMod content updates for %s (managed by the panel)." % content_user,
             "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
    for i, lgsm in enumerate(lgsm_names):
        lines.append("%d 1 * * 0 %s /home/%s/%s update-lgsm > /dev/null 2>&1"
                     % (min(59, i * 2), content_user, content_user, lgsm))
    for i, lgsm in enumerate(lgsm_names):
        lines.append("%d 2 * * 0 %s /home/%s/%s update > /dev/null 2>&1"
                     % (min(59, i * 10), content_user, content_user, lgsm))
    return "\n".join(lines) + "\n"


def install_gmod_content(server, content_user, games, on_progress=None):
    """Install each game's content under the content user via LinuxGSM — the same way a normal
    LinuxGSM content box does: fetch the game's script, then `auto-install` (non-interactive; runs
    SteamCMD + validate). Multiple games share ~/serverfiles, each in its own game dir. Skips games
    already present, then (re)writes the weekly update cron so content stays current. Long-running.
    Returns (ok, installed_list, msg)."""
    games = _valid_content_games(games)
    if not _CU_NAME_RE.match(content_user or ""):
        return False, [], "invalid content user"
    installed = []
    for g in games:
        if content_present(server, content_user, g):
            continue
        lgsm = GMOD_CONTENT_GAMES[g][1]
        if lgsm is None:
            continue   # mount-only (owned game): no LinuxGSM server — only mounts if already present
        if on_progress:
            on_progress("Installing %s content via LinuxGSM" % GMOD_CONTENT_GAMES[g][0])
        # Fetch linuxgsm.sh once (shared), create the game's script, then auto-install its content.
        inner = (f"cd /home/{content_user} && "
                 f"{{ [ -x linuxgsm.sh ] || {{ wget -q -O linuxgsm.sh https://linuxgsm.sh && chmod +x linuxgsm.sh; }}; }} && "
                 f"bash linuxgsm.sh {lgsm} && ./{lgsm} auto-install")
        _core.run_command(server, f"sudo -u {_core._quote(content_user)} bash -c {_core._quote(inner)}",
                    timeout=7200, sudo=False)
        if content_present(server, content_user, g):
            installed.append(g)
    try:
        ensure_content_update_cron(server, content_user)
    except Exception:
        _core._log.debug("content update cron setup failed", exc_info=True)
    return True, installed, ("installed: " + ", ".join(installed) if installed else "already present")


def _installed_content_lgsm_names(server, content_user):
    """LinuxGSM game names of the content games currently installed under the content user (its
    serverfiles has that game's dir AND the game's script exists). Used to build the update cron."""
    names = []
    for g, (_lbl, lgsm) in GMOD_CONTENT_GAMES.items():
        if lgsm and content_present(server, content_user, g):
            _o, _e, _rc = _core.run_privileged(server, "content-script-present", [content_user, lgsm],
                                         timeout=10, merge_stderr=False)
            if _rc == 0 or "Y" in (_o or ""):
                names.append(lgsm)
    return names


def ensure_content_update_cron(server, content_user):
    """Write a weekly cron (as the content user) that keeps every installed content game current —
    Source games DO get content updates, and a stale copy eventually stops matching clients. Mirrors a
    standard LinuxGSM content box: `update-lgsm` (refresh scripts) Sunday 1AM, then `update` (refresh
    content via SteamCMD) Sunday 2AM, staggered so they don't all run at once. Idempotent — rewrites
    the whole file to match whatever is currently installed. Removes the file when nothing's left."""
    if not _CU_NAME_RE.match(content_user or ""):
        return False
    # If the content user already automates updates in its OWN crontab (e.g. a hand-rolled content box
    # like an existing srcds), leave it alone — never add duplicate update jobs on top of the admin's.
    ct, _, _ = _core.run_privileged(server, "crontab-list", [content_user], timeout=10,
                              merge_stderr=False)
    for line in (ct or "").splitlines():
        s = line.strip()
        if s and not s.startswith("#") and re.search(r"\bupdate(-lgsm)?\b", s):
            return True   # the user already updates its content; don't manage a second cron
    names = _installed_content_lgsm_names(server, content_user)
    if not names:
        _core.run_privileged(server, "content-cron-remove", [content_user], timeout=10,
                       merge_stderr=False)
        return True
    _, _, rc = _core.write_content_cron(server, content_user,
                                  _content_update_cron_body(content_user, names), timeout=15)
    return rc == 0


def uninstall_gmod_content(server, content_user, games):
    """Remove each game's content from the host content user — the content dir plus its LinuxGSM
    install (script + config) — then refresh the weekly update cron so it no longer lists the removed
    games. HOST-WIDE: this frees disk for every GMod server on the host, so any server still mounting
    it just loses that content (GMod skips a missing mount). Returns (ok, removed_list, msg)."""
    games = _valid_content_games(games)
    if not _CU_NAME_RE.match(content_user or ""):
        return False, [], "invalid content user"
    removed = []
    for g in games:
        lgsm = GMOD_CONTENT_GAMES[g][1]
        # g is a constant folder key and content_user is validated (no '/'/'..'/metachars), so every
        # path is a fixed subpath of the content home — safe to rm as root, which also sidesteps any
        # parent-dir ownership quirk. The shared lgsm/ framework dir is left for the other games.
        # Three `rm -rf`s that used to be built from an interpolated user name and game key.
        # The verb takes the NAMES; the helper builds the paths.
        _core.run_privileged(server, "content-game-remove", [content_user, g, lgsm or "-"],
                       timeout=120, merge_stderr=False)
        if not content_present(server, content_user, g):
            removed.append(g)
    try:
        ensure_content_update_cron(server, content_user)   # rescan -> drop the removed games
    except Exception:
        _core._log.debug("content update cron refresh after uninstall failed", exc_info=True)
    return True, removed, ("removed: " + ", ".join(removed) if removed else "nothing to remove")


def _gmod_mount_files(content_user, games):
    """Build the (mount.cfg, mountdepots.txt) text GMod reads to mount each game's content from the
    content user's serverfiles. Pure — content_user is a validated Linux username and every game is a
    constant key, so the output is safe to write verbatim. hl2 depot is always enabled (base content)."""
    mountcfg = '"mountcfg"\n{\n' + "".join(
        '\t"%s"\t"/home/%s/serverfiles/%s"\n' % (g, content_user, g) for g in games) + "}\n"
    depots = ('"gamedepotsystem"\n{\n\t"hl2"\t\t"1"\n'
              + "".join('\t"%s"\t\t"1"\n' % g for g in games) + "}\n")
    return mountcfg, depots


def gmod_mount_setup(server, gmod_user, content_user, games):
    """Write a GMod server's mount config to mount exactly `games` from the content user, granting the
    GMod user read access first. An EMPTY `games` writes an empty mount.cfg (unmounts everything).
    Idempotent. Returns (ok, msg). Group membership takes effect when the GMod server (re)starts."""
    import base64
    games = _valid_content_games(games)
    if not _CU_NAME_RE.match(gmod_user or ""):
        return False, "invalid gmod user"
    if games and not _CU_NAME_RE.match(content_user or ""):
        return False, "invalid content user"
    if games:
        group = _user_primary_group(server, content_user)
        # Read access: add the GMod user to the content group, and make the content group-traversable
        # (home) + group-readable (each game tree). Best-effort per command.
        _core.run_privileged(server, "content-grant-read",
                       [content_user, group, gmod_user] + list(games), timeout=180,
                       merge_stderr=False)
    # Write mount.cfg + mountdepots.txt AS the GMod user (base64 so no quoting/interpolation risk).
    mountcfg, depots = _gmod_mount_files(content_user or "", games)
    cfgdir = f"/home/{gmod_user}/serverfiles/garrysmod/cfg"
    b64c = base64.b64encode(mountcfg.encode()).decode()
    b64d = base64.b64encode(depots.encode()).decode()
    inner = (f"mkdir -p {cfgdir} && echo {b64c} | base64 -d > {cfgdir}/mount.cfg && "
             f"echo {b64d} | base64 -d > {cfgdir}/mountdepots.txt && echo __OK__")
    out, err, rc = _core.run_command(server, f"sudo -u {_core._quote(gmod_user)} bash -c {_core._quote(inner)}",
                               timeout=30, sudo=False)
    if rc != 0 or "__OK__" not in (out or ""):
        return False, (err or out or "mount write failed")[:200]
    if not games:
        return True, "Unmounted all content"
    return True, "Mounted: " + ", ".join(GMOD_CONTENT_GAMES[g][0] for g in games)


_MOUNT_LINE_RE = re.compile(r'"([a-z0-9_]+)"\s+"/')


def gmod_current_mounts(server, gmod_user):
    """Which content games a GMod server currently mounts, parsed from its garrysmod/cfg/mount.cfg.
    Returns a list of known game keys (order as written). [] if no file / none. Read-only."""
    if not _CU_NAME_RE.match(gmod_user or ""):
        return []
    out, _, _ = _core.run_privileged(server, "gmod-mount-read", [gmod_user], timeout=10,
                               merge_stderr=False)
    found = []
    for line in (out or "").splitlines():
        s = line.strip()
        if s.startswith("//"):
            continue   # a commented-out mount (Valve KeyValues // comment) is NOT active
        m = _MOUNT_LINE_RE.search(s)
        if m and m.group(1) in GMOD_CONTENT_GAMES and m.group(1) not in found:
            found.append(m.group(1))
    return found
