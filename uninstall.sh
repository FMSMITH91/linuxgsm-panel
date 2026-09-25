#!/usr/bin/env bash

# `systemctl --user` needs XDG_RUNTIME_DIR to reach the user bus, and install.sh has defaulted it
# since it was written — this script never did. Without it, every `svc` call here fails, and each
# one ends in `|| true`, so the failure is silent: the service is NOT stopped, and the `rm -rf` of
# the panel directory a few lines later then deletes the files out from under a running process.
# Same line, same reason, as install.sh.
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
# LinuxGSM Panel — uninstaller.
#
# Removes the panel and everything its installer created: the systemd service and its
# priority drop-in, the panel files + its data (DB / config / encryption keys), and — for a
# root install — the sudoers entry, the root-owned helper directory
# (/usr/local/lib/linuxgsm-panel: panel-helper, db_maintenance.py, panel.conf, install.sh,
# recover.sh and .source.git, root's own clone of the repository),
# the weekly npm/gamedig cron, the panel's sysctl tuning, and the dedicated 'lgsmpanel' user.
#
# That list is the point: install.sh writes in five places OUTSIDE the panel directory, and
# an uninstaller that only removes the obvious one leaves a root cron running weekly and a
# host-wide swappiness change in place on a machine the panel no longer lives on.
#
# It DELIBERATELY LEAVES YOUR GAME SERVERS ALONE. Their Linux users, home directories,
# LinuxGSM installs, and @reboot autostart crontabs are never touched, so every game
# server keeps running exactly as before once the panel is gone.
#
#   Root / system install:   sudo bash uninstall.sh
#   Per-user install:              bash uninstall.sh
#   Skip the confirmation:    ... uninstall.sh --yes
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}$*${NC}"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

SERVICE_USER="lgsmpanel"                              # the dedicated user a root install creates
SYSTEM_UNIT="/etc/systemd/system/linuxgsm-panel.service"

echo -e "${CYAN}╔═══════════════════════════════════════════╗"
echo    "║        LinuxGSM Panel — uninstaller       ║"
echo -e "╚═══════════════════════════════════════════╝${NC}"
echo ""

# ── Work out which kind of install this is ──
if [ "$(id -u)" -eq 0 ]; then
    MODE="system"
    PANEL_USER="${SERVICE_USER}"
    # `|| true`, because getent exits 2 when the account does not exist and `set -euo pipefail`
    # (top of this file) turns that into a silent exit 2 for the WHOLE uninstaller — measured:
    # the script stops here printing nothing. The account being already gone is not an error, it
    # is the ordinary state when someone re-runs this after a partial uninstall, which is exactly
    # when they need it to work. An empty answer falls through to the default path below.
    PANEL_HOME="$(getent passwd "${PANEL_USER}" 2>/dev/null | cut -d: -f6 || true)"
    PANEL_DIR="${PANEL_HOME:-/home/${PANEL_USER}}/linuxgsm-panel"
    UNIT_FILE="${SYSTEM_UNIT}"
    svc() { systemctl "$@"; }
else
    if [ -f "${SYSTEM_UNIT}" ] || id "${SERVICE_USER}" >/dev/null 2>&1; then
        die "This looks like a root/system install (service user '${SERVICE_USER}'). Re-run with sudo:
     sudo bash $0"
    fi
    MODE="user"
    PANEL_USER="$(id -un)"
    PANEL_DIR="${HOME}/linuxgsm-panel"
    UNIT_FILE="${HOME}/.config/systemd/user/linuxgsm-panel.service"
    svc() { systemctl --user "$@"; }
fi

if [ ! -e "${UNIT_FILE}" ] && [ ! -d "${PANEL_DIR}" ]; then
    die "No LinuxGSM Panel install found (${MODE} mode). Nothing to remove."
fi

info "Found a ${MODE} install:"
echo "    Service : ${UNIT_FILE}"
echo "    Files   : ${PANEL_DIR}"
if [ "${MODE}" = "system" ]; then echo "    User    : ${PANEL_USER} (dedicated panel user)"; fi
echo ""
warn "This removes the panel, its service, and its data (accounts / config / keys)."
warn "Your GAME SERVERS are NOT touched — their users, files, and autostart stay put."
echo ""

# ── Confirm (this is destructive) ──
ASSUME_YES=0
case "${1:-}" in --yes|-y) ASSUME_YES=1 ;; esac
if [ "${ASSUME_YES}" -ne 1 ]; then
    if [ -t 0 ]; then
        printf "Type 'yes' to uninstall the panel: "
        ans=""; read -r ans || true
        [ "${ans}" = "yes" ] || { echo "Aborted — nothing was changed."; exit 0; }
    else
        die "Refusing to uninstall without confirmation. Re-run with --yes:
     $([ "${MODE}" = "system" ] && echo 'sudo ')bash $0 --yes"
    fi
fi
echo ""

# ── Read the panel's OWN port + Tailscale flag before we delete its config ──
PANEL_PORT=""; TS_DONE=0; TS_MOUNT=""; TS_CONF_UNREAD=0
if [ -f "${PANEL_DIR}/data/config.json" ]; then
    PANEL_PORT="$(python3 -I -c "import json;print(int(json.load(open('${PANEL_DIR}/data/config.json')).get('port',5000)))" 2>/dev/null || echo "")"
    # The mount the panel published ITSELF at (config.py defaults "tailscale_mount" to "/"). Read
    # here, beside the port, because data/config.json is deleted a few lines below — and validated
    # with the same shape the panel validates it with (privileged.py's _ts_mount), so a value that
    # is not a mount point cannot reach the CLI. A value beginning with "-" would be read by
    # `tailscale` as an OPTION, and this script runs as root on a system install.
    #
    # An unusable value prints NOTHING, and so does a config.json that will not parse. It used to
    # fall back to "/", which is the worst possible default here: "/" is a real mount, and it is
    # the one most likely to belong to something else on the node, so a config this script could
    # not read ended in `tailscale serve --bg --remove /` — the whole-host damage the change to
    # a single `--remove` was made to avoid, just narrower. The panel's own teardown refuses
    # instead of substituting a default (tailscale_integration.disable_tailscale_serve() catches
    # VerbError and returns "That isn't a usable mount point." without calling the CLI); empty
    # here is what mirrors that. A "/" that the config genuinely RECORDS still reads back as "/"
    # and is still removed.
    TS_MOUNT="$(python3 -I -c "import json,re;m=str(json.load(open('${PANEL_DIR}/data/config.json')).get('tailscale_mount') or '/');print(m if m == '/' or re.fullmatch(r'(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,31}){1,3}', m) else '')" 2>/dev/null || echo "")"
    # The config file is HERE and we could not get a mount out of it — worth saying so below,
    # because `tailscale_setup_done` is read out of the same unreadable file by the grep after it.
    [ -n "${TS_MOUNT}" ] || TS_CONF_UNREAD=1
    if grep -q '"tailscale_setup_done": true' "${PANEL_DIR}/data/config.json" 2>/dev/null; then TS_DONE=1; fi
fi

# ── Stop + remove the service ──
info "Stopping and removing the service…"
svc disable --now linuxgsm-panel.service >/dev/null 2>&1 || true
# Confirm it actually stopped before anything is deleted. Every svc call here ends in `|| true`,
# which is right — a missing unit must not abort an uninstall — but it also meant a stop that
# never happened read the same as one that did, and the next step removes the files the running
# process is using.
if [ "$(svc is-active linuxgsm-panel.service 2>/dev/null || true)" = "active" ]; then
    warn "The panel service is STILL RUNNING after the stop request."
    warn "  Stop it yourself and re-run, or its files will be removed from under it:"
    if [ "${MODE}" = "system" ]; then
        warn "    sudo systemctl stop linuxgsm-panel.service"
    else
        warn "    systemctl --user stop linuxgsm-panel.service"
    fi
    die "Refusing to delete a running panel's files."
fi
rm -f "${UNIT_FILE}"
# ...and the low-priority drop-in ensure_service_tuning() writes beside it. Leaving the .d
# directory behind means a later reinstall silently inherits the old Nice/CPUWeight.
rm -rf "${UNIT_FILE}.d"
svc daemon-reload >/dev/null 2>&1 || true
if [ "${MODE}" = "system" ]; then systemctl reset-failed linuxgsm-panel.service >/dev/null 2>&1 || true; fi
ok "Service stopped and removed"

# The sudo the cleanups need when this is a per-user uninstall. Computed here rather than beside
# the root-owned removals further down, because the firewall rule below is the FIRST root-owned
# thing the installer created for a per-user install, and it has to come off the same way.
U_SUDO=""
[ "$(id -u)" -ne 0 ] && U_SUDO="sudo"
# ...and the one line that explains it, said ONCE and said BEFORE the first command that needs it.
# It used to sit further down, beside the /usr/local removals, which stopped being the first sudo
# on this path the moment the firewall rule below was taken out of the system-only branch: a
# per-user uninstall asked for a password with nothing yet printed to say why. A function rather
# than a line, because there are now two places that have to be able to be the first one.
_SUDO_NOTE_SHOWN=0
sudo_note() {
    [ -n "${U_SUDO}" ] || return 0
    [ "${_SUDO_NOTE_SHOWN}" -eq 0 ] || return 0
    _SUDO_NOTE_SHOWN=1
    info "Some pieces live outside your home directory and need sudo to remove…"
}

# ── Undo ONLY the panel's own firewall rule + Tailscale Serve mapping (best-effort).
#    Never a game-server port — those rules are left exactly as they are. ──
# The ufw removal sat inside `if [ "${MODE}" = "system" ]`, so a per-user uninstall never closed
# the port. In its place the closing message asked the operator to remove it "if you opened a
# firewall port for the panel" — which they did not: the INSTALLER opened it, on this very path.
# install.sh runs `${SUDO} ufw allow "${PORT}/tcp"` at column 0, after its own root/user split, so
# it fires for a per-user install too. An operator who never touched ufw correctly read that
# message as not applying to them, and the port stayed open on a host with no panel behind it.
# Removing it here, through ${U_SUDO} like the other root-owned pieces, means the rule the
# installer added is the rule the uninstaller takes away, on both paths.
# An unreadable config.json blanks PANEL_PORT at the top of this file, and that used to skip this
# block in SILENCE — the installer's rule left open on a host with no panel behind it, and nothing
# said so. The Tailscale teardown below already hedges out loud about the same unreadable file;
# the firewall deserves the same. Not knowing the port is not the same as there being no rule.
if [ -z "${PANEL_PORT}" ] && command -v ufw >/dev/null 2>&1; then
    warn "Could not read the panel's port from its config, so its UFW rule was left in place."
    warn "  Find and remove it with:  sudo ufw status numbered"
fi
if [ -n "${PANEL_PORT}" ] && command -v ufw >/dev/null 2>&1; then
    # Report what was actually deleted. Both deletes end in `|| true` — correct, since a
    # rule that was never added must not abort the uninstall — and the success line was
    # printed regardless, so "Removed the panel's UFW rule" appeared for a host where no rule
    # existed, where ufw refused (this needs root), and where the port was still open.
    _ufw_gone=0
    sudo_note
    ${U_SUDO} ufw delete allow "${PANEL_PORT}/tcp" >/dev/null 2>&1 && _ufw_gone=1
    ${U_SUDO} ufw delete allow "${PANEL_PORT}" >/dev/null 2>&1 && _ufw_gone=1
    if [ "${_ufw_gone}" -eq 1 ]; then
        ok "Removed the panel's UFW rule for port ${PANEL_PORT} (game-server ports left intact)"
    else
        warn "No UFW rule for port ${PANEL_PORT} was removed (none present, or ufw declined)."
        warn "  Check with: sudo ufw status"
    fi
fi
# Not gated on MODE. `tailscale_setup_done` is written by the RUNNING PANEL — routes/tailscale.py
# and route_helpers.py set it once setup_tailscale_serve() succeeds, on any install mode, with no
# root/user split anywhere in that path — so a per-user panel publishes a Serve mapping exactly
# like a system one does. Gating the teardown on `system` left that mapping on the tailnet,
# pointing at a backend that no longer exists, for precisely the installs where nothing else was
# going to clean it up. The CLI call needs no root either: setup made the panel user the Tailscale
# operator (ensure_operator()), which is the same reason the panel's own teardown calls it plain.
if command -v tailscale >/dev/null 2>&1 \
   && { [ "${TS_DONE}" -eq 1 ] || [ "${TS_CONF_UNREAD}" -eq 1 ]; }; then
    # `tailscale serve reset` is the CLI's "clear the whole config" verb: it wipes EVERY serve and
    # funnel mapping on this node, not the panel's. A host publishing anything else behind Serve —
    # a /grafana mount, a funnel for a stats page — lost it here, with nothing listed first and
    # nothing to restore afterwards, since serve config is not versioned. And the line printed was
    # "it was pointing at the panel", a statement about the host's serve config that this script
    # never read. Remove the ONE mount the panel recorded, exactly as the panel's own teardown
    # does (tailscale_integration.py remove_serve(): serve --bg --remove <mount>).
    if [ -z "${TS_MOUNT}" ]; then
        # Nothing usable was recorded, so there is no mount this script can honestly claim as the
        # panel's — and every mount it could guess at is one that may belong to something else on
        # this node. Say so and remove nothing, which is what the panel's own teardown does with
        # the same value.
        warn "Leaving this node's Tailscale Serve config alone — the panel's own mount point"
        warn "  could not be read back (its config.json is missing the value, has an unusable"
        warn "  one, or would not parse). Nothing was removed, because the mount this script"
        warn "  would have to guess at may belong to something else on this node."
        warn "  See what this node still publishes with:  tailscale serve status"
    elif tailscale serve --bg --remove "${TS_MOUNT}" >/dev/null 2>&1; then
        ok "Removed the panel's Tailscale Serve mapping at ${TS_MOUNT} (other mappings untouched)"
    else
        warn "Could not remove the panel's Tailscale Serve mapping at ${TS_MOUNT}."
        warn "  See what this node still publishes with:  tailscale serve status"
    fi
fi

# ── Remove the panel files (with a guard against a catastrophic path) ──
if [ -n "${PANEL_DIR}" ] && [ "${PANEL_DIR}" != "/" ] && [ -d "${PANEL_DIR}" ]; then
    info "Removing the panel files at ${PANEL_DIR}…"
    rm -rf "${PANEL_DIR}"
    ok "Removed ${PANEL_DIR}"
fi

# ── Root-owned pieces a PER-USER install creates too ───────────────────────────────────────────
# These were inside the `system` branch below, and three of them are written on BOTH paths:
# install.sh calls ensure_gamedig() and install_root_tools() unconditionally, before its
# root/user split, and both use `sudo` when they are not already root. So a per-user uninstall
# removed the panel and left behind a weekly ROOT cron running `npm install -g` every Sunday
# forever, the root-owned helper tree, a panel.conf pointing at a deleted directory and a
# dangling recovery symlink — then printed "LinuxGSM Panel has been uninstalled."
#
# That is exactly the leftover this file's own header calls "the point" of removing more than
# PANEL_DIR, and per-user is the ordinary way to install.  (${U_SUDO} is computed above, where the
# firewall rule — the first root-owned piece a per-user install leaves behind — is removed.)
#
# WHOSE are they? None of the three paths below is per-install — /usr/local/lib/linuxgsm-panel,
# /etc/cron.d/lgsm-node-tools and /usr/local/bin/linuxgsm-panel-recover are one shared set for the
# whole host. This block used to sit inside the `system` branch and was moved out to fix a
# per-user leftover; the move was right, but it turned a root-only deletion into one that ANY
# unprivileged user's uninstall performs against host-wide state. Two panels on one box, and
# removing the second took the first's helper, its recovery command and its weekly cron.
#
# The answer is already inside the directory being deleted: install.sh writes panel.conf there
# recording `panel_dir=`, and tools/panel-helper reads it back for exactly this purpose. Read it
# rather than assuming.
# A variable, so a test can point it at a fixture: the decision below is the whole of the guard,
# and one that can only run against a real /usr/local on a real host is one nothing exercises.
# This literal is the THIRD copy of the same path (install.sh writes it, recover.sh reads it), and
# a mutation proved it unpinned: changing it alone left the whole suite green. The gate in
# tests/unit/part05.py now reads all three and requires they name one file.
SHARED_CONF="${SHARED_CONF:-/usr/local/lib/linuxgsm-panel/panel.conf}"
SHARED_OWNER=""
if [ -r "${SHARED_CONF}" ]; then
    SHARED_OWNER="$(sed -n 's/^panel_dir=//p' "${SHARED_CONF}" | head -1)"
fi
# panel.conf cannot answer that question on its own, and reading it as if it could left the exact
# co-tenancy bug above still reachable. install.sh rewrites panel.conf unconditionally — on every
# install AND on every self-update, since install_root_tools() runs on all three paths — so it
# names whichever install ran MOST RECENTLY, not the one that owns the shared tree. In the natural
# ordering (alice installs, bob installs after her) it names bob, and bob's uninstall reads his
# own panel_dir back, concludes the host-wide pieces are his, and removes alice's helper, her
# recovery command and the weekly cron while her panel is still running.
#
# So ask the other question too — is any OTHER install still HERE? — by looking for the installs
# themselves rather than for a record of who wrote a file last, using the same home scan install.sh
# and recover.sh already do. The homes root is a variable for the same reason SHARED_CONF is: a
# guard that can only run against a real /home is a guard nothing exercises. It is namespaced,
# like recover.sh's PANEL_RECOVER_HOMES and for the same reason — a bare `HOMES` is a name any
# shell might already have in its environment for something else, and this one now steers both a
# decision about deleting host-wide files and (further down, via the case guard) a root `rm -rf`.
#
# (No need to test for a system install: a per-user uninstall already refuses to run at all when
# ${SYSTEM_UNIT} exists, far above.)
HOMES="${PANEL_UNINSTALL_HOMES:-/home}"
# Whether a directory is THIS install's is a question about identity, not about spelling. Both
# comparisons below used to be string compares, and both of the things they compare against
# ${PANEL_DIR} are written by someone else: the ${HOMES}/* glob spells a home the way the homes
# root is spelled, and panel.conf's `panel_dir=` was written by install.sh on whatever run last
# touched it. The same directory reached two ways — /home a symlink onto another filesystem, a
# trailing slash on $HOME — read as two directories, and the only install on the host matched
# ITSELF as a co-tenant. The decision is an OR, so panel.conf naming this install could not
# override the scan either: every host-shared piece was left behind, under a warning naming an
# install that does not exist. That is the exact leftover this block exists to remove — a root
# `npm install -g` cron running weekly forever on a host with no panel.
#
# Resolve through the PARENT rather than the path itself: ${PANEL_DIR} is already deleted by the
# time this runs (a hundred lines above), and so, usually, is whatever panel.conf names. The home
# that contained it is still there.
_phys() { ( cd -P -- "${1}" 2>/dev/null && pwd -P ) || printf '%s' "${1}"; }
_phys_path() { printf '%s/%s' "$(_phys "$(dirname "${1}")")" "$(basename "${1}")"; }
MY_DIR_PHYS="$(_phys_path "${PANEL_DIR}")"
OTHER_INSTALL=""
for _h in "${HOMES}"/*; do
    [ -d "${_h}" ] || continue
    [ "$(_phys_path "${_h}/linuxgsm-panel")" = "${MY_DIR_PHYS}" ] && continue
    [ -f "${_h}/.config/systemd/user/linuxgsm-panel.service" ] || continue
    OTHER_INSTALL="${_h}/linuxgsm-panel"
    break
done
SHARED_MINE=1
if [ -n "${OTHER_INSTALL}" ] \
   || { [ -n "${SHARED_OWNER}" ] \
        && [ "$(_phys_path "${SHARED_OWNER}")" != "${MY_DIR_PHYS}" ]; }; then
    SHARED_MINE=0
fi
if [ "${SHARED_MINE}" -eq 0 ]; then
    warn "Leaving the host-wide pieces alone — they belong to another install still on this host:"
    warn "    ${OTHER_INSTALL:-${SHARED_OWNER}}"
    warn "  (the helper, the recovery command and the weekly node-tools cron are shared)"
elif [ -d /usr/local/lib/linuxgsm-panel ] || [ -f /etc/cron.d/lgsm-node-tools ] \
   || [ -L /usr/local/bin/linuxgsm-panel-recover ]; then
    sudo_note
    # The root-owned pieces install_root_tools() places OUTSIDE the panel directory: the helper,
    # the offline DB-repair copy, panel.conf (which records the install's paths) and the
    # root-owned installer.
    if [ -d /usr/local/lib/linuxgsm-panel ]; then
        if ${U_SUDO} rm -rf /usr/local/lib/linuxgsm-panel; then
            ok "Removed the root-owned helper, DB-repair tool, panel.conf and installer copy"
        else
            warn "Could not remove /usr/local/lib/linuxgsm-panel — remove it by hand."
        fi
    fi
    # The fail2ban jail the panel installs, and its filter and whitelist. These are root-owned
    # files OUTSIDE the panel directory (privileged.py's WRITE_TARGETS is the authoritative list),
    # and uninstall.sh did not mention fail2ban at all — so `rm -rf "${PANEL_DIR}"` deleted
    # data/auth.log while leaving an ENABLED jail whose `logpath` points at it. fail2ban then runs
    # on a host that no longer has a panel, watching a file that no longer exists.
    #
    # This file's own header calls removing what the installer wrote outside PANEL_DIR "the
    # point", and these were missing from the list.
    _f2b_removed=0
    for _f2b_f in /etc/fail2ban/jail.d/linuxgsm-panel.conf \
                  /etc/fail2ban/filter.d/linuxgsm-panel.conf \
                  /etc/fail2ban/jail.d/zz-panel-whitelist.local; do
        if [ -f "${_f2b_f}" ]; then
            ${U_SUDO} rm -f "${_f2b_f}" && _f2b_removed=1
        fi
    done
    if [ "${_f2b_removed}" -eq 1 ]; then
        # Reload so the running fail2ban stops watching a log that is about to vanish. Best
        # effort: a host where fail2ban is not running is not an error here.
        ${U_SUDO} fail2ban-client reload >/dev/null 2>&1 \
            || ${U_SUDO} systemctl restart fail2ban >/dev/null 2>&1 || true
        ok "Removed the panel's fail2ban jail, filter and whitelist (other jails left intact)"
    fi
    # A weekly ROOT cron that keeps gamedig (pinned v5) current for player queries. With the panel gone
    # it has nothing to serve, and it would otherwise keep running `npm install -g` as root every
    # Sunday forever.
    if [ -f /etc/cron.d/lgsm-node-tools ]; then
        if ${U_SUDO} rm -f /etc/cron.d/lgsm-node-tools; then
            ok "Removed the weekly npm/gamedig update cron"
        else
            warn "Could not remove /etc/cron.d/lgsm-node-tools — remove it by hand."
        fi
    fi
    if [ -L /usr/local/bin/linuxgsm-panel-recover ] || [ -f /usr/local/bin/linuxgsm-panel-recover ]; then
        if ${U_SUDO} rm -f /usr/local/bin/linuxgsm-panel-recover; then
            ok "Removed the linuxgsm-panel-recover command"
        else
            warn "Could not remove /usr/local/bin/linuxgsm-panel-recover — remove it by hand."
        fi
    fi
fi

if [ "${MODE}" = "system" ]; then
    # Both of them: the narrow grant, and the opt-in password-required one the host terminal uses
    # (PANEL_TERMINAL_SUDO=1). Leaving the second behind would leave a general sudo rule naming an
    # account that no longer exists — and that name is reusable.
    rm -f /etc/sudoers.d/linuxgsm-panel /etc/sudoers.d/00-linuxgsm-panel-terminal
    ok "Removed the sudoers entries"

    # Host-wide kernel tuning the installer applied for the panel's sake (vm.swappiness). Re-apply
    # the remaining sysctl config so the host goes back to its own values now, not at next boot.
    if [ -f /etc/sysctl.d/99-linuxgsm-panel.conf ]; then
        rm -f /etc/sysctl.d/99-linuxgsm-panel.conf
        sysctl --system >/dev/null 2>&1 || true
        ok "Removed the panel's sysctl tuning (swappiness back to this host's own setting)"
    fi
    # SAFETY: only ever remove the dedicated panel service user — NEVER a game-server user.
    if [ "${PANEL_USER}" = "${SERVICE_USER}" ] && id "${PANEL_USER}" >/dev/null 2>&1; then
        loginctl disable-linger "${PANEL_USER}" >/dev/null 2>&1 || true
        # Read the home BEFORE the account goes — once userdel succeeds there is nothing left to
        # ask. It matters because `rm -rf "${PANEL_DIR}"` above only clears <home>/linuxgsm-panel,
        # and the panel keeps its remote credential OUTSIDE that directory: ssh_manager defaults
        # to ~/.ssh/id_rsa, i.e. <home>/.ssh/id_rsa, which is root-capable on every managed remote
        # (the remote grant is `sudo bash -c`).
        _panel_home="$(getent passwd "${PANEL_USER}" 2>/dev/null | cut -d: -f6)"
        # _home_rm is the ONLY path this will ever rm -rf, and it is only ever a plain
        # <homes>/<name>: never "/", never ${HOMES} itself, never a path with a segment above it
        # or below it. An `rm -rf` built from a passwd field and running as root gets a guard.
        _home_rm=""
        case "${_panel_home}" in
            "${HOMES}"/..|"${HOMES}"/.|"${HOMES}"/|"${HOMES}"/*/*) ;;  # a parent, or nested: no
            "${HOMES}"/?*) _home_rm="${_panel_home}" ;;                # a plain <homes>/<name>
            *) ;;                                                      # not ours to delete
        esac
        userdel -r "${PANEL_USER}" >/dev/null 2>&1 || userdel "${PANEL_USER}" >/dev/null 2>&1 || true
        # The fallback is `userdel` WITHOUT -r, which by definition leaves the home on disk — and
        # `userdel -r` itself exits 12 when it cannot remove the home (a stray tmux, a mounted
        # home) having already deleted the account. Both of those landed on the success line
        # below, because the only question asked was whether the ACCOUNT was gone: the SSH key
        # that reaches every remote host survived an uninstall that reported itself complete,
        # orphaned to a numeric uid the next useradd on this host can be handed. So take the home
        # explicitly when the account went without it, and only claim the user was removed when
        # the home is gone too.
        if ! id "${PANEL_USER}" >/dev/null 2>&1 \
           && [ -n "${_home_rm}" ] && [ -d "${_home_rm}" ]; then
            rm -rf "${_home_rm}" || true
        fi
        # Ask whether the account is actually gone. Both attempts end in `|| true`, so the success
        # line was printed even when both failed — and a panel user that survives still owns the
        # SSH key that reaches every remote host this panel managed, which is exactly the thing an
        # operator running `uninstall` believes they have just removed.
        if id "${PANEL_USER}" >/dev/null 2>&1; then
            warn "Could not remove the panel user '${PANEL_USER}' — it still exists."
            warn "  It may still own credentials (including the SSH key used for remote hosts)."
            warn "  Remove it yourself once nothing needs it:  sudo userdel -r ${PANEL_USER}"
        elif [ -n "${_panel_home}" ] && [ -d "${_panel_home}" ]; then
            warn "Removed the panel user '${PANEL_USER}', but its home is still on disk:"
            warn "    ${_panel_home}"
            warn "  It holds the SSH key used for remote hosts — remove it once nothing needs it:"
            warn "    sudo rm -rf ${_panel_home}"
        else
            ok "Removed the dedicated panel user '${PANEL_USER}' (game-server users untouched)"
        fi
    fi
fi

echo ""
ok "LinuxGSM Panel has been uninstalled."
echo -e "  ${GREEN}Your game servers were not touched${NC} — their users, files, and @reboot"
echo    "  autostart remain, so they keep running exactly as before."
echo ""
