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
# (/usr/local/lib/linuxgsm-panel: panel-helper, db_maintenance.py, panel.conf, install.sh),
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
    PANEL_HOME="$(getent passwd "${PANEL_USER}" 2>/dev/null | cut -d: -f6)"
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
PANEL_PORT=""; TS_DONE=0
if [ -f "${PANEL_DIR}/data/config.json" ]; then
    PANEL_PORT="$(python3 -c "import json;print(int(json.load(open('${PANEL_DIR}/data/config.json')).get('port',5000)))" 2>/dev/null || echo "")"
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

# ── Undo ONLY the panel's own firewall rule + Tailscale Serve (root install; best-effort).
#    Never a game-server port — those rules are left exactly as they are. ──
if [ "${MODE}" = "system" ]; then
    if [ -n "${PANEL_PORT}" ] && command -v ufw >/dev/null 2>&1; then
        # Report what was actually deleted. Both deletes end in `|| true` — correct, since a
        # rule that was never added must not abort the uninstall — and the success line was
        # printed regardless, so "Removed the panel's UFW rule" appeared for a host where no rule
        # existed, where ufw refused (this needs root), and where the port was still open.
        _ufw_gone=0
        ufw delete allow "${PANEL_PORT}/tcp" >/dev/null 2>&1 && _ufw_gone=1
        ufw delete allow "${PANEL_PORT}" >/dev/null 2>&1 && _ufw_gone=1
        if [ "${_ufw_gone}" -eq 1 ]; then
            ok "Removed the panel's UFW rule for port ${PANEL_PORT} (game-server ports left intact)"
        else
            warn "No UFW rule for port ${PANEL_PORT} was removed (none present, or ufw declined)."
            warn "  Check with: sudo ufw status"
        fi
    fi
    if [ "${TS_DONE}" -eq 1 ] && command -v tailscale >/dev/null 2>&1; then
        tailscale serve reset >/dev/null 2>&1 || true
        ok "Reset Tailscale Serve (it was pointing at the panel)"
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
# PANEL_DIR, and per-user is the ordinary way to install.
U_SUDO=""
[ "$(id -u)" -ne 0 ] && U_SUDO="sudo"

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
SHARED_CONF="${SHARED_CONF:-/usr/local/lib/linuxgsm-panel/panel.conf}"
SHARED_OWNER=""
if [ -r "${SHARED_CONF}" ]; then
    SHARED_OWNER="$(sed -n 's/^panel_dir=//p' "${SHARED_CONF}" | head -1)"
fi
SHARED_MINE=1
if [ -n "${SHARED_OWNER}" ] && [ "${SHARED_OWNER}" != "${PANEL_DIR}" ]; then
    SHARED_MINE=0
fi
if [ "${SHARED_MINE}" -eq 0 ]; then
    warn "Leaving the host-wide pieces alone — panel.conf says they belong to another install:"
    warn "    ${SHARED_OWNER}"
    warn "  (the helper, the recovery command and the weekly node-tools cron are shared)"
elif [ -d /usr/local/lib/linuxgsm-panel ] || [ -f /etc/cron.d/lgsm-node-tools ] \
   || [ -L /usr/local/bin/linuxgsm-panel-recover ]; then
    if [ -n "${U_SUDO}" ]; then
        info "Some pieces live outside your home directory and need sudo to remove…"
    fi
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
    # A weekly ROOT cron that keeps npm + gamedig current for player queries. With the panel gone
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
        userdel -r "${PANEL_USER}" >/dev/null 2>&1 || userdel "${PANEL_USER}" >/dev/null 2>&1 || true
        # Ask whether the account is actually gone. Both attempts end in `|| true`, so the success
        # line was printed even when both failed — and a panel user that survives still owns the
        # SSH key that reaches every remote host this panel managed, which is exactly the thing an
        # operator running `uninstall` believes they have just removed.
        if id "${PANEL_USER}" >/dev/null 2>&1; then
            warn "Could not remove the panel user '${PANEL_USER}' — it still exists."
            warn "  It may still own credentials (including the SSH key used for remote hosts)."
            warn "  Remove it yourself once nothing needs it:  sudo userdel -r ${PANEL_USER}"
        else
            ok "Removed the dedicated panel user '${PANEL_USER}' (game-server users untouched)"
        fi
    fi
fi

echo ""
ok "LinuxGSM Panel has been uninstalled."
echo -e "  ${GREEN}Your game servers were not touched${NC} — their users, files, and @reboot"
echo    "  autostart remain, so they keep running exactly as before."
if [ "${MODE}" = "user" ] && [ -n "${PANEL_PORT}" ]; then
    warn "If you opened a firewall port for the panel (${PANEL_PORT}), remove it yourself:  sudo ufw delete allow ${PANEL_PORT}/tcp"
fi
echo ""
