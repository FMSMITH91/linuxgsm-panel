#!/usr/bin/env bash
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
        ufw delete allow "${PANEL_PORT}/tcp" >/dev/null 2>&1 || true
        ufw delete allow "${PANEL_PORT}" >/dev/null 2>&1 || true
        ok "Removed the panel's UFW rule for port ${PANEL_PORT} (game-server ports left intact)"
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

if [ "${MODE}" = "system" ]; then
    rm -f /etc/sudoers.d/linuxgsm-panel
    rm -f /usr/local/bin/linuxgsm-panel-recover
    ok "Removed the sudoers entry"

    # The root-owned pieces install_root_tools() places OUTSIDE the panel directory. They are the
    # whole reason PANEL_DIR is not the full footprint: the helper, the offline DB-repair copy,
    # panel.conf (which records the install's paths) and the root-owned installer.
    if [ -d /usr/local/lib/linuxgsm-panel ]; then
        rm -rf /usr/local/lib/linuxgsm-panel
        ok "Removed the root-owned helper, DB-repair tool, panel.conf and installer copy"
    fi

    # A weekly ROOT cron that keeps npm + gamedig current for player queries. With the panel gone
    # it has nothing to serve, and it would otherwise keep running `npm install -g` as root every
    # Sunday forever.
    if [ -f /etc/cron.d/lgsm-node-tools ]; then
        rm -f /etc/cron.d/lgsm-node-tools
        ok "Removed the weekly npm/gamedig update cron"
    fi

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
        ok "Removed the dedicated panel user '${PANEL_USER}' (game-server users untouched)"
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
