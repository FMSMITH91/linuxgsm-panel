#!/usr/bin/env bash
# LinuxGSM Panel — uninstaller.
#
# Removes the panel and everything its installer created: the systemd service, the panel
# files + its data (DB / config / encryption keys), the sudoers entry, and — for a root
# install — the dedicated 'lgsmpanel' service user.
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
