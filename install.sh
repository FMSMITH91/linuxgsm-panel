#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────
# LinuxGSM Panel installer
#
#   Recommended:   git clone https://github.com/FMSMITH91/linuxgsm-panel.git
#                  cd linuxgsm-panel && bash install.sh
#
# Behaviour:
#   • Run as a NORMAL user → installs under that user, as a systemd --user
#     service (with linger so it survives logout/reboot).
#   • Run as ROOT → does NOT run the panel as root. Creates a dedicated
#     non-login service user, installs under it, and runs it as a systemd
#     SYSTEM service (User=<that user>). The panel needs passwordless sudo to
#     manage the local host (create game-server users, apt, ufw…), so a scoped
#     NOPASSWD sudoers entry is added for it — remove it if you only ever manage
#     *remote* servers from this panel.
# ─────────────────────────────────────────────────────────

REPO_URL="https://github.com/FMSMITH91/linuxgsm-panel.git"
SERVICE_USER="lgsmpanel"          # dedicated user created for root installs

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}$*${NC}"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

echo -e "${CYAN}╔═══════════════════════════════════════════╗"
echo    "║          LinuxGSM Panel — installer        ║"
echo -e "╚═══════════════════════════════════════════╝${NC}"

# ── Prerequisites ──
command -v python3 >/dev/null 2>&1 || die "Python 3 is required.  apt install -y python3 python3-venv python3-pip"
python3 -m venv --help >/dev/null 2>&1 || die "python3-venv is required.  apt install -y python3-venv"
ok "Python $(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])') found"

# Where is the source? Prefer the current checkout; otherwise we'll clone.
SRC=""
if [ -f "./app.py" ] && [ -f "./requirements.txt" ]; then
    SRC="$(pwd)"
    ok "Using the current checkout as source: ${SRC}"
fi

# ─────────────────────────────────────────────────────────
# Decide the install user + directory + service model.
# ─────────────────────────────────────────────────────────
if [ "$(id -u)" -eq 0 ]; then
    RUN_AS_ROOT=1
    PANEL_USER="${SERVICE_USER}"
    warn "Running as root — the panel will be installed as a dedicated non-root user '${PANEL_USER}' (not as root)."
    if ! id "${PANEL_USER}" >/dev/null 2>&1; then
        useradd --system --create-home --shell /bin/bash "${PANEL_USER}"
        ok "Created service user '${PANEL_USER}'"
    else
        ok "Service user '${PANEL_USER}' already exists"
    fi
    PANEL_HOME="$(getent passwd "${PANEL_USER}" | cut -d: -f6)"
    PANEL_DIR="${PANEL_HOME}/linuxgsm-panel"
else
    RUN_AS_ROOT=0
    PANEL_USER="$(id -un)"
    PANEL_DIR="${HOME}/linuxgsm-panel"
    ok "Installing for the current user '${PANEL_USER}'"
fi

# ── Get the code into PANEL_DIR ──
info "[1/4] Fetching the panel into ${PANEL_DIR}…"
mkdir -p "${PANEL_DIR}"
if [ -n "${SRC}" ] && [ "${SRC}" != "${PANEL_DIR}" ]; then
    # Copy the current checkout (skip venv/data so we don't clobber/copy secrets).
    tar -C "${SRC}" --exclude=./venv --exclude=./data --exclude='*.pyc' -cf - . | tar -C "${PANEL_DIR}" -xf -
elif [ -z "${SRC}" ]; then
    command -v git >/dev/null 2>&1 || die "git is required to fetch the panel.  apt install -y git"
    if [ -d "${PANEL_DIR}/.git" ]; then
        git -C "${PANEL_DIR}" pull --ff-only
    else
        git clone --depth 1 "${REPO_URL}" "${PANEL_DIR}"
    fi
fi

# ── Virtual environment + dependencies ──
info "[2/4] Creating virtual environment & installing dependencies…"
python3 -m venv "${PANEL_DIR}/venv"
"${PANEL_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${PANEL_DIR}/venv/bin/pip" install --quiet -r "${PANEL_DIR}/requirements.txt"
ok "Dependencies installed"

# ── systemd service ──
info "[3/4] Registering the service…"
if [ "${RUN_AS_ROOT}" -eq 1 ]; then
    # Own everything as the service user, then run a system service AS that user.
    chown -R "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}"

    # Passwordless sudo so the panel can manage the local host (game-server users,
    # apt, ufw). Remove /etc/sudoers.d/linuxgsm-panel if you only manage remotes.
    echo "${PANEL_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/linuxgsm-panel
    chmod 440 /etc/sudoers.d/linuxgsm-panel
    visudo -cf /etc/sudoers.d/linuxgsm-panel >/dev/null || { rm -f /etc/sudoers.d/linuxgsm-panel; die "sudoers entry invalid"; }

    cat > /etc/systemd/system/linuxgsm-panel.service <<SERVICEEOF
[Unit]
Description=LinuxGSM Game Server Admin Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${PANEL_USER}
WorkingDirectory=${PANEL_DIR}
ExecStart=${PANEL_DIR}/venv/bin/python ${PANEL_DIR}/app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SERVICEEOF
    systemctl daemon-reload
    systemctl enable --now linuxgsm-panel.service
    SERVICE_HINT="sudo systemctl status linuxgsm-panel"
    LOG_HINT="sudo journalctl -u linuxgsm-panel -f"
else
    mkdir -p "${HOME}/.config/systemd/user"
    cat > "${HOME}/.config/systemd/user/linuxgsm-panel.service" <<SERVICEEOF
[Unit]
Description=LinuxGSM Game Server Admin Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${PANEL_DIR}
ExecStart=${PANEL_DIR}/venv/bin/python ${PANEL_DIR}/app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
SERVICEEOF
    loginctl enable-linger "${PANEL_USER}" >/dev/null 2>&1 || warn "Could not enable linger (panel may not start on boot)."
    systemctl --user daemon-reload
    systemctl --user enable --now linuxgsm-panel.service
    SERVICE_HINT="systemctl --user status linuxgsm-panel"
    LOG_HINT="journalctl --user -u linuxgsm-panel -f"
fi
ok "Service registered and started (running as '${PANEL_USER}')"

info "[4/4] Done."
echo ""
echo -e "  Status:  ${CYAN}${SERVICE_HINT}${NC}"
echo -e "  Logs:    ${CYAN}${LOG_HINT}${NC}"
echo ""
echo -e "Open ${CYAN}http://<your-server-ip>:5000${NC} — the first visit runs the setup wizard."
echo ""
warn "By default the panel binds 0.0.0.0:5000. For anything beyond local testing, put it"
warn "behind Tailscale Serve (recommended) or a reverse proxy with HTTPS — do NOT expose"
warn "the admin panel directly to the public internet."
echo ""

# If a firewall is blocking the port, tell the user (auto-opening the admin port would
# be a bad default — the recommended path is Tailscale, which needs no open port).
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active" \
        && ! ufw status 2>/dev/null | grep -qw "5000"; then
    warn "UFW is active and port 5000 is closed, so you can't reach the wizard by IP yet."
    echo -e "  • Recommended: set up Tailscale (no open port needed)."
    echo -e "  • Or, to reach it directly: ${CYAN}sudo ufw allow 5000/tcp${NC}"
    echo ""
fi
