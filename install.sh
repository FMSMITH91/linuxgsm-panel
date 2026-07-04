#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────
# LinuxGSM Panel installer
#
#   Recommended:   git clone https://github.com/FMSMITH91/linuxgsm-panel.git
#                  cd linuxgsm-panel && bash install.sh
#
#   Or (once the repo is public):
#                  curl -fsSL https://raw.githubusercontent.com/FMSMITH91/linuxgsm-panel/main/install.sh | bash
#
# Creates a venv, installs the pinned dependencies, and registers a systemd *user*
# service with linger enabled so the panel survives logout/reboot.
# ─────────────────────────────────────────────────────────

REPO_URL="https://github.com/FMSMITH91/linuxgsm-panel.git"
PANEL_DIR="${HOME}/linuxgsm-panel"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}$*${NC}"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

echo -e "${CYAN}╔═══════════════════════════════════════════╗"
echo    "║          LinuxGSM Panel — installer        ║"
echo -e "╚═══════════════════════════════════════════╝${NC}"

# ── Prerequisites ──
command -v python3 >/dev/null 2>&1 || die "Python 3 is required.  sudo apt install -y python3 python3-venv python3-pip"
python3 -m venv --help >/dev/null 2>&1 || die "python3-venv is required.  sudo apt install -y python3-venv"
PYVER=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
ok "Python ${PYVER} found"

# ── Get the code: use the current checkout if we're in one, else clone ──
if [ -f "./app.py" ] && [ -f "./requirements.txt" ]; then
    PANEL_DIR="$(pwd)"
    ok "Using the current checkout: ${PANEL_DIR}"
else
    command -v git >/dev/null 2>&1 || die "git is required to fetch the panel.  sudo apt install -y git"
    if [ -d "${PANEL_DIR}/.git" ]; then
        info "Updating existing checkout at ${PANEL_DIR}…"
        git -C "${PANEL_DIR}" pull --ff-only
    else
        info "Cloning ${REPO_URL} → ${PANEL_DIR}…"
        git clone --depth 1 "${REPO_URL}" "${PANEL_DIR}"
    fi
    cd "${PANEL_DIR}"
fi

# ── Virtual environment + dependencies (from the pinned requirements.txt) ──
info "[1/3] Creating virtual environment…"
python3 -m venv "${PANEL_DIR}/venv"
"${PANEL_DIR}/venv/bin/pip" install --quiet --upgrade pip
info "[2/3] Installing dependencies…"
"${PANEL_DIR}/venv/bin/pip" install --quiet -r "${PANEL_DIR}/requirements.txt"
ok "Dependencies installed"

# ── systemd user service ──
info "[3/3] Registering systemd user service…"
mkdir -p "${HOME}/.config/systemd/user"
cat > "${HOME}/.config/systemd/user/linuxgsm-panel.service" <<SERVICEEOF
[Unit]
Description=LinuxGSM Game Server Admin Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${PANEL_DIR}/venv/bin/python ${PANEL_DIR}/app.py
WorkingDirectory=${PANEL_DIR}
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
SERVICEEOF

# Linger lets the --user service run without an active login and start on boot.
loginctl enable-linger "$(id -un)" >/dev/null 2>&1 || warn "Could not enable linger (the panel may not start on boot)."
systemctl --user daemon-reload
systemctl --user enable --now linuxgsm-panel.service
ok "Service registered and started"

echo ""
ok "Installation complete!"
echo ""
echo -e "  Status:  ${CYAN}systemctl --user status linuxgsm-panel${NC}"
echo -e "  Logs:    ${CYAN}journalctl --user -u linuxgsm-panel -f${NC}"
echo ""
echo -e "Open ${CYAN}http://<your-server-ip>:5000${NC} — the first visit runs the setup wizard."
echo ""
warn "By default the panel binds 0.0.0.0:5000. For anything beyond local testing, put it"
warn "behind Tailscale Serve (recommended) or a reverse proxy with HTTPS — do NOT expose"
warn "the admin panel directly to the public internet."
echo ""
