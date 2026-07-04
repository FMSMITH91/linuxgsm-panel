#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────
# LinuxGSM Panel Installer
# One-command setup: curl -fsSL https://raw.githubusercontent.com/... | bash
# ─────────────────────────────────────────────────────────

PANEL_DIR="${HOME}/linuxgsm-panel"
PANEL_USER="${USER}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════╗"
echo "║     LinuxGSM Panel - Installer            ║"
echo "║     Full Game Server Admin Panel           ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# Check Python
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[ERROR] Python 3 is required but not found.${NC}"
    echo "Install it: sudo apt install python3 python3-pip python3-venv"
    exit 1
fi

PYVER=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✓${NC} Python ${PYVER} found"

# Create directory
if [ -d "${PANEL_DIR}" ]; then
    echo -e "${YELLOW}[!] Directory ${PANEL_DIR} already exists.${NC}"
    read -p "Overwrite? (y/N): " OVERWRITE
    if [ "${OVERWRITE}" != "y" ] && [ "${OVERWRITE}" != "Y" ]; then
        echo "Installation cancelled."
        exit 1
    fi
fi

mkdir -p "${PANEL_DIR}/data"
mkdir -p "${PANEL_DIR}/templates"
mkdir -p "${PANEL_DIR}/static"

# Create virtual environment
echo -e "\n${CYAN}[1/3] Creating Python virtual environment...${NC}"
python3 -m venv "${PANEL_DIR}/venv"
source "${PANEL_DIR}/venv/bin/activate"

# Install dependencies
echo -e "${CYAN}[2/3] Installing Python dependencies...${NC}"
pip install --quiet --upgrade pip
cat > /tmp/lgsm-panel-requirements.txt << 'REQEOF'
flask>=3.0
flask-socketio>=5.3
flask-login>=0.6
flask-sqlalchemy>=3.1
paramiko>=3.4
bcrypt>=4.1
eventlet>=0.36
REQEOF
pip install --quiet -r /tmp/lgsm-panel-requirements.txt
rm /tmp/lgsm-panel-requirements.txt
echo -e "${GREEN}✓${NC} Dependencies installed"

# Download panel files
echo -e "${CYAN}[3/3] Downloading panel files...${NC}"

# Source URL - change this to your actual repo
REPO_BASE="https://raw.githubusercontent.com/YOUR_USER/linuxgsm-panel/main"

download_file() {
    local url="$1"
    local dest="$2"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O "$dest"
    else
        echo -e "${RED}[ERROR] Neither curl nor wget found.${NC}"
        exit 1
    fi
}

# NOTE: Replace this URL with your repository URL
# For now, files need to be manually copied or the repo URL set.
# The recommended install method is: git clone <repo> && cd linuxgsm-panel
echo -e "${YELLOW}[!]${NC} To download the actual files, clone the repository:"
echo ""
echo "    git clone https://github.com/YOUR_USER/linuxgsm-panel.git"
echo "    cd linuxgsm-panel"
echo "    bash install.sh"
echo ""

# Create systemd service
echo -e "\n${CYAN}Creating systemd user service...${NC}"
mkdir -p "${HOME}/.config/systemd/user"

cat > "${HOME}/.config/systemd/user/linuxgsm-panel.service" << 'SERVICEEOF'
[Unit]
Description=LinuxGSM Game Server Admin Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/linuxgsm-panel/venv/bin/python %h/linuxgsm-panel/app.py
WorkingDirectory=%h/linuxgsm-panel
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
SERVICEEOF

echo -e "${GREEN}✓${NC} Service file created at ~/.config/systemd/user/linuxgsm-panel.service"

# Enable and start
systemctl --user daemon-reload
systemctl --user enable linuxgsm-panel.service
echo -e "\n${GREEN}✓ Installation complete!${NC}"
echo ""
echo -e "To start the panel:"
echo -e "  ${CYAN}systemctl --user start linuxgsm-panel${NC}"
echo ""
echo -e "To check status:"
echo -e "  ${CYAN}systemctl --user status linuxgsm-panel${NC}"
echo ""
echo -e "To view logs:"
echo -e "  ${CYAN}journalctl --user -u linuxgsm-panel -f${NC}"
echo ""
echo -e "Open your browser and go to:"
echo -e "  ${CYAN}http://<your-server-ip>:5000${NC}"
echo ""
echo -e "The first visit will guide you through the setup wizard."
echo -e "${YELLOW}WARNING:${NC} By default the panel binds to 0.0.0.0:5000."
echo -e "Use a reverse proxy (nginx/Caddy) or Tailscale Serve for production."
echo ""
