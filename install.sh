#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────
# LinuxGSM Panel — all-in-one installer / updater
#
#   Install OR update with ONE command:
#     curl -fsSL https://raw.githubusercontent.com/FMSMITH91/linuxgsm-panel/main/install.sh | bash
#
#   …or from a checkout:
#     git clone https://github.com/FMSMITH91/linuxgsm-panel.git
#     cd linuxgsm-panel && bash install.sh
#
# Re-running the command on an existing install performs a SAFE UPDATE:
#   • snapshots the current code + database first,
#   • pulls the new version, reinstalls deps, restarts the service,
#   • health-checks that the panel actually comes back up, and
#   • AUTO-ROLLS-BACK to the previous version (code + database) if it doesn't.
#   So a broken release can't leave you with a dead panel.
#
# Fresh install behaviour:
#   • Run as a NORMAL user → installs under that user as a systemd --user
#     service (with linger so it survives logout/reboot).
#   • Run as ROOT → does NOT run the panel as root. Creates a dedicated
#     non-login service user, installs under it, and runs it as a systemd
#     SYSTEM service (User=<that user>). The panel needs passwordless sudo to
#     manage the local host (create game-server users, apt, ufw…), so a scoped
#     NOPASSWD sudoers entry is added for it — remove it if you only ever manage
#     *remote* servers from this panel.
# ─────────────────────────────────────────────────────────

REPO_URL="https://github.com/FMSMITH91/linuxgsm-panel.git"
DEFAULT_BRANCH="main"
SERVICE_USER="lgsmpanel"          # dedicated user created for root installs
KEEP_BACKUPS=3                    # how many previous-version snapshots to retain

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}$*${NC}"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

echo -e "${CYAN}╔═══════════════════════════════════════════╗"
echo    "║      LinuxGSM Panel — install / update     ║"
echo -e "╚═══════════════════════════════════════════╝${NC}"

# ── Prerequisites ──
command -v python3 >/dev/null 2>&1 || die "Python 3 is required.  apt install -y python3 python3-venv python3-pip"
python3 -m venv --help >/dev/null 2>&1 || die "python3-venv is required.  apt install -y python3-venv"
command -v curl >/dev/null 2>&1 || warn "curl not found — the post-update health check needs it.  apt install -y curl"
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
    if ! id "${PANEL_USER}" >/dev/null 2>&1; then
        warn "Running as root — the panel will be installed as a dedicated non-root user '${PANEL_USER}' (not as root)."
        useradd --system --create-home --shell /bin/bash "${PANEL_USER}"
        ok "Created service user '${PANEL_USER}'"
    fi
    PANEL_HOME="$(getent passwd "${PANEL_USER}" | cut -d: -f6)"
    PANEL_DIR="${PANEL_HOME}/linuxgsm-panel"
    UNIT_FILE="/etc/systemd/system/linuxgsm-panel.service"
else
    RUN_AS_ROOT=0
    PANEL_USER="$(id -un)"
    PANEL_DIR="${HOME}/linuxgsm-panel"
    UNIT_FILE="${HOME}/.config/systemd/user/linuxgsm-panel.service"
fi

# systemctl / journalctl wrappers that target the right scope (system vs --user).
svc() { if [ "${RUN_AS_ROOT}" -eq 1 ]; then systemctl "$@"; else systemctl --user "$@"; fi; }

svc_active() { svc is-active linuxgsm-panel.service 2>/dev/null || true; }

panel_version() {
    [ -f "${PANEL_DIR}/VERSION" ] && cat "${PANEL_DIR}/VERSION" 2>/dev/null || echo "unknown"
}

# Port the panel serves on (from data/config.json), default 5000.
panel_port() {
    local cfg="${PANEL_DIR}/data/config.json"
    if [ -f "${cfg}" ]; then
        python3 -c "import json;print(int(json.load(open('${cfg}')).get('port',5000)))" 2>/dev/null || echo 5000
    else
        echo 5000
    fi
}

# Return the HTTP status of a URL as a 3-digit string ("000" if unreachable),
# using curl if present and falling back to python3 (always available here) so a
# host without curl still gets a real health check instead of a false rollback.
_http_code() {
    local url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${url}" 2>/dev/null || true
    else
        python3 - "${url}" 2>/dev/null <<'PY' || true
import sys, urllib.request, urllib.error
try:
    print(urllib.request.urlopen(sys.argv[1], timeout=3).getcode())
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print("000")
PY
    fi
}

# Poll the running service until it serves HTTP without a server error.
# Success = systemd reports active AND GET / returns a non-5xx HTTP status
# (302 to the login/setup page is the normal healthy response). This catches the
# common breakages: crash-on-boot, failed DB migration, missing dependency,
# syntax error, or a template that 500s on the entry page.
health_check() {
    local port; port="$(panel_port)"
    local tries=30 code
    for _ in $(seq 1 "${tries}"); do
        if [ "$(svc_active)" = "active" ]; then
            code="$(_http_code "http://127.0.0.1:${port}/")"
            code="${code:-000}"
            # Healthy = a real HTTP response that isn't a server error. 000 = no
            # connection (still booting / crashed), 5xx = the app errored on boot.
            case "${code}" in
                000|5??|"") : ;;
                [1-4][0-9][0-9]) HEALTH_CODE="${code}"; return 0 ;;
            esac
        fi
        sleep 1
    done
    HEALTH_CODE="${code:-000}"
    return 1
}

# Copy the current checkout into PANEL_DIR (skips venv/data so we never clobber
# secrets), or clone/pull from git when there's no local checkout.
fetch_code() {
    mkdir -p "${PANEL_DIR}"
    if [ -n "${SRC}" ] && [ "${SRC}" != "${PANEL_DIR}" ]; then
        tar -C "${SRC}" --exclude=./venv --exclude=./data --exclude='*.pyc' -cf - . | tar -C "${PANEL_DIR}" -xf -
    elif [ -d "${PANEL_DIR}/.git" ]; then
        git -C "${PANEL_DIR}" fetch --quiet origin "${DEFAULT_BRANCH}"
        git -C "${PANEL_DIR}" reset --hard --quiet "origin/${DEFAULT_BRANCH}"
    elif [ -z "${SRC}" ]; then
        command -v git >/dev/null 2>&1 || die "git is required to fetch the panel.  apt install -y git"
        git clone --depth 1 --branch "${DEFAULT_BRANCH}" "${REPO_URL}" "${PANEL_DIR}"
    fi
}

install_deps() {
    python3 -m venv "${PANEL_DIR}/venv"
    "${PANEL_DIR}/venv/bin/pip" install --quiet --upgrade pip
    "${PANEL_DIR}/venv/bin/pip" install --quiet -r "${PANEL_DIR}/requirements.txt"
}

# ── Is this a fresh install or an update of an existing one? ──
IS_UPDATE=0
if [ -f "${PANEL_DIR}/app.py" ] && [ -f "${UNIT_FILE}" ]; then
    IS_UPDATE=1
fi

# ═════════════════════════════════════════════════════════
# UPDATE PATH  (safe: snapshot → update → health-check → rollback)
# ═════════════════════════════════════════════════════════
if [ "${IS_UPDATE}" -eq 1 ]; then
    FROM_VER="$(panel_version)"
    info "Existing install detected at ${PANEL_DIR} (version ${FROM_VER}). Updating…"

    BACKUP_ROOT="${PANEL_DIR}/data/.backups"
    STAMP="$(date +%Y%m%d-%H%M%S)"
    BACKUP="${BACKUP_ROOT}/${STAMP}"
    info "[1/5] Snapshotting current version + database → ${BACKUP}"
    mkdir -p "${BACKUP}"
    # Snapshot the code (minus venv/data) so we can restore the exact prior version…
    tar -C "${PANEL_DIR}" --exclude=./venv --exclude=./data -czf "${BACKUP}/code.tgz" . 2>/dev/null
    # …and the whole data dir (DB + encryption keys + config), since the app runs a
    # startup migration that mutates the DB — we restore this verbatim on rollback.
    if [ -d "${PANEL_DIR}/data" ]; then
        tar -C "${PANEL_DIR}/data" --exclude=./.backups -czf "${BACKUP}/data.tgz" . 2>/dev/null
    fi
    ok "Snapshot saved"

    info "[2/5] Fetching the new version…"
    fetch_code
    TO_VER="$(panel_version)"
    ok "Code updated (${FROM_VER} → ${TO_VER})"

    info "[3/5] Installing dependencies…"
    install_deps
    [ "${RUN_AS_ROOT}" -eq 1 ] && chown -R "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}"
    ok "Dependencies installed"

    info "[4/5] Restarting the service…"
    svc daemon-reload || true
    svc restart linuxgsm-panel.service || true

    info "[5/5] Verifying the panel came back up…"
    if health_check; then
        ok "Health check passed (HTTP ${HEALTH_CODE}) — now running version ${TO_VER}"
        # Prune old snapshots, keep the most recent few.
        if [ -d "${BACKUP_ROOT}" ]; then
            ls -1dt "${BACKUP_ROOT}"/*/ 2>/dev/null | tail -n +"$((KEEP_BACKUPS+1))" | xargs -r rm -rf
        fi
        echo ""
        ok "Update complete: ${FROM_VER} → ${TO_VER}"
        exit 0
    fi

    # ── Health check FAILED → roll back to the snapshot ──
    warn "Health check FAILED (last HTTP status: ${HEALTH_CODE}). Rolling back to ${FROM_VER}…"
    # Restore code (remove tracked files that the new version may have added, then unpack).
    # We only wipe app files, never data/ or venv (venv is rebuilt below anyway).
    find "${PANEL_DIR}" -mindepth 1 -maxdepth 1 \
        ! -name data ! -name venv -exec rm -rf {} + 2>/dev/null || true
    tar -C "${PANEL_DIR}" -xzf "${BACKUP}/code.tgz"
    if [ -f "${BACKUP}/data.tgz" ]; then
        find "${PANEL_DIR}/data" -mindepth 1 -maxdepth 1 ! -name .backups -exec rm -rf {} + 2>/dev/null || true
        tar -C "${PANEL_DIR}/data" -xzf "${BACKUP}/data.tgz"
    fi
    install_deps || true
    [ "${RUN_AS_ROOT}" -eq 1 ] && chown -R "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}"
    svc daemon-reload || true
    svc restart linuxgsm-panel.service || true

    if health_check; then
        ok "Rollback succeeded — the panel is back on the previous version (${FROM_VER}, HTTP ${HEALTH_CODE})."
        echo ""
        die "Update to ${TO_VER} failed its health check and was rolled back. Your panel is unchanged and running.
     Logs from the failed attempt: $([ "${RUN_AS_ROOT}" -eq 1 ] && echo 'sudo journalctl -u linuxgsm-panel -n 50' || echo 'journalctl --user -u linuxgsm-panel -n 50')
     Snapshot kept at: ${BACKUP}"
    else
        echo ""
        die "Update FAILED and the automatic rollback could not confirm health either.
     Restore manually from the snapshot at: ${BACKUP}
       (code.tgz + data.tgz — extract over ${PANEL_DIR}, then restart the service)
     Service logs: $([ "${RUN_AS_ROOT}" -eq 1 ] && echo 'sudo journalctl -u linuxgsm-panel -n 80' || echo 'journalctl --user -u linuxgsm-panel -n 80')"
    fi
fi

# ═════════════════════════════════════════════════════════
# FRESH INSTALL PATH
# ═════════════════════════════════════════════════════════
if [ "${RUN_AS_ROOT}" -eq 1 ]; then
    ok "Installing as dedicated user '${PANEL_USER}' (root will not run the panel)"
else
    ok "Installing for the current user '${PANEL_USER}'"
fi

info "[1/4] Fetching the panel into ${PANEL_DIR}…"
fetch_code

info "[2/4] Creating virtual environment & installing dependencies…"
install_deps
ok "Dependencies installed"

info "[3/4] Registering the service…"
if [ "${RUN_AS_ROOT}" -eq 1 ]; then
    # Own everything as the service user, then run a system service AS that user.
    chown -R "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}"

    # Passwordless sudo so the panel can manage the local host (game-server users,
    # apt, ufw). Remove /etc/sudoers.d/linuxgsm-panel if you only manage remotes.
    echo "${PANEL_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/linuxgsm-panel
    chmod 440 /etc/sudoers.d/linuxgsm-panel
    visudo -cf /etc/sudoers.d/linuxgsm-panel >/dev/null || { rm -f /etc/sudoers.d/linuxgsm-panel; die "sudoers entry invalid"; }

    cat > "${UNIT_FILE}" <<SERVICEEOF
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
    cat > "${UNIT_FILE}" <<SERVICEEOF
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

info "[4/4] Verifying the panel is up…"
if health_check; then
    ok "Panel is responding (HTTP ${HEALTH_CODE})"
else
    warn "The service was registered but didn't answer on port $(panel_port) yet — check the logs:"
    echo -e "  ${CYAN}${LOG_HINT}${NC}"
fi

echo ""
echo -e "  Status:  ${CYAN}${SERVICE_HINT}${NC}"
echo -e "  Logs:    ${CYAN}${LOG_HINT}${NC}"
echo -e "  Update:  ${CYAN}re-run this same command any time — it updates in place and rolls back if the update fails${NC}"
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
