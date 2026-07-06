#!/usr/bin/env bash
set -euo pipefail

# Never block on a git credential prompt (private/unreachable remote) — fail fast.
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=true

# `systemctl --user` needs XDG_RUNTIME_DIR to reach the user bus. It's set for
# interactive logins, but NOT for a plain non-interactive SSH command (e.g. an
# auto-deploy workflow running `ssh host 'bash install.sh'`). Default it so the
# --user service model works in that case too. (Root installs use the system bus.)
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

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
echo    "║     LinuxGSM Panel — install / update     ║"
echo -e "╚═══════════════════════════════════════════╝${NC}"

# ── Prerequisites ──
command -v python3 >/dev/null 2>&1 || die "Python 3 is required."

# `python3 -m venv --help` succeeds even when the python3-venv / ensurepip package
# is missing (common on minimal Ubuntu/Debian VPS images), so the ONLY reliable
# test is to actually build a throwaway venv.
_venv_works() {
    local t; t="$(mktemp -d)" || return 1
    if python3 -m venv "${t}" >/dev/null 2>&1; then rm -rf "${t}"; return 0; fi
    rm -rf "${t}"; return 1
}

# If anything's missing, install it automatically on Debian/Ubuntu (this runs as
# root for a root install, and via sudo otherwise).
if ! _venv_works || ! command -v git >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
        info "Installing prerequisites (python3-venv, python3-pip, git, curl)…"
        ${SUDO} apt-get update -qq || true
        ${SUDO} apt-get install -y python3-venv python3-pip git curl \
            || warn "apt-get reported an error — re-checking prerequisites anyway."
    fi
fi

# Hard-fail only on what we truly cannot proceed without.
_venv_works || die "Python can't create virtual environments. Install the venv package and re-run:
     sudo apt install -y python3-venv python3-pip"
command -v git >/dev/null 2>&1 || die "git is required.  sudo apt install -y git"
command -v curl >/dev/null 2>&1 || warn "curl not found — the health check will fall back to python3."
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

# Pick a free listen port and record it in data/config.json before the first boot. If the
# desired port (5000, or a previously configured one) is already taken by another service,
# the panel would fail to bind — so probe upward for a free port and persist the choice so
# the first start, the health check, and the firewall step all agree. Prints the chosen port.
choose_and_record_port() {
    local desired="${1:-5000}"
    python3 - "${desired}" "${PANEL_DIR}/data/config.json" <<'PYEOF'
import json, os, socket, sys
desired, cfg_path = int(sys.argv[1]), sys.argv[2]

def free(p):
    # Free = we can bind a fresh listening socket on it (an active listener makes bind fail
    # with EADDRINUSE regardless of SO_REUSEADDR). IPv4 is what the panel binds by default.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("0.0.0.0", p))
        return True
    except OSError:
        return False
    finally:
        s.close()

port = desired
for cand in range(desired, desired + 51):   # 5000..5050 — plenty of headroom
    if free(cand):
        port = cand
        break

cfg = {}
try:
    with open(cfg_path) as f:
        cfg = json.load(f)
except Exception:
    cfg = {}
cfg["port"] = port
os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
tmp = cfg_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
os.replace(tmp, cfg_path)
print(port)
PYEOF
}

# Return the HTTP status of a URL as a 3-digit string ("000" if unreachable),
# using curl if present and falling back to python3 (always available here) so a
# host without curl still gets a real health check instead of a false rollback.
# -k / unverified SSL: the panel may serve its own self-signed cert, so accept it here
# (this is a loopback health check, not a trust decision).
_http_code() {
    local url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -k -s -o /dev/null -w '%{http_code}' --max-time 3 "${url}" 2>/dev/null || true
    else
        python3 - "${url}" 2>/dev/null <<'PY' || true
import sys, ssl, urllib.request, urllib.error
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    print(urllib.request.urlopen(sys.argv[1], timeout=3, context=ctx).getcode())
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
# The panel may listen on either http or self-signed https (the default for a plain
# public install), so probe both and record which one answered in PANEL_SCHEME for the
# post-install URL banner.
PANEL_SCHEME="http"
health_check() {
    local port; port="$(panel_port)"
    local tries=30 code scheme
    for _ in $(seq 1 "${tries}"); do
        if [ "$(svc_active)" = "active" ]; then
            for scheme in https http; do
                code="$(_http_code "${scheme}://127.0.0.1:${port}/")"
                code="${code:-000}"
                # Healthy = a real HTTP response that isn't a server error. 000 = no
                # connection (wrong scheme / still booting), 5xx = app errored on boot.
                case "${code}" in
                    000|5??|"") : ;;
                    [1-4][0-9][0-9]) HEALTH_CODE="${code}"; PANEL_SCHEME="${scheme}"; return 0 ;;
                esac
            done
        fi
        sleep 1
    done
    HEALTH_CODE="${code:-000}"
    return 1
}

# Run git inside PANEL_DIR as the repo's owner. When the panel self-updates on a
# root/system-service install, this script runs as root but the checkout is owned
# by the service user — git refuses that ("detected dubious ownership") unless we
# operate as the owner. As root we can sudo -u <owner> without a password.
_gitc() {
    local owner=""
    [ -d "${PANEL_DIR}/.git" ] && owner="$(stat -c '%U' "${PANEL_DIR}/.git" 2>/dev/null || echo)"
    if [ "$(id -u)" -eq 0 ] && [ -n "${owner}" ] && [ "${owner}" != "root" ]; then
        sudo -u "${owner}" git -C "${PANEL_DIR}" "$@"
    else
        git -C "${PANEL_DIR}" "$@"
    fi
}

# Copy the current checkout into PANEL_DIR (skips venv/data so we never clobber
# secrets), or clone/pull from git when there's no local checkout.
fetch_code() {
    mkdir -p "${PANEL_DIR}"
    if [ -n "${SRC}" ] && [ "${SRC}" != "${PANEL_DIR}" ]; then
        tar -C "${SRC}" --exclude=./venv --exclude=./data --exclude='*.pyc' -cf - . | tar -C "${PANEL_DIR}" -xf -
    elif [ -d "${PANEL_DIR}/.git" ]; then
        _gitc fetch --quiet origin "${DEFAULT_BRANCH}"
        _gitc reset --hard --quiet "origin/${DEFAULT_BRANCH}"
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
    REQ_BEFORE="$(sha256sum "${PANEL_DIR}/requirements.txt" 2>/dev/null | awk '{print $1}')"
    fetch_code
    TO_VER="$(panel_version)"
    REQ_AFTER="$(sha256sum "${PANEL_DIR}/requirements.txt" 2>/dev/null | awk '{print $1}')"
    ok "Code updated (${FROM_VER} → ${TO_VER})"

    # Most updates are code-only. Reinstalling deps means pip resolves + may rebuild wheels,
    # which pegs the CPU on a small VPS for no reason. Skip it when requirements.txt is byte-for-byte
    # unchanged AND the venv already exists — the packages are already installed at the same version.
    info "[3/5] Installing dependencies…"
    if [ -x "${PANEL_DIR}/venv/bin/python3" ] && [ -n "${REQ_BEFORE}" ] && [ "${REQ_BEFORE}" = "${REQ_AFTER}" ]; then
        ok "Dependencies unchanged — skipping pip (nothing to build)"
    else
        install_deps
        ok "Dependencies installed"
    fi
    [ "${RUN_AS_ROOT}" -eq 1 ] && chown -R "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}"

    info "[4/5] Restarting the service…"
    svc daemon-reload || true
    svc restart linuxgsm-panel.service || true
    # Ensure the path-independent recovery command exists on existing installs too.
    if [ "$(id -u)" -eq 0 ] && [ -f "${PANEL_DIR}/recover.sh" ]; then
        ln -sf "${PANEL_DIR}/recover.sh" /usr/local/bin/linuxgsm-panel-recover 2>/dev/null || true
    fi

    info "[5/5] Verifying the panel came back up…"
    if health_check; then
        ok "Health check passed (HTTP ${HEALTH_CODE}) — now running version ${TO_VER}"
        # Prune old snapshots, keep the most recent few.
        if [ -d "${BACKUP_ROOT}" ]; then
            ls -1dt "${BACKUP_ROOT}"/*/ 2>/dev/null | tail -n +"$((KEEP_BACKUPS+1))" | xargs -r rm -rf
        fi
        echo ""
        ok "Update complete: ${FROM_VER} → ${TO_VER}"
        # If the panel now answers on HTTPS, say so explicitly. Older installs were plain
        # HTTP, and the self-signed-HTTPS default means an existing http:// bookmark would
        # otherwise just fail with ERR_EMPTY_RESPONSE and no explanation.
        if [ "${PANEL_SCHEME}" = "https" ]; then
            _uport="$(panel_port)"
            _uip="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null \
                || hostname -I 2>/dev/null | awk '{print $1}')"
            echo ""
            echo -e "  ${YELLOW}This panel now serves HTTPS.${NC} Open it at ${CYAN}https://${_uip:-<your-ip>}:${_uport}${NC}"
            echo -e "  ${YELLOW}An http:// address will NOT load (ERR_EMPTY_RESPONSE) — use https://.${NC}"
            echo -e "  ${YELLOW}The built-in cert is self-signed, so you'll see a one-time \"not private\"${NC}"
            echo -e "  ${YELLOW}warning — click Advanced → Proceed. Set up Tailscale/a domain for a trusted cert.${NC}"
        fi

        # A panel-only update doesn't need a reboot — but if the OS has pending updates,
        # apply them now and reboot (same "bake it in + prove it boots" philosophy as a
        # fresh install). Skipped entirely with PANEL_NO_UPGRADE=1, which the CI auto-deploy
        # sets so it never upgrades/reboots the panel host.
        if [ "${PANEL_NO_UPGRADE:-0}" != "1" ] && command -v apt-get >/dev/null 2>&1; then
            UPG_SUDO=""; [ "$(id -u)" -ne 0 ] && UPG_SUDO="sudo"
            export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
            ${UPG_SUDO} apt-get update -qq || true
            if [ "$(${UPG_SUDO} apt-get -s full-upgrade 2>/dev/null | grep -c '^Inst ')" -gt 0 ]; then
                echo ""
                info "System updates are available — applying them, then rebooting…"
                ${UPG_SUDO} apt-get -y -o Dpkg::Options::="--force-confold" full-upgrade \
                    || warn "Some packages could not be upgraded — continuing."
                ${UPG_SUDO} apt-get -y autoremove --purge >/dev/null 2>&1 || true
                warn "Rebooting to bake in the system update — reconnect in ~1 minute; the panel"
                warn "restarts automatically. (Press Ctrl-C in the next 15s to skip.)"
                sleep 15
                ${UPG_SUDO} reboot
            else
                ok "System packages already up to date — no reboot needed."
            fi
        fi
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

# ── One-time full OS upgrade (FRESH install only — the update path never reaches here).
# This tool is meant to bring a brand-new VPS up fast, so bring the whole system current
# up front instead of making the operator babysit apt; if the upgrade needs a reboot
# (e.g. a new kernel) we reboot at the very end. Fully non-interactive. Skip it entirely
# with PANEL_NO_UPGRADE=1.
if [ "${PANEL_NO_UPGRADE:-0}" != "1" ] && command -v apt-get >/dev/null 2>&1; then
    UPG_SUDO=""; [ "$(id -u)" -ne 0 ] && UPG_SUDO="sudo"
    info "Bringing the OS fully up to date (one-time — set PANEL_NO_UPGRADE=1 to skip)…"
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
    ${UPG_SUDO} apt-get update -qq || true
    ${UPG_SUDO} apt-get -y -o Dpkg::Options::="--force-confold" full-upgrade \
        || warn "Some packages could not be upgraded — continuing with the install."
    ${UPG_SUDO} apt-get -y autoremove --purge >/dev/null 2>&1 || true
    ok "System packages up to date"
fi

# ── Automatic OS security updates (FRESH install only). A panel meant to run
# unattended should keep itself patched, so enable unattended-upgrades by default.
# Idempotent and non-fatal — a problem here must never block the install, and it
# can always be toggled later from the panel's Diagnostics page.
if command -v apt-get >/dev/null 2>&1; then
    AU_SUDO=""; [ "$(id -u)" -ne 0 ] && AU_SUDO="sudo"
    info "Enabling automatic security updates (unattended-upgrades)…"
    export DEBIAN_FRONTEND=noninteractive
    ${AU_SUDO} apt-get install -y unattended-upgrades >/dev/null 2>&1 \
        || warn "Could not install unattended-upgrades — enable it later from the panel."
    if dpkg -s unattended-upgrades >/dev/null 2>&1; then
        # Turn on APT's daily package-list refresh + unattended security upgrade.
        if printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
                | ${AU_SUDO} tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null; then
            ok "Automatic security updates enabled"
        else
            warn "Could not enable automatic security updates — turn it on later from the panel."
        fi
    fi
fi

info "[1/4] Fetching the panel into ${PANEL_DIR}…"
fetch_code

info "[2/4] Creating virtual environment & installing dependencies…"
install_deps
ok "Dependencies installed"

# Ensure the panel's listen port is free BEFORE the first boot: if 5000 (or a previously
# configured port) is already taken by another service, the panel would fail to bind. Probe
# for a free port and record it in config.json so the service start, the health check, and
# the firewall step below all use the same, working port. (Written before the chown below so
# the root-install path fixes ownership afterward.)
DESIRED_PORT="$(panel_port)"
PANEL_PORT="$(choose_and_record_port "${DESIRED_PORT}")"
if [ "${PANEL_PORT}" != "${DESIRED_PORT}" ]; then
    warn "Port ${DESIRED_PORT} is already in use — the panel will use port ${PANEL_PORT} instead."
else
    ok "Port ${PANEL_PORT} is free for the panel"
fi

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
# Keep auto-restarting no matter how many times it has crashed — a self-healing
# appliance should keep trying to recover rather than give up and stay down.
StartLimitIntervalSec=0

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
    # Path-independent recovery command: `sudo linuxgsm-panel-recover` from anywhere.
    ln -sf "${PANEL_DIR}/recover.sh" /usr/local/bin/linuxgsm-panel-recover 2>/dev/null || true
    SERVICE_HINT="sudo systemctl status linuxgsm-panel"
    LOG_HINT="sudo journalctl -u linuxgsm-panel -f"
else
    mkdir -p "${HOME}/.config/systemd/user"
    cat > "${UNIT_FILE}" <<SERVICEEOF
[Unit]
Description=LinuxGSM Game Server Admin Panel
After=network-online.target
Wants=network-online.target
# Keep auto-restarting no matter how many times it has crashed — a self-healing
# appliance should keep trying to recover rather than give up and stay down.
StartLimitIntervalSec=0

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
# ── Hand the user the real URL(s) to open ──
PORT="$(panel_port)"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

PUBLIC_IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null \
    || curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null \
    || hostname -I 2>/dev/null | awk '{print $1}')"

# Tailscale address, only if it's installed AND logged in (MagicDNS name preferred).
TS_ADDR=""
if command -v tailscale >/dev/null 2>&1; then
    TS_DNS="$(tailscale status --json 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("Self",{}).get("DNSName","").rstrip("."))' 2>/dev/null || true)"
    TS_IP="$(tailscale ip -4 2>/dev/null | head -1)"
    TS_ADDR="${TS_DNS:-${TS_IP}}"
fi

# Firewall state.
UFW_ACTIVE=0; TS_UFW=0; PORT_OPEN=0
if command -v ufw >/dev/null 2>&1; then
    ufw status 2>/dev/null | grep -q "Status: active" && UFW_ACTIVE=1
    ufw status 2>/dev/null | grep -qi "tailscale0"    && TS_UFW=1
    ufw status 2>/dev/null | grep -qw "${PORT}"        && PORT_OPEN=1
fi

# Auto-open the port when Tailscale ISN'T already a way in (not logged in, or UFW
# doesn't allow the tailscale0 interface) — so a plain-IP install just works. If
# Tailscale access is set up we leave the public port closed (more private).
if [ "${UFW_ACTIVE}" -eq 1 ] && [ "${PORT_OPEN}" -eq 0 ] \
        && { [ -z "${TS_ADDR}" ] || [ "${TS_UFW}" -eq 0 ]; }; then
    if ${SUDO} ufw allow "${PORT}/tcp" >/dev/null 2>&1; then
        PORT_OPEN=1
        ok "Opened ${PORT}/tcp in UFW so the panel is reachable by IP."
    fi
fi

echo -e "${GREEN}Open the panel — the first visit runs the setup wizard:${NC}"
[ -n "${TS_ADDR}" ] && echo -e "  • Tailscale:  ${CYAN}${PANEL_SCHEME}://${TS_ADDR}:${PORT}${NC}"
if [ -n "${PUBLIC_IP}" ]; then
    if [ "${UFW_ACTIVE}" -eq 1 ] && [ "${PORT_OPEN}" -eq 0 ]; then
        echo -e "  • Public IP:  ${CYAN}${PANEL_SCHEME}://${PUBLIC_IP}:${PORT}${NC}  ${YELLOW}(firewalled — run 'ufw allow ${PORT}/tcp' to expose)${NC}"
    else
        echo -e "  • Public IP:  ${CYAN}${PANEL_SCHEME}://${PUBLIC_IP}:${PORT}${NC}"
    fi
fi
if [ "${PANEL_SCHEME}" = "https" ]; then
    echo ""
    echo -e "  ${YELLOW}Served over HTTPS with a built-in self-signed cert, so your browser will show a${NC}"
    echo -e "  ${YELLOW}one-time \"not private\" warning — click Advanced → Proceed. Set up Tailscale Serve${NC}"
    echo -e "  ${YELLOW}or a domain in the wizard for a trusted cert with no warning.${NC}"
fi
echo ""
warn "The panel binds 0.0.0.0:${PORT}. For real use, put it behind Tailscale Serve (HTTPS,"
warn "no open port needed) from the setup wizard — don't leave the admin panel open to the internet."
echo ""
echo -e "${CYAN}Forgot the admin password?${NC} From a shell on this server (no web login needed):"
echo -e "    sudo linuxgsm-panel-recover        ${YELLOW}# or: cd ${PANEL_DIR} && bash reset-password.sh${NC}"
echo ""

# ── Always reboot after a fresh install (unless the OS upgrade was skipped). Rebooting
#    once now bakes in the OS update AND proves the box comes back cleanly with everything
#    applied — better to find a broken boot now than the next time you actually need it.
#    The panel service is enabled on boot, so it's back at the URL above after ~1 minute.
#    Only fresh installs reach this point (the update path exits earlier). ──
if [ "${PANEL_NO_UPGRADE:-0}" != "1" ]; then
    RB_SUDO=""; [ "$(id -u)" -ne 0 ] && RB_SUDO="sudo"
    warn "Rebooting to finish setup — bakes in the OS update and confirms the machine boots"
    warn "cleanly. Reconnect in ~1 minute; the panel will already be running at the URL above."
    warn "(Press Ctrl-C in the next 15s to skip.)"
    sleep 15
    ${RB_SUDO} reboot
fi
