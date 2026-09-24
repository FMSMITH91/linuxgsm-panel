#!/usr/bin/env bash
set -euo pipefail

# Absolute path to THIS script — install_root_tools copies it to the root-owned location, and
# "$0" inside a function is fragile to read. Captured once, before any cd.
SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

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
#     manage the local host (create game-server users, apt, ufw…), so a NOPASSWD
#     sudoers entry is added for it.
#
#     WHAT THAT GRANT IS, precisely. On a fresh root install where all three
#     root-owned pieces below land, it is now:
#
#         <user> ALL=(root) NOPASSWD: /usr/local/lib/linuxgsm-panel/panel-helper
#
#     One command. The helper accepts a fixed verb table, validates every argument,
#     builds argv itself, and can reach no shell — resolve("bash") raises by design.
#
#     For years this said `ALL=(ALL) NOPASSWD:ALL`, and it was honest about it: there
#     was no privilege boundary between "the web panel is compromised" and "the host
#     is root-owned". Narrowing needed every privileged call site routed through the
#     helper first, because a sudoers rule permitting /bin/bash — or systemd-run, or
#     the tailscale binary, each of which runs whatever you hand it — is exactly
#     equivalent to NOPASSWD:ALL. A "scoped" list containing any of them would read
#     as narrower while granting identical power. None of them is in the narrow grant.
#
#     It also needed root to stop executing code out of the panel's own checkout.
#     PANEL_DIR is chown'd to the service user and rewritten by `git pull` on every
#     self-update, so a boundary that let root run files from it would have been
#     decorative. db_maintenance.py and this installer are therefore installed
#     root-owned beside the helper, and placed ONLY here — never by a verb.
#
#     THE GRANT STAYS WIDE if any of those pieces is missing, which is what happens
#     when this script has not been re-run as root since the update: the panel falls
#     back to `sudo bash -c '<verb rendered as text>'`, and narrowing under that
#     would break every privileged action rather than secure anything. Re-run this
#     installer as root to get the narrow grant. It prints which one it wrote.
#
#     If you only manage REMOTE servers from this panel, delete
#     /etc/sudoers.d/linuxgsm-panel — the panel keeps working and the grant goes
#     away entirely.
# ─────────────────────────────────────────────────────────

REPO_URL="https://github.com/FMSMITH91/linuxgsm-panel.git"
# Branch to track. The panel can switch branches from the UI by exporting PANEL_BRANCH
# before invoking this script; unset (the normal path) keeps the default "main" unchanged.
# Restricted to a safe git-ref charset so it can't inject options/paths into git commands.
DEFAULT_BRANCH="main"
if [ -n "${PANEL_BRANCH:-}" ] && printf '%s' "${PANEL_BRANCH}" | grep -Eq '^[A-Za-z0-9._/-]{1,100}$' \
   && [ "${PANEL_BRANCH#-}" = "${PANEL_BRANCH}" ] && [ "${PANEL_BRANCH##*..*}" = "${PANEL_BRANCH}" ]; then
    DEFAULT_BRANCH="${PANEL_BRANCH}"
fi
SERVICE_USER="lgsmpanel"          # dedicated user created for root installs
# The group the panel's SECOND sudoers line names in its Runas position. Membership of it means
# "the panel may become this account" — never root, which stays reachable only through the helper.
# Must match privileged.GAME_GROUP and tools/panel-helper's GAME_GROUP.
GAME_GROUP="lgsmpanel-games"
KEEP_BACKUPS=3                    # how many previous-version snapshots to retain

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}$*${NC}"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
# A `die` is a DELIBERATE, explained exit — it has already said what went wrong and what state the
# panel is left in. The update path arms an EXIT trap over the window where the panel is stopped
# (see [1/6]) to catch the UNexplained aborts: `set -e` on a failed pip, a full disk mid-fetch.
# Letting that trap ALSO print its generic [ERROR] on top of the accurate one would just bury it,
# so record that the operator has already been told and let the handler skip that one sentence.
#
# What this must NOT do is `trap - ERR EXIT`. That was tried, and it disarmed the handler for every
# die in the file — including the three reached through a FUNCTION CALL inside the stopped window
# (fetch_code's missing git, and the `visudo -cf` check in write_sudoers_grant and
# write_terminal_sudo_grant), each of which then exited with the panel still stopped: the exact
# outcome the trap was added to prevent, and a bug the next `die` added in there would inherit.
# The recovery is the handler's job for ALL exits; only the wording is conditional.
die()   { _DIE_SAID=1; echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

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
# BEFORE choosing a mode, look for an install belonging to the OTHER one.
#
# The update check further down asks "is there an app.py and a unit file where I am about to
# install?" — but where that is has already been decided by how this script was invoked. Run as
# root it looks under the service user's home; run as yourself it looks under yours. Neither sees
# the other, so `sudo ./install.sh` on a host with a working per-user install found nothing,
# declared a fresh install, created the service user and built a SECOND panel beside the first:
# two services, two databases, both wanting the same port.
#
# Refuse instead, and say exactly what was found. Adopting the other install automatically would
# mean moving a running service between systemd scopes (--user to system or back) and re-owning
# its data directory, which is a bigger and more dangerous operation than this script should
# perform without being asked.
_other_install=""
if [ "$(id -u)" -eq 0 ]; then
    # Running as root: is there a per-user install under some human's home?
    for _h in /home/*; do
        [ -f "${_h}/linuxgsm-panel/app.py" ] || continue
        _u="$(basename "${_h}")"
        [ "${_u}" = "${SERVICE_USER}" ] && continue      # that IS the root-install location
        [ -f "${_h}/.config/systemd/user/linuxgsm-panel.service" ] || continue
        _other_install="${_h}/linuxgsm-panel (per-user service, owned by '${_u}')"
        break
    done
elif [ -f "/etc/systemd/system/linuxgsm-panel.service" ]; then
    # Running as a normal user: is there already a system-service install?
    _other_install="a system service (/etc/systemd/system/linuxgsm-panel.service)"
fi
if [ -n "${_other_install}" ]; then
    warn "This host already has a LinuxGSM Panel installed in the OTHER service model:"
    warn "    ${_other_install}"
    warn "Installing the way you just invoked this script would create a SECOND, separate panel —"
    warn "its own user, service, database and port — rather than updating the one you have."
    if [ "$(id -u)" -eq 0 ]; then
        warn "To update the existing install, run it AS THAT USER, without sudo:"
        warn "    sudo -u <that-user> -i bash ~/linuxgsm-panel/install.sh"
    else
        warn "To update the existing install, run this script as root:"
        warn "    sudo bash install.sh"
    fi
    die "Refusing to build a parallel install."
fi

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
#
# AS THE OWNER of PANEL_DIR when that is not root. Every path this writes is inside data/, and on
# any re-run after the first chown data/ belongs to the panel user. The panel user can force this
# path by deleting its own app.py. As root, open("w"), os.replace and os.chmod follow a symlink the
# panel user planted there (config.json.tmp used to be a fixed name), so root truncated, rewrote
# and chmodded a file of the panel user's choosing. Dropping to the owner makes the kernel refuse
# that. The script also refuses symlinks and uses an O_EXCL temp file itself, for the one case
# that stays root: a fresh install, where root still owns the tree.
choose_and_record_port() {
    local desired="${1:-5000}" as_owner="" owner=""
    if [ "$(id -u)" -eq 0 ]; then
        owner="$(stat -c '%U' "${PANEL_DIR}" 2>/dev/null || echo root)"
        [ "${owner}" != "root" ] && as_owner="sudo -u ${owner}"
    fi
    ${as_owner} python3 - "${desired}" "${PANEL_DIR}/data/config.json" <<'PYEOF'
import json, os, socket, sys, tempfile
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

port = None
for cand in range(desired, desired + 51):   # 5000..5050 — plenty of headroom
    if free(cand):
        port = cand
        break

# Exhausting the range is a THIRD answer, and it used to print as the happiest of the other two.
# `port` started at `desired` — the value the loop's own first iteration had just measured as BUSY
# — so a host with nothing free in 5000..5050 wrote 5000 into config.json and the caller, which
# compares only against the input, printed "✓ Port 5000 is free for the panel". The service then
# could not bind, systemd restarted it every 5s under Restart=always, the health check timed out,
# and the operator was sent to the logs having been told the port was free. Record nothing and
# print nothing; the caller turns the empty answer into a die() naming the range.
if port is None:
    raise SystemExit(0)

data_dir = os.path.dirname(cfg_path)
os.makedirs(data_dir, exist_ok=True)
# Never write through a link: open(), os.chmod and a fixed temp name all follow one.
if os.path.islink(data_dir) or os.path.islink(cfg_path):
    sys.stderr.write("Refusing to record the port: %s or its config.json is a symbolic link.\n"
                     % data_dir)
    raise SystemExit(3)
cfg = {}
try:
    with open(cfg_path) as f:
        cfg = json.load(f)
except Exception:
    cfg = {}
cfg["port"] = port
try:
    os.chmod(data_dir, 0o700)   # owner-only: keep the DB/keys/config out of other local users' reach
except OSError:
    pass
# mkstemp opens O_CREAT|O_EXCL|O_NOFOLLOW under a random name, 0600 from the start.
fd, tmp = tempfile.mkstemp(dir=data_dir, prefix=".config.json.")
try:
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, cfg_path)
except BaseException:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
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
        # --no-same-owner: as root, tar would otherwise give the copy SRC's owners. A fresh install
        # then chowns it to the panel user anyway; before that, stage_root_source reads the copy
        # directly only when every file in it is root's.
        tar -C "${SRC}" --exclude=./venv --exclude=./data --exclude='*.pyc' -cf - . \
            | tar -C "${PANEL_DIR}" --no-same-owner -xf -
    elif [ -d "${PANEL_DIR}/.git" ]; then
        # The fresh clone below is shallow + single-branch (main only). Widen it so ANY branch is
        # fetchable and give it real history, so switching branches / updating on a branch works.
        _gitc remote set-branches origin '*' 2>/dev/null || true
        _gitc fetch --quiet --prune --unshallow origin 2>/dev/null \
            || _gitc fetch --quiet --prune origin 2>/dev/null \
            || _gitc fetch --quiet origin "${DEFAULT_BRANCH}"
        # Default target is the fetched branch tip. The panel's CI-gated self-update may instead
        # pin PANEL_UPDATE_REF to the newest CI-VERIFIED commit (which can be below the tip when
        # newer commits are still being checked). Honour it ONLY when it's an ancestor of the tip
        # we just fetched, so a bogus value can never check out arbitrary or untracked code.
        local _target="origin/${DEFAULT_BRANCH}"
        if [ -n "${PANEL_UPDATE_REF:-}" ] \
           && _gitc merge-base --is-ancestor "${PANEL_UPDATE_REF}" "origin/${DEFAULT_BRANCH}" 2>/dev/null; then
            _target="${PANEL_UPDATE_REF}"
            echo "  Updating to verified commit ${PANEL_UPDATE_REF}"
        fi
        _gitc reset --hard --quiet "${_target}"
    elif [ -z "${SRC}" ]; then
        command -v git >/dev/null 2>&1 || die "git is required to fetch the panel.  apt install -y git"
        # --no-single-branch keeps the clone shallow (fast) but fetches EVERY branch tip, so the
        # panel's branch switcher can see + check out non-main branches without re-fetching history.
        git clone --depth 1 --no-single-branch --branch "${DEFAULT_BRANCH}" "${REPO_URL}" "${PANEL_DIR}"
    fi
}

# Read-only counterpart to fetch_code: fetch and work out which commit we'd update TO,
# WITHOUT touching the working tree — so the update path can skip the snapshot + restart
# entirely when already current. Sets CURRENT_SHA / TARGET_REF / TARGET_SHA. Returns 1 only
# if the fetch itself fails (offline / private repo), so the caller can stop cleanly.
resolve_update_target() {
    CURRENT_SHA=""; TARGET_REF=""; TARGET_SHA=""
    if [ -n "${SRC}" ] && [ "${SRC}" != "${PANEL_DIR}" ]; then
        return 0   # local-source update: no git comparison, always applies
    fi
    [ -d "${PANEL_DIR}/.git" ] || return 0   # not a git checkout: let fetch_code decide
    _gitc fetch --quiet origin "${DEFAULT_BRANCH}" || return 1
    CURRENT_SHA="$(_gitc rev-parse HEAD 2>/dev/null)"
    TARGET_REF="origin/${DEFAULT_BRANCH}"
    if [ -n "${PANEL_UPDATE_REF:-}" ] \
       && _gitc merge-base --is-ancestor "${PANEL_UPDATE_REF}" "origin/${DEFAULT_BRANCH}" 2>/dev/null; then
        TARGET_REF="${PANEL_UPDATE_REF}"
        # A pinned commit this checkout already contains is not an update when the checkout is
        # itself a newer commit of the branch: stay put rather than reset backwards. The deploy
        # pins each run to the commit whose CI passed, and those runs do not finish in push order
        # (a re-run of an old commit's CI deploys it last). A HEAD that is NOT on the branch (a
        # local commit) is still reset, as it always was.
        if _gitc merge-base --is-ancestor "${PANEL_UPDATE_REF}" HEAD 2>/dev/null \
           && _gitc merge-base --is-ancestor HEAD "origin/${DEFAULT_BRANCH}" 2>/dev/null; then
            TARGET_REF="HEAD"
        fi
    fi
    TARGET_SHA="$(_gitc rev-parse "${TARGET_REF}" 2>/dev/null)"
    return 0
}

# pip runs setup.py and wheel hooks, so "install the dependencies" is "execute code from
# requirements.txt". On the UPDATE path both the pip binary and that file belong to the panel
# user, and the update runs as root — so this was the panel choosing what root executes. Drop to
# the owner when there is an owner to drop to: the venv is theirs anyway, and a root-built one
# leaves root-owned files the service then cannot rewrite.
#
# The condition is "PANEL_DIR already belongs to PANEL_USER", which is precisely when dropping
# works. On the FRESH path it does not yet (the chown comes later), and there the requirements
# came from a clone of REPO_URL that the operator asked for as root — so that path is unchanged.
install_deps() {
    local as_owner=""
    if [ "$(id -u)" -eq 0 ] && [ -n "${PANEL_USER:-}" ] && [ "${PANEL_USER}" != "root" ] \
       && [ "$(stat -c '%U' "${PANEL_DIR}" 2>/dev/null || echo root)" = "${PANEL_USER}" ]; then
        as_owner="sudo -u ${PANEL_USER}"
    fi
    ${as_owner} python3 -m venv "${PANEL_DIR}/venv"
    ${as_owner} "${PANEL_DIR}/venv/bin/pip" install --quiet --upgrade pip
    ${as_owner} "${PANEL_DIR}/venv/bin/pip" install --quiet -r "${PANEL_DIR}/requirements.txt"
}

# Node.js LTS + jq + gamedig, for the panel's game-server player queries (player count/list, the
# empty-only restart, and the moderation Players panel). Installed on the panel HOST so game
# servers running here can be queried; remote hosts get it from the add-remote bootstrap. apt's
# own nodejs is too old for current gamedig (needs Node >=18), so we pin LTS via NodeSource.
# Fully idempotent + best-effort — a failure here must never break the install; player queries
# simply stay unavailable until it's sorted.

# NodeSource's apt repository, configured HERE rather than by running their setup script. That
# script (setup_lts.x) was downloaded and executed as root with nothing checked: whoever could
# serve that one URL — a compromised web host, or anything able to alter the fetch — ran code as
# root on every host installing Node. What the script does is small and fixed (fetch the signing
# key, write a deb822 source and an apt pin), so it is done here, and the one thing fetched — the
# signing key — must be exactly the key below, by fingerprint, before apt is told to trust it.
# Packages are then verified by apt against that key, not against whatever a URL served.
# Bump NODESOURCE_NODE_MAJOR deliberately (setup_lts.x chose 24.x when this was written); the
# fingerprint is NodeSource's published repository key and changes only if they rotate it.
NODESOURCE_KEY_FPR="6F71F525282841EEDAF851B42F59B5F99B1BE0B4"
NODESOURCE_NODE_MAJOR="24"
NODESOURCE_KEY_URL="https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"
NODESOURCE_KEYRING="/usr/share/keyrings/nodesource.gpg"
NODESOURCE_SOURCES="/etc/apt/sources.list.d/nodesource.sources"
NODESOURCE_PREFS="/etc/apt/preferences.d/nodejs"

# 0 if the ASCII-armored key file $1 holds exactly ONE primary key and it is NODESOURCE_KEY_FPR.
# One, not "includes": a file carrying the real key plus a second one would have apt trust both.
nodesource_key_ok() {
    command -v gpg >/dev/null 2>&1 || return 1
    local gh listing
    gh="$(mktemp -d 2>/dev/null)" || return 1
    listing="$(GNUPGHOME="${gh}" gpg --batch --with-colons --show-keys "$1" 2>/dev/null || true)"
    rm -rf "${gh}"
    [ "$(printf '%s\n' "${listing}" | awk -F: '$1=="pub"{n++} END{print n+0}')" = "1" ] || return 1
    [ "$(printf '%s\n' "${listing}" | awk -F: '$1=="fpr"{print $10; exit}')" = "${NODESOURCE_KEY_FPR}" ]
}

# Configure NodeSource's repository with the pinned key. $1 is the sudo prefix ("" or "sudo").
# 0 once the source is written and apt has read it; 1, having trusted nothing, otherwise.
nodesource_setup() {
    local S="$1" arch key gh rc=1
    arch="$(dpkg --print-architecture 2>/dev/null || true)"
    case "${arch}" in amd64|arm64) ;; *) return 1 ;; esac   # the only two NodeSource builds
    command -v gpg >/dev/null 2>&1 || ${S} apt-get install -y gnupg >/dev/null 2>&1 || true
    key="$(mktemp 2>/dev/null)" || return 1
    gh="$(mktemp -d 2>/dev/null)" || { rm -f "${key}"; return 1; }
    if curl -fsSL --connect-timeout 15 --max-time 60 "${NODESOURCE_KEY_URL}" -o "${key}" 2>/dev/null \
        && nodesource_key_ok "${key}" \
        && GNUPGHOME="${gh}" gpg --batch --yes --dearmor -o "${key}.gpg" "${key}" 2>/dev/null \
        && ${S} install -d -m 0755 "$(dirname "${NODESOURCE_KEYRING}")" 2>/dev/null \
        && ${S} install -m 0644 "${key}.gpg" "${NODESOURCE_KEYRING}" 2>/dev/null; then
        # The one-line nodesource.list an older setup script wrote would name the same repo twice.
        ${S} rm -f "$(dirname "${NODESOURCE_SOURCES}")/nodesource.list" 2>/dev/null || true
        if printf 'Types: deb\nURIs: https://deb.nodesource.com/node_%s.x\nSuites: nodistro\nComponents: main\nArchitectures: %s\nSigned-By: %s\n' \
                "${NODESOURCE_NODE_MAJOR}" "${arch}" "${NODESOURCE_KEYRING}" \
                | ${S} tee "${NODESOURCE_SOURCES}" >/dev/null 2>&1 \
            && printf 'Package: nodejs\nPin: origin deb.nodesource.com\nPin-Priority: 600\n' \
                | ${S} tee "${NODESOURCE_PREFS}" >/dev/null 2>&1 \
            && ${S} apt-get update >/dev/null 2>&1; then
            rc=0
        fi
    fi
    rm -rf "${key}" "${key}.gpg" "${gh}"
    return "${rc}"
}

ensure_gamedig() {
    command -v apt-get >/dev/null 2>&1 || return 0
    # Every command below is guarded so it returns 0 — the script runs under `set -euo pipefail`,
    # so an unguarded failure here (e.g. a missing `node`) would abort the whole install.
    local S=""
    [ "$(id -u)" -eq 0 ] || S="sudo"
    if ! command -v jq >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
        ${S} apt-get install -y jq curl >/dev/null 2>&1 || true
    fi
    # pigz (parallel gzip) makes the update snapshot ~3.5x faster on a multi-core host — tiny, optional.
    command -v pigz >/dev/null 2>&1 || ${S} apt-get install -y pigz >/dev/null 2>&1 || true
    # Read Node's major version ONLY if node exists: `node -v` on a host without node fails the pipe
    # under `set -o pipefail`, which would kill install.sh. Absent/unparseable => 0 => (re)install.
    local nmaj=0
    if command -v node >/dev/null 2>&1; then
        nmaj="$(node -v 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)"
        nmaj="${nmaj:-0}"
    fi
    # Prefer the distro's own nodejs when it is new enough. NodeSource publishes ONE repo per
    # distro codename, so in the weeks after a new LTS lands that codename can be missing — which
    # is exactly when people are installing onto it. Ubuntu 24.04 ships Node 18 and 26.04 ships
    # newer still, so on a current release this needs no third-party repo at all. 22.04 ships
    # Node 12, which is why the NodeSource fallback below stays.
    if [ "${nmaj:-0}" -lt 18 ] 2>/dev/null; then
        local cand=0
        cand="$(apt-cache policy nodejs 2>/dev/null | awk '/Candidate:/{print $2}' \
                | grep -oE '^[0-9]+' | head -1 || true)"
        cand="${cand:-0}"
        if [ "${cand:-0}" -ge 18 ] 2>/dev/null; then
            info "Installing Node.js ${cand} from the distro (gamedig needs it for player queries)…"
            ${S} apt-get install -y nodejs >/dev/null 2>&1 || true
            if command -v node >/dev/null 2>&1; then
                nmaj="$(node -v 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)"
                nmaj="${nmaj:-0}"
            fi
        fi
    fi
    if [ "${nmaj:-0}" -lt 18 ] 2>/dev/null; then
        info "Installing Node.js ${NODESOURCE_NODE_MAJOR} from NodeSource (gamedig needs it for player queries)…"
        # NodeSource's repository with its signing key pinned by fingerprint — see nodesource_setup.
        # Their setup script is no longer downloaded and run as root.
        if nodesource_setup "${S}"; then
            ${S} apt-get install -y nodejs >/dev/null 2>&1 \
                || warn "Node.js install failed — player queries stay unavailable until installed."
        else
            warn "NodeSource's repository could not be set up with its pinned signing key — Node.js was not installed, and player queries stay unavailable until Node.js 18+ is."
        fi
    fi
    if command -v npm >/dev/null 2>&1 && ! command -v gamedig >/dev/null 2>&1; then
        info "Installing gamedig globally…"
        # The spec the panel's npm-install-global verb and the weekly cron use: v5, no install hooks.
        ${S} npm install -g --ignore-scripts gamedig@5 >/dev/null 2>&1 \
            || warn "gamedig install failed — player queries unavailable."
    fi
    if command -v gamedig >/dev/null 2>&1; then
        ok "gamedig ready for player queries"
    fi
    # Weekly auto-update for gamedig, alongside the host's other automatic updates, so player queries
    # don't silently break as games/gamedig evolve. Idempotent; no-op if npm isn't installed. Pinned to
    # v5 with --ignore-scripts, and npm itself is not updated: this runs as root, unattended, every
    # week. Byte-identical to the helper's NODE_TOOLS_CRON_BODY and hosts.py's (a unit gate).
    local cf="/etc/cron.d/lgsm-node-tools"
    if printf '%s\n' \
        '# LinuxGSM Panel - keep gamedig current for player queries (managed by the panel).' \
        'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \
        '30 4 * * 0 root command -v npm >/dev/null 2>&1 && npm install -g --ignore-scripts gamedig@5 >/var/log/lgsm-node-tools.log 2>&1' \
        | ${S} tee "${cf}" >/dev/null 2>&1; then
        ${S} chmod 644 "${cf}" 2>/dev/null || true
    fi
    return 0
}

# fail2ban on the panel HOST, so the panel-login brute-force jail (which the panel configures and
# self-heals on startup) has something to bind to. Best-effort + idempotent — a failure here just
# means the jail stays off until fail2ban is installed; it must NEVER abort the install (the script
# runs under set -euo pipefail), so every command is guarded.
ensure_fail2ban() {
    command -v apt-get >/dev/null 2>&1 || return 0
    if command -v fail2ban-client >/dev/null 2>&1; then
        ok "fail2ban present (panel-login brute-force protection)"
        return 0
    fi
    local S=""
    [ "$(id -u)" -eq 0 ] || S="sudo"
    info "Installing fail2ban (brute-force protection for the panel login)…"
    ${S} apt-get install -y fail2ban >/dev/null 2>&1 \
        || warn "fail2ban install failed — panel-login brute-force protection stays off until it's installed."
    return 0
}

# Run the panel (and its bursts: updates, backups, page-load probes) at LOW CPU/IO priority so it
# yields to the game servers under contention — important on a 1-core VPS. Game servers autostart
# via their own cron (nice 0), so they keep priority; the panel just waits its turn. Written as a
# systemd DROP-IN so it applies on updates too (the main unit is only written on a fresh install)
# and survives future unit changes.
ensure_service_tuning() {
    local dir
    if [ "${RUN_AS_ROOT}" -eq 1 ]; then
        dir="/etc/systemd/system/linuxgsm-panel.service.d"
    else
        dir="${HOME}/.config/systemd/user/linuxgsm-panel.service.d"
    fi
    mkdir -p "${dir}"
    cat > "${dir}/priority.conf" <<'PRIOEOF'
[Service]
Nice=10
CPUWeight=30
IOSchedulingClass=best-effort
IOSchedulingPriority=6
PRIOEOF
    svc daemon-reload || true
}

# Prefer RAM over swap on small game hosts. The default vm.swappiness=60 makes the kernel swap out
# pages the game/panel still want even when RAM is free, adding disk-latency stalls. 10 keeps active
# memory in RAM but still lets swap save us from OOM under real pressure (so we DON'T disable swap).
# Root-only (writes /etc/sysctl.d); namespaced file so it's easy to find/remove. Idempotent.
ensure_system_tuning() {
    [ "${RUN_AS_ROOT}" -eq 1 ] || return 0
    cat > /etc/sysctl.d/99-linuxgsm-panel.conf <<'SYSCTLEOF'
# LinuxGSM Panel host tuning — prefer RAM over swap (swap stays as an OOM safety net, just used less).
vm.swappiness=10
vm.vfs_cache_pressure=50
SYSCTLEOF
    sysctl --system >/dev/null 2>&1 || true
}

# ── The privileged helper and its root-owned siblings ──────────────────────────────────────
# tools/panel-helper is copied to a root-owned location OUTSIDE the panel's checkout, together
# with db_maintenance.py, panel.conf and this installer. That placement is the entire point: the
# checkout belongs to the panel user and is rewritten by `git pull` on every self-update, so a
# helper living there would be panel-writable by design — and a privilege boundary the untrusted
# side can edit is not a boundary.
#
# THIS IS A FUNCTION, AND THE UPDATE PATH CALLS IT TOO. It used to be a straight-line block that
# sat AFTER the update path's `exit 0`, so an update — in-panel self-update, the CI auto-deploy,
# or a plain re-run of this script — refreshed the panel's code and left the installed helper at
# whatever version first placed it. The verb table grows nearly every release, and a stale helper
# answers a new verb with `unknown verb` + rc 2 and no fallback, so the feature behind it simply
# stopped working with no message anywhere. The grant was never re-evaluated either, which meant a
# host that first installed pre-helper kept NOPASSWD:ALL forever.
#
# Is this checkout's `origin` the repository THIS installer knows?
#
# The update path runs `git reset --hard origin/<branch>` and then, as root, installs files out of
# the result — including tools/panel-helper over the path the sudoers rule names. `origin` is
# recorded in the panel-owned .git/config and `_gitc` runs git AS THE CHECKOUT OWNER, so a
# compromised panel could point it at a repository of its own and have root install its code as
# the privilege boundary. It cannot change THIS file: install.sh runs from a root-owned copy
# outside the checkout, so REPO_URL here is the thing to compare against.
#
# Running a fork is legitimate, so this does not refuse the update — the code still updates. It
# withholds only the ROOT-OWNED installs, which is the part that crosses a boundary, and says so.
# The panel's Diagnostics card already surfaces a helper/code version mismatch.
ORIGIN_TRUSTED=1
check_origin_trusted() {
    [ -d "${PANEL_DIR}/.git" ] || return 0
    local url
    url="$(_gitc remote get-url origin 2>/dev/null || echo)"
    case "${url}" in
        "${REPO_URL}"|"${REPO_URL%.git}"|"${REPO_URL%.git}.git") return 0 ;;
    esac
    ORIGIN_TRUSTED=0
    warn "This checkout's git origin is '${url:-unset}', not ${REPO_URL}."
    warn "Root-owned components (the privileged helper, db_maintenance, this installer) will NOT"
    warn "be refreshed from it. Re-run this installer by hand if you mean to update them."
    return 0
}

# ── Where root's copy of a boundary file comes from ────────────────────────────────────────────
# NOT the working tree. install_root_tools installs three files root-owned: the helper the sudoers
# rule names, db_maintenance.py (root runs it) and this installer (root runs it on every
# self-update). All three live in ${PANEL_DIR}, which belongs to the PANEL user, and the integrity
# argument was "fetch_code ran `git reset --hard` first, so these are upstream's bytes". They are
# not. Two untracked, panel-owned files inside .git/ defeat it, and _gitc runs git AS THE CHECKOUT
# OWNER, so git honours both:
#
#   * `git update-index --skip-worktree <path>` makes `reset --hard` leave that path alone.
#     Attacker content survives it — and so does a DELETION, which used to zero HELPER_OK and made
#     write_sudoers_grant widen the grant back to NOPASSWD:ALL. The panel user could delete its own
#     sudo restriction by removing a file it owns.
#   * a smudge filter (.git/info/attributes plus filter.<name>.smudge in .git/config) rewrites the
#     file DURING checkout, so `reset --hard` writes the filter's output, not the committed blob.
#
# check_origin_trusted() compares the remote URL and is blind to both.
#
# Reading the committed blob instead (`git cat-file blob HEAD:<path>` through _gitc) closed those
# two and left the rest of .git. The OBJECT STORE is panel-owned too, and git trusts it:
#
#   * a replace ref (`git replace <committed-blob> <attacker-blob>`, i.e. .git/refs/replace/<sha>)
#     makes cat-file return the attacker's bytes, while `rev-parse HEAD` still names the real
#     upstream commit;
#   * a loose object written under the committed blob's name shadows the packed original, and git
#     returns it without re-hashing.
#
# And with no .git at all, the tree was copied as-is. The panel user can delete its own .git.
#
# So when this runs as ROOT, a boundary file comes from something the panel user cannot write:
#
#   * a checkout that is still ROOT'S OWN, tree and .git (the fresh path, before the chown). It
#     is read directly, exactly as before; or else
#   * the OPERATOR'S SOURCE TREE — `sudo bash install.sh` run from a clone or an unpacked tarball
#     (SRC, when that is not ${PANEL_DIR}, and only while the installer running is that tree's own)
#     — when that directory, every directory above it, and every entry down to the file are beyond
#     the panel user's reach, with no symlink on the way down (_operator_src, _operator_file).
#     fetch_code has just copied that very working tree into ${PANEL_DIR}, so this keeps the
#     helper in step with the code it installed, and the operator chose it as root: refusing it
#     (no .git, a local or feature-branch commit, no network) protected nothing and left the
#     helper stale on every such update; or else
#   * ROOT'S OWN CLONE of REPO_URL (ROOT_GIT, below), fetched by root's git with no user or system
#     config. The panel's HEAD is only a request there: it is honoured only when root's clone has
#     that commit on ${DEFAULT_BRANCH}. Nothing else from the panel's .git is read. A checkout at a
#     commit upstream does not have, or with no .git at all, gets NO refresh, and the installer
#     says so.
#
# Run as the account that owns the checkout (a per-user install), none of this applies: that
# account can already rewrite the install.sh it is running.
#
# Either way the output is staged inside HELPER_DIR, which is root-owned 0755 and therefore not
# panel-writable. That is what closes the window between staging and `install`.
# Root-owned, outside the panel's checkout — see stage_root_source and SECURITY.md.
HELPER_DIR="/usr/local/lib/linuxgsm-panel"
ROOT_GIT="${HELPER_DIR}/.source.git"
ROOT_SRC_COMMIT=""
ROOT_SRC_TRIED=0

# Root's git, on root's clone, with no config it did not write: no user or system gitconfig (a
# `url.<x>.insteadOf` there would repoint REPO_URL, a credential helper would run as root), and no
# inherited GIT_* environment. The proxy variables are the only ones passed through.
_rootgit() {
    ${H_SUDO:-} env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=true \
        ${https_proxy:+https_proxy="${https_proxy}"} ${HTTPS_PROXY:+HTTPS_PROXY="${HTTPS_PROXY}"} \
        ${no_proxy:+no_proxy="${no_proxy}"} ${NO_PROXY:+NO_PROXY="${NO_PROXY}"} \
        git --git-dir="${ROOT_GIT}" "$@"
}

# Does the panel user have no hand in this checkout? True only when every file and directory in
# it, .git included, is root's. find does not follow symlinks, so a link is judged by its own owner.
_checkout_is_roots() {
    [ -d "${PANEL_DIR}" ] && [ ! -L "${PANEL_DIR}" ] || return 1
    [ -z "$(find "${PANEL_DIR}" ! -uid 0 -print -quit 2>/dev/null)" ]
}

# The panel user's uid and groups, for the reach tests below. Fails when there is no such account,
# so every reach test fails closed with it.
_panel_ids() {
    _PR_UID="$(id -u "${PANEL_USER:-}" 2>/dev/null)" && [ -n "${_PR_UID}" ] || return 1
    _PR_GIDS=" $(id -G "${PANEL_USER}" 2>/dev/null) "
}

# Can the panel user neither write this one entry nor replace what it holds? Judged on the entry
# itself — stat does not follow a symlink: it must not be the panel user's, nor writable by it
# through the group or other bits. A symlink's own mode means nothing, and a sticky directory
# (/tmp) is exempt from the mode test, because there only an entry's owner can remove or rename
# it; the callers judge every entry below on its own. Needs _panel_ids first.
_panel_cannot_write() {
    local st u g m
    st="$(stat -c '%u %g %a' -- "$1" 2>/dev/null)" || return 1
    read -r u g m <<< "${st}"
    m=$((8#${m}))
    [ -n "${_PR_UID:-}" ] && [ "${u}" != "${_PR_UID}" ] || return 1
    [ ! -L "$1" ] || return 0
    if [ ! -d "$1" ] || [ $((m & 01000)) -eq 0 ]; then
        [ $((m & 02)) -eq 0 ] || return 1
        [ $((m & 020)) -eq 0 ] || [ "${_PR_GIDS#* "${g}" }" = "${_PR_GIDS}" ] || return 1
    fi
}

# The operator's own source tree, resolved: `sudo bash install.sh` run from a clone or an unpacked
# tarball (SRC, the working directory) rather than inside ${PANEL_DIR}. Printed only when
#   * the installer running now is THAT tree's install.sh. Root is already executing a file from
#     it, so reading three more from it trusts nobody new — and that, not the working directory,
#     is what makes it the operator's choice. The panel's self-update verb runs the root-owned
#     copy in ${HELPER_DIR} with its working directory in the checkout, so it never qualifies,
#     wherever the panel user makes that directory lead;
#   * the directory is not ${PANEL_DIR} by any spelling (a symlinked home, or a link the panel
#     user put in its place) — the string comparison above is only a shortcut; and
#   * it and every directory above it are beyond the panel user's reach. Nothing INSIDE it is
#     consulted to decide that: judged after following links, a panel-owned checkout could vouch
#     for itself with `app.py -> /etc/passwd`.
_operator_src() {
    local rs p
    [ -n "${SRC:-}" ] && [ "${SRC}" != "${PANEL_DIR}" ] && _panel_ids || return 1
    rs="$(readlink -f -- "${SRC}" 2>/dev/null)" && [ -d "${rs}" ] || return 1
    [ "$(readlink -f -- "${SCRIPT_PATH:-}" 2>/dev/null)" = "${rs}/install.sh" ] || return 1
    [ "${rs}" != "$(readlink -f -- "${PANEL_DIR}" 2>/dev/null)" ] || return 1
    p="${rs}"
    while :; do
        _panel_cannot_write "${p}" || return 1
        [ "${p}" != "/" ] || break
        p="$(dirname -- "${p}")"
    done
    printf '%s\n' "${rs}"
}

# One boundary file in the operator's tree ($1, as _operator_src printed it; $2, the path below
# it). Every entry on the way down must be a real directory and the last a regular file — no
# symlink anywhere, so nothing is read from where a link lands — and none may be writable by the
# panel user. Prints the path to read.
_operator_file() {
    local p="$1" part
    local -a parts
    _panel_ids || return 1
    IFS=/ read -ra parts <<< "$2"
    for part in "${parts[@]}"; do
        case "${part}" in ""|.|..) return 1 ;; esac
        p="${p}/${part}"
        [ ! -L "${p}" ] && _panel_cannot_write "${p}" || return 1
    done
    [ -f "${p}" ] || return 1
    printf '%s\n' "${p}"
}

# Which commit root may stage from: the checkout's HEAD, once root's own clone shows that commit is
# on REPO_URL's ${DEFAULT_BRANCH}. Sets ROOT_SRC_COMMIT; returns 1, having said why, otherwise.
# Asked once per run, however many files are staged.
root_source_commit() {
    if [ "${ROOT_SRC_TRIED}" -eq 1 ]; then
        [ -n "${ROOT_SRC_COMMIT}" ]
        return
    fi
    ROOT_SRC_TRIED=1
    local want=""
    [ -d "${PANEL_DIR}/.git" ] \
        && want="$(_gitc rev-parse --verify --quiet 'HEAD^{commit}' 2>/dev/null || true)"
    # The panel's git produced this, so it is a request, not a fact: a commit id, or nothing.
    #
    # The warnings below say only that root will not stage FROM this checkout. Which file that
    # leaves unrefreshed is each caller's to say — this answer is cached and shared, and the first
    # caller to ask is not always install_root_tools (a fresh install once asked it for recover.sh
    # alone, seconds after the helper had been placed, and was told the helper was not refreshed).
    case "${want}" in
        ""|*[!0-9a-f]*)
            warn "This checkout has no commit root can verify, so root stages nothing from it."
            return 1 ;;
    esac
    if ! ${H_SUDO:-} test -d "${ROOT_GIT}"; then
        _rootgit init --quiet --bare >/dev/null 2>&1 || {
            warn "Could not create root's copy of the repository at ${ROOT_GIT}."
            return 1; }
    fi
    # Into ONE fixed ref, whatever the branch. A ref named after the branch was never pruned, so
    # once the panel had tracked `fix` and then switched to `fix/x` (or the reverse), git refused
    # to create the new ref beside the old one and every later run warned "Could not fetch" and
    # left the helper stale. The ref only has to hold the tip this run compares against.
    if ! _rootgit fetch --quiet --no-tags "${REPO_URL}" \
            "+refs/heads/${DEFAULT_BRANCH}:refs/root-src/tip" >/dev/null 2>&1; then
        warn "Could not fetch ${REPO_URL} (${DEFAULT_BRANCH}) into root's own copy, so root stages"
        warn "nothing from this checkout. The panel still works; re-run to retry."
        return 1
    fi
    if ! _rootgit merge-base --is-ancestor "${want}" refs/root-src/tip >/dev/null 2>&1; then
        warn "This checkout is at ${want}, which is not on ${REPO_URL}'s ${DEFAULT_BRANCH}."
        warn "Root stages nothing from it."
        return 1
    fi
    ROOT_SRC_COMMIT="${want}"
}

# Answer root_source_commit in THIS shell, before any `x="$(stage_root_source …)"`. Those run in a
# subshell, so an answer found there is lost when it exits (the fetch would repeat for every file),
# and its warnings would land in the captured path instead of on the screen. Always returns 0: the
# staging calls that follow each report their own failure.
_prepare_root_source() {
    if [ "$(id -u)" -eq 0 ] && ! _checkout_is_roots && ! _operator_src >/dev/null; then
        root_source_commit || true
    fi
    return 0
}

stage_root_source() {
    local rel="$1" out="${HELPER_DIR}/.stage-$2" osrc="" from=""
    ${H_SUDO} rm -f "${out}" 2>/dev/null || true
    if [ "$(id -u)" -eq 0 ] && ! _checkout_is_roots && osrc="$(_operator_src)" \
       && from="$(_operator_file "${osrc}" "${rel}")"; then
        # Root, installing from the operator's own tree: the working tree fetch_code just copied
        # in, read at the path the reach test walked.
        cp -- "${from}" "${out}" 2>/dev/null || { rm -f "${out}" 2>/dev/null; return 1; }
    elif [ "$(id -u)" -eq 0 ] && ! _checkout_is_roots; then
        # Root, and the panel user owns some of the checkout: its tree, its .git, or both.
        root_source_commit >&2 || { ${H_SUDO} rm -f "${out}" 2>/dev/null; return 1; }
        _rootgit cat-file blob "${ROOT_SRC_COMMIT}:${rel}" 2>/dev/null \
            | ${H_SUDO} tee "${out}" >/dev/null 2>&1 || { ${H_SUDO} rm -f "${out}" 2>/dev/null; return 1; }
    elif [ -d "${PANEL_DIR}/.git" ]; then
        # A checkout the running account owns outright: root's before the chown, or the invoking
        # user's own on a per-user install.
        _gitc cat-file blob "HEAD:${rel}" 2>/dev/null \
            | ${H_SUDO} tee "${out}" >/dev/null 2>&1 || { ${H_SUDO} rm -f "${out}" 2>/dev/null; return 1; }
    else
        # No git: a tarball / --src install, in a tree the running account owns.
        ${H_SUDO} cp -- "${PANEL_DIR}/${rel}" "${out}" 2>/dev/null \
            || { ${H_SUDO} rm -f "${out}" 2>/dev/null; return 1; }
    fi
    [ -s "${out}" ] || { ${H_SUDO} rm -f "${out}" 2>/dev/null; return 1; }
    ${H_SUDO} chown root:root "${out}" 2>/dev/null || true
    printf '%s\n' "${out}"
}

# ── The recovery command ───────────────────────────────────────────────────────────────────────
# `sudo linuxgsm-panel-recover` is what this installer prints as the lockout remedy and what
# README documents, so it runs as ROOT. It used to be a symlink to ${PANEL_DIR}/recover.sh — a
# file inside the checkout, which this script chowns to the panel user. A compromised panel
# rewrote it and waited for the operator to reach for the documented recovery command. recover.sh
# is careful to drop to the service user before it touches the database, but that is line 112:
# everything above it is root, and an attacker replaces the whole file anyway.
#
# So install a root-owned copy beside the helper, taken from the COMMIT rather than the working
# tree (stage_root_source explains why that distinction matters), and point the symlink at that.
#
# When no fresh copy can be staged, what happens depends on who is running this:
#   * ROOT never points the link into ${PANEL_DIR}. A root run always hands that directory to the
#     service user (the fresh path chowns it straight after), so a link there is the hole above.
#     It keeps a root-owned copy already in place, stale but safe, or else links nothing — and
#     unlinks one an older installer aimed at the checkout. root_source_commit refuses more than
#     the old copy-the-tree path did (no .git, a commit not on upstream's branch, no network), so
#     this is a branch real root installs reach, not a corner.
#   * the ACCOUNT THAT OWNS THE CHECKOUT (a per-user install, run as that user) falls back to
#     ${PANEL_DIR}/recover.sh. That account can already rewrite anything it would run, so the
#     boundary is not what it loses, and a working recovery command is worth more there.
install_recovery_command() {
    local link="/usr/local/bin/linuxgsm-panel-recover" stage="" target=""
    # The origin gate belongs HERE, not at the call sites, because this is the one root-owned file
    # an untrusted origin could still place. On the update path fetch_code has already done
    # `git reset --hard origin/<branch>`, so HEAD — which stage_root_source reads from — is the
    # untrusted commit by the time check_origin_trusted runs. install_root_tools self-gates and
    # write_sudoers_grant is gated at both its call sites, so the helper, db_maintenance, the
    # installer and the grant were all correctly withheld; this was not, and it installs root:root
    # 0755 and points `sudo linuxgsm-panel-recover` at the result. That is precisely the attack the
    # comment above describes, with the added sting that the operator has just been TOLD
    # "Root-owned components … will NOT be refreshed from it".
    #
    # Leaving the existing command untouched is the deliberate trade, the same one
    # install_root_tools makes: a host keeps whatever recovery command it already had rather than
    # being handed one from a source this installer does not trust. Returning before the fallback
    # matters too — that branch points the symlink into ${PANEL_DIR}, which is panel-writable.
    if [ "${ORIGIN_TRUSTED:-1}" -ne 1 ]; then
        warn "Leaving \`linuxgsm-panel-recover\` as it is — it would have come from an untrusted origin."
        return 0
    fi
    H_SUDO=""; [ "$(id -u)" -ne 0 ] && H_SUDO="sudo"
    if ${H_SUDO} install -d -o root -g root -m 0755 "${HELPER_DIR}" 2>/dev/null \
       && _prepare_root_source \
       && stage="$(stage_root_source recover.sh recover.sh)" \
       && ${H_SUDO} install -o root -g root -m 0755 "${stage}" "${HELPER_DIR}/recover.sh" 2>/dev/null; then
        target="${HELPER_DIR}/recover.sh"
        ${H_SUDO} rm -f "${stage}" 2>/dev/null || true
    elif [ "$(id -u)" -eq 0 ]; then
        if [ -f "${HELPER_DIR}/recover.sh" ] && [ ! -L "${HELPER_DIR}/recover.sh" ] \
           && [ "$(stat -c '%U' "${HELPER_DIR}/recover.sh" 2>/dev/null)" = "root" ]; then
            target="${HELPER_DIR}/recover.sh"
            warn "The recovery command was not refreshed; \`linuxgsm-panel-recover\` keeps the"
            warn "root-owned copy already in ${HELPER_DIR}."
        else
            warn "No root-owned recovery command could be placed, so \`linuxgsm-panel-recover\` is not"
            warn "linked: root must not run a file from the panel's checkout. Re-run this installer"
            warn "once it can stage one (a clone of ${REPO_URL:-the repository}'s ${DEFAULT_BRANCH:-main}, or with network access)."
            if [ "$(readlink "${link}" 2>/dev/null)" = "${PANEL_DIR}/recover.sh" ]; then
                rm -f "${link}" 2>/dev/null || true
                warn "Removed the old link that pointed it at ${PANEL_DIR}/recover.sh."
            fi
        fi
    elif [ -f "${PANEL_DIR}/recover.sh" ]; then
        target="${PANEL_DIR}/recover.sh"
        warn "Recovery command points into the checkout — no root-owned copy could be placed."
        warn "Re-run this installer as root so \`sudo linuxgsm-panel-recover\` is not panel-writable."
    fi
    [ -n "${target}" ] || return 0
    ${H_SUDO} ln -sf "${target}" "${link}" 2>/dev/null || true
}

# Sets HELPER_OK / ROOT_TOOLS_OK, which write_sudoers_grant reads.
install_root_tools() {
    if [ "${ORIGIN_TRUSTED:-1}" -ne 1 ]; then
        # Leave HELPER_OK / ROOT_TOOLS_OK as they are: write_sudoers_grant is skipped alongside
        # this, so the host keeps whatever grant it already had rather than being widened.
        return 0
    fi
    HELPER_OK=0
    ROOT_TOOLS_OK=0
    HELPER_DST="${HELPER_DIR}/panel-helper"
    INSTALLER_DST="${HELPER_DIR}/install.sh"
    DBM_DST="${HELPER_DIR}/db_maintenance.py"
    PANEL_CONF="${HELPER_DIR}/panel.conf"
    H_SUDO=""; [ "$(id -u)" -ne 0 ] && H_SUDO="sudo"

    local _stage="" _istage=""

    # Root-owned and 0755 BEFORE anything is staged into it: stage_root_source depends on the panel
    # user being unable to write here.
    if ! ${H_SUDO} install -d -o root -g root -m 0755 "${HELPER_DIR}" 2>/dev/null; then
        warn "Could not create ${HELPER_DIR} (needs root). The panel still works; re-run this"
        warn "installer as root to place the root-owned components."
        return 0
    fi
    _prepare_root_source

    if _stage="$(stage_root_source tools/panel-helper panel-helper)"; then
        if ${H_SUDO} install -o root -g root -m 0755 "${_stage}" "${HELPER_DST}" 2>/dev/null; then
            HELPER_OK=1
            ok "Privileged helper installed at ${HELPER_DST}"
        else
            # Not fatal. ssh_manager.run_privileged falls back to the pre-helper path when the
            # helper is absent, so the panel keeps working — it just does not get the narrower
            # call path yet.
            warn "Could not install/refresh the privileged helper (needs root). The panel still"
            warn "works; re-run this installer as root to place the current one."
        fi
        ${H_SUDO} rm -f "${_stage}" 2>/dev/null || true
    else
        warn "Could not read tools/panel-helper from the repository — the helper was NOT refreshed."
    fi

    # db_maintenance.py is installed ROOT-OWNED beside the helper, and panel.conf records the one
    # path it needs. Both are placed HERE and nowhere else — there is deliberately no verb that
    # copies them, because "install this file from the panel's directory and run it as root later"
    # is the same hole the helper exists to close.
    #
    # Why a second copy at all: the offline database repair runs as root, and the version in the
    # checkout is owned by the panel user and rewritten by `git pull` on every self-update. Root
    # executing it — or the checkout's venv interpreter — would make the boundary decorative. The
    # helper runs THIS copy with the SYSTEM python instead.
    # panel.conf is written HERE, not inside the db_maintenance branch below, because it is the
    # only record of WHERE this install lives and three separate things read it: the helper, the
    # uninstaller's shared-ownership check, and recover.sh. It used to be written only when
    # db_maintenance.py had been staged AND installed — but install_recovery_command is
    # independent of both, so a host where that staging failed got the root-owned recovery tool
    # and the documented `linuxgsm-panel-recover` symlink with NOTHING recording the directory
    # they are meant to operate on. The lockout remedy then answered "Couldn't find a LinuxGSM
    # Panel install on this host". Recording the path costs nothing and does not depend on any
    # file having been copied.
    CONF_OK=0
    printf 'db_path=%s\ndata_dir=%s\npanel_dir=%s\n' \
        "${PANEL_DIR}/data/panel.db" "${PANEL_DIR}/data" "${PANEL_DIR}" \
        | ${H_SUDO} tee "${PANEL_CONF}" >/dev/null 2>&1 \
        && ${H_SUDO} chmod 0644 "${PANEL_CONF}" 2>/dev/null \
        && ${H_SUDO} chown root:root "${PANEL_CONF}" 2>/dev/null && CONF_OK=1

    if _stage="$(stage_root_source db_maintenance.py db_maintenance.py)"; then
        if ${H_SUDO} install -o root -g root -m 0755 "${_stage}" "${DBM_DST}" 2>/dev/null; then
            ${H_SUDO} rm -f "${_stage}" 2>/dev/null || true
            INST_OK=0
            # The installer itself, root-owned, for the same reason: the self-update runs it as
            # root, and the copy in the checkout is panel-writable.
            if ! _istage="$(stage_root_source install.sh install.sh)"; then
                # The documented quick install is `curl -fsSL … | bash`, where there may be no
                # install.sh in the checkout yet. Fall back to the script actually running — the
                # shebang test below is what stops that being /usr/bin/bash.
                _istage=""
                if [ -f "${SCRIPT_PATH}" ]; then
                    _istage="${HELPER_DIR}/.stage-install.sh"
                    ${H_SUDO} cp -- "${SCRIPT_PATH}" "${_istage}" 2>/dev/null || _istage=""
                fi
            fi
            if [ -n "${_istage}" ] && head -n1 "${_istage}" | grep -q '^#!.*sh'; then
                ${H_SUDO} install -o root -g root -m 0755 "${_istage}" "${INSTALLER_DST}" 2>/dev/null && INST_OK=1
            else
                warn "Could not find this installer to copy root-owned — skipping."
            fi
            [ -n "${_istage}" ] && ${H_SUDO} rm -f "${_istage}" 2>/dev/null || true
            # ALL THREE, not just db_maintenance. The grant below is documented as meaning "every
            # root-owned piece is in place … the helper, db_maintenance, and the root-owned
            # installer", and this flag is what it reads.
            if [ "${CONF_OK}" -eq 1 ] && [ "${INST_OK}" -eq 1 ]; then
                ROOT_TOOLS_OK=1
                ok "Offline DB repair installed root-owned at ${DBM_DST}"
            else
                warn "db_maintenance is in place but panel.conf or the root-owned installer is not."
                warn "Keeping the existing sudoers grant until a re-run as root places all three."
            fi
        else
            ${H_SUDO} rm -f "${_stage}" 2>/dev/null || true
            warn "Could not install the root-owned db_maintenance copy (needs root)."
            warn "The panel falls back to the pre-helper repair path until you re-run this as root."
        fi
    else
        warn "Could not read db_maintenance.py from the repository — it was NOT refreshed."
    fi
}

# ── The sudoers grant ──────────────────────────────────────────────────────────────────────
# NARROW when every root-owned piece is in place, because only then does the panel have a way to
# do its privileged work without a general shell: the helper for the verb table, the root-owned
# db_maintenance for the offline repair, and the root-owned installer for self-update. All three
# are placed by install_root_tools, as root — never by the panel.
#
# WIDE otherwise. A host that has the new code but could not place those still falls back to
# `sudo bash -c '<verb rendered as text>'`, and narrowing under it would break every privileged
# action rather than secure anything.
#
# Note what is NOT permitted even in the narrow form: no systemd-run, no bash, no tailscale, no
# sudo -u. Each of those was a call site once, and each is a verb now — a sudoers rule for any of
# them would be equivalent to NOPASSWD:ALL, because they all run whatever you hand them.
#
# Called from the update path as well as the fresh one, so a host that has now received the
# root-owned pieces actually gets its grant narrowed instead of keeping the wide one forever.
# Is every root-owned piece actually in place, root-owned, RIGHT NOW? This asks about the
# INSTALLED state, not about whether this run managed to refresh it — two different questions, and
# only the second one is answerable by the panel user.
#
# install_root_tools used to set HELPER_OK from `[ -f "${PANEL_DIR}/tools/panel-helper" ]`, a path
# the panel user owns. Deleting that file — and making the deletion survive `git reset --hard` with
# `git update-index --skip-worktree` — zeroed the flag, and write_sudoers_grant then replaced the
# narrow rule with NOPASSWD:ALL. The untrusted side could widen its own sudo grant by removing a
# file it owned. What the grant actually depends on is whether the helper root will execute EXISTS,
# so read that instead, and never widen while it does.
root_tools_present() {
    local f
    for f in "${HELPER_DST:-}" "${DBM_DST:-}" "${INSTALLER_DST:-}" "${PANEL_CONF:-}"; do
        [ -n "${f}" ] && [ -f "${f}" ] || return 1
        [ "$(stat -c '%U' "${f}" 2>/dev/null)" = "root" ] || return 1
    done
    return 0
}

# Can this account already reach root by itself? Echoes yes / no / unknown.
#
# Its own function so it can be driven by a test: it is a security decision inside a loop over
# /home, and a check that can only run against the real /home on a real host is a check nothing
# exercises. tests/unit/part06.py lifts it out of this file and runs it with a shimmed `sudo`.
#
# UNKNOWN is a third answer on purpose, and the caller treats it as "do not enrol". Every ambiguous
# reply used to mean "no sudo rights, safe to enrol": `sudo -l -U <unknown account>` prints
# "sudo: unknown user ..." and exits 0, sudo missing or erroring prints nothing, and the phrase
# being matched is NLS-translated so a non-English host answers in its own language. The group is a
# GRANT — the panel's sudoers line says it may BECOME any member — so enrolling an account that can
# already run sudo turns that narrow grant into NOPASSWD:ALL with one extra hop.
#
# LC_ALL=C so the two phrases are the English ones sudo compiles in.
#
# The GROUP test is not only about sudo. docker, lxd, incus-admin and libvirt reach root through
# their daemon (`docker run -v /:/host`), disk through the raw block device, staff through
# /usr/local, which root runs from. adm and shadow read logs and password hashes. None of these
# needs a sudoers entry, so `sudo -l -U` reports the account as "not allowed" and it was enrolled:
# the one-hop NOPASSWD:ALL this function exists to prevent. The first ten are the set
# panel/security/privileged.py already refuses as _NEVER_A_CONTENT_GROUP.
can_already_sudo() {
    _cas_user="$1"
    _cas_groups="sudo|admin|wheel|root|adm|shadow|docker|lxd|disk|staff|incus-admin|libvirt"
    if id -nG "${_cas_user}" 2>/dev/null | tr " " "\n" | grep -qxE "${_cas_groups}"; then
        echo yes; return 0
    fi
    _cas_out="$(LC_ALL=C sudo -l -U "${_cas_user}" 2>&1)" || true
    case "${_cas_out}" in
        *"may run the following"*)    echo yes ;;
        *"not allowed to run sudo"*)  echo no ;;
        *)                            echo unknown ;;
    esac
}

# Every account the panel DRIVES — a game instance's user, the shared GMod content user — joins
# GAME_GROUP, which the narrow grant's second line names. Idempotent, and run on updates too, so an
# existing host picks up its accounts the first time it takes this version.
#
# The rule for "is this a game account" is deliberately a property of the HOME DIRECTORY, not a uid
# range: a LinuxGSM instance (lgsm/config-lgsm) or a Steam content tree (serverfiles). A human's
# account has neither, and must not end up here — the group is a grant, and adding a person to it
# would let the panel become them.
sync_game_user_group() {
    [ "${RUN_AS_ROOT}" -eq 1 ] || return 0
    groupadd -f "${GAME_GROUP}" >/dev/null 2>&1 || {
        warn "Could not create group '${GAME_GROUP}'; game accounts stay outside the grant."
        return 0
    }
    _joined=0
    for _gh in /home/*; do
        [ -d "${_gh}" ] || continue
        _gu="$(basename "${_gh}")"
        [ "${_gu}" = "${PANEL_USER}" ] && continue
        { [ -d "${_gh}/lgsm/config-lgsm" ] || [ -d "${_gh}/serverfiles" ]; } || continue
        id "${_gu}" >/dev/null 2>&1 || continue
        # NEVER enrol an account that can already escalate. The grant says the panel may BECOME a
        # member, so a member who can run sudo makes it NOPASSWD:ALL with one extra hop. Running
        # LinuxGSM under your own sudo-capable account is an ordinary setup — it is what LinuxGSM's
        # own docs show, and the panel's discovery imports exactly those — so this is a likely
        # account to meet here, not an unlikely one.
        case "$(can_already_sudo "${_gu}")" in
            yes)
                # "Already has sudo" and "is already enrolled" are two different accounts, and this
                # branch used to tell both of them the same thing. It runs BEFORE the membership
                # test below, and only ever `continue`d — so an account enrolled while it had no
                # sudo and since given some (`usermod -aG sudo steam` for an afternoon's
                # maintenance, left in place) kept its GAME_GROUP membership on every later run
                # while being told "Not enrolling" and "The panel will not be able to manage that
                # account's servers". Both sentences were false for it: it WAS enrolled, the panel
                # could still become it, and from there `sudo -i` reaches root — the exact
                # escalation the note above names. The one line that should have made the operator
                # act read as reassurance instead. So ask the membership question here, and take
                # the grant back rather than describing a state that is not this host's.
                if id -nG "${_gu}" 2>/dev/null | tr ' ' '\n' | grep -qx "${GAME_GROUP}"; then
                    if gpasswd -d "${_gu}" "${GAME_GROUP}" >/dev/null 2>&1; then
                        warn "Removed '${_gu}' from ${GAME_GROUP}: it can now reach root (sudo, or a"
                        warn "  group such as docker), which would make the panel's grant a path to"
                        warn "  root. The panel can no longer manage that account's servers on this host."
                    else
                        warn "'${_gu}' is in ${GAME_GROUP} AND can reach root (sudo, or a group such as"
                        warn "  docker), so the panel's grant is a path to root, and the membership could"
                        warn "  not be removed. Run:"
                        warn "    gpasswd -d ${_gu} ${GAME_GROUP}"
                    fi
                else
                    warn "Not enrolling '${_gu}' in ${GAME_GROUP}: it can already reach root (sudo,"
                    warn "  or a group such as docker)."
                    warn "  The panel will not be able to manage that account's servers on this host."
                fi
                continue ;;
            no)
                : ;;   # a definite no — safe to enrol
            *)
                warn "Not enrolling '${_gu}' in ${GAME_GROUP}: could not determine whether it can"
                warn "  already use sudo, and this check has to fail closed."
                continue ;;
        esac
        if id -nG "${_gu}" 2>/dev/null | tr ' ' '\n' | grep -qx "${GAME_GROUP}"; then
            continue
        fi
        if usermod -aG "${GAME_GROUP}" "${_gu}" >/dev/null 2>&1; then
            _joined=$((_joined + 1))
        fi
    done
    if [ "${_joined}" -gt 0 ]; then
        ok "Added ${_joined} game account(s) to '${GAME_GROUP}'"
    fi
    return 0
}

# ── Optional: sudo in the host terminal, with a password ───────────────────────────────────────
# Off by default. `PANEL_TERMINAL_SUDO=1 ./install.sh` turns it on, `=0` turns it off, and leaving
# it UNSET changes nothing — so an update neither grants this behind the operator's back nor takes
# away a grant they asked for.
#
# Its own file, never /etc/sudoers.d/linuxgsm-panel: the main grant is rewritten from scratch on
# every install and self-update, and the gates on that narrow rule are worth keeping exactly as
# strict as they are.
#
# The `00-` prefix is load-bearing, not decoration. sudo reads /etc/sudoers.d in LEXICAL order and
# the LAST matching rule wins, so a general `ALL=(ALL) ALL` in a file sorting after
# `linuxgsm-panel` overrides the narrow grant's NOPASSWD line for the helper — and then every
# privileged action the panel takes sits waiting for a password that nothing can type. Measured on
# a real host: `sudo -n <helper>` went from succeeding to "a password is required" purely from the
# filename. Sorting first leaves the narrow NOPASSWD rules as the last match for the helper, while
# everything else still prompts.
#
# NOT NOPASSWD, and that is the entire difference. The note at the top of this file argues that a
# sudoers rule permitting a shell is equivalent to NOPASSWD:ALL — true of a passwordless rule, and
# not true of this one: a compromised panel holds no secret that this line turns into root.
#
# What it DOES weaken is worth saying plainly, because it is not obvious: the operator types that
# password into a terminal the panel is rendering. A panel that is already compromised can read it
# as it is typed. This is strictly weaker than the same sudo over real SSH, and it is the reason
# this is opt-in rather than the default.
write_terminal_sudo_grant() {
    [ "${RUN_AS_ROOT}" -eq 1 ] || return 0
    _tsudo_f=/etc/sudoers.d/00-linuxgsm-panel-terminal
    case "${PANEL_TERMINAL_SUDO:-}" in
        1|yes|true)
            ;;
        0|no|false)
            if [ -f "${_tsudo_f}" ]; then
                rm -f "${_tsudo_f}"
                ok "Host-terminal sudo disabled (removed ${_tsudo_f})"
            fi
            return 0
            ;;
        *)
            # Unset: leave the host exactly as it is, and say which way that is.
            [ -f "${_tsudo_f}" ] && info "Host-terminal sudo is enabled (${_tsudo_f})"
            return 0
            ;;
    esac
    echo "${PANEL_USER} ALL=(ALL) ALL" > "${_tsudo_f}"
    chmod 440 "${_tsudo_f}"
    visudo -cf "${_tsudo_f}" >/dev/null \
        || { rm -f "${_tsudo_f}"; die "terminal sudoers entry invalid"; }
    ok "Host-terminal sudo enabled: ${PANEL_USER} may run any command, after entering a password"
    # A --system account has no password at all, so sudo would prompt for one that can never be
    # given and the feature would look broken rather than absent. Check, and say what to run.
    case "$(passwd -S "${PANEL_USER}" 2>/dev/null | awk '{print $2}')" in
        P)  ;;
        *)  warn "  '${PANEL_USER}' has no password set, so that sudo can never succeed."
            warn "  Set one with:  passwd ${PANEL_USER}"
            ;;
    esac
}

write_sudoers_grant() {
    [ "${RUN_AS_ROOT}" -eq 1 ] || return 0
    if { [ "${HELPER_OK}" -eq 1 ] && [ "${ROOT_TOOLS_OK}" -eq 1 ]; } || root_tools_present; then
        sync_game_user_group
        # TWO lines, and the split is the whole point. Root is reachable only by running the
        # root-owned helper, which validates every argument against its own table. Becoming a GAME
        # account needs no helper — the panel does it for the file browser, the GMod content
        # mounts, the cron writers and the install flows, about 45 call sites — so it is granted
        # directly, but only for accounts in GAME_GROUP. `sudo -u root` stays refused.
        {
            echo "${PANEL_USER} ALL=(root) NOPASSWD: ${HELPER_DST}"
            echo "${PANEL_USER} ALL=(%${GAME_GROUP}) NOPASSWD: ALL"
        } > /etc/sudoers.d/linuxgsm-panel
        SUDO_SCOPE="narrow (panel-helper for root; game accounts in ${GAME_GROUP})"
    else
        echo "${PANEL_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/linuxgsm-panel
        SUDO_SCOPE="WIDE (NOPASSWD:ALL) — the root-owned helper pieces are not all installed"
        warn "  (Reached only when the root-owned pieces are genuinely absent from ${HELPER_DIR:-/usr/local/lib/linuxgsm-panel};"
        warn "   a failure to REFRESH them no longer widens a grant that is already narrow.)"
    fi
    chmod 440 /etc/sudoers.d/linuxgsm-panel
    visudo -cf /etc/sudoers.d/linuxgsm-panel >/dev/null \
        || { rm -f /etc/sudoers.d/linuxgsm-panel
             # Name the damage. This `rm` has just taken the panel's sudo grant away, and the
             # window handler that now catches this die goes on to restore the code and report
             # "the panel has been restarted on <version>" — true, and reassuring, and silent
             # about the one thing that changed for the worse. A panel running without its grant
             # fails every privileged action with no clue why.
             die "sudoers entry invalid — the grant at /etc/sudoers.d/linuxgsm-panel has been REMOVED,
     so the panel's privileged actions (firewall, service control, game accounts) will fail until it
     is rewritten. Re-run this installer once the cause is fixed."; }
    # Say which one loudly when it is the wide one. This runs on updates now, so a host that was
    # narrow and could not place the helper this time gets its grant widened again — a real
    # security downgrade, and it should not slide past in a wall of green ticks.
    case "${SUDO_SCOPE}" in narrow*) _narrow=1 ;; *) _narrow=0 ;; esac
    if [ "${_narrow}" -eq 1 ]; then
        ok "sudo grant: ${SUDO_SCOPE}"
    else
        warn "sudo grant: ${SUDO_SCOPE}"
        warn "  The panel falls back to the pre-helper path, which needs the wide grant to work."
        warn "  Re-run this installer as root once the helper can be placed to narrow it again."
    fi
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

    # Ensure Node LTS + gamedig on the host regardless of whether there's an update to apply, so a
    # plain `install.sh` run also fixes a missing/old install (idempotent + best-effort).
    ensure_gamedig
    ensure_fail2ban   # backfill fail2ban on existing installs so the panel-login jail can come up

    # Decide whether there's anything to do BEFORE snapshotting or touching the service — a
    # no-op update shouldn't burn a snapshot (disk + gzip CPU) or blink the panel. This only
    # fetches; the working tree stays untouched until fetch_code below.
    CURRENT_SHA=""; TARGET_REF=""; TARGET_SHA=""
    if ! resolve_update_target; then
        die "Couldn't reach the update source (offline, or a private repo without credentials).
     Nothing was changed."
    fi
    if [ -n "${CURRENT_SHA}" ] && [ "${CURRENT_SHA}" = "${TARGET_SHA}" ]; then
        # Nothing to FETCH is not nothing to DO. The root-owned pieces and the sudoers grant live
        # outside the checkout, so they can be stale or missing while the code is perfectly current
        # — and this branch used to `exit 0` before reaching either of them.
        #
        # That made the remedy this script prints ("re-run this installer as root once the helper
        # can be placed to narrow it again") a no-op on any host whose code was already up to date,
        # which is most of them by the time an operator gets round to it. It also stranded every
        # host that took new code by another route — the panel's own self-update, or a plain
        # `git pull` — with an old helper and an old grant: new verbs answered "unknown verb", and
        # the grant naming the game-user group was never written, so the panel could not manage a
        # single server while reporting itself up to date.
        #
        # All three are idempotent and cheap: the helper is re-staged (see stage_root_source for
        # where root takes it from — as root, never the panel-owned checkout itself), the grant
        # is rewritten and re-validated with visudo, and the group sync is `groupadd -f` plus an
        # append-only `usermod -aG`. So do them, then report.
        check_origin_trusted
        install_root_tools
        [ "${ORIGIN_TRUSTED}" -eq 1 ] && write_sudoers_grant
        write_terminal_sudo_grant
        # And the recovery command, which was the one root-owned piece this branch backfilled
        # everything EXCEPT. /usr/local/bin/linuxgsm-panel-recover lives outside the checkout and
        # has exactly the staleness this branch exists for — an install that took new code by
        # another route, or from a version that predates install_recovery_command, has current code
        # and no recovery command. It is also what this installer prints as THE lockout remedy
        # ("Forgot the admin password? … sudo linuxgsm-panel-recover"), so the operator who re-runs
        # the installer to repair a lockout was the one person guaranteed to reach this branch —
        # and got "Already up to date", exit 0, and `command not found` on the very next line they
        # were told to type. It self-gates on ORIGIN_TRUSTED, which check_origin_trusted set above.
        install_recovery_command
        ok "Already up to date (version ${FROM_VER}) — no snapshot taken, panel left running."
        exit 0
    fi

    BACKUP_ROOT="${PANEL_DIR}/data/.backups"
    STAMP="$(date +%Y%m%d-%H%M%S)"
    BACKUP="${BACKUP_ROOT}/${STAMP}"
    info "[1/6] Snapshotting current version + database → ${BACKUP}"
    mkdir -p "${BACKUP}"
    # Compressor: pigz (parallel gzip) when present — ~3.5x faster than gzip on a multi-core box for
    # the same size — else gzip -1 (fastest single-core). The level barely matters here: the payload
    # is mostly already-compressed data (git packs + screenshots), so we pick speed. pigz/gzip both
    # emit a standard .tgz, so rollback (tar -xzf) reads old + new snapshots.
    if command -v pigz >/dev/null 2>&1; then SNAP_GZ="pigz -6"; else SNAP_GZ="gzip -1"; fi
    # Snapshot the code (minus venv/data) so we can restore the exact prior version…
    # --ignore-failed-read: a file the snapshot can't read (e.g. a root-owned Tailscale cert KEY that
    # landed in the panel dir at mode 600) must NEVER abort the whole update — plain tar would exit 2
    # here and `set -o pipefail` would kill the update. `|| true` also absorbs a compressor hiccup;
    # then we VERIFY the archive is non-empty, so a GENUINE failure (disk full, etc.) still aborts
    # cleanly with a clear message instead of a cryptic exit code.
    tar -C "${PANEL_DIR}" --ignore-failed-read --exclude=./venv --exclude=./data -cf - . 2>/dev/null | ${SNAP_GZ} > "${BACKUP}/code.tgz" || true
    # `-s` only asks whether it is non-empty, and the failure this check names by name — the disk
    # filling mid-write — produces a TRUNCATED archive, which is non-empty. It passed, and the
    # rollback below then wiped PANEL_DIR and fed the truncated stream to tar. `tar -tz` reads the
    # whole thing: it fails on a broken gzip stream and on a truncated member, which is the actual
    # question ("can this be unpacked again?").
    #
    # "Can it be unpacked" is still not "is anything IN it", and both matter when this archive is
    # the only surviving copy: the rollback wipes data/ before unpacking it. `printf '' | gzip -1`
    # is a 20-byte file, so `-s` is true, and GNU tar reads it happily and lists zero members, so
    # `-tz` is true as well — an empty snapshot would print "Snapshot saved" and restore nothing.
    # So COUNT the members. `wc -l` and not `head -1`, which would SIGPIPE tar and (under
    # pipefail, set at the top of this file) read as a broken archive; and the count comes from
    # the same pipeline whose status still has to be 0, because a TRUNCATED archive lists the
    # members it got to before tar failed. One line on purpose: tests/unit/part06.py extracts this
    # function by line and executes it, rather than reimplementing what it hopes it says.
    snapshot_ok() { local _n; [ -s "$1" ] && _n="$(tar -tzf "$1" 2>/dev/null | wc -l)" && [ "${_n}" -gt 0 ]; }
    snapshot_ok "${BACKUP}/code.tgz" || die "Couldn't snapshot the current version (the backup is empty or unreadable) —
     update ABORTED, the panel is unchanged. Check free disk space with 'df -h' and try again."
    # …and the whole data dir (DB + encryption keys + config), since the app runs a
    # startup migration that mutates the DB — we restore this verbatim on rollback.
    #
    # STOP THE PANEL FIRST. This tar used to run against a LIVE database, ten lines before the
    # service was stopped for [2/6]. panel.db is in WAL mode with ~10 daemon threads committing
    # into it continuously, so tar was reading panel.db, panel.db-wal and panel.db-shm as three
    # separate, non-atomic reads while a writer was mid-commit — the archive can hold a main image
    # that does not match its WAL, which SQLite reports on restore as "database disk image is
    # malformed". tar says "file changed as we read it" and exits 1 when that happens, and
    # `2>/dev/null … || true` threw away both the message and the status; snapshot_ok only asks
    # whether the archive UNPACKS, which cannot see an inconsistent database inside it. So the
    # script printed "Snapshot saved" over a torn copy — and this is the ONLY copy of the database
    # on the rollback path, which wipes data/ before unpacking it. Quiescing first costs the
    # seconds the tar takes, and [2/6] below needs the service down anyway.
    svc stop linuxgsm-panel.service || true

    # ── The panel is DOWN from here until [5/6] starts it again ──────────────────────────────
    # Everything in that window can fail — the snapshot, the database maintenance, the fetch, pip
    # — and every one of those failures used to fall straight off the end of the script under
    # `set -e`: service stopped, no rollback, no message. The rollback block at the bottom is
    # reachable only from a FAILED HEALTH CHECK, so it never ran for any of them, and the operator
    # (or the in-panel self-update, which only watches the log) got `=== installer exit 1 ===` and
    # a dead panel with no web UI left to read it from — flatly contradicting the promise at the
    # top of this file that "a broken release can't leave you with a dead panel".
    #
    # This trap owns the window instead. It restores the CODE only when fetch_code has actually
    # replaced the working tree; it deliberately does NOT restore data.tgz, because the new
    # version never started inside this window, so the live database is still the pre-update one
    # and unpacking over it would only risk losing it. Then it starts the service and says what
    # failed and where the snapshot is. It fires for a `die` too — a deliberate exit still leaves
    # the panel stopped, and the recovery is the same — but a die has already explained itself, so
    # the handler drops its own generic sentence and adds only the one thing the die cannot know:
    # that the panel is back up (see die() at the top of this file).
    _CODE_FETCHED=0
    _ABORT_SIG=""
    _update_window_abort() {
        local _rc=$?
        trap - ERR EXIT HUP INT TERM
        # What to call the reason. `$?` is 0 when bash runs an EXIT trap because the script was
        # KILLED, so "(exit 0)" was a false statement in the one message the operator gets: name
        # the signal when there was one, and say nothing at all when there is neither.
        local _why=""
        if [ -n "${_ABORT_SIG}" ]; then
            _why=" (killed by ${_ABORT_SIG})"
        elif [ "${_rc}" -ne 0 ]; then
            _why=" (exit ${_rc})"
        fi
        # A `die` has already printed an accurate, specific message (see die() at the top), so the
        # generic sentence is skipped — but only that sentence. The RECOVERY below runs for a die
        # exactly as it does for an unexplained abort, because the panel is stopped either way.
        [ "${_DIE_SAID:-0}" -eq 1 ] || warn "The update aborted unexpectedly${_why} with the panel stopped."
        if [ "${_CODE_FETCHED}" -eq 1 ] && [ -f "${BACKUP}/code.tgz" ]; then
            warn "Putting ${FROM_VER} back from the snapshot…"
            find "${PANEL_DIR}" -mindepth 1 -maxdepth 1 \
                ! -name data ! -name venv -exec rm -rf {} + 2>/dev/null || true
            tar -C "${PANEL_DIR}" -xzf "${BACKUP}/code.tgz" 2>/dev/null || true
            install_deps || true
        fi
        [ "${RUN_AS_ROOT}" -eq 1 ] && chown -R "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}" 2>/dev/null || true
        svc daemon-reload || true
        svc start linuxgsm-panel.service || true
        if [ "${_DIE_SAID:-0}" -eq 1 ]; then
            # The what and the why are already on screen; add only what the die could not know —
            # that the recovery above has run.
            warn "The panel has been restarted on ${FROM_VER}. Snapshot of this attempt: ${BACKUP}"
            if [ "${_rc}" -eq 0 ]; then _rc=1; fi
            exit "${_rc}"
        fi
        die "Update ABORTED partway through${_why} — the panel has been restarted on ${FROM_VER}.
     Snapshot of this attempt: ${BACKUP}"
    }
    # A kill is not an exit status. Catch the signals so the handler can NAME the one that arrived
    # (bash runs the EXIT trap either way, with `$?` still 0), and let the EXIT trap keep doing the
    # single, shared recovery.
    _update_window_signal() { _ABORT_SIG="$1"; exit "$2"; }
    trap '_update_window_signal SIGHUP 129' HUP
    trap '_update_window_signal SIGINT 130' INT
    trap '_update_window_signal SIGTERM 143' TERM
    trap _update_window_abort ERR EXIT

    if [ -d "${PANEL_DIR}/data" ]; then
        tar -C "${PANEL_DIR}/data" --ignore-failed-read --exclude=./.backups -cf - . 2>/dev/null | ${SNAP_GZ} > "${BACKUP}/data.tgz" || true
        # The service is stopped by now, so this die must put it back — the message promises the
        # panel is unchanged, and a panel that is down is not unchanged.
        if ! snapshot_ok "${BACKUP}/data.tgz"; then
            svc start linuxgsm-panel.service || true
            die "Couldn't snapshot the database/config (backup empty or unreadable) — update ABORTED,
     the panel is unchanged and has been restarted on ${FROM_VER}."
        fi
    fi
    ok "Snapshot saved"

    # Database maintenance runs AFTER the snapshot (so nothing here can lose data — the
    # snapshot is the fallback) and with the service STOPPED (VACUUM and any rebuild need
    # exclusive access — the stop now happens up at [1/6], so the snapshot gets a quiesced
    # database too). check -> repair only if needed -> optimize -> re-check. The tool is
    # part of the INSTALLED version, so it's present whenever this newer install.sh runs.
    info "[2/6] Checking + optimising the database…"
    # WHICH python and WHICH script, as root, matters here — this runs at step [2/6], BEFORE any
    # git fetch, so nothing about it is "the new code we just verified". It used to be
    # ${PANEL_DIR}/venv/bin/python3 running ${PANEL_DIR}/db_maintenance.py: an interpreter and a
    # script that both belong to the panel user, executed as root at the panel's own request
    # (panel-self-update runs this installer). That is arbitrary root execution with no update
    # involved at all.
    #
    # The root-owned copy at ${HELPER_DIR}/db_maintenance.py exists for exactly this, and the
    # helper already runs it with the SYSTEM python for exactly this reason. Root uses that pair;
    # an unprivileged (systemd --user) install keeps the checkout copy, where there is no boundary
    # to cross — it is the same account either way.
    DBM_RUN=""
    if [ "$(id -u)" -eq 0 ]; then
        [ -f "/usr/local/lib/linuxgsm-panel/db_maintenance.py" ] \
            && DBM_RUN="python3 /usr/local/lib/linuxgsm-panel/db_maintenance.py"
    elif [ -x "${PANEL_DIR}/venv/bin/python3" ] && [ -f "${PANEL_DIR}/db_maintenance.py" ]; then
        DBM_RUN="${PANEL_DIR}/venv/bin/python3 ${PANEL_DIR}/db_maintenance.py"
    fi
    if [ -n "${DBM_RUN}" ]; then
        if ${DBM_RUN} update; then
            ok "Database checked"
        else
            _dbrc=$?
            if [ "${_dbrc}" -eq 2 ]; then
                warn "The database failed its health check and could not be repaired."
                svc start linuxgsm-panel.service || true
                die "Update ABORTED to protect your data. The panel is UNCHANGED and has been
     restarted on the current version (${FROM_VER}); its database was left exactly as it was
     (a copy of the flagged file is saved alongside it). Repair it from the panel's database
     tools, or restore a backup, then update again.  Snapshot of this attempt: ${BACKUP}"
            fi
            warn "Database maintenance reported a non-fatal issue (rc=${_dbrc}) — continuing."
        fi
    else
        info "  (no root-owned database maintenance tool yet — skipping; this run installs one)"
    fi

    info "[3/6] Fetching the new version…"
    REQ_BEFORE="$(sha256sum "${PANEL_DIR}/requirements.txt" 2>/dev/null | awk '{print $1}')"
    fetch_code
    _CODE_FETCHED=1   # from here an abort has to put the old code back, not just restart the service
    TO_VER="$(panel_version)"
    REQ_AFTER="$(sha256sum "${PANEL_DIR}/requirements.txt" 2>/dev/null | awk '{print $1}')"
    ok "Code updated (${FROM_VER} → ${TO_VER})"

    # Most updates are code-only. Reinstalling deps means pip resolves + may rebuild wheels,
    # which pegs the CPU on a small VPS for no reason. Skip it when requirements.txt is byte-for-byte
    # unchanged AND the venv already exists — the packages are already installed at the same version.
    info "[4/6] Installing dependencies…"
    if [ -x "${PANEL_DIR}/venv/bin/python3" ] && [ -n "${REQ_BEFORE}" ] && [ "${REQ_BEFORE}" = "${REQ_AFTER}" ]; then
        ok "Dependencies unchanged — skipping pip (nothing to build)"
    else
        install_deps
        ok "Dependencies installed"
    fi
    [ "${RUN_AS_ROOT}" -eq 1 ] && chown -R "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}"

    # Refresh the ROOT-OWNED copies to match the code we just fetched, BEFORE the service comes
    # back up — the new code may call verbs the installed helper does not know yet, and a stale
    # helper answers those with `unknown verb` and no fallback. This is also the only place an
    # existing install's sudoers grant is ever re-evaluated, so a host that first installed before
    # the helper existed gets narrowed here instead of keeping NOPASSWD:ALL indefinitely.
    check_origin_trusted
    install_root_tools
    [ "${ORIGIN_TRUSTED}" -eq 1 ] && write_sudoers_grant
    write_terminal_sudo_grant

    info "[5/6] Starting the service…"
    ensure_service_tuning   # refresh the low-priority drop-in (existing installs get it on update)
    ensure_system_tuning    # prefer RAM over swap (applied on update too)
    svc daemon-reload || true
    svc start linuxgsm-panel.service || true   # it was stopped at [1/6] to quiesce the DB
    # The panel is up again, so the stopped-window trap has nothing left to rescue: hand failures
    # from here on to the health-check/rollback path below, which owns them.
    trap - ERR EXIT HUP INT TERM
    # Ensure the path-independent recovery command exists on existing installs too — including
    # non-root (systemd --user) installs, where writing to /usr/local/bin needs sudo. This used to be
    # root-only, so `--user` installs never got `linuxgsm-panel-recover` (command not found).
    install_recovery_command

    info "[6/6] Verifying the panel came back up…"
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
                info "System updates are available — applying them now…"
                ${UPG_SUDO} apt-get -y -o Dpkg::Options::="--force-confold" full-upgrade \
                    || warn "Some packages could not be upgraded — continuing."
                ${UPG_SUDO} apt-get -y autoremove --purge >/dev/null 2>&1 || true
                if [ ! -f /var/run/reboot-required ]; then
                    ok "System updated — no reboot required."
                elif pgrep -x tmux >/dev/null 2>&1 || pgrep -x SCREEN >/dev/null 2>&1; then
                    warn "The update needs a reboot, but game servers are running (tmux/screen) —"
                    warn "not rebooting so players aren't dropped. Reboot when they're empty:  ${UPG_SUDO} reboot"
                else
                    warn "Rebooting to bake in the system update — reconnect in ~1 minute; the panel"
                    warn "restarts automatically. (Press Ctrl-C in the next 15s to skip.)"
                    sleep 15
                    ${UPG_SUDO} reboot
                fi
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
    # Guarded, and it is the reason the guard matters: PANEL_DIR has just been emptied, so an
    # unpack that fails leaves a half-populated install. Bare, `set -e` killed the script right
    # here — past install_deps, past the service restart, and past BOTH die messages below — so
    # the operator (or the in-panel self-update, which only watches the log) got a dead panel and
    # no explanation at all. This says what happened and where the snapshot is.
    if ! tar -C "${PANEL_DIR}" -xzf "${BACKUP}/code.tgz"; then
        die "Update FAILED, and so did the rollback: the code snapshot could not be unpacked.
     ${PANEL_DIR} is INCOMPLETE and the panel will not start. Restore it by hand from:
       ${BACKUP}/code.tgz
     (data/ and venv/ were not touched.)"
    fi
    if [ -f "${BACKUP}/data.tgz" ]; then
        find "${PANEL_DIR}/data" -mindepth 1 -maxdepth 1 ! -name .backups -exec rm -rf {} + 2>/dev/null || true
        if ! tar -C "${PANEL_DIR}/data" -xzf "${BACKUP}/data.tgz"; then
            die "Update FAILED, and so did the rollback: the data snapshot could not be unpacked.
     ${PANEL_DIR}/data is INCOMPLETE — the database and encryption keys are missing. Restore by hand from:
       ${BACKUP}/data.tgz"
        fi
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
ensure_gamedig   # Node LTS + gamedig for querying game servers that run on this panel host
ensure_fail2ban  # brute-force protection for the panel login (jail is configured by the panel itself)

# Ensure the panel's listen port is free BEFORE the first boot: if 5000 (or a previously
# configured port) is already taken by another service, the panel would fail to bind. Probe
# for a free port and record it in config.json so the service start, the health check, and
# the firewall step below all use the same, working port. (Written before the chown below so
# the root-install path fixes ownership afterward.)
DESIRED_PORT="$(panel_port)"
PANEL_PORT="$(choose_and_record_port "${DESIRED_PORT}")"
# Empty = the probe found nothing free in the whole range and recorded nothing. Asked only "is it
# the port we wanted?", these two branches could say "a different port" or "it is free" and nothing
# else — so the one outcome where NONE of the three consumers named above would work printed as the
# green tick. Stop here instead: the operator can free a port or pick one, and either beats a
# service that restarts every 5s against an address the installer called free.
if [ -z "${PANEL_PORT}" ]; then
    die "No free port found in ${DESIRED_PORT}-$((DESIRED_PORT + 50)).
     Free one of them, or set \"port\" in ${PANEL_DIR}/data/config.json, and re-run."
elif [ "${PANEL_PORT}" != "${DESIRED_PORT}" ]; then
    warn "Port ${DESIRED_PORT} is already in use — the panel will use port ${PANEL_PORT} instead."
else
    ok "Port ${PANEL_PORT} is free for the panel"
fi

install_root_tools

info "[3/4] Registering the service…"
if [ "${RUN_AS_ROOT}" -eq 1 ]; then
    # Path-independent recovery command: `sudo linuxgsm-panel-recover` from anywhere. HERE, beside
    # install_root_tools and before the chown below, for the same reason: until then the checkout
    # is still root's own, so recover.sh is read straight from it. After the chown it is the panel
    # user's, and root would need its own clone to agree — which a tarball, a --src tree with no
    # .git or a local commit, or a host without network never gets, leaving no recovery command.
    install_recovery_command
    # Own everything as the service user, then run a system service AS that user.
    chown -R "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}"

    # Passwordless sudo so the panel can manage the local host (game-server users,
    # apt, ufw). This is UNRESTRICTED root for the service user — see the trust-model
    # note at the top of this file for why it cannot currently be scoped, and delete
    # /etc/sudoers.d/linuxgsm-panel if you only manage remotes.
    write_sudoers_grant
    write_terminal_sudo_grant

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
    # Recovery command for --user installs too — this branch is non-root, so sudo writes /usr/local/bin.
    install_recovery_command
fi
ensure_service_tuning                          # low CPU/IO priority so the panel yields to games
ensure_system_tuning                           # prefer RAM over swap (vm.swappiness)
svc restart linuxgsm-panel.service || true     # apply the priority drop-in just written
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
#
# ${SUDO} — computed fifteen lines above and not used here. `ufw status` requires uid 0: as an
# ordinary user it writes "ERROR: You need to be root to run this script" to stderr, which the
# 2>/dev/null discarded, and exits non-zero. So on the NON-ROOT install path (the documented
# systemd --user model) all three probes came back empty and all three flags stayed 0 — an empty
# answer read as the fact "ufw is not active".
#
# Both consequences were silent. The auto-open below is gated on UFW_ACTIVE, so the port was never
# opened; and the banner's else branch printed the bare public URL under "Open the panel — the
# first visit runs the setup wizard" with no firewalled caveat. The health check passes either
# way, because it probes 127.0.0.1, so the install reported green while handing the user an
# address their firewall was blocking.
#
# Read ONCE into a variable, too: three separate invocations of a root-only command could disagree
# with each other, and only one of them needs to be right to matter.
UFW_ACTIVE=0; TS_UFW=0; PORT_OPEN=0; UFW_READ=0
if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS="$(${SUDO} ufw status 2>/dev/null)" || true
    # `ufw status` always prints a "Status:" line when it really ran. Its absence means the command
    # did not answer — which is not the same as "inactive", and must not be reported as one.
    if printf '%s' "${UFW_STATUS}" | grep -q "Status:"; then
        UFW_READ=1
        printf '%s' "${UFW_STATUS}" | grep -q "Status: active" && UFW_ACTIVE=1
        printf '%s' "${UFW_STATUS}" | grep -qi "tailscale0"    && TS_UFW=1
        printf '%s' "${UFW_STATUS}" | grep -qw "${PORT}"       && PORT_OPEN=1
    fi
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
    elif [ "${UFW_READ}" -eq 0 ] && command -v ufw >/dev/null 2>&1; then
        # ufw is installed but would not answer — as an ordinary user it needs root. Say the state
        # is unknown rather than printing the address as though it were reachable: the health check
        # above proves only that the panel answers on 127.0.0.1.
        echo -e "  • Public IP:  ${CYAN}${PANEL_SCHEME}://${PUBLIC_IP}:${PORT}${NC}  ${YELLOW}(firewall state unknown — check 'sudo ufw status' allows ${PORT}/tcp)${NC}"
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

# ── Reboot ONLY if an update actually requires one — and NEVER out from under running game
#    servers. A brand-new VPS with a fresh kernel reboots to bake it in and prove it boots cleanly;
#    but if this host is already running game servers (tmux/screen sessions), a reboot would drop
#    the players, so we never do it automatically — we tell you to reboot when they're empty.
#    Skip the reboot entirely with PANEL_NO_UPGRADE=1 or PANEL_NO_REBOOT=1. The panel service is
#    enabled on boot, so it's back at the URL above ~1 minute after any reboot. ──
if [ "${PANEL_NO_UPGRADE:-0}" != "1" ] && [ "${PANEL_NO_REBOOT:-0}" != "1" ]; then
    RB_SUDO=""; [ "$(id -u)" -ne 0 ] && RB_SUDO="sudo"
    if [ ! -f /var/run/reboot-required ]; then
        ok "No reboot needed — nothing pending requires one."
    elif pgrep -x tmux >/dev/null 2>&1 || pgrep -x SCREEN >/dev/null 2>&1; then
        warn "A system update needs a reboot to finish (e.g. a new kernel), but this host is running"
        warn "game servers (tmux/screen sessions detected) — NOT rebooting so players aren't dropped."
        warn "Reboot it yourself once your servers are empty:  ${RB_SUDO} reboot"
    else
        warn "A system update needs a reboot to finish; no game servers are running, so rebooting now"
        warn "to bake it in and confirm a clean boot. Reconnect in ~1 minute; the panel comes back"
        warn "at the URL above. (Press Ctrl-C in the next 15s to skip and reboot yourself later.)"
        sleep 15
        ${RB_SUDO} reboot
    fi
fi
