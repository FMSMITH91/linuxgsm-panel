#!/usr/bin/env bash
# LinuxGSM Panel — one-command recovery. Finds your install and runs the recovery CLI
# from anywhere, so you never have to cd into the panel directory or know the venv path.
#
#   sudo linuxgsm-panel-recover                         # reset the sole superadmin's password
#   sudo linuxgsm-panel-recover reset-password [user]
#   sudo linuxgsm-panel-recover disable-2fa <user>      # lost your authenticator
#   sudo linuxgsm-panel-recover create-admin <user>     # no superadmin left
#   sudo linuxgsm-panel-recover list-users
#
# No command yet (older install) or a fresh shell? Same one-liner style as the installer:
#   curl -fsSL https://raw.githubusercontent.com/FMSMITH91/linuxgsm-panel/main/recover.sh | sudo bash
#   curl -fsSL .../recover.sh | sudo bash -s -- disable-2fa alice
set -euo pipefail

SYSTEM_UNIT="/etc/systemd/system/linuxgsm-panel.service"
USER_UNIT="${HOME}/.config/systemd/user/linuxgsm-panel.service"

read_unit() {  # $1=unit file, $2=key — print the value of `key=...`
    [ -f "$1" ] || return 0
    awk -F= -v k="$2=" 'index($0,k)==1 {print substr($0, length(k) + 1); exit}' "$1"
}

# ── Locate the install (systemd unit first, then common fallbacks) ──
PANEL_DIR=""; SVC_USER=""
if [ -f "${SYSTEM_UNIT}" ]; then
    PANEL_DIR="$(read_unit "${SYSTEM_UNIT}" WorkingDirectory)"
    SVC_USER="$(read_unit "${SYSTEM_UNIT}" User)"
elif [ -f "${USER_UNIT}" ]; then
    PANEL_DIR="$(read_unit "${USER_UNIT}" WorkingDirectory)"
    SVC_USER="$(id -un)"
fi
# A systemd --user install: run under sudo, $HOME is root's, so the USER_UNIT above isn't found.
# Scan every real user's home for the unit and adopt its owner as the service user.
if [ -z "${PANEL_DIR}" ]; then
    for uu in /home/*/.config/systemd/user/linuxgsm-panel.service; do
        [ -f "${uu}" ] || continue
        d="$(read_unit "${uu}" WorkingDirectory)"
        if [ -n "${d}" ] && [ -f "${d}/manage.py" ]; then
            PANEL_DIR="${d}"; SVC_USER="$(echo "${uu}" | awk -F/ '{print $3}')"; break
        fi
    done
fi
if [ -z "${PANEL_DIR}" ] || [ ! -f "${PANEL_DIR}/manage.py" ]; then
    # Resolve THROUGH any symlink (e.g. /usr/local/bin/linuxgsm-panel-recover) to this script's real
    # directory — the panel dir — so it's found even when run as root via the symlink.
    self="$(readlink -f "$0" 2>/dev/null || echo "$0")"
    selfdir="$(cd "$(dirname "${self}")" 2>/dev/null && pwd)" || selfdir=""
    for d in "/home/lgsmpanel/linuxgsm-panel" "${HOME}/linuxgsm-panel" "${selfdir}"; do
        if [ -n "${d}" ] && [ -f "${d}/manage.py" ]; then PANEL_DIR="${d}"; break; fi
    done
fi
if [ -z "${PANEL_DIR}" ] || [ ! -f "${PANEL_DIR}/manage.py" ]; then
    echo "Couldn't find a LinuxGSM Panel install on this host — run this ON the panel server." >&2
    exit 1
fi
[ -n "${SVC_USER}" ] || SVC_USER="$(stat -c '%U' "${PANEL_DIR}")"

PY="${PANEL_DIR}/venv/bin/python"
[ -x "${PY}" ] || PY="$(command -v python3 || true)"
[ -n "${PY}" ] || { echo "No Python found for the panel." >&2; exit 1; }

# Default action: reset the (sole) superadmin's password.
[ "$#" -gt 0 ] || set -- reset-password

# Run AS THE PANEL'S USER so the SQLite database and its WAL files keep the correct
# ownership (running as root could leave root-owned journal files the service can't write).
if [ "$(id -un)" = "${SVC_USER}" ]; then
    exec "${PY}" "${PANEL_DIR}/manage.py" "$@"
elif [ "$(id -u)" -eq 0 ]; then
    exec sudo -u "${SVC_USER}" "${PY}" "${PANEL_DIR}/manage.py" "$@"
else
    echo "Re-run with sudo so it can read the panel's owner-only database:" >&2
    echo "    sudo ${0##*/} $*" >&2
    exit 1
fi
