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
# Where per-user installs are looked for. A variable so a test can point the scan at a sandbox
# without rewriting this script — the same reason panel-helper declares its paths in one place.
HOMES="${PANEL_RECOVER_HOMES:-/home}"

read_unit() {  # $1=unit file, $2=key — print the value of `key=...`
    [ -f "$1" ] || return 0
    awk -F= -v k="$2=" 'index($0,k)==1 {print substr($0, length(k) + 1); exit}' "$1"
}

# ── Locate the install (an explicit PANEL_DIR wins, then the systemd unit, then fallbacks) ──
# PANEL_DIR may be set by the caller to name the install outright — which is what the ambiguity
# refusal below tells the operator to do.
PANEL_DIR="${PANEL_DIR:-}"; SVC_USER=""
if [ -n "${PANEL_DIR}" ]; then
    :                                   # named explicitly; nothing to discover
elif [ -f "${SYSTEM_UNIT}" ]; then
    PANEL_DIR="$(read_unit "${SYSTEM_UNIT}" WorkingDirectory)"
    SVC_USER="$(read_unit "${SYSTEM_UNIT}" User)"
elif [ -f "${USER_UNIT}" ]; then
    PANEL_DIR="$(read_unit "${USER_UNIT}" WorkingDirectory)"
    SVC_USER="$(id -un)"
fi
# A systemd --user install: run under sudo, $HOME is root's, so the USER_UNIT above isn't found.
# Scan every real user's home for the unit and adopt its owner as the service user.
#
# EVERY candidate is collected, not the first one found. /home/* is one directory per LOCAL USER,
# and this script runs as root during a lockout. The panel itself creates a Linux account per game
# server (useradd -m), so those homes exist by design — which means anyone who gets code execution
# as a game server (a malicious mod, an RCE in the game) can write
# ~/.config/systemd/user/linuxgsm-panel.service pointing WorkingDirectory at a directory of their
# own that contains a manage.py.
#
# The loop took the first match and broke, and glob expansion is alphabetical, so "aaaserver" wins
# over "ubuntu": `sudo linuxgsm-panel-recover` would run THEIR manage.py — as them, so not a
# privilege gain — and hand it the new superadmin password the operator is in the middle of typing,
# while the real panel stayed locked.
#
# Ownership cannot tell the two apart: a genuine per-user install and a planted one are both owned
# by the user whose home they sit in. So this does not guess. One candidate is unambiguous; more
# than one is a question only the operator can answer, and it gets asked.
if [ -z "${PANEL_DIR}" ]; then
    CANDIDATES=""
    for uu in "${HOMES}"/*/.config/systemd/user/linuxgsm-panel.service; do
        [ -f "${uu}" ] || continue
        d="$(read_unit "${uu}" WorkingDirectory)"
        [ -n "${d}" ] && [ -f "${d}/manage.py" ] || continue
        CANDIDATES="${CANDIDATES}$(basename "$(dirname "$(dirname "$(dirname "$(dirname "${uu}")")")")")|${d}
"
    done
    N_CAND="$(printf '%s' "${CANDIDATES}" | grep -c . || true)"
    if [ "${N_CAND}" -gt 1 ]; then
        echo "More than one per-user panel install is present on this host:" >&2
        printf '%s' "${CANDIDATES}" | while IFS='|' read -r u d; do
            [ -n "${u}" ] && echo "    ${d}   (user ${u})" >&2
        done
        echo "" >&2
        echo "Refusing to guess which one you mean. Name it:" >&2
        echo "    sudo PANEL_DIR=/path/to/panel ${0##*/} $*" >&2
        exit 1
    fi
    if [ "${N_CAND}" -eq 1 ]; then
        SVC_USER="$(printf '%s' "${CANDIDATES}" | head -1 | cut -d'|' -f1)"
        PANEL_DIR="$(printf '%s' "${CANDIDATES}" | head -1 | cut -d'|' -f2)"
    fi
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

# Say WHICH install is about to be driven, every time. This is the general defence behind the
# ambiguity refusal above: whatever route found the install, the operator sees the path and the
# account before they type a password into it.
echo "Using ${PANEL_DIR} (service user ${SVC_USER})" >&2

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
