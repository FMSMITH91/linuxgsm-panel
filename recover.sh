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

# All three overridable, for the reason the HOMES comment already gives. The unit paths were
# fixed strings, and they are consulted BEFORE the scan — so on a host that really has a panel
# unit (i.e. any real install) the sandbox below was bypassed entirely and the ambiguity checks
# in tests/unit/part06.py silently exercised a branch they were not written for. Found by running
# the suite on a deployed host, where recover.sh reported the test's own directory with the live
# service user. Defaults are unchanged, so production behaviour is identical.
SYSTEM_UNIT="${PANEL_RECOVER_SYSTEM_UNIT:-/etc/systemd/system/linuxgsm-panel.service}"
USER_UNIT="${PANEL_RECOVER_USER_UNIT:-${HOME}/.config/systemd/user/linuxgsm-panel.service}"
# Where per-user installs are looked for. A variable so a test can point the scan at a sandbox
# without rewriting this script — the same reason panel-helper declares its paths in one place.
HOMES="${PANEL_RECOVER_HOMES:-/home}"
# The file install_root_tools writes beside the privileged helper, recording `panel_dir=` for the
# install it configured. Root-owned, so reading it costs nothing; overridable for the same reason
# as the paths above. Consulted only by the last-resort block below — see the comment there.
PANEL_CONF="${PANEL_RECOVER_PANEL_CONF:-/usr/local/lib/linuxgsm-panel/panel.conf}"

read_unit() {  # $1=unit file, $2=key — print the value of `key=...`
    # -r as well as -f, and a `|| return 0` on the awk. A file that EXISTS but cannot be read made
    # awk exit 2, and under the `set -euo pipefail` above that killed the whole script at the
    # assignment — with a raw "awk: fatal: cannot open file" and none of this script's own output,
    # in the one tool an operator reaches for when they are already locked out. Proven by running
    # this function verbatim against a chmod 000 file: exit 2, before the next line.
    # Every caller already treats an empty answer as "nothing recorded", which is the right
    # reading: could-not-read is not a value, and guessing one here picks an install.
    [ -f "$1" ] && [ -r "$1" ] || return 0
    awk -F= -v k="$2=" 'index($0,k)==1 {print substr($0, length(k) + 1); exit}' "$1" || return 0
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
    # Nothing named the install, so ask the INSTALLER first, then try the two conventional
    # locations, then this script's own directory.
    #
    # ${selfdir} was the last-resort arm, and the comment here claimed it resolved "through the
    # symlink to the panel dir". That stopped being true: install_recovery_command now stages a
    # ROOT-OWNED copy of this script in /usr/local/lib/linuxgsm-panel and points
    # /usr/local/bin/linuxgsm-panel-recover at THAT, so on a normally-installed host readlink
    # lands in the helper directory — which holds no manage.py — and the arm never matched. An
    # install outside the two conventional locations (a per-user one whose systemd unit had been
    # lost, or whose home is outside ${HOMES}) was told "Couldn't find a LinuxGSM Panel install on
    # this host" during a lockout, on a host that plainly had one.
    #
    # ${PANEL_CONF} is what makes the last resort work again, without guessing: install_root_tools
    # writes `panel_dir=` there for exactly this question, and it is root-owned, so a compromised
    # panel cannot aim it. ${selfdir} stays for the case it does still cover — this script run
    # straight out of the checkout (`bash ~/linuxgsm-panel/recover.sh`, the curl one-liner), or the
    # degraded install where no root-owned copy could be placed and the symlink points at the
    # checkout after all. The `-f .../manage.py` guard applies to every arm alike, so a stale conf
    # naming a directory that is gone is not mistaken for an install, and does not mask one that
    # another arm can still reach.
    #
    # It is tried FIRST, ahead of the two conventional locations, because it is the only arm that
    # KNOWS rather than guesses. The others are shaped like guesses and one of them is aimed by the
    # environment: this runs under sudo, so ${HOME} is ROOT's, and a leftover /root/linuxgsm-panel
    # checkout — a half-finished install, a clone made while debugging — would otherwise outrank
    # the install the installer actually recorded, and the lockout remedy would drive the wrong
    # tree with the operator's new superadmin password.
    #
    # What panel.conf is trusted FOR here is the LOCATION of an install, not its OWNERSHIP; those
    # are separate claims and only the second is the one this tree rejects. uninstall.sh
    # deliberately does NOT read panel.conf to decide whether the host-shared pieces are ITS to
    # remove, because install.sh rewrites the file on every install and every self-update, so on a
    # co-tenanted host it names whoever ran LAST — "is another install still here?" is a question
    # it cannot answer. "Where is an install?" is one it can: root wrote that path, and the
    # directory either holds a manage.py or it does not. The cost is that on a co-tenanted host
    # with both systemd units gone this drives the last-installed panel instead of refusing, which
    # is why the "Using <dir> (service user <user>)" line below is printed before the operator
    # types anything into it.
    conf_dir="$(read_unit "${PANEL_CONF}" panel_dir)"
    self="$(readlink -f "$0" 2>/dev/null || echo "$0")"
    selfdir="$(cd "$(dirname "${self}")" 2>/dev/null && pwd)" || selfdir=""
    if [ -n "${conf_dir}" ] && [ -f "${conf_dir}/manage.py" ]; then
        # Same reason as the loop below: SVC_USER, where it is set at all, came from the install
        # being discarded here, and the `stat` further down derives it from the directory chosen.
        [ "${conf_dir}" = "${PANEL_DIR}" ] || SVC_USER=""
        PANEL_DIR="${conf_dir}"
    else
        for d in "/home/lgsmpanel/linuxgsm-panel" "${HOME}/linuxgsm-panel" "${selfdir}"; do
            if [ -n "${d}" ] && [ -f "${d}/manage.py" ]; then
                # The account came from the install this block is DISCARDING — a unit file's User=,
                # or the owner of a directory that turned out to have no manage.py. Clearing it lets
                # the `stat -c '%U' "${PANEL_DIR}"` below derive the account from the directory
                # actually chosen, which is the line that exists to do exactly that.
                #
                # Left set, the two halves came from different installs: the interpreter is
                # ${PANEL_DIR}/venv/bin/python from the NEW directory, run under `sudo -u` as the OLD
                # directory's user — and the line that announces the pairing
                # ("Using <dir> (service user <user>)") printed a combination nothing had established.
                [ "${d}" != "${PANEL_DIR}" ] && SVC_USER=""
                PANEL_DIR="${d}"
                break
            fi
        done
    fi
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
