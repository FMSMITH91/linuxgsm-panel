#!/usr/bin/env bash
# install-gamedig.sh: install gamedig, the panel's player-query tool, from the hash-locked
# package-lock.json beside this script, and point the `gamedig` command at it. Run as root.
#
# WHY A LOCKFILE. gamedig used to be `npm install -g gamedig@5`, once at install and again from a
# weekly root cron: whatever 5.x release, and whatever versions of its ~50 floating dependencies,
# the registry served that Sunday, fetched by root with nobody reviewing them, and then run hourly
# as every game account. Now the whole tree is the one package-lock.json names. It is committed to
# the repository and moves only through reviewed Dependabot pull requests, and `npm ci` checks
# every tarball it downloads against the sha512 recorded there.
#
# WHERE. Everything lives in the directory this script is in (/usr/local/lib/linuxgsm-panel/gamedig
# on every host):
#   <dir>/<sha256 of the lockfile>/   one installed tree per lockfile
#   <dir>/current                     -> the tree in use, switched by one rename
#   /usr/local/bin/gamedig and /usr/bin/gamedig  -> <dir>/current/node_modules/.bin/gamedig
# Both links, because an older gamedig lived in either place. NodeSource's npm installs global
# commands in /usr/bin, and the hourly restart-when-empty lines already in game accounts' crontabs
# call a bare `gamedig` on cron's PATH, which is /usr/bin:/bin. The distro's npm installs them in
# /usr/local/bin, which comes first on every other PATH, so a stale copy left there would shadow
# the new one for the panel's own player reads.
#
# NEVER IN PLACE. `npm ci` deletes node_modules before it downloads anything, so a registry outage
# halfway through would leave the host with no gamedig at all. The new tree is built in a staging
# directory and run once. Only then does `current` switch to it, and only then are the links
# touched. Until that point the tree in use and whatever the links point at are left alone.
# `npm ci` gets ten minutes: npm has no overall deadline. Against a registry that accepts
# connections and never answers it was still running after half an hour (a 5-minute fetch
# timeout per request, then retries), holding this script's lock through fd 9 even once the
# script itself was gone, and TERM alone did not stop it.
#
# IDEMPOTENT. When `current` is already this lockfile's tree and it runs, nothing is fetched. The
# weekly cron that calls this is a repair job, not an updater: only a new lockfile changes the tree.
set -uo pipefail
umask 022

# The logical path, not the physical one: the links name it, and uninstall.sh recognises the panel's
# links by that prefix (/usr/local/lib/linuxgsm-panel/gamedig/), which a resolved symlink would hide.
HERE="$(cd -- "$(dirname -- "$0")" && pwd)" || exit 1
PKG="${HERE}/package.json"
LOCK="${HERE}/package-lock.json"
LINK_DIRS=(/usr/local/bin /usr/bin)
BIN="node_modules/.bin/gamedig"

say() { printf 'install-gamedig: %s\n' "$*"; }
fail() { say "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run this as root"
{ [ -f "${PKG}" ] && [ -f "${LOCK}" ]; } \
    || fail "package.json and package-lock.json must be beside this script, in ${HERE}"

# One run at a time. install.sh, the weekly cron and the panel's daily pass for a remote can meet.
if command -v flock >/dev/null 2>&1; then
    exec 9>"${HERE}/.lock" || fail "cannot open ${HERE}/.lock"
    flock -w 900 9 || fail "another run is still going after 15 minutes"
fi

HASH="$(sha256sum -- "${LOCK}" 2>/dev/null)"
HASH="${HASH%% *}"
[[ "${HASH}" =~ ^[0-9a-f]{64}$ ]] || fail "could not hash ${LOCK}"
TREE="${HERE}/${HASH}"

# Does the gamedig at $1 run? Asked of a server that is not there: loopback port 1, one attempt,
# short timeouts, about a second and a half. gamedig reports that on stdout as {"error":...}.
# Anything else (a stack trace from a missing module, a Node too old for it, no output at all) is a
# tree that does not work.
works() {
    local out
    out="$(cd / && timeout 60 "$1" --type minecraft 127.0.0.1:1 --givenPortOnly --maxRetries 1 \
             --socketTimeout 1000 --attemptTimeout 3000 2>/dev/null)" || return 1
    case "${out}" in '{"error":'*) return 0 ;; esac
    return 1
}

if [ "$(readlink -- "${HERE}/current" 2>/dev/null)" = "${HASH}" ] && works "${TREE}/${BIN}"; then
    say "gamedig is current (lockfile ${HASH:0:12}), nothing to fetch"
else
    command -v npm >/dev/null 2>&1 \
        || fail "npm is not installed, so gamedig cannot be installed (it needs Node.js 18+ and npm)"
    STAGE="$(mktemp -d "${HERE}/.stage.XXXXXXXX")" || fail "cannot create a staging directory in ${HERE}"
    trap 'rm -rf -- "${STAGE}"' EXIT
    # mktemp -d makes it 0700. The tree is run by every game account, so it has to be searchable.
    { chmod 755 "${STAGE}" && cp -- "${PKG}" "${LOCK}" "${STAGE}/"; } \
        || fail "cannot copy the lockfile into ${STAGE}"
    say "installing gamedig from lockfile ${HASH:0:12}"
    # --ignore-scripts: no package's install hook runs, as root or at all. --omit=dev: the tree
    # gamedig runs with and nothing else. The cache is inside the staging directory and is deleted
    # with it, so a run under sudo never leaves root-owned files in somebody else's home.
    # timeout: see NEVER IN PLACE above. -k: npm is sent KILL if TERM has not ended it in 30s.
    (cd -- "${STAGE}" && timeout -k 30 600 npm ci --ignore-scripts --omit=dev --no-audit \
        --no-fund --no-update-notifier --cache "${STAGE}/.npm-cache") \
        || fail "npm ci failed, or did not finish in 10 minutes. The gamedig already in place, if any, was left as it was."
    rm -rf -- "${STAGE}/.npm-cache"
    works "${STAGE}/${BIN}" \
        || fail "the new gamedig does not run. The gamedig already in place, if any, was left as it was."
    rm -rf -- "${TREE}"
    mv -T -- "${STAGE}" "${TREE}" || fail "cannot move the new tree to ${TREE}"
    trap - EXIT
    { ln -sfn -- "${HASH}" "${HERE}/.current.new" && mv -Tf -- "${HERE}/.current.new" "${HERE}/current"; } \
        || fail "cannot switch ${HERE}/current to the new tree"
fi

# The two commands. A link is replaced when it is missing, dangling, the panel's, or npm's; a
# regular file, or a link to some other gamedig, is somebody else's and is left alone, and the run
# reports it. Each is swapped in with one rename, so `gamedig` never stops resolving in between.
TARGET="${HERE}/current/${BIN}"
rc=0
for d in "${LINK_DIRS[@]}"; do
    [ -d "${d}" ] || continue
    link="${d}/gamedig"
    if [ -e "${link}" ] || [ -L "${link}" ]; then
        if [ ! -L "${link}" ]; then
            say "left ${link} alone: it is a file, not the panel's link or npm's"
            rc=1
            continue
        fi
        cur="$(readlink -- "${link}")"
        [ "${cur}" = "${TARGET}" ] && continue
        case "${cur}" in
            "${HERE}"/*|*node_modules/gamedig/*) ;;
            *)
                if [ -e "${link}" ]; then
                    say "left ${link} alone: it points at ${cur}, which is not the panel's gamedig or npm's"
                    rc=1
                    continue
                fi ;;
        esac
    fi
    tmp="${d}/.gamedig.new.$$"
    { ln -sfn -- "${TARGET}" "${tmp}" && mv -Tf -- "${tmp}" "${link}"; } \
        || { rm -f -- "${tmp}"; say "could not link ${link}"; rc=1; }
done

# npm's own global gamedig, from before this script existed. Removed only now that both links
# above point at the new tree, and only when every one of them does (rc 0): a link left alone
# may still be npm's, and would dangle. The package directory is deleted rather than
# `npm uninstall -g`, which also deletes the command at npm's bin path — /usr/bin/gamedig with
# NodeSource's npm, /usr/local/bin/gamedig with the distro's — whatever it points at. Run before
# the links were made, that left `gamedig` resolving nowhere until they were.
if [ "${rc}" -eq 0 ] && command -v npm >/dev/null 2>&1; then
    NPM_ROOT="$(npm root -g 2>/dev/null)" || NPM_ROOT=""
    if [ -n "${NPM_ROOT}" ] && [ -d "${NPM_ROOT}/gamedig" ] && [ ! -L "${NPM_ROOT}/gamedig" ]; then
        say "removing npm's global gamedig (${NPM_ROOT}/gamedig)"
        rm -rf -- "${NPM_ROOT}/gamedig" \
            || say "could not remove ${NPM_ROOT}/gamedig; the links above already replace its command"
    fi
fi

# Trees for older lockfiles, and staging directories a killed run left behind.
for p in "${HERE}"/* "${HERE}"/.stage.*; do
    { [ -d "${p}" ] && [ ! -L "${p}" ]; } || continue
    n="${p##*/}"
    [ "${n}" != "${HASH}" ] || continue
    if [[ "${n}" =~ ^[0-9a-f]{64}$ ]] || [[ "${n}" == .stage.* ]]; then
        rm -rf -- "${p}"
    fi
done

VER="$(sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([^"]*\)".*/\1/p' \
        "${TREE}/node_modules/gamedig/package.json" 2>/dev/null | head -n 1)"
[ "${rc}" -ne 0 ] || say "gamedig ${VER:-(version unknown)} ready: ${TARGET}"
exit "${rc}"
