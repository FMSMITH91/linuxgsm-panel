#!/usr/bin/env bash
# Sign the add-on catalog: tools/sign-catalog.sh [--yes] [--refresh-catalog] <full commit id on main>
#
# Panels take the images and versions their add-ons run from a catalog signed with the release key,
# fetched from the release-signatures branch, so a new add-on image needs no panel update. The same
# catalog carries the websites' pins in its `sites` section (proxy binary, site images, runtimes, app
# recipes, the Cloudflare ranges); tools/addon_catalog.py refuses a catalog without a valid one, checked
# by the panels' own panel/services/websites_catalog.py. The source
# is panel/addon_images/catalog.json at the commit given. tools/sign-release.sh runs this after it
# signs a main commit (with --yes, its own confirmation already typed); run it by hand to publish or
# refresh the catalog alone.
#
# What it does, in order, and it stops at the first thing that is not right:
#   1. fetches main by its full name and refuses unless <sha> is a full commit id on its FIRST-PARENT
#      line, and reads the commit's catalog;
#   2. fetches release-signatures, and checks the published catalog/latest.json against its signature
#      (namespace linuxgsm-panel-addons) before trusting its seq;
#   3. refuses a commit OLDER than the one the published catalog came from (catalog/latest.source):
#      re-signing an old catalog with a higher seq would roll every panel back;
#   4. decides: the commit's catalog differs from the published one, or the published one expires
#      within tools/addon_catalog.py's REFRESH_DAYS, or --refresh-catalog was given. Otherwise there
#      is nothing to publish and it stops here, with success;
#   5. refuses unless every check the commit must pass has passed (the set deploy.yml waits for);
#   6. shows what changes and asks you to type the first 12 characters of the commit id. --yes skips
#      the typing only when stdin is not a terminal (a script);
#   7. signs the exact bytes with ssh-keygen -Y sign -n linuxgsm-panel-addons (its OWN namespace: a
#      catalog signature never passes as a release signature, nor the reverse) using
#      SIGN_RELEASE_KEY (default ~/.ssh/id_ed25519_signing), and verifies it against the repository's
#      release-signers as a host would;
#   8. commits catalog/<seq>.json, .json.sig and .source, and catalog/latest.json, .json.sig and
#      .source to release-signatures through a private index (your checkout is not touched), signed
#      (git commit-tree -S), and pushes it without force.
#
# Environment: SIGN_RELEASE_REMOTE (default origin), SIGN_RELEASE_KEY, SIGN_RELEASE_GH (default gh)
# for the GitHub CLI command that reads the commit's check runs.
set -euo pipefail
export LC_ALL=C.UTF-8 LANG=C.UTF-8 LANGUAGE=

NS="linuxgsm-panel-addons"
BRANCH="main"
SIG_BRANCH="release-signatures"
SRC_PATH="panel/addon_images/catalog.json"
die() { echo "sign-catalog: $*" >&2; exit 1; }

YES=0
MODE="auto"
ARGS=()
for a in "$@"; do
    case "${a}" in
        --yes) YES=1 ;;
        --refresh-catalog) MODE="refresh" ;;
        *) ARGS+=("${a}") ;;
    esac
done
[[ ${#ARGS[@]} -eq 1 ]] || die "usage: tools/sign-catalog.sh [--yes] [--refresh-catalog] <full commit id on main>"
SHA="${ARGS[0]}"
if [[ "${YES}" -eq 1 ]] && [[ -t 0 ]]; then
    die "--yes is refused at a terminal: run without it and type the commit id when asked."
fi
REMOTE="${SIGN_RELEASE_REMOTE:-origin}"
read -ra GH <<< "${SIGN_RELEASE_GH:-gh}"
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY="${SIGN_RELEASE_KEY:-${HOME}/.ssh/id_ed25519_signing}"
PY="${PYTHON:-$(command -v python3 || true)}"

case "${SHA}" in ""|*[!0-9a-f]*) die "'${SHA}' is not a full commit id (40 lowercase hex)." ;; esac
[[ "${#SHA}" -eq 40 ]] || die "'${SHA}' is not a full commit id (40 lowercase hex)."
[[ -f "${KEY}" ]] || die "no signing key at ${KEY} (set SIGN_RELEASE_KEY)."
command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen is not installed."
[[ -n "${PY}" ]] || die "python3 is not installed."
catalog_py() { "${PY}" -I "${TOOLS_DIR}/addon_catalog.py" "$@"; }

TRACK="refs/remotes/${REMOTE}/${BRANCH}"
SIGTRACK="refs/remotes/${REMOTE}/${SIG_BRANCH}"

# 1. On main's first-parent line (fetched by full name, compared as a string, as sign-release does).
git fetch --quiet --no-tags "${REMOTE}" "+refs/heads/${BRANCH}:${TRACK}" \
    || die "could not fetch ${BRANCH} from ${REMOTE}."
git show-ref --verify --quiet "${TRACK}" || die "${REMOTE} has no branch ${BRANCH}."
git rev-list --first-parent "${TRACK}" \
    | awk -v want="${SHA}" '($0 "") == want { found = 1 } END { exit !found }' \
    || die "${SHA} is not on ${REMOTE}/${BRANCH}'s first-parent line; nothing was signed."

TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT
git cat-file blob "${SHA}:${SRC_PATH}" > "${TMP}/source.json" 2>/dev/null \
    || die "${SHA} has no ${SRC_PATH}; nothing was signed."

# The release-signers the hosts that take this catalog hold: the commit's parent's (what a host on
# the previous release trusts), else the commit's own, as sign-release checks a release.
signers_at() {
    git cat-file blob "$1:panel/install/release-signers" 2>/dev/null \
        || git cat-file blob "$1:release-signers" 2>/dev/null
}
if git cat-file -e "${SHA}^1" 2>/dev/null && signers_at "${SHA}^1" > "${TMP}/signers"; then
    :
else
    signers_at "${SHA}" > "${TMP}/signers" || die "${SHA} has no release-signers to check signatures against."
fi
verify() {   # verify <file> <signature>: as a panel checks the catalog
    ssh-keygen -Y verify -f "${TMP}/signers" -I release -n "${NS}" -s "$2" < "$1" >/dev/null 2>&1
}

# 2. What is published now.
PARENT=""
if git fetch --quiet --no-tags "${REMOTE}" "+refs/heads/${SIG_BRANCH}:${SIGTRACK}" 2>/dev/null \
   && git show-ref --verify --quiet "${SIGTRACK}"; then
    PARENT="$(git rev-parse --verify "${SIGTRACK}^{commit}")"
fi
: > "${TMP}/latest.json"
if [[ -n "${PARENT}" ]] && git cat-file -e "${PARENT}:catalog/latest.json" 2>/dev/null; then
    git cat-file blob "${PARENT}:catalog/latest.json" > "${TMP}/latest.json"
    git cat-file blob "${PARENT}:catalog/latest.json.sig" > "${TMP}/latest.json.sig" 2>/dev/null \
        || die "catalog/latest.json on ${SIG_BRANCH} has no signature beside it; nothing was signed."
    verify "${TMP}/latest.json" "${TMP}/latest.json.sig" \
        || die "the published catalog/latest.json does not verify against release-signers; nothing was signed."
    # 3. Never an older commit's catalog over a newer one's.
    PREV_SRC="$( (git cat-file blob "${PARENT}:catalog/latest.source" 2>/dev/null || true) | awk 'NR == 1 { print $2 }')"
    [[ "${PREV_SRC}" =~ ^[0-9a-f]{40}$ ]] \
        || die "catalog/latest.source on ${SIG_BRANCH} names no commit; nothing was signed."
    git merge-base --is-ancestor "${PREV_SRC}" "${SHA}" 2>/dev/null \
        || die "the published catalog came from ${PREV_SRC:0:12}, which ${SHA:0:12} does not contain: signing it would roll panels back."
fi

# 4. Due?
RC=0
{ cat "${TMP}/source.json"; printf '\0'; cat "${TMP}/latest.json"; } \
    | catalog_py build "$(date -u +%s)" "${MODE}" > "${TMP}/catalog.json" 2> "${TMP}/review" || RC=$?
if [[ "${RC}" -eq 3 ]]; then
    echo "sign-catalog: $(cat "${TMP}/review")"
    exit 0
fi
[[ "${RC}" -eq 0 ]] || die "$(cat "${TMP}/review")"
SEQ="$(catalog_py seq < "${TMP}/catalog.json")" || die "the catalog built has no seq."
[[ "${SEQ}" =~ ^[1-9][0-9]{0,8}$ ]] || die "seq '${SEQ}' is not a whole number."
if [[ -n "${PARENT}" ]] && git cat-file -e "${PARENT}:catalog/${SEQ}.json" 2>/dev/null; then
    die "catalog/${SEQ}.json is already on ${SIG_BRANCH}; nothing was signed."
fi

# 5. Every check the commit must pass has passed.
command -v "${GH[0]}" >/dev/null 2>&1 || die "${GH[0]} is not installed: the commit's checks cannot be read."
"${GH[@]}" api --paginate "repos/{owner}/{repo}/commits/${SHA}/check-runs?per_page=100" \
    --jq '.check_runs[] | [.name, .status, (.conclusion // "")] | @tsv' > "${TMP}/checks" \
    || die "could not read ${SHA:0:12}'s check runs."
catalog_py checks < "${TMP}/checks" 2> "${TMP}/why" \
    || die "${SHA:0:12}: $(cat "${TMP}/why"). Re-run once its checks have passed; nothing was signed."

# 6. What is being signed.
echo "================================================================================"
echo "Signing the add-on catalog of ${BRANCH} ${SHA}"
cat "${TMP}/review"
echo "================================================================================"
if [[ "${YES}" -eq 1 ]]; then
    echo "--yes given (stdin is not a terminal): signing without the typed confirmation."
else
    printf 'Type the first 12 characters of the commit id to sign its catalog: '
    ANSWER=""
    read -r ANSWER || ANSWER=""
    [[ "${ANSWER}" = "${SHA:0:12}" ]] || die "'${ANSWER}' does not match ${SHA:0:12}; nothing was signed."
fi

# 7. Sign the exact bytes, then check them as a panel will.
ssh-keygen -q -Y sign -f "${KEY}" -n "${NS}" "${TMP}/catalog.json" >/dev/null 2>&1 \
    || die "ssh-keygen could not sign with ${KEY}."
[[ -s "${TMP}/catalog.json.sig" ]] || die "ssh-keygen wrote no signature."
verify "${TMP}/catalog.json" "${TMP}/catalog.json.sig" \
    || die "the signature does not verify against release-signers; is ${KEY} the release key?"

# 8. Published through a private index: the caller's work tree, index and HEAD are not touched.
export GIT_INDEX_FILE="${TMP}/index"
if [[ -n "${PARENT}" ]]; then git read-tree "${PARENT}"; else git read-tree --empty; fi
CBLOB="$(git hash-object -w "${TMP}/catalog.json")"
SBLOB="$(git hash-object -w "${TMP}/catalog.json.sig")"
OBLOB="$(printf '%s %s\n' "${BRANCH}" "${SHA}" | git hash-object -w --stdin)"
for name in "${SEQ}" latest; do
    git update-index --add --cacheinfo "100644,${CBLOB},catalog/${name}.json"
    git update-index --add --cacheinfo "100644,${SBLOB},catalog/${name}.json.sig"
    git update-index --add --cacheinfo "100644,${OBLOB},catalog/${name}.source"
done
TREE="$(git write-tree)"
PARGS=()
[[ -z "${PARENT}" ]] || PARGS=(-p "${PARENT}")
COMMIT="$(git commit-tree -S "${PARGS[@]}" -m "Add-on catalog ${SEQ}: ${BRANCH} ${SHA}" "${TREE}")"
unset GIT_INDEX_FILE
git push --quiet "${REMOTE}" "${COMMIT}:refs/heads/${SIG_BRANCH}" \
    || die "could not push ${SIG_BRANCH} (it may have moved: re-run)."
echo "sign-catalog: published add-on catalog ${SEQ} from ${BRANCH} ${SHA:0:12} and pushed ${SIG_BRANCH} (${COMMIT:0:10})."
