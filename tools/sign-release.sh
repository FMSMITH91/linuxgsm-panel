#!/usr/bin/env bash
# Sign a release: tools/sign-release.sh <full commit id> [branch]   (branch defaults to main)
#
# A panel installs an update only when the commit carries a signature made with the owner's own
# SSH key (install.sh, "Release signatures"). GitHub signs every squash merge with its own key,
# which proves nothing against someone holding the GitHub account; this key lives only on the
# owner's PC. Run this there, once a merged commit's checks have passed.
#
# What it does, in order, and it stops at the first thing that is not right:
#   1. fetches <branch> by its full name and refuses unless <sha> is a full commit id on its
#      FIRST-PARENT line (the commits the branch itself has been at);
#   2. builds the message every host builds for itself, and signs it with ssh-keygen -Y sign
#      (namespace linuxgsm-panel-release) using SIGN_RELEASE_KEY (default ~/.ssh/id_ed25519_signing);
#   3. verifies that signature against the repository's release-signers, as a host would;
#   4. commits <branch>/<sha>.sig to the branch release-signatures (created, with no history, when
#      it does not exist yet), through a private index: your checkout, its index and HEAD are not
#      touched. The commit is signed like any other (git commit-tree -S);
#   5. pushes that branch, and for main starts the deploy of <sha> (gh workflow run deploy.yml).
#
# Environment: SIGN_RELEASE_REMOTE (default origin), SIGN_RELEASE_KEY, SIGN_RELEASE_NO_DEPLOY=1 to
# skip step 5's deploy.
set -euo pipefail
export LC_ALL=C.UTF-8 LANG=C.UTF-8 LANGUAGE=

NS="linuxgsm-panel-release"
SIG_BRANCH="release-signatures"
die() { echo "sign-release: $*" >&2; exit 1; }

[[ $# -ge 1 && $# -le 2 ]] || die "usage: tools/sign-release.sh <full commit id> [branch]"
SHA="$1"
BRANCH="${2:-main}"
REMOTE="${SIGN_RELEASE_REMOTE:-origin}"
KEY="${SIGN_RELEASE_KEY:-${HOME}/.ssh/id_ed25519_signing}"

case "${SHA}" in ""|*[!0-9a-f]*) die "'${SHA}' is not a full commit id (40 lowercase hex)." ;; esac
[[ "${#SHA}" -eq 40 ]] || die "'${SHA}' is not a full commit id (40 lowercase hex)."
# The same charset install.sh accepts for PANEL_BRANCH, and never the signatures branch itself.
printf '%s' "${BRANCH}" | grep -Eq '^[A-Za-z0-9._/-]{1,100}$' && [[ "${BRANCH#-}" = "${BRANCH}" ]] \
    && [[ "${BRANCH##*..*}" = "${BRANCH}" ]] || die "'${BRANCH}' is not a branch name install.sh accepts."
[[ "${BRANCH}" != "${SIG_BRANCH}" ]] || die "${SIG_BRANCH} holds signatures, not code."
[[ -f "${KEY}" ]] || die "no signing key at ${KEY} (set SIGN_RELEASE_KEY)."
command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen is not installed."

TRACK="refs/remotes/${REMOTE}/${BRANCH}"
SIGTRACK="refs/remotes/${REMOTE}/${SIG_BRANCH}"

# 1. On the branch's first-parent line. Fetched by full name, --no-tags: a bare name would be
#    looked up as a tag first (see install.sh, _ref_exists). Streamed through awk, compared as a
#    STRING, for the reasons install.sh's _on_first_parent_line gives.
git fetch --quiet --no-tags "${REMOTE}" "+refs/heads/${BRANCH}:${TRACK}" \
    || die "could not fetch ${BRANCH} from ${REMOTE}."
git show-ref --verify --quiet "${TRACK}" || die "${REMOTE} has no branch ${BRANCH}."
git rev-list --first-parent "${TRACK}" \
    | awk -v want="${SHA}" '($0 "") == want { found = 1 } END { exit !found }' \
    || die "${SHA} is not on ${REMOTE}/${BRANCH}'s first-parent line; nothing was signed."

TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT

# 2. The message, exactly as install.sh's _release_message builds it.
printf 'linuxgsm-panel release\nbranch %s\ncommit %s\n' "${BRANCH}" "${SHA}" > "${TMP}/msg"
ssh-keygen -q -Y sign -f "${KEY}" -n "${NS}" "${TMP}/msg" >/dev/null 2>&1 \
    || die "ssh-keygen could not sign with ${KEY}."
[[ -s "${TMP}/msg.sig" ]] || die "ssh-keygen wrote no signature."

# 3. Checked against the key the hosts that will install it hold: the one the commit's PARENT
#    carries, which is what a host on the previous release trusts. So a release that rotates the
#    key is signed with the old one. The first release that has the file has no parent copy, and
#    is checked against its own.
if git cat-file -e "${SHA}^1:release-signers" 2>/dev/null; then
    git cat-file blob "${SHA}^1:release-signers" > "${TMP}/signers"
else
    git cat-file blob "${SHA}:release-signers" > "${TMP}/signers" 2>/dev/null \
        || die "${SHA} has no release-signers to check the signature against."
fi
ssh-keygen -Y verify -f "${TMP}/signers" -I release -n "${NS}" -s "${TMP}/msg.sig" \
    < "${TMP}/msg" >/dev/null 2>&1 \
    || die "the signature does not verify against release-signers; is ${KEY} the release key?"

# 4. The commit on release-signatures, through a private index (GIT_INDEX_FILE): read-tree,
#    update-index, write-tree and commit-tree never look at the caller's work tree or HEAD.
PARENT=""
if git fetch --quiet --no-tags "${REMOTE}" "+refs/heads/${SIG_BRANCH}:${SIGTRACK}" 2>/dev/null \
   && git show-ref --verify --quiet "${SIGTRACK}"; then
    PARENT="$(git rev-parse --verify "${SIGTRACK}^{commit}")"
fi
export GIT_INDEX_FILE="${TMP}/index"
if [[ -n "${PARENT}" ]]; then
    git read-tree "${PARENT}"
    if git cat-file -e "${PARENT}:${BRANCH}/${SHA}.sig" 2>/dev/null; then
        echo "sign-release: ${BRANCH}/${SHA}.sig is already on ${SIG_BRANCH}; nothing to commit."
        PUSHED=0
    fi
else
    git read-tree --empty
fi
if [[ -z "${PUSHED:-}" ]]; then
    BLOB="$(git hash-object -w "${TMP}/msg.sig")"
    git update-index --add --cacheinfo "100644,${BLOB},${BRANCH}/${SHA}.sig"
    TREE="$(git write-tree)"
    PARGS=()
    [[ -z "${PARENT}" ]] || PARGS=(-p "${PARENT}")
    COMMIT="$(git commit-tree -S "${PARGS[@]}" -m "Release signature: ${BRANCH} ${SHA}" "${TREE}")"
    unset GIT_INDEX_FILE
    # 5. Not forced: with a parent this is a fast-forward, and a push that lost a race is refused
    #    rather than dropping someone else's signature. Re-run to retry.
    git push --quiet "${REMOTE}" "${COMMIT}:refs/heads/${SIG_BRANCH}" \
        || die "could not push ${SIG_BRANCH} (it may have moved: re-run)."
    echo "sign-release: signed ${BRANCH} ${SHA} and pushed ${SIG_BRANCH} (${COMMIT:0:10})."
fi
unset GIT_INDEX_FILE

if [[ "${BRANCH}" = "main" ]] && [[ "${SIGN_RELEASE_NO_DEPLOY:-}" != "1" ]]; then
    if command -v gh >/dev/null 2>&1; then
        gh workflow run deploy.yml --ref main -f sha="${SHA}" \
            || echo "sign-release: could not start the deploy; run: gh workflow run deploy.yml --ref main -f sha=${SHA}" >&2
    else
        echo "sign-release: gh is not installed; start the deploy with: gh workflow run deploy.yml --ref main -f sha=${SHA}" >&2
    fi
fi
