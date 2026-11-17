#!/usr/bin/env bash
# Sign a release: tools/sign-release.sh [--yes] <full commit id> [branch]   (branch defaults to main)
#
# A panel installs an update only when the commit carries a signature made with the release SSH
# key (install.sh, "Release signatures"). GitHub signs every squash merge with its own key, which
# proves nothing against someone holding the GitHub account; the release key is kept off GitHub.
# Run this where that key is, once a merged commit's checks have passed.
#
# What it does, in order, and it stops at the first thing that is not right:
#   1. fetches <branch> by its full name and refuses unless <sha> is a full commit id on its
#      FIRST-PARENT line (the commits the branch itself has been at);
#   2. shows what you are about to sign: every first-parent commit since the newest one already
#      signed (with its author and committer), the files changed, and a loud WARNING for any change
#      to the workflows, release-signers, install.sh or tools/panel-helper. Then it asks you to
#      type the first 12 characters of the commit id. --yes skips the typing only when stdin is
#      not a terminal (a script), and still prints all of it. The signature says only that you
#      ran this: read what it shows before you type;
#   2b. builds the message every host builds for itself, and signs it with ssh-keygen -Y sign
#      (namespace linuxgsm-panel-release) using SIGN_RELEASE_KEY (default ~/.ssh/id_ed25519_signing);
#   3. verifies that signature against the repository's release-signers, as a host would;
#   4. commits <branch>/<sha>.sig to the branch release-signatures (created, with no history, when
#      it does not exist yet), through a private index: your checkout, its index and HEAD are not
#      touched. The commit is signed like any other (git commit-tree -S);
#   5. pushes that branch, and for main starts the deploy of <sha> (gh workflow run deploy.yml),
#      unless <sha> itself changes only paths CI does not run for (ci.yml's paths-ignore): its
#      deploy would wait 20 minutes for checks that never come, and then fail.
#
#   6. for main, publishes a GitHub Release of <sha>: tag YYYY.M.D (the commit's date in UTC; .2, .3
#      for a later release the same day), the CHANGELOG entries it added as the notes (the same
#      entries a panel's "What's new" shows), and the signature and an SBOM attached (CycloneDX JSON
#      of the packages the commit's lockfiles pin, tools/sbom.py). A release that already
#      exists is left alone. A failure here is reported, never fatal: the signature is already pushed.
#
# Environment: SIGN_RELEASE_REMOTE (default origin), SIGN_RELEASE_KEY, SIGN_RELEASE_NO_DEPLOY=1 to
# skip step 5's deploy and step 6's release, SIGN_RELEASE_NO_RELEASE=1 to skip only the release,
# SIGN_RELEASE_GH (default gh) for the GitHub CLI command.
set -euo pipefail
export LC_ALL=C.UTF-8 LANG=C.UTF-8 LANGUAGE=

NS="linuxgsm-panel-release"
SIG_BRANCH="release-signatures"
die() { echo "sign-release: $*" >&2; exit 1; }

YES=0
ARGS=()
for a in "$@"; do
    if [[ "${a}" = "--yes" ]]; then YES=1; else ARGS+=("${a}"); fi
done
[[ ${#ARGS[@]} -ge 1 && ${#ARGS[@]} -le 2 ]] || die "usage: tools/sign-release.sh [--yes] <full commit id> [branch]"
SHA="${ARGS[0]}"
BRANCH="${ARGS[1]:-main}"
# --yes is for a script feeding this, never for a person at a terminal: a person types the id.
if [[ "${YES}" -eq 1 ]] && [[ -t 0 ]]; then
    die "--yes is refused at a terminal: run without it and type the commit id when asked."
fi
REMOTE="${SIGN_RELEASE_REMOTE:-origin}"
read -ra GH <<< "${SIGN_RELEASE_GH:-gh}"
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# 1b. The signatures branch now, so the review below can start at the last signed release.
PARENT=""
if git fetch --quiet --no-tags "${REMOTE}" "+refs/heads/${SIG_BRANCH}:${SIGTRACK}" 2>/dev/null \
   && git show-ref --verify --quiet "${SIGTRACK}"; then
    PARENT="$(git rev-parse --verify "${SIGTRACK}^{commit}")"
fi

# 2. What is being signed. BASE is the newest commit below SHA on the branch's first-parent line
#    that already has a signature; with none, this is the first release and the whole line shows.
BASE=""
if [[ -n "${PARENT}" ]]; then
    while read -r c; do
        if git cat-file -e "${PARENT}:${BRANCH}/${c}.sig" 2>/dev/null; then BASE="${c}"; break; fi
    done < <(git rev-list --first-parent "${SHA}^" 2>/dev/null || true)
fi
EMPTY_TREE="$(git hash-object -t tree /dev/null)"
echo "================================================================================"
if [[ -n "${BASE}" ]]; then
    echo "Signing ${BRANCH} ${SHA}"
    echo "Changes since the last signed release ${BASE}:"
    RANGE="${BASE}..${SHA}"; FROM="${BASE}"
else
    echo "Signing ${BRANCH} ${SHA} -- NO earlier signed release: everything up to it is new."
    RANGE="${SHA}"; FROM="${EMPTY_TREE}"
fi
echo "--------------------------------------------------------------------------------"
# git stops at 200 itself: `git log | head -n 200` under pipefail killed the script with SIGPIPE
# (exit 141) whenever there were more, as on the first release, which lists all of history.
git --no-pager log --first-parent --max-count=200 \
    --format='%h  author: %an <%ae>  committer: %cn  %s' "${RANGE}"
N_COMMITS="$(git rev-list --first-parent --count "${RANGE}")"
(( N_COMMITS > 200 )) && echo "... and $(( N_COMMITS - 200 )) older commits (${N_COMMITS} in all)"
echo "--------------------------------------------------------------------------------"
git --no-pager diff --stat=120 "${FROM}" "${SHA}" | tail -n 60
# Every file root installs from a signed release and runs (install.sh's stage_root_source callers:
# the helper, the release key, db_maintenance.py, the installer, recover.sh, uninstall.sh and
# gamedig's three files), and CI's workflows and the scripts they run. A unit check holds this list
# equal to those callers: the db_maintenance.py root runs at every update showed up only as a
# --stat line among many.
FLAGGED="$(git diff --name-only "${FROM}" "${SHA}" \
           | grep -E '^(\.github/workflows/|\.github/scripts/|release-signers$|install\.sh$|tools/panel-helper$|db_maintenance\.py$|recover\.sh$|uninstall\.sh$|panel/install/release-signers$|panel/install/db_maintenance\.py$|panel/install/recover\.sh$|panel/install/uninstall\.sh$|tools/gamedig/)' || true)"
if [[ -n "${FLAGGED}" ]]; then
    echo "################################################################################"
    echo "!!! WARNING: this release changes what runs as root, the release key, or CI:"
    while IFS= read -r f; do printf '!!!     %s\n' "${f}"; done <<< "${FLAGGED}"
    echo "!!! Read these diffs (git diff ${FROM:0:12} ${SHA:0:12} -- <file>) before you sign."
    echo "################################################################################"
fi
echo "================================================================================"
if [[ "${YES}" -eq 1 ]]; then
    echo "--yes given (stdin is not a terminal): signing without the typed confirmation."
else
    printf 'Type the first 12 characters of the commit id to sign it: '
    ANSWER=""
    read -r ANSWER || ANSWER=""
    [[ "${ANSWER}" = "${SHA:0:12}" ]] || die "'${ANSWER}' does not match ${SHA:0:12}; nothing was signed."
fi

# 2. The message, exactly as install.sh's _release_message builds it.
printf 'linuxgsm-panel release\nbranch %s\ncommit %s\n' "${BRANCH}" "${SHA}" > "${TMP}/msg"
ssh-keygen -q -Y sign -f "${KEY}" -n "${NS}" "${TMP}/msg" >/dev/null 2>&1 \
    || die "ssh-keygen could not sign with ${KEY}."
[[ -s "${TMP}/msg.sig" ]] || die "ssh-keygen wrote no signature."

# 3. Checked against the key the hosts that will install it hold: the one the commit's PARENT
#    carries, which is what a host on the previous release trusts. So a release that rotates the
#    key is signed with the old one. The first release that has the file has no parent copy, and
#    is checked against its own.
#    The file is in panel/install/, or at the root in a commit from before the root clean-up.
signers_at() {   # signers_at <commit>: that commit's release-signers, wherever it keeps it
    git cat-file blob "$1:panel/install/release-signers" 2>/dev/null \
        || git cat-file blob "$1:release-signers" 2>/dev/null
}
if git cat-file -e "${SHA}^1" 2>/dev/null && signers_at "${SHA}^1" > "${TMP}/signers"; then
    :
else
    signers_at "${SHA}" > "${TMP}/signers" \
        || die "${SHA} has no release-signers to check the signature against."
fi
ssh-keygen -Y verify -f "${TMP}/signers" -I release -n "${NS}" -s "${TMP}/msg.sig" \
    < "${TMP}/msg" >/dev/null 2>&1 \
    || die "the signature does not verify against release-signers; is ${KEY} the release key?"

release_tag() {    # release_tag <commit> <remote>: YYYY.M.D, or .2, .3... when that tag is another commit's
    local base tag at n=1
    base="$(TZ=UTC git show -s --format=%cd --date=format-local:%Y.%-m.%-d "$1")" || return 1
    tag="${base}"
    while at="$(git ls-remote --tags "$2" "refs/tags/${tag}" "refs/tags/${tag}^{}" | awk '{print $1}' | tail -n 1)" \
          && [[ -n "${at}" ]] && [[ "${at}" != "$1" ]]; do
        n=$(( n + 1 )); tag="${base}.${n}"
    done
    printf '%s\n' "${tag}"
}
# The release's name (main only), saved beside its signature as <branch>/<sha>.name, so a panel
# shows the name its GitHub Release carries (2026.11.16.5) and not only the commit's date. A name
# that cannot be read is left out: the panel then shows the date, and the signing goes on.
# Whether a panel would be offered this commit as an update: it changes a file a panel runs, by the
# panel's own rule (system_ops._path_class with the commit's .github/update-paths.txt). Only such a
# commit gets a GitHub Release page; one that changes only docs, tests or tooling is still signed
# (panels install only signed commits) but publishes none. Fails safe: anything that cannot be
# judged -- no venv, no rules file, an error -- counts as reaching panels, so a release is published.
reaches_panels() {
    local py="${TOOLS_DIR}/../.venv/bin/python" rules files
    # The checkout's venv, else the interpreter named by PYTHON (the suites run with it), else python3.
    [[ -x "${py}" ]] || py="${PYTHON:-$(command -v python3)}"
    [[ -n "${py}" ]] || return 0
    rules="$(git show "$1:.github/update-paths.txt" 2>/dev/null)" || return 0
    files="$(git diff --no-renames --name-only "$1^1" "$1" -- 2>/dev/null)" || return 0
    [[ -n "${files}" ]] || return 1
    printf '%s\n' "${files}" | (cd "${TOOLS_DIR}/.." && "${py}" -c '
import sys
sys.path.insert(0, ".")
try:
    from panel.ops.system_ops import _parse_update_paths, _path_class
    rules = _parse_update_paths(sys.argv[1]) or None
    sys.exit(0 if any(_path_class(f, rules) != "noise" for f in sys.stdin.read().split() if f) else 1)
except SystemExit:
    raise
except Exception:
    sys.exit(0)
' "${rules}" 2>/dev/null)
}
NAME=""
# Only a commit panels are offered gets a name: no release page means no tag, so a name saved for a
# docs-only commit would be taken again by the next release of that day.
if [[ "${BRANCH}" = "main" ]] && reaches_panels "${SHA}"; then
    NAME="$(release_tag "${SHA}" "${REMOTE}" 2>/dev/null)" || NAME=""
    [[ "${NAME}" =~ ^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,2}(\.[0-9]{1,3})?$ ]] || NAME=""
fi

# 4. The commit on release-signatures (PARENT, fetched at 1b), through a private index
#    (GIT_INDEX_FILE): read-tree, update-index, write-tree and commit-tree never look at the
#    caller's work tree or HEAD.
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
    if [[ -n "${NAME}" ]]; then
        NBLOB="$(printf '%s\n' "${NAME}" | git hash-object -w --stdin)"
        git update-index --add --cacheinfo "100644,${NBLOB},${BRANCH}/${SHA}.name"
    fi
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

# 6. The GitHub Release.
changelog_at() {   # changelog_at <commit>: that commit's CHANGELOG, from docs/ or the root
    git cat-file blob "$1:docs/CHANGELOG.md" 2>/dev/null || git cat-file blob "$1:CHANGELOG.md" 2>/dev/null
}
sbom_at() {   # sbom_at <commit> <tag>: the CycloneDX SBOM of that commit's lockfiles, on stdout
    local f
    for f in panel/install/requirements.txt panel/install/requirements.in tools/gamedig/package-lock.json; do
        git cat-file blob "$1:${f}" 2>/dev/null || :
        [[ "${f}" = tools/gamedig/package-lock.json ]] || printf '\0'
    done | python3 "${TOOLS_DIR}/sbom.py" "$1" "$2" \
        "$(TZ=UTC git show -s --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ "$1")"
}
publish_release() {   # publish_release <commit> <previous signed commit or ""> <signature file>
    local tag
    # The name saved beside the signature, so the release and the panel say the same.
    tag="${NAME}"
    [[ -n "${tag}" ]] || tag="$(release_tag "$1" "${REMOTE}")" \
        || { echo "sign-release: could not name the release." >&2; return 1; }
    if "${GH[@]}" release view "${tag}" >/dev/null 2>&1; then
        echo "sign-release: release ${tag} already exists; left as it is."
        return 0
    fi
    # The two changelogs go in on stdin, the previous release's first, split by a NUL (which no
    # changelog holds); none for the previous one on the first release.
    { if [[ -n "$2" ]]; then changelog_at "$2" || :; fi; printf '\0'; changelog_at "$1" || :; } \
        | python3 "${TOOLS_DIR}/release_notes.py" "$1" "${tag}" > "${TMP}/notes.md" \
        || { echo "sign-release: could not write the release notes." >&2; return 1; }
    cp "$3" "${TMP}/linuxgsm-panel-${tag}.sig"
    local assets=("${TMP}/linuxgsm-panel-${tag}.sig")
    # The SBOM (CycloneDX JSON) of what this commit installs, from its own lockfiles; a release
    # without one is still published, and says so.
    if sbom_at "$1" "${tag}" > "${TMP}/linuxgsm-panel-${tag}.cdx.json"; then
        assets+=("${TMP}/linuxgsm-panel-${tag}.cdx.json")
    else
        echo "sign-release: could not write the SBOM; the release has none." >&2
    fi
    "${GH[@]}" release create "${tag}" --target "$1" --title "${tag}" --notes-file "${TMP}/notes.md" \
        "${assets[@]}" >/dev/null \
        || { echo "sign-release: could not create the GitHub release ${tag}." >&2; return 1; }
    echo "sign-release: published GitHub release ${tag}."
}
if [[ "${BRANCH}" = "main" ]] && [[ "${SIGN_RELEASE_NO_DEPLOY:-}" != "1" ]] \
   && [[ "${SIGN_RELEASE_NO_RELEASE:-}" != "1" ]] && ! reaches_panels "${SHA}"; then
    echo "sign-release: ${SHA:0:12} changes nothing a panel runs (docs, tests or tooling): signed, no release page."
elif [[ "${BRANCH}" = "main" ]] && [[ "${SIGN_RELEASE_NO_DEPLOY:-}" != "1" ]] \
   && [[ "${SIGN_RELEASE_NO_RELEASE:-}" != "1" ]]; then
    if command -v "${GH[0]}" >/dev/null 2>&1; then
        publish_release "${SHA}" "${BASE}" "${TMP}/msg.sig" \
            || echo "sign-release: the signature is pushed; publish the release later by re-running this." >&2
    else
        echo "sign-release: ${GH[0]} is not installed; no GitHub release was published." >&2
    fi
fi

# A commit that changes only what ci.yml's paths-ignore lists ('**/*.md', 'docs/**', LICENSE,
# .gitignore, .editorconfig; system_ops._ci_path_ignored reads the same list) gets no CI or CodeQL
# run, so the deploy's verify step, which waits for their checks on this exact commit, could only
# time out. A root commit, or a diff git cannot produce, counts as code.
ci_ignored_only() {
    local changed
    changed="$(git diff --name-only "$1^1" "$1" -- 2>/dev/null)" || return 1
    [[ -n "${changed}" ]] || return 1
    ! grep -qvE '(\.md$|^docs/|^LICENSE$|^\.gitignore$|^\.editorconfig$)' <<< "${changed}"
}

if [[ "${BRANCH}" = "main" ]] && [[ "${SIGN_RELEASE_NO_DEPLOY:-}" != "1" ]] && ci_ignored_only "${SHA}"; then
    echo "sign-release: ${SHA:0:12} changes only documentation, which CI does not run for, so no deploy was started."
elif [[ "${BRANCH}" = "main" ]] && [[ "${SIGN_RELEASE_NO_DEPLOY:-}" != "1" ]]; then
    if command -v "${GH[0]}" >/dev/null 2>&1; then
        "${GH[@]}" workflow run deploy.yml --ref main -f sha="${SHA}" \
            || echo "sign-release: could not start the deploy; run: gh workflow run deploy.yml --ref main -f sha=${SHA}" >&2
    else
        echo "sign-release: gh is not installed; start the deploy with: gh workflow run deploy.yml --ref main -f sha=${SHA}" >&2
    fi
fi
