#!/usr/bin/env bash
# The check install.sh runs on every host after installing panel/install/requirements.txt, run over
# this job's Python: CI installs that file --no-deps as install.sh does, which turns off pip's own
# check that it is the whole closure. This runs install.sh's _pip_check_deps itself, read out of
# install.sh, so the two cannot drift: `pip check` may report only eventlet's dnspython requirement
# (panel/install/requirements.in says why dnspython is left out), and anything else fails, named.
# Then dnspython must not be importable at all: with it present, a missed EVENTLET_NO_GREENDNS would
# pass every suite here and fail only on a host.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fn="$(sed -n '/^_pip_check_deps() {$/,/^}$/p' "${root}/install.sh")"
if [[ -z "${fn}" ]]; then
    echo "::error::install.sh has no _pip_check_deps function to run."
    exit 1
fi
# shellcheck source=/dev/null
. <(printf '%s\n' "${fn}")
if ! _pip_check_deps "${PYTHON:-python}" -m pip; then
    echo "::error::pip check found the panel's requirements incomplete (see above)."
    exit 1
fi
if "${PYTHON:-python}" -c 'import dns' 2>/dev/null; then
    echo "::error::dnspython is installed in this job's Python; nothing in the panel's lockfile should bring it."
    exit 1
fi
echo "pip check: the panel's requirements are complete (eventlet's dnspython requirement aside), and dnspython is not installed."
