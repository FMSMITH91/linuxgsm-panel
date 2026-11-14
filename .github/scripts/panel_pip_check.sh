#!/usr/bin/env bash
# The check install.sh runs on every host after installing panel/install/requirements.txt, run over
# this job's Python: CI installs that file --no-deps as install.sh does, which turns off pip's own
# check that it is the whole closure. This runs install.sh's _pip_check_deps itself, read out of
# install.sh, so the two cannot drift: `pip check` may report only the requirements that file leaves
# out on purpose (panel/install/requirements.in says why, for each), and anything else fails, named.
# Then none of what it leaves out may be installed or importable at all: with one present, code
# that started to need it would pass every suite here and fail only on a host. The names are the
# lockfile's own (--unsafe-package in its header), read by install.sh's _lock_left_out.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fn=""
for name in _pip_check_deps _lock_left_out; do
    body="$(sed -n "/^${name}() {\$/,/^}\$/p" "${root}/install.sh")"
    if [[ -z "${body}" ]]; then
        echo "::error::install.sh has no ${name} function to run."
        exit 1
    fi
    fn+="${body}"$'\n'
done
# shellcheck source=/dev/null
. <(printf '%s\n' "${fn}")
if ! _pip_check_deps "${PYTHON:-python}" -m pip; then
    echo "::error::pip check found the panel's requirements incomplete (see above)."
    exit 1
fi
mapfile -t left_out < <(_lock_left_out "${root}/panel/install/requirements.txt")
if [[ "${#left_out[@]}" -eq 0 ]]; then
    echo "::error::panel/install/requirements.txt leaves nothing out (no --unsafe-package in its header)."
    exit 1
fi
# Prints each name installed (its metadata) or importable (its module: dnspython's is dns, the
# rest are the name with - as _), and exits 0 when it printed any.
# shellcheck disable=SC2016
found="$("${PYTHON:-python}" -c '
import importlib.metadata as md, importlib.util, sys
hits = []
for name in sys.argv[1:]:
    try:
        md.distribution(name)
        hits.append(name)
    except md.PackageNotFoundError:
        try:
            spec = importlib.util.find_spec({"dnspython": "dns"}.get(name, name.replace("-", "_")))
        except (ImportError, ValueError):
            spec = None
        if spec is not None:
            hits.append(name)
print(" ".join(hits))
sys.exit(0 if hits else 1)
' "${left_out[@]}")" && {
    echo "::error::${found:-a package} is installed in this job's Python, though requirements.txt leaves it out; nothing in the panel's lockfile should bring it."
    exit 1
}
echo "pip check: the panel's requirements are complete (apart from what requirements.txt leaves out), and none of ${left_out[*]} is installed."
