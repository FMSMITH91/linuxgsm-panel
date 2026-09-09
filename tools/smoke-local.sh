#!/usr/bin/env bash
# Run the smoke (or rbac) suite on THIS machine without the two things that normally make that a
# bad idea:
#
#   1. sudo. Booting the real app makes several page renders probe host state, and on a machine
#      without passwordless sudo every probe is an auth failure counted by pam_faillock — enough
#      runs in one session will lock you out of sudo on your own workstation. tools/nosudo_runner.py
#      refuses those commands at the local-exec choke points instead, which is exactly the code path
#      an unprivileged production install takes. Check with: faillock --user "$USER"
#
#   2. Your data/ dir. Both suites refuse to run when data/panel.db exists (they will not touch a
#      real install), so this copies the WORKING TREE — your uncommitted edits included — into a
#      throwaway dir that has no data/ at all, and runs there. Nothing under the repo is written.
#
#   ./tools/smoke-local.sh                     # tests/smoke_test.py
#   ./tools/smoke-local.sh tests/rbac_test.py
set -euo pipefail
cd "$(dirname "$0")/.."
SUITE="${1:-tests/smoke_test.py}"
PY="$(cd "$(dirname "${PYTHON:-./.venv/bin/python}")" && pwd)/$(basename "${PYTHON:-./.venv/bin/python}")"
[ -x "$PY" ] || { echo "no interpreter at $PY (set PYTHON=)" >&2; exit 1; }

WORK="$(mktemp -d -t lgsm-smoke-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
# --others --exclude-standard: new, not-yet-committed files count too (a suite you just
# added is the usual reason to run this), while everything in .gitignore stays out.
git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf - | tar -xf - -C "$WORK"
echo "== $SUITE (throwaway tree: $WORK, no sudo) =="
cd "$WORK"
# Tee so a SKIP can be detected. Both suites bail out with "SKIP: ... already exists" and exit 0
# when they find a database, so anything that creates one before their guard runs turns the whole
# run into a silent pass that tested nothing. That has already happened once (the runner used to
# import `manage`, which builds the DB on import). Make it loud instead.
set -o pipefail
"$PY" tools/nosudo_runner.py "$SUITE" 2>&1 | tee "$WORK/.run.log"
rc=$?
if grep -q "^SKIP:" "$WORK/.run.log"; then
    echo "" >&2
    echo "ERROR: the suite SKIPPED — it never ran. Something created data/ in the throwaway tree" >&2
    echo "       before the suite's own guard. Nothing above was verified." >&2
    exit 1
fi
exit "$rc"
