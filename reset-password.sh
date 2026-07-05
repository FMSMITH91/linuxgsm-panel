#!/usr/bin/env bash
# Reset a panel password from the server over SSH — no web login needed.
# Handy when the (only) superadmin forgets their password right after setup.
#
#   bash reset-password.sh              # reset the ONLY superadmin (typical case)
#   bash reset-password.sh <username>   # reset a specific user
#
# You're prompted for the new password (never echoed); existing sessions are revoked.
set -euo pipefail
cd "$(dirname "$0")"

PY="./venv/bin/python"
if [ ! -x "${PY}" ]; then
    PY="$(command -v python3 || true)"
fi
[ -n "${PY}" ] || { echo "No Python found (looked for ./venv/bin/python and python3)." >&2; exit 1; }

exec "${PY}" manage.py reset-password "$@"
