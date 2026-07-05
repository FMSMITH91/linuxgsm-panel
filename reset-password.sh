#!/usr/bin/env bash
# Convenience shim → the recovery tool. Resets a password (defaults to the sole
# superadmin). `recover.sh` / `linuxgsm-panel-recover` cover the rest (disable-2fa,
# create-admin, list-users, …) and can be run from anywhere.
#
#   bash reset-password.sh              # reset the ONLY superadmin
#   bash reset-password.sh <username>   # reset a specific user
set -euo pipefail
exec bash "$(dirname "$0")/recover.sh" reset-password "$@"
