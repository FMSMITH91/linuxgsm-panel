#!/usr/bin/env bash
#
# update-repo.sh — pull the currently-deployed panel code off the server into this
# git repo, commit it, and push to GitHub. Run this whenever the panel has been
# changed and you want that snapshot saved to GitHub.
#
#   Usage:   bash update-repo.sh "short message describing what changed"
#            (message is optional; a default is used if omitted)
#
# The SERVER is the source of truth (that's where the running/edited code lives).
# This script never touches secrets: data/ (DB + creds), the venv, and caches are
# excluded, and the repo's own README/.gitignore/LICENSE are kept (not overwritten).
#
set -euo pipefail

REMOTE="ubuntu@100.84.48.111"
REMOTE_DIR="/home/ubuntu/linuxgsm-panel"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
MSG="${1:-Update panel}"

cd "$REPO_DIR"

echo "==> Pulling deployed code from $REMOTE ..."
ssh "$REMOTE" "tar czf - -C '$REMOTE_DIR' \
  --exclude=./venv --exclude=./data --exclude=__pycache__ --exclude=./.git \
  --exclude='*.pyc' --exclude=./linuxgsm.sh \
  --exclude=./README.md --exclude=./.gitignore --exclude=./LICENSE \
  --exclude=./update-repo.sh --exclude=./.github ." | tar xzf -

# Safety net: make absolutely sure no secret ever gets staged.
git add -A
if git diff --cached --name-only | grep -qiE '(^|/)data/|\.db$|secret_key'; then
  echo "!! ABORTING: a secret-looking file was about to be committed:"
  git diff --cached --name-only | grep -iE '(^|/)data/|\.db$|secret_key'
  git reset -q
  exit 1
fi

if git diff --cached --quiet; then
  echo "==> No new file changes."
else
  echo "==> Changes to be committed:"
  git status --short
  git commit -q -m "$MSG"
  echo "==> Committed."
fi

# Push anything not yet on GitHub (this run's commit and/or earlier unpushed ones).
if [ -n "$(git log origin/main..main --oneline 2>/dev/null)" ]; then
  echo "==> Pushing to GitHub ..."
  git push origin main
  echo "==> Done. https://github.com/FMSMITH91/linuxgsm-panel"
else
  echo "==> Already up to date with GitHub. Nothing to push."
fi
