#!/usr/bin/env bash
# Push Sentinel Stream repo to GitHub.
# Usage:
#   ./scripts/push-to-github.sh <github-url>
# Examples:
#   ./scripts/push-to-github.sh https://github.com/myteam/sentinel-stream.git
#   ./scripts/push-to-github.sh git@github.com:myteam/sentinel-stream.git
#
# For HTTPS URLs with a personal access token:
#   GH_TOKEN=ghp_xxxx ./scripts/push-to-github.sh https://github.com/myteam/sentinel-stream.git

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <github-url>" >&2
  exit 1
fi

REPO_URL="$1"
cd "$(git rev-parse --show-toplevel)"

# Inject token into HTTPS URL if provided
if [[ -n "${GH_TOKEN:-}" ]] && [[ "$REPO_URL" == https://github.com/* ]]; then
  REPO_URL="https://x-access-token:${GH_TOKEN}@${REPO_URL#https://}"
fi

# Configure git identity if missing
git config user.name 2>/dev/null || git config user.name "Sentinel Stream Team"
git config user.email 2>/dev/null || git config user.email "team@sentinel-stream.io"

# Set remote (add or update)
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REPO_URL"
  echo "Updated origin → $1"
else
  git remote add origin "$REPO_URL"
  echo "Added origin → $1"
fi

# Push
echo "Pushing to origin/main..."
git push -u origin main

echo ""
echo "✓ Push complete. Repo live at: $1"
echo ""
echo "Next: open the repo URL in a browser and verify the README renders."
