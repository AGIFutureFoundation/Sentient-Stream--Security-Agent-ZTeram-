#!/usr/bin/env bash
# Set up Sentinel Stream on GitHub — creates repo + pushes + configures.
#
# Usage:
#   GH_TOKEN=ghp_xxxxxxxxxxxx ./scripts/setup-github.sh <github-username> [repo-name]
#
# Token needs scopes: repo, workflow (for GitHub Actions CI)
# Create one at: https://github.com/settings/tokens/new?scopes=repo,workflow

set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <github-username> [repo-name]" >&2
  echo "  GH_TOKEN env var must be set" >&2
  echo "  Create token at: https://github.com/settings/tokens/new?scopes=repo,workflow" >&2
  exit 1
fi

GITHUB_USER="$1"
REPO_NAME="${2:-sentinel-stream}"

if [[ -z "${GH_TOKEN:-}" ]]; then
  echo "Error: GH_TOKEN env var not set" >&2
  echo "Create a token at: https://github.com/settings/tokens/new?scopes=repo,workflow" >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

echo "=== 1. Authenticate gh CLI ==="
echo "$GH_TOKEN" | gh auth login --with-token 2>&1
gh auth status 2>&1

echo ""
echo "=== 2. Update README badge owner placeholder ==="
# Replace PLACEHOLDER_OWNER with the actual GitHub username
sed -i.bak "s/PLACEHOLDER_OWNER/${GITHUB_USER}/g" README.md
rm -f README.md.bak
echo "README badges updated to point to ${GITHUB_USER}/sentinel-stream"

echo ""
echo "=== 3. Commit README badge update ==="
git config user.name 2>/dev/null || git config user.name "Sentinel Stream Team"
git config user.email 2>/dev/null || git config user.email "team@sentinel-stream.io"
git add README.md
git commit -m "docs: update README badge URLs to point to ${GITHUB_USER}/sentinel-stream" 2>&1 | tail -2 || echo "(no changes to commit)"

echo ""
echo "=== 4. Create GitHub repo: $GITHUB_USER/$REPO_NAME ==="
gh repo create "$GITHUB_USER/$REPO_NAME" \
  --public \
  --description "Sentinel Stream — Real-Time Threat Detection for LLM Agents. Built at Cyberdefense Hackathon 2025 with Omega-Claw multi-agent framework + hacker-bob integration." \
  --source=. \
  --remote=origin \
  --push 2>&1 || {
    echo "Repo creation via gh failed. Trying manual approach..."
    curl -s -X POST "https://api.github.com/user/repos" \
      -H "Authorization: token $GH_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"name\":\"$REPO_NAME\",\"description\":\"Sentinel Stream — Real-Time Threat Detection for LLM Agents\",\"public\":true}" 2>&1

    git remote add origin "https://$GITHUB_USER:$GH_TOKEN@github.com/$GITHUB_USER/$REPO_NAME.git" 2>/dev/null || \
      git remote set-url origin "https://$GITHUB_USER:$GH_TOKEN@github.com/$GITHUB_USER/$REPO_NAME.git"
    git push -u origin main 2>&1
  }

echo ""
echo "=== 5. Push tags ==="
git push origin --tags 2>&1 || echo "(tag push skipped)"

echo ""
echo "=== 6. Configure repo settings ==="
gh repo edit "$GITHUB_USER/$REPO_NAME" \
  --enable-issues \
  --enable-wiki \
  --enable-discussions 2>&1 || true

echo ""
echo "=== 7. Add topics for discoverability ==="
gh repo edit "$GITHUB_USER/$REPO_NAME" \
  --add-topic cybersecurity \
  --add-topic llm-security \
  --add-topic hackathon \
  --add-topic clickhouse \
  --add-topic mcp \
  --add-topic hacker-bob \
  --add-topic prompt-injection \
  --add-topic threat-detection \
  --add-topic defensive-ai \
  --add-topic real-time-analytics 2>&1 || true

echo ""
echo "=== 8. Verify push ==="
gh repo view "$GITHUB_USER/$REPO_NAME" --json url,description,visibility,defaultBranchRef 2>&1

echo ""
echo "✅ DONE! Repo live at: https://github.com/$GITHUB_USER/$REPO_NAME"
echo ""
echo "Next steps:"
echo "  - Add teammates as collaborators:"
echo "    gh repo edit $GITHUB_USER/$REPO_NAME --add-collaborator <username>"
echo "  - Watch the CI run:"
echo "    gh run list --repo $GITHUB_USER/$REPO_NAME"
echo "  - Update demo-video/index.html and pitch-deck/index.html repo URLs"
