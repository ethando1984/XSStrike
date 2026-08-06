#!/usr/bin/env bash
# Install the XSStrike git hooks into this repository.
#
#   scripts/hooks/install.sh
#
# Points core.hooksPath at scripts/hooks so the versioned hooks are used
# directly (no copying, stays in sync with the repo).
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

chmod +x scripts/hooks/pre-commit
git config core.hooksPath scripts/hooks

echo "Installed XSStrike git hooks (core.hooksPath = scripts/hooks)."
echo "The pre-commit hook now runs --scan-dir on staged files."
echo
echo "Uninstall with:  git config --unset core.hooksPath"
