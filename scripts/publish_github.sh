#!/usr/bin/env bash
# Run locally with your own GitHub authentication. No token is accepted here.
set -euo pipefail
REPO="tosnetwork/tos-secure-custody"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "${1:-}" in
  --public|--private) VISIBILITY="$1" ;;
  *) echo "Usage: bash scripts/publish_github.sh --public|--private" >&2; exit 2 ;;
esac
cd "$ROOT"
command -v gh >/dev/null || { echo "Install GitHub CLI and run gh auth login first." >&2; exit 2; }
gh auth status >/dev/null 2>&1 || { echo "Run gh auth login with repository-creation access to tosnetwork." >&2; exit 2; }
if [[ -e .git ]]; then
  echo "Refusing to initialize over an existing Git repository. Publish it manually after reviewing remotes." >&2
  exit 2
fi
if gh repo view "$REPO" >/dev/null 2>&1; then
  echo "$REPO already exists. Refusing to overwrite it." >&2
  exit 2
fi
# Verify a distributed bundle before making any local changes.
if [[ -f SOURCE-MANIFEST.json ]]; then
  python3 scripts/verify_source_manifest.py
fi
# Refuse accidental secret, cache, or unexpected file inclusion.
python3 scripts/source_bundle.py --output dist/prepublication-source.tar
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/check_release_readiness.py --expect-blocked
if ! git var GIT_AUTHOR_IDENT >/dev/null 2>&1; then
  echo "Configure your Git author name and email before publishing." >&2
  exit 2
fi
git init --initial-branch=main
git add .
git diff --cached --check
git commit -m "Bootstrap TOS Secure Custody: specifications and fail-closed reference core"
# This creates a new repository only; it never force-pushes or modifies tosnetwork/tos.
gh repo create "$REPO" "$VISIBILITY" --source=. --remote=origin --push \
  --description "Open and verifiable custody infrastructure for TOS. Experimental; production signing disabled."
printf '\nPublished source to %s. Run python3 scripts/publish_issues.py to create the tracked workstreams.\n' "$REPO"
