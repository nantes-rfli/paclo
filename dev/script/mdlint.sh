#!/usr/bin/env bash
set -euo pipefail

# Run markdownlint-cli2 via npx (no local deps). Requires network on first run.
# Usage: dev/script/mdlint.sh [--fix] [paths...]
# If no paths, lint current and historical documentation, including archives.

fix_flag=""
if [ "${1:-}" = "--fix" ]; then
  fix_flag="--fix"
  shift
fi

paths=("$@")
if [ ${#paths[@]} -eq 0 ]; then
  paths+=(README.md CHANGELOG.md AGENTS.md CONTRIBUTING.md)
  while IFS= read -r -d '' path; do paths+=("$path"); done < <(
    find docs -type f -name '*.md' -print0
  )
  while IFS= read -r -d '' path; do paths+=("$path"); done < <(
    find dev -maxdepth 2 -type f -name '*.md' -print0
  )
fi

if [ ${#paths[@]} -eq 0 ]; then
  echo "[mdlint] No markdown files found; skipping." >&2
  exit 0
fi

echo "[mdlint] Linting: ${paths[*]}"
npx --yes markdownlint-cli2@0.18.1 $fix_flag "${paths[@]}"
