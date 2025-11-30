#!/usr/bin/env bash
set -euo pipefail

# Run markdownlint-cli2 via npx (no local deps). Requires network on first run.
# Usage: script/mdlint.sh [paths...]
# If no args, lint README.md and docs/*.md

paths=("$@")
if [ ${#paths[@]} -eq 0 ]; then
  if ls README.md >/dev/null 2>&1; then
    paths+=(README.md)
  fi
  if ls docs/*.md >/dev/null 2>&1; then
    paths+=(docs/*.md)
  fi
fi

if [ ${#paths[@]} -eq 0 ]; then
  echo "[mdlint] No markdown files found; skipping." >&2
  exit 0
fi

echo "[mdlint] Linting: ${paths[*]}"
# --config can be added later if we need custom rules
npx markdownlint-cli2 "${paths[@]}"
