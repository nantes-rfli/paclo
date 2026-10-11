#!/usr/bin/env bash
set -euo pipefail

# Run markdownlint-cli2 via npx (no local deps). Requires network on first run.
# Usage: dev/script/mdlint.sh [--fix] [paths...]
# If no paths, lint maintained public docs and Codex development instructions.

fix_flag=""
if [ "${1:-}" = "--fix" ]; then
  fix_flag="--fix"
  shift
fi

paths=("$@")
if [ ${#paths[@]} -eq 0 ]; then
  if ls README.md >/dev/null 2>&1; then
    paths+=(README.md)
  fi
  if ls docs/*.md >/dev/null 2>&1; then
    paths+=(docs/*.md)
  fi
  paths+=(AGENTS.md CONTRIBUTING.md dev/codex-plan.md dev/codex-environment-validation.md)
fi

if [ ${#paths[@]} -eq 0 ]; then
  echo "[mdlint] No markdown files found; skipping." >&2
  exit 0
fi

echo "[mdlint] Linting: ${paths[*]}"
# --config is auto-detected (.markdownlint.jsonc)
npx --yes markdownlint-cli2@0.18.1 $fix_flag "${paths[@]}"
