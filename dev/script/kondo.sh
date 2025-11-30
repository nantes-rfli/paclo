#!/usr/bin/env bash
set -euo pipefail

# Run clj-kondo lint. Provide a --fix flag to apply safe fixes (where supported).
# Usage: dev/script/kondo.sh [--fix] [paths...]
# Defaults to src test dev

fix_mode=0
if [ "${1:-}" = "--fix" ]; then
  fix_mode=1
  shift
fi

paths=("$@")
if [ ${#paths[@]} -eq 0 ]; then
  paths=(src test dev)
fi

echo "[clj-kondo] Linting paths: ${paths[*]}"
if [ $fix_mode -eq 1 ]; then
  # --fix is limited to a subset of rules; still useful for imports etc.
  clj-kondo --lint "${paths[@]}" --fix
else
  clj-kondo --lint "${paths[@]}"
fi
