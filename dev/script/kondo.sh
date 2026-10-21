#!/usr/bin/env bash
set -euo pipefail

# Run clj-kondo lint. Provide a --fix flag to apply safe fixes (where supported).
# Usage: dev/script/kondo.sh [--fix] [paths...]
# Defaults to all Clojure source, test, development and build roots

fix_mode=0
if [ "${1:-}" = "--fix" ]; then
  fix_mode=1
  shift
fi

paths=("$@")
if [ ${#paths[@]} -eq 0 ]; then
  paths=(src test dev extensions/dns/src build.clj)
fi

# clj-kondo can print a configuration-read warning yet exit zero. Keep its
# original failure status and reject incomplete analysis even in that case.
paclo_output="$(mktemp "${TMPDIR:-/tmp}/paclo-kondo.XXXXXX")"
trap 'rm -f -- "$paclo_output"' EXIT

echo "[clj-kondo] Linting paths: ${paths[*]}"
if [ $fix_mode -eq 1 ]; then
  # --fix is limited to a subset of rules; still useful for imports etc.
  clj-kondo --lint "${paths[@]}" --fix 2>&1 | tee "$paclo_output"
else
  clj-kondo --lint "${paths[@]}" 2>&1 | tee "$paclo_output"
fi
if grep -q '^WARNING:' "$paclo_output"; then
  echo "clj-kondo reported incomplete analysis or configuration; refusing success." >&2
  exit 1
fi
