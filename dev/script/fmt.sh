#!/usr/bin/env bash
set -euo pipefail
# Default remains the developer hook's formatter; --dry is the CI/local check.
if [[ $# -gt 1 || ($# -eq 1 && "$1" != --dry) ]]; then
  echo "Usage: bash dev/script/fmt.sh [--dry]" >&2
  exit 2
fi
# Validate tracked EDN before LSP can fall back from an unreadable config.
bash "$(dirname -- "${BASH_SOURCE[0]}")/kondo.sh" .clj-kondo/config.edn .lsp/config.edn
clojure-lsp clean-ns "$@"
clojure-lsp format "$@"
clojure-lsp format --filenames deps.edn,dev/nvd-clojure.edn "$@"
