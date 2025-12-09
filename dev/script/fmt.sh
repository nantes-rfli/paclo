#!/usr/bin/env bash
set -euo pipefail
clojure-lsp clean-ns --parallel
clojure-lsp format --parallel
clojure-lsp format --filenames deps.edn,dev/nvd-clojure.edn
echo "Formatted & cleaned namespaces."
