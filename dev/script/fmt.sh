#!/usr/bin/env bash
set -euo pipefail
clojure-lsp clean-ns --parallel
clojure-lsp format --parallel
echo "Formatted & cleaned namespaces."
