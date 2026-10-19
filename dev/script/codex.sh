#!/usr/bin/env bash
set -euo pipefail

# One entry point for local and managed-cloud development. No system installs,
# credentials, network policy changes, or tracked-file edits are performed here.
paclo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$paclo_root"

usage() {
  cat <<'USAGE'
Usage: bash dev/script/codex.sh COMMAND [ARGS...]
  doctor      Check Java/Clojure versions, native libpcap, and optional tools
  prepare     Resolve development dependencies and compile Java sources/tests
  tools       Install pinned lint binaries locally (Linux x86_64)
  smoke       Check offline PCAP I/O, decoding, and the DNS extension
  test        Compile Java bindings and run Clojure tests (runner args allowed)
  java-test   Compile Java bindings/tests and run JUnit
  check       Run Java tests, all Clojure tests, and the offline smoke check
  lint        Run clj-kondo, Eastwood, format dry-runs, and Markdown lint
  perf        Run the existing offline performance gate
  package     Build the JAR (deletes and recreates target/)
  repl        Start a terminal REPL with development and DNS namespaces available
  help        Show this help

PACLO_ENV_ACTIVATE may name an activation script. If unset, the existing
/workspace/.paclo-env/activate.sh is used when present. Set it to an empty
string to use only the current shell environment.
USAGE
}

paclo_command="${1:-help}"
if [[ $# -gt 0 ]]; then shift; fi
case "$paclo_command" in
  help|-h|--help) usage; exit 0 ;;
  doctor|prepare|tools|smoke|test|java-test|check|lint|perf|package|repl) ;;
  *) usage >&2; exit 2 ;;
esac
if [[ "$paclo_command" != test && $# -gt 0 ]]; then
  echo "Only test accepts additional arguments." >&2
  exit 2
fi

paclo_activate="${PACLO_ENV_ACTIVATE-/workspace/.paclo-env/activate.sh}"
if [[ -n "$paclo_activate" && -f "$paclo_activate" ]]; then
  # shellcheck source=/dev/null
  source "$paclo_activate"
elif [[ -n "${PACLO_ENV_ACTIVATE:-}" ]]; then
  echo "Activation script not found: $PACLO_ENV_ACTIVATE" >&2
  exit 1
fi

export PATH="$paclo_root/.dev-tools/bin:$PATH"

if [[ "$paclo_command" == tools ]]; then
  exec bash dev/script/setup-lint-tools.sh
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing command: $1. See CONTRIBUTING.md." >&2
    exit 1
  fi
}

require_command java
require_command javac
require_command clojure

compile_java() { clojure -T:build javac; }
java_tests() {
  clojure -T:build javac-test
  clojure -T:build junit
}
smoke() {
  clojure -M:dev:dns-ext -m paclo.dev.environment-check smoke
}

case "$paclo_command" in
  doctor)
    echo "Paclo reference Clojure CLI: 1.12.5.1664 (library version is set by deps.edn)"
    java -version
    javac -version
    clojure -Sdescribe
    compile_java
    clojure -M:dev:dns-ext -m paclo.dev.environment-check doctor
    for paclo_tool in clj-kondo clojure-lsp npx; do
      if command -v "$paclo_tool" >/dev/null 2>&1; then
        echo "Optional tool available: $paclo_tool"
      else
        echo "Optional tool missing: $paclo_tool (needed for lint)"
      fi
    done
    ;;
  prepare)
    clojure -P -M:dev:test:dns-ext:junit
    compile_java
    clojure -T:build javac-test
    ;;
  smoke) compile_java; smoke ;;
  test) compile_java; clojure -M:test "$@" ;;
  java-test) compile_java; java_tests ;;
  check) compile_java; java_tests; clojure -M:test; smoke ;;
  lint)
    require_command clj-kondo
    require_command clojure-lsp
    require_command npx
    compile_java
    clj-kondo --lint src test dev extensions/dns/src
    clojure -M:eastwood
    clojure-lsp clean-ns --dry
    clojure-lsp format --dry
    bash dev/script/mdlint.sh
    ;;
  perf) compile_java; clojure -M:perf-gate ;;
  package) clojure -T:build jar ;;
  repl) compile_java; exec clojure -M:dev:dns-ext ;;
esac
