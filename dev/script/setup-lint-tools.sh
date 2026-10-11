#!/usr/bin/env bash
set -euo pipefail

# Pinned Linux x86_64 tools for the managed development image. Other platforms
# should use their existing installation, following CONTRIBUTING.md and CI.
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "This installer supports Linux x86_64; see CONTRIBUTING.md for other platforms." >&2
  exit 1
fi
for paclo_tool in curl python3; do
  if ! command -v "$paclo_tool" >/dev/null 2>&1; then
    echo "Missing installer prerequisite: $paclo_tool" >&2
    exit 1
  fi
done

paclo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
paclo_stage="$(mktemp -d "${TMPDIR:-/tmp}/paclo-tools.XXXXXX")"
trap 'rm -rf -- "$paclo_stage"' EXIT
mkdir -p "$paclo_root/.dev-tools/bin"

install_tool() {
  local paclo_name="$1" paclo_url="$2" paclo_sha="$3"
  curl --fail --location --silent --show-error --retry 2 \
    "$paclo_url" -o "$paclo_stage/$paclo_name.zip"
  python3 - "$paclo_stage/$paclo_name.zip" "$paclo_sha" "$paclo_name" \
    "$paclo_root/.dev-tools/bin" <<'PY'
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import zipfile

archive, expected, name, destination = sys.argv[1:]
actual = hashlib.sha256(Path(archive).read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit(f"Checksum mismatch for {name}: {actual}")
with zipfile.ZipFile(archive) as bundle:
    payload = bundle.read(name)
target = Path(destination) / name
with tempfile.NamedTemporaryFile(dir=destination, delete=False) as staging:
    staging.write(payload)
    temp = Path(staging.name)
try:
    temp.chmod(0o755)
    os.replace(temp, target)
finally:
    temp.unlink(missing_ok=True)
PY
  "$paclo_root/.dev-tools/bin/$paclo_name" --version
}

install_tool clj-kondo \
  https://github.com/clj-kondo/clj-kondo/releases/download/v2025.10.23/clj-kondo-2025.10.23-linux-amd64.zip \
  7d3e563668ec4e8da164c78ed1a9264b5f442a2933c4934c6d0a06652bbfe494
install_tool clojure-lsp \
  https://github.com/clojure-lsp/clojure-lsp/releases/download/2025.11.28-12.47.43/clojure-lsp-native-linux-amd64.zip \
  6021378f08248c140aecaea88cc27822cc70093362b5805d27173c29dcafcd0d
