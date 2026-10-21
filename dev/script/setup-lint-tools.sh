#!/usr/bin/env bash
set -euo pipefail

# Native upstream distributions; pins are shared with CI through this installer.
paclo_kondo_version=2026.10.20
paclo_lsp_version=2026.10.15-11.42.38
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    paclo_platform=linux-amd64
    paclo_kondo_sha=cfc093e177d0e4619ae7bf9d5acd8f0ea43e7bb18dae9d64c1fa9fbcd3832681
    paclo_lsp_sha=d68acf630465cec9d3685fd958f914d9228d90a07222edd301f1a4740b8e8b76
    ;;
  Linux/aarch64)
    paclo_platform=linux-aarch64
    paclo_kondo_sha=8231f5a039dfa4d6c255a25ad3c1286a6a1679cd706ddbee646a6cbed4ba684c
    paclo_lsp_sha=232ac0cd191070a3b7b5532135ec9f97217b82324de7e97da0b1bf81353a3c94
    ;;
  Darwin/x86_64)
    paclo_platform=macos-amd64
    paclo_kondo_sha=4c3caabc03108d2fc9b1860ae6a140af67c791115e6c1e8eeadc7e943bf49c0f
    paclo_lsp_sha=468c261b48a7276c79cb92a82ddfce5474bc563ba6673df30cabf17a7f239ef3
    ;;
  Darwin/arm64)
    paclo_platform=macos-aarch64
    paclo_kondo_sha=675c2e508c71afe774cfa402f7959a6580a82f15c15dc935502489ff88133815
    paclo_lsp_sha=84df57e51e27f4ecf20d0cd65aab3296e2ebf28dbaacca4fe216b6cf20485716
    ;;
  *)
    echo "Unsupported lint-tool platform: $(uname -s)/$(uname -m). See CONTRIBUTING.md." >&2
    exit 1
    ;;
esac
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
  "https://github.com/clj-kondo/clj-kondo/releases/download/v$paclo_kondo_version/clj-kondo-$paclo_kondo_version-$paclo_platform.zip" \
  "$paclo_kondo_sha"
install_tool clojure-lsp \
  "https://github.com/clojure-lsp/clojure-lsp/releases/download/$paclo_lsp_version/clojure-lsp-native-$paclo_platform.zip" \
  "$paclo_lsp_sha"
