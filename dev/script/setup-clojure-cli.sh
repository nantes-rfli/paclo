#!/usr/bin/env bash
set -euo pipefail

# Optional, unprivileged Linux/macOS installation. Select it explicitly via PATH.
if [[ $# != 1 || "$1" != /* ]]; then
  echo "Usage: bash dev/script/setup-clojure-cli.sh /absolute/install/prefix" >&2
  exit 2
fi
paclo_prefix="$1"
if [[ -e "$paclo_prefix" ]]; then
  echo "Install prefix already exists: $paclo_prefix" >&2
  exit 1
fi
paclo_cli_version=1.12.5.1664
# Official posix-install-1.12.5.1664.sh archive checksum.
paclo_cli_sha=77dd6868948074adcc93e83a796f8e8f15a1a92bcb1b9002d715fd2210e476f3
paclo_tmp="$(mktemp -d)"
trap 'rm -rf "$paclo_tmp"' EXIT
curl -fSL --retry 5 --connect-timeout 5 --max-time 120 \
  "https://download.clojure.org/install/clojure-tools-$paclo_cli_version.tar.gz" \
  -o "$paclo_tmp/tools.tar.gz"
python3 - "$paclo_tmp/tools.tar.gz" "$paclo_cli_sha" <<'PY'
import hashlib
from pathlib import Path
import sys
if hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit("Clojure CLI archive checksum mismatch")
PY
tar xzf "$paclo_tmp/tools.tar.gz" -C "$paclo_tmp"
python3 - "$paclo_tmp/clojure-tools" "$paclo_prefix" "$paclo_cli_version" <<'PY'
from pathlib import Path
import shutil
import sys
source, prefix = map(Path, sys.argv[1:3])
lib = prefix / "lib/clojure"
(lib / "libexec").mkdir(parents=True)
(prefix / "bin").mkdir()
man = prefix / "share/man/man1"
man.mkdir(parents=True)
for name in ("deps.edn", "example-deps.edn", "tools.edn"):
    shutil.copy2(source / name, lib / name)
for name in ("exec.jar", f"clojure-tools-{sys.argv[3]}.jar"):
    shutil.copy2(source / name, lib / "libexec" / name)
for name in ("clojure", "clj"):
    target = prefix / "bin" / name
    target.write_text((source / name).read_text().replace("PREFIX", str(lib))
                      .replace("BINDIR", str(prefix / "bin")))
    target.chmod(0o755)
    shutil.copy2(source / f"{name}.1", man / f"{name}.1")
PY
"$paclo_prefix/bin/clojure" -Sdescribe
