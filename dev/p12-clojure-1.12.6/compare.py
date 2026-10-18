#!/usr/bin/env python3
"""P12 comparison: unchanged offline workers, fixed heap, serial ABBA runtimes."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ("1.12.1", "1.12.6")
SCENARIOS = ("raw-reduce", "full-decode", "full-reduce", "flow-reduce", "write-pipeline")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "target/p12-comparison")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    classpaths = {}
    for version in VERSIONS:
        deps = '{:deps {org.clojure/clojure {:mvn/version "' + version + '"}}}'
        classpaths[version] = subprocess.check_output(
            ["clojure", "-Sdeps", deps, "-Spath", "-M:dev"], cwd=ROOT, text=True).strip()
    # No other dependency or source difference is permitted in this comparison.
    if classpaths[VERSIONS[0]].replace("1.12.1", "1.12.6") != classpaths[VERSIONS[1]]:
        raise ValueError("Comparison classpaths differ beyond the Clojure version")
    dataset = output / "mixed.pcap"
    expr = ('(require (quote [paclo.dev.perf-data :as d])) '
            '(d/ensure-dataset! ' + json.dumps(str(dataset)) +
            ' {:count 50000 :frame-size 64 :alternate-frame-size 512 :traffic :mixed})')
    subprocess.run(["clojure", "-M:dev", "-e", expr], cwd=ROOT, check=True)
    (output / "dataset.sha256").write_text(hashlib.sha256(dataset.read_bytes()).hexdigest() + "\n")
    sources = sorted((ROOT / "src").rglob("*.clj")) + sorted((ROOT / "src-java").rglob("*.java"))
    sources += sorted((ROOT / "dev/paclo/dev").glob("perf*.clj"))
    manifest = {
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_dirty": bool(subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True)),
        "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sources},
        "packets": 50000, "warmups": 5, "runs": 7,
        "runtime_order": ["1.12.1", "1.12.6", "1.12.6", "1.12.1"],
        "scenarios": SCENARIOS,
        "jvm_flags": ["-XX:-OmitStackTraceInFastThrow", "-Xms512m", "-Xmx512m"],
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with (output / "results.edn").open("w") as results:
        for batch, version in enumerate(("1.12.1", "1.12.6", "1.12.6", "1.12.1"), 1):
            scenarios = SCENARIOS if batch < 3 else tuple(reversed(SCENARIOS))
            for scenario in scenarios:
                print(f"batch={batch} clojure={version} scenario={scenario}", flush=True)
                result = subprocess.check_output([
                    "java", "-XX:-OmitStackTraceInFastThrow", "-Xms512m", "-Xmx512m",
                    "-cp", classpaths[version], "clojure.main", "-m", "paclo.dev.perf-worker",
                    "--mode", "offline", "--scenario", scenario, "--path", str(dataset),
                    "--count", "50000", "--warmups", "5", "--runs", "7"], cwd=ROOT, text=True)
                results.write(result)
                results.flush()


if __name__ == "__main__":
    main()
