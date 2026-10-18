#!/usr/bin/env python3
"""Run the experimental JDK25 source checks without widening the support guard.

Use an empty/fresh output directory. Logs retain unfiltered stdout and stderr,
including native-access/Unsafe warnings. Existing JDK21 quality gates still apply.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys


def run_checks(output):
    output.mkdir(parents=True, exist_ok=False)
    steps = [
        ("identity", ["java", "-XshowSettings:properties", "-version"]),
        ("javac", ["clojure", "-T:build", "javac"]),
        ("javac-test", ["clojure", "-T:build", "javac-test"]),
        ("junit", ["clojure", "-T:build", "junit"]),
        ("clojure-tests", ["clojure", "-M:test"]),
        ("native-smoke", ["clojure", "-M:dev:dns-ext", "-e",
                          "(require 'distribution-consumer.consumer) "
                          "(try (distribution-consumer.consumer/native-check! "
                          '"test/resources/dns-sample.pcap") '
                          "(distribution-consumer.consumer/write-runtime! "
                          + json.dumps(str(output / "runtime.json")) + ") "
                          "(finally (shutdown-agents)))"]),
        ("dependencies", ["clojure", "-Stree"]),
    ]
    summary = []
    try:
        # Fail before compilation if a JDK alias resolves to a different runtime.
        identity = subprocess.check_output(
            ["java", "-XshowSettings:properties", "-version"], stderr=subprocess.STDOUT, text=True)
        if not any(line.strip() == "java.specification.version = 25" for line in identity.splitlines()):
            raise ValueError("This experiment requires actual JDK 25")
        for name, command in steps:
            print(f"Running {name}: {command}", flush=True)
            with (output / f"{name}.log").open("w") as log:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=900)
            summary.append({"step": name, "command": command, "exit": result.returncode})
            if result.returncode:
                raise RuntimeError(f"{name} failed; see {output / (name + '.log')}")
    finally:
        (output / "steps.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("JDK25 source checks passed; retained warnings and runtime identity in", output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    run_checks(args.output.resolve())


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
