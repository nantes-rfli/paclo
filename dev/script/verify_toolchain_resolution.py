"""Verify fresh/warm Maven+Git resolution and prep-lib without user deps/caches.

Run with the reference CLI. Uses temporary repositories, never clears user caches.
Output must be a fresh directory; retains commands, timing and diagnostics.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def verify(output):
    output.mkdir(parents=True)
    config = output / "config"
    config.mkdir()
    # -Srepro must ignore this deliberately unresolvable user dependency.
    (config / "deps.edn").write_text('{:deps {invalid/user-dependency {:mvn/version "0.0.0"}}}\n')
    env = dict(os.environ, CLJ_CONFIG=str(config), GITLIBS=str(output / "gitlibs"))
    project = output / "project"
    project.mkdir()
    deps = (ROOT / "deps.edn").read_text()
    (project / "deps.edn").write_text(deps.rstrip()[:-1] + '\n :mvn/local-repo ' + json.dumps(str(output / "m2")) + '}\n')
    records = []

    def run(name, args, cwd=project):
        start = time.monotonic()
        result = subprocess.run(["clojure", "-Srepro", *args], cwd=cwd, env=env,
                                capture_output=True, text=True, timeout=600)
        (output / f"{name}.log").write_text(result.stdout + result.stderr)
        records.append({"name": name, "args": args, "exit": result.returncode,
                        "seconds": round(time.monotonic() - start, 3)})
        (output / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError(f"{name} failed; see {output / (name + '.log')}")
        return result.stdout + result.stderr

    run("cli", ["-Sdescribe"])
    for state in ("cold", "warm"):
        logs = run(f"{state}-maven-git", ["-Sforce", "-P", "-M:test"])
        logs += run(f"{state}-build", ["-Sforce", "-P", "-T:build"])
        if state == "warm":
            assert "Downloading:" not in logs and "Cloning:" not in logs, logs
    tree = run("tree", ["-A:test", "-Stree"])
    assert "org.clojure/clojure 1.12.6" in tree and "test-runner v0.5.1" in tree, tree
    assert list((output / "m2").rglob("tools.build-0.10.14.jar"))
    runner = list((output / "gitlibs/libs").rglob("src/cognitect/test_runner.clj"))
    assert len(runner) == 1 and "dfb30dd6605cb6c0efc275e1df1736f6e90d4d73" in str(runner[0]), runner

    # Exercise the actual library prep contract from a separate local consumer.
    # Prep launches another CLI, which does not inherit the parent's -Srepro.
    # Keep that subprocess independent of user deps with an empty CLJ_CONFIG.
    (config / "deps.edn").write_text('{}\n')
    source = output / "source"
    source.mkdir()
    shutil.copy2(project / "deps.edn", source / "deps.edn")
    shutil.copy2(ROOT / "build.clj", source / "build.clj")
    shutil.copytree(ROOT / "src-java", source / "src-java")
    consumer = output / "consumer"
    consumer.mkdir()
    (consumer / "deps.edn").write_text(
        '{:deps {org.clojure/clojure {:mvn/version "1.12.6"}\n'
        '        org.clojars.nanto/paclo {:local/root ' + json.dumps(str(source)) + '}}\n'
        ' :mvn/local-repo ' + json.dumps(str(output / "m2")) + '}\n')
    run("prep-lib", ["-X:deps", "prep"], consumer)
    binding = source / "target/classes/paclo/jnr/PcapHeader.class"
    assert struct.unpack(">H", binding.read_bytes()[6:8])[0] == 61
    run("prepped-consumer", ["-M", "-e",
                            '(import paclo.jnr.PcapHeader) (assert (= "1.12.6" (clojure-version)))'], consumer)
    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    verify(parser.parse_args().output.resolve())
