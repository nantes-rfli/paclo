#!/usr/bin/env python3
"""Offline JAR-only comparison; writes raw evidence, never edits either JAR.

python3 dev/release-compatibility/compare.py OLD.jar CANDIDATE.jar OUTPUT.json
Requires git, Python, JDK 21, Clojure CLI, cached dependencies and libpcap.
CLI examples are external inputs extracted unchanged from v1.3.0/current HEAD;
they are repository commands, not contents of the published library JAR.
"""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def main():
    old, candidate, output = map(lambda x: Path(x).resolve(), sys.argv[1:])
    report = {"source_commit": git("rev-parse", "HEAD").decode().strip(),
              "runtime": subprocess.run(["java", "-version"], capture_output=True,
                                        text=True, check=True).stderr,
              "variants": {}}
    for label, jar, ref in [("v1.3.0", old, "v1.3.0"), ("candidate", candidate, "HEAD")]:
        with tempfile.TemporaryDirectory(prefix="paclo-compatibility-") as directory:
            work = Path(directory)
            examples = work / "examples"
            examples.mkdir()
            for name in git("ls-tree", "-r", "--name-only", ref, "dev/examples").decode().splitlines():
                if name.endswith(".clj"):
                    (examples / Path(name).name).write_bytes(git("show", f"{ref}:{name}"))
            shutil.copy(ROOT / "dev/paclo/dev/release_compatibility_probe.clj", work / "probe.clj")
            sample = ROOT / "test/resources/dns-sample.pcap"
            shutil.copy(sample, work / "sample.pcap")
            # A valid global header with an incomplete first record header.
            (work / "broken.pcap").write_bytes(sample.read_bytes()[:24] + b"\0" * 7)
            # Preserve real frame bytes; shift record times to distinct 1-second buckets.
            data = bytearray(sample.read_bytes())
            pos, i = 24, 0
            while pos < len(data):
                caplen = struct.unpack_from("<I", data, pos + 8)[0]
                struct.pack_into("<II", data, pos, 1700000000 + i, 0)
                pos += 16 + caplen
                i += 1
            (work / "buckets.pcap").write_bytes(data)
            (work / "deps.edn").write_text(
                '{:paths ["."] :deps {org.clojars.nanto/paclo {:local/root '
                + json.dumps(str(jar)) + '}}}')
            cases = {"library": ["-M", "-i", "probe.clj", "-e", "(paclo.dev.release-compatibility-probe/-main)"]}
            for case, ns, args in [
                ("flow", "flow-topn", '"sample.pcap"'),
                ("flow-bound", "flow-topn", '"sample.pcap" "_" "10" "unidir" "packets" "edn" "--max-flows" "1"'),
                ("rtt", "dns-rtt", '"sample.pcap"'),
                ("rtt-stats", "dns-rtt", '"sample.pcap" "_" "50" "stats"'),
                ("qps-client", "dns-qps", '"sample.pcap" "_" "1000" "client" "edn"'),
                ("qps-server", "dns-qps", '"sample.pcap" "_" "1000" "server" "edn"'),
                ("qps-bound", "dns-qps", '"buckets.pcap" "_" "1000" "rcode" "edn" "--max-buckets" "1"'),
            ]:
                cases[case] = ["-M", "-e", f"(require 'examples.{ns})", "-e",
                               f"(try (examples.{ns}/-main {args}) (finally (shutdown-agents)))"]
            results = {}
            for case, args in cases.items():
                run = subprocess.run(["clojure", "-Srepro", *args], cwd=work,
                                     capture_output=True, text=True, timeout=120)
                results[case] = {"exit": run.returncode, "stdout": run.stdout, "stderr": run.stderr}
                if case in ("library", "flow", "rtt", "qps-client") and run.returncode:
                    raise RuntimeError(f"{label}/{case}: {run.stderr}")
                print(label, case, run.returncode, flush=True)
            report["variants"][label] = {"jar_sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
                                         "examples_ref": git("rev-parse", ref).decode().strip(),
                                         "cases": results}
    output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
