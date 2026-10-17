#!/usr/bin/env python3
"""Inspect the release JAR and prepare/run a checkout-independent consumer.

prepare never builds: invoke build/jar under JDK 21 first (as Publish does).
consume runs only the supplied JAR, harness and fixtures, with -Srepro.
"""

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


POM_PATH = "META-INF/maven/org.clojars.nanto/paclo/pom.xml"
SOURCES = {
    f"paclo/{name}.clj" for name in (
        "core", "stream", "decode_ext", "flow", "flow/project", "window", "dns",
        "pcapng", "pcapng/cursor", "pcapng/writer", "pcap", "parse", "linktype",
        "capture", "dev", "stream/impl", "proto/dns_ext", "proto/tls_ext",
    )
}
CLASSES = {
    f"paclo/jnr/{name}.class" for name in (
        "BpfProgram", "PcapConfigLibrary", "PcapErrors", "PcapHandle", "PcapHeader",
        "PcapLibrary", "PcapLibrary$PcapIf", "PcapStat", "PcapStatsLibrary", "PcapStdioLibrary",
    )
}
# The existing published coordinates/dependency graph; changes require review.
DEPENDENCIES = {
    "org.clojure/clojure": "1.12.1",
    "org.clojure/core.async": "1.6.681",
    "com.github.jnr/jnr-ffi": "2.2.14",
    "org.clojure/data.json": "2.5.0",
    "com.github.spotbugs/spotbugs-annotations": "4.8.6",
}
FIXTURES = (
    "dns-sample.pcap", "tls-sni-alpn-sample.pcap", "cooked/sll.pcap", "cooked/sll2.pcap",
    "raw-ip/raw.pcap", "null-loop/null-header-le-file-le.pcap",
    "null-loop/loop-header-be-file-le.pcap", "pcapng-contracts/rich.pcapng",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_jar(path, version):
    with zipfile.ZipFile(path) as jar:
        names = [name for name in jar.namelist() if not name.endswith("/")]
        expected = SOURCES | CLASSES | {"META-INF/MANIFEST.MF", POM_PATH, POM_PATH.replace(".xml", ".properties")}
        require(len(names) == len(set(names)), "Duplicate JAR entries")
        require(set(names) == expected,
                f"JAR contents mismatch: missing={expected - set(names)}, extra={set(names) - expected}")
        versions = {}
        for name in sorted(n for n in names if n.endswith(".class")):
            magic, minor, major = struct.unpack(">IHH", jar.read(name)[:8])
            require(magic == 0xCAFEBABE and minor != 65535, f"Invalid/preview class: {name}")
            require(major <= 61, f"Java 17 incompatible class: {name}: major {major} > 61")
            versions[name] = major
        pom = jar.read(POM_PATH)
        root = ET.fromstring(pom)
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}

        def field(node, name):
            return node.findtext(f"m:{name}", namespaces=ns)

        require((field(root, "groupId"), field(root, "artifactId"), field(root, "version")) ==
                ("org.clojars.nanto", "paclo", version), "POM coordinates changed")
        deps = {}
        for dep in root.findall("m:dependencies/m:dependency", ns):
            require(field(dep, "scope") in (None, "compile") and
                    field(dep, "optional") in (None, "false") and
                    field(dep, "classifier") is None and
                    field(dep, "type") in (None, "jar") and
                    dep.find("m:exclusions", ns) is None, "POM dependency semantics changed")
            coord = f'{field(dep, "groupId")}/{field(dep, "artifactId")}'
            require(coord not in deps, "Duplicate dependency")
            deps[coord] = field(dep, "version")
        require(deps == DEPENDENCIES, f"POM dependencies changed: {deps}")
        properties = dict(line.split("=", 1) for line in
                          jar.read(POM_PATH.replace(".xml", ".properties")).decode().splitlines()
                          if "=" in line and not line.startswith("#"))
        require(properties == {"groupId": "org.clojars.nanto", "artifactId": "paclo",
                               "version": version}, "pom.properties mismatch")
        return {"class_major_versions": versions, "dependencies": deps,
                "coordinates": f"org.clojars.nanto/paclo:{version}"}, pom


def java_version():
    return subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT, text=True).strip()


def prepare(jar, output, version):
    root = Path(__file__).resolve().parents[2]
    inspection, pom = inspect_jar(jar, version)
    # Compare packaged Clojure bytes with production roots, never dev/test roots.
    with zipfile.ZipFile(jar) as archive:
        for name in SOURCES:
            source = root / ("extensions/dns/src" if name == "paclo/proto/dns_ext.clj" else "src") / name
            require(archive.read(name) == source.read_bytes(), f"Packaged source differs: {name}")
    require(not output.exists(), f"Output already exists: {output}")
    output.mkdir(parents=True)
    shutil.copy2(jar, output / "paclo.jar")
    (output / "pom.xml").write_bytes(pom)
    (output / "distribution_consumer").mkdir()
    shutil.copy2(root / "dev/distribution_consumer/consumer.clj",
                 output / "distribution_consumer/consumer.clj")
    shutil.copy2(Path(__file__), output / "verify_distribution.py")
    for fixture in FIXTURES:
        dest = output / "fixtures" / fixture
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / "test/resources" / fixture, dest)
    deps = "\n        ".join(f'{coord} {{:mvn/version "{v}"}}' for coord, v in sorted(DEPENDENCIES.items()))
    (output / "deps.edn").write_text(
        '{:paths ["."]\n :deps {org.clojars.nanto/paclo {:local/root "paclo.jar"}\n        ' + deps + '}}\n')
    inspection.update({
        "version": version,
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=root, text=True)),
        "build_java": java_version(),
        "jar_sha256": sha256(output / "paclo.jar"),
        "files": {str(p.relative_to(output)): sha256(p) for p in sorted(output.rglob("*")) if p.is_file()},
    })
    (output / "provenance.json").write_text(json.dumps(inspection, indent=2) + "\n")
    print(json.dumps(inspection, indent=2))


def verify(bundle):
    manifest = json.loads((bundle / "provenance.json").read_text())
    for name, digest in manifest["files"].items():
        path = (bundle / name).resolve()
        require(path.is_relative_to(bundle.resolve()), f"Unsafe manifest path: {name}")
        require(sha256(path) == digest, f"SHA-256 mismatch: {name}")
    require(sha256(bundle / "paclo.jar") == manifest["jar_sha256"], "JAR SHA-256 mismatch")
    inspection, pom = inspect_jar(bundle / "paclo.jar", manifest["version"])
    require(pom == (bundle / "pom.xml").read_bytes(), "External and embedded POM differ")
    for key, value in inspection.items():
        require(manifest[key] == value, f"Provenance mismatch: {key}")
    print(f'SHA-256 verified: {manifest["jar_sha256"]}; source: {manifest["source_commit"]}')
    return manifest


def consume(bundle, report):
    manifest = verify(bundle)
    # A fresh project outside the checkout, with only the artifact and test inputs.
    with tempfile.TemporaryDirectory(prefix="paclo-distribution-") as tmp:
        project = Path(tmp)
        for name in manifest["files"]:
            dest = project / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(bundle / name, dest)
        before = sha256(project / "paclo.jar")
        subprocess.run(["clojure", "-Srepro", "-M", "-m", "distribution-consumer.consumer"], cwd=project, check=True, timeout=180)
        require(before == sha256(project / "paclo.jar") == manifest["jar_sha256"], "Consumer changed JAR")
    result = {"source_commit": manifest["source_commit"], "jar_sha256": before,
              "runtime_java": java_version(), "status": "passed"}
    report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("jar", type=Path)
    prep.add_argument("output", type=Path)
    prep.add_argument("--version", default="1.4.0-SNAPSHOT")
    for command in ("verify", "consume"):
        sub = commands.add_parser(command)
        sub.add_argument("bundle", type=Path)
        if command == "consume":
            sub.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.jar.resolve(), args.output.resolve(), args.version)
    elif args.command == "verify":
        verify(args.bundle.resolve())
    else:
        consume(args.bundle.resolve(), args.report.resolve())


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
