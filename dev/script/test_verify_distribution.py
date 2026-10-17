"""Negative controls for the release artifact gate (no JVM/dependencies needed)."""

import hashlib
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

import verify_distribution as gate


class DistributionGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.jar = self.root / "paclo.jar"
        dependencies = "".join(
            f"<dependency><groupId>{coord.split('/')[0]}</groupId>"
            f"<artifactId>{coord.split('/')[1]}</artifactId><version>{version}</version></dependency>"
            for coord, version in gate.DEPENDENCIES.items())
        self.pom = (
            '<project xmlns="http://maven.apache.org/POM/4.0.0">'
            '<groupId>org.clojars.nanto</groupId><artifactId>paclo</artifactId><version>test</version>'
            f'<dependencies>{dependencies}</dependencies></project>').encode()
        self.entries = {name: b"(ns placeholder)" for name in gate.SOURCES}
        self.entries.update({name: struct.pack(">IHH", 0xCAFEBABE, 0, 61) for name in gate.CLASSES})
        self.entries.update({gate.POM_PATH: self.pom, "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
                             gate.POM_PATH.replace(".xml", ".properties"):
                                 b"groupId=org.clojars.nanto\nartifactId=paclo\nversion=test\n"})

    def write_jar(self):
        with zipfile.ZipFile(self.jar, "w") as jar:
            for name, value in self.entries.items():
                jar.writestr(name, value)

    def test_java17_artifact(self):
        self.write_jar()
        inspection, pom = gate.inspect_jar(self.jar, "test")
        self.assertEqual({61}, set(inspection["class_major_versions"].values()))
        self.assertEqual(self.pom, pom)

    def test_rejects_one_java21_class(self):
        # Check every entry, including a nested class rather than just the first.
        self.entries["paclo/jnr/PcapLibrary$PcapIf.class"] = struct.pack(">IHH", 0xCAFEBABE, 0, 65)
        self.write_jar()
        with self.assertRaisesRegex(ValueError, "major 65 > 61"):
            gate.inspect_jar(self.jar, "test")

    def test_rejects_preview(self):
        self.entries["paclo/jnr/PcapHandle.class"] = struct.pack(">IHH", 0xCAFEBABE, 65535, 61)
        self.write_jar()
        with self.assertRaisesRegex(ValueError, "preview"):
            gate.inspect_jar(self.jar, "test")

    def test_rejects_missing_namespace(self):
        del self.entries["paclo/proto/dns_ext.clj"]
        self.write_jar()
        with self.assertRaisesRegex(ValueError, "contents mismatch"):
            gate.inspect_jar(self.jar, "test")

    def test_rejects_fixture_or_test_leak(self):
        for name in ("fixtures/example.pcap", "paclo/core_test.clj", "paclo/dev/tool.clj"):
            with self.subTest(name=name):
                self.entries[name] = b"unwanted"
                self.write_jar()
                with self.assertRaisesRegex(ValueError, "contents mismatch"):
                    gate.inspect_jar(self.jar, "test")
                del self.entries[name]

    def test_rejects_changed_coordinates_or_dependencies(self):
        for old, new, message in ((b"org.clojars.nanto", b"other", "coordinates"),
                                  (b"1.12.1", b"1.12.2", "dependencies"),
                                  (b"</dependency>", b"<scope>test</scope></dependency>", "semantics")):
            with self.subTest(old=old):
                self.entries[gate.POM_PATH] = self.pom.replace(old, new)
                self.write_jar()
                with self.assertRaisesRegex(ValueError, message):
                    gate.inspect_jar(self.jar, "test")

    def test_rejects_same_name_different_jar(self):
        self.write_jar()
        manifest = {"files": {"paclo.jar": hashlib.sha256(self.jar.read_bytes()).hexdigest()}}
        (self.root / "provenance.json").write_text(json.dumps(manifest))
        with self.jar.open("ab") as jar:
            jar.write(b"changed after upload")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            gate.verify(self.root)


if __name__ == "__main__":
    unittest.main()
