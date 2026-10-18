"""Negative controls for the release artifact gate (no JVM/dependencies needed)."""

import hashlib
import json
import struct
import tempfile
import unittest
from unittest.mock import patch
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
        self.entries = {name: b"(ns placeholder)" for name in gate.SOURCES}
        self.entries.update({name: struct.pack(">IHH", 0xCAFEBABE, 0, 61) for name in gate.CLASSES})
        self.entries["META-INF/MANIFEST.MF"] = b"Manifest-Version: 1.0\n"
        self.dependencies = dependencies
        self.set_metadata("1.5.0-SNAPSHOT", "a" * 40)

    def set_metadata(self, version, scm):
        self.version = version
        self.pom = (
            '<project xmlns="http://maven.apache.org/POM/4.0.0">'
            f'<groupId>org.clojars.nanto</groupId><artifactId>paclo</artifactId><version>{version}</version>'
            f'<scm><tag>{scm}</tag></scm>'
            f'<dependencies>{self.dependencies}</dependencies></project>').encode()
        self.entries[gate.POM_PATH] = self.pom
        self.entries[gate.POM_PATH.replace(".xml", ".properties")] = (
            f"groupId=org.clojars.nanto\nartifactId=paclo\nversion={version}\n").encode()

    def write_jar(self):
        with zipfile.ZipFile(self.jar, "w") as jar:
            for name, value in self.entries.items():
                jar.writestr(name, value)

    def test_java17_artifact(self):
        self.write_jar()
        inspection, pom = gate.inspect_jar(self.jar, self.version)
        self.assertEqual({61}, set(inspection["class_major_versions"].values()))
        self.assertEqual(self.pom, pom)

    def write_bundle(self):
        self.write_jar()
        inspection, _ = gate.inspect_jar(self.jar, self.version)
        (self.root / "pom.xml").write_bytes(self.pom)
        manifest = dict(inspection, version=self.version, source_commit="a" * 40,
                        jar_sha256=gate.sha256(self.jar),
                        files={name: gate.sha256(self.root / name) for name in ("paclo.jar", "pom.xml")})
        (self.root / "provenance.json").write_text(json.dumps(manifest))
        return manifest

    def test_release_and_snapshot_identity(self):
        for version, scm in (("1.5.0-SNAPSHOT", "a" * 40), ("1.4.0", "v1.4.0")):
            with self.subTest(version=version):
                self.set_metadata(version, scm)
                manifest = self.write_bundle()
                self.assertEqual(manifest, gate.verify(self.root))

    def test_rejects_wrong_version_and_properties(self):
        self.write_jar()
        with self.assertRaisesRegex(ValueError, "coordinates"):
            gate.inspect_jar(self.jar, "1.4.0")
        self.entries[gate.POM_PATH.replace(".xml", ".properties")] = (
            b"groupId=org.clojars.nanto\nartifactId=paclo\nversion=1.4.0\n")
        self.write_jar()
        with self.assertRaisesRegex(ValueError, "properties mismatch"):
            gate.inspect_jar(self.jar, self.version)

    def test_rejects_wrong_scm(self):
        for version, scm in (("1.5.0-SNAPSHOT", "v1.5.0-SNAPSHOT"),
                             ("1.5.0-SNAPSHOT", "HEAD"), ("1.5.0-SNAPSHOT", ""),
                             ("1.4.0", "v1.5.0"), ("1.4.0", "a" * 40)):
            with self.subTest(version=version, scm=scm):
                self.set_metadata(version, scm)
                self.write_jar()
                with self.assertRaisesRegex(ValueError, "SCM"):
                    gate.inspect_jar(self.jar, self.version)

    def test_prepare_rejects_different_source_commit(self):
        self.write_jar()
        output = self.root / "bundle"
        with patch.object(gate.subprocess, "check_output", return_value="b" * 40):
            with self.assertRaisesRegex(ValueError, "SCM/source commit mismatch"):
                gate.prepare(self.jar, output, self.version)
        self.assertFalse(output.exists())

    def test_rejects_mismatched_provenance(self):
        manifest = self.write_bundle()
        for key, value in (("source_commit", "b" * 40), ("version", "1.4.0"),
                           ("scm_tag", "b" * 40), ("coordinates", "org.clojars.nanto/paclo:1.4.0"),
                           ("jar_sha256", "0" * 64)):
            with self.subTest(key=key):
                (self.root / "provenance.json").write_text(json.dumps(dict(manifest, **{key: value})))
                with self.assertRaises(ValueError):
                    gate.verify(self.root)

    def test_rejects_external_pom_even_with_updated_hash(self):
        manifest = self.write_bundle()
        (self.root / "pom.xml").write_bytes(self.pom.replace(b"1.5.0-SNAPSHOT", b"1.4.0"))
        manifest["files"]["pom.xml"] = gate.sha256(self.root / "pom.xml")
        (self.root / "provenance.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "External and embedded POM differ"):
            gate.verify(self.root)

    def test_rejects_one_java21_class(self):
        # Check every entry, including a nested class rather than just the first.
        self.entries["paclo/jnr/PcapLibrary$PcapIf.class"] = struct.pack(">IHH", 0xCAFEBABE, 0, 65)
        self.write_jar()
        with self.assertRaisesRegex(ValueError, "major 65 > 61"):
            gate.inspect_jar(self.jar, self.version)

    def test_rejects_preview(self):
        self.entries["paclo/jnr/PcapHandle.class"] = struct.pack(">IHH", 0xCAFEBABE, 65535, 61)
        self.write_jar()
        with self.assertRaisesRegex(ValueError, "preview"):
            gate.inspect_jar(self.jar, self.version)

    def test_rejects_missing_namespace(self):
        del self.entries["paclo/proto/dns_ext.clj"]
        self.write_jar()
        with self.assertRaisesRegex(ValueError, "contents mismatch"):
            gate.inspect_jar(self.jar, self.version)

    def test_rejects_fixture_or_test_leak(self):
        for name in ("fixtures/example.pcap", "paclo/core_test.clj", "paclo/dev/tool.clj"):
            with self.subTest(name=name):
                self.entries[name] = b"unwanted"
                self.write_jar()
                with self.assertRaisesRegex(ValueError, "contents mismatch"):
                    gate.inspect_jar(self.jar, self.version)
                del self.entries[name]

    def test_rejects_changed_coordinates_or_dependencies(self):
        for old, new, message in ((b"org.clojars.nanto", b"other", "coordinates"),
                                  (b"1.12.1", b"1.12.2", "dependencies"),
                                  (b"</dependency>", b"<scope>test</scope></dependency>", "semantics")):
            with self.subTest(old=old):
                self.entries[gate.POM_PATH] = self.pom.replace(old, new)
                self.write_jar()
                with self.assertRaisesRegex(ValueError, message):
                    gate.inspect_jar(self.jar, self.version)

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
