"""Installer integrity and actual analyzer failure controls (requires pinned tools)."""

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "dev/script"


def executable(path, source):
    path.write_text(source)
    path.chmod(0o755)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="paclo-installer-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "shims"
        self.bin.mkdir()
        self.script = self.root / "dev/script/setup-lint-tools.sh"
        self.script.parent.mkdir(parents=True)
        self.source = (SCRIPTS / self.script.name).read_text()
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                    "PACLO_TEST_ROOT": str(self.root), "PACLO_TEST_OS": "Linux",
                    "PACLO_TEST_ARCH": "x86_64"}
        executable(self.bin / "uname", '#!/bin/bash\nif [[ "$1" == -s ]]; then '
                   'echo "$PACLO_TEST_OS"; else echo "$PACLO_TEST_ARCH"; fi\n')
        executable(self.bin / "curl", '''#!/bin/bash
set -eu
name=clj-kondo
for arg in "$@"; do
  [[ "$arg" != *clojure-lsp* ]] || name=clojure-lsp
done
echo "$*" >> "$PACLO_TEST_ROOT/requests"
while [[ "$1" != -o ]]; do shift; done
cp "$PACLO_TEST_ROOT/$name.zip" "$2"
''')
        for name in ("clj-kondo", "clojure-lsp"):
            with zipfile.ZipFile(self.root / (name + ".zip"), "w") as archive:
                archive.writestr(name, "#!/bin/sh\necho fixture-tool\n")
        self.pin_fixtures()

    def pin_fixtures(self):
        source = self.source
        for tool, variable in (("clj-kondo", "kondo"), ("clojure-lsp", "lsp")):
            digest = hashlib.sha256((self.root / (tool + ".zip")).read_bytes()).hexdigest()
            source = re.sub(r"paclo_" + variable + r"_sha=[0-9a-f]{64}",
                            "paclo_" + variable + "_sha=" + digest, source)
        self.script.write_text(source)

    def run_installer(self):
        return subprocess.run(["bash", str(self.script)], env=self.env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)

    def test_all_platform_selections_and_atomic_replacement(self):
        for system, arch, asset in (("Linux", "x86_64", "linux-amd64"),
                                    ("Linux", "aarch64", "linux-aarch64"),
                                    ("Darwin", "x86_64", "macos-amd64"),
                                    ("Darwin", "arm64", "macos-aarch64")):
            with self.subTest(system=system, arch=arch):
                self.env.update(PACLO_TEST_OS=system, PACLO_TEST_ARCH=arch)
                result = self.run_installer()
                self.assertEqual(0, result.returncode, result.stdout)
                self.assertIn(asset + ".zip", (self.root / "requests").read_text())
                for name in ("clj-kondo", "clojure-lsp"):
                    self.assertTrue(os.access(self.root / ".dev-tools/bin" / name, os.X_OK))
                self.assertEqual(2, len(list((self.root / ".dev-tools/bin").iterdir())))

    def test_checksum_mismatch_preserves_existing_binary(self):
        target = self.root / ".dev-tools/bin/clj-kondo"
        target.parent.mkdir(parents=True)
        target.write_text("existing binary")
        (self.root / "clj-kondo.zip").write_bytes(b"tampered")
        result = self.run_installer()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Checksum mismatch", result.stdout)
        self.assertEqual("existing binary", target.read_text())
        self.assertFalse(target.with_name("clojure-lsp").exists())

    def test_missing_archive_member_fails_before_install(self):
        with zipfile.ZipFile(self.root / "clj-kondo.zip", "w") as archive:
            archive.writestr("wrong-member", "payload")
        self.pin_fixtures()
        result = self.run_installer()
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.root / ".dev-tools/bin/clj-kondo").exists())

    def test_download_failure_propagates(self):
        executable(self.bin / "curl", "#!/bin/sh\nexit 22\n")
        self.assertEqual(22, self.run_installer().returncode)

    def test_unsupported_platform_fails_without_download(self):
        self.env["PACLO_TEST_ARCH"] = "riscv64"
        result = self.run_installer()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Unsupported lint-tool platform", result.stdout)
        self.assertFalse((self.root / "requests").exists())


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="paclo-analyzer-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for folder in ("src", ".clj-kondo", ".lsp", "dev"):
            (self.root / folder).mkdir()
        for name in ("clj-kondo", "clojure-lsp"):
            self.assertIsNotNone(shutil.which(name), "Required analyzer missing: " + name)
        (self.root / ".clj-kondo/config.edn").write_text(
            (ROOT / ".clj-kondo/config.edn").read_text())
        (self.root / ".lsp/config.edn").write_text(
            '{:source-paths ["src"] :project-specs []}')
        self.file = self.root / "src/probe.clj"
        self.file.write_text("(ns probe)\n(def answer 42)\n")
        for name in ("deps.edn", "dev/nvd-clojure.edn", "build.clj"):
            (self.root / name).write_text("{}\n" if name.endswith("edn") else "(ns build)\n")

    def run_tool(self, *args):
        return subprocess.run(args, cwd=self.root, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=120)

    def kondo(self):
        return self.run_tool("bash", str(SCRIPTS / "kondo.sh"), "src", "--cache", "false")

    def test_valid_source_and_resource_macro_lint_as(self):
        # Existing resource macros keep ordinary lexical bindings without hooks.
        self.file.write_text("(ns probe (:require [paclo.pcap :as p]))\n"
                             "(p/with-pcap [handle nil] (identity handle))\n")
        result = self.kondo()
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("errors: 0, warnings: 0", result.stdout)

    def test_unresolved_symbol_fails(self):
        self.file.write_text("(ns probe)\n(undefined-call 1)\n")
        result = self.kondo()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Unresolved symbol", result.stdout)

    def test_unsupported_reader_syntax_fails(self):
        self.file.write_text("(ns probe)\n#<unreadable>\n")
        result = self.kondo()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("error:", result.stdout)

    def test_malformed_kondo_configuration_cannot_pass_with_warning(self):
        (self.root / ".clj-kondo/config.edn").write_text("{:lint-as")
        result = self.kondo()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("configuration", result.stdout)

    def test_malformed_lsp_configuration_fails_before_fallback(self):
        (self.root / ".lsp/config.edn").write_text("{:source-paths")
        result = self.run_tool("bash", str(SCRIPTS / "fmt.sh"), "--dry")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("error:", result.stdout)

    def test_lsp_dry_checks_pass_without_writes(self):
        before = self.file.read_bytes()
        result = self.run_tool("bash", str(SCRIPTS / "fmt.sh"), "--dry")
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual(before, self.file.read_bytes())

    def test_lsp_format_difference_fails_without_writes(self):
        self.file.write_text("(ns probe)\n(defn answer []\n(+ 1 2))\n")
        before = self.file.read_bytes()
        result = self.run_tool("clojure-lsp", "format", "--dry")
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertEqual(before, self.file.read_bytes())

    def test_lsp_namespace_difference_fails_without_writes(self):
        self.file.write_text("(ns probe (:require [clojure.string :as str]))\n")
        before = self.file.read_bytes()
        result = self.run_tool("clojure-lsp", "clean-ns", "--dry")
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertEqual(before, self.file.read_bytes())

    def test_lsp_parser_failure_propagates(self):
        self.file.write_text("(ns probe)\n(defn invalid []\n")
        for command in ("clean-ns", "format"):
            with self.subTest(command=command):
                result = self.run_tool("clojure-lsp", command, "--dry")
                self.assertNotEqual(0, result.returncode, result.stdout)

    def test_formatter_rejects_unknown_arguments(self):
        result = self.run_tool("bash", str(SCRIPTS / "fmt.sh"), "--unknown")
        self.assertEqual(2, result.returncode)


if __name__ == "__main__":
    unittest.main()
