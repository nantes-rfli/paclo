"""Real -T:build failure propagation, prep and reproducibility regressions."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CLI = shutil.which("clojure")


class BuildToolchainTest(unittest.TestCase):
    def run_build(self, task, cwd=ROOT, **env):
        return subprocess.run([CLI, "-Srepro", "-T:build", task], cwd=cwd,
                              env=dict(os.environ, **env), capture_output=True,
                              text=True, timeout=180)

    def test_workflow_cli_pins(self):
        for name in ("ci.yml", "publish.yml", "dependency-audit.yml"):
            text = (ROOT / ".github/workflows" / name).read_text()
            versions = re.findall(r"linux-install-([\d.]+)\.sh|cli: ['\"]?([\w.]+)", text)
            self.assertTrue(versions, name)
            self.assertEqual({"1.12.5.1664"}, {a or b for a, b in versions}, name)

    def test_subprocess_failures_reach_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            stub = path / "clojure"
            stub.write_text('#!/usr/bin/env bash\necho "injected child failure" >&2\nexit 37\n')
            stub.chmod(0o755)
            # The outer CLI is absolute. Only the build task's child is replaced.
            for task in ("spotbugs", "checkstyle", "jacoco", "jacoco-gate", "javadoc", "junit"):
                with self.subTest(task=task):
                    result = self.run_build(task, PATH=tmp + os.pathsep + os.environ["PATH"])
                    self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
                    self.assertIn("Build subprocess failed", result.stderr)
                    self.assertIn("injected child failure", result.stdout + result.stderr)

    def test_junit_launcher_failure_reaches_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Resolve genuine classpaths but replace only the JUnit launch.
            stub = Path(tmp) / "java"
            real_java = str(Path(os.environ["JAVA_HOME"]) / "bin/java") if os.environ.get("JAVA_HOME") else shutil.which("java")
            stub.write_text('#!/usr/bin/env bash\nif [[ "$1" == -jar ]]; then\n'
                            '  echo "injected junit failure" >&2; exit 38\nfi\n'
                            'exec ' + repr(real_java) + ' "$@"\n')
            stub.chmod(0o755)
            result = self.run_build("junit", PATH=tmp + os.pathsep + os.environ["PATH"])
            self.assertNotEqual(0, result.returncode)
            self.assertIn("injected junit failure", result.stdout + result.stderr)

    def test_javac_failure_and_java17_api_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            for name in ("deps.edn", "build.clj"):
                shutil.copy2(ROOT / name, project / name)
            (project / "src-java").mkdir()
            # Thread.threadId exists on newer JDKs, but not under --release 17.
            (project / "src-java/TooNew.java").write_text(
                'class TooNew { long id() { return Thread.currentThread().threadId(); } }\n')
            for task in ("javac", "javac-test", "jar"):
                with self.subTest(task=task):
                    result = self.run_build(task, cwd=project)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("threadId", result.stdout + result.stderr)

    def test_source_date_epoch_pom(self):
        outputs = []
        for _ in range(2):
            result = self.run_build("pom", SOURCE_DATE_EPOCH="946684800", PACLO_VERSION="1.5.0-SNAPSHOT")
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            outputs.append(((ROOT / "target/maven/pom.xml").read_bytes(),
                            (ROOT / "target/maven/pom.properties").read_bytes()))
        self.assertEqual(outputs[0], outputs[1])
        # Month/day names use the JVM locale; the fixed UTC instant is stable.
        self.assertIn(b"00:00:00 UTC 2000", outputs[0][1])

    def test_install_to_isolated_maven_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            repository = project / "m2"
            deps = (ROOT / "deps.edn").read_text().rstrip()[:-1]
            (project / "deps.edn").write_text(deps + '\n :mvn/local-repo "' + str(repository) + '"}\n')
            shutil.copy2(ROOT / "build.clj", project / "build.clj")
            for name in ("src-java", "src", "extensions/dns/src"):
                shutil.copytree(ROOT / name, project / name)
            # A disposable source fixture gives SNAPSHOT a genuine commit.
            git = ["git", "-c", "user.name=Paclo build fixture", "-c",
                   "user.email=build-fixture@example.invalid", "-c", "commit.gpgsign=false",
                   "-c", "core.hooksPath=/dev/null"]
            for args in (["init"], ["add", "deps.edn", "build.clj", "src-java", "src", "extensions"],
                         ["commit", "-m", "Build toolchain fixture"]):
                subprocess.run([*git, *args], cwd=project, check=True, capture_output=True)
            result = self.run_build("install", cwd=project, PACLO_VERSION="1.5.0-SNAPSHOT")
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            installed = repository / "org/clojars/nanto/paclo/1.5.0-SNAPSHOT"
            self.assertEqual((project / "target/paclo-1.5.0-SNAPSHOT.jar").read_bytes(),
                             (installed / "paclo-1.5.0-SNAPSHOT.jar").read_bytes())
            self.assertTrue((installed / "paclo-1.5.0-SNAPSHOT.pom").is_file())


if __name__ == "__main__":
    unittest.main()
