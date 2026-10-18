"""Exercise real build/POM version resolution and the existing Publish guards.

Never installs artifacts, creates release tags, dispatches workflows or publishes.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def workflow_script(name):
    workflow = (ROOT / ".github/workflows/publish.yml").read_text()
    step = workflow.split(f"      - name: {name}\n", 1)[1].split("\n      - name:", 1)[0]
    return "\n".join(line[10:] for line in step.split("        run: |\n", 1)[1].splitlines())


class BuildIdentityTest(unittest.TestCase):
    def test_real_pom_versions_and_scm(self):
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        cases = (
            ({}, "1.5.0-SNAPSHOT", commit),
            ({"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1.4.0"}, "1.4.0", "v1.4.0"),
            ({"GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "v1.4.0"}, "1.5.0-SNAPSHOT", commit),
            ({"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "unrelated"}, "1.5.0-SNAPSHOT", commit),
            ({"PACLO_VERSION": "1.4.0", "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1.3.0"},
             "1.4.0", "v1.4.0"),
            ({"PACLO_VERSION": "1.5.0-SNAPSHOT", "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1.4.0"},
             "1.5.0-SNAPSHOT", commit),
        )
        for overrides, version, scm in cases:
            with self.subTest(overrides=overrides):
                env = {k: v for k, v in os.environ.items()
                       if k not in ("PACLO_VERSION", "GITHUB_REF_TYPE", "GITHUB_REF_NAME")}
                env.update(overrides)
                subprocess.run(["clojure", "-T:build", "pom"], cwd=ROOT, env=env,
                               check=True, timeout=120, capture_output=True, text=True)
                pom = ET.parse(ROOT / "target/maven/pom.xml")
                self.assertEqual(version, pom.findtext("m:version", namespaces=NS))
                self.assertEqual(scm, pom.findtext("m:scm/m:tag", namespaces=NS))

    def test_snapshot_requires_source_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            git = Path(tmp) / "git"
            git.write_text("#!/usr/bin/env bash\nexit 1\n")
            git.chmod(0o755)
            env = dict(os.environ, PACLO_VERSION="1.5.0-SNAPSHOT",
                       PATH=tmp + os.pathsep + os.environ["PATH"])
            result = subprocess.run(["clojure", "-T:build", "pom"], cwd=ROOT, env=env,
                                    capture_output=True, text=True, timeout=120)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("SNAPSHOT builds require a source Git commit", result.stderr)


class PublishGuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.env = dict(os.environ, GITHUB_EVENT_NAME="push", GITHUB_REF_NAME="v1.4.0",
                        GITHUB_SHA="source", GITHUB_OUTPUT=str(self.path / "output"),
                        PACLO_RELEASE_VERSION="1.4.0", PACLO_DRY_RUN="false")
        # Controlled git responses exercise the workflow's actual shell conditions.
        git = self.path / "git"
        git.write_text('''#!/usr/bin/env bash
set -eu
case "$1" in
  fetch) exit 0 ;;
  rev-parse) echo "${TEST_MAIN_SHA:-source}" ;;
  rev-list) echo "${TEST_TAG_SHA:-source}" ;;
  merge-base) exit "${TEST_ANCESTOR_EXIT:-0}" ;;
  *) exit 99 ;;
esac
''')
        git.chmod(0o755)
        self.env["PATH"] = str(self.path) + os.pathsep + self.env["PATH"]

    def run_guard(self, name, **overrides):
        return subprocess.run(["bash", "-c", workflow_script(name)], cwd=ROOT,
                              env=dict(self.env, **overrides), capture_output=True, text=True, timeout=30)

    def test_version_resolution(self):
        for event, inputs, expected in (
                ("push", {}, "1.4.0"),
                ("workflow_dispatch", {"DISPATCH_VERSION": "1.5.0-SNAPSHOT"}, "1.5.0-SNAPSHOT")):
            with self.subTest(event=event):
                result = self.run_guard("Resolve version", GITHUB_EVENT_NAME=event, **inputs)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertIn(f"artifact=target/paclo-{expected}.jar", (self.path / "output").read_text())
        self.assertNotEqual(0, self.run_guard("Resolve version", GITHUB_REF_NAME="vbad").returncode)

    def test_source_and_metadata_guards(self):
        for overrides, success in (
                ({}, True),
                ({"GITHUB_EVENT_NAME": "workflow_dispatch"}, True),
                ({"GITHUB_EVENT_NAME": "workflow_dispatch", "TEST_MAIN_SHA": "different"}, False),
                ({"TEST_TAG_SHA": "different"}, False),
                ({"TEST_ANCESTOR_EXIT": "1"}, False),
                ({"PACLO_RELEASE_VERSION": "1.5.0-SNAPSHOT"}, False),
                ({"PACLO_RELEASE_VERSION": "1.4.99"}, False)):
            with self.subTest(overrides=overrides):
                result = self.run_guard("Verify release source and metadata", **overrides)
                self.assertEqual(success, result.returncode == 0, result.stdout + result.stderr)

    def test_publication_conditions_remain_explicit(self):
        publish = (ROOT / ".github/workflows/publish.yml").read_text()
        self.assertIn("  push:\n    tags:\n      - 'v*'\n  workflow_dispatch:", publish)
        self.assertIn("        default: true\n        type: boolean", publish)
        self.assertIn("      - name: Publish to Clojars\n"
                      "        if: github.event_name == 'push' || inputs.dry_run == false", publish)
        self.assertIn("    if: github.repository == 'nantes-rfli/paclo'", publish)
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertNotIn("deps-deploy", ci)
        self.assertNotIn("CLOJARS_PASSWORD", ci)


if __name__ == "__main__":
    unittest.main()
