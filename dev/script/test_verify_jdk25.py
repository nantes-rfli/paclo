"""Negative controls for the experimental runtime gate and failure reporting."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_jdk25 as gate


class Jdk25GateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name) / "report"

    def test_rejects_alias_to_different_jdk_before_compiling(self):
        with patch.object(gate.subprocess, "check_output", return_value="java.specification.version = 26\n"), \
                patch.object(gate.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "actual JDK 25"):
                gate.run_checks(self.output)
        run.assert_not_called()

    def test_junit_failure_is_fatal_and_records_unfiltered_warnings(self):
        def execute(command, stdout, **kwargs):
            stdout.write("WARNING: native warning retained\n")
            return subprocess.CompletedProcess(command, 2 if command[-1] == "junit" else 0)

        with patch.object(gate.subprocess, "check_output", return_value="java.specification.version = 25\n"), \
                patch.object(gate.subprocess, "run", side_effect=execute):
            with self.assertRaisesRegex(RuntimeError, "junit failed"):
                gate.run_checks(self.output)
        steps = json.loads((self.output / "steps.json").read_text())
        self.assertEqual("junit", steps[-1]["step"])
        self.assertEqual(2, steps[-1]["exit"])
        self.assertIn("WARNING: native warning retained", (self.output / "junit.log").read_text())
        self.assertFalse((self.output / "clojure-tests.log").exists())


if __name__ == "__main__":
    unittest.main()
