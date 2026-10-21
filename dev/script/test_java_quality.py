"""Run the real Java-quality entry points in disposable projects, including failures."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class JavaQualityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java = shutil.which("java")
        result = subprocess.run(
            ["clojure", "-Spath", "-A:spotbugs:jacoco:junit:jacoco-gate"],
            cwd=ROOT, capture_output=True, text=True, check=True, timeout=180)
        cls.cp = os.pathsep.join(str((ROOT / p).resolve()) for p in result.stdout.strip().split(os.pathsep))
        # No test classes in the child fixture's classpath (for the zero-test control).
        cls.child_cp = os.pathsep.join(p for p in cls.cp.split(os.pathsep)
                                      if p != str(ROOT / "target/test-classes"))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        (self.path / "target/classes").mkdir(parents=True)
        (self.path / "dev/resources").mkdir(parents=True)
        shutil.copy2(ROOT / "dev/resources/spotbugs-exclude.xml", self.path / "dev/resources")
        self.bin = self.path / "bin"
        self.bin.mkdir()
        self.stub("clojure", 'printf "%s\\n" "$PACLO_TEST_CP"\n')
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        PACLO_TEST_CP=self.child_cp)

    def stub(self, name, body):
        file = self.bin / name
        file.write_text("#!/usr/bin/env bash\n" + body)
        file.chmod(0o755)

    def run_runner(self, name, **env):
        return subprocess.run([self.java, "-cp", self.cp, "clojure.main", "-m", "paclo.dev." + name],
                              cwd=self.path, env=dict(self.env, **env),
                              capture_output=True, text=True, timeout=120)

    def gate(self, report, succeeds, **env):
        if report is not None:
            (self.path / "target/jacoco.xml").write_text(report)
        result = self.run_runner("jacoco-gate", **env)
        self.assertEqual(succeeds, result.returncode == 0, result.stdout + result.stderr)

    def test_gate_boundary_and_bundle_counter(self):
        # Class/sourcefile counters must not distort the actual bundle ratio.
        self.gate('<report><package><counter type="LINE" covered="99" missed="0"/></package>'
                  '<counter type="LINE" covered="1" missed="3"/></report>', True)
        self.gate('<report><counter type="LINE" covered="1" missed="4"/></report>', False)

    def test_gate_rejects_corrupt_missing_empty_duplicate_and_negative(self):
        for report in (None, '<report>', '<report/>',
                       '<report><counter type="LINE" covered="0" missed="0"/></report>',
                       '<report><counter type="LINE" covered="-1" missed="5"/></report>',
                       '<report><counter type="LINE" covered="NaN" missed="5"/></report>',
                       '<report>' + '<counter type="LINE" covered="1" missed="1"/>' * 2 + '</report>'):
            with self.subTest(report=report):
                self.gate(report, False)

    def test_gate_threshold_cannot_be_weakened_or_nan(self):
        for threshold in ('0.24', 'NaN', 'Infinity', '1.01'):
            with self.subTest(threshold=threshold):
                self.gate('<report><counter type="LINE" covered="1" missed="0"/></report>',
                          False, JACOCO_MIN_LINE=threshold)

    def test_classpath_failures_reach_both_entry_points(self):
        self.stub("clojure", 'echo "injected resolution failure" >&2\nexit 37\n')
        for runner in ('spotbugs', 'jacoco'):
            result = self.run_runner(runner)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Java quality subprocess failed", result.stderr)

    def test_spotbugs_launcher_failure_cannot_reuse_old_report(self):
        (self.path / "target/spotbugs.xml").write_text('<BugCollection/>')
        self.stub("java", 'echo "injected analyzer failure" >&2\nexit 1\n')
        result = self.run_runner('spotbugs')
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.path / "target/spotbugs.xml").exists())

    def test_spotbugs_analysis_flags_fail(self):
        for status in (2, 3, 4, 5, 6, 7, 37):
            with self.subTest(status=status):
                self.stub("java", f'exit {status}\n')
                self.assertNotEqual(0, self.run_runner('spotbugs').returncode)

    def test_real_spotbugs_findings_and_missing_class(self):
        source = self.path / "Probe.java"
        source.write_text('public class Probe { public int bad() { String s = null; return s.length(); } }')
        subprocess.run(['javac', '--release', '17', '-d', 'target/classes', str(source)],
                       cwd=self.path, check=True, capture_output=True)
        result = self.run_runner('spotbugs')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('NP_ALWAYS_NULL', (self.path / 'target/spotbugs.xml').read_text())
        source.write_text('public class Probe extends Missing {}\nclass Missing {}')
        subprocess.run(['javac', '--release', '17', '-d', 'target/classes', str(source)],
                       cwd=self.path, check=True, capture_output=True)
        (self.path / 'target/classes/Missing.class').unlink()
        result = self.run_runner('spotbugs')
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('SpotBugs analysis failed', result.stderr)

    def test_new_detector_and_improved_ignored_copy_detection(self):
        source = self.path / "Probe.java"
        source.write_text('public class Probe {'
                          ' public String misleading(StringBuilder s) { return s.substring(0); }'
                          ' public void ignoredCopy(int[] a) { java.util.Arrays.copyOf(a, a.length); } }')
        subprocess.run(['javac', '--release', '17', '-d', 'target/classes', str(source)],
                       cwd=self.path, check=True, capture_output=True)
        result = self.run_runner('spotbugs')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        report = (self.path / 'target/spotbugs.xml').read_text()
        self.assertIn('DMI_MISLEADING_SUBSTRING', report)
        self.assertIn('RV_RETURN_VALUE_IGNORED_NO_SIDE_EFFECT', report)

    def test_real_junit_zero_tests_fails_and_clears_stale_data(self):
        for file in ('jacoco.exec', 'jacoco.xml'):
            (self.path / 'target' / file).write_text('stale')
        result = self.run_runner('jacoco')
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertFalse((self.path / 'target/jacoco.xml').exists())
        self.assertNotEqual(b'stale', (self.path / 'target/jacoco.exec').read_bytes())

    def test_real_jacoco_corrupt_execution_data_fails(self):
        data = self.path / 'target/corrupt.exec'
        data.write_bytes(b'not jacoco data')
        result = subprocess.run([self.java, '-cp', self.cp,
                                 'org.jacoco.cli.internal.Main', 'report', str(data),
                                 '--classfiles', 'target/classes', '--xml', 'target/corrupt.xml'],
                                cwd=self.path, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.path / 'target/corrupt.xml').exists())

    def test_jacoco_test_and_report_failures_reach_cli(self):
        for phase in ('test', 'report'):
            with self.subTest(phase=phase):
                self.stub('java', 'if [[ "$1" == -javaagent:* ]]; then\n'
                          + ('exit 38\n' if phase == 'test' else 'exit 0\n')
                          + 'fi\nexit 39\n')
                result = self.run_runner('jacoco')
                self.assertNotEqual(0, result.returncode)
                self.assertIn('Java quality subprocess failed', result.stderr)


if __name__ == '__main__':
    unittest.main()
