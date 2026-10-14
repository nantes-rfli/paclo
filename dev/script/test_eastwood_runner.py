"""Exercise the CI Eastwood entrypoint in isolated JVMs, including real failures."""

import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class EastwoodRunnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        classpath = subprocess.run(
            ["clojure", "-Spath", "-A:eastwood"], cwd=ROOT,
            check=True, capture_output=True, text=True, timeout=120,
        ).stdout.strip()
        cls.classpath = os.pathsep.join(
            str((ROOT / entry).resolve()) for entry in classpath.split(os.pathsep)
        )

    def run_runner(self, first_form, second_form=None):
        with tempfile.TemporaryDirectory(prefix="paclo-eastwood-") as directory:
            path = pathlib.Path(directory)
            (path / "probe.clj").write_text(
                "(ns probe)\n" + first_form + "\n", encoding="utf-8",
            )
            if second_form is not None:
                (path / "dependent.clj").write_text(
                    "(ns dependent (:require [probe]))\n" + second_form + "\n",
                    encoding="utf-8",
                )
            # Override only fixture roots. Keep the production linters/excludes
            # and invoke exactly the -main used by clojure -M:eastwood in CI.
            expression = """
            (require 'eastwood-runner)
            (with-redefs [eastwood-runner/lint-options
                          (assoc eastwood-runner/lint-options
                                 :source-paths [(System/getenv "PACLO_EASTWOOD_FIXTURE")]
                                 :test-paths [])]
              (eastwood-runner/-main))
            """
            result = subprocess.run(
                ["java", "-cp", self.classpath + os.pathsep + directory,
                 "clojure.main", "-e", expression],
                cwd=path, env={**os.environ, "PACLO_EASTWOOD_FIXTURE": directory},
                capture_output=True, text=True, timeout=60,
            )
            return result.returncode, result.stdout + result.stderr

    def test_complete_analysis_succeeds(self):
        code, output = self.run_runner("(def value 1)", "(def value probe/value)")
        self.assertEqual(0, code, output)
        self.assertIn("== Linting dependent ==", output)
        self.assertIn("Exceptions thrown: 0", output)

    def test_analysis_exception_and_unanalyzed_namespace_fail(self):
        code, output = self.run_runner(
            "(def value (paclo.missing.Binding.))", "(def value probe/value)",
        )
        self.assertNotEqual(0, code, output)
        self.assertIn("Exceptions thrown: 1", output)
        self.assertIn("1 namespaces left unanalyzed", output)
        self.assertNotIn("== Linting dependent ==", output)
        self.assertIn("Eastwood analysis failed", output)
        print(f"Negative analysis probe: exit {code}; one namespace unanalyzed")

    def test_evaluation_exception_fails(self):
        code, output = self.run_runner('(throw (ex-info "probe failure" {}))')
        self.assertNotEqual(0, code, output)
        self.assertIn("probe failure", output)
        self.assertIn("Eastwood analysis failed", output)

    def test_warnings_remain_informational(self):
        code, output = self.run_runner("(defn value [] (= 1))")
        self.assertEqual(0, code, output)
        self.assertIn("suspicious-expression:", output)
        self.assertIn("Exceptions thrown: 0", output)


if __name__ == "__main__":
    unittest.main()
