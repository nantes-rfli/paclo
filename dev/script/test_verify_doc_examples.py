"""Dependency-free regressions for snippet discovery and runner startup."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, call, patch

import verify_doc_examples as verifier


DNS = 'clojure -M:dev:dns-ext -e "(require \'[paclo.proto.dns-ext :as dns-ext]) (dns-ext/register!) (println :dns-ext-ok)"'


class SnippetTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "docs").mkdir()
        self.checks = {
            "c": verifier.Check("clj", "clojure", "(vector? result)"),
            "dns": verifier.Check("dns", "bash"),
        }

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def doc(self, name, language, code):
        return f"<!-- paclo-doc-test: {name} -->\n```{language}\n{code}\n```\n"

    def scan(self, checks=None, required_ids=frozenset()):
        return verifier.discover(self.root, checks or self.checks, required_ids)

    def test_both_languages_and_quoted_command(self):
        self.write("README.md", "# Start\n" + self.doc("c", "clojure", "(vector 1 2)"))
        self.write("docs/usage.md", self.doc("dns", "bash", DNS))
        found = self.scan()
        self.assertEqual(found["c"].code, "(vector 1 2)")
        self.assertEqual(found["dns"].code, DNS)
        self.assertEqual(verifier.dns_argv(found["dns"].code), [
            "clojure", "-M:dev:dns-ext", "-e",
            "(require '[paclo.proto.dns-ext :as dns-ext]) (dns-ext/register!) (println :dns-ext-ok)",
        ])

    def test_heading_change_and_move_within_docs(self):
        self.write("README.md", "# Previous heading\n" + self.doc("c", "clojure", "1"))
        self.write("docs/x.md", self.doc("dns", "bash", DNS))
        self.assertEqual(len(self.scan()), 2)
        self.write("README.md", "# Renamed heading\n")
        (self.root / "docs" / "x.md").rename(self.root / "docs" / "renamed.md")
        self.write("docs/guide.md", self.doc("c", "clojure", "1"))
        self.assertEqual(len(self.scan()), 2)

    def test_archive_ignored_even_for_duplicate_marker(self):
        self.write("README.md", self.doc("c", "clojure", "1") + self.doc("dns", "bash", DNS))
        self.write("docs/archive/history.md", self.doc("c", "clojure", "(future-api)") + self.doc("dns", "bash", "echo historical"))
        self.write("docs/sub/archive/history.md", self.doc("c", "clojure", "(future-api)"))
        self.assertEqual(self.scan()["c"].code, "1")

    def test_missing_required(self):
        self.write("README.md", self.doc("c", "clojure", "1"))
        with self.assertRaisesRegex(AssertionError, "missing documentation test IDs: dns"):
            self.scan(required_ids={"c", "dns"})

    def test_missing_definition(self):
        self.write("README.md", self.doc("c", "clojure", "1"))
        with self.assertRaisesRegex(AssertionError, "missing required check definitions"):
            self.scan(required_ids={"unknown"})

    def test_duplicate_id_in_current_docs(self):
        self.write("README.md", self.doc("c", "clojure", "1") + self.doc("c", "clojure", "2"))
        with self.assertRaisesRegex(AssertionError, "duplicate test ID: c"):
            self.scan()

    def test_unknown_id(self):
        self.write("README.md", self.doc("unregistered", "clojure", "1"))
        with self.assertRaisesRegex(AssertionError, "unregistered test ID"):
            self.scan()

    def test_wrong_fence_language(self):
        self.write("README.md", self.doc("c", "bash", "echo no"))
        with self.assertRaisesRegex(AssertionError, "requires clojure, got bash"):
            self.scan()

    def test_intervening_prose(self):
        self.write("README.md", "<!-- paclo-doc-test: c -->\nExplanation\n```clojure\n1\n```\n")
        with self.assertRaisesRegex(AssertionError, "must precede a code fence"):
            self.scan()

    def test_fence_missing_unclosed_and_empty(self):
        for fragment, expected in (
            ("<!-- paclo-doc-test: c -->", "must precede a code fence"),
            ("<!-- paclo-doc-test: c -->\n```clojure\n1", "unclosed code fence"),
            (self.doc("c", "clojure", ""), "empty code fence"),
        ):
            with self.subTest(fragment=fragment):
                self.write("README.md", fragment)
                with self.assertRaisesRegex(AssertionError, expected):
                    self.scan()

    def test_bad_marker(self):
        self.write("README.md", "<!-- paclo-doc-test: c --> trailing\n")
        with self.assertRaisesRegex(AssertionError, "malformed test marker"):
            self.scan()

    def test_new_registered_id(self):
        self.write("README.md", self.doc("c", "clojure", "1") + self.doc("new-one", "clojure", "2"))
        checks = {"c": self.checks["c"], "new-one": verifier.Check("next", "clojure", "(= result 2)")}
        self.assertEqual(set(self.scan(checks=checks, required_ids={"c"})), {"c", "new-one"})

    def test_reject_unsafe_bash(self):
        for command in (
            DNS + "\necho next", DNS + " && echo next", DNS + ";echo next",
            DNS + " | cat", DNS + " > /tmp/output", DNS + " $(id)",
            "echo :dns-ext-ok", "python3 -c 'print(1)'", DNS.replace(":dns-ext-ok", "$HOME"),
        ):
            with self.subTest(command=command), self.assertRaises(ValueError):
                verifier.dns_argv(command)


class RunnerStartupTests(unittest.TestCase):
    def test_classpath_prepared_before_parallel_workers(self):
        calls = Mock()
        with patch.object(verifier, "discover", return_value={}), \
             patch.object(verifier, "CHECKS", {}), \
             patch.object(verifier, "execute") as prepare, \
             patch.object(verifier, "ThreadPoolExecutor") as pool, \
             patch("builtins.print"):
            calls.attach_mock(prepare, "prepare")
            calls.attach_mock(pool, "pool")
            verifier.main()
        self.assertEqual(calls.mock_calls[:2], [
            call.prepare("Prepare documentation classpath", ["clojure", "-P", "-M:dev:dns-ext"]),
            call.pool(max_workers=verifier.MAX_WORKERS),
        ])

    def test_preparation_failure_stops_before_parallel_start(self):
        with patch.object(verifier, "discover", return_value={}), \
             patch.object(verifier, "execute", side_effect=RuntimeError("classpath unavailable")), \
             patch.object(verifier, "ThreadPoolExecutor") as pool:
            with self.assertRaisesRegex(RuntimeError, "classpath unavailable"):
                verifier.main()
            pool.assert_not_called()


if __name__ == "__main__":
    unittest.main()
