"""Offline regression tests for Markdown links and GitHub-style anchors."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import verify_doc_links as checker


class LinkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "docs" / "archive").mkdir(parents=True)
        (self.root / "dev" / "archive").mkdir(parents=True)

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def test_current_and_archived_links_and_url_encoding(self):
        self.write("README.md", "[current](docs/guide.md#some-heading)\n"
                   "[history](docs/archive/old%20doc.md#historical)\n")
        self.write("docs/guide.md", "# Some Heading\n")
        self.write("docs/archive/old doc.md", "# Historical\n")
        self.assertEqual(checker.check(self.root), [])

    def test_missing_file_and_heading(self):
        self.write("README.md", "[missing](docs/absent.md)\n"
                   "[bad](docs/guide.md#wrong)\n")
        self.write("docs/guide.md", "# Existing\n")
        errors = checker.check(self.root)
        self.assertEqual(len(errors), 2)
        self.assertIn("missing local path", errors[0])
        self.assertIn("missing heading", errors[1])

    def test_punctuation_code_and_duplicate_heading_slug(self):
        target = self.write("README.md", "# Intro\n"
                            "## API: " + chr(96) + "packet-xf" + chr(96) + "!\n"
                            "## API: " + chr(96) + "packet-xf" + chr(96) + "!\n"
                            "[one](#api-packet-xf) [two](#api-packet-xf-1)\n")
        self.assertEqual(checker.anchors(target), {
            "intro", "api-packet-xf", "api-packet-xf-1"
        })
        self.assertEqual(checker.check(self.root), [])

    def test_reference_links(self):
        self.write("README.md", "[Guide][go] [Other][]\n"
                   "[go]: docs/guide.md#intro\n"
                   "[Other]: <docs/archive/old.md>\n")
        self.write("docs/guide.md", "# Intro\n")
        self.write("docs/archive/old.md", "# History\n")
        self.assertEqual(checker.check(self.root), [])

    def test_undefined_reference(self):
        self.write("README.md", "[missing][unknown]\n")
        self.assertIn("undefined link reference", "\n".join(checker.check(self.root)))

    def test_ignores_fences_inline_code_and_remote_urls(self):
        backtick = chr(96)
        self.write("README.md",
                   backtick * 3 + "markdown\n[bad](oops.md)\n" + backtick * 3 + "\n"
                   + backtick + "[skip](bad.md)" + backtick + "\n"
                   "<!-- [comment](no.md) -->\n"
                   "[web](https://example.org/bad) [mail](mailto:user@example.org)\n")
        self.assertEqual(checker.check(self.root), [])

    def test_archive_is_also_checked(self):
        self.write("README.md", "# Root\n")
        self.write("docs/archive/old.md", "[missing](../not-here.md)\n")
        self.assertEqual(len(checker.check(self.root)), 1)

    def test_outside_repository_is_invalid(self):
        self.write("README.md", "[outside](../../elsewhere.md)\n")
        self.assertIn("outside repository", "\n".join(checker.check(self.root)))

    def test_help_and_invalid_fixture(self):
        self.assertEqual(checker.main(["--root", str(self.root)]), 0)
        self.write("README.md", "[missing](absent.md)\n")
        self.assertEqual(checker.main(["--root", str(self.root)]), 1)


if __name__ == "__main__":
    unittest.main()
