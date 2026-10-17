"""Guard the distinction between unpublished dry-run metadata and publication."""

import unittest

from verify_release_metadata import validate


class ReleaseMetadataTest(unittest.TestCase):
    def test_candidate_only_permitted_for_dry_run(self):
        text = "## [Unreleased]\n\n## [1.4.0] (unreleased)\n"
        self.assertIn("candidate", validate(text, "1.4.0", True))
        with self.assertRaises(ValueError):
            validate(text, "1.4.0", False)

    def test_dated_release_accepted_in_both_modes(self):
        for dry_run in (True, False):
            self.assertEqual("dated release", validate("## [1.4.0] - 2026-10-17\n",
                                                       "1.4.0", dry_run))

    def test_invalid_or_missing_metadata_fails(self):
        for text in ("## [Unreleased]", "## [1.4.1] (unreleased)",
                     "## [1.4.0] - TBD", "## [1.4.0] - 2026-02-30",
                     "example: ## [1.4.0] (unreleased)", "## [1x4x0] - 2026-10-17"):
            for dry_run in (True, False):
                with self.subTest(text=text, dry_run=dry_run):
                    with self.assertRaises(ValueError):
                        validate(text, "1.4.0", dry_run)

    def test_invalid_version_fails(self):
        with self.assertRaises(ValueError):
            validate("## [bad] (unreleased)", "bad", True)


if __name__ == "__main__":
    unittest.main()
