#!/usr/bin/env python3
"""Validate changelog metadata; this command never builds or publishes."""

import argparse
from datetime import date
from pathlib import Path
import re


def validate(changelog, version, dry_run):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError(f"Invalid version: {version}")
    if dry_run and f"## [{version}] (unreleased)" in changelog.splitlines():
        return "unreleased candidate (dry-run only)"
    heading = re.search(rf"^## \[{re.escape(version)}\] - (\d{{4}}-\d{{2}}-\d{{2}})$",
                        changelog, re.MULTILINE)
    if heading:
        date.fromisoformat(heading.group(1))
        return "dated release"
    raise ValueError(f"CHANGELOG.md requires a dated section for {version}; "
                     "only dry-run accepts an explicitly unreleased candidate")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        print(validate(Path("CHANGELOG.md").read_text(), args.version, args.dry_run))
    except ValueError as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
