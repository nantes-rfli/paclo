#!/usr/bin/env python3
"""Check local Markdown paths and GitHub-style heading anchors without network.

Supports inline links/images, reference links/definitions, and local fragments.
Ignores fenced code, inline code, and HTML comments.
"""

import argparse
from collections import Counter
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

FENCE = re.compile(r"^\s{0,3}(\x60{3,}|~{3,})(.*)$")
HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
INLINE = re.compile(r"!?\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)(?:\s+[^)]*)?\)")
REFERENCE = re.compile(r"!?\[([^\]\n]+)\]\[([^\]\n]*)\]")
DEFINITION = re.compile(r"^\s{0,3}\[([^\]]+)\]:\s*(<[^>]+>|\S+)")
INLINE_CODE = re.compile(r"(\x60+)(.*?)\1")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def documents(root):
    """Current and archived docs; exclude source and test fixtures."""
    paths = [root / n for n in ("README.md", "CHANGELOG.md", "AGENTS.md", "CONTRIBUTING.md")]
    paths += list((root / "docs").rglob("*.md"))
    paths += list((root / "dev").glob("*.md"))
    paths += list((root / "dev" / "archive").rglob("*.md"))
    return sorted(p for p in set(paths) if p.is_file())


def visible_lines(content, strip_inline=True):
    """Drop code fences and HTML comments, preserving source line numbers."""
    content = HTML_COMMENT.sub(lambda m: "\n" * m.group().count("\n"), content)
    fence_char = None
    fence_len = 0
    for line_no, line in enumerate(content.splitlines(), start=1):
        match = FENCE.match(line)
        if fence_char:
            if match and match.group(1)[0] == fence_char and len(match.group(1)) >= fence_len and not match.group(2).strip():
                fence_char = None
            yield line_no, ""
        elif match:
            fence_char = match.group(1)[0]
            fence_len = len(match.group(1))
            yield line_no, ""
        else:
            yield line_no, INLINE_CODE.sub("", line) if strip_inline else line


def heading_slug(text):
    text = re.sub(r"<[^>]*>", "", text)
    text = re.sub(r"!?\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = text.replace(chr(96), "").lower().strip()
    text = "".join(c for c in text if c.isalnum() or c in " _-\t")
    return re.sub(r"\s", "-", text)


def anchors(path):
    seen = Counter()
    result = set()
    previous = None
    for _, line in visible_lines(path.read_text(encoding="utf-8"), strip_inline=False):
        match = HEADING.match(line)
        heading = match.group(1) if match else None
        if not heading and previous and re.fullmatch(r"\s{0,3}(=+|-+)\s*", line):
            heading = previous.strip()
        if heading:
            slug = heading_slug(heading)
            suffix = seen[slug]
            seen[slug] += 1
            result.add(slug if not suffix else f"{slug}-{suffix}")
        previous = line if line.strip() else None
    return result


def check(root):
    errors = []
    cache = {}

    def validate(source, number, destination):
        destination = destination.strip("<>")
        parsed = urlsplit(destination)
        if parsed.scheme or parsed.netloc or destination.startswith("//"):
            return  # No network validation of external URLs or mailto.
        path_text = unquote(parsed.path)
        fragment = unquote(parsed.fragment)
        target = (source.parent / path_text).resolve() if path_text else source
        if not target.is_relative_to(root.resolve()):
            errors.append(f"{source.relative_to(root)}:{number}: outside repository: {destination}")
            return
        if not target.exists():
            errors.append(f"{source.relative_to(root)}:{number}: missing local path: {destination}")
            return
        if fragment:
            if target.is_dir():
                target = target / "README.md"
            if target.suffix.lower() not in (".md", ".markdown") or not target.is_file():
                errors.append(f"{source.relative_to(root)}:{number}: anchor on non-Markdown: {destination}")
                return
            if target not in cache:
                cache[target] = anchors(target)
            if fragment not in cache[target]:
                errors.append(f"{source.relative_to(root)}:{number}: missing heading #{fragment}: {destination}")

    for source in documents(root):
        lines = list(visible_lines(source.read_text(encoding="utf-8")))
        refs = {}
        for number, line in lines:
            definition = DEFINITION.match(line)
            if definition:
                label = " ".join(definition.group(1).lower().split())
                refs[label] = definition.group(2)
                validate(source, number, definition.group(2))
        for number, line in lines:
            if DEFINITION.match(line):
                continue
            for match in INLINE.finditer(line):
                validate(source, number, match.group(1))
            for match in REFERENCE.finditer(line):
                label = " ".join((match.group(2) or match.group(1)).lower().split())
                if label not in refs:
                    errors.append(f"{source.relative_to(root)}:{number}: undefined link reference: {label}")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2],
                        help="Repository root")
    args = parser.parse_args(argv)
    problems = check(args.root.resolve())
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f"FAIL: {len(problems)} local Markdown link problems", file=sys.stderr)
        return 1
    print("PASS: local Markdown links and heading anchors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
