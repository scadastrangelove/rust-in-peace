#!/usr/bin/env python3
"""Fail when a tracked Markdown document points at a missing local path.

This deliberately checks path existence, not heading anchors.  It covers the
root documentation and ``docs/`` tree, where a mistaken ``docs/foo.md`` link
inside ``docs/bar.md`` otherwise survives until someone reads the page on
GitHub.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"!?\[[^\]]*]\(([^)]+)\)")
EXTERNAL_SCHEMES = ("http://", "https://", "mailto:", "data:")


def tracked_documents() -> tuple[Path, ...]:
    proc = subprocess.run(
        ["git", "ls-files", "-z", "*.md"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return tuple(
        ROOT / raw.decode()
        for raw in proc.stdout.split(b"\0")
        if raw
    )


def missing_links() -> list[tuple[Path, int, str]]:
    missing: list[tuple[Path, int, str]] = []
    for document in tracked_documents():
        if not document.exists():
            continue
        for line_no, line in enumerate(
            document.read_text(encoding="utf-8").splitlines(), 1
        ):
            for raw_target in LINK.findall(line):
                target = raw_target.strip().strip("<>")
                path_part = target.split("#", 1)[0]
                if (
                    not path_part
                    or path_part.startswith(EXTERNAL_SCHEMES)
                    or path_part.startswith("/")
                ):
                    continue
                if not (document.parent / path_part).resolve().exists():
                    missing.append((document.relative_to(ROOT), line_no, target))
    return missing


def main() -> int:
    documents = tracked_documents()
    missing = missing_links()
    for document, line_no, target in missing:
        print(f"{document}:{line_no}: missing local link target: {target}")
    if missing:
        print(f"{len(missing)} broken local Markdown link(s)", file=sys.stderr)
        return 1
    print(f"Markdown links OK ({len(documents)} tracked documents)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
