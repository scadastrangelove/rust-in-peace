#!/usr/bin/env python3
"""fetch_fix_regions.py — recover defect locations from the fix PRs we filed.

    python3 scripts/fetch_fix_regions.py -o corpus/fix-regions.jsonl [--crate miniz_oxide ...]

`DISCLOSURES.json` records artifacts, not locations, and only 17 findings have a local disclosure
package. But **42 of our 58 findings were filed as public issues/PRs**, and a PR carries a diff —
which is a better location source than any prose citation:

  * it is authoritative (it is where the fix actually went), and
  * per `docs/variant-analysis.md` the fix commit "pins the exact control that was added", making it
    the highest-grade seed for variant analysis: the thing you diff every sibling against.

## Region, not point

A fix PR touches scaffolding as well as the defect — new fields, new public API, docs, tests. So each
hunk is a *region* in which the defect lived, not the defect line. That is enough for the question a
rule gate needs to answer — "did the rule fire inside the region the fix touched?" — and it is
honest about what it is: `granularity: "fix-hunk"`, never `"defect-line"`.

## Every finding is a valid source

An earlier version fetched public artifacts only, on an "embargo" argument that does not hold: what
embargo restricts is *publication*, and nothing here is published. The corpus is build-local working
data; what ships is a generalized rule naming no crate, file or line. A defect reported through a
private advisory teaches exactly the same mechanism as one reported through a public PR, so both are
fetched.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def pr_diff(repo: str, number: str) -> str | None:
    try:
        r = subprocess.run(["gh", "pr", "diff", number, "--repo", repo],
                           capture_output=True, text=True, timeout=90)
        return r.stdout if r.returncode == 0 and r.stdout.strip() else None
    except Exception:                                        # noqa: BLE001
        return None


def regions(diff: str) -> list[dict]:
    out, cur = [], None
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            cur = line[6:].strip()
            if cur == "/dev/null":
                cur = None
        elif line.startswith("@@") and cur:
            m = HUNK.match(line)
            if not m:
                continue
            start = int(m.group(1))
            span = int(m.group(2) or 1)
            out.append({"file": cur, "start": start, "end": start + max(span - 1, 0)})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", default="corpus/fix-regions.jsonl")
    ap.add_argument("--crate", action="append", default=None)
    ap.add_argument("--repo-root", default=".")
    args = ap.parse_args()

    disc = json.loads((pathlib.Path(args.repo_root) / "DISCLOSURES.json").read_text())
    rows, skipped = [], {"not_pr": 0, "no_diff": 0}

    for a in disc.get("findings", []):
        if a.get("artifact_type") != "pr":
            skipped["not_pr"] += 1
            continue
        if args.crate and a.get("crate") not in args.crate:
            continue
        repo, num = a.get("repo"), str(a.get("identifier") or "")
        if not repo or not num.isdigit():
            continue
        d = pr_diff(repo, num)
        if not d:
            skipped["no_diff"] += 1
            print(f"  · no diff: {repo}#{num}", file=sys.stderr)
            continue
        reg = [r for r in regions(d)
               if r["file"].endswith(".rs")
               and not re.search(r"(^|/)(tests?|benches?|examples|fuzz)/", r["file"])]
        if not reg:
            continue
        rows.append({
            "finding_id": a.get("finding_id"), "crate": a.get("crate"), "repo": repo,
            "pr": num, "url": a.get("url"), "title": a.get("title"),
            "granularity": "fix-hunk",          # a REGION the fix touched, not the defect line
            "label_source": "public_pr_diff",
            "regions": reg,
        })
        print(f"  ✓ {a.get('crate'):<14}#{num:<6}{len(reg)} hunks", file=sys.stderr)

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"\n{out}: {len(rows)} fix PRs, "
          f"{sum(len(r['regions']) for r in rows)} hunks across "
          f"{len({r['crate'] for r in rows})} crates")
    print(f"skipped: {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
