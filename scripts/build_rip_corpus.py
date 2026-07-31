#!/usr/bin/env python3
"""build_rip_corpus.py — turn our own disclosed findings into a labelled rule corpus (W29).

    python3 scripts/build_rip_corpus.py -o corpus/rip-findings.jsonl

Joins `DISCLOSURES.json` (finding id, crate, repo, severity, outcome) with the `file:line` citations
inside each disclosure package's REPORT.md. The result is the other half of the rule-development
ground truth, and in one important respect the better half:

  * **DVRA is web-application shaped** — SQLi, SSRF, IDOR, path traversal, command injection. Good
    for those classes, silent on ours.
  * **Our findings are protocol/parser shaped** — panic on malformed input, unbounded allocation,
    integer overflow, decompression bombs, state-machine and framing defects, in real upstream code
    that real maintainers reviewed. These are the classes this project actually hunts, and nothing
    in DVRA develops a rule for them.

## The same corpus is also the false-positive corpus

Each finding names a crate we have already scanned. A rule that fires once on the line we reported
and 400 times elsewhere in the same crate is measurably over-broad — checkable immediately, on code
where we know the answer. Recall and precision come from the same source.

## What this file will NOT pretend

Most of these findings are almost certainly *not* pattern-visible. The h2 trailers violation and the
rustls QUIC downgrade are protocol logic — a rule for them would be
a rule for "HTTP", i.e. noise. DVRA's oracle labels this axis explicitly (`static_visible`); ours
does not, so every row starts `static_visible: null` and must be triaged by hand before it can be a
rule target. **A corpus that silently assumes its findings are rule-able produces exactly the
over-broad rules this whole exercise exists to avoid.**

There is no "embargo" axis here, and an earlier version that had one was wrong. Every finding is a
valid rule source regardless of how it was filed: the corpus is build-local working data, and what
ships is a generalized rule that names no crate, no file and no line. A GHSA-reported defect teaches
the same mechanism as a public PR.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import Counter

SITE = re.compile(r"\b((?:src|crates|lib|apps)/[A-Za-z0-9_./-]+\.rs):(\d+)")
# Classes we can plausibly express as a pattern, vs ones that need reasoning. Starting hypothesis
# only — every row still needs manual triage before it becomes a rule target.
PATTERNISH = re.compile(
    r"(unwrap|panic|index|slice|overflow|underflow|with_capacity|alloc|unbounded|"
    r"recursion|decompress|bomb|cast|truncat)", re.I)
LOGICAL = re.compile(
    r"(smuggl|desync|downgrade|state|framing|trailer|reconcil|differential|mirror|"
    r"authz|tenant|protocol)", re.I)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("-o", "--out", default="corpus/rip-findings.jsonl")
    args = ap.parse_args()

    repo = pathlib.Path(args.repo)
    disc = json.loads((repo / "DISCLOSURES.json").read_text())

    # finding_id -> merged metadata (one row per artifact upstream; collapse to the finding)
    findings: dict[str, dict] = {}
    for a in disc.get("findings", []):
        fid = a.get("finding_id")
        if not fid:
            continue
        f = findings.setdefault(fid, {
            "finding_id": fid, "crate": a.get("crate"), "repo": a.get("repo"),
            "title": a.get("title"), "severity": a.get("severity"),
            "artifacts": [], "outcomes": set(),
        })
        f["artifacts"].append({"type": a.get("artifact_type"), "id": a.get("identifier"),
                               "url": a.get("url"), "status": a.get("status"),
                               "channel": a.get("channel", "")})
        f["outcomes"].add(a.get("outcome_bucket") or a.get("status") or "unknown")

    # Sites come from the disclosure packages' REPORT.md.
    sites: dict[str, list[tuple[str, int]]] = {}
    for pkg in sorted(repo.glob("*-disclosure")) + sorted(repo.glob("*-pr")):
        found: list[tuple[str, int]] = []
        for md in pkg.glob("*.md"):
            for m in SITE.finditer(md.read_text(errors="ignore")):
                found.append((m.group(1), int(m.group(2))))
        if found:
            sites[pkg.name] = sorted(set(found))

    rows = []
    for fid, f in findings.items():
        # Match a package to a finding by crate-name overlap — crude but the package names are
        # crate-prefixed by convention.
        pkgs = [p for p in sites if f["crate"] and p.startswith(f["crate"].replace("_", "-"))]
        site_list = sorted({s for p in pkgs for s in sites[p]})
        blob = f"{f['title']} {f['finding_id']}"
        rows.append({
            "source": "rust-in-peace",
            "finding_id": fid,
            "crate": f["crate"],
            "repo": f["repo"],
            "title": f["title"],
            "severity": f["severity"],
            "sites": [{"file": s[0], "line": s[1]} for s in site_list],
            "site_label_source": "derived_from_report" if site_list else None,
            # Deliberately unset: our reports carry no static-visibility claim. Triage required.
            "static_visible": None,
            "class_hint": ("patternish" if PATTERNISH.search(blob) else
                           "logical" if LOGICAL.search(blob) else "unknown"),
            "outcomes": sorted(f["outcomes"]),
            "channels": sorted({a.get("channel", "") for a in f["artifacts"]}),
            "artifacts": f["artifacts"],
            "rule_dev_eligible": False,     # never true until static_visible is triaged by hand
        })

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))

    with_sites = [r for r in rows if r["sites"]]
    print(f"{out}: {len(rows)} findings across {len(set(r['crate'] for r in rows))} crates")
    print(f"  with at least one derived site   {len(with_sites)}")
    print(f"  class hint {dict(Counter(r['class_hint'] for r in rows))}")
    print()
    print("  by crate:", dict(Counter(r["crate"] for r in rows).most_common(12)))
    print()
    print("  NOTE: rule_dev_eligible is false for every row. Our reports make no static-visibility")
    print("  claim, and most of these are protocol logic that no pattern can express. Triage the")
    print("  `patternish` rows by hand before writing rules against them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
