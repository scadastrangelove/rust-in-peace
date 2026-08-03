#!/usr/bin/env python3
"""finder_to_triage.py — bridge run_finder.py output into the `/triage` ingest shape.

`/triage` recognises a `{findings: [...]}` container and maps source keys onto its canonical fields.
The finder writes its own schema (verdict/defect/reachability/trigger/consequence/...), so without
this adapter the two stages do not meet and the candidates would have to be re-typed by hand — which
is exactly where provenance gets dropped.

Two things this file is careful about:

  * **`cell_id` survives the hop.** It is the join key from `cells.jsonl` all the way to the ledger,
    and it is what makes the eventual `candidate`/`refuted` labels attributable to the cell that
    produced them. A bridge that loses it re-creates the unmineable state the queue exists to fix.
  * **Severity is NOT carried over.** The finder reports a CONSEQUENCE (panic / oob / resource
    exhaustion); deriving how bad that is from preconditions and reachability is `/triage` Phase 4's
    job, and pre-filling it would let a finder's optimism survive verification unexamined. Every
    record therefore goes in as `severity: "unknown"` with `candidate: true`.

Usage:
    python3 finder_to_triage.py --in /tmp/sast-finder-findings.json \
        --out /tmp/SAST-FINDINGS.json [--only candidate]
"""
from __future__ import annotations

import argparse
import json
import re

# "…at src/foo.rs:214" / "src/foo.rs:214-220" / "`src/foo.rs:214`"
LOC = re.compile(r"([\w./\-]+\.rs):(\d+)")


def split_loc(text: str | None) -> tuple[str | None, int | None]:
    if not text:
        return None, None
    m = LOC.search(text)
    return (m.group(1), int(m.group(2))) if m else (None, None)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", default="/tmp/sast-finder-findings.json")
    ap.add_argument("--out", dest="dst", default="/tmp/SAST-FINDINGS.json")
    ap.add_argument("--only", default="candidate",
                    help="verdicts to forward (comma-separated); 'all' forwards everything")
    args = ap.parse_args()

    raw = json.load(open(args.src))
    want = None if args.only == "all" else {v.strip() for v in args.only.split(",")}

    findings, skipped = [], 0
    for i, v in enumerate(raw, 1):
        if want is not None and v.get("verdict") not in want:
            skipped += 1
            continue
        f, ln = split_loc(v.get("defect"))
        if f is None:
            f, ln = split_loc(v.get("evidence"))
        crate = v["cell_id"].split("@", 1)[0]
        findings.append({
            "id": f"find{i:03d}",
            "cell_id": v["cell_id"],                 # provenance — do not drop
            "crate": crate,
            "file": f,
            "line": ln,
            "category": v.get("consequence") or "unknown",
            # Derived by /triage Phase 4 from preconditions + reachability, never carried in.
            "severity": "unknown",
            "candidate": True,
            "finder_confidence": v.get("confidence"),
            "title": (v.get("defect") or "")[:200] or f"candidate in {crate}",
            "description": (
                f"{v.get('evidence') or ''}\n\n"
                f"REACHABILITY (as traced by the finder): {v.get('reachability') or 'not established'}\n"
                f"WHAT WOULD DISPROVE IT: {v.get('disproof') or 'not stated'}\n"
                f"NOT READ: {v.get('unread') or 'not stated'}"
            ).strip(),
            "exploit_scenario": v.get("trigger") or None,
            # Says out loud what `candidate` means, so a reader of this file alone cannot mistake it
            # for a verified finding.
            "note": ("A finder read the source and believes this is a defect. NOT verified: no "
                     "independent proof of concept exists yet, and the reachability above is the "
                     "finder's own trace. /triage must attempt to refute it."),
        })

    out = {
        "tool": "sast-finder",
        "note": ("Candidates from the finder stage of the SAST queue. Unverified by construction — "
                 "each carries the cell_id it came from so the triage verdict can be written back "
                 "onto that cell."),
        "findings": findings,
    }
    with open(args.dst, "w") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)
    print(json.dumps({"written": args.dst, "findings": len(findings), "skipped": skipped,
                      "with_file_line": sum(1 for f in findings if f["file"]),
                      "by_category": {c: sum(1 for f in findings if f["category"] == c)
                                      for c in sorted({f["category"] for f in findings})}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
