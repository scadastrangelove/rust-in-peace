#!/usr/bin/env python3
"""apply_triage.py — write `/triage` verdicts back onto the SAST queue, joined by `cell_id`.

This is the last hop of the provenance chain:

    cells.jsonl -> SAST-FINDINGS.json -> sast-queue.jsonl -> findings-ledger.jsonl
                                              ^
                                              this script closes it

`run_finder.py` writes `candidate` / `refuted` — a reader's belief. `/triage` then spends N
independent adversarial verifiers per candidate and derives severity from preconditions. That is a
STRICTLY STRONGER label, and collapsing it back onto `candidate` would throw away the only
distinction the eventual mined predictor (queue Step 4) actually wants to learn: which cells produced
findings that SURVIVED refutation, not merely which ones a finder liked.

So the status enum gains one value:

    unread | in-review | candidate | confirmed | refuted | deprioritised
                            ^           ^          ^
                        finder said  triage     either stage
                        "defect"     upheld it  killed it

A triage FALSE_POSITIVE overwrites a finder's `candidate` with `refuted` — that is the correction
working as intended, and it is the labelled negative that makes the positives mean something. The
`triage` block records how close the vote was, because a 2-1 split and a 3-0 sweep are not the same
evidence and a predictor fitted as if they were will be overconfident.

Nothing here decides disclosure. `confirmed` means three readers could not refute it statically; an
independent PoC is still the gate before anything is filed.

Usage:
    python3 apply_triage.py --triage ./TRIAGE.json --queue /tmp/sast-queue.jsonl [--dry-run]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys

# What each triage verdict does to the queue row.
STATUS = {"true_positive": "confirmed", "false_positive": "refuted", "duplicate": "refuted"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--triage", default="./TRIAGE.json")
    ap.add_argument("--queue", default="/tmp/sast-queue.jsonl")
    ap.add_argument("--by", default="triage/apply_triage")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    findings = json.load(open(args.triage))["findings"]
    by_cell: dict[str, dict] = {}
    for f in findings:
        cid = f.get("cell_id")
        if not cid:
            # A finding that lost its cell_id cannot be attributed, and silently dropping it is how
            # the unmineable state this queue exists to fix gets recreated. Say so.
            print(f"WARN: {f.get('id')} carries no cell_id — cannot join to the queue", file=sys.stderr)
            continue
        by_cell[cid] = f

    rows = [json.loads(l) for l in open(args.queue) if l.strip()]
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    applied, changed, unmatched = 0, [], set(by_cell)
    for r in rows:
        f = by_cell.get(r["cell_id"])
        if not f:
            continue
        unmatched.discard(r["cell_id"])
        new = STATUS.get(f["verdict"])
        if not new:
            continue
        if r.get("status") != new:
            changed.append((r["cell_id"], r.get("status"), new))
        r["status"] = new
        r["triage"] = {
            "finding_id": f["id"],
            "verdict": f["verdict"],
            "verify_verdict": f.get("verify_verdict"),
            "severity": f.get("severity"),
            "access_level": f.get("access_level"),
            "confidence": f.get("confidence"),
            # A 2-1 split is weaker evidence than 3-0; keep the shape, not just the winner.
            "votes": f.get("vote_breakdown"),
            "severity_alignment": f.get("severity_alignment"),
            "exclusion_rule": f.get("exclusion_rule"),
            "refute_reasons": f.get("refute_reasons"),
            "first_links": f.get("first_links"),
            "note": ("Static adversarial verification only — no PoC was built or run. `confirmed` "
                     "means N independent verifiers could not refute it, not that it is exploitable."),
        }
        r["updated"], r["by"] = now, args.by
        applied += 1

    for cid in sorted(unmatched):
        print(f"WARN: cell_id not present in queue: {cid}", file=sys.stderr)

    print(json.dumps({
        "queue": args.queue, "rows": len(rows), "triage_findings": len(findings),
        "applied": applied, "unmatched": len(unmatched),
        "status_changes": [{"cell_id": c, "from": a, "to": b} for c, a, b in changed],
        "by_status": {s: sum(1 for r in rows if r.get("status") == s)
                      for s in sorted({r.get("status") for r in rows})},
    }, indent=2))

    if args.dry_run:
        print("dry-run: queue not written")
        return 0
    with open(args.queue, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
