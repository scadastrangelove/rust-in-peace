#!/usr/bin/env python3
"""apply_prioritisation.py — write /sast-prioritise verdicts back into the stateful queue.

An agent call whose output is not persisted converts budget into nothing and leaves the corpus
exactly as unlabelled as before. This is the step that makes the queue a LABEL STORE rather than a
work list: `agent_priority` is the first column a future mined predictor can be fit against, and
`cell_id` is the join key that E13 never recorded.

Nothing is ever deleted or reordered out of existence. A `low` verdict sets the priority and the
reason and leaves the row in the queue — priority is an ORDER, never a CUT.
"""
from __future__ import annotations

import argparse
import collections
import datetime as _dt
import json


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", required=True)
    ap.add_argument("--verdicts", required=True, help="JSON list from the prioritise agents")
    ap.add_argument("--by", default="sast-prioritise")
    args = ap.parse_args()

    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    verdicts = {v["cell_id"]: v for v in json.load(open(args.verdicts))}

    rows, applied, missing = [], 0, []
    for line in open(args.queue):
        if not line.strip():
            continue
        r = json.loads(line)
        v = verdicts.pop(r["cell_id"], None)
        if v and r.get("status") in ("candidate", "refuted"):
            # A finder pass has already spoken about this cell. Ranking is a judgement about WORTH
            # and must never overwrite a judgement about TRUTH — otherwise a later cheap pass can
            # silently erase an expensive one, and the label store stops being a record.
            print(f"  skip {r['cell_id']}: finder verdict '{r['status']}' present; not overwriting")
            v = None
        if v:
            r["agent_priority"] = v.get("priority")
            r["agent_reason"] = v.get("reason")
            r["question"] = v.get("question")
            r["reachable_from"] = v.get("reachable_from")
            r["unread_note"] = v.get("unread")
            r["status"] = "in-review"      # a verdict on WORTH, never on truth — only a finder may
            r["updated"] = now             # move a cell to candidate/refuted
            r["by"] = args.by
            applied += 1
        rows.append(r)
    missing = list(verdicts)

    with open(args.queue, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    judged = [r for r in rows if r.get("agent_priority")]
    # Agreement between the PRIOR and the agent is the first evidence about whether the priors are
    # any good — and the seed of the predictor that will replace them.
    agree = collections.Counter()
    for r in judged:
        high_prior = r["prior"] >= 0.6
        high_agent = r["agent_priority"] == "high"
        agree[("prior_high" if high_prior else "prior_low",
               "agent_high" if high_agent else "agent_not_high")] += 1

    print(json.dumps({
        "queue": args.queue,
        "applied": applied,
        "verdicts_with_no_matching_cell": missing,
        "judged_total": len(judged),
        "by_agent_priority": dict(collections.Counter(r["agent_priority"] for r in judged)),
        "prior_vs_agent": {f"{k[0]}/{k[1]}": v for k, v in agree.items()},
        "still_unread": sum(1 for r in rows if r["status"] == "unread"),
        "queue_total": len(rows),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
