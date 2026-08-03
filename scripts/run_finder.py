#!/usr/bin/env python3
"""run_finder.py — spend a FINDER pass on the cells prioritisation selected.

This is the stage that finally produces the label the whole queue exists to collect. Prioritisation
answers "is this worth reading"; a finder answers "is there a defect here", and writes back
`candidate` or `refuted`. Those two values — not the `high/medium/low` of the prioritiser — are the
ground truth a mined predictor can be fitted on (queue Step 4).

Two disciplines carried over from the rest of the layer, both learned the expensive way:

  * **A finder verdict is TRIAGE, not truth.** `candidate` means a reader who read the code believes
    there is a defect. It does not survive into a disclosure without an INDEPENDENT proof of concept —
    that gate is what caught the over-claims in every campaign that skipped it. The status name says
    `candidate` for exactly this reason.
  * **The question comes from the previous stage.** The prioritiser already read the module and wrote
    one specific question. A finder that ignores it and re-derives the surface wastes the pass; a
    finder that answers ONLY it misses the neighbourhood. The brief below says additive, never
    restrictive — the same rule that keeps SAST cells from narrowing the blind pass.

Environment is sourced by the caller (never by this script):
    . ~/.rip-proxy && . ~/.rip-auth

Usage:
    python3 run_finder.py --queue /tmp/sast-queue.jsonl --priority high,medium \
        [--crates a,b,c] [--top N] [--concurrency 4] [--dry-run]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as _dt
import json
import os
import re
import subprocess
import sys

PROMPT = """You are reviewing a specific piece of Rust code for a SECURITY DEFECT. A previous pass \
already established that this module is worth reading and wrote the question below. Your job is to \
answer it from the source, and to report what you find honestly — including "nothing".

Repo root: {root}
Read/Grep only. Do NOT execute anything, do not modify files.
{strip_note}
CELL
  id:       {cell_id}
  crate:    {crate}    class: {cls}    module: {module}
  evidence: {hits} static-analysis hits — TOOL OUTPUT, not findings. Most are noise.
  sites:    {sites}

THE QUESTION FROM TRIAGE (answer this first):
  {question}

Reachability the previous pass traced: {reach}
Its reasoning: {reason}

ADDITIVE, NOT RESTRICTIVE: attend to that question, but do not restrict yourself to it. If you find a \
different real defect while reading this module, report that instead — a finder told to look only \
where the previous pass pointed loses exactly the unexpected-class recall this layer exists for.

────────────────────────────────────────────────────────────────────
STEP 1. Answer the question from the source. Quote the lines that settle it.
STEP 2. If you believe there IS a defect, establish and state, separately:
    - the DEFECT: what invariant is broken, at file:line
    - REACHABILITY: the concrete path from an untrusted input to that line, naming each hop. If you \
cannot trace one, say so — an unreachable defect is not a finding.
    - the TRIGGER: what an attacker must supply. Be concrete (a byte sequence, a frame, a header).
    - the CONSEQUENCE: panic / hang / OOB / silent corruption / resource exhaustion. Do not inflate: \
a bounds-checked panic in safe Rust is a DoS, not memory corruption.
    - WHAT WOULD DISPROVE IT: the guard you looked for and did not find, and where it would live.
STEP 3. If you do NOT believe there is a defect, say `refuted` and give the guard that makes it safe, \
with its file:line. "I could not find anything" without naming the guard is `unknown`, not `refuted`.
STEP 4. State what you did not read.

Be willing to return `refuted`. Most cells are noise, the previous pass only ranked worth, and a \
finder that never refutes is not reading.

Return JSON only, no prose around it:
{{"cell_id":"{cell_id}","verdict":"candidate|refuted|unknown",\
"defect":"one sentence at file:line, or null","reachability":"path or null","trigger":"or null",\
"consequence":"panic|hang|oob|corruption|resource-exhaustion|none","confidence":"low|medium|high",\
"disproof":"the guard whose absence this rests on","evidence":"2-4 sentences quoting the source",\
"unread":"what you did not look at"}}"""


def build_prompt(row: dict, src_root: str) -> str:
    module = str(row.get("module", ""))
    strip = ("(Site paths are prefixed `work/` — strip it: `work/src/...` is `src/...` under the repo "
             "root.)\n" if module.startswith("work/") else "")
    sites = row.get("sites") or {}
    flat = [s for v in sites.values() for s in v] if isinstance(sites, dict) else []
    return PROMPT.format(
        root=os.path.join(src_root, row["crate"]), strip_note=strip,
        cell_id=row["cell_id"], crate=row["crate"], cls=row.get("class"), module=module,
        hits=row.get("hits"), sites=json.dumps(flat[:40]),
        question=row.get("question") or "(none recorded — derive one from the sites)",
        reach=row.get("reachable_from") or "(not established)",
        reason=(row.get("agent_reason") or "(none)")[:400],
    )


def find(row: dict, src_root: str, timeout: int) -> dict:
    try:
        r = subprocess.run(["claude", "-p", build_prompt(row, src_root), "--output-format", "text"],
                           capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"cell_id": row["cell_id"], "verdict": "unknown",
                "evidence": f"finder timed out after {timeout}s", "unread": "everything"}
    m = re.search(r"\{.*\}", r.stdout.strip(), re.S)
    if not m:
        return {"cell_id": row["cell_id"], "verdict": "unknown",
                "evidence": f"no JSON in finder output (rc={r.returncode}): {r.stdout[:200]}",
                "unread": "everything"}
    try:
        v = json.loads(m.group(0))
    except Exception as exc:                                        # noqa: BLE001
        return {"cell_id": row["cell_id"], "verdict": "unknown",
                "evidence": f"unparseable finder JSON: {exc}", "unread": "everything"}
    v["cell_id"] = row["cell_id"]
    return v


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", default="/tmp/sast-queue.jsonl")
    ap.add_argument("--src-root", default=os.path.expanduser("~/rip-sast/work/src"))
    ap.add_argument("--priority", default="high,medium")
    ap.add_argument("--crates")
    ap.add_argument("--top", type=int, default=100)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--findings-out", default="/tmp/sast-finder-findings.json")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not (os.environ.get("CLAUDE_CODE_OAUTH_TOKEN") or os.environ.get("ANTHROPIC_API_KEY")):
        print("no credentials in env — source ~/.rip-auth first", file=sys.stderr)
        return 2

    rows = [json.loads(l) for l in open(args.queue) if l.strip()]
    want_pri = {p.strip() for p in args.priority.split(",") if p.strip()}
    want_crates = {c.strip() for c in args.crates.split(",")} if args.crates else None

    # Only cells a prioritiser has ALREADY judged, and only those it ranked worth reading. A cell that
    # already carries a finder verdict is skipped — the queue is state, and a second pass must not
    # redo it.
    pool = [r for r in rows
            if r.get("agent_priority") in want_pri
            and r.get("status") not in ("candidate", "refuted")
            and (want_crates is None or r["crate"] in want_crates)]
    order = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    pool.sort(key=lambda r: (order.get(r.get("agent_priority"), 9), -r.get("prior", 0)))
    todo = pool[:args.top]

    print(json.dumps({"selected": len(todo), "left_in_filter": len(pool) - len(todo),
                      "by_priority": {p: sum(1 for r in todo if r.get("agent_priority") == p)
                                      for p in sorted(want_pri)}}, indent=2))
    if args.dry_run or not todo:
        for r in todo:
            print(f"  {r.get('agent_priority'):<7} {r['crate']:<12} {r.get('class'):<14} {r.get('module')}")
        return 0

    out = []
    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = {ex.submit(find, r, args.src_root, args.timeout): r for r in todo}
        for f in cf.as_completed(futs):
            v = f.result()
            out.append(v)
            print(f"  {v.get('verdict','?'):<10} {v.get('consequence','-'):<20} {v['cell_id'][:60]}",
                  flush=True)

    # Write the finder verdicts back — this is the ground-truth label the queue exists to collect.
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    by_id = {v["cell_id"]: v for v in out}
    n = 0
    for r in rows:
        v = by_id.get(r["cell_id"])
        if not v:
            continue
        verdict = v.get("verdict")
        if verdict in ("candidate", "refuted"):
            r["status"] = verdict
            n += 1
        r["verdict"] = {k: v.get(k) for k in
                        ("defect", "reachability", "trigger", "consequence", "confidence",
                         "disproof", "evidence", "unread")}
        r["updated"] = now
        r["by"] = "sast-finder/run_finder"
    with open(args.queue, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(args.findings_out, "w") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)

    counts: dict[str, int] = {}
    for v in out:
        counts[v.get("verdict", "?")] = counts.get(v.get("verdict", "?"), 0) + 1
    print(json.dumps({"finder_verdicts": counts, "queue_rows_labelled": n,
                      "findings": args.findings_out,
                      "note": "candidate = a reader believes there is a defect. NOT confirmed — an "
                              "independent PoC is still required before this becomes a finding."},
                     indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
