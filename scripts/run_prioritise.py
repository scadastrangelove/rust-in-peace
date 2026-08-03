#!/usr/bin/env python3
"""run_prioritise.py — the /sast-prioritise stage as a PIPELINE STEP, not a session.

Reads the stateful queue, takes the top-N `unread` cells by prior, spawns one `claude -p` per cell to
judge WORTH (never truth), and writes the verdicts straight back through
`scripts/apply_prioritisation.py`. Running it twice advances the queue; it never redoes a judged cell.

Why this file exists rather than an operator driving agents by hand: a judgement that lives in a chat
transcript is not state. The corpus is 3205 cells — it will be worked through over many passes, and
"which cells has anyone actually looked at" has to survive the session that looked at them.

Environment (both are sourced by the caller, not by this script — it never touches credentials):
    . ~/.rip-proxy      egress to api.anthropic.com
    . ~/.rip-auth       CLAUDE_CODE_OAUTH_TOKEN

Usage:
    python3 run_prioritise.py --queue /tmp/sast-queue.jsonl --src-root ~/rip-sast/work/src \
        --top 20 [--class coverage-gap] [--crate object] [--concurrency 4] [--dry-run]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
import tempfile

# The rubric differs per family because the signal differs per family — see build_sast_queue.prior_for.
RUBRIC = {
    "coverage-gap": (
        "NO rule fired anywhere in this file. Does it contain reachable logic (parsing, arithmetic on "
        "parsed values, indexing, unsafe), or is it data/boilerplate/tests/doc-examples? Doc examples "
        "(`///`) and `#[cfg(test)]` are NOT sinks — if the hits are there, say so plainly; that is the "
        "useful answer. Also check platform gating (`#[cfg(windows)]`): code that never compiles on the "
        "scanned platform explains the silence and is not a risk signal."
    ),
    "limit-pair": (
        "A cap is declared {declared}x and enforced {enforced}x in this module. Is there a path that "
        "reaches a guarded operation WITHOUT consulting the cap? Beware the measured false signal: in a "
        "format-DEFINITIONS module (struct fields, protocol constants) zero enforcement is the correct "
        "shape, not an asymmetry — enforcement lives in the readers. Say so if that is the case."
    ),
    "index-surface": (
        "Is this class of operation, in THIS module, on a path that consumes untrusted input? A rare "
        "rule firing in a parser is worth more than a common rule anywhere. Const-bounded table lookups "
        "and type-bounded indices (`b as usize` into a 256-entry array) are the archetypal misfire."
    ),
}
DEFAULT_RUBRIC = (
    "Is this class of operation, in THIS module, on a path that consumes untrusted input? Distinguish a "
    "real defect shape from a rule that matched on syntax alone."
)

PROMPT = """You are deciding whether a static-analysis CELL is worth a security reviewer's time, and \
what question that reviewer should arrive with. You are NOT deciding whether a bug exists — no \
verdict, no finding report.

Repo root: {root}
Read/Grep only. Do NOT execute anything.
{strip_note}
CELL
  id:      {cell_id}
  crate:   {crate}   class: {cls}   module: {module}   data path: {dpath}
  evidence: {hits} hits from {engines}
  rules:   {rules}
  sites:   {sites}
  prior:   {prior} from {terms}   <- measured directions, NOT a mined rule. The prior chose the
           reading order; it is not evidence about the code. Reproducing it instead of reading is
           worth nothing.

FAMILY RUBRIC: {rubric}

STEP 1. Read enough to answer: what does this code DO, and is it on a path that sees attacker-\
controlled bytes? Name the entry point you traced to, or say you could not find one.
STEP 2. Assign PRIORITY, and be willing to say `low`:
  high    reachable from untrusted input AND the shape could plausibly break there
  medium  reachable, but the shape looks guarded or the class is weak here
  low     not attacker-reachable, or structurally uninteresting (data tables, generated code, tests,
          doc examples, platform-gated code)
  unknown could not establish reachability; say what is missing
STEP 3. Write the QUESTION a finder should arrive with — ONE sentence, specific, naming a function \
and line. "Check for bugs" is a non-answer. If there is nothing to ask, say exactly that.
STEP 4. State what you did NOT read, and what would change your priority.

Return JSON only, no prose around it:
{{"cell_id":"{cell_id}","priority":"high|medium|low|unknown","reachable_from":"entry point or null",\
"question":"...","reason":"2-3 sentences","unread":"what you did not look at"}}"""


def build_prompt(row: dict, src_root: str) -> str:
    cls = row.get("class", "")
    rub = RUBRIC.get(cls, DEFAULT_RUBRIC)
    if cls == "limit-pair":
        rub = rub.format(declared=row.get("declared"), enforced=row.get("enforced"))
    module = str(row.get("module", ""))
    # Cells produced inside the container carry the analyze-phase prefix; the repo on disk does not.
    strip = ("(Site paths are prefixed `work/` — strip it: `work/src/...` is `src/...` under the repo "
             "root.)\n" if module.startswith("work/") else "")
    sites = row.get("sites") or {}
    flat = [s for v in sites.values() for s in v] if isinstance(sites, dict) else []
    return PROMPT.format(
        root=os.path.join(src_root, row["crate"]),
        strip_note=strip,
        cell_id=row["cell_id"], crate=row["crate"], cls=cls, module=module,
        dpath=row.get("data_path") or "unclassified",
        hits=row.get("hits"), engines=json.dumps(row.get("engines") or {}),
        rules=json.dumps(row.get("rules") or {})[:300],
        sites=json.dumps(flat[:40]),
        prior=row.get("prior"), terms=json.dumps(row.get("prior_terms") or {}),
        rubric=rub,
    )


def judge(row: dict, src_root: str, timeout: int) -> dict | None:
    prompt = build_prompt(row, src_root)
    try:
        r = subprocess.run(["claude", "-p", prompt, "--output-format", "text"],
                           capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"cell_id": row["cell_id"], "priority": "unknown",
                "reason": f"prioritise agent timed out after {timeout}s", "unread": "everything"}
    out = r.stdout.strip()
    m = re.search(r"\{.*\}", out, re.S)          # the model may wrap the JSON in a fence or prose
    if not m:
        return {"cell_id": row["cell_id"], "priority": "unknown",
                "reason": f"no JSON in agent output (rc={r.returncode}): {out[:200]}",
                "unread": "everything"}
    try:
        v = json.loads(m.group(0))
    except Exception as exc:                                    # noqa: BLE001
        return {"cell_id": row["cell_id"], "priority": "unknown",
                "reason": f"unparseable agent JSON: {exc}", "unread": "everything"}
    v["cell_id"] = row["cell_id"]                               # never trust the model with the key
    return v


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", default="/tmp/sast-queue.jsonl")
    ap.add_argument("--src-root", default=os.path.expanduser("~/rip-sast/work/src"))
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--crate")
    ap.add_argument("--crates", help="comma-separated target set (the strategic tier)")
    ap.add_argument("--class", dest="cls")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--stratify", action="store_true",
                    help="take the top cell per crate instead of the global top-N")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--apply", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                    "apply_prioritisation.py"))
    args = ap.parse_args()

    if not os.environ.get("CLAUDE_CODE_OAUTH_TOKEN") and not os.environ.get("ANTHROPIC_API_KEY"):
        print("no CLAUDE_CODE_OAUTH_TOKEN / ANTHROPIC_API_KEY in env — source ~/.rip-auth first",
              file=sys.stderr)
        return 2

    rows = [json.loads(l) for l in open(args.queue) if l.strip()]
    pool = [r for r in rows if r.get("status") == "unread"]
    if args.crate:
        pool = [r for r in pool if r["crate"] == args.crate]
    if args.crates:
        # The strategic target set. Selected from OUR OWN disclosure outcomes, not from taste:
        # network-reachable projects whose maintainers accept security reports through a private
        # channel and act on them (quinn-proto accepted + fix in progress; rustls took both findings
        # via PR #3173; h2/ciborium under review; ntex/quick-xml/x509-parser 100% resolved).
        # Deliberately EXCLUDED: image / png / fdeflate (17 filed, 6 closed, SECURITY.md puts DoS out
        # of scope) and object ("DoS is not an issue"), where our findings are exactly DoS-class.
        want = {c.strip() for c in args.crates.split(",") if c.strip()}
        pool = [r for r in pool if r["crate"] in want]
    if args.cls:
        pool = [r for r in pool if r.get("class") == args.cls]
    pool.sort(key=lambda r: -r.get("prior", 0))

    if args.stratify:
        seen, strat = set(), []
        for r in pool:
            if r["crate"] not in seen:
                seen.add(r["crate"]); strat.append(r)
        pool = strat
    todo = pool[:args.top]

    # A slice that does not name its own tail reads as a complete pass.
    tail = len(pool) - len(todo)
    print(json.dumps({"selected": len(todo), "left_unread_in_filter": tail,
                      "prior_at_cut": todo[-1]["prior"] if todo else None,
                      "queue_unread_total": sum(1 for r in rows if r.get("status") == "unread")},
                     indent=2))
    if args.dry_run or not todo:
        for r in todo:
            print(f"  {r['prior']:.3f} {r['crate']:<14} {r.get('class'):<14} {r.get('module')}")
        return 0

    verdicts = []
    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = {ex.submit(judge, r, args.src_root, args.timeout): r for r in todo}
        for f in cf.as_completed(futs):
            v = f.result()
            if v:
                verdicts.append(v)
                print(f"  {v.get('priority','?'):<8} {v['cell_id'][:70]}", flush=True)

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(verdicts, fh, ensure_ascii=False)
        vpath = fh.name
    rc = subprocess.run([sys.executable, args.apply, "--queue", args.queue,
                         "--verdicts", vpath, "--by", "sast-prioritise/run_prioritise"]).returncode
    os.unlink(vpath)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
