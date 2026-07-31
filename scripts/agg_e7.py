#!/usr/bin/env python3
"""E7 aggregation — per rule, how often does it separate a vulnerable version from its patch?"""
import json, sys, collections, os

CELLS = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/rip-corpus/e7-cells.jsonl")
ENUM = lambda r: r.startswith("rip-e0")   # U1 worklists — firing on both sides is CORRECT for them

def verdict(tp, tn):
    if tp > 0 and tn == 0: return "discriminating"   # the rule tracks the defect
    if tp > tn > 0:        return "weakened"         # patch removed some sites — partial signal
    if tp == tn > 0:       return "fires-both"       # tracks the crate's STYLE, not the vulnerability
    if 0 < tp < tn:        return "reverse"          # more hits AFTER the fix — look before believing
    if tp == 0 and tn > 0: return "reverse"
    return "silent"

rows, errs = [], 0
for line in open(CELLS):
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if "error" in d: errs += 1; continue
    rows.append(d)

per = collections.defaultdict(collections.Counter)
pairs = set()
for d in rows:
    pairs.add(d["id"])
    per[d["rule"]][verdict(d["tp_lib"], d["tn_lib"])] += 1

print(f"pairs scored: {len(pairs)}   rule-cells: {len(rows)}   scan errors: {errs}\n")

tot = collections.Counter()
print(f"{'rule':<52} {'disc':>5} {'weak':>5} {'both':>5} {'rev':>4}  {'disc%':>6}")
print("-" * 84)
for rule in sorted(per, key=lambda r: (ENUM(r), -per[r]["discriminating"])):
    c = per[rule]
    fired = c["discriminating"] + c["weakened"] + c["fires-both"] + c["reverse"]
    if not fired: continue
    pct = 100.0 * c["discriminating"] / fired
    tag = "  [enumerator — judged on completeness, not this]" if ENUM(rule) else ""
    print(f"{rule:<52} {c['discriminating']:>5} {c['weakened']:>5} {c['fires-both']:>5} "
          f"{c['reverse']:>4}  {pct:>5.1f}%{tag}")
    if not ENUM(rule):
        tot.update(c)

fired = tot["discriminating"] + tot["weakened"] + tot["fires-both"] + tot["reverse"]
print("\n=== candidate rules only (enumerators excluded) ===")
for k in ("discriminating", "weakened", "fires-both", "reverse"):
    print(f"  {k:<16} {tot[k]:>6}  ({100.0*tot[k]/max(fired,1):.1f}%)")
print(f"  {'TOTAL fired':<16} {fired:>6}")
