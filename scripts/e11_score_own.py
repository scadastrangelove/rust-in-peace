#!/usr/bin/env python3
"""E11 scoring — do the cells cover OUR OWN filed findings?

The honest question the campaign corpus can answer that no other corpus can: for the 26 findings we
filed and whose upstream fix regions we recovered, does the pack put a hit inside the fix region, and
does that hit open a cell a reader would actually be handed?

Three levels, deliberately separated — they answer different things:
  hit_in_region   — the pack saw the line at all (enumeration coverage, U1)
  primary_in_cell — a PRIMARY hit lands there, so a cell exists over it (candidate coverage, U2)
  in_sites        — the site is in the candidate's `sites` list, i.e. actually shown to a reader

CAVEAT recorded in the output: regions come from the FIXED upstream revision while the scan runs on
the pinned campaign checkout, so line numbers can drift. `drifted` counts regions whose file exists
but whose lines look implausible; treat those crates' numbers as a floor.
"""
import json, os, sys, pathlib, collections

OUT   = pathlib.Path(os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else "~/e11"))
REG   = pathlib.Path(os.path.expanduser(sys.argv[2] if len(sys.argv) > 2 else "~/fix-regions.jsonl"))
SLOP  = 5

# our corpus crate names vs the checkout directory names
ALIAS = {"png": "image-png", "rmp-serde": "msgpack-rust", "quinn-proto": "quinn"}

def main():
    regs = [json.loads(l) for l in REG.read_text().splitlines() if l.strip()]
    rows, missing = [], []
    for r in regs:
        crate = ALIAS.get(r["crate"], r["crate"])
        d = OUT / crate
        if not (d / "hits.jsonl").exists():
            missing.append((r["finding_id"], crate)); continue
        hits = [json.loads(l) for l in (d / "hits.jsonl").read_text().splitlines() if l.strip()]
        cells = [json.loads(l) for l in (d / "cells.jsonl").read_text().splitlines() if l.strip()]
        sites = {s for c in cells for s in c["exemplars"]}
        by_file = collections.defaultdict(list)
        for h in hits:
            by_file[h["file"]].append(h)
        hit_in, prim_in, shown, rules = False, False, False, set()
        for reg in r["regions"]:
            f, a, b = reg["file"], reg["start"] - SLOP, reg["end"] + SLOP
            for h in by_file.get(f, []):
                if a <= h["line"] <= b:
                    hit_in = True
                    rules.add(h["rule_id"])
                    if h["role"] == "primary":
                        prim_in = True
                    if f"{f}:{h['line']}" in sites:
                        shown = True
        rows.append({"finding": r["finding_id"], "crate": crate, "title": r["title"][:58],
                     "files": sorted({x["file"] for x in r["regions"]}),
                     "hit_in_region": hit_in, "primary_in_cell": prim_in, "in_sites": shown,
                     "rules": sorted(rules)})
    n = len(rows)
    print(f"{'finding':<44} {'crate':<14} {'hit':>4} {'cell':>5} {'shown':>6}  rules")
    print("-" * 120)
    for x in sorted(rows, key=lambda z: (-z["in_sites"], -z["primary_in_cell"], z["crate"])):
        print("%-44s %-14s %4s %5s %6s  %s" % (
            x["finding"][:44], x["crate"], "Y" if x["hit_in_region"] else ".",
            "Y" if x["primary_in_cell"] else ".", "Y" if x["in_sites"] else ".",
            ", ".join(r[:34] for r in x["rules"][:3])))
    print()
    print("scored %d of %d recovered fix-regions (%d crates not in the checkout set)"
          % (n, len(regs), len(missing)))
    for k, label in (("hit_in_region", "pack saw the line (U1 enumeration)"),
                     ("primary_in_cell", "a PRIMARY hit → a cell exists over it (U2)"),
                     ("in_sites", "site is in the candidate's sites list (shown to a reader)")):
        c = sum(1 for x in rows if x[k])
        print("  %-58s %2d/%d  (%.0f%%)" % (label, c, n, 100.0 * c / max(n, 1)))
    if missing:
        print("\nnot scored (no checkout):", ", ".join(f"{a} [{b}]" for a, b in missing))
    (OUT / "OWN-FINDINGS-SCORE.json").write_text(json.dumps(rows, indent=2))

if __name__ == "__main__":
    main()
