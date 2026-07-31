#!/usr/bin/env python3
"""E11 — run the capless pipeline over the crates we actually ran campaigns on.

Unlike E7 (628 advisory pairs, a corpus the rules were NOT built from) and E10 (one crate, one
advisory), this is the set where WE have ground truth: 58 filed findings, 26 with fix regions
recovered from the upstream PRs.

Produces, per crate: hits.jsonl / cells.jsonl / SAST-FINDINGS.json, plus a cross-crate ledger.
No agents — this is the free half. Candidate triage is a separate, budgeted step.
"""
import json, os, subprocess, sys, pathlib, collections

AG        = os.path.expanduser("~/cq-port/bin/ast-grep")
CONFIG    = os.path.expanduser("~/rip-sast/rules/astgrep/sgconfig.yml")
NORMALIZE = os.path.expanduser("~/rip-sast/docker-sast/normalize.py")
SRC       = pathlib.Path(os.path.expanduser("~/rip-sast/work/src"))
OUT       = pathlib.Path(os.path.expanduser("~/e11"))

def run(names):
    OUT.mkdir(parents=True, exist_ok=True)
    ledger = []
    for name in names:
        src = SRC / name
        if not src.is_dir():
            print(f"  !! {name}: no source"); continue
        d = OUT / name
        (d / "raw").mkdir(parents=True, exist_ok=True)
        with open(d / "raw" / "astgrep.json", "w") as fh:
            rc = subprocess.run([AG, "scan", "-c", CONFIG, "--json=stream", str(src)],
                                stdout=fh, stderr=subprocess.DEVNULL, timeout=1800).returncode
        r = subprocess.run([sys.executable, NORMALIZE, "--out", str(d), "--src", str(src),
                            "--crate", name, "--commit", "HEAD"], capture_output=True, text=True)
        sp = d / "summary.json"
        if not sp.exists():
            print(f"  !! {name}: normalize failed: {r.stderr.strip()[:200]}"); continue
        s = json.load(open(sp))
        fs = json.load(open(d / "SAST-FINDINGS.json"))["findings"]
        ledger.append({"crate": name, **{k: s.get(k) for k in
                       ("loc_non_test", "raw_hits", "kept_hits", "hits_per_kloc", "cells")},
                       "dropped": s.get("dropped", {}), "candidates": len(fs),
                       "sites_total": sum(len(f["sites"]) for f in fs),
                       "largest_cell": max((len(f["sites"]) for f in fs), default=0)})
        print("  %-16s %7d LOC  %5d kept  %5.1f/kLOC  %2d cells  %4d sites (largest %3d)" % (
            name, s.get("loc_non_test", 0), s.get("kept_hits", 0), s.get("hits_per_kloc", 0),
            s.get("cells", 0), ledger[-1]["sites_total"], ledger[-1]["largest_cell"]))
    (OUT / "LEDGER.json").write_text(json.dumps(ledger, indent=2))
    tot = collections.Counter()
    for l in ledger:
        for k in ("loc_non_test", "kept_hits", "cells", "candidates", "sites_total"):
            tot[k] += l.get(k) or 0
    print(f"\n{len(ledger)} crates | {tot['loc_non_test']:,} LOC | {tot['kept_hits']:,} kept hits | "
          f"{tot['cells']} cells | {tot['sites_total']:,} sites")
    print(f"-> {OUT}/LEDGER.json")

if __name__ == "__main__":
    run(sys.argv[1:] or sorted(p.name for p in SRC.iterdir() if p.is_dir()))
