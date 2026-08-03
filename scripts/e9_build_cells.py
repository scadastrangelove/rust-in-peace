#!/usr/bin/env python3
"""E9 — build judge-ready cells for known-vulnerable crates, with a hidden scoring key.

Picks crates from the TIGHT advisory pairs (fix region <= 2% of the crate), runs the ast-grep pack on
the VULNERABLE version, clusters via docker/sast/normalize.py, and records which cell contains the
real fix site.

The fix-site marking is the SCORING KEY and never enters a judge prompt. The judge sees exactly what
it would see on an unknown target; the key is only opened afterwards.
"""
import json, os, subprocess, sys, pathlib, difflib, hashlib, collections

AG        = os.path.expanduser("~/cq-port/bin/ast-grep")
CONFIG    = os.path.expanduser("~/rip-sast/rules/astgrep/sgconfig.yml")
NORMALIZE = os.path.expanduser("~/rip-sast/docker-sast/normalize.py")
CORP      = pathlib.Path(os.path.expanduser("~/rip-corpus"))
OUT       = pathlib.Path(os.path.expanduser("~/e9"))
SLOP      = 3
SKIP      = ("tests", "examples", "benches", "fuzz", "target")

def fix_lines(tp, tn):
    out = {}
    for f in pathlib.Path(tp).rglob("*.rs"):
        rel = f.relative_to(tp).as_posix()
        if rel.split("/", 1)[0] in SKIP:
            continue
        g = pathlib.Path(tn) / rel
        try:
            a = f.read_text(errors="replace").splitlines()
        except Exception:
            continue
        if not g.exists():
            out[rel] = set(range(1, len(a) + 1)); continue
        try:
            b = g.read_text(errors="replace").splitlines()
        except Exception:
            continue
        if a == b:
            continue
        lines = set()
        for tag, i1, i2, _, _ in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
            if tag in ("replace", "delete"):
                lines.update(range(i1 + 1, i2 + 1))
            elif tag == "insert":
                lines.update(range(max(1, i1 - SLOP + 1), i1 + SLOP + 1))
        if lines:
            out[rel] = lines
    return out

def run(ids):
    manifest = {json.loads(l)["id"]: json.loads(l)
                for l in (CORP / "manifest.jsonl").read_text().splitlines() if l.strip()}
    OUT.mkdir(parents=True, exist_ok=True)
    index = []
    for rid in ids:
        a = manifest.get(rid)
        if not a:
            print(f"  !! {rid} not in manifest"); continue
        tp, tn = a["tp_dir"], a["tn_dir"]
        d = OUT / rid
        (d / "raw").mkdir(parents=True, exist_ok=True)
        # 1. the pack, on the vulnerable tree
        with open(d / "raw" / "astgrep.json", "w") as fh:
            subprocess.run([AG, "scan", "-c", CONFIG, "--json=stream", tp],
                           stdout=fh, stderr=subprocess.DEVNULL, timeout=600)
        # 2. cluster with the production normalizer — same code path a real run uses
        r = subprocess.run([sys.executable, NORMALIZE, "--out", str(d), "--src", tp,
                            "--crate", a["package"], "--commit", a["tp_version"]],
                           capture_output=True, text=True)
        cells_p = d / "cells.jsonl"
        if not cells_p.exists():
            print(f"  !! {rid} normalize produced no cells: {r.stderr.strip()[:160]}"); continue
        cells = [json.loads(l) for l in cells_p.read_text().splitlines() if l.strip()]
        # 3. the SCORING KEY — which cells cover the real fix, by module and by exemplar proximity
        fx = fix_lines(tp, tn)
        fix_modules = {str(pathlib.PurePosixPath(f).parent) for f in fx}
        for c in cells:
            mod = c["module"]
            c["_fix_module"] = any(m == mod or m.startswith(mod + "/") for m in fix_modules)
            c["_fix_exemplar"] = any(
                ex.split(":")[0] in fx and
                any(abs(int(ex.split(":")[1]) - x) <= SLOP for x in fx[ex.split(":")[0]])
                for ex in c["exemplars"] if ":" in ex)
        key = {"id": rid, "package": a["package"], "tp": a["tp_version"], "tn": a["tn_version"],
               "categories": a.get("categories", []), "title": a.get("title", ""),
               "fix_files": sorted(fx), "n_fix_lines": sum(len(v) for v in fx.values()),
               "n_cells": len(cells),
               "cells_covering_fix_module": [c["cell_id"] for c in cells if c["_fix_module"]],
               "cells_with_fix_exemplar": [c["cell_id"] for c in cells if c["_fix_exemplar"]]}
        (d / "KEY.json").write_text(json.dumps(key, indent=2))
        # judge input: the key fields stripped out
        blind = [{k: v for k, v in c.items() if not k.startswith("_")} for c in cells]
        (d / "cells-blind.jsonl").write_text("".join(json.dumps(c) + "\n" for c in blind))
        index.append(key)
        print(f"  {rid:<20} {a['package']:<18} cells={len(cells):>3}  "
              f"fix-module cells={len(key['cells_covering_fix_module'])}  "
              f"fix-exemplar cells={len(key['cells_with_fix_exemplar'])}")
    (OUT / "INDEX.json").write_text(json.dumps(index, indent=2))
    print(f"\n-> {OUT}")

if __name__ == "__main__":
    run(sys.argv[1:])
