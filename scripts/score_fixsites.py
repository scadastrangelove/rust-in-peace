#!/usr/bin/env python3
"""E7b — the sharp version of E7.

E7 compared HIT COUNTS between the vulnerable and patched trees and found 84% identical. That number
is real but it is a weak instrument, and the weakness is structural: most security patches are a
1-3 line diff, so a rule that legitimately fires on 300 sites fires on ~300 sites after the patch too.
Count equality over a whole crate cannot see a single site disappearing.

The test that actually answers "does the rule detect the defect":

    diff TP vs TN  ->  the lines the FIX touched
    does any hit of the rule land ON one of those lines (in the TP tree)?

That is recall against real fixes, and it is what `scripts/fetch_fix_regions.py` already does for our
own findings — same technique, 628× more ground truth.
"""
import json, subprocess, sys, pathlib, collections, os, time, difflib, hashlib
from concurrent.futures import ProcessPoolExecutor

AG      = os.path.expanduser("~/cq-port/bin/ast-grep")
CONFIG  = os.path.expanduser("~/rip-sast/rules/astgrep/sgconfig.yml")
CORPUS  = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/rip-corpus"))
OUT     = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser("~/rip-corpus/e7b-fixsites.jsonl"))
SLOP    = 3          # a guard added just above the defect still counts as pointing at it
TIMEOUT = 240

# A TN that is a whole minor release away is not a FIX, it is a RELEASE: the diff is thousands of
# lines and locates nothing. Pairs wider than this are excluded and COUNTED, never silently dropped —
# how many advisory pairs are tight enough to locate a fix is itself a result.
MAX_CHANGED_FILES = 40

def _h(p):
    try:
        return hashlib.blake2b(p.read_bytes(), digest_size=16).digest()
    except Exception:
        return None

def changed_regions(tp: pathlib.Path, tn: pathlib.Path):
    """-> ({relpath: set(TP line numbers the patch removed or changed)}, wide_diff: bool)"""
    # cheap pass first: hash-compare to find WHICH files differ. difflib on a whole crate is the
    # bottleneck (a major-version pair stalled the first run outright).
    differing = []
    for f in tp.rglob("*.rs"):
        rel = f.relative_to(tp).as_posix()
        head = rel.split("/", 1)[0]
        if head in ("tests", "examples", "benches", "fuzz", "target"):
            continue
        g = tn / rel
        if not g.exists() or _h(f) != _h(g):
            differing.append((rel, f, g))
    if len(differing) > MAX_CHANGED_FILES:
        return {}, True
    out = {}
    for rel, f, g in differing:
        try:
            a = f.read_text(errors="replace").splitlines()
        except Exception:
            continue
        if not g.exists():
            out[rel] = set(range(1, len(a) + 1))          # file deleted by the patch: all of it changed
            continue
        try:
            b = g.read_text(errors="replace").splitlines()
        except Exception:
            continue
        lines = set()
        for tag, i1, i2, _, _ in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
            if tag in ("replace", "delete"):
                lines.update(range(i1 + 1, i2 + 1))
            elif tag == "insert":
                lines.update(range(max(1, i1 - SLOP + 1), i1 + SLOP + 1))  # anchor an insert to its site
        if lines:
            out[rel] = lines
    return out, False

def scan(d):
    try:
        r = subprocess.run([AG, "scan", "-c", CONFIG, "--json=stream", str(d)],
                           capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return None
    hits = collections.defaultdict(list)
    for line in r.stdout.splitlines():
        if not line.strip():
            continue
        try:
            m = json.loads(line)
        except Exception:
            continue
        rid = m.get("ruleId")
        if not rid:
            continue
        rel = os.path.relpath(m.get("file", ""), d)
        ln = (m.get("range", {}).get("start", {}) or {}).get("line")
        if ln is None:
            continue
        hits[rid].append((rel, int(ln) + 1))               # ast-grep lines are 0-based
    if not r.stdout.strip() and r.stderr.strip():
        return None
    return dict(hits)

def one(a):
    """One pair -> one result record. Pure function so it can run in a worker process."""
    tp, tn = pathlib.Path(a["tp_dir"]), pathlib.Path(a["tn_dir"])
    regions, wide = changed_regions(tp, tn)
    if wide:
        return {"id": a["id"], "package": a["package"], "excluded": "wide-diff"}
    hits = scan(tp)
    if hits is None:
        return {"id": a["id"], "error": "scan-failed"}
    on_fix = collections.defaultdict(list)
    for rule, locs in hits.items():
        for rel, ln in locs:
            lines = regions.get(rel)
            if lines and any(abs(ln - x) <= SLOP for x in lines):
                on_fix[rule].append(f"{rel}:{ln}")
    return {
        "id": a["id"], "package": a["package"], "categories": a.get("categories", []),
        "tp_version": a["tp_version"], "tn_version": a["tn_version"],
        "fix_files": sorted(regions)[:20], "n_fix_files": len(regions),
        "n_fix_lines": sum(len(v) for v in regions.values()),
        "rules_on_fix": {k: v[:5] for k, v in on_fix.items()},
        "n_rules_fired": len(hits),
    }

def main():
    manifest = [json.loads(l) for l in (CORPUS / "manifest.jsonl").read_text().splitlines() if l.strip()]
    workers = int(os.environ.get("E7B_WORKERS", "8"))
    print(f"pairs: {len(manifest)}  workers: {workers}", flush=True)
    t0, done = time.time(), 0
    # Flush every record. The first run wrote through a default 8 KB buffer, so `wc -l` reported 41
    # rows for ten minutes and the run looked hung when it was not — an instrumentation lie of exactly
    # the L52 shape, one layer down.
    with open(OUT, "w") as fh, ProcessPoolExecutor(max_workers=workers) as ex:
        for rec in ex.map(one, manifest, chunksize=1):
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            done += 1
            if done % 25 == 0:
                print(f"  {done}/{len(manifest)} ({done/max(time.time()-t0,1):.2f}/s)", flush=True)
    print(f"-> {OUT}", flush=True)

if __name__ == "__main__":
    main()
