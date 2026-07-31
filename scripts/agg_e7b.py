#!/usr/bin/env python3
"""E7b aggregation — did the rules point AT the fix, and is that better than chance?

The control matters more than the headline. A crate with 300 rule hits and a 57-line fix will have
some hits land on the fix by coincidence. So every number here is reported against the null:

    P(a random hit lands on a fix line) = fix_lines / total_lib_lines

If observed ~= expected, the rules are not detecting fixes, they are covering the file.
"""
import json, os, sys, collections, pathlib

ROWS = os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else "~/rip-corpus/e7b-fixsites.jsonl")
CORP = pathlib.Path(os.path.expanduser("~/rip-corpus"))
SLOP = 3

CLASS_CATS = {
    "recursion": {"denial-of-service"}, "subtree": {"denial-of-service"},
    "loop": {"denial-of-service"}, "alloc": {"denial-of-service"},
    "limit": {"denial-of-service"}, "pop": {"denial-of-service", "memory-corruption"},
    "decompress": {"denial-of-service"}, "index": {"denial-of-service", "memory-corruption"},
    "path": {"file-disclosure"}, "sql": {"format-injection"},
    "shell": {"code-execution"}, "spawn": {"code-execution"}, "secret": {"memory-exposure"},
}
def cls(r):
    for k in CLASS_CATS:
        if k in r: return k
    return None

def lib_lines(d):
    n = 0
    for f in pathlib.Path(d).rglob("*.rs"):
        head = f.relative_to(d).as_posix().split("/", 1)[0]
        if head in ("tests", "examples", "benches", "fuzz", "target"): continue
        try: n += len(f.read_text(errors="replace").splitlines())
        except Exception: pass
    return n

rows = [json.loads(l) for l in open(ROWS) if l.strip()]
excl = [r for r in rows if r.get("excluded") == "wide-diff"]
errs = [r for r in rows if "error" in r]
rows = [r for r in rows if "error" not in r and "excluded" not in r]
print("EXCLUDED wide-diff (TN is a release, not a fix): %d   scan errors: %d"
      % (len(excl), len(errs)))

hit_pairs = [r for r in rows if r["rules_on_fix"]]
withfix   = [r for r in rows if r["n_fix_lines"] > 0]

print(f"pairs analysed            : {len(rows)}")
print(f"  with a non-empty lib diff: {len(withfix)}")
print(f"  where >=1 rule landed ON the fix region: {len(hit_pairs)} "
      f"({100.0*len(hit_pairs)/max(len(withfix),1):.1f}% of those)")
print()

# ── the control: fix-line density vs on-fix hit density ────────────────────────────────────────
exp_num = exp_den = 0
for r in withfix:
    tot = lib_lines(CORP / "tp" / r["id"])
    if tot:
        exp_num += r["n_fix_lines"] * (2 * SLOP + 1)   # a hit within SLOP counts, so widen the target
        exp_den += tot
p_null = exp_num / max(exp_den, 1)
print(f"NULL: a fix region (±{SLOP} lines) covers {100.0*p_null:.2f}% of library lines on average.")
print("      Landing on it at that rate is coincidence, not detection.\n")

per = collections.Counter(); per_matched = collections.Counter()
fired_pairs = collections.Counter()
for r in withfix:
    cats = set(r.get("categories") or [])
    for rule, locs in r["rules_on_fix"].items():
        per[rule] += 1
        c = cls(rule)
        if c and (cats & CLASS_CATS[c]):
            per_matched[rule] += 1

print(f"{'rule':<52} {'pairs hitting the fix':>22} {'category-matched':>18}")
print("-" * 96)
for rule, n in per.most_common(20):
    print(f"{rule:<52} {n:>22} {per_matched[rule]:>18}")

print()
print("=== pairs where a CATEGORY-MATCHED rule landed on the fix ===")
n = 0
for r in withfix:
    cats = set(r.get("categories") or [])
    for rule, locs in r["rules_on_fix"].items():
        c = cls(rule)
        if c and (cats & CLASS_CATS[c]):
            print(f"  {r['id']:<20} {r['package']:<20} {rule:<46} {locs[0]}")
            n += 1
            break
print(f"  ({n} pairs)")
