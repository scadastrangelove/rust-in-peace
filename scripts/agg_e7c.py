#!/usr/bin/env python3
"""E7c — E7b restricted to pairs where the fix is small enough for a hit to MEAN something.

E7b's headline was "80.5% of pairs had at least one rule land on the fix region". That number is
worthless, and the control says why: a fix region (±3 lines) covers **33.9%** of library lines on
average across the corpus. With ~50 rules firing dozens of times each, P(at least one lands in a
third of the file) is essentially 1. The metric measured file coverage, not detection.

So: compute the null PER PAIR, keep only the pairs where it is small, and compare observed against
expected inside that subset. A tight fix in a large crate is the only configuration where "the rule
pointed at the fix" carries information.
"""
import json, os, sys, collections, pathlib

ROWS = os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else "~/rip-corpus/e7b-fixsites.jsonl")
CORP = pathlib.Path(os.path.expanduser("~/rip-corpus"))
SLOP = 3
TIGHT = float(os.environ.get("TIGHT", "0.02"))   # fix regions covering <2% of the crate

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

# The null needs k = the number of INDEPENDENT DRAWS, i.e. how many hits the pack placed in the
# crate — not how many distinct rules fired. Using the rule count understates the chance baseline and
# therefore OVERSTATES the lift; the first version of this script did exactly that. The real counts
# are already in E7's per-cell output, so join them in rather than re-scanning.
CELLS = os.path.expanduser("~/rip-corpus/e7-cells.jsonl")
hits_total, hits_enum, hits_cand = collections.Counter(), collections.Counter(), collections.Counter()
hits_matched = collections.Counter()   # the matched row needs ITS OWN k, or its lift is nonsense
if os.path.exists(CELLS):
    for l in open(CELLS):
        if not l.strip(): continue
        d = json.loads(l)
        if "error" in d: continue
        n = d.get("tp_lib", 0)
        hits_total[d["id"]] += n
        (hits_enum if d["rule"].startswith("rip-e0") else hits_cand)[d["id"]] += n
        c = cls(d["rule"])
        if c and (set(d.get("categories") or []) & CLASS_CATS[c]):
            hits_matched[d["id"]] += n

rows = [json.loads(l) for l in open(ROWS) if l.strip()]
rows = [r for r in rows if "error" not in r and "excluded" not in r and r.get("n_fix_lines", 0) > 0]

tight, wide = [], 0
for r in rows:
    tot = lib_lines(CORP / "tp" / r["id"])
    if not tot:
        continue
    p = min(1.0, r["n_fix_lines"] * (2 * SLOP + 1) / tot)
    r["_p_null"], r["_lib_lines"] = p, tot
    (tight.append(r) if p <= TIGHT else None)
    wide += (p > TIGHT)

print(f"pairs with a real lib diff : {len(rows)}")
print(f"  TIGHT (fix region <= {TIGHT:.0%} of the crate): {len(tight)}")
print(f"  too wide to be informative              : {wide}")
if not tight:
    sys.exit(0)
print(f"  mean null inside the tight set          : {sum(r['_p_null'] for r in tight)/len(tight):.3%}\n")

def report(name, subset, matched_only, mode="all"):
    hit = exp = 0.0
    n_hit = 0
    for r in subset:
        rules = r["rules_on_fix"]
        cats = set(r.get("categories") or [])
        if mode == "enum":
            rules = {k: v for k, v in rules.items() if k.startswith("rip-e0")}
        elif mode == "candidate":
            rules = {k: v for k, v in rules.items() if not k.startswith("rip-e0")}
        if matched_only:
            rules = {k: v for k, v in rules.items()
                     if cls(k) and (cats & CLASS_CATS[cls(k)])}
        if rules:
            n_hit += 1
        # expected: with k independent hits, P(>=1 on the fix) = 1-(1-p)^k. k is unknown per rule, so
        # use the conservative floor of one hit per rule that fired anywhere in the crate.
        src = hits_matched if matched_only else \
              {"enum": hits_enum, "candidate": hits_cand}.get(mode, hits_total)
        k = src.get(r["id"], 0)
        if k == 0 and not matched_only:
            k = r.get("n_rules_fired", 0)
        exp += 1 - (1 - r["_p_null"]) ** max(k, 1)
    print(f"--- {name}: {len(subset)} pairs")
    print(f"    observed >=1 rule on the fix : {n_hit}  ({100.0*n_hit/len(subset):.1f}%)")
    print(f"    expected by chance           : {exp:.1f}  ({100.0*exp/len(subset):.1f}%)")
    print(f"    lift                         : {n_hit/max(exp,0.01):.2f}x")
    src = hits_matched if matched_only else \
          {"enum": hits_enum, "candidate": hits_cand}.get(mode, hits_total)
    ks = [src.get(r["id"], 0) for r in subset]
    print(f"    (null used k = actual hits placed; median {sorted(ks)[len(ks)//2]} per crate)")

report("tight pairs, ANY rule", tight, False)
print()
# Which half of the pack is doing the work? The 5 U1 enumerators fire everywhere by design, so if the
# lift is theirs alone, the candidate rules add nothing and the conclusion is very different.
report("tight pairs, U1 ENUMERATORS only", tight, False, mode="enum")
print()
report("tight pairs, CANDIDATE rules only (no enumerators)", tight, False, mode="candidate")
print()
report("tight pairs, CATEGORY-MATCHED rule only", tight, True)
print()

print("=== tight pairs where a category-matched rule landed on the fix ===")
for r in sorted(tight, key=lambda x: x["_p_null"]):
    cats = set(r.get("categories") or [])
    for rule, locs in r["rules_on_fix"].items():
        c = cls(rule)
        if c and (cats & CLASS_CATS[c]):
            print(f"  null={r['_p_null']:6.2%}  {r['id']:<20} {r['package']:<18} "
                  f"{rule:<46} {locs[0]}")
            break
