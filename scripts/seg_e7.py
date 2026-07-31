import json, collections, os
CELLS = os.path.expanduser("~/rip-corpus/e7-cells.jsonl")
rows = [json.loads(l) for l in open(CELLS) if l.strip()]
rows = [d for d in rows if "error" not in d]

def verdict(tp, tn):
    if tp > 0 and tn == 0: return "disc"
    if tp > tn > 0:        return "weak"
    if tp == tn > 0:       return "both"
    if tp < tn:            return "rev"
    return "silent"

CLASS_CATS = {
    "recursion": {"denial-of-service"}, "subtree": {"denial-of-service"},
    "loop": {"denial-of-service"}, "alloc": {"denial-of-service"},
    "limit": {"denial-of-service"}, "pop": {"denial-of-service", "memory-corruption"},
    "decompress": {"denial-of-service"}, "index": {"denial-of-service", "memory-corruption"},
    "path": {"file-disclosure"}, "sql": {"format-injection"},
    "shell": {"code-execution"}, "spawn": {"code-execution"},
    "secret": {"memory-exposure"}, "error-swallow": set(),
}

def cls(r):
    for k in CLASS_CATS:
        if k in r: return k
    return None

tot, matched = collections.Counter(), collections.Counter()
for d in rows:
    if d["rule"].startswith("rip-e0"): continue
    v = verdict(d["tp_lib"], d["tn_lib"])
    if v == "silent": continue
    tot[v] += 1
    c = cls(d["rule"]); cats = set(d.get("categories") or [])
    if c and CLASS_CATS[c] and (cats & CLASS_CATS[c]):
        matched[v] += 1

def show(name, c):
    n = sum(c.values())
    print("--- %s: %d fired cells" % (name, n))
    for k in ("disc", "weak", "both", "rev"):
        print("    %-6s %5d  %5.1f%%" % (k, c[k], 100.0 * c[k] / max(n, 1)))

print("=== ALL pairs (rule class vs advisory class NOT matched) ===");  show("all", tot); print()
print("=== CATEGORY-MATCHED only ===");                                 show("matched", matched); print()

print("=== the discriminating cells, by advisory category ===")
cc = collections.Counter()
for d in rows:
    if d["rule"].startswith("rip-e0"): continue
    if verdict(d["tp_lib"], d["tn_lib"]) == "disc":
        for k in (d.get("categories") or ["(none)"]): cc[k] += 1
for k, v in cc.most_common(): print("    %4d  %s" % (v, k))
print()

print("=== sample discriminating cells (category-matched) ===")
n = 0
for d in rows:
    if d["rule"].startswith("rip-e0"): continue
    c = cls(d["rule"]); cats = set(d.get("categories") or [])
    if verdict(d["tp_lib"], d["tn_lib"]) == "disc" and c and CLASS_CATS[c] and (cats & CLASS_CATS[c]):
        print("    %-20s %-18s %-46s tp=%d tn=%d" % (d["id"], d["package"], d["rule"], d["tp_lib"], d["tn_lib"]))
        n += 1
        if n >= 25: break
