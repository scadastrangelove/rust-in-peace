#!/usr/bin/env python3
"""E7 — score every rule against every (vulnerable, patched) pair.

The pair is what makes this falsifiable. Per (rule, advisory):

    fires on TP, silent on TN  -> DISCRIMINATING — the rule tracks the defect
    fires on both              -> FIRES-BOTH     — it tracks the crate's STYLE, not the vulnerability
    silent on both             -> silent         — no signal for this pair
    fires on TN only           -> REVERSE        — suspicious; look before believing

Enumerator rules (U1 worklists) are tagged, not judged: firing on both sides is CORRECT for them.
"""
import json, subprocess, sys, pathlib, collections, os, time

AG      = os.path.expanduser("~/cq-port/bin/ast-grep")
CONFIG  = os.path.expanduser("~/rip-sast/rules/astgrep/sgconfig.yml")
CORPUS  = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/rip-corpus"))
OUT     = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser("~/rip-corpus/e7-cells.jsonl"))
TIMEOUT = 240

def scan(d):
    """-> {rule: [paths]}; ({}, reason) on failure so a crash is never read as 'clean'."""
    try:
        r = subprocess.run([AG, "scan", "-c", CONFIG, "--json=stream", str(d)],
                           capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    hits = collections.defaultdict(list)
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            m = json.loads(line)
        except Exception:
            continue
        rid = m.get("ruleId")
        if rid:
            hits[rid].append(os.path.relpath(m.get("file", ""), d))
    # ast-grep exits non-zero when it has matches; only an EMPTY stdout with stderr is a real failure
    if not r.stdout.strip() and r.stderr.strip():
        return None, r.stderr.strip()[:200]
    return dict(hits), None

def is_lib(p):
    """Library code only. tests/examples/benches are noise on BOTH sides and would just dilute."""
    head = p.split("/", 1)[0]
    return head not in ("tests", "examples", "benches", "fuzz", "target")

def main():
    manifest = [json.loads(l) for l in (CORPUS / "manifest.jsonl").read_text().splitlines() if l.strip()]
    print(f"pairs: {len(manifest)}")
    done, t0 = 0, time.time()
    with open(OUT, "w") as fh:
        for a in manifest:
            tp_hits, tp_err = scan(pathlib.Path(a["tp_dir"]))
            tn_hits, tn_err = scan(pathlib.Path(a["tn_dir"]))
            if tp_err or tn_err:
                fh.write(json.dumps({"id": a["id"], "package": a["package"],
                                     "error": tp_err or tn_err}) + "\n")
                continue
            for rule in set(tp_hits) | set(tn_hits):
                tp_all = tp_hits.get(rule, [])
                tn_all = tn_hits.get(rule, [])
                fh.write(json.dumps({
                    "id": a["id"], "package": a["package"], "rule": rule,
                    "categories": a.get("categories", []),
                    "informational": a.get("informational"),
                    "tp_version": a["tp_version"], "tn_version": a["tn_version"],
                    "tp": len(tp_all), "tn": len(tn_all),
                    "tp_lib": sum(1 for p in tp_all if is_lib(p)),
                    "tn_lib": sum(1 for p in tn_all if is_lib(p)),
                }) + "\n")
            done += 1
            if done % 25 == 0:
                rate = done / max(time.time() - t0, 1)
                print(f"  {done}/{len(manifest)}  ({rate:.1f} pairs/s)", flush=True)
    print(f"cells -> {OUT}")

if __name__ == "__main__":
    main()
