#!/usr/bin/env python3
"""rule_test.py — gate candidate SAST rules against DVRA ground truth.

    python3 scripts/rule_test.py --scan astgrep.json --tests rules/rule-tests.yml \
                                 --src /path/to/dvra-1/source

Reads ast-grep's JSON output (produced wherever ast-grep lives — the tool image, CI, a laptop) and
checks each rule against the expectations in `rule-tests.yml`. Kept separate from the scanner on
purpose: the gate must be runnable without the engine, so it can be re-checked in review.

## Why the NEGATIVE gate is the whole point

DVRA places the hardened `fixed_handle` in the SAME FILE as the vulnerable `handle`. So a rule that
"matches the file" has proven nothing. Passing the negative gate means the rule encoded the GUARD,
not merely the dangerous shape — which is exactly the property that separates a rule from a grep,
and exactly what our 7-crate vendor-default run failed to have (`unwrap_used` fired 883 times and
yielded nothing).

## Decoy expectations are per-decoy, not uniform

Treating all decoys as "must not fire" would be dishonest about which defence a rule relies on. A
pattern rule SHOULD fire on the unsafe decoy — its defence is the reachability judge downstream. It
must NOT fire on the guarded-unwrap decoy, because there the guard is right there in the function.

Exit code is non-zero if any rule fails a gate, so this can gate a commit.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

try:
    import yaml
except ImportError:                                          # pragma: no cover
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    raise

FN_START = re.compile(r"^\s*(pub\s+)?(async\s+)?fn\s+(\w+)")


def fn_line_range(path: pathlib.Path, name: str) -> tuple[int, int] | None:
    """Line span of a function, by scanning for the next top-level `fn` after it.

    Deliberately crude — a brace-counting parser would be more correct, but the negative gate only
    needs "is this match inside the hardened twin", and the twin is always the last or
    second-to-last item in these files. If the span is wrong the gate errs toward FAILING a rule,
    which is the safe direction.
    """
    if not path.exists():
        return None
    lines = path.read_text().splitlines()
    start = None
    for i, ln in enumerate(lines, 1):
        m = FN_START.match(ln)
        if m and m.group(3) == name:
            start = i
        elif m and start is not None and i > start:
            return (start, i - 1)
    return (start, len(lines)) if start else None


def load_matches(scan_path: pathlib.Path) -> list[dict]:
    """ast-grep emits either a JSON array or one object per line (--json=stream)."""
    text = scan_path.read_text().strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    out = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def rel(p: str, root: str) -> str:
    p = str(p)
    for pre in (root.rstrip("/") + "/", "/work/", "/src/"):
        if p.startswith(pre):
            return p[len(pre):]
    return p.lstrip("/")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", required=True)
    ap.add_argument("--tests", default="rules/rule-tests.yml")
    ap.add_argument("--src", default=None, help="DVRA source root (overrides target_root)")
    args = ap.parse_args()

    spec = yaml.safe_load(pathlib.Path(args.tests).read_text())
    root = args.src or spec.get("target_root")
    src = pathlib.Path(root)

    matches = load_matches(pathlib.Path(args.scan))
    by_rule: dict[str, list[tuple[str, int]]] = {}
    for m in matches:
        rid = m.get("ruleId") or m.get("id") or "?"
        f = rel(m.get("file", ""), root)
        line = int(((m.get("range") or {}).get("start") or {}).get("line", 0)) + 1
        by_rule.setdefault(rid, []).append((f, line))

    print(f"scan: {len(matches)} matches across {len(by_rule)} rules\n")

    failures = 0
    print(f"{'rule':<44}{'pos':<6}{'neg':<6}{'decoys':<20}verdict")
    print("-" * 96)

    for r in spec.get("rules", []):
        rid, hits = r["id"], by_rule.get(r["id"], [])

        # positive: matched the oracle's vuln line (±2 lines — the match may anchor on the
        # expression rather than the statement the oracle cited)
        pos = r["positive"]
        pos_ok = any(f == pos["file"] and abs(l - pos["line"]) <= 2 for f, l in hits)

        # negative: did NOT match anywhere inside the hardened twin
        neg, neg_ok = r["negative"], True
        span = fn_line_range(src / neg["file"], neg["fn"])
        if span:
            neg_ok = not any(f == neg["file"] and span[0] <= l <= span[1] for f, l in hits)
        else:
            neg_ok = False                                   # cannot verify ⇒ fail closed

        # decoys: per-decoy expectation
        decoy_notes, decoy_ok = [], True
        for d in spec.get("decoys", []):
            fired = any(f == d["file"] for f, _ in hits)
            if d["expect"] == "must_not_fire" and fired:
                decoy_ok = False
                decoy_notes.append(f"FIRED:{d['file'].split('/')[-1]}")
            elif d["expect"] == "may_fire" and fired:
                decoy_notes.append(f"ok-fired:{d['file'].split('/')[-1]}")

        ok = pos_ok and neg_ok and decoy_ok
        failures += 0 if ok else 1
        print(f"{rid:<44}{'PASS' if pos_ok else 'MISS':<6}{'PASS' if neg_ok else 'LEAK':<6}"
              f"{(','.join(decoy_notes) or '-'):<20}{'✅' if ok else '❌ FAIL'}")
        if not pos_ok:
            print(f"    ↳ positive not matched: expected {pos['file']}:{pos['line']}; "
                  f"got {hits[:4] or 'nothing'}")
        if not neg_ok and span:
            leaked = [(f, l) for f, l in hits if f == neg["file"] and span[0] <= l <= span[1]]
            print(f"    ↳ MATCHED THE HARDENED TWIN at {leaked} — the rule did not encode the guard")
        elif not neg_ok:
            print(f"    ↳ could not locate fn {neg['fn']} in {neg['file']} (failing closed)")

    print()
    print(f"{len(spec.get('rules', [])) - failures}/{len(spec.get('rules', []))} rules pass all gates")
    if failures:
        print("A failing rule is NOT a setback — it is the gate doing its job. Fix the rule, or")
        print("record that the class needs reasoning rather than a pattern (see the oracle's own")
        print("static_visible=false notes for what that looks like).")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
