#!/usr/bin/env python3
"""build_dvra_corpus.py — unify the three DVRA instructor oracles into one corpus file.

    python3 scripts/build_dvra_corpus.py /path/to/dvra -o corpus/dvra-findings.jsonl

DVRA (github.com/scadastrangelove/damn-vulnerable-rust-app) ships gold labels for its planted
defects. It is the ground truth the rule work is developed against — and, crucially, it ships the
*negative* half too, which is the expensive part of any rule corpus:

  * **dvra-1** labels at SITE level: `file` + `vuln_line`, plus `fixed_fn` — "the hardened
    counterpart in the same module". A rule can be tested directly: it MUST match the vuln line and
    MUST NOT match the fixed function.
  * **dvra-2 / dvra-3** label at SCENARIO level: id, CWE, truth flags, a `reproducer` command and
    (dvra-3) a `fixed_surface` endpoint. **No file:line.**

## The distinction this file refuses to blur

A corpus that silently mixes "the author told us where the bug is" with "we went and found it
ourselves" looks authoritative and is not. Every row therefore carries:

    label_source = "oracle"   the location came from the instructor oracle
                 = "derived"  WE located it; unverified, and must not be used as recall ground
                              truth until confirmed

For dvra-2/3 the honest position is that the oracle gives us *what* and *whether*, not *where*. Their
`reproducer` commands are a stronger validation signal than any static label — they demonstrate the
defect dynamically — but they cannot serve as a rule's positive test until a site is resolved.

## Fields that drive rule development

  rule_dev_eligible   true iff we have a concrete site AND the oracle says a pattern can see it
                      (`static_visible`). Findings the oracle marks static-invisible are NOT rule
                      targets — chasing them produces exactly the over-broad rules this whole
                      exercise is meant to avoid. The oracle even explains why for each
                      ("the WRONG BOUND is the bug", "needs reasoning about two normalizers").
  negative_site       the hardened twin (`fixed_fn` / `fixed_surface`) — a rule matching this is
                      broken by definition, because it failed to encode the guard.

Stdlib + PyYAML only.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tomllib

try:
    import yaml
except ImportError:                                          # pragma: no cover
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    raise


def _truthy(v) -> bool:
    """Oracle booleans arrive as real TOML/YAML bools, or as strings when a trailing comment made
    the author quote them. Treat a leading 'true' as true; anything else false."""
    if isinstance(v, bool):
        return v
    return isinstance(v, str) and v.strip().lower().startswith("true")


def _note(v) -> str | None:
    """The oracle's inline justifications ('# the WRONG BOUND is the bug') are the most useful prose
    in the whole file — they specify where pattern matching stops working. Keep them."""
    if isinstance(v, str) and "#" in v:
        return v.split("#", 1)[1].strip()
    return None


def _inline_comments(text: str) -> dict[str, dict[str, str]]:
    """Recover the oracle's inline justifications, keyed by finding id.

    `tomllib` parses `static_visible = false   # the WRONG BOUND is the bug` into a plain `False`
    and throws the comment away — but that comment is the single most valuable line in the file: it
    states WHY a pattern engine cannot see the defect, i.e. exactly where rule-writing stops paying.
    Recover it from the raw text rather than lose it.
    """
    out: dict[str, dict[str, str]] = {}
    cur: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("id ="):
            cur = line.split("=", 1)[1].strip().strip('"')
            out.setdefault(cur, {})
        elif cur and "=" in line and "#" in line and not line.startswith("#"):
            key, rhs = line.split("=", 1)
            if "#" in rhs:
                out[cur][key.strip()] = rhs.split("#", 1)[1].strip()
    return out


def load_dvra1(root: pathlib.Path) -> list[dict]:
    p = root / "dvra-1" / "instructor-oracle" / "MANIFEST.toml"
    if not p.exists():
        return []
    text = p.read_text()
    doc = tomllib.loads(text)
    comments = _inline_comments(text)
    out = []
    for f in doc.get("finding", []):
        sv, rch = f.get("static_visible"), f.get("reachable")
        site = f.get("file")
        cmt = comments.get(f.get("id") or "", {})
        out.append({
            "impl": "dvra-1",
            "id": f.get("id"),
            "title": f.get("feature"),
            "cwe": [f["cwe"]] if f.get("cwe") else [],
            "file": site,
            "line": f.get("vuln_line"),
            "negative_site": f.get("fixed_fn"),
            "negative_kind": "function" if f.get("fixed_fn") else None,
            "category": f.get("category"),
            "reachable": _truthy(rch),
            "reachable_note": _note(rch) or cmt.get("reachable"),
            "static_visible": _truthy(sv),
            "static_visible_note": _note(sv) or cmt.get("static_visible"),
            "fuzz_visible": _truthy(f.get("fuzz_visible")),
            "panic": _truthy(f.get("panic")),
            "reproducer": None,
            "label_source": "oracle",
            "rule_dev_eligible": bool(site) and _truthy(sv),
        })
    return out


def load_scenarios(root: pathlib.Path, impl: str) -> list[dict]:
    p = root / impl / "instructor-oracle" / "scenarios.yaml"
    if not p.exists():
        return []
    doc = yaml.safe_load(p.read_text()) or {}
    out = []
    for s in doc.get("scenarios", []) or []:
        truth = s.get("truth") or {}
        out.append({
            "impl": impl,
            "id": s.get("id"),
            "title": s.get("title"),
            "cwe": s.get("cwe") or [],
            # No file:line in these oracles — deliberately left null rather than guessed.
            "file": None,
            "line": None,
            "negative_site": s.get("fixed_surface"),
            "negative_kind": "api_surface" if s.get("fixed_surface") else None,
            "category": "reachable-real" if truth.get("reachable") else None,
            "reachable": bool(truth.get("reachable")),
            "reachable_note": None,
            # The oracle makes no static-visibility claim here; do NOT infer one.
            "static_visible": None,
            "static_visible_note": None,
            "fuzz_visible": None,
            "panic": None,
            "truth": truth,
            "threat_models": s.get("threat_models"),
            "reproducer": s.get("reproducer"),
            "expected_signal": s.get("expected_signal"),
            "label_source": "oracle",          # the FINDING is oracle-labelled…
            "site_label_source": None,         # …but its LOCATION is not labelled at all
            "rule_dev_eligible": False,        # cannot be a rule positive without a site
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dvra_root")
    ap.add_argument("-o", "--out", default="corpus/dvra-findings.jsonl")
    args = ap.parse_args()

    root = pathlib.Path(args.dvra_root)
    rows = load_dvra1(root) + load_scenarios(root, "dvra-2") + load_scenarios(root, "dvra-3")
    if not rows:
        print(f"no oracles found under {root}", file=sys.stderr)
        return 1

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))

    n_site = sum(1 for r in rows if r["file"])
    n_neg = sum(1 for r in rows if r["negative_site"])
    n_dev = sum(1 for r in rows if r["rule_dev_eligible"])
    by_impl: dict[str, int] = {}
    for r in rows:
        by_impl[r["impl"]] = by_impl.get(r["impl"], 0) + 1

    print(f"{out}: {len(rows)} findings  {by_impl}")
    print(f"  with a concrete site (file:line)        {n_site}")
    print(f"  with a negative twin (fixed_fn/surface) {n_neg}")
    print(f"  RULE-DEV ELIGIBLE (site + static_visible) {n_dev}")
    print()
    print("  Rule-development set:")
    for r in rows:
        if r["rule_dev_eligible"]:
            cwe = ",".join(r["cwe"])
            print(f"    {r['id']:<24}{cwe:<10}{r['file']}:{r['line']}  neg={r['negative_site']}")
    print()
    print("  Oracle-declared NOT static-visible — do not write pattern rules for these:")
    for r in rows:
        if r["static_visible"] is False and r["file"]:
            print(f"    {r['id']:<24}{r['static_visible_note'] or '(no reason given)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
