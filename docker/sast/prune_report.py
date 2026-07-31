#!/usr/bin/env python3
"""prune_report.py — build PRUNE-LEDGER.md from a batch of `sast-driven` runs.

    python3 prune_report.py <results-root> [-o PRUNE-LEDGER.md]

The `sast-driven` premise is "run every default rule, prune what doesn't pay". This turns the raw
per-crate `hits.jsonl` into the table that decides what to prune — and it separates TWO KINDS of
prune, because they have different evidence bars:

  * **Semantic prune (immediate, safe).** A lint whose CATEGORY cannot express a security defect —
    documentation formatting, naming, idiom preference, import style — is droppable on inspection.
    `clippy::doc_markdown` (missing backticks in a doc comment) will never be a vulnerability no
    matter how many crates it fires on. Waiting for yield data on these is a waste: no amount of
    triage will promote them, and they are ~half the volume.
  * **Yield prune (needs evidence).** A lint that COULD matter — `unwrap_used`, `indexing_slicing`,
    `arithmetic_side_effects` — is only droppable on measured yield: ≥3 crates AND zero candidates
    that survived verify. `indexing_slicing` on a bounds-proven byte parser is noise; on a length
    field parsed from the wire it is the bug. Volume alone never decides.

Everything unrecognized stays IN and is reported as `unclassified` — a classifier that silently
swallows what it does not recognize is the same defect class as a status field that reports on the
wrong artifact (LESSONS L52).

The candidates/confirmed columns are filled in by hand after triage; this tool never invents them.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import Counter, defaultdict

# ── semantic classes: what a rule is ABOUT, independent of how often it fires ────────────────────
# NON_SECURITY: the category cannot express a security defect. Droppable on inspection.
NON_SECURITY = [
    (re.compile(r"doc|missing_errors|missing_panics|missing_safety_doc$"), "documentation"),
    (re.compile(r"semicolon|unreadable_literal|separated_literal|inline_always|"
                r"uninlined_format|write_with_newline|writeln_empty"), "formatting"),
    (re.compile(r"use_self|redundant_pub_crate|elidable|needless_lifetimes|module_name_repetitions|"
                r"wildcard_imports|enum_glob_use|items_after_statements|single_char|"
                r"unnecessary_wraps|struct_excessive_bools|too_many_lines|match_same_arms|"
                r"option_if_let_else|single_match_else|redundant_closure|manual_let_else|"
                r"map_unwrap_or|explicit_iter_loop|implicit_hasher|return_self_not_must_use|"
                r"must_use_candidate|missing_const_for_fn|missing_inline_in_public_items"), "style/idiom"),
    (re.compile(r"similar_names|upper_case_acronyms|used_underscore|min_ident_chars"), "naming"),
]
# SECURITY_RELEVANT: could express a real defect — prune only on measured yield.
SECURITY_RELEVANT = [
    (re.compile(r"unwrap|expect_used|panic|unreachable|todo|unimplemented"), "panic-surface"),
    (re.compile(r"indexing_slicing|get_unchecked|slice_"), "index-surface"),
    (re.compile(r"arithmetic|overflow|wrapping|saturating"), "arithmetic"),
    (re.compile(r"cast_|as_conversions|truncation|sign_loss|precision_loss|lossless"), "conversion"),
    (re.compile(r"unsafe|transmute|uninit|ptr_|raw_|mem_forget|mem_replace"), "unsafe"),
    (re.compile(r"await|mutex|lock|atomic|rc_|send|sync"), "concurrency"),
    (re.compile(r"command|process|exit|env_|path|fs_|temp"), "os-interaction"),
    (re.compile(r"crypto|hash|rand|secret|insecure|ssl|tls|verify|cert"), "crypto-trust"),
    (re.compile(r"rustsec|advisory|yanked"), "dependency"),
]


def classify(rule: str) -> tuple[str, str]:
    """-> (verdict, category). Order matters: security wins ties, since a false 'non-security'
    is a silently dropped real finding while a false 'security' only costs triage time."""
    if rule.startswith("rip-e"):
        return "enumerator", "u1-worklist"
    for pat, cat in SECURITY_RELEVANT:
        if pat.search(rule):
            return "security-relevant", cat
    for pat, cat in NON_SECURITY:
        if pat.search(rule):
            return "non-security", cat
    return "unclassified", "-"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("-o", "--out", default="PRUNE-LEDGER.md")
    args = ap.parse_args()

    root = pathlib.Path(args.root)
    per_rule_crate: dict[str, Counter] = defaultdict(Counter)
    rule_engine: dict[str, str] = {}
    rule_tier: dict[str, str] = {}
    crates: list[str] = []
    partial: dict[str, list[str]] = {}

    for crate_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        runs = sorted(d for d in crate_dir.iterdir() if (d / "hits.jsonl").exists())
        if not runs:
            continue
        run = runs[-1]
        crates.append(crate_dir.name)
        man = run / "manifest.json"
        if man.exists():
            m = json.loads(man.read_text())
            bad = (m.get("engines_partial") or []) + (m.get("engines_failed") or [])
            if bad:
                partial[crate_dir.name] = bad
        for line in (run / "hits.jsonl").read_text().splitlines():
            if not line.strip():
                continue
            h = json.loads(line)
            r = h["rule_id"]
            per_rule_crate[r][crate_dir.name] += 1
            rule_engine[r] = h.get("engine", "?")
            if h.get("group", "-") not in ("-", None):
                rule_tier[r] = h["group"]

    if not crates:
        print(f"no runs with hits.jsonl under {root}", file=sys.stderr)
        return 1

    rows = []
    for rule, counts in per_rule_crate.items():
        verdict, cat = classify(rule)
        rows.append({
            "rule": rule.split(".")[-1] if rule.startswith("opt.") else rule,
            "engine": rule_engine.get(rule, "?"), "tier": rule_tier.get(rule, "-"),
            "hits": sum(counts.values()), "crates": len(counts),
            "verdict": verdict, "category": cat,
        })
    rows.sort(key=lambda r: -r["hits"])

    tot = sum(r["hits"] for r in rows)
    by_verdict = Counter()
    for r in rows:
        by_verdict[r["verdict"]] += r["hits"]

    L = []
    L.append("# PRUNE-LEDGER — `sast-driven` rule yield\n")
    L.append(f"Crates: **{len(crates)}** ({', '.join(crates)}) · rules firing: **{len(rows)}** · "
             f"total kept hits: **{tot}**\n")
    if partial:
        L.append("> ⚠ **Incomplete engines — these counts are NOT comparable across crates:**\n>")
        for c, e in partial.items():
            L.append(f"> - `{c}`: {', '.join(e)}")
        L.append("")
    L.append("## Volume by prune class\n")
    L.append("| class | hits | share | what it means |")
    L.append("|---|---|---|---|")
    meaning = {
        "non-security": "**droppable on inspection** — the category cannot express a security defect",
        "security-relevant": "prune only on measured yield (≥3 crates AND zero surviving candidates)",
        "enumerator": "U1 worklists — judged on completeness, never pruned on volume",
        "unclassified": "**review these** — not recognized, kept by default",
    }
    for v in ("non-security", "security-relevant", "enumerator", "unclassified"):
        n = by_verdict.get(v, 0)
        L.append(f"| {v} | {n} | {100*n/tot:.1f}% | {meaning[v]} |")
    L.append("")
    L.append("## Per-rule\n")
    L.append("| rule | engine | tier | hits | crates | class | category | candidates | confirmed |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        L.append(f"| `{r['rule']}` | {r['engine']} | {r['tier']} | {r['hits']} | {r['crates']} "
                 f"| {r['verdict']} | {r['category']} | | |")
    L.append("\n**candidates / confirmed are filled in BY HAND after triage.** Volume alone never "
             "prunes a security-relevant rule: `indexing_slicing` on a bounds-proven byte parser is "
             "noise, on a wire-parsed length it is the bug.\n")

    pathlib.Path(args.out).write_text("\n".join(L))
    print(f"{args.out}: {len(rows)} rules, {tot} hits, {len(crates)} crates")
    for v in ("non-security", "security-relevant", "enumerator", "unclassified"):
        print(f"  {v:<20}{by_verdict.get(v,0):>7} ({100*by_verdict.get(v,0)/tot:.1f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
