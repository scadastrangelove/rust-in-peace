#!/usr/bin/env python3
"""normalize.py — raw engine output → hits.jsonl → cells.jsonl → summary.json.

The `sast-driven` mode runs every engine with its DEFAULT rules (v1 premise: take everything, then
prune from measured yield). That premise only works if the output is *attributable*: every hit
carries its engine, rule id, and — for clippy — its lint GROUP, so `summary.json` answers "which
rule families paid for themselves?" without a human ranking 800 lints by hand.

Three disciplines from docs/sast-layer.md:
  * **Every drop is counted.** A filter that silently truncates reads as "covered everything".
    `summary.dropped` breaks the count down by reason; nothing is removed without a tally.
  * **Cells, not hits, reach agents.** Raw hits are 10^2-10^3; cells are ~10^1. Clustering is what
    makes the agent tier affordable — it caps the number of agent CALLS, one per cell. It is NOT a
    licence to show an agent less than the cell contains; see the EXEMPLARS note below.
  * **Never crash on bad input.** A malformed artifact is recorded in `summary.parse_errors`, not
    raised — one broken engine must not destroy the other five engines' results.

Stdlib only: this runs inside the tool image with no pip step.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# ── tier-1 structural filter ─────────────────────────────────────────────────
# Paths whose findings are not attacker-reachable by construction (fp-rules R5, mechanized).
# Agent-budget target. Cells, not hits, cost money: ~20 is what one triage pass can absorb. This is
# a CLUSTERING target, never a truncation — exceeding it coarsens the module key (merging siblings),
# it never drops a cell.
MAX_CELLS = 20

# ── EXEMPLARS: a cell hands over ALL of its sites ────────────────────────────────────────────────
# This used to be capped at **8**, and the 8 had no justification — measured in E9 and corrected:
#
#   * The design rule that carries the cost is "ONE AGENT PER CELL, never per hit". That caps the
#     number of agent CALLS. It says nothing about how many lines go inside one prompt, and the two
#     were conflated when this code was first written.
#   * Measured cost of the cap: median cell holds **10** hits, so for half the corpus it saved
#     nothing; the largest cell in the E9 set held 337, i.e. ~2.7k tokens. Meanwhile each judge agent
#     spent a **median of 54k tokens** reading source. The cap was saving 0.1–5 % of a prompt while
#     forcing the agent to rediscover sinks the pack had already located.
#   * Measured harm: the pack found the real defect site in **7 of 8** E9 crates, but the site was
#     among the 8 shown exemplars in only **2 of 8**. The reader reached a verdict by rediscovering
#     sinks the pack already had — expensive, and luck.
#
# So: show EVERYTHING, ordered rarest-rule-first (see below). There is no cap. A residual "runaway
# guard" was written and then removed — it would have been a silent truncation with no measured
# threshold behind it, i.e. the same unjustified 8 with a bigger number. If a cell is ever large
# enough to be a problem, the fix is the CLUSTERING (MAX_CELLS coarsens the module key) or the rule
# that produced the volume, never a quiet slice of the evidence.
#
# Effect of removing the cap, measured on the 8 E9 crates: the real fix site is visible to the reader
# in **7 of 8** targets, up from **2 of 8**.

DROP_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("test_code",   re.compile(r"(^|/)(tests?|benches|examples|fuzz)/")),
    ("test_file",   re.compile(r"(^|/)[^/]*_?test(s)?\.rs$")),
    ("build_script", re.compile(r"(^|/)build\.rs$")),
    ("generated",   re.compile(r"(^|/)(target|vendor|third_party|\.cargo)/")),
    # Test VECTORS, not test code — h2 ships `fixtures/hpack/*.json`, where a secrets rule matched
    # 39 base64 blobs as "generic-api-key". Caught by the capability gate on the first real run;
    # cheaper to exclude structurally.
    ("test_fixture", re.compile(r"(^|/)(fixtures?|testdata|test_data|corpus)/")),
    # Dev tooling shipped as its own workspace member rather than under tests/ or benches/ — rustls
    # keeps its benchmark harness in `ci-bench/`. Measured: 20 of 24 surviving rule hits on the real
    # corpus were `ci-bench/`, code that is never published and never sees attacker input.
    #
    # DELIBERATELY NARROW. The first draft also swept `tools/`, `scripts/`, `dev/` and any
    # `*-tests?/` — which is over-filtering: plenty of crates ship real, attacker-reachable code
    # under `tools/`, and a filter that hides it is worse than the noise it removes. A filter is a
    # silent, permanent FN; only exclude what is non-shipped by construction. The precise test is
    # "is this workspace member published", which needs cargo metadata — until then, keep the list
    # short and boring.
    ("dev_tooling", re.compile(r"(^|/)(ci-bench|xtask)/")),
]

# ── in-file `#[cfg(test)] mod tests { … }` ───────────────────────────────────────────────────────
# DROP_PATTERNS above are PATH-based and therefore blind to the commonest Rust layout of all: unit
# tests living at the bottom of the module they test. Measured in E9 — two independent reachability
# judges, on two different crates, spent their budget reporting that cell exemplars were test code:
# kamadak-exif `src/endian.rs:90,98` and tract-nnef `src/ast/parse.rs:613` both sit inside an in-file
# `#[cfg(test)] mod tests`. A path filter cannot see them, so they reached agents.
#
# Brace-counting, not parsing. It is exact enough for the shape being excluded (`#[cfg(test)]`
# immediately followed by a `mod … {` block) and it stays wrong in the SAFE direction: string or
# comment braces can only make the block look longer, i.e. drop test code — never shipped code.
CFG_TEST = re.compile(r"^\s*#\[cfg\(test\)\]")
MOD_OPEN = re.compile(r"^\s*(pub\s+)?mod\s+\w+\s*\{")
_cfg_test_cache: dict[str, set[int]] = {}


def cfg_test_lines(src_root: str, rel: str) -> set[int]:
    """1-based line numbers inside an in-file `#[cfg(test)] mod …` block."""
    if rel in _cfg_test_cache:
        return _cfg_test_cache[rel]
    lines_out: set[int] = set()
    try:
        text = (Path(src_root) / rel).read_text(errors="replace").splitlines()
    except Exception:                                       # noqa: BLE001 — unreadable file: no claim
        _cfg_test_cache[rel] = lines_out
        return lines_out
    i = 0
    while i < len(text):
        if CFG_TEST.match(text[i]):
            j = i + 1
            while j < len(text) and not text[j].strip():
                j += 1
            if j < len(text) and MOD_OPEN.match(text[j]):
                depth, k = 0, j
                while k < len(text):
                    depth += text[k].count("{") - text[k].count("}")
                    if depth <= 0 and k > j:
                        break
                    k += 1
                lines_out.update(range(i + 1, min(k, len(text) - 1) + 2))
                i = k
        i += 1
    _cfg_test_cache[rel] = lines_out
    return lines_out

# ── unpublished workspace members ────────────────────────────────────────────────────────────────
# The `dev_tooling` DROP_PATTERN above is a hardcoded guess (`ci-bench`, `xtask`) and its own comment
# says the precise test is "is this workspace member published". That test does not need cargo
# metadata — `publish = false` is right there in each member's Cargo.toml.
#
# Measured on rustls: **14 of 26 cells** sat in `publish = false` members (bogo, openssl-tests,
# rustls-bench, rustls-test, rustls-fuzzing-provider) — code that is never shipped and never sees
# attacker input. Worse, they were the SMALL cells, so the "rarer is more interesting" prior put them
# at the TOP of the queue. An agent budget spent there is spent on the test suite.
#
# Still narrow by construction: this drops only what the crate's own manifest declares unpublished.
# It never guesses from a directory name, which is what made `dev_tooling` unable to grow.
def unpublished_dirs(src_root: str) -> list[str]:
    out = []
    root = Path(src_root)
    for manifest in list(root.glob("*/Cargo.toml")) + list(root.glob("*/*/Cargo.toml")):
        try:
            txt = manifest.read_text(errors="replace")
        except Exception:                                   # noqa: BLE001
            continue
        if re.search(r"^\s*publish\s*=\s*false", txt, re.M):
            out.append(manifest.parent.relative_to(root).as_posix())
    return sorted(out)


# Rule taxonomy lives in ruleclass.py — ONE source of truth shared with prune_report.py, so cell
# formation and the yield ledger can never drift into disagreeing about what a rule is.
try:
    from ruleclass import classify as classify_rule
except ImportError:                                          # running outside the image
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent))
    from ruleclass import classify as classify_rule


def rel(path: str, src: str) -> str:
    p = str(path or "")
    for prefix in (f"{src}/", src, "file://"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p.lstrip("/")


def hit_id(engine: str, rule: str, file: str, line: int) -> str:
    return hashlib.sha1(f"{engine}|{rule}|{file}|{line}".encode()).hexdigest()[:16]


# ── parsers, one per artifact shape ──────────────────────────────────────────
def parse_sarif(path: Path, engine: str, src: str) -> list[dict]:
    hits: list[dict] = []
    doc = json.loads(path.read_text())
    for run in doc.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
        # SARIF puts rule metadata in a side table; index it so severity survives.
        meta = {r.get("id"): r for r in tool.get("rules", []) or []}
        for res in run.get("results", []) or []:
            rule = res.get("ruleId") or res.get("rule", {}).get("id") or "?"
            msg = (res.get("message", {}) or {}).get("text", "")
            locs = res.get("locations") or [{}]
            for loc in locs:
                phys = (loc.get("physicalLocation") or {})
                art = (phys.get("artifactLocation") or {}).get("uri", "")
                region = phys.get("region") or {}
                hits.append({
                    "engine": engine,
                    "rule_id": rule,
                    "file": rel(art, src),
                    "line": int(region.get("startLine") or 0),
                    "message": msg[:400],
                    "severity": (meta.get(rule, {}).get("defaultConfiguration", {}) or {}).get("level")
                                or res.get("level") or "warning",
                })
    return hits


def parse_astgrep(path: Path, engine: str, src: str) -> list[dict]:
    """ast-grep --json=stream emits one JSON object per line (or a single array)."""
    hits: list[dict] = []
    text = path.read_text().strip()
    if not text:
        return hits
    records: list[dict] = []
    if text.startswith("["):
        records = json.loads(text)
    else:
        for line in text.splitlines():
            line = line.strip().rstrip(",").lstrip("[").rstrip("]")
            if line.startswith("{"):
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    for r in records:
        rng = r.get("range", {}).get("start", {})
        hits.append({
            "engine": engine,
            "rule_id": r.get("ruleId") or r.get("id") or "astgrep-pattern",
            "file": rel(r.get("file", ""), src),
            "line": int(rng.get("line", 0)) + 1,
            "message": (r.get("message") or r.get("text") or "")[:400],
            "severity": r.get("severity", "info"),
        })
    return hits


def parse_cargo_json(path: Path, engine: str, src: str) -> list[dict]:
    """`cargo ... --message-format=json` stream (dylint, and clippy if the SARIF bridge fails)."""
    hits: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("reason") != "compiler-message":
            continue
        msg = rec.get("message", {}) or {}
        code = (msg.get("code") or {}).get("code") or msg.get("level") or "?"
        for span in msg.get("spans", []) or []:
            if not span.get("is_primary"):
                continue
            hits.append({
                "engine": engine,
                "rule_id": code,
                "file": rel(span.get("file_name", ""), src),
                "line": int(span.get("line_start") or 0),
                "message": (msg.get("message") or "")[:400],
                "severity": msg.get("level", "warning"),
            })
    return hits


def parse_audit(path: Path, engine: str, src: str) -> list[dict]:
    doc = json.loads(path.read_text())
    hits = []
    for v in (doc.get("vulnerabilities", {}) or {}).get("list", []) or []:
        adv = v.get("advisory", {}) or {}
        pkg = v.get("package", {}) or {}
        hits.append({
            "engine": engine,
            "rule_id": adv.get("id", "RUSTSEC-?"),
            "file": "Cargo.lock",
            "line": 0,
            "message": f"{pkg.get('name')} {pkg.get('version')}: {adv.get('title', '')}"[:400],
            "severity": "error",
        })
    return hits


def parse_geiger(path: Path, engine: str, src: str) -> list[dict]:
    """geiger is an INVENTORY (U1), not a finder: one hit per crate with unsafe usage."""
    doc = json.loads(path.read_text())
    hits = []
    for pkg in doc.get("packages", []) or []:
        counts = ((pkg.get("unsafety") or {}).get("used") or {})
        total = sum(int((counts.get(k) or {}).get("unsafe_", 0)) for k in counts)
        if total:
            pid = (pkg.get("package", {}) or {}).get("id", {}) or {}
            hits.append({
                "engine": engine,
                "rule_id": "geiger-unsafe-usage",
                "file": f"{pid.get('name', '?')}",
                "line": 0,
                "message": f"{total} unsafe expressions used",
                "severity": "note",
            })
    return hits


ARTIFACTS = [
    ("clippy.sarif", "clippy", parse_sarif),
    ("dylint.json", "dylint", parse_cargo_json),
    ("astgrep.json", "astgrep", parse_astgrep),
    ("audit.json", "audit", parse_audit),
    ("geiger.json", "geiger", parse_geiger),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--src", default="/src")
    ap.add_argument("--crate", default="unknown")
    ap.add_argument("--commit", default="unknown")
    args = ap.parse_args()

    out, raw = Path(args.out), Path(args.out) / "raw"
    parse_errors: list[dict] = []
    hits: list[dict] = []

    def collect(fn, path: Path, engine: str) -> None:
        try:
            hits.extend(fn(path, engine, args.src))
        except Exception as exc:                                # noqa: BLE001 — one bad artifact
            parse_errors.append({"artifact": path.name, "error": f"{type(exc).__name__}: {exc}"})

    for sarif in sorted(raw.glob("opengrep-*.sarif")):
        collect(parse_sarif, sarif, sarif.stem)                 # engine keeps its pack name
    for name, engine, fn in ARTIFACTS:
        p = raw / name
        if p.exists() and p.stat().st_size:
            collect(fn, p, engine)

    # clippy lint → group, for per-group yield ranking
    try:
        lint_groups = json.load(open("/opt/sast/clippy-lints.json"))
    except Exception:                                           # noqa: BLE001
        lint_groups = {}

    # ── tier 1: structural filter, every drop counted ────────────────────────
    unpublished = unpublished_dirs(args.src)
    dropped: Counter[str] = Counter()
    kept: list[dict] = []
    for h in hits:
        f = h.get("file", "")
        # PHANTOM RULES. rustc E0602 is "unknown lint" — clippy emits it when a lint NAME does not
        # exist in this toolchain (ours, or one the target crate names in its own attributes). The
        # SARIF bridge turns that diagnostic into a hit attributed to the nonexistent lint, so the
        # ledger grows rules that cannot fire and can never be pruned on yield. Measured on h2:
        # `clippy::manual_assert_eq` (not a real lint; rustc suggests `manual_assert`).
        if h.get("rule_id") == "E0602" or "unknown lint" in (h.get("message") or "").lower():
            dropped["phantom_rule_unknown_lint"] += 1
            continue
        reason = next((why for why, pat in DROP_PATTERNS if pat.search(f)), None)
        if reason:
            dropped[reason] += 1
            continue
        # Path filters miss the commonest Rust test layout of all — unit tests at the bottom of the
        # module they test. See cfg_test_lines(): measured in E9, where two judges burned their
        # budget reporting that cell exemplars were `#[cfg(test)] mod tests` code.
        if h.get("line") and h["line"] in cfg_test_lines(args.src, f):
            dropped["test_code_in_file"] += 1
            continue
        if any(f == d or f.startswith(d + "/") for d in unpublished):
            dropped["unpublished_member"] += 1
            continue
        rid = h.get("rule_id", "?")
        h["role"], h["class"] = classify_rule(rid)
        # `tier` is clippy's DEFAULT LEVEL (default_allow = the opt-in pedantic/nursery/restriction
        # set we turned on deliberately, i.e. the noise under scrutiny). It is NOT clippy's group
        # taxonomy — that is not obtainable offline. See lint_catalog.py.
        h["group"] = (lint_groups.get(rid, {}) or {}).get("tier", "unattributed") \
            if rid.startswith("clippy::") else "-"
        h["target"] = {"crate": args.crate, "commit": args.commit}
        h["hit_id"] = hit_id(h["engine"], rid, f, h.get("line", 0))
        h["mode"] = "candidate"
        kept.append(h)

    # ── dedupe: same engine+rule+file+line from two rule packs is one hit ────
    seen: set[str] = set()
    deduped = []
    for h in kept:
        if h["hit_id"] in seen:
            dropped["duplicate"] += 1
            continue
        seen.add(h["hit_id"])
        deduped.append(h)

    # ── cluster into cells: (class, module), PRIMARY hits only ──────────────
    # Only `primary` hits open a cell. `corroborating` hits (style/docs/naming — categories that
    # cannot express a security defect) are ATTACHED as context to whatever cell covers their module,
    # and `enumerator` hits go to a separate worklist. Nothing is deleted: hits.jsonl stays complete,
    # and every corroborating hit remains visible inside the cell it touches.
    #
    # Why: before this split, h2's largest cell was 402 hits of class `other` in src/proto/streams —
    # 60%+ style noise, with `doc_markdown` and `missing_const_for_fn` in its top rules. Handing that
    # to an agent is paying for a mostly-irrelevant read, and a resulting "nothing here" would be
    # indistinguishable from "the tools found nothing".
    # Module granularity is ADAPTIVE. A fine class taxonomy spread across deep paths produces one
    # cell per (class × leaf directory) — h2 landed at 50, well past the ~20 an agent budget can
    # absorb. So coarsen the module key (drop trailing path components) until the cell count fits,
    # and record the depth used. Coarsening merges siblings; it never drops anything.
    def module_of(path: str, depth: int) -> str:
        parts = Path(path).parent.parts
        return str(Path(*parts[:depth])) if parts[:depth] else "."

    primaries = [h for h in deduped if h["role"] == "primary"]
    depth = 9
    for d in range(9, 0, -1):
        if len({(h["class"], module_of(h["file"], d)) for h in primaries}) <= MAX_CELLS:
            depth = d
            break
        depth = d
    module_depth = depth

    cells: dict[tuple[str, str], dict] = {}
    context: dict[str, Counter] = defaultdict(Counter)     # module -> corroborating rule counts
    worklist: dict[str, Counter] = defaultdict(Counter)    # module -> enumerator rule counts
    roles = Counter()

    for h in deduped:
        module = module_of(h["file"], module_depth)
        roles[h["role"]] += 1
        if h["role"] == "corroborating":
            context[module][h["rule_id"]] += 1
            continue
        if h["role"] == "enumerator":
            worklist[module][h["rule_id"]] += 1
            continue
        key = (h["class"], module)
        cell = cells.setdefault(key, {
            "cell_id": f"{args.crate}@{args.commit[:8]}/{module}::{h['class']}",
            "class": h["class"], "module": module, "crate": args.crate,
            "hits": 0, "engines": Counter(), "rules": Counter(),
            "sites": defaultdict(list), "exemplars": [],
            "filters": {"structural": "kept", "capability": "unevaluated",
                        "reachability": "unjudged", "where_checked": None},
        })
        cell["hits"] += 1
        cell["engines"][h["engine"]] += 1
        cell["rules"][h["rule_id"]] += 1
        cell["sites"][h["rule_id"]].append(f"{h['file']}:{h['line']}")

    cell_list = []
    for cell in sorted(cells.values(), key=lambda c: -c["hits"]):
        cell["engines"] = dict(cell["engines"])
        # Rarest rule FIRST. Two independent measurements say the rare rule is the informative one:
        # E7c (a rule's hits/crate runs inversely to its discrimination rate — 1.9/crate → 11.1 %,
        # 32.5/crate → 0.5 %) and the h2 judge pass in the skill (the two SMALLEST cells produced both
        # real seeds; the five largest produced none). Ordering by count ascending puts the signal
        # where an agent reads first.
        by_rarity = sorted(cell["sites"].items(), key=lambda kv: (len(kv[1]), kv[0]))
        cell["rules"] = {r: len(v) for r, v in by_rarity}
        # EVERY site, grouped by rule, rarest rule first — not a sample.
        cell["exemplars"] = [s for _, sites in by_rarity for s in sites]
        cell["sites"] = {r: v for r, v in by_rarity}
        # Context and worklist travel WITH the cell so the finder sees them without them having
        # bought an agent call of their own.
        cell["context_corroborating"] = dict(context.get(cell["module"], Counter()).most_common(6))
        cell["u1_worklist"] = dict(worklist.get(cell["module"], Counter()).most_common(6))
        cell_list.append(cell)

    # Modules with enumerator/corroborating output but NO primary hit: no cell, but the U1 worklist
    # is still a real artifact for the mirror-walk. Report the count so it is not silently lost.
    orphan_worklist_modules = sorted(set(worklist) - {c["module"] for c in cell_list})

    # ── LOC, for hits/kloc ──────────────────────────────────────────────────
    loc = 0
    for p in Path(args.src).rglob("*.rs"):
        s = str(p)
        if any(pat.search(s) for _, pat in DROP_PATTERNS):
            continue
        try:
            loc += sum(1 for _ in open(p, "rb"))
        except OSError:
            pass

    by_rule = Counter(h["rule_id"] for h in deduped)
    summary = {
        "crate": args.crate, "commit": args.commit,
        "loc_non_test": loc,
        "raw_hits": len(hits),
        "kept_hits": len(deduped),
        "dropped": dict(dropped),
        "dropped_total": sum(dropped.values()),
        "hits_per_kloc": round(len(deduped) / (loc / 1000), 2) if loc else None,
        "cells": len(cell_list),
        # Roles, not just totals: `primary` is the only number that costs agent time.
        "by_role": dict(roles),
        "module_depth": module_depth,     # how far the module key had to be coarsened to fit MAX_CELLS
        "primary_hits": roles.get("primary", 0),
        "primary_per_kloc": round(roles.get("primary", 0) / (loc / 1000), 2) if loc else None,
        "orphan_worklist_modules": len(orphan_worklist_modules),
        "by_engine": dict(Counter(h["engine"] for h in deduped)),
        "by_class": dict(Counter(h["class"] for h in deduped)),
        "by_clippy_group": dict(Counter(h["group"] for h in deduped if h["group"] != "-")),
        "top_rules": by_rule.most_common(40),
        "rules_firing": len(by_rule),
        "unpublished_members": unpublished,
        "parse_errors": parse_errors,
    }

    (out / "hits.jsonl").write_text("".join(json.dumps(h, default=str) + "\n" for h in deduped))
    (out / "cells.jsonl").write_text("".join(json.dumps(c, default=str) + "\n" for c in cell_list))
    (out / "summary.json").write_text(json.dumps(summary, indent=2))

    # ── SAST-FINDINGS.json — the `/triage` ingest shape ──────────────────────────────────────────
    # One CANDIDATE per cell, never per hit. The bespoke reachability judge this used to feed was
    # measured in E9 and did not gate: 27 `yes` / 2 `no` / 0 `unknown` over 29 cells, a 7 % prune rate,
    # because "is this class of site reachable" is a question with a predetermined answer on a crate
    # whose whole public surface eats untrusted bytes. `/triage` already does the job that pass was
    # reaching for — verify each candidate is real, dedupe across runs and scanners, re-rank by
    # DERIVED exploitability rather than the scanner's claim, and route — and it is battle-tested,
    # has adversarial N-vote verification, and takes `--fp-rules profiles/rust/fp-rules.txt`.
    #
    # Every field below is deliberately non-committal. These are TOOL OUTPUT: `severity` is unknown
    # because no rule here has earned the right to assert one, and the description says so in words,
    # because the receiving skill's first job is to refute.
    findings = []
    for i, c in enumerate(cell_list, 1):
        sites = c["exemplars"]
        head_file, _, head_line = (sites[0] if sites else ":").rpartition(":")
        rules_desc = "; ".join(f"{r} ×{n}" for r, n in c["rules"].items())
        findings.append({
            "id": f"sast{i:03d}",
            "cell_id": c["cell_id"],
            "file": head_file or None,
            "line": int(head_line) if head_line.isdigit() else None,
            "category": c["class"],
            "severity": "unknown",
            "candidate": True,
            # A SCHEDULING prior only — ORDINAL, not a probability, and `/triage` uses it only to
            # decide what to verify first. SMALLER CELL RANKS HIGHER. Two independent measurements
            # say that is the right direction: the h2 pass (the two smallest cells produced both real
            # seeds; the five largest, 527 hits combined, produced none) and E7c (a rule's hits/crate
            # runs inversely to its discrimination rate — 1.9/crate → 11.1 %, 32.5/crate → 0.5 %).
            #
            # First draft used "1/(1 + hits of the rarest rule in the cell)" and was DEGENERATE:
            # almost every cell contains some rule with exactly one hit, so every candidate scored
            # 0.500. Cell size is the signal that actually varies.
            "scanner_confidence": round(1.0 / (1.0 + c["hits"]) ** 0.5, 4),
            "description": (
                f"{c['hits']} static-analysis hits of class `{c['class']}` in `{c['module']}` "
                f"({c['crate']}). Rules, rarest first: {rules_desc}. "
                f"These are TOOL OUTPUT, not findings — most are noise. All {len(sites)} sites are "
                f"listed in `sites` so nothing is hidden behind a sample; read the code and decide."
            ),
            "sites": sites,
            "sites_by_rule": c["sites"],
            "context_corroborating": c.get("context_corroborating", {}),
            "u1_worklist": c.get("u1_worklist", {}),
            "engines": c["engines"],
        })
    (out / "SAST-FINDINGS.json").write_text(json.dumps(
        {"tool": "sast-driven", "target": {"crate": args.crate, "commit": args.commit},
         "note": "cells, not hits: one candidate per (class × module). Unverified by construction.",
         "findings": findings}, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != "top_rules"}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
