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
#
# RECALL-FIRST (2026-08-01). This was 20, chosen as "what one triage pass can absorb" — i.e. an
# AGENT-BUDGET number controlling a CLUSTERING knob. That conflation costs recall two ways:
#
#   1. Coarsening merges siblings, and a merged cell gets ONE verdict. Measured harm (bringup §5.3):
#      h2's `unsafe` cell merged `hpack/header.rs:283` (decode path, the only real seed) with two
#      `table.rs` hits carrying no `unsafe` at all on the SEND path — "same class name, disjoint
#      trust boundary". One judge refuting the wrong half discards the other half unread. E9 found
#      the same shape independently ("serialize-side merged with parse-side").
#   2. Budget is now managed where it belongs: cells are RANKED (rarest-rule-first) and spent
#      top-down, with the unread tail LOGGED, not merged away. Ordering is not truncation.
#
# So the cap is raised far above the point where coarsening normally triggers, and the cell key
# additionally splits on data-path direction (see data_path_of). If a run legitimately produces more
# cells than the agent budget, that is a RANKING problem, not a reason to fuse trust boundaries.
#
# The number is MEASURED, not guessed — cells at each module depth over the 7 archived runs
# (primary hits only, 2026-08-01):
#
#     crate       prim   d1    d2    d3   file(d9)   files
#     h2           657    27    51    93     118       53
#     httparse     142     7    15    21      21       10
#     hyper         64    13    24    32      34       28
#     lopdf        812    45   122   138     138       66
#     object       686    18    37    82     176       77
#     quick-xml    377     7    41    66      66       25
#     rustls       846    38    46   150     228      114
#     TOTAL             155   336   582     781
#
# Depth 2 is the natural Rust module unit (`src/hpack`, `src/proto/streams`) and the granularity at
# which trust boundaries actually live; 150 keeps every one of these crates at depth 2-3 instead of
# collapsing to `src` (depth 1), where a single cell like `src::panic-surface` would hold 78 sites
# spanning three unrelated subsystems and receive ONE verdict.
#
# NOTE the tradeoff this number does NOT resolve: cells carry every site, so a COARSE cell still
# shows the agent all hits in one read — coarsening loses verdict independence, not site coverage.
# Finer cells cost proportionally more agent calls, and any cell left unread is coverage lost
# outright. That is why the complementary fix is a PER-SITE-GROUP verdict (see SKILL.md): a coarse
# cell must never be refutable wholesale.
MAX_CELLS = 150

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

# ── enclosing function / impl, for the data-path split ───────────────────────────────────────────
# A hit's trust boundary is a property of the code it sits in, not of its filename. Cheap resolver:
# index every `fn` / `impl` header in the file, then bind a hit line to the nearest preceding one.
# Fail-open in every direction — an unreadable file or an unrecognised header yields "", which keeps
# the old (path-only) behaviour, so this can only ever SPLIT a cell, never merge two.
FN_DECL = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"(?:extern\s+\"[^\"]*\"\s+)?fn\s+(\w+)")
IMPL_DECL = re.compile(r"^\s*(?:unsafe\s+)?impl(?:\s*<[^>]*>)?\s+(?:([\w:]+)\s+for\s+)?([\w:<>]+)")
_fnidx_cache: dict[str, list[tuple[int, str]]] = {}


def fn_index(src_root: str, rel: str) -> list[tuple[int, str]]:
    """[(line, 'Impl::fn'), …] ascending, 1-based."""
    if rel in _fnidx_cache:
        return _fnidx_cache[rel]
    out: list[tuple[int, str]] = []
    try:
        text = (Path(src_root) / rel).read_text(errors="replace").splitlines()
    except Exception:                                       # noqa: BLE001 — unreadable: no claim
        _fnidx_cache[rel] = out
        return out
    cur_impl = ""
    for n, ln in enumerate(text, 1):
        mi = IMPL_DECL.match(ln)
        if mi:
            cur_impl = mi.group(1) or mi.group(2) or ""
        mf = FN_DECL.match(ln)
        if mf:
            out.append((n, f"{cur_impl}::{mf.group(1)}" if cur_impl else mf.group(1)))
    _fnidx_cache[rel] = out
    return out


def enclosing_context(src_root: str, rel: str, line: int) -> str:
    idx = fn_index(src_root, rel)
    name = ""
    for n, nm in idx:
        if n <= line:
            name = nm
        else:
            break
    return name


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
    # CodeQL (L1, 2026-08-01). The class × ENGINE grid says no engine dominates and four classes
    # INVERT between ast-grep and CodeQL — mutual recursion A→B→A (ast-grep N / CodeQL R), counter
    # width & type disambiguation (N / R), guard DOMINANCE vs mere presence (E / R), allocation via
    # helper/field dataflow (E / R). E13 ran opengrep+astgrep+clippy+audit+dylint+geiger and NO
    # CodeQL, so those four classes were structurally unreachable in the run that produced 24 finds.
    # Adding the engine is the cheapest recall gain available: no rule authoring, and the queries and
    # databases already exist.
    ("codeql.sarif", "codeql", parse_sarif),
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
        # Depth counts path components INCLUDING the file, so the finest granularity is one cell per
        # (class × file) rather than per (class × directory). Directory-level was the granularity in
        # which h2's §5.3 fusion happened: `hpack/header.rs` (decode) and `hpack/table.rs` (send) are
        # siblings, so no directory key can separate them, and the direction is not in either name.
        # File-level cannot fuse two files by construction; coarser levels still merge siblings when
        # the cap forces it, and that is now recorded in module_depth.
        parts = Path(path).parts
        return str(Path(*parts[:depth])) if parts[:depth] else "."

    # ── data-path direction: the trust boundary the coarsened module key cannot see ──────────────
    # Measured defect (bringup §5.3): one cell merged a DECODE-path site with SEND-path sites under
    # the same class+module key — "same class name, disjoint trust boundary" — and a single verdict
    # then covers both. E9 independently reported "serialize-side merged with parse-side" as one of
    # its three upstream defects. Direction is the cheapest discriminator that separates them: on a
    # parser crate the attacker-facing half is the read/decode half, and mixing it with the emit half
    # is what makes a cell unjudgeable.
    #
    # Deliberately coarse and fail-open: anything that does not clearly say read or write becomes
    # "" (unclassified) and keeps its old behaviour, so this can only SPLIT cells, never merge them.
    # Boundary class includes ':' — enclosing contexts arrive as `Impl::fn` (`Recv::recv_headers`,
    # `Encoder::update_max_size`), and a boundary of just [/_.] silently failed to match every one
    # of them. Caught by testing the resolver against real h2 source rather than trusting the regex.
    _READ = re.compile(r"(^|[/_:])(de|dec|decode|decoder|decoding|read|reader|parse|parser|parsing|"
                       r"recv|receive|input|inflate|decompress|demux|demuxer|scan|scanner|lex|lexer)"
                       r"([/_.:]|$)")
    _WRITE = re.compile(r"(^|[/_:])(en|enc|encode|encoder|encoding|write|writer|ser|serialize|"
                        r"serializer|send|emit|output|deflate|compress|mux|muxer|build|builder)"
                        r"([/_.:]|$)")

    def _dir_of_text(s: str) -> str:
        s = s.lower()
        r, w = bool(_READ.search(s)), bool(_WRITE.search(s))
        if r and not w:
            return "read"
        if w and not r:
            return "write"
        return ""

    def data_path_of(path: str, line: int | None = None) -> str:
        # The ENCLOSING FUNCTION first, the path second. Measured reason: in the h2 §5.3 case the
        # direction was not in the path at all — `hpack/header.rs` (decode) and `hpack/table.rs`
        # (send) are both direction-neutral as filenames, which is exactly why they fused. The
        # decode/emit split lives in the function the hit sits in (`decode*` vs `encode*`/`put_*`),
        # so resolve that first and fall back to the path only when the code context says nothing.
        if line:
            ctx = enclosing_context(args.src, path, line)
            d = _dir_of_text(ctx)
            if d:
                return d
        return _dir_of_text(path)

    primaries = [h for h in deduped if h["role"] == "primary"]
    depth = 9
    for d in range(9, 0, -1):
        if len({(h["class"], module_of(h["file"], d), data_path_of(h["file"], h.get("line")))
                for h in primaries}) <= MAX_CELLS:
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
        direction = data_path_of(h["file"], h.get("line"))
        key = (h["class"], module, direction)
        _dsuffix = f"::{direction}" if direction else ""
        cell = cells.setdefault(key, {
            "cell_id": f"{args.crate}@{args.commit[:8]}/{module}::{h['class']}{_dsuffix}",
            "class": h["class"], "module": module, "data_path": direction, "crate": args.crate,
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

    # ── coverage-gap cells: the files NO rule pointed at ─────────────────────────────────────────
    # Measured 2026-08-01 over the 7 archived runs: only **262 of 419** shipped .rs files (63 %) carry
    # a single primary hit, and **25 % of shipped LOC (58,513 of 236,389)** is untouched. Code that no
    # rule points at is code no reader ever opens, so that 25 % is a pure recall hole — and it is not
    # empty space: in one corpus crate the two largest blind files (3.2k and 2.1k LOC) turned out to
    # hold both halves of a defect confirmed later by a reader — the guard in one, the sink in the
    # other. Neither file had a single rule hit.
    #
    # Why they are blind is NOT a sink-vocabulary gap — `reserve`/`with_capacity`/`resize` are all in
    # cls-alloc already. It is the SOURCE side: tier 2 requires the size to come from a parse call
    # (`read_u32`, `from_be_bytes`, …) in the same expression, and those two files contain **zero**
    # such calls. Their sizes come from struct fields and `.len()` — i.e. parse → field → (elsewhere)
    # → sink, which no single-expression pattern can express. Widening the rule to match would drop
    # its precision to nil; the recall-first answer is to stop requiring a rule to be right and just
    # put a reader in front of the file, which is the layer's actual job ("narrow scope, not aim").
    #
    # So: one cell per blind file that contains at least one sink-shaped construct, carrying those
    # lines as its sites. These are explicitly LOW-confidence (`scanner_confidence: 0.0`) and rank
    # last by construction; they exist to make coverage complete, not to make a claim.
    GAP_SINKS = {
        "alloc":      re.compile(r"\b(?:with_capacity|reserve_exact|reserve|resize_with|resize|set_len)\s*\(|vec!\s*\["),
        "index":      re.compile(r"\[[A-Za-z_]\w*(?:\s*[-+*]\s*[\w.]+)?\s*(?:as\s+\w+\s*)?\]"),
        "arith_sub":  re.compile(r"[\w)\]]\s*-\s*[\w(]"),
        "cast":       re.compile(r"\bas\s+(?:usize|u8|u16|u32|u64|i8|i16|i32|i64)\b"),
        "unwrap":     re.compile(r"\.(?:unwrap|expect)\s*\("),
        "unsafe":     re.compile(r"\bunsafe\s*\{|get_unchecked|from_utf8_unchecked"),
    }
    hit_files = {h["file"] for h in deduped if h["role"] == "primary"}
    gap_cells: list[dict] = []
    for p in sorted(Path(args.src).rglob("*.rs")):
        relp = str(p.relative_to(args.src))
        if relp in hit_files:
            continue
        if next((why for why, pat in DROP_PATTERNS if pat.search(relp)), None):
            continue                                            # tests/benches/examples/generated
        if any(relp == d or relp.startswith(d + "/") for d in unpublished):
            continue                                            # publish = false workspace member
        try:
            text = p.read_text(errors="replace")
        except Exception:                                       # noqa: BLE001 — unreadable: no claim
            continue
        sites: dict[str, list[str]] = {}
        for n, line_txt in enumerate(text.splitlines(), 1):
            if n in cfg_test_lines(args.src, relp):
                continue
            # COMMENTS AND DOC EXAMPLES ARE NOT SINKS. Caught by the prioritisation stage on
            # quick-xml `src/writer/async_tokio.rs`: all 24 "sink-shaped" lines were `///` doc
            # examples and `#[cfg(test)]` code — 15 of them `str::from_utf8(&buf).unwrap()` inside
            # rustdoc snippets. The cell scored 0.75 and an agent call went on a file with no sink in
            # it at all. `cfg_test_lines` already handles the test block; rustdoc examples are the
            # other half, and they are the more misleading one because they LOOK like shipped code.
            stripped = line_txt.lstrip()
            if stripped.startswith(("///", "//!", "//")):
                continue
            # ATTRIBUTES ARE NOT INDEXING. `#[inline]`, `#[derive(...)]`, `#[cfg(...)]` all match the
            # `index` pattern on their brackets. Measured on actix-web `response/responder.rs`, where
            # three of the five cited sites were `#[inline]` lines and the rest were markdown link
            # brackets and `/// - ` bullets inside the doc block — a 367-line file of trait impls that
            # scored the maximum prior and cost an agent call to establish it contains no logic at all.
            if stripped.startswith("#["):
                continue
            for kind, rx in GAP_SINKS.items():
                if rx.search(line_txt):
                    sites.setdefault(f"coverage-gap:{kind}", []).append(f"{relp}:{n}")
        if not sites:
            continue                                            # genuinely nothing sink-shaped here
        by_rarity = sorted(sites.items(), key=lambda kv: (len(kv[1]), kv[0]))
        gap_cells.append({
            "cell_id": f"{args.crate}@{args.commit[:8]}/{relp}::coverage-gap",
            "class": "coverage-gap", "module": relp,
            "data_path": data_path_of(relp), "crate": args.crate,
            "hits": sum(len(v) for v in sites.values()),
            "engines": {"coverage-gap": 1},
            "rules": {r: len(v) for r, v in by_rarity},
            "sites": {r: v for r, v in by_rarity},
            "exemplars": [s for _, ss in by_rarity for s in ss],
            "loc": text.count("\n") + 1,
            "filters": {"structural": "kept", "capability": "unevaluated",
                        "reachability": "unjudged", "where_checked": None},
            "context_corroborating": {}, "u1_worklist": {},
            "note": "NO rule fired anywhere in this file. Sites are sink-SHAPED lines found by a "
                    "plain scan, not a rule claim — read the file, do not triage the list.",
        })
    # Ranking. LOC alone is the wrong signal, measured: lopdf's `src/encodings/glyphnames.rs` (3,804
    # LOC) ranked second on LOC while being a pure DATA TABLE — 3,281 of its 3,283 "sites" are the
    # `index` pattern firing inside a glyph-table macro. Rank instead on the sink kinds that imply
    # LOGIC (alloc / unsafe / unwrap); `index`, `cast` and `arith_sub` stay in the evidence but do not
    # rank, because they fire on essentially any Rust file. Data tables sink to the bottom on their
    # own without a filter deciding they are uninteresting (L6: rank, never cut).
    def _logic_weight(c: dict) -> int:
        return sum(len(v) for k, v in c["sites"].items()
                   if k.rsplit(":", 1)[-1] in ("alloc", "unsafe", "unwrap"))

    gap_cells.sort(key=lambda c: (-_logic_weight(c), -c.get("loc", 0)))
    cell_list.extend(gap_cells)

    # ── limit-pair cells: the mirror walk, precomputed ───────────────────────────────────────────
    # Limit-bypass is the single most common mechanism behind our disclosed findings (5 clusters
    # across 5 crates: object, miniz_oxide, ciborium, fdeflate, image) and NO single-site rule can
    # express it — "a cap exists; some input shape reaches the path that ignores it. No individual
    # line is wrong." But BOTH halves are enumerable, and the comparison between them is exactly the
    # mirror walk. So enumerate the halves and hand over the ASYMMETRY as the unit of work.
    #
    # Measured on object with the current pack (2026-08-01): 287 declaration sites against 13
    # enforcement sites, and the asymmetry is concentrated, not uniform — `src/macho.rs` 55 declared
    # / 0 enforced, `src/write/elf` 54 / 5, `src/pe.rs` 39 / 0. A module that declares dozens of caps
    # and enforces none is a question worth an agent; a 1:1 module is not.
    LIMIT_DECL = ("limit-field", "limit-fn", "limit-init", "limit-const", "limit-magic")
    pair: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for h in deduped:
        rid = h.get("rule_id", "")
        if "limit-" not in rid:
            continue
        site = f"{h['file']}:{h.get('line')}"
        mod = module_of(h["file"], min(module_depth + 1, 3))
        if any(k in rid for k in LIMIT_DECL):
            pair[mod]["declared"].append(site)
        elif "limit-guard" in rid:
            pair[mod]["enforced"].append(site)
        elif "limit-optout" in rid:
            pair[mod]["opted-out"].append(site)
    limit_cells = []
    for mod, groups in pair.items():
        ndecl, nenf = len(groups.get("declared", [])), len(groups.get("enforced", []))
        if not ndecl:
            continue                                            # no cap declared here: nothing to mirror
        limit_cells.append({
            "cell_id": f"{args.crate}@{args.commit[:8]}/{mod}::limit-pair",
            "class": "limit-pair", "module": mod, "data_path": "", "crate": args.crate,
            "hits": sum(len(v) for v in groups.values()),
            "engines": {"astgrep": 1},
            "rules": {k: len(v) for k, v in groups.items()},
            "sites": {k: v for k, v in groups.items()},
            "exemplars": [s for v in groups.values() for s in v],
            "declared": ndecl, "enforced": nenf, "gap": ndecl - nenf,
            "filters": {"structural": "kept", "capability": "unevaluated",
                        "reachability": "unjudged", "where_checked": None},
            "context_corroborating": {}, "u1_worklist": {},
            "note": f"{ndecl} cap DECLARATIONS vs {nenf} ENFORCEMENT sites in this module. The unit "
                    "of work is the COMPARISON, not either list: for each declared cap, find the "
                    "path that reaches the guarded operation without consulting it. A declared-but-"
                    "never-enforced cap is the limit-bypass shape; an enforced one is control.",
        })
    limit_cells.sort(key=lambda c: -c["gap"])
    cell_list.extend(limit_cells)

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
    # ── which clippy rung actually produced the artifact ─────────────────────────────────────────
    # `run_fb` tries `--all-features` first and falls back to the default feature set. Both write the
    # SAME artifact, so the hits are complete either way — but the two rungs scan DIFFERENT code:
    # feature-gated modules only exist in the all-features build. Measured over the 25-crate corpus:
    # 15 crates scanned at all-features, 10 at default, because `--all-features` pulls in native
    # build-script dependencies that cannot build offline (`dav1d-sys`, `aws-lc-fips-sys`) or feature
    # combinations that do not compile. That is a real inhomogeneity in the corpus and it was only
    # inferable by cross-reading engine statuses; record it as a first-class field instead.
    feature_mode = "unknown"
    try:
        eng = [json.loads(l) for l in (Path(args.out) / "engines.jsonl").read_text().splitlines() if l.strip()]
        st = {e["engine"]: e["status"] for e in eng}
        if st.get("clippy") == "ok":
            feature_mode = "all-features"
        elif st.get("clippy-fb") == "ok":
            feature_mode = "default-features"
        elif "clippy" in st:
            feature_mode = "clippy-produced-nothing"
    except Exception:                                           # noqa: BLE001 — absent log: no claim
        pass

    summary = {
        "crate": args.crate, "commit": args.commit,
        "clippy_feature_mode": feature_mode,
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
