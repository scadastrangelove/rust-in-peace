# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Union-of-N aggregation — recall-first cross-run merge.

The pipeline is find→(fuzz)→review: recall is the objective and false positives
are filtered cheaply downstream, so the right cross-run combiner is **union, not
majority**. On rust-mizan, single-run recall swung 2..8/11 on *identical* inputs
(L13); the apparent "75%→72% regression" was pure noise. Union ≥1/5 scored 82%
vs a majority vote's 36% — and two real Rudra recoveries were visible ONLY
through voting. So a second independent derivation of a crash SITE is not
redundancy to suppress; it is the *vote* that proves the finding real.

This module sits at the *aggregation* layer, never in the search: agents still
hunt freely (dedup during search starves later agents of recall — L13). We merge
their `result.json`s afterward, keyed by (crash-class + crash-site) — not exact
line (L4: right-verdict / wrong-line true positives share a root cause) — and
attach `votes: k/N` per candidate for downstream ordering.

`union` keeps every candidate ≥1 run found (the default). `majority` keeps only
k*2 > N — offered for precision-first callers, but it is NOT the recommended
default for `profile: rust`.

Reuses `dedup._signature` so a candidate's key matches the `dedup`/`report`
grouping exactly.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .dedup import dedup, NO_FRAME

AGG_MODES = ("union", "majority")

# Which grade statuses count a run as having "confirmed" the candidate.
_PASSED = "crash_found"

# Union keys on CWE + crash-SITE, NOT exact line (L4: a right-verdict/wrong-line
# true positive shares the root cause — e.g. a panic the finder localized one
# line off is the same bug). Strip a trailing `:<line>` or `:<line>:<col>` so
# `parse::read /src/p.rs:120:18` and `:121` collapse to one candidate. The
# function + file identity is kept; only the line/col is dropped.
_LINE_SUFFIX = re.compile(r":\d+(?::\d+)?\s*$")


def _site_key(frame: str) -> str:
    if frame == NO_FRAME:
        return frame
    return _LINE_SUFFIX.sub("", frame).rstrip()


@dataclass(frozen=True)
class Candidate:
    """One unique (class, site) finding merged across a batch's runs."""
    crash_type: str
    site: str                    # top project frame; NO_FRAME if none parsed
    votes: int                   # distinct runs that independently found it
    n_runs: int                  # runs in the batch (the vote denominator)
    passed_votes: int            # of those, runs whose grade passed
    operations: tuple[str, ...]  # parsed operation(s) seen (read/write/alloc/…)
    best_path: Path              # representative result.json (passed > smaller PoC)
    run_paths: tuple[Path, ...]  # every result.json in the group

    @property
    def signature(self) -> tuple[str, str]:
        return (self.crash_type, self.site)

    @property
    def is_confirmed(self) -> bool:
        """≥2 independent votes OR a passed grade — the "proved real" bar the
        journal used (a lone unverified single-run hit stays a candidate)."""
        return self.votes >= 2 or self.passed_votes >= 1

    def vote_str(self) -> str:
        return f"{self.votes}/{self.n_runs}"


@dataclass(frozen=True)
class AggregateResult:
    mode: str
    n_runs: int
    candidates: tuple[Candidate, ...]   # already filtered by mode + ordered

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "n_runs": self.n_runs,
            "n_candidates": len(self.candidates),
            "candidates": [
                {
                    "crash_type": c.crash_type,
                    "site": None if c.site == NO_FRAME else c.site,
                    "votes": c.votes,
                    "n_runs": c.n_runs,
                    "vote_fraction": f"{c.votes}/{c.n_runs}",
                    "passed_votes": c.passed_votes,
                    "operations": list(c.operations),
                    "confirmed": c.is_confirmed,
                    "best": str(c.best_path),
                    "runs": [str(p) for p in c.run_paths],
                }
                for c in self.candidates
            ],
        }


def count_runs(results_root: Path) -> int:
    """Runs in the batch = the vote denominator. Multi-run layout is
    `run_NNN/` subdirs; single-run is a top-level `result.json` (== 1 run).
    Falls back to the number of distinct result.json parents if neither shape
    is present (e.g. a hand-assembled dir)."""
    run_dirs = list(results_root.glob("run_[0-9][0-9][0-9]"))
    if run_dirs:
        return len(run_dirs)
    if (results_root / "result.json").exists():
        return 1
    parents = {p.parent for p in results_root.rglob("result.json")}
    return max(1, len(parents))


def _run_id(path: Path, results_root: Path) -> Path:
    """The run a result.json belongs to — its `run_NNN` dir, or the batch root
    for the single-run layout. Two crashes with the same signature from the same
    run count as ONE vote (votes = distinct runs, not distinct crashes)."""
    parent = path.parent
    if parent.name.startswith("run_"):
        return parent
    return results_root


def _poc_len(result_path: Path) -> int:
    try:
        crash = json.loads(result_path.read_text()).get("crash") or {}
    except (OSError, json.JSONDecodeError):
        return 1 << 30
    return len(crash.get("poc_bytes") or "")   # base64 len is monotone in real size


def aggregate(results_root: Path, mode: str = "union") -> AggregateResult:
    """Merge a batch's runs into unique (class, site) candidates with vote
    counts. `union` keeps all; `majority` keeps k*2 > N."""
    if mode not in AGG_MODES:
        raise ValueError(f"unknown aggregate mode {mode!r}; known: {', '.join(AGG_MODES)}")

    n = count_runs(results_root)
    raw = dedup(results_root)   # {(crash_type, frame): [(path, status, reason), ...]}
    # Re-bucket by CWE + line-stripped site so wrong-line duplicates of one root
    # cause become a single voted candidate (L4), not N one-vote fragments.
    merged: dict[tuple[str, str], list] = {}
    for (crash_type, frame), entries in raw.items():
        merged.setdefault((crash_type, _site_key(frame)), []).extend(entries)

    cands: list[Candidate] = []
    for (crash_type, site), entries in merged.items():
        runs_hit: set[Path] = set()
        passed_runs: set[Path] = set()
        ops: list[str] = []
        for path, status, reason in entries:
            rid = _run_id(path, results_root)
            runs_hit.add(rid)
            if status == _PASSED:
                passed_runs.add(rid)
            if (op := (reason or {}).get("operation")) and op not in ops:
                ops.append(op)
        # Representative: passed grade first, then smallest PoC, then path order.
        best = min(
            entries,
            key=lambda e: (0 if e[1] == _PASSED else 1, _poc_len(e[0]), str(e[0])),
        )[0]
        cands.append(Candidate(
            crash_type=crash_type, site=site,
            votes=len(runs_hit), n_runs=n, passed_votes=len(passed_runs),
            operations=tuple(sorted(ops)),
            best_path=best, run_paths=tuple(sorted(p for p, _s, _r in entries)),
        ))

    if mode == "majority":
        cands = [c for c in cands if c.votes * 2 > n]
    # union keeps everything.

    # Order: most-voted first, then confirmed, then passed, then signature.
    cands.sort(key=lambda c: (-c.votes, not c.is_confirmed, -c.passed_votes,
                              c.crash_type, c.site))
    return AggregateResult(mode=mode, n_runs=n, candidates=tuple(cands))


def format_report(agg: AggregateResult, root: Path | None = None) -> str:
    if not agg.candidates:
        return f"No candidates ({agg.mode} over {agg.n_runs} run(s)).\n"
    n_conf = sum(1 for c in agg.candidates if c.is_confirmed)
    lines = [
        f"{len(agg.candidates)} candidate(s) [{agg.mode}, N={agg.n_runs}] "
        f"— {n_conf} confirmed (≥2 votes or a passed grade):",
        "",
    ]
    for c in agg.candidates:
        where = f" in {c.site}" if c.site != NO_FRAME else ""
        ops = f" ({'/'.join(c.operations)})" if c.operations else ""
        flag = "✓" if c.is_confirmed else " "
        passed = f", {c.passed_votes} passed" if c.passed_votes else ""
        lines.append(f"[{flag}] votes {c.vote_str()}{passed}  {c.crash_type}{ops}{where}")
        shown = c.best_path.relative_to(root) if root else c.best_path
        lines.append(f"      best: {shown}")
    lines.append("")
    return "\n".join(lines)
