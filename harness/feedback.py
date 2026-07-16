# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Cross-stage feedback loops (P2) — thin state machines, new edges only.

The pipeline is a DAG (find→grade→judge→report→patch, plus the reattack bridge).
The evaluation showed three places a *feedback edge* recovers recall the one-shot
DAG leaves on the table (L6/L11/L16):

  1. **loop-until-dry** — keep re-finding until a whole pass adds no new union
     member. A fixed `--runs N` stops at N even when run N+1 would have surfaced a
     tail bug; a dry-streak stop adapts to the target's variance.
  2. **residual→escalate** — a clean reattack whose `residual_reason` names a
     missing rung escalates to exactly that rung, ONCE (bounded — no infinite
     climb). needs-MSan → MSan, asan-on-C → FFI-ASan, grammar-gated → grammar.
  3. **triage→fuzz-confirm** — a CONTESTED candidate (flip-flops across votes, no
     passed grade) skips a final static verdict and auto-dispatches to the dynamic
     confirmer. The dynamic verdict is authoritative (the "Miri settles 0021"
     move, automated).

All pure/deterministic here — the orchestrator (cli) owns the actual re-runs; this
module owns the DECISIONS (continue? escalate where? confirm what?). Keeping the
control logic pure makes it unit-testable without spinning agents/containers.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .aggregate import AggregateResult, Candidate
from .rust.find_to_fuzz import escalate_rung, Dispatch  # re-exported edge (2)

__all__ = [
    "union_signatures", "new_members", "LoopUntilDry",
    "escalate_rung", "contested_to_findings",
]


# ── edge 1: loop-until-dry ───────────────────────────────────────────────────
def union_signatures(agg: AggregateResult) -> set[tuple[str, str]]:
    """The (crash_type, site) set an aggregate represents — the union membership."""
    return {c.signature for c in agg.candidates}


def new_members(before: set[tuple[str, str]],
                after: set[tuple[str, str]]) -> set[tuple[str, str]]:
    """Signatures present after a pass that weren't before — what the pass added."""
    return after - before


@dataclass
class LoopUntilDry:
    """Drives re-find rounds until K consecutive passes add no new union member.

    A simple `while count < N` misses the tail (L6); a dry-streak stop keeps going
    exactly as long as passes are still productive, bounded by max_rounds and the
    caller's token/time budget.

    Usage per round:
        loop = LoopUntilDry(k=2, max_rounds=8)
        while loop.should_continue():
            agg = run_a_find_pass_and_aggregate()      # caller's job
            loop.observe(union_signatures(agg))
    """
    k: int = 2                      # dry passes in a row required to stop
    max_rounds: int = 8             # hard cap regardless of dryness
    seen: set[tuple[str, str]] = field(default_factory=set)
    dry_streak: int = 0
    rounds: int = 0
    last_added: int = 0             # members the most recent pass added

    def should_continue(self) -> bool:
        return self.rounds < self.max_rounds and self.dry_streak < self.k

    def observe(self, pass_signatures: set[tuple[str, str]]) -> int:
        """Record one pass's union; update the dry streak. Returns members added."""
        added = new_members(self.seen, pass_signatures)
        self.last_added = len(added)
        self.seen |= added
        self.dry_streak = 0 if added else self.dry_streak + 1
        self.rounds += 1
        return self.last_added

    @property
    def stopped_dry(self) -> bool:
        """True if we stopped because passes went dry (not because of the cap)."""
        return self.dry_streak >= self.k


# ── edge 3: triage → fuzz-confirm ────────────────────────────────────────────
def _crash_type_to_cwe(crash_type: str) -> str:
    """Minimal class→CWE for auto-dispatch (mirrors cli._crash_type_to_cwe for the
    common classes; the cli version is authoritative when operation is known)."""
    ct = (crash_type or "").lower()
    if "use-after-free" in ct:
        return "CWE-416"
    if "double-free" in ct:
        return "CWE-415"
    if "uninitialized" in ct:
        return "CWE-908"
    if "race" in ct:
        return "CWE-362"
    if "arith-overflow" in ct or "capacity overflow" in ct:
        return "CWE-190"
    return "CWE-125"


def contested_to_findings(agg: AggregateResult) -> list[dict]:
    """Turn CONTESTED candidates into reattack findings (auto-dispatch to the
    dynamic confirmer). Non-contested candidates are left to the normal path."""
    out: list[dict] = []
    for i, c in enumerate(agg.contested()):
        out.append({
            "finding_id": f"contested_{i:02d}",
            "cwe": _crash_type_to_cwe(c.crash_type),
            "site": c.site,
            "mechanism": f"CONTESTED: {c.crash_type}, {c.vote_str()} votes, 0 passed "
                         f"— static/grade did not settle it; dynamic verdict authoritative",
        })
    return out
