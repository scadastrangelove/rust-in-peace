# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Reachability oracle (P2) — an honest verdict for the non-reproduction.

rust-mizan 0040 sat clean across 8.5M runs in three modalities. The honest
conclusion was "unreachable / mislabeled as-extracted" — but "0 crashes" alone
does NOT prove that (L18: the honest verdict needs a proof, not more fuzz time).
This module gates the `suspected-unreachable` verdict behind a discipline so it
can't be reached by simply giving up early:

  reproduced          — the harness crashed. Done.
  residual            — clean, but a NAMED missing rung explains it (needs-MSan,
                        asan-on-C, grammar-gated, address-space-only). Escalate
                        that rung (see feedback.escalate_rung); do NOT call it
                        unreachable.
  suspected-unreachable — clean, no rung explains it, AND (a) the modality budget
                        is met (blind ∪ coverage ∪ grammar ∪ Miri ∪ MSan ≥ N
                        runs), AND (b) a static reachability read of the seeded
                        line's guards was supplied (what dominates the sink). Only
                        then is non-reproduction evidence of unreachability — and
                        even then the next step is symbolic execution, not a
                        louder "0 bugs".

The tri-state keeps a human in the loop for the last verdict (L14/L18): declaring
a residual a benchmark/label artifact is a judgment the pipeline surfaces with
evidence, it does not auto-file.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Residuals that NAME a concrete missing rung — these are `residual`, never
# `suspected-unreachable` (there IS a next thing to try).
_NAMED_RUNGS = frozenset({
    "needs-MSan", "asan-on-C", "grammar-gated", "address-space-only",
})

# Default: unreachability may only be *suspected* after this many union runs
# across modalities (blind ∪ coverage ∪ grammar ∪ Miri ∪ MSan).
DEFAULT_MODALITY_THRESHOLD = 5

REACHABILITY_STATES = ("reproduced", "residual", "suspected-unreachable")


@dataclass
class ModalityBudget:
    """Runs spent per modality — the union is what the budget gate checks. A
    finding fuzzed 3M times blind but never under Miri has NOT met a Miri-shaped
    budget; count modalities, not raw executions."""
    blind: int = 0
    coverage: int = 0
    grammar: int = 0
    miri: int = 0
    msan: int = 0

    def modalities_run(self) -> list[str]:
        return [k for k, v in (("blind", self.blind), ("coverage", self.coverage),
                               ("grammar", self.grammar), ("miri", self.miri),
                               ("msan", self.msan)) if v > 0]

    def met(self, threshold: int = DEFAULT_MODALITY_THRESHOLD) -> bool:
        """Budget is met when ≥2 distinct modalities ran AND their combined run
        count clears the threshold — a single modality, however many runs, is not
        enough to suspect unreachability (0040 needed blind ∪ coverage ∪ grammar)."""
        total = self.blind + self.coverage + self.grammar + self.miri + self.msan
        return len(self.modalities_run()) >= 2 and total >= threshold


@dataclass
class ReachabilityVerdict:
    state: str                       # one of REACHABILITY_STATES
    reason: str
    modalities: list[str] = field(default_factory=list)
    guard_read: str | None = None    # the static guard trace, if supplied
    symbolic_plan: dict | None = None

    @property
    def is_terminal(self) -> bool:
        """reproduced and suspected-unreachable are terminal; residual escalates."""
        return self.state in ("reproduced", "suspected-unreachable")

    def to_dict(self) -> dict:
        return {
            "state": self.state, "reason": self.reason,
            "modalities": self.modalities, "guard_read": self.guard_read,
            "symbolic_plan": self.symbolic_plan,
        }


def symbolic_escalation_plan(site: str, guard_read: str | None) -> dict:
    """The escalation PAST the fuzz budget (L18): a symbolic-execution plan over
    the guarded path to the seeded sink. We don't run KLEE/haybale here (heavy,
    per-target build) — we emit the plan an operator or a later stage executes.
    A SAT model = a reaching input (reproduction); UNSAT under the guards = a
    proof of unreachability, which is what the honest verdict actually needs."""
    return {
        "tool": "haybale (Rust/LLVM symbolic executor) — or KLEE over the LLVM bitcode",
        "target_path": site,
        "constraints": guard_read or "(no guard read supplied — read the sink's dominating guards first)",
        "goal": "solve for an input that satisfies the guards AND reaches the sink",
        "interpretation": {
            "sat": "the model is a reaching input → feed it back as a fuzz seed / PoC (reproduced)",
            "unsat": "no input satisfies the guards to the sink → PROOF of unreachable-as-extracted",
            "timeout": "inconclusive → remains `residual`, not `suspected-unreachable`",
        },
    }


def classify(
    *,
    reproduced: bool,
    residual_reason: str,
    modality_budget: ModalityBudget,
    static_guard_read: str | None = None,
    site: str = "",
    threshold: int = DEFAULT_MODALITY_THRESHOLD,
) -> ReachabilityVerdict:
    """The tri-state decision. `static_guard_read` is the mandatory read of the
    seeded line's dominating guards — without it we cannot conclude unreachable,
    only `residual`."""
    mods = modality_budget.modalities_run()
    if reproduced:
        return ReachabilityVerdict("reproduced", "harness crashed as intended", mods)

    if residual_reason in _NAMED_RUNGS:
        return ReachabilityVerdict(
            "residual", f"named missing rung: {residual_reason} — escalate that rung", mods)

    # Clean, no named rung. Unreachability may only be SUSPECTED with both gates.
    if not modality_budget.met(threshold):
        return ReachabilityVerdict(
            "residual",
            f"budget not met ({'+'.join(mods) or 'none'} < {threshold} across ≥2 modalities) "
            f"— fuzz more before concluding anything",
            mods)
    if not static_guard_read:
        return ReachabilityVerdict(
            "residual",
            "budget met but no static guard read supplied — read the sink's "
            "dominating guards before suspecting unreachability",
            mods)

    # Both gates cleared: suspect unreachable, and hand off the proof to symbolic.
    return ReachabilityVerdict(
        "suspected-unreachable",
        "clean across the modality budget AND the seeded sink's guards block every "
        "traced path — likely unreachable-as-extracted (needs symbolic proof)",
        mods,
        guard_read=static_guard_read,
        symbolic_plan=symbolic_escalation_plan(site, static_guard_read),
    )
