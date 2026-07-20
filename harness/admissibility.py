# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Admissibility gates — structural forcing functions on a `real` verdict.

Generalized from BOTH real-OSS campaigns (LESSONS.md L1, L3, L12). The recurring
failure was not a weak model — it was a load-bearing premise that no one made the
pipeline *evidence*:

  * **x509 (L1/L3):** the one wrong verdict rested on an uncited, false claim
    about a dependency's accept-behaviour (`asn1-rs`). A "smarter" review layer
    reproduced the same over-claim — only outside pressure caught it. The fix is
    structural, not smarter: a verdict whose premise is a dependency's behaviour
    is *inadmissible* until it cites that dep's source.
  * **lopdf (L12):** the reattack bridge "reproduced" a finding by constructing
    the target object via the builder API, **bypassing the parser** — the same
    false-reachability trap, one layer up inside the automation. "Reproduced via
    construction" ≠ "reachable from untrusted bytes."
  * **x509 (L3):** a reachability claim with no trace of *where* reachability was
    checked is an assertion, not a finding.

These are one idea: a finding cannot be graded `real` until the specific premise
it stands on is backed by an artifact. This module encodes that as three
independent gates over a `VerdictClaim`, each profile-agnostic — dependencies,
untrusted entry points, and reachability traces exist in *every* ecosystem (a C
library links deps and has a parse entry; an Android app calls SDKs and has an
Intent entry; a Rust crate has both):

  * **dep-citation gate (P0.2/L1):** premise rests on a dependency's behaviour →
    needs `dep_citation` (that dep's `file:line`); missing → CONTESTED.
  * **reachability where-checked gate (P1.4/L3):** the finding claims to be
    reachable → needs `where_checked` (the entry→sink trace that proves it);
    missing → CONTESTED.
  * **harness-construction gate (P0.5/L12):** a reproduction whose harness built
    the object directly (not via the untrusted entry) → UNVERIFIED until it is
    re-reproduced through the real parse/entry.

The result is not a boolean; it is a *disposition* that plugs into the existing
union-of-N / witness vocabulary:

  * ``ADMISSIBLE``  — every relied-on premise is evidenced; grade may proceed.
  * ``CONTESTED``   — a premise is unevidenced; route to the dynamic confirmer
                      (same disposition `aggregate.Candidate.is_contested` uses),
                      NOT a silent `real`.
  * ``UNVERIFIED``  — reproduced, but via a path that does not prove reachability
                      from untrusted input; must be re-verified through the real
                      entry before it can be `real`.

Pure and deterministic — the orchestrator owns the re-runs; this module owns the
decision, so it is unit-testable without agents or containers (same design as
`feedback.py`).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── admissibility states ─────────────────────────────────────────────────────
ADMISSIBLE = "admissible"
CONTESTED = "contested"        # aligns with aggregate.Candidate.is_contested
UNVERIFIED = "unverified"      # reproduced via the wrong path (L12)

# Ordered worst→best so a claim's overall state is the worst gate it trips.
_SEVERITY_ORDER = (UNVERIFIED, CONTESTED, ADMISSIBLE)


def _worst(states: list[str]) -> str:
    for s in _SEVERITY_ORDER:
        if s in states:
            return s
    return ADMISSIBLE


# ── how a reproduction reached the target object ─────────────────────────────
# The untrusted entry (parse/load/Intent) vs an internal builder/constructor.
HARNESS_PARSE_ENTRY = "parse_entry"            # drove the real untrusted-input entry
HARNESS_DIRECT_CONSTRUCTION = "direct_construction"  # built the object via internal API
HARNESS_KINDS: frozenset[str] = frozenset({HARNESS_PARSE_ENTRY, HARNESS_DIRECT_CONSTRUCTION})


@dataclass(frozen=True)
class VerdictClaim:
    """The premises a `real`/`false_positive` verdict stands on. Fields default
    to the permissive value, so a claim that relies on nothing special is
    ADMISSIBLE — the gates only bite when a premise is *declared* and unbacked.

    * ``rests_on_dependency_behavior`` / ``dep_citation`` — P0.2.
    * ``claims_reachable`` / ``where_checked`` — P1.4.
    * ``harness_kind`` — P0.5 (None ⇒ no reproduction harness, gate inactive).
    """
    finding_id: str = ""
    rests_on_dependency_behavior: bool = False
    dep_citation: str | None = None
    claims_reachable: bool = False
    where_checked: str | None = None
    harness_kind: str | None = None

    def __post_init__(self):
        if self.harness_kind is not None and self.harness_kind not in HARNESS_KINDS:
            raise ValueError(
                f"harness_kind {self.harness_kind!r} not in {sorted(HARNESS_KINDS)}")


@dataclass(frozen=True)
class AdmissibilityVerdict:
    state: str
    reasons: tuple[str, ...] = ()

    @property
    def is_admissible(self) -> bool:
        return self.state == ADMISSIBLE

    def to_dict(self) -> dict:
        return {"state": self.state, "reasons": list(self.reasons)}


def _citation_ok(c: str | None) -> bool:
    """A dependency citation must look like `path:line` — a bare "asn1-rs
    rejects it" is exactly the uncited premise L1 forbids."""
    return bool(c) and ":" in c and any(ch.isdigit() for ch in c.rsplit(":", 1)[-1])


def check(claim: VerdictClaim) -> AdmissibilityVerdict:
    """Apply the three gates; the overall state is the worst gate tripped."""
    states: list[str] = []
    reasons: list[str] = []

    # P0.2/L1 — dependency-behaviour premise needs a citation.
    if claim.rests_on_dependency_behavior and not _citation_ok(claim.dep_citation):
        states.append(CONTESTED)
        reasons.append(
            "verdict rests on a dependency's behaviour but has no `dep_citation` "
            "(file:line into that dep's source) — inadmissible premise (L1); "
            "route to dynamic confirm, do not grade real")

    # P1.4/L3 — a reachability claim needs a where-checked trace.
    if claim.claims_reachable and not (claim.where_checked or "").strip():
        states.append(CONTESTED)
        reasons.append(
            "claims reachable but supplies no `where_checked` entry→sink trace — "
            "an assertion, not a finding (L3); route to dynamic confirm")

    # P0.5/L12 — a construction-based reproduction proves nothing about
    # reachability from untrusted input.
    if claim.harness_kind == HARNESS_DIRECT_CONSTRUCTION:
        states.append(UNVERIFIED)
        reasons.append(
            "reproduced by constructing the object directly, bypassing the "
            "untrusted entry (L12) — re-verify through the real parse/entry "
            "(e.g. load_mem on crafted bytes) before grading real")

    return AdmissibilityVerdict(state=_worst(states), reasons=tuple(reasons))


def gate_grade(claim: VerdictClaim) -> bool:
    """Convenience for a stage: may this claim proceed to a `real` grade? True
    only when fully ADMISSIBLE. A CONTESTED/UNVERIFIED claim is NOT graded real —
    it is routed on (dynamic confirm / re-verify)."""
    return check(claim).is_admissible
