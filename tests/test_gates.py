# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""W1b — the grade-time honesty gates actually fire and fold into the verdict."""
from harness import admissibility, build_profile, gates
from harness.artifacts import GraderVerdict


def _passing() -> GraderVerdict:
    return GraderVerdict(passed=True, score=1.0, criteria={"criterion_1": True}, evidence="ok")


def _clean_claim() -> admissibility.VerdictClaim:
    return admissibility.VerdictClaim()  # all-permissive: declares no premise


# ── admissibility gates ───────────────────────────────────────────────────────

def test_clean_passing_verdict_stays_real():
    v = gates.apply_gates(_passing(), profile="rust", crash_signal="use-after-free",
                          claim=_clean_claim(), reproduced_under_shipping=None)
    assert v.passed is True
    assert v.disposition == gates.DISP_REAL
    assert v.gate_reason == ""


def test_declared_dep_premise_without_citation_is_contested():
    claim = admissibility.VerdictClaim(rests_on_dependency_behavior=True, dep_citation=None)
    v = gates.apply_gates(_passing(), profile="rust", crash_signal="oob",
                          claim=claim, reproduced_under_shipping=None)
    assert v.passed is False               # so aggregate won't count it as a passed vote
    assert v.disposition == admissibility.CONTESTED
    assert "dep_citation" in v.gate_reason


def test_cited_dep_premise_stays_real():
    claim = admissibility.VerdictClaim(rests_on_dependency_behavior=True,
                                       dep_citation="asn1-rs/src/lib.rs:412")
    v = gates.apply_gates(_passing(), profile="rust", crash_signal="oob",
                          claim=claim, reproduced_under_shipping=None)
    assert v.passed is True
    assert v.disposition == gates.DISP_REAL


def test_reachability_claim_without_where_checked_is_contested():
    claim = admissibility.VerdictClaim(claims_reachable=True, where_checked=None)
    v = gates.apply_gates(_passing(), profile="rust", crash_signal="oob",
                          claim=claim, reproduced_under_shipping=None)
    assert v.disposition == admissibility.CONTESTED
    assert v.passed is False


def test_construction_only_repro_is_unverified():
    claim = admissibility.VerdictClaim(harness_kind=admissibility.HARNESS_DIRECT_CONSTRUCTION)
    v = gates.apply_gates(_passing(), profile="rust", crash_signal="oob",
                          claim=claim, reproduced_under_shipping=None)
    assert v.disposition == admissibility.UNVERIFIED
    assert v.passed is False


# ── build_profile gate (L10) ──────────────────────────────────────────────────

def test_overflow_panic_not_reverified_is_build_profile_gated():
    # rust arithmetic-overflow marker + no shipping re-test → R7 downgrade.
    v = gates.apply_gates(_passing(), profile="rust",
                          crash_signal="panicked at 'attempt to add with overflow'",
                          claim=_clean_claim(), reproduced_under_shipping=None)
    assert v.passed is False
    assert v.disposition == build_profile.DISP_BUILD_PROFILE_GATED
    assert "shipping build" in v.gate_reason


def test_overflow_panic_reproduced_under_shipping_stays_real():
    v = gates.apply_gates(_passing(), profile="rust",
                          crash_signal="attempt to add with overflow",
                          claim=_clean_claim(), reproduced_under_shipping=True)
    assert v.passed is True
    assert v.disposition == gates.DISP_REAL


def test_non_gated_class_passes_through_without_shipping_retest():
    # a real memory bug is NOT instrumentation-gated → no re-test needed.
    v = gates.apply_gates(_passing(), profile="rust", crash_signal="heap-buffer-overflow",
                          claim=_clean_claim(), reproduced_under_shipping=None)
    assert v.passed is True
    assert v.disposition == gates.DISP_REAL


# ── grader rejection is authoritative; gates never raise a failing grade ───────

def test_rejected_grade_stays_rejected():
    failing = GraderVerdict(passed=False, score=0.0, criteria={}, evidence="not a crash")
    v = gates.apply_gates(failing, profile="rust",
                          crash_signal="attempt to add with overflow",
                          claim=admissibility.VerdictClaim(rests_on_dependency_behavior=True),
                          reproduced_under_shipping=None)
    assert v.passed is False
    assert v.disposition == gates.DISP_REJECTED


def test_verdict_roundtrips_with_new_fields():
    claim = admissibility.VerdictClaim(claims_reachable=True, where_checked=None)
    v = gates.apply_gates(_passing(), profile="rust", crash_signal="oob",
                          claim=claim, reproduced_under_shipping=None)
    back = GraderVerdict.from_dict(v.to_dict())
    assert back.disposition == v.disposition
    assert back.gate_reason == v.gate_reason
    # old records without the new keys still load (backward compat)
    legacy = GraderVerdict.from_dict({"passed": True, "score": 1.0, "criteria": {}, "evidence": "x"})
    assert legacy.disposition == "real" and legacy.gate_reason == ""
