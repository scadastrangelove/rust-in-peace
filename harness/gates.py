# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Grade-time honesty gates — the call-site that makes admissibility + build_profile
actually fire (W1b).

`admissibility.py` and `build_profile.py` are pure gate logic; until now nothing
invoked them from a stage, so a grader's `passed=True` shipped straight through.
This module is the one place `run_grade` calls after the grader returns: it folds
the gate dispositions back into the `GraderVerdict` so a gated finding is NOT a
passed grade — it flows through the EXISTING aggregate/dedup path (passed=False →
status `crash_rejected` → not a passed vote → the candidate routes to
CONTESTED/dynamic-confirm), with no change to aggregate.py.

Additive & backward-compatible by construction:
  * A grader that reports none of the new claim fields declares no premise, so
    `admissibility.check` returns ADMISSIBLE and nothing is downgraded.
  * `build_profile` only bites the instrumentation-gated crash classes for the
    profile (rust/cpp overflow markers); every other class passes straight
    through (`requires_shipping_reverify` is False → DISP_CONFIRMED).

Disposition vocabulary on the returned `GraderVerdict.disposition`:
  * ``real``                 — passed grade, every declared premise evidenced,
                               not an un-re-tested instrumentation-gated crash.
  * ``contested``            — a declared premise is unevidenced (L1/L3) → route
                               to dynamic confirm (aggregate already does this).
  * ``unverified``           — reproduced via direct construction (L12) → re-run
                               through the real entry.
  * ``build_profile_gated``  — an instrumentation-only crash class that did not
                               reproduce under the shipping build (L10 / R7).
  * ``rejected``             — the grader itself rejected the crash (passed=False
                               before any gate); carried through unchanged.
"""
from __future__ import annotations

from dataclasses import replace

from . import admissibility, build_profile
from .artifacts import GraderVerdict

DISP_REAL = "real"
DISP_REJECTED = "rejected"


def apply_gates(
    verdict: GraderVerdict,
    *,
    profile: str | None,
    crash_signal: str,
    claim: admissibility.VerdictClaim,
    reproduced_under_shipping: bool | None,
) -> GraderVerdict:
    """Fold the honesty gates into a fresh `GraderVerdict`.

    * ``profile`` / ``crash_signal`` drive `build_profile` (crash_signal is the
      crash_type label and/or raw crash_output — substring-matched).
    * ``claim`` drives `admissibility` (its fields default permissive, so an
      undeclared premise never trips a gate).
    * ``reproduced_under_shipping`` is the grader's shipping re-test result
      (None == "not re-tested" → an instrumentation-gated class is gated).

    The grader's own rejection is authoritative: a ``passed=False`` verdict is
    returned unchanged with disposition ``rejected`` (gates only ever *lower* a
    passing grade, never raise a failing one)."""
    if not verdict.passed:
        return replace(verdict, disposition=DISP_REJECTED)

    reasons: list[str] = []
    disposition = DISP_REAL

    # P0.2/P0.5/P1.4 — admissibility of the premises the `real` verdict rests on.
    adm = admissibility.check(claim)
    if not adm.is_admissible:
        disposition = adm.state  # contested | unverified
        reasons.extend(adm.reasons)

    # P0.1/L10 — an instrumentation-gated crash must reproduce under the shipping
    # build. build_profile_gated is the strongest "not production-real as found"
    # signal, so let it win the disposition label if it also trips.
    bp = build_profile.disposition(profile, crash_signal, reproduced_under_shipping)
    if bp == build_profile.DISP_BUILD_PROFILE_GATED:
        disposition = build_profile.DISP_BUILD_PROFILE_GATED
        reasons.append(
            "crash class is instrumentation-gated for this profile and did not "
            "reproduce under the shipping build (L10 / R7) — not production-real "
            f"as found; {build_profile.reverify_command_hint(profile)}")

    if disposition == DISP_REAL:
        return replace(verdict, disposition=DISP_REAL)

    # Any gate tripped → this is not a passed `real` grade. Lower `passed` so the
    # existing aggregate path treats it as unsettled, and carry the reason.
    return replace(
        verdict,
        passed=False,
        disposition=disposition,
        gate_reason=" | ".join(reasons),
    )
