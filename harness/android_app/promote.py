# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Witness promotion — turn an observed device effect into a stronger witness.

`find_to_fuzz.dispatch()` picks the promotion plan and the strength a successful
observation *earns*; `find_to_fuzz.build_reattack` tells the agent how to drive
it. This module is the deterministic **consumer**: given the static witness, its
dispatch, and the device `Observation`, it decides whether the effect actually
fired (under the 3/3 determinism bar) and emits the promoted `SecurityWitness` —
or a named non-promotion (`contested` / `guard_held` / `terminal` /
`native_gated` / `device_unavailable`).

It is the android analog of the grade step re-running a PoC: a pure function of
`(witness, dispatch, observation)`, so the whole promotion path is testable
without a real emulator — the canary feeds it a *recorded* observation (see
`targets/android-canary/run_dynamic`), exactly as `reach` feeds a recorded
reachability walk. A real target's `android-app-dynamic` stage swaps the recorded
observation for a live adb/Frida run in the device sandbox
(`docs/profiles/android/DEVICE-SANDBOX.md`).
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from .. import witness as _witness
from .find_to_fuzz import Dispatch, dispatch as _dispatch

# The android analog of the 3/3-crash bar: an observed effect must reproduce this
# many times identically before it promotes. A sometimes-fires effect is flaky,
# not confirmed — it stays contested (ADR-4: strength is evidential rigor).
DET_BAR = 3

# Verdicts (mirror build_reattack's <verdict>/<residual> vocabulary).
V_PROMOTED = "promoted"
V_NATIVE_CRASH = "native_crash"
V_CONTESTED = "contested"
V_TERMINAL = "terminal"
V_GUARD_HELD = "guard_held"
R_NATIVE_GATED = "native_gated"
R_DEVICE_UNAVAILABLE = "device_unavailable"


@dataclass(frozen=True)
class Observation:
    """The device's answer for one promotion attempt — what the dynamic stage
    (or the canary's recorded fixture) reports back.

    `effect_observed` is the load-bearing bit: did the SINK actually fire / the
    sensitive datum actually appear? `runs`/`of_runs` carry the determinism count
    (`runs` identical observations out of `of_runs` attempts). `guard_blocked`
    means the probe was *rejected* by a guard — that REFUTES the path (a win for
    correctness), it is not merely "no effect"."""
    effect_observed: bool
    runs: int = 0
    of_runs: int = 0
    guard_blocked: bool = False
    device_available: bool = True
    evidence: str = ""            # the raw logcat / rows / cleartext / native line

    @property
    def deterministic(self) -> bool:
        return self.effect_observed and self.runs >= DET_BAR and self.runs == self.of_runs


@dataclass(frozen=True)
class Promotion:
    """The outcome of a promotion attempt."""
    witness: _witness.SecurityWitness   # the (possibly upgraded) witness
    verdict: str                        # promoted | native_crash | contested | terminal | guard_held
    residual: str                       # verdict, or native_gated / device_unavailable
    detail: str

    @property
    def promoted(self) -> bool:
        return self.witness.strength >= 2 and self.verdict in (V_PROMOTED, V_NATIVE_CRASH)


def _dynamic_witness(base: _witness.SecurityWitness, disp: Dispatch) -> _witness.SecurityWitness:
    """The upgraded witness a successful observation yields — same class/severity,
    the kind/strength/domain/tier this plan earned."""
    return replace(
        base,
        kind=disp.kind,
        strength=disp.strength,
        domain=disp.domain,
        tier=disp.tier,
    )


def promote(
    static_witness: _witness.SecurityWitness,
    disp: Dispatch,
    observation: Observation,
    *,
    native_reachable: bool = False,
) -> Promotion:
    """Decide the promotion for one finding.

    * static plans (`static_argument` / `static_terminal`) never promote — a
      terminal build-config class settles as `real_latent_static_argument`,
      everything else stays `contested`.
    * a native (JNI) plan promotes to a `native_crash` (strength 4) only when the
      ADR-1 chain is confirmed (`native_reachable`) AND a crash was observed;
      otherwise it is `native_gated` (down-rank, do not fuzz a bare `.so`).
    * a dynamic plan promotes to strength 2/3 only on a **3/3** observed effect; a
      blocked probe is `guard_held` (refuted); a flaky/absent effect stays
      `contested`.
    """
    # --- static plans: no dynamic observation is possible ---------------------
    if disp.is_static:
        if disp.plan == "static_terminal" and \
                static_witness.finding_class in _witness.STATIC_TERMINAL_CLASSES:
            return Promotion(static_witness, V_TERMINAL, V_TERMINAL,
                             "declared build-config terminal — nothing to observe")
        return Promotion(static_witness, V_CONTESTED, V_CONTESTED,
                         "no cheap dynamic observation — strength-1 argument stands")

    # --- native (JNI) plan: gated on the ADR-1 reachability chain --------------
    if disp.kind == _witness.KIND_NATIVE_CRASH:
        if not native_reachable:
            return Promotion(static_witness, V_CONTESTED, R_NATIVE_GATED,
                             "bare .so / chain unconfirmed — down-rank, do not fuzz JNI (ADR-1)")
        if observation.guard_blocked:
            return Promotion(static_witness, V_GUARD_HELD, V_GUARD_HELD,
                             "JNI reached but no crash — path refuted")
        if observation.deterministic:
            w = _dynamic_witness(static_witness, disp)
            return Promotion(w, V_NATIVE_CRASH, V_NATIVE_CRASH,
                             f"JNI crash observed 3/3: {observation.evidence}")
        return Promotion(static_witness, V_CONTESTED, V_CONTESTED,
                         "JNI chain confirmed but no reproducing crash this run")

    # --- dynamic observation plan (Tier A strength 2 / Tier B strength 3) ------
    if not observation.device_available:
        return Promotion(static_witness, V_CONTESTED, R_DEVICE_UNAVAILABLE,
                         "no device/emulator — the reason must be fixed and re-run")
    if observation.guard_blocked:
        return Promotion(static_witness, V_GUARD_HELD, V_GUARD_HELD,
                         f"guard held — path refuted (correctness win): {observation.evidence}")
    if observation.deterministic:
        w = _dynamic_witness(static_witness, disp)
        return Promotion(w, V_PROMOTED, V_PROMOTED,
                         f"effect observed {observation.runs}/{observation.of_runs}: {observation.evidence}")
    if observation.effect_observed:
        return Promotion(static_witness, V_CONTESTED, V_CONTESTED,
                         f"effect flaky ({observation.runs}/{observation.of_runs} < {DET_BAR}/{DET_BAR}) — not promoted")
    return Promotion(static_witness, V_CONTESTED, V_CONTESTED,
                     "no effect observed this run — wants retry / heavier tier")


def promote_finding(
    static_witness: _witness.SecurityWitness,
    observation: Observation,
    *,
    capability: str | None = None,
    structure_gated: bool = False,
    native_reachable: bool = False,
) -> Promotion:
    """Convenience: dispatch on the witness's finding class (+ optional capability
    / structure gate), then promote. The one-call entry the dynamic stage uses."""
    disp = _dispatch(static_witness.finding_class, capability, structure_gated)
    return promote(static_witness, disp, observation, native_reachable=native_reachable)


def render_promoted_witness(promotion: Promotion, evidence_line: str | None = None) -> str:
    """The WITNESS block for a promoted finding — header + an `observed:` evidence
    line — so the detector re-parses the stronger witness back into the pipeline.
    For a non-promotion the header still reflects the unchanged static witness."""
    header = promotion.witness.header()
    obs = evidence_line or (promotion.detail if promotion.promoted else "")
    return f"{header}\nobserved: {obs}" if obs else header
