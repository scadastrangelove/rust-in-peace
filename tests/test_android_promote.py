# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for harness/android_app/promote.py — witness promotion (Tier-A/B)."""
from __future__ import annotations

from harness import witness as W
from harness.android_app import promote as P
from harness.android_app import detect as D
from harness.android_app.find_to_fuzz import dispatch


def _static(cls, sev="HIGH"):
    return W.SecurityWitness(kind=W.KIND_STATIC_REACHABILITY, strength=1,
                             severity=sev, finding_class=cls)


def _obs(effect, runs=3, of=3, **kw):
    return P.Observation(effect_observed=effect, runs=runs, of_runs=of, **kw)


def test_exported_ipc_promotes_to_strength2_light_adb():
    w = _static("android:exported-activity-launch")
    pr = P.promote_finding(w, _obs(True), capability="exported_ipc")
    assert pr.verdict == P.V_PROMOTED and pr.promoted
    assert pr.witness.kind == W.KIND_DYNAMIC_OBSERVATION
    assert pr.witness.strength == 2 and pr.witness.tier == "light_adb" and pr.witness.domain == "behavior"
    # class + severity carried over
    assert pr.witness.finding_class == "android:exported-activity-launch"
    assert pr.witness.severity == "HIGH"
    # disposition is now confirmed
    assert pr.witness.disposition == W.DISP_CONFIRMED


def test_webview_bridge_promotes_to_strength3_heavy():
    w = _static("android:webview-js-bridge")
    pr = P.promote_finding(w, _obs(True), capability="webview_bridge")
    assert pr.promoted and pr.witness.strength == 3
    assert pr.witness.tier == "heavy_instrumented"


def test_guard_blocked_is_refutation_not_promotion():
    w = _static("android:exported-activity-launch")
    pr = P.promote_finding(w, _obs(False, guard_blocked=True), capability="exported_ipc")
    assert pr.verdict == P.V_GUARD_HELD and not pr.promoted
    assert pr.witness.strength == 1  # unchanged


def test_flaky_effect_stays_contested():
    w = _static("android:exported-activity-launch")
    pr = P.promote_finding(w, _obs(True, runs=2, of=3), capability="exported_ipc")
    assert pr.verdict == P.V_CONTESTED and pr.witness.strength == 1


def test_no_effect_stays_contested():
    w = _static("android:exported-activity-launch")
    pr = P.promote_finding(w, _obs(False), capability="exported_ipc")
    assert pr.verdict == P.V_CONTESTED


def test_device_unavailable_residual():
    w = _static("android:exported-activity-launch")
    pr = P.promote_finding(w, _obs(True, device_available=False), capability="exported_ipc")
    assert pr.verdict == P.V_CONTESTED and pr.residual == P.R_DEVICE_UNAVAILABLE


def test_build_config_terminal_settles_static():
    w = _static("android:allow-backup", sev="MEDIUM")
    pr = P.promote_finding(w, _obs(False), capability="build_config_exposure")
    assert pr.verdict == P.V_TERMINAL
    assert pr.witness.strength == 1 and pr.witness.disposition == W.DISP_REAL_LATENT_STATIC


def test_pending_intent_static_argument_contested():
    w = _static("android:pending-intent-hijack")
    pr = P.promote_finding(w, _obs(False), capability="pending_intent")
    assert pr.verdict == P.V_CONTESTED and pr.witness.strength == 1


def test_native_gated_without_reachability():
    w = _static("android:native-parse")
    pr = P.promote_finding(w, _obs(True), capability="android_native_code", native_reachable=False)
    assert pr.verdict == P.V_CONTESTED and pr.residual == P.R_NATIVE_GATED
    assert pr.witness.strength == 1


def test_native_crash_when_chain_confirmed():
    w = _static("android:native-parse")
    pr = P.promote_finding(w, _obs(True, evidence="ASan heap-overflow"),
                           capability="android_native_code", native_reachable=True)
    assert pr.verdict == P.V_NATIVE_CRASH and pr.witness.strength == 4


def test_structure_gated_escalates_tier():
    w = _static("android:exported-activity-launch")
    # a light-adb plan that needs an instrumented drive → heavy, strength 3
    pr = P.promote_finding(w, _obs(True), capability="exported_ipc", structure_gated=True)
    assert pr.witness.strength == 3 and pr.witness.tier == "heavy_instrumented"


def test_promoted_witness_round_trips_through_detector():
    w = _static("android:exported-activity-launch")
    pr = P.promote_finding(w, _obs(True, evidence="logcat: startActivity(evil://x)"),
                           capability="exported_ipc")
    text = P.render_promoted_witness(pr) + "\nsink: startActivity smali/a.smali:10"
    parsed = W.parse(text)
    assert parsed.kind == W.KIND_DYNAMIC_OBSERVATION and parsed.strength == 2
    assert D.crash_reason(text)["crash_type"] == "android:exported-activity-launch"
