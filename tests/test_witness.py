# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for harness/witness.py — the SecurityWitness strength model."""
from __future__ import annotations

import pytest

from harness import witness as W


def test_strength_ordinal():
    assert W.strength_of(W.KIND_STATIC_REACHABILITY) == 1
    assert W.strength_of(W.KIND_DYNAMIC_OBSERVATION, "light_adb") == 2
    assert W.strength_of(W.KIND_DYNAMIC_OBSERVATION, "heavy_instrumented") == 3
    assert W.strength_of(W.KIND_DYNAMIC_OBSERVATION) == 2  # tier defaults to light
    assert W.strength_of(W.KIND_NATIVE_CRASH) == 4


def test_strength_unknown_kind_raises():
    with pytest.raises(ValueError):
        W.strength_of("bogus")


def test_disposition_observed_is_confirmed():
    # Any strength >= 2 (observed) is confirmed regardless of class.
    assert W.default_disposition("android:exported-activity-launch", 2) == W.DISP_CONFIRMED
    assert W.default_disposition("anything", 4) == W.DISP_CONFIRMED


def test_disposition_static_terminal_class_is_real_latent():
    # A declared build-config class with no stronger witness → real_latent(static).
    for cls in W.STATIC_TERMINAL_CLASSES:
        assert W.default_disposition(cls, 1) == W.DISP_REAL_LATENT_STATIC


def test_disposition_static_nonterminal_is_contested():
    # A reachability finding at strength 1 must NOT self-promote — it is contested
    # (needs dynamic promotion), the ADR-4 anti-gaming rule.
    assert W.default_disposition("android:exported-activity-launch", 1) == W.DISP_CONTESTED
    assert W.default_disposition("android:webview-js-bridge", 1) == W.DISP_CONTESTED


def test_parse_headerless_is_native_crash_strength4():
    # Backward-compat: any crash_output without a WITNESS header (all cpp/rust
    # crashes) parses to native_crash / strength 4 — today's behavior preserved.
    for raw in ["", "AddressSanitizer: heap-buffer-overflow", "thread 'main' panicked at x"]:
        w = W.parse(raw)
        assert w.kind == W.KIND_NATIVE_CRASH
        assert w.strength == 4


def test_parse_roundtrip_static_reachability():
    w = W.SecurityWitness(
        kind=W.KIND_STATIC_REACHABILITY, strength=1, severity="HIGH",
        finding_class="android:exported-activity-launch",
    )
    got = W.parse(w.header() + "\nentry: MainActivity\nsink: startActivity(intent)")
    assert got.kind == W.KIND_STATIC_REACHABILITY
    assert got.strength == 1
    assert got.severity == "HIGH"
    assert got.finding_class == "android:exported-activity-launch"
    assert got.disposition == W.DISP_CONTESTED


def test_parse_roundtrip_dynamic_observation():
    w = W.SecurityWitness(
        kind=W.KIND_DYNAMIC_OBSERVATION, strength=3, severity="CRITICAL",
        finding_class="android:content-provider-sqli", domain="storage",
        tier="heavy_instrumented",
    )
    got = W.parse(w.header())
    assert got.kind == W.KIND_DYNAMIC_OBSERVATION
    assert got.strength == 3
    assert got.domain == "storage"
    assert got.tier == "heavy_instrumented"
    assert got.disposition == W.DISP_CONFIRMED


def test_parse_bad_severity_falls_back():
    w = W.parse("WITNESS: kind=static_reachability strength=1 severity=BOGUS class=x")
    assert w.severity == "MEDIUM"


def test_parse_bad_strength_derives_from_kind():
    w = W.parse("WITNESS: kind=native_crash strength=notanint")
    assert w.strength == 4
