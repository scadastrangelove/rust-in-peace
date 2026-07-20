# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for harness/build_profile.py — the P0.1 shipping-profile gate (L10)."""
from __future__ import annotations

from harness import build_profile as bp


def test_rust_arith_overflow_is_instrumentation_gated():
    # The lopdf L10 case: a const-overflow panic found under overflow-checks=on.
    assert bp.requires_shipping_reverify("rust", "arithmetic-overflow")
    assert bp.requires_shipping_reverify("rust", "attempt to add with overflow")
    assert bp.requires_shipping_reverify(
        "rust", "thread panicked: panic_const_mul_overflow")


def test_rust_real_panics_are_not_gated():
    # index-oob / unwrap abort under the shipping build too — pass straight through.
    assert not bp.requires_shipping_reverify("rust", "index-out-of-bounds")
    assert not bp.requires_shipping_reverify(
        "rust", "called `Result::unwrap()` on an `Err` value")


def test_cpp_ubsan_only_classes_gated_memory_bugs_not():
    assert bp.requires_shipping_reverify("cpp", "signed-integer-overflow")
    # ASan memory bugs are real in release — never gated.
    assert not bp.requires_shipping_reverify("cpp", "heap-buffer-overflow")
    assert not bp.requires_shipping_reverify("cpp", "use-after-free")


def test_android_has_no_gated_classes():
    assert bp.instrumentation_gated_classes("android-app") == frozenset()
    assert not bp.requires_shipping_reverify("android-app", "arithmetic-overflow")


def test_unknown_profile_and_empty_signal_never_gate():
    assert not bp.requires_shipping_reverify("brand-new", "arithmetic-overflow")
    assert not bp.requires_shipping_reverify("rust", "")
    assert not bp.requires_shipping_reverify("rust", None)  # type: ignore[arg-type]


def test_disposition_gated_class_not_reproduced_is_r7():
    # Found under detection, did NOT reproduce under shipping → build_profile_gated.
    assert bp.disposition("rust", "arithmetic-overflow", False) == bp.DISP_BUILD_PROFILE_GATED
    assert bp.disposition("rust", "arithmetic-overflow", None) == bp.DISP_BUILD_PROFILE_GATED


def test_disposition_gated_class_reproduced_under_shipping_is_confirmed():
    # A genuine overflow that DOES panic in release is a real bug.
    assert bp.disposition("rust", "arithmetic-overflow", True) == bp.DISP_CONFIRMED


def test_disposition_non_gated_class_always_confirmed():
    assert bp.disposition("rust", "index-out-of-bounds", None) == bp.DISP_CONFIRMED
    assert bp.disposition("cpp", "heap-buffer-overflow", False) == bp.DISP_CONFIRMED


def test_profiles_and_hint():
    assert bp.shipping_profile("rust").name == "rust-release"
    assert bp.detection_profile("rust").name == "rust-detect"
    assert bp.shipping_profile("android-app") is None
    assert "overflow-checks" in bp.reverify_command_hint("rust")
    assert "release build" in bp.reverify_command_hint("brand-new") or \
        "re-test" in bp.reverify_command_hint("brand-new")
