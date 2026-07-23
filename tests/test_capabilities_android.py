# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the android-app additions to harness/capabilities.py."""
from __future__ import annotations

from harness import capabilities as C


def test_android_keys_and_gates_present():
    for k in ("exported_ipc", "webview_bridge", "deeplink_applink", "content_provider",
              "insecure_storage", "cleartext_tls", "dynamic_code_load",
              "build_config_exposure", "android_native_code"):
        assert k in C.CAPABILITY_KEYS
        assert C.gates_for(k) is not None, k


def test_app_security_gates_have_no_memory_sanitizer():
    # The app-security classes use a reachability/observation oracle, not a
    # sanitizer — only android_native_code carries asan.
    assert C.gates_for("exported_ipc").sanitizer == "none"
    assert C.gates_for("webview_bridge").sanitizer == "none"
    assert C.gates_for("android_native_code").sanitizer == "asan"


def test_native_reachability_axis_gates_the_native_track():
    # Bare .so present but reachability unknown → do NOT run the native track.
    inv = C.from_dict({
        "capabilities": {"android_native_code": {"present": "yes", "evidence": "lib/arm64/libfoo.so"}},
    })
    assert inv.is_active("android_native_code")
    assert inv.native_reachable_from_untrusted_input() == "unknown"
    assert inv.run_android_native() is False


def test_native_track_runs_when_chain_confirmed():
    inv = C.from_dict({
        "capabilities": {"android_native_code": {"present": "yes", "evidence": "libfoo.so"}},
        "native_reachable_from_untrusted_input": {
            "present": "partial",
            "evidence": "Java_com_app_Parser_parse receives attacker byte[]",
        },
    })
    assert inv.run_android_native() is True
    # the axis is split out of capabilities, not counted as one
    assert "native_reachable_from_untrusted_input" not in inv.caps


def test_native_track_skipped_when_chain_absent():
    inv = C.from_dict({
        "capabilities": {"android_native_code": {"present": "yes", "evidence": "libfoo.so"}},
        "native_reachable_from_untrusted_input": {"present": "no", "evidence": "codec, no app path"},
    })
    assert inv.run_android_native() is False


def test_vote_budget_native_is_high_variance():
    assert C.vote_budget("android_native_code") == C._HIGH_VARIANCE
    assert C.vote_budget("exported_ipc") == C._STABLE


def test_android_target_routing_end_to_end():
    inv = C.from_dict({
        "capabilities": {
            "exported_ipc": {"present": "yes", "evidence": "3 exported activities"},
            "webview_bridge": {"present": "yes", "evidence": "addJavascriptInterface"},
            "cleartext_tls": {"present": "no", "evidence": "NSC blocks cleartext"},
        },
    })
    active = inv.active_capabilities()
    assert "exported_ipc" in active and "webview_bridge" in active
    assert "cleartext_tls" not in active
    # skips carry a paper trail
    assert ("cleartext_tls", "NSC blocks cleartext") in inv.skips()
    # scan sections union pulls the android §A refs
    assert "§A1" in inv.scan_sections() and "§A3" in inv.scan_sections()
    # vote budget = max over active (webview=5 > exported=3)
    assert inv.vote_budget() == C.DEFAULT_VOTE_BUDGET
