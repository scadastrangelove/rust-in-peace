# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for harness/android_app/detect.py — reachability-witness parsing."""
from __future__ import annotations

from harness.android_app import detect as D

WITNESS = (
    "WITNESS: kind=static_reachability strength=1 severity=HIGH "
    "class=android:exported-activity-launch domain=- tier=-\n"
    "entry: com.app.ExportedActivity (exported=true, no permission)  AndroidManifest.xml\n"
    "  --> smali/com/app/ExportedActivity.smali:42  onCreate reads getIntent().getData()\n"
    "guard: none\n"
    "sink:  startActivity smali/com/app/ExportedActivity.smali:88\n"
)


def test_crash_reason_reads_finding_class_from_header():
    assert D.crash_reason(WITNESS)["crash_type"] == "android:exported-activity-launch"


def test_project_frames_sink_first_and_skip_framework():
    frames = D.project_frames(WITNESS, n=3)
    # sink is the primary (most bug-identifying) anchor
    assert frames[0].startswith("startActivity")
    assert "ExportedActivity.smali:88" in frames[0]
    # entry comes next
    assert any("ExportedActivity.smali:42" in f for f in frames)


def test_framework_refs_are_dropped():
    text = (
        "WITNESS: kind=static_reachability strength=1 severity=LOW class=android:x\n"
        "entry: Foo  androidx/core/app/Bar.java:10\n"
        "sink:  Baz  smali/com/app/Real.smali:20\n"
    )
    frames = D.project_frames(text, n=3)
    assert all("androidx/" not in f for f in frames)
    assert any("Real.smali:20" in f for f in frames)


def test_top_frame():
    assert "ExportedActivity.smali:88" in D.top_frame(WITNESS)


def test_excerpt_keeps_header_and_path():
    ex = D.excerpt(WITNESS)
    assert ex.splitlines()[0].startswith("WITNESS:")
    assert "sink:" in ex


def test_native_fallback_no_header():
    # A promoted android-native finding: ASan trace, no WITNESS header.
    asan = "SUMMARY: AddressSanitizer: heap-buffer-overflow /work/jni/parse.c:88"
    assert D.crash_reason(asan)["crash_type"] == "asan-heap-buffer-overflow"


def test_unclassified_when_empty():
    assert D.crash_reason("")["crash_type"] == "android:unclassified"


def test_no_frames_when_no_roles():
    assert D.project_frames("WITNESS: kind=static_reachability strength=1 class=x") == []
