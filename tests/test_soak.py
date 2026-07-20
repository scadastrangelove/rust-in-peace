# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for harness/soak.py — P0.3 distinct-site enumeration (L-ops)."""
from __future__ import annotations

from types import SimpleNamespace

from harness import soak
from harness.dedup import NO_FRAME


class _StubDetector:
    """Duck-types the detector surface soak.site_of needs: crash_reason + top_frame.
    Frame = the first `@site:line` token in the text; class = the first word."""
    @staticmethod
    def crash_reason(out):
        return {"crash_type": out.split()[0] if out.split() else "unknown"}

    @staticmethod
    def top_frame(out):
        for tok in out.split():
            if tok.startswith("@"):
                return tok[1:]
        return ""


DET = _StubDetector()


def test_single_site_over_many_inputs():
    # The lopdf content_decode case: thousands of inputs, ONE site.
    outputs = ["panic @parser/mod.rs:670 unwrap" for _ in range(6911)]
    sites = soak.enumerate_sites(outputs, detector=DET)
    assert len(sites) == 1                       # ← the number to report
    assert sum(sites.values()) == 6911           # ← the counter, NOT a finding count
    assert sites[("panic", "parser/mod.rs:670")] == 6911


def test_multiple_distinct_sites():
    outputs = (
        ["panic @a.rs:10 x"] * 3
        + ["overflow @b.rs:20 y"] * 1
        + ["panic @c.rs:30 z"] * 2
    )
    sites = soak.enumerate_sites(outputs, detector=DET)
    assert len(sites) == 3
    assert sites[("panic", "a.rs:10")] == 3
    assert sites[("overflow", "b.rs:20")] == 1


def test_site_with_no_frame_falls_back():
    sites = soak.enumerate_sites(["panic no-frame-here"], detector=DET)
    assert ("panic", NO_FRAME) in sites


def test_format_leads_with_distinct_sites_not_counter():
    outputs = ["panic @parser/mod.rs:670 unwrap"] * 6911
    sites = soak.enumerate_sites(outputs, detector=DET)
    report = soak.format_site_report(sites, total_inputs=6911)
    assert "1 distinct crash site" in report
    assert "NOT a finding count" in report
    assert "parser/mod.rs:670" in report


def test_format_zero_sites_is_clean():
    report = soak.format_site_report({}, total_inputs=2_310_000)
    assert "0 distinct crash sites" in report
    assert "clean" in report


def test_done_line_carries_enumeration():
    sites = {("panic", "parser/mod.rs:670"): 6911}
    line = soak.done_line("content_decode", sites, 6911)
    assert line == "SOAK-DONE-content_decode distinct_sites=1 crash_inputs=6911"


def test_detector_autosniffed_when_none(monkeypatch):
    # With no detector passed, soak sniffs one via profiles.detector_for_output.
    monkeypatch.setattr(soak, "detector_for_output", lambda out: DET)
    sites = soak.enumerate_sites(["panic @z.rs:9 q"])
    assert sites[("panic", "z.rs:9")] == 1
