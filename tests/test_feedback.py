# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for cross-stage feedback loops (harness/feedback.py)."""
import json

from harness import feedback
from harness.aggregate import aggregate


def test_loop_until_dry_stops_after_k_dry_passes():
    loop = feedback.LoopUntilDry(k=2, max_rounds=8)
    assert loop.should_continue()
    loop.observe({("a", "x"), ("b", "y")})
    assert loop.last_added == 2 and loop.should_continue()
    loop.observe({("a", "x"), ("b", "y"), ("c", "z")})
    assert loop.last_added == 1 and loop.should_continue()
    loop.observe({("a", "x"), ("b", "y"), ("c", "z")})       # dry 1
    assert loop.dry_streak == 1 and loop.should_continue()
    loop.observe({("a", "x")})                                # dry 2 (subset adds nothing)
    assert loop.dry_streak == 2 and not loop.should_continue()
    assert loop.stopped_dry


def test_loop_until_dry_respects_max_rounds():
    loop = feedback.LoopUntilDry(k=99, max_rounds=3)
    for i in range(5):
        if loop.should_continue():
            loop.observe({(str(i), "x")})                     # always productive
    assert loop.rounds == 3 and not loop.should_continue()
    assert not loop.stopped_dry                                # stopped on the cap, not dry


def test_new_members_and_union_signatures(tmp_path):
    before = {("a", "1"), ("b", "2")}
    after = {("a", "1"), ("b", "2"), ("c", "3")}
    assert feedback.new_members(before, after) == {("c", "3")}


def _mkrun(root, i, site, status):
    d = root / f"run_{i:03d}"
    d.mkdir(parents=True)
    out = f"==ERROR: AddressSanitizer: heap-buffer-overflow\n    #0 0x1 in {site} /s.rs:1"
    d.joinpath("result.json").write_text(json.dumps({
        "target": "t", "status": status,
        "crash": {"crash_output": out, "crash_type": "heap-buffer-overflow",
                  "poc_bytes": "AA", "reason": {"crash_type": "heap-buffer-overflow", "operation": "READ"}},
    }))


def test_contested_to_findings(tmp_path):
    # flip: 2/5 votes, 0 passed → contested; stable: 3/5 all passed → settled
    _mkrun(tmp_path, 0, "flip", "crash_rejected")
    _mkrun(tmp_path, 1, "flip", "crash_rejected")
    _mkrun(tmp_path, 2, "stable", "crash_found")
    _mkrun(tmp_path, 3, "stable", "crash_found")
    _mkrun(tmp_path, 4, "stable", "crash_found")
    agg = aggregate(tmp_path, "union")
    cf = feedback.contested_to_findings(agg)
    assert len(cf) == 1
    assert "flip" in cf[0]["site"] and "CONTESTED" in cf[0]["mechanism"]
    assert cf[0]["cwe"] == "CWE-125"


def test_escalate_rung_reexported():
    # feedback re-exports the bounded escalation edge from find_to_fuzz
    assert feedback.escalate_rung("needs-MSan").sanitizer == "msan"
    assert feedback.escalate_rung("address-space-only") is None
