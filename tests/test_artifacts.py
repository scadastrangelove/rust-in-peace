# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Round-trip serialization tests for artifact dataclasses."""
from harness.artifacts import CrashArtifact, GraderVerdict, MaintainerReviewVerdict, RunResult


def test_crash_artifact_roundtrip():
    orig = CrashArtifact(
        poc_path="/tmp/poc.bin",
        poc_bytes=b"\x89PNG\r\n\x1a\n\x00\x00\xff\xfe",  # binary, non-UTF8
        reproduction_command="/work/entry /tmp/poc.bin",
        crash_type="heap-buffer-overflow",
        crash_output="==12345==ERROR: AddressSanitizer: heap-buffer-overflow\n  #0 0xdeadbeef",
        exit_code=134,
        dup_check="Checked: top frame decode_chunk via parse_foo — no match in Already Filed.",
    )
    restored = CrashArtifact.from_dict(orig.to_dict())
    assert restored == orig
    assert restored.poc_bytes == orig.poc_bytes  # bytes survived b64 round-trip


def test_crash_artifact_from_dict_missing_dup_check():
    # Older result.json files won't have this key
    d = CrashArtifact(
        poc_path="/tmp/x", poc_bytes=b"\x00", reproduction_command="/work/entry /tmp/x",
        crash_type="SEGV", crash_output="trace", exit_code=134,
    ).to_dict()
    del d["dup_check"]
    assert CrashArtifact.from_dict(d).dup_check is None


def test_grader_verdict_roundtrip():
    orig = GraderVerdict(
        passed=True,
        score=1.0,
        criteria={"criterion_1": True, "criterion_2": True, "criterion_3": True,
                  "criterion_4": True, "criterion_5": False},
        evidence="PoC is 847 bytes, 3/3 runs crashed.",
    )
    restored = GraderVerdict.from_dict(orig.to_dict())
    assert restored.passed == orig.passed
    assert restored.score == orig.score
    assert restored.criteria == orig.criteria
    assert restored.evidence == orig.evidence


def test_maintainer_review_verdict_roundtrip():
    orig = MaintainerReviewVerdict(
        verdict="DOWNGRADE",
        corrected_severity="LOW",
        reachability="CONSTRUCTION_ONLY",
        fix_ok=True,
        fix_problem="-",
        rebuttals="argstack.rs:38 debug_assert is inert in release",
        one_line="Real but only reachable via an internal constructor, not the public API.",
    )
    restored = MaintainerReviewVerdict.from_dict(orig.to_dict())
    assert restored == orig


def test_run_result_json_roundtrip():
    crash = CrashArtifact(
        poc_path="/tmp/x",
        poc_bytes=b"\x00\x01\x02\xff",
        reproduction_command="/work/entry /tmp/x",
        crash_type="use-after-free",
        crash_output="trace",
        exit_code=134,
    )
    verdict = GraderVerdict(passed=False, score=0.6, criteria={"criterion_1": True}, evidence="nope")
    orig = RunResult(
        target="stb",
        status="crash_rejected",
        crash=crash,
        verdict=verdict,
        find_transcript=[{"role": "assistant", "text": "hi"}],
        grade_transcript=[],
        timings={"build": 12.3, "find": 4567.8, "grade": 89.0},
        error=None,
    )
    restored = RunResult.from_json(orig.to_json())
    assert restored.target == orig.target
    assert restored.status == orig.status
    assert restored.crash == orig.crash
    assert restored.verdict.passed == orig.verdict.passed
    assert restored.verdict.score == orig.verdict.score
    assert restored.timings == orig.timings


def test_run_result_no_crash():
    orig = RunResult(
        target="stb",
        status="no_crash_found",
        crash=None,
        verdict=None,
        timings={"build": 10.0, "find": 100.0},
    )
    restored = RunResult.from_json(orig.to_json())
    assert restored.crash is None
    assert restored.verdict is None
    assert restored.status == "no_crash_found"
