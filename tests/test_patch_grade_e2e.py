# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""End-to-end grader validation against real Docker (canary, no LLM).

Hand-crafted patches with known correct verdicts, asserting grade_patch
agrees. Every assertion is a deterministic oracle (compiler / ASAN exit code);
re-attack is unit-tested separately with mocks since it needs an LLM in the
loop.

Skipped if Docker can't spawn containers (set VULN_PIPELINE_DOCKER_RUNTIME=runsc
on hosts where the default runtime is unavailable).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from harness import docker_ops
from harness.artifacts import CrashArtifact
from harness.config import TargetConfig
from harness.patch_grade import grade_patch

REPO = Path(__file__).resolve().parents[1]
CANARY = TargetConfig.load(REPO / "targets" / "canary")

ALPHA_CRASH = CrashArtifact(
    poc_path="/tmp/poc.bin",
    poc_bytes=bytes.fromhex("4140" + "41" * 64),  # 'A', claimed=0x40, payload
    reproduction_command="/work/entry /tmp/poc.bin",
    crash_type="heap-buffer-overflow",
    crash_output="    #1 0x40 in parse_alpha /work/entry.c:25\n",
    exit_code=134,
)


def _docker_available() -> bool:
    if not docker_ops.image_exists(CANARY.image_tag):
        return False
    try:
        docker_ops.run(CANARY.image_tag, name="pgrade_probe")
        return True
    except RuntimeError:
        return False
    finally:
        docker_ops.rm("pgrade_probe")


pytestmark = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker can't spawn containers (set VULN_PIPELINE_DOCKER_RUNTIME)",
)


def _grade(diff_path: str):
    diff = (REPO / diff_path).read_bytes()
    return asyncio.run(
        grade_patch(
            CANARY,
            ALPHA_CRASH,
            diff,
            model="unused",
            container_name="pgrade_e2e",
            run_reattack=False,
        )
    )


def test_noop_diff_passes_t0_fails_t1():
    """A patch that changes nothing meaningful must fail at T1."""
    v = _grade("tests/fixtures/canary_noop.diff")
    assert v.t0_builds
    assert not v.t1_poc_stops
    assert "AddressSanitizer" in v.evidence.get("t1", "")
    assert not v.passed


def test_crashsite_diff_passes_t0_t1():
    """Symptom-only fix (guards memcpy with too-loose bound) passes T1 for the
    specific PoC but is wrong — re-attack would catch it (mocked unit test
    covers that path)."""
    v = _grade("tests/fixtures/canary_alpha_crashsite.diff")
    assert v.t0_builds
    assert v.t1_poc_stops
    assert v.t2_tests_pass


def test_golden_diff_passes_all():
    """Root-cause fix passes T0+T1."""
    v = _grade("tests/fixtures/canary_alpha_golden.diff")
    assert v.t0_builds
    assert v.t1_poc_stops
    assert v.passed


def test_malformed_diff_fails_t0():
    """Garbage diff bytes must fail at T0 (apply step)."""
    v = asyncio.run(
        grade_patch(
            CANARY,
            ALPHA_CRASH,
            b"not a diff\n",
            model="unused",
            container_name="pgrade_e2e",
            run_reattack=False,
        )
    )
    assert not v.t0_builds
    assert "apply" in v.evidence.get("t0", "")
