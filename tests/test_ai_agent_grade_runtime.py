# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for provodka #1: grade/aggregate routed through the trusted replay.

No Docker. The replay (`runtime.replay`) and the assessment (`evidence.assess`) are
monkeypatched; what is under test is the WIRING — that a passed grade for the
ai-agent profile means "the independent replay confirmed it", that errors fail
closed (never a silent pass), and that aggregate confirmation uses the replay
(passed_votes) rather than the crash-model votes>=2 shortcut for this profile.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.agent import AgentResult
from harness.ai_agent import detect, grade_runtime
from harness.ai_agent.evidence import Assessment
from harness.aggregate import Candidate
from harness.artifacts import CrashArtifact, GraderVerdict
from harness.config import TargetConfig


def _target(contract_path: str | None = "contract.json") -> TargetConfig:
    return TargetConfig(
        name="canary", dockerfile_dir="/t", image_tag="img:tag",
        github_url="x", commit="HEAD", binary_path="/b", source_root="/s",
        profile="ai-agent", ai_agent_contract_path=contract_path,
    )


def _crash() -> CrashArtifact:
    return CrashArtifact(
        poc_path="/tmp/scenario.json", poc_bytes=b'{"scenario": "stub"}',
        reproduction_command="n/a", crash_type="aiagent:authz-bypass",
        crash_output="AIAGENT: invariant=aiagent:authz-bypass component=vault",
        exit_code=0,
    )


def _stub_parsing(monkeypatch):
    """Short-circuit decode/validate/load so no real schema or file I/O runs."""
    monkeypatch.setattr(grade_runtime, "decode", lambda raw: {"scenario": "stub"})
    monkeypatch.setattr(grade_runtime, "validate", lambda v, name: v)
    monkeypatch.setattr(grade_runtime, "validate_scenario", lambda v, c: v)
    monkeypatch.setattr(grade_runtime, "load", lambda p, name: {"contract": "stub"})


def _assessment(disposition, successes, completed, scheduled, reason="r"):
    return Assessment(disposition, reason, successes, completed, scheduled)


# ---- grade_via_replay: disposition -> verdict mapping ------------------------

def test_confirmed_replay_passes(monkeypatch):
    _stub_parsing(monkeypatch)
    monkeypatch.setattr(grade_runtime, "replay", lambda s, c, img: {"trials": []})
    monkeypatch.setattr(grade_runtime, "assess",
                        lambda ev, s, c: _assessment("confirmed", 3, 3, 3))
    verdict, result, elapsed = grade_runtime.grade_via_replay(_crash(), _target())
    assert verdict.passed is True
    assert verdict.score == 1.0
    assert verdict.disposition == "real"
    assert verdict.criteria["replay_confirmed"] is True
    assert "3/3" in verdict.evidence
    assert isinstance(result, AgentResult)
    assert result.transcript() == []           # no grader agent ran
    assert elapsed >= 0.0


def test_decoy_not_observed_is_rejected(monkeypatch):
    _stub_parsing(monkeypatch)
    monkeypatch.setattr(grade_runtime, "replay", lambda s, c, img: {})
    monkeypatch.setattr(grade_runtime, "assess",
                        lambda ev, s, c: _assessment("not_observed", 0, 3, 3))
    verdict, _, _ = grade_runtime.grade_via_replay(_crash(), _target())
    assert verdict.passed is False
    assert verdict.score == 0.0
    assert verdict.disposition == "unverified"
    assert verdict.gate_reason


def test_component_only_is_contested_half_score(monkeypatch):
    _stub_parsing(monkeypatch)
    monkeypatch.setattr(grade_runtime, "replay", lambda s, c, img: {})
    monkeypatch.setattr(grade_runtime, "assess",
                        lambda ev, s, c: _assessment("component_only", 1, 3, 3))
    verdict, _, _ = grade_runtime.grade_via_replay(_crash(), _target())
    assert verdict.passed is False             # not a shipping entrypoint
    assert verdict.score == 0.5
    assert verdict.disposition == "contested"
    assert verdict.criteria["shipping_entry"] is False


def test_unresolved_controls_fail_closed(monkeypatch):
    _stub_parsing(monkeypatch)
    monkeypatch.setattr(grade_runtime, "replay", lambda s, c, img: {})
    monkeypatch.setattr(grade_runtime, "assess",
                        lambda ev, s, c: _assessment("unresolved", 0, 2, 3))
    verdict, _, _ = grade_runtime.grade_via_replay(_crash(), _target())
    assert verdict.passed is False
    assert verdict.disposition == "unverified"
    assert verdict.criteria["controls_passed"] is False


def test_replay_error_fails_closed(monkeypatch):
    _stub_parsing(monkeypatch)
    from harness.ai_agent.runtime import ReplayError

    def boom(s, c, img):
        raise ReplayError("docker unavailable")
    monkeypatch.setattr(grade_runtime, "replay", boom)
    verdict, result, _ = grade_runtime.grade_via_replay(_crash(), _target())
    assert verdict.passed is False             # infra error is NEVER a silent pass
    assert verdict.disposition == "unverified"
    assert "replay unavailable" in verdict.evidence
    assert isinstance(result, AgentResult)


def test_missing_contract_path_fails_closed(monkeypatch):
    _stub_parsing(monkeypatch)
    # replay/assess must not even be reached without a contract path.
    monkeypatch.setattr(grade_runtime, "replay",
                        lambda *a: pytest.fail("replay reached without a contract"))
    verdict, _, _ = grade_runtime.grade_via_replay(_crash(), _target(contract_path=None))
    assert verdict.passed is False
    assert verdict.disposition == "unverified"


def test_scenario_is_validated_against_contract(monkeypatch):
    """The PoC bytes are decoded, schema-validated AND cross-checked to the
    contract before the replay — a scenario bound to a different target is rejected."""
    _stub_parsing(monkeypatch)
    called = {}
    def check(scenario, contract):
        called["cross_check"] = True
        return scenario
    monkeypatch.setattr(grade_runtime, "validate_scenario", check)
    monkeypatch.setattr(grade_runtime, "replay", lambda s, c, img: {})
    monkeypatch.setattr(grade_runtime, "assess",
                        lambda ev, s, c: _assessment("confirmed", 3, 3, 3))
    grade_runtime.grade_via_replay(_crash(), _target())
    assert called.get("cross_check") is True


# ---- aggregate confirmation routing -----------------------------------------

def _candidate(crash_type, votes, passed_votes, n_runs=3):
    return Candidate(
        crash_type=crash_type, site="vault request->leak",
        votes=votes, n_runs=n_runs, passed_votes=passed_votes,
        operations=(), best_path=Path("x"), run_paths=(Path("x"),),
    )


def test_aiagent_needs_replay_not_votes():
    # Two finders agreed but no replay confirmed -> NOT confirmed for ai-agent.
    assert _candidate("aiagent:authz-bypass", votes=3, passed_votes=0).is_confirmed is False
    # A confirmed replay (passed grade) -> confirmed.
    assert _candidate("aiagent:authz-bypass", votes=1, passed_votes=1).is_confirmed is True
    # Unclassified fallback is still namespaced, same rule.
    assert _candidate("aiagent:unclassified", votes=3, passed_votes=0).is_confirmed is False


def test_crash_model_profiles_keep_vote_shortcut():
    # Non-ai-agent: votes>=2 still confirms (sanitizer backstop); unchanged.
    assert _candidate("heap-buffer-overflow", votes=2, passed_votes=0).is_confirmed is True
    assert _candidate("heap-buffer-overflow", votes=1, passed_votes=1).is_confirmed is True
    assert _candidate("heap-buffer-overflow", votes=1, passed_votes=0).is_confirmed is False


# ---- detect namespacing guarantee -------------------------------------------

def test_crash_reason_namespaces_invariant():
    # Already-prefixed (the finder's convention) passes through.
    h1 = "AIAGENT: invariant=aiagent:authz-bypass component=vault scope=static_path"
    assert detect.crash_reason(h1)["crash_type"] == "aiagent:authz-bypass"
    # A finder that forgot the prefix is normalized, so is_confirmed can't misroute it.
    h2 = "AIAGENT: invariant=authz-bypass component=vault scope=static_path"
    assert detect.crash_reason(h2)["crash_type"] == "aiagent:authz-bypass"
    # Empty -> the tolerated unclassified bucket, still namespaced.
    assert detect.crash_reason("")["crash_type"] == "aiagent:unclassified"
