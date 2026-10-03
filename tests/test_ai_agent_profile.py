"""Profile-registration + prompt/detector wiring for the ai-agent profile.

Offline: no Docker, no network. Verifies the profile resolves, the generic
pipeline's required tags are emitted, the detector sniffs/parses AIAGENT output
without a stack trace, and config validation fails closed.
"""
import shutil
import tempfile
from pathlib import Path

import pytest

import harness.profiles as P
from harness.config import TargetConfig

_REPO = Path(__file__).resolve().parents[1]


def test_profile_resolves_and_detector():
    assert "ai-agent" in P.known_profiles()
    pr = P.get_profile("ai-agent")
    assert pr.name == "ai-agent"
    assert pr.detector is P._ai_detect
    # registering ai-agent must not break the other profiles
    for name in ("rust", "cpp", "android-app"):
        assert P.get_profile(name).name == name


def test_builders_emit_required_tags():
    pr = P.get_profile("ai-agent")
    find = pr.build_find_prompt(github_url="u", commit="c", source_root="s", binary_path="b")
    for tag in ("<poc_path>", "<reproduction_command>", "<crash_type>", "<crash_output>",
                "<exit_code>", "<dup_check>", "AIAGENT:"):
        assert tag in find
    grade = pr.build_grade_prompt(image_tag="i", reproduction_command="r",
                                  reproduction_command_adapted="r", crash_type="aiagent:x",
                                  exit_code=0, source_root="s", workspace_poc="w")
    for tag in ("<overall>", "<criterion_1>", "<criterion_5>", "<score>", "<evidence>"):
        assert tag in grade
    judge = pr.build_judge_prompt(asan_excerpt="AIAGENT: invariant=aiagent:x component=c",
                                  dup_check="d", grade_status="PASS", grade_score=0.9,
                                  poc_size=10, manifest_entries=[])
    assert "<judgment>" in judge and "DUP_SKIP" in judge
    assert "<winner>" in pr.build_compare_prompt(report_a="a", report_b="b")
    report = pr.build_report_prompt(github_url="u", commit="c", source_root="s", binary_path="b",
                                    reproduction_command="r",
                                    crash_output="AIAGENT: invariant=aiagent:x component=c",
                                    attack_surface=None, upstream_log=None, crash_file=None)
    assert "<exploitability_report>" in report
    patch = pr.build_patch_prompt(source_root="s", binary_path="b", build_command="bc",
                                  test_command=None, reproduction_command="r", crash_output="x")
    assert "<patch_path>" in patch
    assert "<" in pr.build_style_judge_prompt("diff")


def test_grade_prompt_does_not_claim_dynamic_confirmation():
    """The ledger forbids inheriting vote/self-report confirmation. The grade
    prompt must defer confirmation to the operator replay."""
    pr = P.get_profile("ai-agent")
    g = pr.build_grade_prompt(image_tag="i", reproduction_command="r",
                              reproduction_command_adapted="r", crash_type="aiagent:x",
                              exit_code=0, source_root="s", workspace_poc="w").lower()
    assert "not" in g and ("replay" in g or "confirmation" in g)


_HEADER = ("AIAGENT: invariant=aiagent:authz-bypass component=vault scope=static_path\n"
           "attacker: visitor\nentry: GET /vault\nguard: owner-token check\neffect: read vault\n")


def test_detector_surface():
    d = P.detector_for_output(_HEADER)
    assert d is P._ai_detect
    assert d.crash_reason(_HEADER)["crash_type"] == "aiagent:authz-bypass"
    tf = d.top_frame(_HEADER)
    assert tf and ":" not in tf.split("->")[0]  # no :line suffix to mangle _site_key
    assert "vault" in tf
    assert d.project_frames(_HEADER)  # non-empty identity frames
    assert "AIAGENT:" in d.asan_excerpt(_HEADER)


def test_detector_tolerates_empty():
    d = P._ai_detect
    assert d.project_frames("") == []
    assert d.top_frame("") is None
    assert d.crash_reason("")["crash_type"] == "aiagent:unclassified"  # tolerated bucket


def test_config_validates_canary_and_fails_closed():
    tc = TargetConfig.load(str(_REPO / "targets" / "ai-agent-canary"))
    assert tc.profile == "ai-agent"
    assert tc.ai_agent_contract_path and tc.ai_agent_contract_path.endswith("target-contract.json")
    d = tempfile.mkdtemp()
    try:
        Path(d, "config.yaml").write_text("profile: ai-agent\n")  # missing contract path
        with pytest.raises(ValueError, match="requires ai_agent_contract_path"):
            TargetConfig.load(d)
    finally:
        shutil.rmtree(d)
