# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the find→fuzz bridge (harness/rust/find_to_fuzz.py) — the pure,
non-container parts: dispatch, prompt binding, residual classification, and the
ReattackArtifact contract."""
import pytest

from harness.rust import find_to_fuzz as ff
from harness.artifacts import ReattackArtifact, RunScorecard
from harness.profiles import get_profile


def test_profile_wiring():
    assert get_profile("rust").build_reattack is ff.build_reattack
    assert get_profile("cpp").build_reattack is None      # cpp uses static reattack_harness


@pytest.mark.parametrize("cwe,template,san", [
    ("CWE-125", "index_arbitrary.rs", "asan"),
    ("CWE-787", "index_arbitrary.rs", "asan"),
    ("CWE-190", "index_arbitrary.rs", "asan"),
    ("CWE-662", "sendsync_compileproof.rs", "compile_proof"),
    ("CWE-908", "index_arbitrary.rs", "msan"),
    ("CWE-134", "byte_parser.rs", "asan_on_c"),
    ("CWE-362", "threaded_driver.rs", "tsan"),
    (None, "byte_parser.rs", "asan"),                     # default
])
def test_dispatch_by_cwe(cwe, template, san):
    d = ff.dispatch(cwe)
    assert d.template == template and d.sanitizer == san


def test_dispatch_precedence():
    # capability override beats CWE (a CWE-125 through a lying trait impl → Miri)
    assert ff.dispatch("CWE-125", capability="unsafe_trait_trust").sanitizer == "miri"
    assert ff.dispatch("CWE-125", capability="unsafe_generic_soundness").sanitizer == "compile_proof"
    # structure_gated beats everything → grammar rung
    d = ff.dispatch("CWE-125", capability="unsafe_trait_trust", structure_gated=True)
    assert d.fuzz_rung == "grammar" and d.template == "grammar_parser.rs"


def test_cwe_parsing_forms():
    assert ff.dispatch(125).sanitizer == "asan"
    assert ff.dispatch("cwe125").sanitizer == "asan"
    assert ff.dispatch("CWE-787: OOB write").sanitizer == "asan"


def test_build_reattack_binds_template_and_rules():
    p = ff.build_reattack(
        github_url="https://x/y", commit="abc", source_root="/src",
        cwe="CWE-787", site="SmallVec::insert_many (src/lib.rs:120)",
        mechanism="trusts size_hint", capability="unsafe_trait_trust",
        defer_sketch="impl Iterator with a lying size_hint")
    assert "adversarial_impl.rs" in p           # dispatched template inlined
    assert "Heap-owning element (L12)" in p     # §3 rule
    assert "cargo +nightly fuzz build reattack" in p
    assert "DEFER-TO-DYNAMIC sketch" in p        # defer section rendered


def test_load_template_unshipped_fallback():
    # a template dispatch might route to but that isn't in-repo yet falls back to
    # the nearest shipped skeleton + an inline note (the mechanism; all current
    # dispatch targets ARE shipped, so exercise it directly).
    name, text = ff._load_template("future_template.rs")
    assert name == "future_template.rs"
    assert "not shipped yet" in text and "byte_parser.rs" in text


def test_build_reattack_grammar_loads_real_template():
    p = ff.build_reattack(github_url="x", commit="c", source_root="/s",
                          cwe="CWE-125", site="get_id3", structure_gated=True)
    assert "grammar_parser.rs" in p and "not shipped yet" not in p   # now shipped


def test_classify_residual():
    d908 = ff.dispatch("CWE-908")
    assert ff.classify_residual("reproduced", "", d908) == "reproduced"
    assert ff.classify_residual("build_failed", "", d908) == "build-failed"
    assert ff.classify_residual("clean", "error: use of uninitialized value", d908) == "needs-MSan"
    assert ff.classify_residual("clean", "frame sync / magic mismatch", d908) == "grammar-gated"
    # dispatch-implied fallback when output is opaque
    assert ff.classify_residual("clean", "nothing useful", d908) == "needs-MSan"
    assert ff.classify_residual("clean", "opaque", ff.dispatch("CWE-125")) == "uncharacterized"
    # a valid agent-supplied residual is honored
    assert ff.classify_residual("clean", "", ff.dispatch("CWE-125"),
                                agent_residual="address-space-only") == "address-space-only"


def test_reattack_artifact_contract():
    a = ReattackArtifact("cand_00", "CWE-787", "adversarial_impl.rs", "miri",
                         "reproduced", "reproduced", crash_input=b"\x00\x01")
    assert a.reproduced
    assert ReattackArtifact.from_dict(a.to_dict()).crash_input == b"\x00\x01"
    with pytest.raises(ValueError):                 # clean must carry a real residual
        ReattackArtifact("f", "C", "t", "asan", "clean", "reproduced")
    with pytest.raises(ValueError):                 # reproduced must be 'reproduced'
        ReattackArtifact("f", "C", "t", "asan", "reproduced", "needs-MSan")


def test_runscorecard_counts():
    a = ReattackArtifact("cand_00", "CWE-787", "adversarial_impl.rs", "miri",
                         "reproduced", "reproduced", crash_input=b"x")
    b = ReattackArtifact("cand_01", "CWE-908", "index_arbitrary.rs", "msan",
                         "clean", "needs-MSan")
    sc = RunScorecard("mizan", [a, b])
    d = sc.to_dict()
    assert d["n_reattacks"] == 2 and d["n_reproduced"] == 1
    assert RunScorecard.from_dict(d).reproduced[0].finding_id == "cand_00"


def test_l12_lint():
    assert ff.lint_adversarial_harness("impl Iterator for L { type Item = u32; }")
    assert not ff.lint_adversarial_harness("impl Iterator for L { type Item = Box<u32>; }")
    assert ff.lint_adversarial_harness("struct Bomb(u32);")
    assert not ff.lint_adversarial_harness("struct Bomb(Box<u32>);")
    assert not ff.lint_adversarial_harness("struct Bomb(String);")


def test_l12_lint_clean_on_shipped_templates():
    import pathlib
    tdir = pathlib.Path(__file__).resolve().parents[1] / "profiles" / "rust" / "harness-templates"
    for t in ("adversarial_impl.rs", "grammar_parser.rs", "threaded_driver.rs", "index_arbitrary.rs"):
        assert ff.lint_adversarial_harness((tdir / t).read_text()) == [], f"{t} should pass L12"


def test_escalate_rung():
    assert ff.escalate_rung("needs-MSan").sanitizer == "msan"
    assert ff.escalate_rung("asan-on-C").sanitizer == "asan_on_c"
    assert ff.escalate_rung("grammar-gated").fuzz_rung == "grammar"
    assert ff.escalate_rung("address-space-only") is None   # out of fuzz scope → no escalation
    assert ff.escalate_rung("reproduced") is None


def test_shipped_templates_includes_new():
    assert "grammar_parser.rs" in ff.SHIPPED_TEMPLATES
    assert "threaded_driver.rs" in ff.SHIPPED_TEMPLATES
