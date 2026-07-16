# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for corpus-as-regression (harness/corpus.py)."""
from harness import corpus


def test_save_and_load(tmp_path):
    root = tmp_path / "corpus"
    e = corpus.save_regression(
        root, finding_id="cand_00", cwe="CWE-787", sanitizer="miri",
        crash_input=b"\x00\x01\x02", reproduction_command="cargo +nightly fuzz run reattack")
    assert (root / e.input_file).read_bytes() == b"\x00\x01\x02"
    loaded = corpus.load_manifest(root)
    assert len(loaded) == 1 and loaded[0].finding_id == "cand_00"
    assert loaded[0].sha256 == e.sha256


def test_idempotent_on_finding_and_sha(tmp_path):
    root = tmp_path / "corpus"
    for _ in range(3):
        corpus.save_regression(root, finding_id="cand_00", cwe="CWE-787",
                               sanitizer="miri", crash_input=b"same",
                               reproduction_command="x")
    assert len(corpus.load_manifest(root)) == 1     # same (id, sha) collapses


def test_distinct_inputs_are_distinct_entries(tmp_path):
    root = tmp_path / "corpus"
    corpus.save_regression(root, finding_id="c0", cwe="CWE-125", sanitizer="asan",
                           crash_input=b"aaa", reproduction_command="x")
    corpus.save_regression(root, finding_id="c1", cwe="CWE-125", sanitizer="asan",
                           crash_input=b"bbb", reproduction_command="x")
    assert len(corpus.load_manifest(root)) == 2


def test_replay_plan(tmp_path):
    root = tmp_path / "corpus"
    corpus.save_regression(root, finding_id="c0", cwe="CWE-787", sanitizer="miri",
                           crash_input=b"z", reproduction_command="x")
    plan = corpus.replay_plan(root, fuzz_target="reattack")
    assert len(plan) == 1
    assert "cargo +nightly fuzz run reattack" in plan[0] and "c0" in plan[0]


def test_load_manifest_missing(tmp_path):
    assert corpus.load_manifest(tmp_path / "nope") == []
    assert corpus.replay_plan(tmp_path / "nope") == []
