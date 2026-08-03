# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the F4 config `commit` argument-injection guard (self-review)."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.config import TargetConfig, _safe_git_ref

D = Path("/tmp/some-target")
ROOT = Path(__file__).resolve().parents[1]


def test_accepts_hash_and_tag():
    assert _safe_git_ref("a1b2c3d4e5f6", D) == "a1b2c3d4e5f6"
    assert _safe_git_ref("0.18.0-beta.1", D) == "0.18.0-beta.1"   # tag-like ref
    assert _safe_git_ref("zune-jpeg-0.5.15", D) == "zune-jpeg-0.5.15"
    assert _safe_git_ref("  1efa270  ", D) == "1efa270"           # trimmed


@pytest.mark.parametrize("bad", [
    "--output=/tmp/pwn",   # leading-dash → git option injection
    "-1",
    "--all",
    "a b",                 # whitespace
    "a\tb",
    "",                    # empty
    "   ",
    "x\x00y",              # NUL
])
def test_rejects_injection_shaped_refs(bad):
    with pytest.raises(ValueError):
        _safe_git_ref(bad, D)


def test_all_shipped_target_configs_load():
    """A hardening guard must not make a checked-in target unloadable."""
    configs = sorted((ROOT / "targets").glob("*/config.yaml"))
    assert configs, "no shipped target configs found"
    loaded = [TargetConfig.load(config.parent) for config in configs]
    assert [target.name for target in loaded] == [config.parent.name for config in configs]


def test_provenance_label_is_separate_from_machine_git_ref():
    target = TargetConfig.load(ROOT / "targets" / "dvra3-parser")
    assert target.commit == "d9228e51d19756330d189d19d0934946d630b7ae"
    assert target.provenance_label and "benchmark" in target.provenance_label
