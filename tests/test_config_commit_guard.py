# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the F4 config `commit` argument-injection guard (self-review)."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.config import _safe_git_ref

D = Path("/tmp/some-target")


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
