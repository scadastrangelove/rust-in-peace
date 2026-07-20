# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Predisclose stage: maintainer-review-block parsing (P1.3, LESSONS.md L13).

The first structural home for the pre-disclosure checklist — see harness/
predisclose.py's module docstring for what this does and doesn't cover yet.
"""
from harness.predisclose import _parse_maintainer_review
from harness.artifacts import MaintainerReviewVerdict


REVIEW_BLOCK = """\
<maintainer_review>
<verdict>ACCEPT</verdict>
<corrected_severity>MEDIUM</corrected_severity>
<reachability>REACHABLE</reachability>
<fix_ok>YES</fix_ok>
<fix_problem>-</fix_problem>
<rebuttals>argstack.rs:38 debug_assert is inert in release; the mandatory bounds
check on the wrapped index still panics</rebuttals>
<one_line>Confirmed: BLEND pops the operand count unconditionally, same class as #80.</one_line>
</maintainer_review>
"""


def test_parse_full_review_block():
    v = _parse_maintainer_review(REVIEW_BLOCK)
    assert isinstance(v, MaintainerReviewVerdict)
    assert v.verdict == "ACCEPT"
    assert v.corrected_severity == "MEDIUM"
    assert v.reachability == "REACHABLE"
    assert v.fix_ok is True
    assert v.fix_problem == "-"
    assert "argstack.rs:38" in v.rebuttals
    assert "BLEND" in v.one_line


def test_parse_downgrade_and_fix_not_ok():
    text = REVIEW_BLOCK.replace("<verdict>ACCEPT</verdict>", "<verdict>DOWNGRADE</verdict>") \
                        .replace("<fix_ok>YES</fix_ok>", "<fix_ok>NO</fix_ok>") \
                        .replace("<fix_problem>-</fix_problem>",
                                 "<fix_problem>leaves `n` unused after the early return</fix_problem>")
    v = _parse_maintainer_review(text)
    assert v.verdict == "DOWNGRADE"
    assert v.fix_ok is False
    assert "unused" in v.fix_problem


def test_parse_missing_block_returns_none():
    assert _parse_maintainer_review("no structured output here") is None


def test_parse_missing_verdict_tag_returns_none():
    # A block that's present but truncated mid-write (e.g. agent hit max_turns)
    # must not silently default to ACCEPT.
    text = "<maintainer_review>\n<corrected_severity>LOW</corrected_severity>\n</maintainer_review>"
    assert _parse_maintainer_review(text) is None


def test_parse_defaults_severity_and_reachability_when_absent():
    text = ("<maintainer_review>\n<verdict>REJECT</verdict>\n"
            "<fix_ok>NO</fix_ok>\n</maintainer_review>")
    v = _parse_maintainer_review(text)
    assert v.verdict == "REJECT"
    assert v.corrected_severity == "LOW"       # default, per _parse_token's fallback
    assert v.reachability == "UNCLEAR"          # default
    assert v.fix_ok is False
