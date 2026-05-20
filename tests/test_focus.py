# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Focus-area prompt section rendering + round-robin assignment."""
from harness.prompts.find_prompt import build_find_prompt
from harness.cli import _assigned_focus


# ── build_find_prompt conditional sections ───────────────────────────────────

def test_no_focus_no_bugs_omits_sections():
    p = build_find_prompt("url", "abc", "/src", "/bin")
    assert "## Focus Area" not in p
    assert "## Already Filed" not in p
    # Baseline sections still present
    assert "## Setup" in p
    assert "## Task" in p


def test_focus_area_section_renders():
    p = build_find_prompt("url", "abc", "/src", "/bin",
                          focus_area="PNG decoder (stbi__png_*)")
    assert "## Focus Area" in p
    assert "**PNG decoder (stbi__png_*)**" in p
    assert "## Already Filed" not in p


def test_reattack_harness_switches_template():
    default = build_find_prompt("url", "abc", "/src", "/bin", "ctr")
    harn = build_find_prompt("url", "abc", "/src", "/bin", "ctr",
                             reattack_harness="/tools/check.sh 60")
    assert "Reproduction harness: `/tools/check.sh 60`" in harn
    assert "/poc/" in harn
    assert "/tools/check.sh" not in default
    # output contract identical
    for tag in ("<poc_path>", "<reproduction_command>", "<crash_output>", "<dup_check>"):
        assert tag in harn and tag in default


def test_reattack_harness_with_known_bugs():
    p = build_find_prompt("url", "abc", "/src", "/bin", "ctr",
                          reattack_harness="/tools/check.sh",
                          known_bugs=["UAF in bar()"])
    assert "## Already Filed" in p
    assert "- UAF in bar()" in p


def test_known_bugs_section_renders():
    p = build_find_prompt("url", "abc", "/src", "/bin",
                          known_bugs=["NULL deref at foo.c:42", "UAF in bar()"])
    assert "## Already Filed" in p
    assert "- NULL deref at foo.c:42" in p
    assert "- UAF in bar()" in p
    assert "## Focus Area" not in p


def test_both_sections_render_in_order():
    p = build_find_prompt("url", "abc", "/src", "/bin",
                          focus_area="JPEG", known_bugs=["bug1"])
    focus_pos = p.index("## Focus Area")
    bugs_pos = p.index("## Already Filed")
    task_pos = p.index("## Task")
    setup_pos = p.index("## Setup")
    assert setup_pos < focus_pos < bugs_pos < task_pos


def test_empty_known_bugs_list_omits_section():
    p = build_find_prompt("url", "abc", "/src", "/bin", known_bugs=[])
    assert "## Already Filed" not in p


def test_accept_dos_section_off_by_default():
    p = build_find_prompt("url", "abc", "/src", "/bin")
    assert "Benchmark mode" not in p
    assert "allocation-size-too-big" not in p


def test_accept_dos_section_renders_when_enabled():
    p = build_find_prompt("url", "abc", "/src", "/bin", accept_dos=True)
    assert "## Benchmark mode — DoS-class crashes are in scope" in p
    assert "allocation-size-too-big" in p
    assert "allocator_may_return_null=1" in p
    # Comes after the quality tiers — it overrides them
    tiers_pos = p.index("## Crash Quality Tiers")
    dos_pos = p.index("## Benchmark mode")
    output_pos = p.index("## Output Format")
    assert tiers_pos < dos_pos < output_pos


# ── _assigned_focus round-robin ──────────────────────────────────────────────

def test_assigned_focus_empty_list():
    assert _assigned_focus(0, []) is None
    assert _assigned_focus(5, []) is None


def test_assigned_focus_round_robin():
    areas = ["A", "B", "C"]
    assert [_assigned_focus(i, areas) for i in range(7)] == ["A", "B", "C", "A", "B", "C", "A"]


def test_assigned_focus_single_area():
    assert _assigned_focus(0, ["only"]) == "only"
    assert _assigned_focus(99, ["only"]) == "only"
