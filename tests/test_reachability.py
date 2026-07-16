# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the reachability oracle (harness/reachability.py)."""
from harness import reachability as rc


def test_modality_budget_needs_two_modalities():
    # one modality, however many runs, never meets the budget
    assert not rc.ModalityBudget(blind=99).met(5)
    # two modalities clearing the threshold → met
    assert rc.ModalityBudget(blind=3, coverage=2).met(5)
    # two modalities under the threshold → not met
    assert not rc.ModalityBudget(blind=1, coverage=1).met(5)


def test_reproduced_is_terminal():
    v = rc.classify(reproduced=True, residual_reason="reproduced",
                    modality_budget=rc.ModalityBudget(blind=3, coverage=3))
    assert v.state == "reproduced" and v.is_terminal


def test_named_rung_is_residual_not_unreachable():
    v = rc.classify(reproduced=False, residual_reason="needs-MSan",
                    modality_budget=rc.ModalityBudget(blind=3, coverage=3),
                    static_guard_read="whatever")
    assert v.state == "residual" and not v.is_terminal


def test_budget_not_met_stays_residual():
    v = rc.classify(reproduced=False, residual_reason="uncharacterized",
                    modality_budget=rc.ModalityBudget(blind=9),   # one modality
                    static_guard_read="magic!=ID3 dominates")
    assert v.state == "residual"


def test_no_guard_read_stays_residual():
    v = rc.classify(reproduced=False, residual_reason="uncharacterized",
                    modality_budget=rc.ModalityBudget(blind=3, coverage=2, grammar=2))
    assert v.state == "residual"                              # budget met but no guard read


def test_both_gates_cleared_is_suspected_unreachable_with_symbolic_plan():
    v = rc.classify(reproduced=False, residual_reason="uncharacterized",
                    modality_budget=rc.ModalityBudget(blind=3, coverage=2, grammar=2),
                    static_guard_read="the `!= b\"ID3\"` reject dominates the sink",
                    site="id3::get_id3")
    assert v.state == "suspected-unreachable" and v.is_terminal
    assert v.symbolic_plan and v.symbolic_plan["target_path"] == "id3::get_id3"
    assert "unsat" in v.symbolic_plan["interpretation"]
    assert set(v.to_dict()) == {"state", "reason", "modalities", "guard_read", "symbolic_plan"}


def test_states_vocabulary():
    assert rc.REACHABILITY_STATES == ("reproduced", "residual", "suspected-unreachable")
