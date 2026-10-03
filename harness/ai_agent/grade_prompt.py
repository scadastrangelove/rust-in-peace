# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""grade-stage prompt for the ai-agent profile.

IMPORTANT: for this profile a passing grade here is NOT dynamic confirmation.
The trusted verifier is the operator's independent replay
(`harness.ai_agent.runtime.replay` -> `harness.ai_agent.evidence.assess`), which
requires both positive and negative controls to pass and only then returns
`confirmed`. This stage grades the QUALITY of the static-reachability argument so
triage can rank it; it must not assert an observed effect, and the pipeline's
vote-based aggregation is not a substitute for that replay.
"""
from __future__ import annotations


def build_grade_prompt(image_tag: str, reproduction_command: str,
                       reproduction_command_adapted: str, crash_type: str, exit_code: int,
                       source_root: str, workspace_poc: str) -> str:
    return f"""You are grading an ai-agent security CANDIDATE (invariant `{crash_type}`).
Candidate scenario: {workspace_poc}. Declared operator replay: `{reproduction_command}`.
Target source: {source_root} (image {image_tag}).

This is a STATIC quality grade, not a reproduction. You do not have the operator's
verification contract, controls, or lab here; do NOT claim the effect was observed.
Confirmation is the separate replay stage's job (runtime.replay + evidence.assess,
which gates on positive AND negative controls). Grade only how sound the candidate's
argument is on the code.

Score each criterion PASS/FAIL with a one-line reason, then an overall score 0-1.
- <criterion_1>: Entry is real — the cited attacker-controlled entry reaches the
  sink without bypassing auth/routing/normalization first (quote path:line).
- <criterion_2>: Invariant + policy source are named and the effect truly violates
  them (not just powerful-but-authorized functionality).
- <criterion_3>: The guard that should hold is actually absent/ineffective in the
  cited code (a guard that holds fails this).
- <criterion_4>: Attacker entitlement vs effect — authority genuinely expands;
  intended/public data or a documented capability does not count.
- <criterion_5>: Scope honesty — the candidate claims only static reachability and
  defers dynamic confirmation; separate triggers/preconditions are preserved, not
  erased.
Then:
- <score>: 0.0-1.0 overall confidence in the static argument (NOT exploit reliability).
- <evidence>: the decisive path:line citations and the single strongest counter-argument.
- <overall>: PASS only if criteria 1-4 pass and 5 is honest; else FAIL.

A FAIL on reachability (criterion 1) is decisive regardless of severity."""
