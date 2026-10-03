# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""patch-stage prompt for the ai-agent profile.

A fix restores the missing/ineffective guard so the invariant holds at the point of
use. Re-exports the language-agnostic style judge unchanged. NOTE: for this profile
a fix is NOT verified by "exit 0 / no sanitizer output" — the behavioral oracle
(the operator replay with positive+negative controls, plus a legitimate-operation
control that must still pass) is what proves the repair; that lives in the separate
replay stage, not here.
"""
from __future__ import annotations

from ..prompts.patch_prompt import build_style_judge_prompt  # noqa: F401  (re-exported)


def build_patch_prompt(source_root: str, binary_path: str, build_command: str,
                       test_command: str | None, reproduction_command: str,
                       crash_output: str, report_text: str | None = None,
                       retry_evidence: tuple[str, str] | None = None) -> str:
    report = (report_text or "").strip()
    report_sec = f"\nReport:\n{report[:4000]}\n" if report else ""
    retry = ""
    if retry_evidence:
        prev_diff, why = retry_evidence
        retry = (f"\nYour previous attempt did not hold. Diff:\n{prev_diff[:1500]}\n"
                 f"Why it failed: {why}\n")
    tests = test_command or "(none configured)"
    return f"""Propose a fix for this ai-agent finding.

Target: {source_root} (artifact {binary_path}). Build: `{build_command}`. Tests: `{tests}`.
Replay entry: {reproduction_command}.
AIAGENT header:
{crash_output}{report_sec}{retry}

Fix the ROOT CAUSE: restore the guard so the invariant holds at the point of use
(check effective authority at use, including retries/callbacks/concurrency). Do not
merely block the one payload in the candidate, and do not disable the feature or the
service to hide the symptom — a disabled path fails the repair.

Preserve legitimate behavior: the fix must keep authorized callers working (a
legitimate-operation control is part of verification). Keep the change minimal and
local to the guard/authorization logic.

Verification note (for the operator, not this stage): acceptance is a behavioral
re-replay — the attacker path no longer violates the invariant AND the positive
legitimate-operation control still passes. Exit code and absent sanitizer output are
NOT the oracle here.

Apply the fix to the source tree and emit the path to your written patch/diff inside
a single <patch_path>...</patch_path> tag."""
