# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""judge-stage prompt for the ai-agent profile.

Dedup identity is root cause + invariant + component, NOT a sink line (several
paths behind one missing guard are one cause; similar entry/sink labels can hide
independent causes). Re-exports the language-agnostic compare prompt unchanged.
"""
from __future__ import annotations

from ..prompts.judge_prompt import build_compare_prompt  # noqa: F401  (re-exported)


def build_judge_prompt(asan_excerpt: str, dup_check: str, grade_status: str,
                       grade_score: float, poc_size: int, manifest_entries: list[dict]) -> str:
    prior = "\n\n".join(
        f"[{i}] {e.get('asan_excerpt', '').strip()}\n{(e.get('report_text') or '').strip()[:800]}"
        for i, e in enumerate(manifest_entries)
    ) or "(none yet)"
    return f"""You are deduplicating an ai-agent finding against prior confirmed/known ones.

NEW finding:
{asan_excerpt}

Reachability/dup note from the finder:
{dup_check}

Grade: {grade_status} (score {grade_score}).  Candidate size: {poc_size} bytes.

Prior findings:
{prior}

Decide identity by ROOT CAUSE + INVARIANT + COMPONENT, not by matching a file/line
or a sink label:
- Two attacker paths behind the SAME missing guard / same root cause = one finding.
- The SAME invariant id on a DIFFERENT component or via an independent root cause =
  a distinct finding, even if the labels look alike.
- A fix that would close the new one but not the prior (or vice versa) => distinct.

Emit exactly one <judgment> tag:
- <judgment>NEW</judgment>        — a distinct root cause not covered above.
- <judgment>DUP_BETTER</judgment> — same root cause as a prior one, but this write-up
  is stronger (clearer entry/guard/effect, better evidence scope).
- <judgment>DUP_SKIP</judgment>   — same root cause and no improvement over a prior.
Keep uncertain identities provisional: when unsure whether two share a cause, prefer
NEW and say why, preserving both paths' evidence."""
