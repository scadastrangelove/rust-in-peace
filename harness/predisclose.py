# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Predisclose stage: the pre-disclosure gate that runs after report+patch.

Wires up harness/prompts/maintainer_review_prompt.py (P1.3, LESSONS.md L13) —
written and tested since the lopdf campaign but never called from any CLI
stage until now (a real gap: the four axes it attacks — misunderstanding,
inflated severity, weak reachability, broken fix — are exactly the ones that
kept needing a human to re-derive by hand every campaign; see LESSONS.md
L15/L23/L31-L34 for the sibling disciplines this stage is the first structural
home for. Reverify-against-main, tracker-scope duplicate check, and a measured
severity baseline are documented but not yet coded here — this stage is where
they belong when they land, not a parallel one).

Mirrors report.py/patch.py's shape: fresh container from the target image
(same trust boundary as grade/report/patch), only the finding text + fix diff
cross in. The finding/fix are untrusted data (they embed target output and,
for the fix, agent-authored source) — the prompt template already wraps them.
"""
from __future__ import annotations

from . import sandbox
from .agent import AgentResult, parse_xml_tag, run_agent
from .artifacts import MaintainerReviewVerdict
from .prompts.maintainer_review_prompt import build_maintainer_review_prompt

MAINTAINER_REVIEW_MAX_TURNS = 60

_VERDICT_TOKENS = ("ACCEPT", "DOWNGRADE", "REJECT", "WONTFIX")
_SEVERITY_TOKENS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_REACH_TOKENS = ("REACHABLE", "CONSTRUCTION_ONLY", "UNCLEAR")


async def run_maintainer_review(
    *,
    finding_text: str,
    severity_claimed: str,
    fix_snippet: str,
    reachability_arg: str,
    source_root: str,
    image_tag: str,
    model: str,
    agent_env: dict[str, str] | None = None,
    container_name: str = "predisclose_target",
    max_turns: int = MAINTAINER_REVIEW_MAX_TURNS,
    transcript_path: str | None = None,
    progress_prefix: str | None = None,
    system_prompt: str | None = None,
) -> tuple[MaintainerReviewVerdict | None, AgentResult]:
    """Run the adversarial maintainer-review agent on one finding + its fix.

    Returns (verdict, agent_result). verdict is None if the agent emitted no
    parseable <maintainer_review> block (treat as a hard stop, same as a
    missing report/patch block elsewhere in the pipeline — don't disclose on
    an unparseable review).
    """
    prompt = build_maintainer_review_prompt(
        finding_text=finding_text,
        severity_claimed=severity_claimed,
        fix_snippet=fix_snippet,
        reachability_arg=reachability_arg,
        source_root=source_root,
    )

    with sandbox.agent_container(image_tag, container_name, agent_env) as container:
        result = await run_agent(
            prompt=prompt,
            max_turns=max_turns,
            model=model,
            container=container,
            transcript_path=transcript_path,
            progress_prefix=progress_prefix,
            system_prompt=system_prompt,
        )

    text = result.find_tagged_message("maintainer_review")
    return _parse_maintainer_review(text), result


def _parse_maintainer_review(text: str) -> MaintainerReviewVerdict | None:
    block = parse_xml_tag(text, "maintainer_review")
    if not block:
        return None
    verdict = _parse_token(block, "verdict", _VERDICT_TOKENS, default=None)
    if verdict is None:
        return None
    return MaintainerReviewVerdict(
        verdict=verdict,
        corrected_severity=_parse_token(block, "corrected_severity", _SEVERITY_TOKENS,
                                        default="LOW"),
        reachability=_parse_token(block, "reachability", _REACH_TOKENS,
                                  default="UNCLEAR"),
        fix_ok=(parse_xml_tag(block, "fix_ok") or "").strip().upper() == "YES",
        fix_problem=(parse_xml_tag(block, "fix_problem") or "-").strip(),
        rebuttals=(parse_xml_tag(block, "rebuttals") or "").strip(),
        one_line=(parse_xml_tag(block, "one_line") or "").strip(),
    )


def _parse_token(text: str, tag: str, tokens: tuple[str, ...], default: str | None) -> str | None:
    raw = (parse_xml_tag(text, tag) or "").upper()
    for t in tokens:
        if t in raw:
            return t
    return default
