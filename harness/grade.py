# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Grade loop: fresh container from same image, grader agent verifies PoC.

The trust boundary is the image tag — find-agent could write anywhere
in its container but can't retroactively modify the image. A fresh container
from the same tag is pristine. Only the PoC bytes cross the boundary.

Budget: 50 turns — it's a checklist, not research.
"""
from __future__ import annotations

import os
import time

from . import admissibility, docker_ops, gates, sandbox
from .agent import run_agent, parse_xml_tag, AgentResult
from .artifacts import CrashArtifact, GraderVerdict
from .config import TargetConfig
from .profiles import get_profile


def _tag_bool(text: str, tag: str) -> bool:
    """A `<tag>` whose value starts YES/TRUE. Absent → False (permissive)."""
    v = parse_xml_tag(text, tag)
    return bool(v) and v.strip().upper().startswith(("YES", "TRUE", "PASS"))


def _tag_tristate(text: str, tag: str) -> bool | None:
    """A shipping-reverify style tag: YES/TRUE → True, NO/FALSE → False, absent
    or anything else → None ("not re-tested")."""
    v = parse_xml_tag(text, tag)
    if not v:
        return None
    u = v.strip().upper()
    if u.startswith(("YES", "TRUE", "REPRODUCED")):
        return True
    if u.startswith(("NO", "FALSE", "GONE", "WRAPS")):
        return False
    return None


def _claim_from_grader(text: str) -> admissibility.VerdictClaim:
    """Build the admissibility premise-claim from optional grader tags. Every
    field defaults permissive, so a grader that emits none declares no premise
    and trips no gate (backward-compatible)."""
    harness_kind = parse_xml_tag(text, "harness_kind")
    harness_kind = harness_kind.strip() if harness_kind else None
    if harness_kind not in admissibility.HARNESS_KINDS:
        harness_kind = None
    return admissibility.VerdictClaim(
        rests_on_dependency_behavior=_tag_bool(text, "rests_on_dependency_behavior"),
        dep_citation=(parse_xml_tag(text, "dep_citation") or None),
        claims_reachable=_tag_bool(text, "claims_reachable"),
        where_checked=(parse_xml_tag(text, "where_checked") or None),
        harness_kind=harness_kind,
    )


GRADE_MAX_TURNS = 50


async def run_grade(
    crash: CrashArtifact,
    target: TargetConfig,
    model: str,
    workspace_dir: str,
    agent_env: dict[str, str] | None = None,
    container_name: str = "grader_target",
    transcript_path: str | None = None,
    progress_prefix: str | None = None,
    system_prompt: str | None = None,
) -> tuple[GraderVerdict, AgentResult, float]:
    """Verify a CrashArtifact in a fresh container.

    workspace_dir: host-side results dir where we also persist poc.bin so
    it survives the container teardown.
    """
    # Path-substitution sanity: replace() below no-ops silently if poc_path
    # isn't in reproduction_command. That's a find-agent output inconsistency
    # — reject it here rather than hand the grader an unadapted command.
    if crash.poc_path not in crash.reproduction_command:
        raise ValueError(
            f"poc_path {crash.poc_path!r} not found in reproduction_command "
            f"{crash.reproduction_command!r} — find-agent output is inconsistent"
        )

    # Fresh agent container from the SAME image — find-agent never touched it.
    with sandbox.agent_container(target.image_tag, container_name, agent_env) as container:
        # Only the PoC bytes cross the boundary. Substitute the path: the
        # find-agent saved to some arbitrary path; we write to a fixed one.
        docker_ops.write_file(container, "/tmp/poc.bin", crash.poc_bytes)
        adapted_cmd = crash.reproduction_command.replace(crash.poc_path, "/tmp/poc.bin")

        os.makedirs(workspace_dir, exist_ok=True)
        workspace_poc = os.path.join(workspace_dir, "poc.bin")
        with open(workspace_poc, "wb") as f:
            f.write(crash.poc_bytes)

        prompt = get_profile(target.profile).build_grade_prompt(
            image_tag=target.image_tag,
            reproduction_command=crash.reproduction_command,
            reproduction_command_adapted=adapted_cmd,
            crash_type=crash.crash_type,
            exit_code=crash.exit_code,
            source_root=target.source_root,
            workspace_poc="/tmp/poc.bin",
        )
        t0 = time.time()
        result = await run_agent(
            prompt=prompt,
            max_turns=GRADE_MAX_TURNS,
            model=model,
            container=container,
            transcript_path=transcript_path,
            progress_prefix=progress_prefix,
            system_prompt=system_prompt,
        )
        elapsed = time.time() - t0

        text = result.find_tagged_message("overall")
        criteria: dict[str, bool] = {}
        for i in range(1, 6):
            val = parse_xml_tag(text, f"criterion_{i}")
            criteria[f"criterion_{i}"] = val is not None and val.upper().startswith("PASS")

        overall = parse_xml_tag(text, "overall")
        score_str = parse_xml_tag(text, "score")
        evidence = parse_xml_tag(text, "evidence") or ""

        verdict = GraderVerdict(
            passed=(overall is not None and overall.upper().startswith("PASS")),
            score=_parse_score(score_str),
            criteria=criteria,
            evidence=evidence,
        )

        # W1b — fire the honesty gates on the grader's verdict. Additive: the
        # premise claim defaults permissive, so a grader that emits none of the
        # optional tags declares nothing and is not downgraded; build_profile
        # only bites the instrumentation-gated crash classes for this profile.
        verdict = gates.apply_gates(
            verdict,
            profile=target.profile,
            crash_signal=f"{crash.crash_type}\n{crash.crash_output}",
            claim=_claim_from_grader(text),
            reproduced_under_shipping=_tag_tristate(text, "reproduced_under_shipping"),
        )
        return verdict, result, elapsed


def _parse_score(s: str | None) -> float:
    if not s:
        return 0.0
    try:
        return float(s.strip())
    except ValueError:
        return 0.0
