# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Grade an ai-agent candidate by the TRUSTED replay, not a self-grading agent.

`run_grade` delegates here for `profile: ai-agent`. Confirmation comes from
`runtime.replay` -> `evidence.assess` (a fresh network-isolated victim per control
and per attack, positive+negative controls gating every trial) — never the finder's
self-report and never a vote count. The returned `GraderVerdict.passed` is true only
when the independent replay observed the invariant violation.

The candidate's PoC bytes are the scenario JSON the find stage wrote; the target
contract is the operator-reviewed `ai_agent_contract_path` validated at config load.
Needs Docker and the built target image (`target.image_tag`); on any
infra/contract error the verdict is a non-passing `unverified`, never a silent pass.
"""
from __future__ import annotations

import time

from ..agent import AgentResult
from ..artifacts import CrashArtifact, GraderVerdict
from ..config import TargetConfig
from .contracts import ContractError, decode, load, validate, validate_scenario
from .evidence import assess
from .runtime import ReplayError, replay

# assess() disposition -> GraderVerdict.disposition (real|contested|unverified|...)
_DISPOSITION = {
    "confirmed": "real",
    "component_only": "contested",
    "not_observed": "unverified",
    "unresolved": "unverified",
}


def grade_via_replay(crash: CrashArtifact, target: TargetConfig) -> tuple[GraderVerdict, AgentResult, float]:
    t0 = time.time()
    try:
        if not target.ai_agent_contract_path:
            raise ContractError("target has no ai_agent_contract_path")
        contract = load(target.ai_agent_contract_path, "target-contract")
        # PoC bytes are the scenario the find stage wrote: decode + schema-validate
        # + cross-check that the scenario is bound to THIS contract before replaying.
        scenario = validate(decode(crash.poc_bytes), "scenario")
        validate_scenario(scenario, contract)
        ev = replay(scenario, contract, target.image_tag)
        a = assess(ev, scenario, contract)
        verdict = GraderVerdict(
            passed=a.confirmed,
            score=1.0 if a.confirmed else (0.5 if a.disposition == "component_only" else 0.0),
            criteria={"replay_confirmed": a.confirmed,
                      "controls_passed": a.disposition != "unresolved",
                      "shipping_entry": a.disposition != "component_only"},
            evidence=f"replay {a.disposition}: {a.successes}/{a.completed} trials of {a.scheduled} — {a.reason}",
            disposition=_DISPOSITION.get(a.disposition, "unverified"),
            gate_reason="" if a.confirmed else f"replay did not confirm: {a.disposition}",
        )
    except (ReplayError, ContractError, ValueError, OSError) as exc:
        verdict = GraderVerdict(
            passed=False, score=0.0, criteria={},
            evidence=f"replay unavailable: {type(exc).__name__}: {exc}",
            disposition="unverified",
            gate_reason="replay could not run; candidate stays unconfirmed",
        )
    # Synthetic result: no grader agent ran. transcript() is [] for messages=[].
    result = AgentResult(messages=[], result_message={"type": "result", "subtype": "ai-agent-replay"})
    return verdict, result, time.time() - t0
