"""Evidence validation and conservative promotion, independent of taxonomy.

JSON imported from a finder is a claim, even when it has this exact shape.
Only the orchestrator's fresh replay supplies evidence to `assess`; the caller
must not promote an imported file by calling it a trusted replay.
"""
from __future__ import annotations

from dataclasses import dataclass

from .contracts import ContractError, digest, validate


@dataclass(frozen=True)
class Assessment:
    disposition: str
    reason: str
    successes: int
    completed: int
    scheduled: int

    @property
    def confirmed(self) -> bool:
        return self.disposition == "confirmed"


def validate_evidence(data: dict, scenario: dict, contract: dict) -> dict:
    data = validate(data, "evidence")
    if data["scenario_digest"] != digest(scenario) or data["contract_digest"] != digest(contract):
        raise ContractError("evidence belongs to a different scenario/contract")
    if data["mode"] != scenario["mode"] or data["mode"] != contract["runtime"]["mode"]:
        raise ContractError("evidence runtime mode mismatch")
    if data["artifact"]["configuration"] != digest(contract["artifact"]):
        raise ContractError("evidence artifact configuration mismatch")
    if data["artifact"]["source_commit"] != contract["artifact"]["source_commit"]:
        raise ContractError("evidence source pin mismatch")
    if data["oracle"] != scenario["oracle"] or data["invariant"] != scenario["finding"]["invariant"]:
        raise ContractError("evidence changes the requested oracle/invariant")
    if data["scheduled_trials"] != contract["runtime"]["trials"]:
        raise ContractError("evidence changes the declared trial budget")
    trial_ids = [t["id"] for t in data["trials"]]
    if len(trial_ids) != len(set(trial_ids)) or len(trial_ids) != data["scheduled_trials"]:
        raise ContractError("every scheduled trial must have a unique outcome")
    observations = {o["id"]: o for o in data["observations"]}
    if len(observations) != len(data["observations"]):
        raise ContractError("duplicate observation ID")
    if any(o["trial_id"] not in trial_ids for o in observations.values()):
        raise ContractError("orphan observation")
    if any(digest(o["value"]) != o["value_digest"] for o in observations.values()):
        raise ContractError("observation value digest mismatch")
    control_ids = {c["id"] for c in contract["controls"]}
    control_pairs = set()
    for control in data["controls"]:
        pair = control["trial_id"], control["id"]
        if pair in control_pairs or pair[0] not in trial_ids or pair[1] not in control_ids:
            raise ContractError("duplicate or orphan control")
        control_pairs.add(pair)
        expected = next(c for c in contract["controls"] if c["id"] == pair[1])
        if control["kind"] != expected["kind"]:
            raise ContractError("control kind mismatch")
    for trial in data["trials"]:
        refs = trial["observation_ids"]
        if len(set(refs)) != len(refs):
            raise ContractError("repeated observation reference")
        if any(ref not in observations or observations[ref]["trial_id"] != trial["id"] for ref in refs):
            raise ContractError("missing or cross-trial observation reference")
        if trial["status"] != "completed":
            if trial["violation"] is not None or not trial["error"]:
                raise ContractError("incomplete trials need an error, not a negative result")
        else:
            if trial["violation"] is None or trial["error"] is not None or not refs:
                raise ContractError("completed trial lacks evaluable observations")
            matched = any(observations[ref]["matched"] for ref in refs)
            if trial["violation"] != matched:
                raise ContractError("trial result disagrees with observations")
            if any((trial["id"], cid) not in control_pairs for cid in control_ids):
                raise ContractError("completed trial is missing controls")
        if data["mode"] == "agent_behavior" and not trial.get("model"):
            raise ContractError("agent-behavior trial is missing model metadata")
    referenced = {ref for t in data["trials"] for ref in t["observation_ids"]}
    if referenced != set(observations):
        raise ContractError("unreferenced observation")
    return data


def assess(data: dict, scenario: dict, contract: dict) -> Assessment:
    data = validate_evidence(data, scenario, contract)
    completed = [t for t in data["trials"] if t["status"] == "completed"]
    successes = sum(t["violation"] is True for t in completed)
    def result(disposition: str, reason: str) -> Assessment:
        return Assessment(disposition, reason, successes, len(completed), data["scheduled_trials"])
    oracle = contract["oracles"].get(scenario["oracle"])
    if oracle is None or oracle["invariant"] != scenario["finding"]["invariant"]:
        return result("unresolved", "New oracle/invariant requires an independently reviewed verifier")
    if not completed:
        return result("unresolved", "No evaluable trials; inspect infrastructure and unsupported adapters")
    if any(o["kind"] not in {"response", "file", "exit_code", "duration_ms"} for o in data["observations"]):
        return result("unresolved", "Observation kind needs a reviewed verifier")
    # Both positive and negative controls must run and pass for each promoted
    # trial. A broken observer or a disabled service cannot confirm or clear it.
    for trial in completed:
        controls = [c for c in data["controls"] if c["trial_id"] == trial["id"]]
        if {c["kind"] for c in controls} != {"positive", "negative"} or not all(c["passed"] for c in controls):
            return result("unresolved", "Control failure: environment, observer or legitimate behavior is broken")
    if data["scope"] in {"component", "static_path"}:
        return result("component_only", "Observation does not establish the shipping attacker entry")
    if successes:
        return result("confirmed", "Independent replay observed an invariant violation; reliability is reported separately")
    if len(completed) != data["scheduled_trials"]:
        return result("unresolved", "No observed violation and some scheduled trials were not evaluable")
    return result("not_observed", "No violation observed within this configuration and trial budget")
