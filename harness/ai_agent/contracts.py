"""Versioned JSON contracts shared by discovery, replay and reporting.

No permissive WITNESS fallback, coercion, duplicate JSON keys, NaN, external
schema resolution, executable payload unpacking, or finder-selected policy.
Schema validation proves structure only; it never confirms a vulnerability.
"""
from __future__ import annotations

import hashlib
import json
import math
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator

MAX_DOCUMENT_BYTES = 2 * 1024 * 1024


class ContractError(ValueError):
    """Invalid or unsupported evidence/configuration, not a refuted finding."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise ContractError(f"non-finite JSON number: {value}")


def decode(raw: str | bytes) -> dict:
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ContractError("document exceeds the input budget")
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="strict")
        if len(raw.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise ContractError("document exceeds the input budget")
        result = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_nonfinite)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as e:
        raise ContractError(f"invalid JSON: {e}") from e
    if not isinstance(result, dict):
        raise ContractError("document must be an object")
    pending = [(result, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > 128:
            raise ContractError("JSON exceeds the nesting budget")
        if isinstance(value, float) and not math.isfinite(value):
            raise ContractError("JSON contains a non-finite number")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
    return result


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as e:
        raise ContractError(f"not a finite JSON value: {e}") from e


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def schema(name: str) -> dict:
    if name not in {"scenario", "target-contract", "evidence", "capabilities"}:
        raise ContractError(f"unknown schema: {name}")
    return json.loads(files(__package__).joinpath(f"schemas/{name}.schema.json").read_text())


def validate(value: dict, name: str) -> dict:
    # Round-trip also rejects non-JSON Python values and excessive depth/size.
    value = decode(canonical(value))
    errors = sorted(Draft202012Validator(schema(name)).iter_errors(value),
                    key=lambda e: str(list(e.absolute_path)))
    if errors:
        error = errors[0]
        location = "/".join(map(str, error.absolute_path)) or "$"
        raise ContractError(f"{name}/{location}: {error.message}")
    return value


def load(path: str | Path, name: str) -> dict:
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_DOCUMENT_BYTES + 1)
    return validate(decode(raw), name)


def safe_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (bool(value) and bool(path.parts) and not path.is_absolute() and str(path) == value
            and not any(p in {".", ".."} for p in path.parts)
            and "\\" not in value and not any(ord(c) < 32 for c in value))


def validate_target(value: dict) -> dict:
    value = validate(value, "target-contract")
    principals = set(value["policy"]["principals"])
    invariants = value["policy"]["invariants"]
    fixtures = value["fixtures"]
    for name, entry in value["entries"].items():
        if entry["actor"] not in principals:
            raise ContractError(f"entry {name}: unknown principal")
        for arg in entry["argv"]:
            if "\x00" in arg:
                raise ContractError(f"entry {name}: NUL in argv")
    for name, oracle in value["oracles"].items():
        if oracle["invariant"] not in invariants:
            raise ContractError(f"oracle {name}: unknown invariant")
        source = oracle["observe"]
        if source["kind"] == "file":
            if (not source["path"].startswith("/") or "\x00" in source["path"]
                    or ".." in PurePosixPath(source["path"]).parts):
                raise ContractError(f"oracle {name}: unsafe observation path")
        if source["kind"] == "response" and source["entry"] not in value["entries"]:
            raise ContractError(f"oracle {name}: unknown entry")
        pred = oracle["predicate"]
        if pred["op"] == "contains_canary" and fixtures.get(pred["fixture"], {}).get("kind") != "canary":
            raise ContractError(f"oracle {name}: unknown canary")
    for name, fixture in fixtures.items():
        if not safe_relative_path(fixture["path"]):
            raise ContractError(f"fixture {name}: unsafe relative path")
    fixture_paths = [f["path"] for f in fixtures.values()]
    if len(set(fixture_paths)) != len(fixture_paths):
        raise ContractError("fixtures must have distinct paths")
    for control in value["controls"]:
        _validate_steps(control["steps"], value)
        if control["oracle"] not in value["oracles"]:
            raise ContractError(f"control {control['id']}: unknown oracle")
    if len({c["id"] for c in value["controls"]}) != len(value["controls"]):
        raise ContractError("control IDs must be unique")
    if {c["kind"] for c in value["controls"]} != {"positive", "negative"}:
        raise ContractError("both positive and negative controls are required")
    if value["runtime"]["mode"] == "agent_behavior" and not value["runtime"].get("model"):
        raise ContractError("agent-behavior mode requires model metadata")
    return value


def _validate_steps(steps: list[dict], contract: dict) -> None:
    for step in steps:
        if step["entry"] not in contract["entries"]:
            raise ContractError(f"unknown entry {step['entry']!r}")
    if len(steps) > contract["runtime"]["max_steps"]:
        raise ContractError("scenario exceeds the step budget")


def validate_scenario(value: dict, contract: dict | None = None) -> dict:
    value = validate(value, "scenario")
    if contract is not None:
        if value["contract_id"] != contract["id"]:
            raise ContractError("scenario refers to a different target contract")
        if value["mode"] != contract["runtime"]["mode"]:
            raise ContractError("scenario runtime mode does not match target contract")
        _validate_steps(value["steps"], contract)
        entries = [contract["entries"][s["entry"]] for s in value["steps"]]
        if entries[0]["role"] != "attacker" or any(e["role"] == "control" for e in entries):
            raise ContractError("candidate must start at an attacker entry and cannot invoke control-only entries")
        if value["path"]["attacker"] != entries[0]["actor"]:
            raise ContractError("claimed attacker does not match the entry principal")
        actual_triggers = {(e["actor"], e["authority"]) for e in entries if e["role"] == "trigger"}
        declared_triggers = {(t["actor"], t["authority"]) for t in value["path"]["triggers"]}
        if actual_triggers != declared_triggers:
            raise ContractError("separate trigger actors/authority must be declared exactly")
        # Unknown oracle/invariant is intentionally NOT a malformed candidate.
        # Replay records it as unsupported; the new hypothesis survives for review.
    return value
