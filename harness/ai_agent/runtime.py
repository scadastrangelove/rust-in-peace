"""Fresh victim labs and operator-defined observations.

The host only orchestrates Docker and evaluates bounded data. Target code runs
in a credential-free, read-only, non-root container. Neither finder commands
nor finder observer code are executed during verification. An entry adapter
is supplied by the operator in the pinned target image, accepts JSON on stdin,
and must preserve the declared attacker entry (component adapters say so).
"""
from __future__ import annotations

import contextlib
import json
import math
import os
import secrets
import selectors
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Iterator

from .. import sandbox
from .contracts import ContractError, canonical, digest, validate_scenario, validate_target
from .evidence import validate_evidence

COLLECTOR_VERSION = "1"


class ReplayError(RuntimeError):
    pass


class UnsupportedReplay(ReplayError):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_ms: float


def bounded_command(argv: list[str], *, payload: bytes = b"", timeout: float = 30,
                    limit: int = 2_097_152) -> CommandResult:
    """Bound both output streams while running, not after filling host RAM/disk."""
    start = time.monotonic()
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    output = {"stdout": bytearray(), "stderr": bytearray()}
    offset = total = 0
    try:
        with selectors.DefaultSelector() as selector:
            for stream, name in [(process.stdout, "stdout"), (process.stderr, "stderr")]:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            if payload:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
            while selector.get_map():
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
                    raise ReplayError("command exceeded the time budget")
                for key, _ in selector.select(min(remaining, 0.2)):
                    if key.data == "stdin":
                        try:
                            offset += os.write(key.fd, payload[offset:offset + 65536])
                        except BrokenPipeError:
                            offset = len(payload)
                        if offset == len(payload):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        total += len(chunk)
                        if total > limit:
                            raise ReplayError("command exceeded the observation byte budget")
                        output[key.data].extend(chunk)
            try:
                process.wait(timeout=max(0.001, timeout - (time.monotonic() - start)))
            except subprocess.TimeoutExpired as exc:
                raise ReplayError("command exceeded the time budget") from exc
        return CommandResult(process.returncode, bytes(output["stdout"]),
                             bytes(output["stderr"]), (time.monotonic() - start) * 1000)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()


def image_identity(image: str) -> str:
    result = bounded_command(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    image_id = result.stdout.decode().strip()
    if result.returncode or not image_id.startswith("sha256:") or len(image_id) != 71:
        raise ReplayError("cannot resolve target image to an immutable Docker image ID")
    return image_id


class DockerLab:
    def __init__(self, container: str, contract: dict, fixtures: dict[str, str]):
        self.container, self.contract, self.fixtures = container, contract, fixtures

    def execute(self, entry: str, value: object) -> CommandResult:
        cfg = self.contract["runtime"]
        result = bounded_command([
            "docker", "exec", "-i", "--user", cfg["user"], self.container,
            *self.contract["entries"][entry]["argv"],
        ], payload=canonical(value) + b"\n", timeout=cfg["timeout_s"],
            limit=cfg["max_output_bytes"])
        return result

    def read(self, path: str) -> bytes:
        cfg = self.contract["runtime"]
        result = bounded_command(["docker", "exec", "--user", "0:0", self.container,
                                  "/bin/cat", "--", path], timeout=cfg["timeout_s"],
                                 limit=cfg["max_output_bytes"])
        if result.returncode:
            raise ReplayError(f"file observer could not read {path!r}")
        return result.stdout


@contextlib.contextmanager
def victim_lab(image_id: str, contract: dict) -> Iterator[DockerLab]:
    cfg = contract["runtime"]
    if cfg["network"] != "none" or cfg["mode"] != "mechanism":
        raise UnsupportedReplay("model-proxy/agent-behavior adapter is not installed")
    name = "vp-ai-victim-" + uuid.uuid4().hex
    argv = ["docker", "run", "--detach", "--name", name, "--network", "none",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(cfg["pids_limit"]), "--memory", f"{cfg['memory_mb']}m",
            "--user", cfg["user"], "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=32m",
            "--tmpfs", "/work/state:rw,nosuid,nodev,noexec,size=32m,mode=1777"]
    if sandbox.runtime():
        argv += ["--runtime", sandbox.runtime()]
    # Immutable image, explicit entrypoint; no image-supplied startup command.
    argv += ["--entrypoint", "/bin/sleep", image_id, "infinity"]
    fixtures = {key: (secrets.token_hex(32) if value["kind"] == "canary" else value["value"])
                for key, value in contract["fixtures"].items()}
    try:
        started = bounded_command(argv)
        if started.returncode:
            raise ReplayError("victim container launch failed: " + started.stderr.decode(errors="replace"))
        for key, fixture in contract["fixtures"].items():
            # Container-relative destinations validated before this boundary.
            # The shell body is constant and all path/data values are arguments.
            path = "/work/state/" + fixture["path"]
            setup = bounded_command([
                "docker", "exec", "-i", "--user", "0:0", name, "/bin/sh", "-c",
                'mkdir -p -- "$(dirname -- "$1")" && cat > "$1" && chmod 0444 "$1"', "_", path,
            ], payload=fixtures[key].encode())
            if setup.returncode:
                raise ReplayError("fixture setup failed")
        yield DockerLab(name, contract, fixtures)
    finally:
        # Killing docker exec is not sufficient to terminate a victim process.
        # Always remove the whole lab, including timeout/output-limit failures.
        bounded_command(["docker", "rm", "--force", name], timeout=30)


def _control_input(value: object, fixtures: dict[str, str]) -> object:
    if isinstance(value, dict):
        if set(value) == {"$fixture"}:
            if value["$fixture"] not in fixtures:
                raise ContractError("control refers to an unknown fixture")
            return fixtures[value["$fixture"]]
        return {k: _control_input(v, fixtures) for k, v in value.items()}
    if isinstance(value, list):
        return [_control_input(v, fixtures) for v in value]
    return value


def _json_pointer(value: object, pointer: str) -> object:
    if not pointer:
        return value
    if not pointer.startswith("/"):
        raise ReplayError("JSON pointer must be empty or absolute")
    for part in pointer[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        try:
            value = value[int(part)] if isinstance(value, list) else value[part]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ReplayError("observed response is missing the configured JSON field") from exc
    return value


def observe(lab: DockerLab, steps: list[dict], oracle: dict, *, control: bool = False) -> tuple[bool, object]:
    events = {}
    for step in steps:
        value = _control_input(step["input"], lab.fixtures) if control else step["input"]
        events[step["entry"]] = lab.execute(step["entry"], value)
    source = oracle["observe"]
    if source["kind"] == "file":
        value = lab.read(source["path"]).decode("utf-8", errors="strict")
    else:
        event = events.get(source["entry"])
        if event is None:
            raise ReplayError("scenario never invoked the observed entry")
        if source["kind"] == "exit_code":
            value = event.returncode
        elif source["kind"] == "duration_ms":
            value = event.duration_ms
        else:
            if event.returncode:
                raise ReplayError("entry failed before producing a valid response")
            value = getattr(event, source["channel"]).decode("utf-8", errors="strict")
            if "pointer" in source:
                try:
                    value = _json_pointer(json.loads(value), source["pointer"])
                except (ValueError, RecursionError) as exc:
                    raise ReplayError("response is not valid bounded JSON") from exc
    predicate = oracle["predicate"]
    op = predicate["op"]
    if op == "contains_canary":
        matched = isinstance(value, str) and lab.fixtures[predicate["fixture"]] in value
    elif op == "equals":
        matched = type(value) is type(predicate["value"]) and value == predicate["value"]
    elif op == "not_equals":
        matched = type(value) is not type(predicate["value"]) or value != predicate["value"]
    elif op == "contains":
        expected = predicate["value"]
        matched = isinstance(value, str) and isinstance(expected, str) and expected in value
    elif op in {"gt", "gte"}:
        if type(value) not in {int, float} or not math.isfinite(value):
            raise ReplayError("numeric observation is unavailable")
        matched = value > predicate["value"] if op == "gt" else value >= predicate["value"]
    else:
        raise UnsupportedReplay(f"unsupported predicate {op}")
    return matched, value


def replay(scenario: dict, contract: dict, image: str) -> dict:
    """Freeze inputs, run every scheduled trial, reset between controls/attacks."""
    contract = validate_target(contract)
    scenario = validate_scenario(scenario, contract)
    image_id = image_identity(image)
    oracle = contract["oracles"].get(scenario["oracle"])
    scopes = {contract["entries"][s["entry"]]["scope"] for s in scenario["steps"]}
    scope = ("component" if "component" in scopes or "static_path" in scopes
             else "full_chain" if len(scenario["steps"]) > 1 else "shipping_entrypoint")
    evidence = {
        "schema_version": 1, "profile": "ai-agent", "scenario_digest": digest(scenario),
        "contract_digest": digest(contract), "artifact": {
            "image": image_id, "configuration": digest(contract["artifact"]),
            "source_commit": contract["artifact"]["source_commit"], "platform": contract["artifact"]["platform"],
        }, "mode": scenario["mode"], "scope": scope,
        "oracle": scenario["oracle"], "invariant": scenario["finding"]["invariant"],
        "collector": {"name": "docker-external-observer", "version": COLLECTOR_VERSION,
                      "boundary": "orchestrator captures victim output; credentials and evaluator outside victim"},
        "observations": [], "controls": [], "trials": [],
        "scheduled_trials": contract["runtime"]["trials"], "discovery_attempts": None,
        "coverage": [], "notes": ["Existence and reliability are separate; finite negatives are not immunity."],
    }
    for index in range(evidence["scheduled_trials"]):
        trial_id = f"trial-{index:03d}"
        start = time.monotonic()
        trial = {"id": trial_id, "status": "completed", "violation": None,
                 "duration_ms": 0, "error": None, "observation_ids": []}
        if contract["runtime"].get("model"):
            trial["model"] = contract["runtime"]["model"]
        try:
            if oracle is None or oracle["invariant"] != scenario["finding"]["invariant"]:
                raise UnsupportedReplay("new oracle/invariant needs a reviewed observation adapter")
            for control in contract["controls"]:
                with victim_lab(image_id, contract) as lab:
                    matched, _ = observe(lab, control["steps"], contract["oracles"][control["oracle"]], control=True)
                passed = matched == control["expect"]
                evidence["controls"].append({"id": control["id"], "trial_id": trial_id,
                    "kind": control["kind"], "passed": passed, "detail": f"expected={control['expect']}; observed={matched}"})
                if not passed:
                    raise ReplayError(f"control {control['id']} failed")
            with victim_lab(image_id, contract) as lab:
                matched, value = observe(lab, scenario["steps"], oracle)
            observation_id = f"observation-{index:03d}"
            evidence["observations"].append({"id": observation_id, "trial_id": trial_id,
                "source": json.dumps(oracle["observe"], sort_keys=True), "kind": oracle["observe"]["kind"],
                "value": value, "value_digest": digest(value), "matched": matched,
                "detail": "Predicate evaluated by independent collector against freshly initialized target"})
            trial["observation_ids"] = [observation_id]
            trial["violation"] = matched
        except (ReplayError, ContractError, UnicodeError, OSError) as exc:
            trial.update(status="unsupported" if isinstance(exc, UnsupportedReplay) else "infrastructure_error",
                         violation=None, error=str(exc))
        trial["duration_ms"] = (time.monotonic() - start) * 1000
        evidence["trials"].append(trial)
    evidence["coverage"] = [{"surface": scenario["path"]["entry"], "state": "partial",
                            "reason": "Only the frozen scenario, declared controls and scheduled trials were exercised"}]
    return validate_evidence(evidence, scenario, contract)
