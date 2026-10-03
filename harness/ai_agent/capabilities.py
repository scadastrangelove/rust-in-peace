"""Routing hints for optional engines; never a taxonomy-shaped search gate."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .contracts import load, validate


@dataclass(frozen=True)
class EngineDecision:
    engine: str
    decision: str  # run | investigate | skip
    reasons: tuple[str, ...]


class Inventory:
    def __init__(self, data: dict):
        self.data = validate(data, "capabilities")

    @classmethod
    def load(cls, path: str | Path) -> Inventory:
        return cls(load(path, "capabilities"))

    def observation(self, capability: str) -> dict:
        return self.data["capabilities"].get(capability, {
            "state": "unknown", "scope": "not inventoried",
            "evidence": [], "collector": "none",
        }).copy()

    def route(self, engine: str, prerequisites: tuple[str, ...]) -> EngineDecision:
        absent, unknown = [], []
        for capability in prerequisites:
            observation = self.observation(capability)
            state = observation["state"]
            if state == "absent":
                absent.append(f"{capability}: absent within {observation['scope']}; "
                              + "; ".join(observation["evidence"]))
            elif state in {"unknown", "partial"}:
                unknown.append(f"{capability}: {state} within {observation['scope']}")
        if absent:
            return EngineDecision(engine, "skip", tuple(absent))
        if unknown:
            return EngineDecision(engine, "investigate", tuple(unknown))
        return EngineDecision(engine, "run", ())

    def research_queue(self, mapped: set[str] | None = None) -> list[dict]:
        mapped = mapped or set()
        queue = [{"capability": name, **self.observation(name),
                  "reason": "unmapped" if name not in mapped else "incomplete evidence"}
                 for name in sorted(self.data["capabilities"])
                 if name not in mapped or self.observation(name)["state"] in {"unknown", "partial"}]
        # General review exists even with an empty/entirely absent inventory.
        return [{"capability": "*", "state": "unknown",
                 "reason": "open-ended source, configuration and behavior review"}, *queue]

    def update(self, capability: str, observation: dict) -> Inventory:
        # A new inventory is a fresh routing input; no permanent skip cache.
        return Inventory({**self.data, "capabilities": {
            **self.data["capabilities"], capability: observation,
        }})
