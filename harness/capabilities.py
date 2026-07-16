# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Machine-readable target capabilities — the §9 routing table.

The `threat-model` skill inventories a target's *shape* into `THREAT_MODEL.md`
§9 (prose) AND `capabilities.json` (this module's input). Each capability
(`present ∈ yes|no|test_only|partial` + evidence) gates which *specialized*
checks the downstream stages turn on — so a pure-Rust library gets no FFI-ABI
fuzz, a single-threaded target gets no TSan, and every skip carries a paper
trail (§9 says `no`, here's the grep that proved it).

`capabilities.md` is the human contract; this file is the machine one. The
`_GATES` table below is the code twin of that doc's gating matrix, so a stage
can route programmatically instead of a reviewer reading the table by hand
(which is where the rust-mizan mis-route happened — a blind-fuzz pass burned on
a soundness-dominated corpus before someone noticed Miri was the apt stage).

One axis is not a capability but a *ranking* signal: `reachable_from_public_api`.
An `unreachable-as-extracted` finding (rust-mizan 0013/0018/0028/0040 — real code,
but no public entry drives it) should be DOWN-RANKED before fuzz time is spent,
not gated in or out. `gates_for()` returns None for it; read it via
`CapabilityInventory.reachable_from_public_api()`.

JSON shape (see `.claude/skills/threat-model/schema.md` §9):

    {
      "capabilities": {
        "untrusted_deserialization": {"present": "yes", "evidence": "serde derive on wire types"},
        "inbound_c_abi":             {"present": "no",  "evidence": "grep extern \\"C\\" empty"},
        ...
      },
      "reachable_from_public_api":    {"present": "yes", "evidence": "lib.rs re-exports parse()"}
    }
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── controlled vocabulary ────────────────────────────────────────────────────
# Capability keys (the gate table). Extend as the corpus grows — an unknown key
# is tolerated (kept, treated as active if present!=no) but has no _GATES row,
# so it enables nothing until a mapping is added here.
CAPABILITY_KEYS: frozenset[str] = frozenset({
    "inbound_c_abi",
    "outbound_ffi",
    "concurrency_async",
    "untrusted_deserialization",
    "multi_tenant_authz",
    "unsafe_simd",
    "unsafe_trait_trust",
    "unsafe_generic_soundness",
    "network_protocol_parser",
    "subprocess_exec",
    "crypto_secrets",
})

# Ranking axes — NOT capabilities. Present in the same file, read differently:
# they down-rank a finding, they don't gate a check on/off.
ROUTING_AXES: frozenset[str] = frozenset({"reachable_from_public_api"})

PRESENT_VALUES: frozenset[str] = frozenset({"yes", "no", "test_only", "partial"})

# A capability is "active" (its checks run) when present is any of these — i.e.
# anything but `no`. `test_only`/`partial` run but rank as latent hardening.
_ACTIVE_PRESENT: frozenset[str] = frozenset({"yes", "test_only", "partial"})


@dataclass(frozen=True)
class CapabilityGate:
    """What one capability turns on, per stage — the code twin of the
    `capabilities.md` gating matrix row."""
    capability: str
    scan_sections: tuple[str, ...]   # scan-extras.txt sections `find` appends
    detector: str                    # primary crash oracle (human label)
    sanitizer: str                   # reattack sanitizer: asan|msan|miri|tsan|compile_proof|none
    fuzz_rung: str                   # concrete fuzzing rung (find-to-fuzz dispatch hint)
    triage_rules: tuple[str, ...]    # most-relevant fp-rules for triage


# The gating matrix, machine form. Section refs match profiles/rust/scan-extras.txt;
# sanitizer/fuzz_rung feed find_to_fuzz.dispatch(); triage_rules match fp-rules.txt.
_GATES: dict[str, CapabilityGate] = {
    "inbound_c_abi": CapabilityGate(
        "inbound_c_abi", ("§7",), "guard-page + ASan", "asan",
        "stage2_ffi_abi", ("R2",)),
    "outbound_ffi": CapabilityGate(
        "outbound_ffi", ("§7",), "ASan", "asan",
        "ffi_asan", ("R2",)),
    "concurrency_async": CapabilityGate(
        "concurrency_async", ("§8",), "TSan / loom", "tsan",
        "loom_cancellation", ("R8", "R9")),
    "untrusted_deserialization": CapabilityGate(
        "untrusted_deserialization", (), "ASan + hang-timeout", "asan",
        "blind+structured_arbitrary", ("R1", "R7")),
    "multi_tenant_authz": CapabilityGate(
        "multi_tenant_authz", ("§6",), "logic (no memory oracle)", "none",
        "none", ("R2",)),
    "unsafe_simd": CapabilityGate(
        "unsafe_simd", ("§2",), "Miri", "miri",
        "libfuzzer_unsafe_entry", ("R1", "R9")),
    "unsafe_trait_trust": CapabilityGate(
        "unsafe_trait_trust", ("§2",), "Miri (UB oracle)", "miri",
        "adversarial_trait_impl", ("R8", "R10")),
    "unsafe_generic_soundness": CapabilityGate(
        "unsafe_generic_soundness", ("§8",), "Miri (multi-thread) / compile-proof", "miri",
        "adversarial_cross_thread_send", ("R8", "R9")),
    "network_protocol_parser": CapabilityGate(
        "network_protocol_parser", ("§9",), "differential", "asan",
        "differential_vs_reference", ("R7",)),
    "subprocess_exec": CapabilityGate(
        "subprocess_exec", ("§5",), "ASan", "asan",
        "path_zipslip_corpus", ("R2",)),
    "crypto_secrets": CapabilityGate(
        "crypto_secrets", ("§10",), "logic (constant-time / leak)", "none",
        "none", ("R2",)),
}


def gates_for(capability: str) -> CapabilityGate | None:
    """The checks a capability enables, or None for a routing axis / unknown key
    (a key with no gating row enables nothing — see CAPABILITY_KEYS note)."""
    return _GATES.get(capability)


# ── per-class vote budgeting (P1.3) ──────────────────────────────────────────
# Route the union-of-N budget by capability. The high-variance Rudra classes
# (raw-unsafe / trait-trust / generic-soundness) swung 2..8/11 across identical
# runs (L13) — they need MORE votes to surface the tail. The plain-parser / panic
# / race / uninit / leak classes had single-run recall already ~3/3, so 3 votes
# is enough and 8 is waste. Absent/unknown → the measured elbow, 5.
DEFAULT_VOTE_BUDGET = 5
_HIGH_VARIANCE = 8    # raw-unsafe / soundness — the Rudra tail lives in the votes
_STABLE = 3           # single-run recall already strong

_VOTE_BUDGET: dict[str, int] = {
    "unsafe_trait_trust": _HIGH_VARIANCE,
    "unsafe_generic_soundness": _HIGH_VARIANCE,
    "unsafe_simd": _HIGH_VARIANCE,
    "inbound_c_abi": _HIGH_VARIANCE,          # new hand-written unsafe ptr/len/lifecycle
    "untrusted_deserialization": _STABLE,
    "network_protocol_parser": _STABLE,
    "subprocess_exec": _STABLE,
    "multi_tenant_authz": _STABLE,
    "concurrency_async": _STABLE,             # races/uninit/leaks were 3/3
    "crypto_secrets": _STABLE,
    "outbound_ffi": DEFAULT_VOTE_BUDGET,
}


def vote_budget(capability: str) -> int:
    """N (number of union-of-N find runs) this capability calls for."""
    return _VOTE_BUDGET.get(capability, DEFAULT_VOTE_BUDGET)


class CapabilityError(ValueError):
    """Malformed capabilities.json — a machine file the pipeline reads, so a bad
    `present` value fails loud rather than silently mis-routing."""


@dataclass(frozen=True)
class CapabilityInventory:
    """Parsed capabilities.json. `caps` maps capability → (present, evidence);
    `axes` holds the ranking axes (reachable_from_public_api) the same way."""
    caps: dict[str, tuple[str, str]] = field(default_factory=dict)
    axes: dict[str, tuple[str, str]] = field(default_factory=dict)

    # ── queries a stage asks ──────────────────────────────────────────────────
    def present(self, capability: str) -> str:
        """`present` value, or 'no' if the capability is absent (absence ==
        deliberate skip — the §9 default)."""
        return self.caps.get(capability, ("no", "absent from §9"))[0]

    def evidence(self, capability: str) -> str:
        return self.caps.get(capability, ("no", "absent from §9"))[1]

    def is_active(self, capability: str) -> bool:
        """True when the capability's specialized checks should run (present !=
        no). Unknown-but-present keys are active too (forward-compatible)."""
        return self.present(capability) in _ACTIVE_PRESENT

    def active_capabilities(self) -> list[str]:
        return sorted(c for c in self.caps if self.is_active(c))

    def active_gates(self) -> list[CapabilityGate]:
        """Gates for every active capability that has a mapping — the stage's
        to-do list. Active capabilities with no _GATES row are omitted here but
        still visible via active_capabilities()."""
        out = [gates_for(c) for c in self.active_capabilities()]
        return [g for g in out if g is not None]

    def skips(self) -> list[tuple[str, str]]:
        """(capability, evidence) for every present==no capability — the paper
        trail. A stage logs these as evidenced skips, not silent omissions."""
        return [(c, self.evidence(c)) for c in sorted(self.caps)
                if self.present(c) == "no"]

    def reachable_from_public_api(self) -> str:
        """'yes' | 'no' | 'unknown'. 'no' → down-rank the finding before fuzz
        time (the unreachable-as-extracted case). Absence == 'unknown', NOT
        'no': we only down-rank on an explicit, evidenced call."""
        return self.axes.get("reachable_from_public_api", ("unknown", ""))[0]

    def sanitizers(self) -> list[str]:
        """Distinct reattack sanitizers the active capabilities call for — the
        Tamm execution matrix this target actually needs (drops 'none')."""
        seen: list[str] = []
        for g in self.active_gates():
            if g.sanitizer != "none" and g.sanitizer not in seen:
                seen.append(g.sanitizer)
        return seen

    def scan_sections(self) -> list[str]:
        """Union of scan-extras sections `find` should append for this target."""
        seen: list[str] = []
        for g in self.active_gates():
            for s in g.scan_sections:
                if s not in seen:
                    seen.append(s)
        return seen

    def vote_budget(self) -> int:
        """The union-of-N budget this target calls for — the MAX over its active
        capabilities (route to the most-variance-demanding class present). No
        active capability → the default elbow (5)."""
        active = self.active_capabilities()
        if not active:
            return DEFAULT_VOTE_BUDGET
        return max(vote_budget(c) for c in active)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capabilities": {c: {"present": p, "evidence": e}
                             for c, (p, e) in sorted(self.caps.items())},
            **{axis: {"present": p, "evidence": e}
               for axis, (p, e) in sorted(self.axes.items())},
        }


def _coerce_entry(key: str, raw: Any) -> tuple[str, str]:
    """Normalize one {"present":..,"evidence":..} entry; validate present."""
    if isinstance(raw, str):          # shorthand: "yes" == {"present":"yes"}
        raw = {"present": raw}
    if not isinstance(raw, dict):
        raise CapabilityError(f"{key!r}: expected object or string, got {type(raw).__name__}")
    present = raw.get("present", "no")
    evidence = raw.get("evidence", "")
    # Axes use yes|no|unknown; capabilities use the 4-value vocab. Validate against
    # the union so one parser handles both, but keep the distinction downstream.
    if present not in (PRESENT_VALUES | {"unknown"}):
        raise CapabilityError(
            f"{key!r}: present={present!r} not in {sorted(PRESENT_VALUES | {'unknown'})}")
    return (present, str(evidence))


def from_dict(d: dict[str, Any]) -> CapabilityInventory:
    """Build an inventory from parsed JSON. Tolerant of two layouts: a nested
    {"capabilities": {...}} block, or a flat top-level map of capability→entry.
    Routing axes (reachable_from_public_api) are split out of either layout."""
    if not isinstance(d, dict):
        raise CapabilityError(f"top level must be an object, got {type(d).__name__}")

    raw_caps = d.get("capabilities")
    if raw_caps is None:
        # Flat layout: every top-level key that isn't an axis is a capability.
        raw_caps = {k: v for k, v in d.items() if k not in ROUTING_AXES}
    if not isinstance(raw_caps, dict):
        raise CapabilityError("'capabilities' must be an object")

    caps: dict[str, tuple[str, str]] = {}
    for k, v in raw_caps.items():
        if k in ROUTING_AXES:          # tolerate an axis nested under capabilities
            continue
        caps[k] = _coerce_entry(k, v)

    axes: dict[str, tuple[str, str]] = {}
    for axis in ROUTING_AXES:
        if axis in d:
            axes[axis] = _coerce_entry(axis, d[axis])
        elif isinstance(d.get("capabilities"), dict) and axis in d["capabilities"]:
            axes[axis] = _coerce_entry(axis, d["capabilities"][axis])

    return CapabilityInventory(caps=caps, axes=axes)


def load(path: str | Path) -> CapabilityInventory:
    """Read + parse a capabilities.json. Raises CapabilityError on missing file
    or malformed content — a stage that asked for capability routing wants to
    know the file is bad, not silently run un-gated."""
    p = Path(path)
    try:
        raw = p.read_text()
    except OSError as e:
        raise CapabilityError(f"cannot read {p}: {e}") from e
    try:
        d = json.loads(raw)
    except json.JSONDecodeError as e:
        raise CapabilityError(f"{p}: invalid JSON: {e}") from e
    return from_dict(d)


def load_optional(path: str | Path | None) -> CapabilityInventory | None:
    """Like load(), but returns None if path is None or the file doesn't exist —
    for the additive/backward-compatible case (older targets have no §9 JSON)."""
    if path is None:
        return None
    if not Path(path).exists():
        return None
    return load(path)
