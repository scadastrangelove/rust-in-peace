# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""SecurityWitness — the typed evidence a finding carries.

The base pipeline had one kind of evidence: a crash (PoC bytes + a sanitizer
trace, hard to fake — it reproduces or it doesn't). That works for any
technology whose bugs terminate in an executable crash (C/C++ → ASan; Rust →
Miri/panic/hang). It does not work for a technology whose bugs are logic /
configuration / platform issues with no crash oracle — which is most of the
Android application surface (exported IPC, WebView bridges, insecure storage,
cleartext, deeplink redirection over decompiled DEX, where there is no
recompile-with-instrumentation path).

This module generalizes *crash* to *witness* so those profiles can still ride
the find → grade → judge → report rail. A ``SecurityWitness`` has:

* **kind** — how the evidence was obtained;
* **strength** (1..4) — an explicit ordinal of *evidential rigor* (how hard the
  witness is to fabricate / how reproducible it is), consumed by the scorecard
  and the triage DISPOSITION gate;
* **severity** — impact, **orthogonal** to strength (a strength-4 native DoS
  panic can be LOW; a strength-3 token-exfil can be CRITICAL — so the honesty
  gate sorts on strength, the triage priority sorts on severity).

Design constraints this module honors (see docs/profiles/android/DECISIONS.md):

* **ADR-4 — explicit ranking.** A ``static_reachability`` witness is an
  *argument*, cheap to fabricate; without an explicit strength feeding the
  DISPOSITION gate, the "recall-first under a hard correctness gate" discipline
  silently erodes on weak-oracle classes. Strength is a first-class field.
* **Backward-compat is a hard requirement.** The cpp/rust case is
  ``native_crash`` / strength 4 and reduces to today's confirmed/contested
  behavior exactly. This module is **additive**: the core ``CrashArtifact`` wire
  format is unchanged. A witness is *carried inside* a ``CrashArtifact`` —
  ``crash_type`` is the finding class, and ``crash_output`` begins with a
  machine-parseable ``WITNESS:`` header this module reads back. ``native_crash``
  needs no header (absence ⇒ strength 4), so cpp/rust artifacts are untouched.
* **ADR-4 anti-gaming.** A strength-1 finding defaults to ``contested`` /
  needs-confirmation, *except* for a **declared** set of finding classes for
  which no stronger witness is obtainable (pure build-config checks). That set
  is ``STATIC_TERMINAL_CLASSES`` below — a property of the class id, NOT a
  per-finding agent judgment, so an agent can't self-declare a weak finding
  terminal to skip promotion.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ── controlled vocabulary ────────────────────────────────────────────────────
KIND_STATIC_REACHABILITY = "static_reachability"
KIND_DYNAMIC_OBSERVATION = "dynamic_observation"
KIND_NATIVE_CRASH = "native_crash"
WITNESS_KINDS: frozenset[str] = frozenset({
    KIND_STATIC_REACHABILITY, KIND_DYNAMIC_OBSERVATION, KIND_NATIVE_CRASH,
})

# dynamic_observation sub-fields (ADR-5: two cost tiers; ADR-4: three domains).
DYNAMIC_DOMAINS: frozenset[str] = frozenset({"behavior", "network", "storage"})
DYNAMIC_TIERS: frozenset[str] = frozenset({"light_adb", "heavy_instrumented"})

# Severity is orthogonal to strength — impact, not evidential rigor.
SEVERITIES: tuple[str, ...] = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def strength_of(kind: str, tier: str | None = None) -> int:
    """Evidential-rigor ordinal (1..4). Higher = harder to fabricate / more
    reproducible. This is what the scorecard/DISPOSITION gate consumes.

        1  static_reachability            — an argument, not an artifact
        2  dynamic_observation/light_adb  — observed via adb/am/logcat/run-as
        3  dynamic_observation/heavy_instrumented — observed via Frida/emulator
        4  native_crash                   — a reproducible crash (cpp/rust)
    """
    if kind == KIND_NATIVE_CRASH:
        return 4
    if kind == KIND_DYNAMIC_OBSERVATION:
        return 3 if tier == "heavy_instrumented" else 2
    if kind == KIND_STATIC_REACHABILITY:
        return 1
    raise ValueError(f"unknown witness kind {kind!r}; known: {sorted(WITNESS_KINDS)}")


# ── ADR-4 anti-gaming: the declared static-terminal class set ─────────────────
# Finding classes for which NO stronger witness than a static argument is
# obtainable — pure build/config properties that are fully visible in the
# manifest/decompile and have nothing to "dynamically observe" beyond what is
# already statically present. ONLY these may be dispositioned
# ``real_latent (static-argument)`` at strength 1; every other strength-1
# finding defaults to ``contested`` until promoted to strength ≥ 2.
#
# This is deliberately a small, closed set keyed on the finding CLASS id, not a
# per-finding agent judgment — so an agent cannot self-declare a weak
# reachability finding terminal to skip dynamic promotion.
STATIC_TERMINAL_CLASSES: frozenset[str] = frozenset({
    "android:missing-proguard",          # no code shrink/obfuscation configured
    "android:debuggable-flag",           # android:debuggable="true" in release
    "android:allow-backup",              # android:allowBackup="true"
    "android:cleartext-config",          # usesCleartextTraffic / permissive NSC
    "android:exported-no-permission",    # exported component w/o a permission gate
    "android:backup-no-rules",           # backup enabled, no full-backup-content rules
    "android:test-only-flag",            # android:testOnly="true"
})

# DISPOSITION values — align with the union-of-N layer's confirmed/contested
# (harness/aggregate.py). Strength is the tie-breaker the scorecard reports.
DISP_CONFIRMED = "confirmed"                 # strength ≥ 2 (observed) OR ≥2 votes
DISP_REAL_LATENT_STATIC = "real_latent_static_argument"  # strength 1, class is terminal
DISP_CONTESTED = "contested"                 # strength 1, wants dynamic promotion


def default_disposition(finding_class: str, strength: int) -> str:
    """The default triage disposition for a finding given its strongest witness.

    * strength ≥ 2 (any observed witness / native crash) → ``confirmed``.
    * strength 1 (static argument only):
        * class ∈ STATIC_TERMINAL_CLASSES → ``real_latent_static_argument``
          (separately tagged — never silently merged with observed findings);
        * otherwise → ``contested`` (needs dynamic promotion to strength ≥ 2).

    This is the honesty gate ADR-4 requires: an all-static (strength-1) result is
    a pile of *candidates*, and the scorecard must say so rather than reporting
    them as verified.
    """
    if strength >= 2:
        return DISP_CONFIRMED
    if finding_class in STATIC_TERMINAL_CLASSES:
        return DISP_REAL_LATENT_STATIC
    return DISP_CONTESTED


# ── the witness itself, and its wire header ──────────────────────────────────
@dataclass(frozen=True)
class SecurityWitness:
    """Typed evidence for one finding.

    ``native_crash`` is the degenerate case (strength 4, no domain/tier) that the
    cpp/rust profiles produce implicitly — they never write a WITNESS header, and
    ``parse`` returns this for headerless output.
    """
    kind: str
    strength: int
    severity: str = "MEDIUM"
    finding_class: str = ""              # e.g. "android:exported-activity-launch"
    domain: str | None = None            # dynamic_observation only
    tier: str | None = None              # dynamic_observation only

    @property
    def disposition(self) -> str:
        return default_disposition(self.finding_class, self.strength)

    def header(self) -> str:
        """The single machine-parseable line prepended to ``crash_output`` so the
        detector (and the scorecard) can read the witness back off a stored
        result.json without re-deriving it."""
        parts = [
            f"kind={self.kind}",
            f"strength={self.strength}",
            f"severity={self.severity}",
            f"class={self.finding_class or '-'}",
            f"domain={self.domain or '-'}",
            f"tier={self.tier or '-'}",
        ]
        return "WITNESS: " + " ".join(parts)


_HEADER = re.compile(r"^WITNESS:\s*(.+)$", re.MULTILINE)
_KV = re.compile(r"(\w+)=(\S+)")


def parse(text: str | None) -> SecurityWitness:
    """Read a witness back off oracle output.

    Headerless output (the cpp/rust case, and any raw crash) ⇒ a ``native_crash``
    witness at strength 4 — so this is safe to call on *any* crash_output and
    preserves today's behavior for the base profiles.
    """
    m = _HEADER.search(text or "")
    if not m:
        return SecurityWitness(kind=KIND_NATIVE_CRASH, strength=4)
    kv = dict(_KV.findall(m.group(1)))
    kind = kv.get("kind", KIND_NATIVE_CRASH)
    domain = kv.get("domain") if kv.get("domain", "-") != "-" else None
    tier = kv.get("tier") if kv.get("tier", "-") != "-" else None
    # Trust an explicit strength if present and sane; else derive from kind/tier.
    try:
        strength = int(kv.get("strength", ""))
    except ValueError:
        strength = strength_of(kind, tier) if kind in WITNESS_KINDS else 4
    severity = kv.get("severity", "MEDIUM").upper()
    if severity not in SEVERITIES:
        severity = "MEDIUM"
    return SecurityWitness(
        kind=kind,
        strength=strength,
        severity=severity,
        finding_class=kv.get("class", "") if kv.get("class", "-") != "-" else "",
        domain=domain,
        tier=tier,
    )
