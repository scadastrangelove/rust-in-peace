# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Build-profile gate (P0.1) — the detector's flags are part of the threat model.

Generalized from the lopdf campaign (LESSONS.md L10). The crash pipeline built
the target with detection-only instrumentation (`-C overflow-checks=on`); **all
five autonomous "crashes" were `panic_const_*_overflow` that do NOT reproduce
under the target's shipping release profile** (overflow-checks off — they wrap
silently). The grader re-ran each PoC against the *same instrumented* binary, so
it graded build-config artifacts as `real`, while the curated static triage
correctly called them overflow-checks-conditional. The human-in-the-loop was
more honest on severity than the autonomous grader.

The lesson is not Rust-specific. Every technology has a **detection build** that
diverges from the **shipping build**, and a set of crash CLASSES that manifest
only under the detection flags:

    profile   detection-only flags                    instrumentation-gated classes
    ────────  ──────────────────────────────────────  ──────────────────────────────
    rust      -C overflow-checks=on                    arithmetic overflow panics
              -C debug-assertions=on                   (add/sub/mul/shl with overflow)
    cpp        -fsanitize=undefined                    signed-integer-overflow,
              -D_GLIBCXX_ASSERTIONS                    shift-exponent, (UBSan-only reports)
    android-app (none — witnesses are static/dynamic,  (none)
               not instrumentation crashes)

So this module is the profile-agnostic twin of `witness.py`: a crash's
*disposition* is gated on whether its class is instrumentation-only for the
target's profile AND whether it was re-verified under the shipping build.

Contract, keyed on the profile name (the swappable noun), NOT on a per-finding
agent judgment — so an agent can't self-declare a real overflow "shipping-safe"
to skip the re-test, mirroring `witness.STATIC_TERMINAL_CLASSES`:

  * ``requires_shipping_reverify(profile, crash_class)`` — is this class
    instrumentation-gated for this profile? (→ the grade stage must re-verify
    under the shipping build before it may pass).
  * ``disposition(profile, crash_class, reproduced_under_shipping)`` — the
    triage disposition after that re-test: ``build_profile_gated`` (R7) when the
    class is gated and it did NOT reproduce shipping; ``confirmed`` otherwise.

Backward-compatible: a profile/class with no gated set (the default, and the
whole cpp memory-safety surface that ASan finds legitimately) always returns
``requires_shipping_reverify == False`` and passes straight through — existing
targets are untouched.
"""
from __future__ import annotations

from dataclasses import dataclass

# Disposition this gate can assign. Aligns with the fp-rule taxonomy (R7 =
# "only fires under a non-shipping build flag") and the union-of-N /
# witness DISPOSITION vocabulary in aggregate.py / witness.py.
DISP_BUILD_PROFILE_GATED = "build_profile_gated"   # R7 — not production-real as found
DISP_CONFIRMED = "confirmed"                        # reproduces under the shipping build


@dataclass(frozen=True)
class BuildProfile:
    """One build configuration of a target."""
    name: str
    flags: tuple[str, ...]
    note: str = ""


# ── the shipping-vs-detection registry, keyed by profile name ────────────────
# `detection` is what the crash pipeline builds under; `shipping` is the
# target's real release configuration a `real` verdict must survive.
_SHIPPING: dict[str, BuildProfile] = {
    "rust": BuildProfile(
        "rust-release",
        ("-C opt-level=3", "-C overflow-checks=off", "-C debug-assertions=off"),
        "cargo's default `[profile.release]` — overflow wraps, debug_assert! is out",
    ),
    "cpp": BuildProfile(
        "cpp-release",
        ("-O2", "-DNDEBUG"),
        "release build — no UBSan, assertions compiled out",
    ),
}
_DETECTION: dict[str, BuildProfile] = {
    "rust": BuildProfile(
        "rust-detect",
        ("-C overflow-checks=on", "-C debug-assertions=on"),
        "the fuzz/find detector build — arithmetic overflow panics instead of wrapping",
    ),
    "cpp": BuildProfile(
        "cpp-detect",
        ("-fsanitize=undefined,address", "-D_GLIBCXX_ASSERTIONS"),
        "ASan/UBSan detector build — UBSan flags legal-in-release signed overflow",
    ),
}

# Crash-class substrings that manifest ONLY under the detection flags for a
# profile — i.e. a crash of this class is a build-config artifact until it is
# re-reproduced under the shipping build. Matched case-insensitively as a
# substring of the crash_type / crash_output, so both a parsed class label
# ("arithmetic-overflow") and a raw panic line ("attempt to add with overflow",
# "panic_const_add_overflow") are covered.
_INSTRUMENTATION_GATED: dict[str, frozenset[str]] = {
    "rust": frozenset({
        "arithmetic-overflow",
        "attempt to add with overflow",
        "attempt to subtract with overflow",
        "attempt to multiply with overflow",
        "attempt to negate with overflow",
        "attempt to shift left with overflow",
        "attempt to shift right with overflow",
        "attempt to divide with overflow",
        "panic_const_add_overflow",
        "panic_const_sub_overflow",
        "panic_const_mul_overflow",
        # NB: index-out-of-bounds / unwrap / slice panics are NOT here — those
        # abort under the shipping build too, so they pass straight through.
    }),
    "cpp": frozenset({
        "signed-integer-overflow",
        "shift-exponent",
        "implicit-conversion",
        # NB: heap-buffer-overflow / use-after-free / etc. are NOT here — ASan
        # finds real memory bugs present in the shipping build.
    }),
    # android-app: no instrumentation-gated crash classes (its evidence is a
    # static/dynamic witness, not a build-flag crash). Absent ⇒ empty set.
}


def shipping_profile(profile_name: str | None) -> BuildProfile | None:
    return _SHIPPING.get(profile_name or "")


def detection_profile(profile_name: str | None) -> BuildProfile | None:
    return _DETECTION.get(profile_name or "")


def instrumentation_gated_classes(profile_name: str | None) -> frozenset[str]:
    return _INSTRUMENTATION_GATED.get(profile_name or "", frozenset())


def requires_shipping_reverify(profile_name: str | None, crash_signal: str) -> bool:
    """True when ``crash_signal`` (a crash_type label or raw crash_output) names
    a class that only manifests under the detection build for this profile — so
    the grade stage MUST re-verify it under the shipping build before it may be
    graded ``real``. Case-insensitive substring match; empty/None never gates."""
    if not crash_signal:
        return False
    hay = crash_signal.lower()
    return any(marker in hay for marker in instrumentation_gated_classes(profile_name))


def disposition(
    profile_name: str | None,
    crash_signal: str,
    reproduced_under_shipping: bool | None,
) -> str:
    """Triage disposition for a crash after the shipping re-test.

    * class is instrumentation-gated AND ``reproduced_under_shipping`` is False
      (or None == "not re-tested") → ``build_profile_gated`` (R7): NOT
      production-real as found; the L10 downgrade.
    * otherwise → ``confirmed`` (a non-gated class, or one that DID reproduce
      under the shipping build — a genuine bug).
    """
    if requires_shipping_reverify(profile_name, crash_signal) and not reproduced_under_shipping:
        return DISP_BUILD_PROFILE_GATED
    return DISP_CONFIRMED


def reverify_command_hint(profile_name: str | None) -> str:
    """A copy-pasteable hint for how to build the shipping profile for the
    re-test — surfaced to the grader/operator, not executed here (the concrete
    build is per-target)."""
    sp = shipping_profile(profile_name)
    if sp is None:
        return "(no shipping-profile mapping for this profile — re-test under the target's release build)"
    return f"rebuild under {sp.name} [{' '.join(sp.flags)}] — {sp.note}"
