# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Pipeline profiles — the swappable-noun registry.

A *profile* bundles the language/detector-specific pieces the generic
orchestration (find/grade/judge/report/patch/dedup) resolves at run time:
the find prompt, the crash detector (stack-frame + crash-class parsing), and
the grade/judge/report/patch prompt builders.

`cpp` is the original C/C++ + AddressSanitizer pipeline, unchanged. `rust` is
the Rust-security fork (Miri UB / sanitizer OOB / panic-DoS / hang), forking the
pieces whose behavior differs and reusing the rest.

Each stage does:  `profile = get_profile(target.profile)` then
`profile.build_find_prompt(...)` / `profile.detector.top_frame(...)` / etc.
The default is `cpp`, so existing targets keep working with no config change.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from types import ModuleType
from typing import Callable

# --- base (C/C++ / ASAN) pieces ------------------------------------------
from . import asan as _asan
from .prompts import find_prompt as _cpp_find
from .prompts import grade_prompt as _cpp_grade
from .prompts import judge_prompt as _cpp_judge
from .prompts import report_prompt as _cpp_report
from .prompts import patch_prompt as _cpp_patch

# --- rust pieces ---------------------------------------------------------
from .rust import find_prompt as _rs_find
from .rust import detect as _rs_detect
from .rust import grade_prompt as _rs_grade
from .rust import judge_prompt as _rs_judge
from .rust import report_prompt as _rs_report
from .rust import patch_prompt as _rs_patch
from .rust import find_to_fuzz as _rs_reattack


@dataclass(frozen=True)
class Profile:
    """Everything the generic pipeline needs that varies by language/detector.

    `detector` is a module exposing the asan.py surface:
    `project_frames`, `top_frame`, `crash_reason`, `asan_excerpt`.
    """
    name: str
    detector: ModuleType
    build_find_prompt: Callable[..., str]
    build_grade_prompt: Callable[..., str]
    build_judge_prompt: Callable[..., str]
    build_compare_prompt: Callable[..., str]
    build_report_prompt: Callable[..., str]
    build_patch_prompt: Callable[..., str]
    build_style_judge_prompt: Callable[..., str]
    # find→fuzz reattack binder (P0.2). None → this profile has no dispatch-based
    # reattack stage and uses the static `config.reattack_harness` script instead
    # (cpp's model). rust wires find_to_fuzz.build_reattack.
    build_reattack: Callable[..., str] | None = None


_CPP = Profile(
    name="cpp",
    detector=_asan,
    build_find_prompt=_cpp_find.build_find_prompt,
    build_grade_prompt=_cpp_grade.build_grade_prompt,
    build_judge_prompt=_cpp_judge.build_judge_prompt,
    build_compare_prompt=_cpp_judge.build_compare_prompt,
    build_report_prompt=_cpp_report.build_report_prompt,
    build_patch_prompt=_cpp_patch.build_patch_prompt,
    build_style_judge_prompt=_cpp_patch.build_style_judge_prompt,
)

_RUST = Profile(
    name="rust",
    detector=_rs_detect,
    build_find_prompt=_rs_find.build_find_prompt,
    build_grade_prompt=_rs_grade.build_grade_prompt,
    build_judge_prompt=_rs_judge.build_judge_prompt,
    build_compare_prompt=_rs_judge.build_compare_prompt,  # language-agnostic (report vs report)
    build_report_prompt=_rs_report.build_report_prompt,   # Rust primitive taxonomy + trust boundary
    build_patch_prompt=_rs_patch.build_patch_prompt,      # *.rs diff + parse-time-validation guidance
    build_style_judge_prompt=_rs_patch.build_style_judge_prompt,  # re-export of the base (language-agnostic)
    build_reattack=_rs_reattack.build_reattack,           # dispatch(cwe/cap)→template→bind→validate
)

_REGISTRY: dict[str, Profile] = {"cpp": _CPP, "rust": _RUST}


def get_profile(name: str | None) -> Profile:
    """Resolve a profile by name. `None`/empty → cpp (backward-compatible)."""
    if not name:
        return _CPP
    try:
        return _REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY))
        raise ValueError(f"unknown profile {name!r}; known profiles: {known}")


def known_profiles() -> list[str]:
    return sorted(_REGISTRY)


# --- content autodetect for post-hoc dedup across mixed/unknown results ---
_RS_FRAME_HINT = re.compile(r"^\s*\d+:\s+\S+::", re.MULTILINE)


def detector_for_output(crash_output: str) -> ModuleType:
    """Pick a detector by sniffing the crash text — for `vuln-pipeline dedup`,
    which walks result.json files that may span profiles and carries no single
    target. Rust markers → rust_detect; otherwise the ASAN parser (its
    assertion/summary regex also covers non-ASAN C crashes)."""
    t = crash_output or ""
    if "panicked at" in t or "error: Undefined Behavior:" in t or _RS_FRAME_HINT.search(t):
        return _rs_detect
    return _asan
