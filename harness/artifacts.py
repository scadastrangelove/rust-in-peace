# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Data contracts for the find→grade pipeline.

CrashArtifact is the pivot: find emits it, grade consumes it.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(frozen=True)
class CrashArtifact:
    """A crash the find-agent claims to have produced. Not yet verified."""
    poc_path: str              # path inside the find-container, e.g. /tmp/poc.bin
    poc_bytes: bytes           # PoC file contents — bytes, inputs are often binary
    reproduction_command: str  # exact command, e.g. "/work/entry /tmp/poc.bin"
    crash_type: str            # agent's classification, e.g. "heap-buffer-overflow"
    crash_output: str          # ASAN trace / stderr, truncated to 10K chars
    exit_code: int             # e.g. 134 (SIGABRT from ASAN)
    dup_check: str | None = None  # agent's reasoning that this isn't a known dup

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["poc_bytes"] = base64.b64encode(self.poc_bytes).decode("ascii")
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CrashArtifact:
        return cls(
            poc_path=d["poc_path"],
            poc_bytes=base64.b64decode(d["poc_bytes"]),
            reproduction_command=d["reproduction_command"],
            crash_type=d["crash_type"],
            crash_output=d["crash_output"],
            exit_code=d["exit_code"],
            dup_check=d.get("dup_check"),
        )


@dataclass
class GraderVerdict:
    """The grade-agent's judgment of a CrashArtifact."""
    passed: bool
    score: float               # 0.0–1.0
    criteria: dict[str, bool]  # {"criterion_1": True, ..., "criterion_5": True}
    evidence: str              # grader's summary

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> GraderVerdict:
        return cls(
            passed=d["passed"],
            score=d["score"],
            criteria=d["criteria"],
            evidence=d["evidence"],
        )


@dataclass
class PatchVerdict:
    """T0-T3 ladder result for a candidate patch. Every gating tier is an
    executable oracle (compiler/ASAN/tests); T3 is advisory-only."""
    t0_builds: bool
    t1_poc_stops: bool
    t2_tests_pass: bool | None     # None = target has no test suite
    re_attack_clean: bool | None   # None = re-attack not run (--no-reattack)
    t3_style_score: float | None   # 0-10, None when style judge not run
    evidence: dict[str, str]       # per-tier stdout/stderr excerpts
    timings: dict[str, float]

    @property
    def passed(self) -> bool:
        return (
            self.t0_builds
            and self.t1_poc_stops
            and self.t2_tests_pass is not False
            and self.re_attack_clean is not False
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["passed"] = self.passed
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PatchVerdict:
        return cls(
            t0_builds=d["t0_builds"],
            t1_poc_stops=d["t1_poc_stops"],
            t2_tests_pass=d["t2_tests_pass"],
            re_attack_clean=d["re_attack_clean"],
            t3_style_score=d.get("t3_style_score"),
            evidence=d.get("evidence", {}),
            timings=d.get("timings", {}),
        )


@dataclass
class JudgeVerdict:
    """The judge-agent's call on whether a new crash warrants a report."""
    judgment: str              # NEW, DUP_BETTER, DUP_SKIP
    bug_id: int | None         # which existing bug it matches (required for DUP_*)
    reasoning: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> JudgeVerdict:
        return cls(
            judgment=d["judgment"],
            bug_id=d.get("bug_id"),
            reasoning=d.get("reasoning", ""),
        )


@dataclass
class ReportVerdict:
    """The report-agent's exploitability analysis of a verified crash."""
    section_scores: dict[str, int]  # primitive, reachability, heap_layout, escalation_path, constraints → 0/1/2
    rubric_score: int               # sum of section scores, 0..10
    escalation_bonus: int           # 0..4 for escalation_attempt depth
    total_score: float              # (rubric + bonus) / 14
    severity_rating: str            # agent's CRITICAL/HIGH/MEDIUM/LOW/NOT-A-BUG/NOT_STATED
    novelty_status: str             # FIXED/UNFIXED/UNKNOWN/NOT_CHECKED
    reachability_verdict: str       # REACHABLE/HARNESS_ONLY/UNCLEAR

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ReportVerdict:
        return cls(
            section_scores=d["section_scores"],
            rubric_score=d["rubric_score"],
            escalation_bonus=d["escalation_bonus"],
            total_score=d["total_score"],
            severity_rating=d["severity_rating"],
            novelty_status=d["novelty_status"],
            reachability_verdict=d["reachability_verdict"],
        )


@dataclass
class MaintainerReviewVerdict:
    """The adversarial maintainer-review agent's (P1.3, LESSONS.md L13) verdict
    on a finding + its proposed fix — the pre-disclosure gate."""
    verdict: str               # ACCEPT, DOWNGRADE, REJECT, WONTFIX
    corrected_severity: str    # CRITICAL, HIGH, MEDIUM, LOW, INFO
    reachability: str          # REACHABLE, CONSTRUCTION_ONLY, UNCLEAR
    fix_ok: bool
    fix_problem: str
    rebuttals: str
    one_line: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MaintainerReviewVerdict:
        return cls(
            verdict=d["verdict"],
            corrected_severity=d["corrected_severity"],
            reachability=d["reachability"],
            fix_ok=d["fix_ok"],
            fix_problem=d.get("fix_problem", "-"),
            rebuttals=d.get("rebuttals", ""),
            one_line=d.get("one_line", ""),
        )


@dataclass
class RunResult:
    """One end-to-end run's outcome."""
    target: str
    status: str                     # crash_found, no_crash_found, crash_rejected, agent_failed, build_failed, error
    crash: CrashArtifact | None
    verdict: GraderVerdict | None
    find_transcript: list[dict] = field(default_factory=list)
    grade_transcript: list[dict] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "status": self.status,
            "crash": self.crash.to_dict() if self.crash else None,
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "find_transcript": self.find_transcript,
            "grade_transcript": self.grade_transcript,
            "timings": self.timings,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RunResult:
        return cls(
            target=d["target"],
            status=d["status"],
            crash=CrashArtifact.from_dict(d["crash"]) if d.get("crash") else None,
            verdict=GraderVerdict.from_dict(d["verdict"]) if d.get("verdict") else None,
            find_transcript=d.get("find_transcript", []),
            grade_transcript=d.get("grade_transcript", []),
            timings=d.get("timings", {}),
            error=d.get("error"),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, s: str) -> RunResult:
        return cls.from_dict(json.loads(s))


# ── find→fuzz reattack (P0.2) ────────────────────────────────────────────────
# Fixed residual vocabulary: a non-reproduction is a capability/sanitizer-fit
# map, never a bare "0 bugs" (find-to-fuzz.md §5). A `clean` verdict without a
# residual_reason is rejected by the scorecard — force characterization.
RESIDUAL_REASONS = (
    "reproduced",              # not a residual — the harness crashed as intended
    "grammar-gated",           # deep-structure parser; blind+coverage miss → grammar/dict rung
    "address-space-only",      # real defect but only at >4 GiB / 32-bit — out of 64-bit fuzz scope
    "asan-on-C",               # format-string / FFI into un-instrumented C — needs ASan-compiled dep
    "needs-MSan",              # uninitialized read — ASan is blind to it, rerun under MSan
    "unreachable-as-extracted",# no public entry drives the sink (reachable_from_public_api: no)
    "build-failed",            # harness never compiled within the retry budget (agent API error)
    "uncharacterized",         # clean but reason not yet established — MUST be replaced before ship
)


@dataclass(frozen=True)
class ReattackArtifact:
    """The find→fuzz bridge's output for one finding: the generated harness, the
    sanitizer it ran under, whether it reproduced, and — if not — the fixed-enum
    residual reason (find-to-fuzz.md §4/§5)."""
    finding_id: str            # stable id of the source finding (e.g. bug_03 / a signature)
    cwe: str                   # the CWE that drove dispatch (e.g. "CWE-125")
    template: str              # harness-templates/ skeleton chosen
    sanitizer: str             # asan|msan|miri|tsan|compile_proof|asan_on_c
    verdict: str               # "reproduced" | "clean" | "build_failed"
    residual_reason: str       # one of RESIDUAL_REASONS ("reproduced" iff verdict==reproduced)
    harness_path: str | None = None    # path to the generated fuzz harness (in results dir)
    crash_input: bytes | None = None   # the reproducing input, if any
    crash_output: str = ""     # detector trace / panic (truncated)
    build_attempts: int = 0    # compile retries the agent needed (compiler-as-oracle)
    detail: str = ""           # free-text: features enabled, wrapper fn found, etc.

    def __post_init__(self) -> None:
        if self.residual_reason not in RESIDUAL_REASONS:
            raise ValueError(
                f"residual_reason={self.residual_reason!r} not in {RESIDUAL_REASONS}")
        # Contract: a clean verdict must carry a real (non-'reproduced') residual —
        # "0 bugs found" without a reason is the exact lie §5 forbids.
        if self.verdict == "clean" and self.residual_reason == "reproduced":
            raise ValueError("clean verdict requires a residual_reason (§5)")
        if self.verdict == "reproduced" and self.residual_reason != "reproduced":
            raise ValueError("reproduced verdict must have residual_reason='reproduced'")

    @property
    def reproduced(self) -> bool:
        return self.verdict == "reproduced"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["crash_input"] = (base64.b64encode(self.crash_input).decode("ascii")
                            if self.crash_input is not None else None)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ReattackArtifact:
        ci = d.get("crash_input")
        return cls(
            finding_id=d["finding_id"], cwe=d["cwe"], template=d["template"],
            sanitizer=d["sanitizer"], verdict=d["verdict"],
            residual_reason=d["residual_reason"],
            harness_path=d.get("harness_path"),
            crash_input=base64.b64decode(ci) if ci else None,
            crash_output=d.get("crash_output", ""),
            build_attempts=d.get("build_attempts", 0),
            detail=d.get("detail", ""),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class RunScorecard:
    """Per-batch dynamic scorecard (P1.1). "0 bugs found" is forbidden output:
    every finding lists its reattack verdict + residual, and every §9 capability
    the run could not exercise is named under missing_capabilities."""
    target: str
    reattacks: list[ReattackArtifact] = field(default_factory=list)
    missing_capabilities: list[dict] = field(default_factory=list)  # [{capability, evidence, why_unexercised}]

    @property
    def reproduced(self) -> list[ReattackArtifact]:
        return [r for r in self.reattacks if r.reproduced]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "n_reattacks": len(self.reattacks),
            "n_reproduced": len(self.reproduced),
            "reattacks": [r.to_dict() for r in self.reattacks],
            "missing_capabilities": self.missing_capabilities,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RunScorecard:
        return cls(
            target=d["target"],
            reattacks=[ReattackArtifact.from_dict(r) for r in d.get("reattacks", [])],
            missing_capabilities=d.get("missing_capabilities", []),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
