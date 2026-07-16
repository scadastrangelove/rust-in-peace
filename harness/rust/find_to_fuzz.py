# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""find → fuzz bridge — the reattack stage for Rust.

A graded static finding (a CWE + a vulnerable fn/file/line, optionally a
DEFER-TO-DYNAMIC soundness sketch from find_prompt) becomes a *reproducing*
dynamic harness automatically. The split that works — validated by hand-building
22 harnesses against the rust-mizan CVE corpus (19/22 reproduced), then
harvesting them into `profiles/rust/find-to-fuzz.md`:

  1. dispatch(cwe, capability)  → (template, sanitizer)   deterministic, this file
  2. agent.bind(template, finding, crate) → working harness   program synthesis
  3. validate: `cargo +nightly fuzz build` + smoke run + replay  compiler = oracle

The determinism is in **dispatch and validation**, not generation. This module
owns steps 1 and 3 (pure/orchestration) and produces the step-2 *prompt*
(`build_reattack`, wired as `Profile.build_reattack`). The agent fills the holes
a table can't — private wrappers, `no_std` panic handlers, feature/cfg gates, the
L12 heap-owning-element trick — and the validator gates it.

A non-reproduction is a capability/sanitizer-fit map, not a failure (§5): the
`residual_reason` names the missing rung (grammar / MSan / ASan-on-C /
unreachable), which is the actionable output.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

from .. import docker_ops, sandbox
from ..agent import run_agent, parse_xml_tag, AgentResult
from ..artifacts import ReattackArtifact, RESIDUAL_REASONS
from ..config import TargetConfig

DEFAULT_REATTACK_MAX_TURNS = 400
SMOKE_SECONDS = 90          # cargo fuzz run -max_total_time (find-to-fuzz.md §4)
RSS_LIMIT_MB = 4096         # OOM cap (§3)

_TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "profiles" / "rust" / "harness-templates"

# Templates shipped in-repo today. dispatch() may route to a not-yet-shipped
# template (grammar_parser/threaded_driver — P1.2); build_reattack falls back to
# the nearest shipped skeleton + an inline note so the agent still has a base.
SHIPPED_TEMPLATES = frozenset({
    "index_arbitrary.rs", "byte_parser.rs",
    "adversarial_impl.rs", "sendsync_compileproof.rs",
})


@dataclass(frozen=True)
class Dispatch:
    """The deterministic routing decision for one finding."""
    template: str        # harness-templates/ filename
    sanitizer: str       # asan | msan | miri | tsan | compile_proof | asan_on_c
    oracle: str          # human-readable oracle note
    fuzz_rung: str       # blind | grammar | adversarial_impl | compile | threaded | libfuzzer_unsafe | differential | path_zipslip

    @property
    def template_shipped(self) -> bool:
        return self.template in SHIPPED_TEMPLATES


# ── CWE → dispatch (find-to-fuzz.md §1) ──────────────────────────────────────
_INDEX_ASAN = Dispatch("index_arbitrary.rs", "asan", "ASan (cargo-fuzz default)", "blind")
_BYTE_ASAN = Dispatch("byte_parser.rs", "asan", "ASan", "blind")
_TRAIT_MIRI = Dispatch("adversarial_impl.rs", "miri", "Miri (+ASan for heap-overflow/UAF variants)", "adversarial_impl")
_SENDSYNC = Dispatch("sendsync_compileproof.rs", "compile_proof", "the compiler (compiles ⇒ unsound)", "compile")
_UNINIT_MSAN = Dispatch("index_arbitrary.rs", "msan", "MSan (-Zsanitizer=memory); ASan is blind to it", "msan")
_FMT_C = Dispatch("byte_parser.rs", "asan_on_c", "ASan only if the C is -fsanitize=address-compiled; else %n/bad-ptr oracle", "blind")
_RACE_TSAN = Dispatch("threaded_driver.rs", "tsan", "TSan / loom (libFuzzer alone won't find it)", "threaded")
_GRAMMAR = Dispatch("grammar_parser.rs", "asan", "ASan over an Arbitrary AST of the format + libFuzzer -dict", "grammar")

_BY_CWE: dict[int, Dispatch] = {
    125: _INDEX_ASAN,   # OOB read
    787: _INDEX_ASAN,   # OOB write
    129: _INDEX_ASAN,   # improper array index
    193: _INDEX_ASAN,   # off-by-one
    190: Dispatch("index_arbitrary.rs", "asan", "ASan + overflow-checks (panic)", "blind"),  # int overflow → alloc/index
    416: _TRAIT_MIRI,   # UAF (via caller trait impl)
    415: _TRAIT_MIRI,   # double-free
    662: _SENDSYNC,     # improper synchronization / unsound Send/Sync
    908: _UNINIT_MSAN,  # uninitialized read (valid alloc) — but trait-trust variant overridden by capability
    134: _FMT_C,        # format string into a C library
    362: _RACE_TSAN,    # data race / concurrency
}

# ── capability → dispatch override (the stronger routing signal, P0.3) ────────
# When the threat-model §9 capability names the mechanism, it beats the CWE for
# picking Miri-vs-ASan-vs-compiler (a CWE-125 reached *through a lying trait impl*
# needs Miri, not blind ASan).
_BY_CAPABILITY: dict[str, Dispatch] = {
    "unsafe_trait_trust": _TRAIT_MIRI,
    "unsafe_generic_soundness": _SENDSYNC,
    "concurrency_async": _RACE_TSAN,
    "unsafe_simd": Dispatch("index_arbitrary.rs", "miri", "Miri prioritized over the unsafe entry point", "libfuzzer_unsafe"),
    "network_protocol_parser": Dispatch("byte_parser.rs", "asan", "differential fuzz vs the reference impl", "differential"),
    "subprocess_exec": Dispatch("byte_parser.rs", "asan", "ASan over a path/zip-slip corpus", "path_zipslip"),
}

_CWE_RE = re.compile(r"(\d{1,4})")


def _cwe_num(cwe: str | int | None) -> int | None:
    if cwe is None:
        return None
    if isinstance(cwe, int):
        return cwe
    m = _CWE_RE.search(str(cwe))
    return int(m.group(1)) if m else None


def dispatch(cwe: str | int | None,
             capability: str | None = None,
             structure_gated: bool = False) -> Dispatch:
    """Route a finding to (template, sanitizer, oracle, rung).

    Precedence (strongest routing signal first):
      structure_gated → grammar rung (deep parser a random byte stream can't
        satisfy — 0040's ID3 case; skip straight past blind);
      capability override (definitive mechanism — trait-trust→Miri, Send/Sync→
        compiler, race→TSan, simd→Miri);
      CWE table; else the general byte-parser/ASan default.
    """
    if structure_gated:
        return _GRAMMAR
    if capability and capability in _BY_CAPABILITY:
        return _BY_CAPABILITY[capability]
    n = _cwe_num(cwe)
    # CWE-908 is ambiguous: uninit-read (MSan) vs trait-trust UAF (Miri). Absent a
    # trait-trust capability, treat it as the uninit case (the _BY_CWE default).
    if n is not None and n in _BY_CWE:
        return _BY_CWE[n]
    return _BYTE_ASAN


# ── step 3: validation commands + residual classification ────────────────────
def fuzz_build_cmd(fuzz_target: str, features: str | None = None) -> str:
    """`cargo +nightly fuzz build` — the compiler is the oracle that catches the
    agent's API mistakes before any fuzz time is spent (§4)."""
    feat = f" --features {features}" if features else ""
    return f"cargo +nightly fuzz build {fuzz_target}{feat}"


def fuzz_run_cmd(fuzz_target: str, seconds: int = SMOKE_SECONDS,
                 rss_limit_mb: int = RSS_LIMIT_MB) -> str:
    """`cargo fuzz run` smoke run with an OOM cap (§3/§4)."""
    return (f"cargo +nightly fuzz run {fuzz_target} -- "
            f"-max_total_time={seconds} -rss_limit_mb={rss_limit_mb}")


# stderr signatures → residual reason (§5). Order matters: first match wins.
_RESIDUAL_SIGNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"use of uninitialized|MemorySanitizer", re.I), "needs-MSan"),
    (re.compile(r"exceeds maximum|larger than 4 ?gib|only on 32-bit|address space", re.I), "address-space-only"),
    (re.compile(r"format string|%n|libsqlite3-sys|un-?instrumented C|-fsanitize=address", re.I), "asan-on-C"),
    (re.compile(r"magic|frame sync|synchsafe|checksum|structure[- ]gated|dictionary", re.I), "grammar-gated"),
    (re.compile(r"no public|unreachable|not exported|private (fn|function)|cannot reach", re.I), "unreachable-as-extracted"),
)


def classify_residual(verdict: str, output: str,
                      disp: Dispatch,
                      agent_residual: str | None = None) -> str:
    """Reconcile a run's outcome into the fixed RESIDUAL_REASONS vocabulary.

    `verdict` ∈ {reproduced, clean, build_failed}. A reproduction is always
    'reproduced'. A build failure is 'build-failed'. For a clean run, prefer the
    agent's own reason if it's valid, else sniff the output for a known
    signature, else fall back to the sanitizer-fit implied by dispatch (an MSan
    rung that ran clean → 'needs-MSan' is wrong; but a clean *ASan* run on a
    finding dispatch routed to MSan means MSan was the missing rung). Last
    resort: 'uncharacterized' — which the scorecard rejects, forcing a human or
    a re-run to name the reason (§5: "0 bugs found" is a lie the reason corrects).
    """
    if verdict == "reproduced":
        return "reproduced"
    if verdict == "build_failed":
        return "build-failed"
    # clean:
    if agent_residual in RESIDUAL_REASONS and agent_residual not in ("reproduced", "build-failed"):
        return agent_residual
    text = output or ""
    for pat, reason in _RESIDUAL_SIGNS:
        if pat.search(text):
            return reason
    # dispatch-implied fallbacks: the finding wanted a rung this run didn't use.
    if disp.sanitizer == "msan":
        return "needs-MSan"
    if disp.sanitizer == "asan_on_c":
        return "asan-on-C"
    if disp.fuzz_rung == "grammar":
        return "grammar-gated"
    return "uncharacterized"


# ── step 2: the binding prompt (Profile.build_reattack) ──────────────────────
def _load_template(name: str) -> tuple[str, str]:
    """Return (template_name_used, template_text). Falls back to the nearest
    shipped skeleton if the routed template isn't in-repo yet (P1.2 pending)."""
    p = _TEMPLATES_DIR / name
    if p.exists():
        return name, p.read_text()
    # not-yet-shipped rung → give the agent the closest shipped base + a note.
    fallback = "byte_parser.rs"
    fp = _TEMPLATES_DIR / fallback
    text = fp.read_text() if fp.exists() else "// (template unavailable)\n"
    note = (f"// NOTE: the dispatched template `{name}` is not shipped yet; this is\n"
            f"// `{fallback}` as a base — adapt it to the {name} shape described above.\n\n")
    return name, note + text


REATTACK_PROMPT_TEMPLATE = """\
You are turning a graded static Rust finding into a REPRODUCING fuzz harness, as
part of an authorized defensive security assessment. A table already picked your
template and oracle; your job is the one step a table cannot do — bind the
skeleton to THIS crate's real API, then let the compiler and the sanitizer gate
the result.

## Environment

Isolated sandbox, everything local, network egress blocked. The crate from
{github_url} (commit {commit}) is at {source_root}. Available: cargo (stable +
nightly), cargo-fuzz, cargo-miri, rustc, python3, xxd, file.

## The finding

- CWE: {cwe}
- Vulnerable site: {site}
- Mechanism / notes: {mechanism}
{defer_section}
## Dispatched harness

- Template: `{template}`   (skeleton below — adapt, do not paste verbatim)
- Oracle / sanitizer: **{sanitizer}** — {oracle}
- Fuzzing rung: {fuzz_rung}

```rust
{template_text}
```

The `fuzz/` project boilerplate (one file) is `fuzz-Cargo.toml.template` in the
same template set — create `fuzz/Cargo.toml` from it, pointing the `path`
dependency at this crate.

## Two rules you must not miss

- **Heap-owning element (L12).** For any duplicate / uninit / OOB-write bug, make
  the moved/dropped/written element OWN heap — `Box<u32>` / `String`, never a
  bare `u32`. `Bomb(u32)` turns a double-drop or drop-of-uninit into a silent
  *logic* error the sanitizer/Miri cannot see; `Bomb(Box<u32>)` turns it into an
  invalid-free they flag. Same for OOB writes: a wrong integer is silent, a
  corrupted heap pointer is caught.
- **OOM caps.** Cap fuzzed lengths/capacities (`% 4096`) and rely on the
  `-rss_limit_mb={rss_limit}` you'll pass at run time, so the budget is spent on
  the bug, not a giant allocation. Clamp an index/param ONLY where the API's own
  `assert!` would legitimately fire — otherwise you fuzz the panic, not the
  memory bug.

## Binding notes (the long tail a generator loses on)

- If the vulnerable fn is **private**, find the public wrapper that reaches it
  (e.g. a parser's private `get_id3` reached via public `read_from_slice`).
- If the crate is **`no_std` with its own `#[panic_handler]`**, it clashes with
  libfuzzer's `std` — `include!` the real source module instead of depending on
  the crate.
- If the bug is behind a **feature/cfg** (`--features ringbuffer`, `--cfg
  threadsafe`), discover and enable it (`--features` goes on the fuzz build).

## Validation protocol — the compiler is your oracle

1. Write the harness + `fuzz/Cargo.toml`.
2. Build: `{build_cmd}`. If it fails, READ the stderr, fix the API mismatch, and
   rebuild. Repeat until it compiles — this catches ~all API errors before any
   fuzz time. Report how many rebuilds you needed.
3. Smoke run: `{run_cmd}`. Record crash (ASan/panic/Miri UB + file:line) or clean.
   For the `compile_proof` oracle there is NO run — *if it compiles, it is
   unsound*; that compilation IS the reproduction.
4. If a known crash input exists, replay it and assert it reproduces.

## A "no crash" is a capability map, not a failure

If it runs clean, the REASON is the deliverable — name the missing rung:
`grammar-gated` (deep magic/length/frame parser — blind & coverage both miss →
needs an Arbitrary-AST / `-dict=` grammar harness), `address-space-only` (bug only
at >4 GiB / 32-bit — real but out of 64-bit fuzz scope), `asan-on-C` (format
string / FFI into un-instrumented C — build the C dep with ASan), `needs-MSan`
(uninitialized read — ASan is blind, rerun under MSan), or
`unreachable-as-extracted` (no public entry drives the sink). "0 bugs found"
without a reason is not an acceptable output.

## Output format

When done, emit exactly these tags:

<harness_path>/path/to/fuzz/fuzz_targets/reattack.rs</harness_path>
<verdict>reproduced|clean|build_failed</verdict>
<residual_reason>reproduced|grammar-gated|address-space-only|asan-on-C|needs-MSan|unreachable-as-extracted|build-failed|uncharacterized</residual_reason>
<build_attempts>N</build_attempts>
<crash_input>/path/to/crash-input-file</crash_input>   (only if verdict=reproduced)
<crash_output>
[the ASan/panic/Miri trace with file:line, OR — for compile_proof — the fact
that it compiled; OR the clean-run summary that justifies the residual_reason]
</crash_output>
<detail>features enabled, public wrapper used, element type chosen, etc.</detail>

`<residual_reason>` MUST be `reproduced` iff `<verdict>` is `reproduced`; a clean
verdict MUST carry a real residual reason. Emit the tags once.
"""

_DEFER_SECTION = """\
- DEFER-TO-DYNAMIC sketch from the finder (an adversarial trait-impl / schedule
  the static stage could not turn into a byte input — build the harness around
  THIS):
{defer_sketch}
"""


def build_reattack(
    *,
    github_url: str,
    commit: str,
    source_root: str,
    cwe: str | int | None,
    site: str,
    mechanism: str = "",
    capability: str | None = None,
    structure_gated: bool = False,
    defer_sketch: str | None = None,
    smoke_seconds: int = SMOKE_SECONDS,
    rss_limit_mb: int = RSS_LIMIT_MB,
    fuzz_target: str = "reattack",
) -> str:
    """Step-2 binding prompt for the reattack agent (wired as
    `Profile.build_reattack`). Dispatches deterministically, inlines the chosen
    template, and hands the agent the §2/§3 rules + §4 validation protocol."""
    disp = dispatch(cwe, capability, structure_gated)
    template_used, template_text = _load_template(disp.template)
    defer_section = (
        _DEFER_SECTION.format(defer_sketch=defer_sketch) if defer_sketch else "")
    return REATTACK_PROMPT_TEMPLATE.format(
        github_url=github_url,
        commit=commit,
        source_root=source_root,
        cwe=cwe if cwe is not None else "unknown",
        site=site,
        mechanism=mechanism or "(none given — infer from the site)",
        defer_section=defer_section,
        template=template_used,
        sanitizer=disp.sanitizer,
        oracle=disp.oracle,
        fuzz_rung=disp.fuzz_rung,
        template_text=template_text,
        rss_limit=rss_limit_mb,
        build_cmd=fuzz_build_cmd(fuzz_target),
        run_cmd=fuzz_run_cmd(fuzz_target, smoke_seconds, rss_limit_mb),
    )


# ── orchestration: run one reattack in a container (mirrors run_find) ─────────
async def run_reattack(
    finding: dict,
    target: TargetConfig,
    model: str,
    max_turns: int = DEFAULT_REATTACK_MAX_TURNS,
    agent_env: dict[str, str] | None = None,
    container_name: str = "reattack_target",
    transcript_path: str | None = None,
    progress_prefix: str | None = None,
    system_prompt: str | None = None,
) -> tuple[ReattackArtifact, AgentResult, dict[str, float]]:
    """Build a reproducing harness for one finding and validate it in-container.

    `finding` is a dict with at least: finding_id, cwe, site. Optional:
    mechanism, capability, structure_gated, defer_sketch.
    Returns (artifact, agent_result, timings).
    """
    timings: dict[str, float] = {}
    disp = dispatch(finding.get("cwe"), finding.get("capability"),
                    bool(finding.get("structure_gated")))
    fid = str(finding.get("finding_id") or finding.get("site") or "finding")

    def _artifact(verdict: str, residual: str, *, harness_path=None,
                  crash_input=None, crash_output="", build_attempts=0, detail="") -> ReattackArtifact:
        return ReattackArtifact(
            finding_id=fid, cwe=str(finding.get("cwe") or "unknown"),
            template=disp.template, sanitizer=disp.sanitizer,
            verdict=verdict, residual_reason=residual,
            harness_path=harness_path, crash_input=crash_input,
            crash_output=crash_output[:10_000], build_attempts=build_attempts,
            detail=detail,
        )

    with sandbox.agent_container(
        target.image_tag, container_name, agent_env,
        memory=target.memory_limit, shm_size=target.shm_size,
    ) as container:
        prompt = build_reattack(
            github_url=target.github_url, commit=target.commit,
            source_root=target.source_root,
            cwe=finding.get("cwe"), site=str(finding.get("site") or ""),
            mechanism=str(finding.get("mechanism") or ""),
            capability=finding.get("capability"),
            structure_gated=bool(finding.get("structure_gated")),
            defer_sketch=finding.get("defer_sketch"),
        )
        t0 = time.time()
        result = await run_agent(
            prompt=prompt, max_turns=max_turns, model=model, container=container,
            transcript_path=transcript_path, progress_prefix=progress_prefix,
            system_prompt=system_prompt,
        )
        timings["reattack"] = time.time() - t0

        text = result.find_tagged_message("verdict") or ""
        verdict = (parse_xml_tag(text, "verdict") or "clean").strip()
        if verdict not in ("reproduced", "clean", "build_failed"):
            verdict = "clean"
        harness_path = parse_xml_tag(text, "harness_path")
        crash_output = parse_xml_tag(text, "crash_output") or ""
        agent_residual = parse_xml_tag(text, "residual_reason")
        detail = parse_xml_tag(text, "detail") or ""
        build_attempts = _int(parse_xml_tag(text, "build_attempts"))

        residual = classify_residual(verdict, crash_output, disp, agent_residual)

        crash_input = None
        if verdict == "reproduced":
            ci_path = parse_xml_tag(text, "crash_input")
            if ci_path:
                crash_input = docker_ops.read_file(container, ci_path) or None
            if crash_input is None and disp.sanitizer != "compile_proof":
                # Claimed a repro but produced no input (and it's not the
                # compile-proof oracle, which has no input) — downgrade honestly.
                verdict = "clean"
                residual = classify_residual(verdict, crash_output, disp, agent_residual)

        return (
            _artifact(verdict, residual, harness_path=harness_path,
                      crash_input=crash_input, crash_output=crash_output,
                      build_attempts=build_attempts, detail=detail),
            result, timings,
        )


def _int(s: str | None) -> int:
    if s and s.strip().lstrip("-").isdigit():
        return int(s.strip())
    return 0
