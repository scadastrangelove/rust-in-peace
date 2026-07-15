# Rust-security profile

A Rust-focused variant of this pipeline, added **alongside** the C/C++ + ASAN
default (nothing in the base pipeline is modified). It reflects lessons from
auditing a production Rust parser: the bugs that matter in Rust concentrate in
`unsafe`/FFI, panics on untrusted input, parser/deserialization trust
(integrity ≠ bounds validation), and release-only behavior.

The pipeline's shape is unchanged — *an agent crafts an input, a detector fires,
verifiers check, an analyst assesses exploitability.* Only the swappable nouns
change: **detector** (ASAN → Miri + `-Zsanitizer=address` + panic/abort + hang),
**bug taxonomy**, and **crash signatures**.

## Two layers (use either or both)

### 1. Interactive skills — usable today, zero setup

Tune the read-only `/vuln-scan` and `/triage` skills for Rust with the two
plain-text files here:

```
/vuln-scan <dir> --extra   profiles/rust/scan-extras.txt
/triage <findings>.json --fp-rules profiles/rust/fp-rules.txt
```

- **`scan-extras.txt`** appends Rust vuln categories to the scan brief: unsafe/FFI
  memory safety, panic-DoS, deserialization/parser trust, release-only behavior,
  and the Rust-specific DO-NOT-REPORT list. Emphasizes stating the **trust
  boundary** (attacker- vs operator-controlled input) for every finding.
- **`fp-rules.txt`** appends 7 Rust false-positive precedents to the triage
  verifier — most importantly **R1** (an unsafe read bounded by a checked
  invariant is a FP; trace the invariant) and **R2** (operator-only /
  trusted-by-construction inputs are latent hardening, not live vulns). These
  encode the two mistakes that dominate naive Rust audits.

These need no Docker and no code execution. This is the recommended starting
point and, for many teams, sufficient on its own.

### 2. Autonomous pipeline — a first-class `profile: rust`

The pipeline now has a **profile registry** (`harness/profiles.py`). A profile
bundles the language/detector-specific pieces the generic orchestration resolves
at run time. Selecting it is one line in a target's `config.yaml`:

```yaml
profile: rust        # default is "cpp" — existing C targets are unchanged
```

Every stage does `profile = get_profile(target.profile)` then
`profile.build_find_prompt(...)` / `profile.detector.top_frame(...)` / etc.
`cpp` (the original C/C++ + ASAN pipeline) is the default, so all existing
targets keep working with no change. `targets/rust-canary/config.yaml` sets
`profile: rust`.

| Piece | `cpp` | `rust` |
|-------|-------|--------|
| find prompt | `harness/prompts/find_prompt.py` | `harness/rust/find_prompt.py` |
| detector | `harness/asan.py` | `harness/rust/detect.py` |
| grade prompt | `harness/prompts/grade_prompt.py` | `harness/rust/grade_prompt.py` |
| judge prompt | `harness/prompts/judge_prompt.py` | `harness/rust/judge_prompt.py` |
| report / patch / compare | base | base (reused; fork when the Rust exploitability/fix wording is worth it) |
| system prompt | shared (generalized to be detector-neutral) | shared |

- **`harness/rust/find_prompt.py`** — same `build_find_prompt(...)` signature.
  Rust crash tiers (Miri UB > sanitizer OOB > panic-DoS > hang), the
  multi-detector run model, a Rust out-of-scope list.
- **`harness/rust/detect.py`** — same surface as `asan.py`
  (`project_frames`, `top_frame`, `crash_reason`, `excerpt`/`asan_excerpt`).
  Parses **panic**, **Miri UB**, **ASAN**, and **abort**; the dedup signature
  keys on crash SITE + class, skipping panic/UB machinery frames
  (`rust_begin_unwind`, `core::panicking::*`, `/rustc/` std frames).
- **`harness/rust/{grade,judge}_prompt.py`** — Rust rubric (a valid crash is a
  Miri UB / sanitizer OOB / panic / hang, not a clean `Err`) and Rust dedup
  (same site across panic/UB/ASAN classes = one bug).
- **`targets/rust-canary/`** — a runnable, deliberately-vulnerable crate with the
  seeded bug classes + one safe decoy (a triage FP). Standard `config.yaml`
  schema; `docker build` works with zero pipeline changes.

For post-hoc `vuln-pipeline dedup` (which walks result.json files that may span
profiles and carries no single target), `harness/profiles.detector_for_output()`
sniffs the crash text and picks the right parser automatically.

Adding another language later = a new `harness/<lang>/` package + one `Profile`
entry in `harness/profiles.py`. The generic orchestration doesn't change.

## Detectors

All four the base pipeline's ASAN slot maps onto, fast → thorough:

| Detector | Catches | Cost |
|----------|---------|------|
| **`-Zsanitizer=address`** driver | OOB read/write in `unsafe`/FFI, UAF | fast (the main loop) |
| **panic / abort** (exit 101/134) | `unwrap`/index/slice/overflow on untrusted input | free (same driver) |
| **hang-timeout** | unbounded loop/recursion from untrusted control data | one bounded re-run |
| **Miri** (`cargo +nightly miri run`) | UB the sanitizer misses: provenance, uninit reads, invalid values, data races | slow; escalation oracle |
| **cargo-fuzz** (installed in the image) | reachability — turn a static candidate into a reproduced crash | per-target harness |

`targets/rust-canary/run_detectors.sh` chains sanitizer → hang → Miri and is the
target's `reattack_harness`.

## Grade / report / patch deltas (still C/C++-worded in the base prompts)

The base grade/report/patch prompts assume memory corruption (heap layout,
escalation). For Rust, adjust the rubric wording (keep the structure):

- **Grade** — a valid crash is a Miri `Undefined Behavior`, a sanitizer
  buffer-overflow/UAF, a reproducing panic on untrusted input, or a hang. A
  clean `Err(...)` return is NOT a crash.
- **Report** — swap "heap layout / escalation path" for: *primitive* (OOB
  read = info-leak / OOB write = corruption / panic = availability), *unsafe
  reachability from a public API*, *trust boundary* (attacker- vs
  operator-controlled input — the single biggest severity driver for Rust), and
  *soundness* (does the fix restore a real invariant or just move the panic).
- **Patch** — a fix is accepted when the detector no longer fires AND
  `cargo test` (T2) still passes. Prefer parse-time validation (bound the field
  once) over per-use checks when the hot path is perf-sensitive — validating at
  the trust boundary keeps `unsafe` reads unchecked at zero runtime cost.

These are documented rather than pre-forked to keep the port minimal; the base
prompt files are small if you want to hard-fork them per `docs/customizing.md`.

## Provenance

The bug taxonomy, the FP rules (esp. R1/R2), and the canary's seeded bugs are
distilled from a real audit run of this pipeline against a Rust literal-matching
engine: unchecked `read_unaligned` at an offset trusted after a CRC check
(→ parse-time validation), panic on untrusted operand reads in an interpreter,
an unbounded chain walk with a data-controlled terminator, and one false
positive (an unchecked read the caller's exclusion mask actually bounds).

## Canonical reference

The Rust bug taxonomy, FP rules, and severity calibration here are grounded in
[`references/rust-security-review.md`](references/rust-security-review.md) — a
merged canonical "Rust Security Code Review" best-practices document (unsafe
audit dimensions, panic/DoS, `as`-conversions, FFI, concurrency/async, parser
differentials, secrets/crypto, supply chain, CI layers, and real-world RustSec
case studies mapped to each). `scan-extras.txt` / `fp-rules.txt` distil it into
the interactive briefs; the full text is the depth reference for a reviewer.
