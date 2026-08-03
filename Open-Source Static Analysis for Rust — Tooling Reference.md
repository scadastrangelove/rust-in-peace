# Open-Source Static Analysis for Rust — Tooling Reference

**Version:** July 2026 · Companion to *Rust Security Code Review — Canonical Best Practices* (intended as §13.x, CI pipeline)
**Verification snapshot:** 2026-07-20. Repository states and versions verified directly where marked ✅; inferred or second-hand claims marked ⚠️.

---

## 0. The headline

**No single mature open-source SAST covers Rust soundness + AppSec + protocol logic.** The best achievable result is a deliberate layering of tools, each mapped to one defect-origin family and one oracle.

Two structural facts drive every recommendation below:

1. **Classic taint-tracking SAST is weak for Rust** relative to Java/Python/Go. The strongest AppSec coverage comes from CodeQL; the strongest fully-open coverage from OpenGrep; and neither reaches the cross-file depth those engines achieve in older-supported languages.
2. **The heaviest lifting is done by dynamic oracles** — Miri, fuzzing, sanitizers — not by static scanners. Static analysis for Rust is best understood as *policy enforcement plus candidate generation*, with dynamic tools as the verdict.

---

## 1. Tool-to-family map

Families are from the canonical document's defect-origin taxonomy.

| Family | Primary static finder | Fully-open alternative | PR gate? | Real oracle |
| --- | --- | --- | --- | --- |
| **APP-TRUST-BOUNDARY** (SQLi, SSRF, traversal, identity) | CodeQL | OpenGrep `--taint-intrafile` | ✅ | reachability + integration witness |
| **RUST-PANIC-RESOURCE** (panic/OOM on hostile input) | Clippy restriction lints + Dylint | same | ✅ | fuzzing + panic/hang/OOM witness |
| **RUST-SOUNDNESS** (safe API → UB) | Dylint (ported Rudra rules) + MIRAI | same | ⚠️ nightly only | Miri, ASan/TSan/MSan, adversarial `Drop`/trait tests |
| **PROTOCOL-LOGIC** (framing/state disagreement) | **none** — seeds only | — | ❌ | differential multi-peer harness |
| **RUNTIME-SANDBOX** | MIRAI (selective) | same | ❌ | guest PoC + differential execution + model checking |
| **BUILD-SUPPLY-CHAIN** | cargo-audit / deny / vet / geiger / auditable | same | ✅ | isolated build, provenance, artifact comparison |

**The PROTOCOL-LOGIC row is the important one.** No SAST finds request smuggling. The Pingora advisories (RUSTSEC-2026-0033/0034/0035, CVSS up to 9.3) would not be caught by CodeQL, OpenGrep, MIRAI, or Rudra, because the defect lives in the *disagreement between two parsers*, not in either one's code. Static tools can only generate seeds (e.g. "flag every place a framing header is read outside the canonical parser"). The verdict requires a differential harness across the real frontend and backend.

---

## 2. Recommended stacks

### Fully open-source

```text
Clippy            → low-noise correctness/policy baseline (ships with toolchain)
Dylint            → type-aware, project-specific security invariants
OpenGrep          → AppSec patterns + intrafile taint, SARIF out
MIRAI             → selective path-sensitive escalation (parsers, crypto, authz core)
cargo-audit/deny/vet/geiger → supply chain
Miri + cargo-fuzz + sanitizers → the actual verification layer
```

### If CodeQL licensing is acceptable

```text
CodeQL (security-extended) → primary APP-TRUST-BOUNDARY finder
OpenGrep                   → custom domain rules + independent second finder
Clippy + Dylint            → Rust-specific policy and correctness
MIRAI                      → selective deep analysis
Miri / fuzz / differential PoC → oracles
```

Do not run Semgrep CE and OpenGrep together — they solve the same problem. Choose OpenGrep for an independent fully-open chain, or Semgrep CE if you already have Semgrep infrastructure and need registry compatibility.

---

## 3. Tool notes

### Clippy — mandatory baseline, not a SAST ✅

Ships with the toolchain; ~700–800 lints depending on version. The `correctness` group targets code that is almost certainly wrong; from `restriction` you cherry-pick security-relevant prohibitions.

```toml
[workspace.lints.rust]
unsafe_op_in_unsafe_fn = "deny"

[workspace.lints.clippy]
unwrap_used = "warn"
expect_used = "warn"
panic = "warn"
panic_in_result_fn = "warn"
indexing_slicing = "warn"
arithmetic_side_effects = "warn"
as_conversions = "warn"
undocumented_unsafe_blocks = "deny"
missing_safety_doc = "deny"
```

Do **not** enable all of `clippy::restriction` — official guidance warns the group is deliberately excessive and internally contradictory. Clippy sees local anti-patterns well; it does not build a taint graph from HTTP request to SSRF/SQL sink.

### CodeQL — strongest AppSec coverage ✅

Rust analysis reached **general availability in CodeQL 2.23.3 (October 2025)**, after a public preview from June 2025. Coverage includes all OWASP Top 10 categories except A06 (Vulnerable and Outdated Components), where GitHub relies on Dependabot. Standard query packs cover SQL injection, SSRF, path injection, XSS, log injection, cleartext storage/transmission, disabled TLS verification, hard-coded and weak crypto, uncontrolled allocation, and pointer-lifetime issues. Additional Rust queries have shipped since (e.g. `rust/insecure-cookie` in 2.23.3; extended `rust/hard-coded-cryptographic-value` heuristics in 2.24.0).

Practical notes:
- Requires `rustup` and `cargo`; **nightly toolchain features are not supported**.
- Rust uses `build-mode: none` — no project build needed, which is both convenient and safer when analysing unfamiliar code.
- Database-backed analysis gives deeper cross-file dataflow than pattern engines; custom path queries and framework models are supported.

**Licensing caveat:** queries and libraries are open source (MIT), but the CodeQL CLI is licensed separately and analysing closed-source code may require a commercial license. Free for public repositories on GitHub; private repositories need GitHub Advanced Security. **Therefore CodeQL is the best technical choice but not the answer to a strict "fully FOSS" requirement.**

### OpenGrep — best fully-open AppSec engine ✅

A fork of Semgrep v1.100.0 under **LGPL-2.1**, created after Semgrep moved critical features behind a commercial license. Backed by a consortium of 10+ AppSec organisations (Aikido, Arnica, Amplify, Endor Labs, Jit, Kodem, Legit, Mobb, Orca Security, Phoenix Security). Latest release **1.22.0 (2026-05-19)**; 73 releases to date.

Relevant capabilities:
- **Compatible with existing Semgrep rules and rulesets**, unchanged.
- JSON and **SARIF** output; self-contained binaries (Nuitka, no Python required); Cosign-signed releases.
- **`--taint-intrafile`**: constructor and field-assignment tracking, **inter-method taint flow**, higher-order function support across 12 languages, collection-method tainting (map/filter/reduce).
- Rust is among the 30+ supported languages — the project's own getting-started example is a Rust `.unwrap()` rule.

**Limitation:** taint remains *intrafile* (as the flag name says). It handles cross-function flow within a file but does not reach CodeQL's cross-file depth, and it degrades on long dataflow through traits and framework abstractions.

Example of the rule shape that pays off most — untrusted request data reaching a process sink:

```yaml
rules:
  - id: rust-untrusted-command
    languages: [rust]
    mode: taint
    pattern-sources:
      - pattern: $REQ.query(...)
      - pattern: $REQ.path(...)
    pattern-sinks:
      - pattern: std::process::Command::new($X)
    message: Untrusted request data reaches process execution
    severity: ERROR
```

High-value domain rules for a proxy/WAF codebase: `unwrap`/indexing on request or parser paths; untrusted URL → HTTP client without an SSRF policy; untrusted value → SQL string formatting; path construction from request data; custom (unsafe) TLS verifiers; `read_to_end`/`collect`/allocation without a cap; **use of raw headers after normalization**; dangerous framework configuration; banned APIs inside security-critical modules.

### Semgrep CE — viable, but weaker than OpenGrep for this purpose ✅

Open under LGPL, mature, good CI integration, supports Rust (GA, with 70+ Pro rules advertised). Two caveats:
- CE is effectively **single-function/single-file**; cross-file and cross-function engines are Pro.
- Rust is **not** in Semgrep's highest cross-file dataflow maturity tier (that tier is Python, JS/TS, Java, C#, Go, PHP, Kotlin, Swift, C/C++), and the high-accuracy Rust AppSec rules are largely Pro.

### Dylint — highest-leverage tool for your own invariants ✅

Trail of Bits; Apache-2.0/MIT; actively maintained. Dylint runs lints from **user-specified dynamic libraries** rather than a fixed built-in set, so a team maintains its own lint collection. Scaffold with `cargo dylint new <name>`; configure via `[workspace.metadata.dylint]` in `Cargo.toml` or `dylint.toml`; per-library settings supported; rust-analyzer/VS Code integration available.

The decisive difference from a text pattern matcher: **a Dylint lint is a compiler lint** — it receives HIR, type information, and macro-expanded code. That buys type-aware matching, Rust-specific semantics, and a much lower false-positive rate for project invariants, at a higher authoring cost per rule.

Rules worth encoding as Dylint lints (each is a canonical-document red flag that a text matcher handles badly):

```text
manual Send/Sync impl requires an annotated justification
set_len / MaybeUninit / raw-pointer ownership requires a reviewed safety invariant
allocation derived from a wire length must go through a SizeLimit type
unwrap forbidden in functions taking wire types
lock/guard held across .await
std::process::Command forbidden in request-handling modules
HTTP client construction without an SSRF-safe connector
the HTTP normalization API must not be bypassed
narrowing `as` casts forbidden in codec modules
```

The three Rudra analyses (panic safety, higher-order invariants, Send/Sync variance) are the natural first candidates to port here, since Rudra itself is no longer usable in CI (below).

### MIRAI — deep, selective; note the live fork ✅

**The original `facebookexperimental/MIRAI` is archived** ("became orphaned when the sponsoring organization was disbanded"); **active development continues at `endorlabs/MIRAI`**. Any tool index still pointing at the Facebook repo is stale.

An abstract interpreter over MIR performing **top-down, full-program, path-sensitive** analysis via `cargo mirai` (works like `cargo check`). Three uses:
- **panic finder** — requires no annotations, explicitly designed for CI integration;
- **property verification** — requires source annotations for pre/postconditions;
- **security analysis** — taint analysis (information leaks, injection) and **constant-time analysis** (side-channel leaks).

Constraints: needs a compilable project; produces warnings from analysis limitations that must be silenced with annotations; sensitive to rustc internals versions. Run it on selected crates, not the whole monorepo — parsers, crypto, authorization core, length/offset arithmetic, state machines, unsafe boundary crates.

### Rudra — archived; offline use only ✅ (corrects an earlier recommendation)

**Archived by the owner on 2026-04-02, now read-only**, with an explicit README banner: "This project is archived and no longer maintained."

It targets three of the most valuable Rust-specific classes — **panic safety** in unsafe code, **higher-order invariants** (unsafe trusting a safe trait/callback, e.g. assuming `Borrow` returns the same reference on repeated calls), and **Send/Sync variance** (generic `unsafe impl` without correct bounds on `T`). Historically it found 264 memory-safety issues across crates.io, yielding 76 CVEs.

Why it cannot be a merge gate:
- `master` is pinned to **`nightly-2021-10-21`** and only analyses projects that compile with it;
- **no workspace support** (issue #11);
- **cannot suppress findings at specific locations** — the README itself flags this as a CI/CD usability problem given false positives.

Usable as: a frozen Docker image (`ghcr.io/sslab-gatech/rudra:master`) for periodic offline scans; a candidate generator for an agent or human triage; a corpus of real unsafe patterns; and the **source specification for porting its three analyses to Dylint**.

### SonarQube Community Build — aggregator, not the analyser ⚠️

Reportedly added Rust support with ~85 rules, running or importing Clippy results, plus complexity/coverage/duplication metrics and a dashboard/quality gate. **Unverified in this pass.** Even if accurate, the open edition's Rust analysis is largely built on top of Clippy; deeper taint/security analysis is commercially differentiated. Useful as a results aggregator and quality gate — not a reason to skip CodeQL/OpenGrep/Dylint.

### Excluded: MirChecker ✅

Reported false-positive rate of **95.1%** of warnings. Independently, the Yuga authors report it is incompatible with the toolchains most current Rust projects use and that it **detected none of the 27 bugs** in their synthetic dataset. Not viable in any gate.

### Research-tool false-positive rates ✅ (plan your FP budget)

Reported rates vary by study and dataset, but the ordering is consistent:

| Tool | Reported FP rate | Notes |
| --- | --- | --- |
| MirChecker | 95.1% | plus zero detections on a 27-bug synthetic set |
| Rudra | ~50% (raw precision reported as low as 25.6% in one study) | archived; see above |
| Yuga | 46.15% | lifetime-annotation bugs |

An RL-based filtering approach reports lifting Rudra precision from 25.6% to 59.0%, with a further ~10.7pp accuracy gain when combined with dynamic fuzzing — a research prototype, not a product. **Practical consequence: none of these belongs in a blocking PR gate. They are candidate generators requiring human triage.**

### Other actively maintained analysers worth knowing ⚠️

From the curated [Awesome-Rust-Checker](https://github.com/BurtonQin/Awesome-Rust-Checker) index (last-updated dates as listed there):

- **lockbud** (2026-05) — double-lock, conflicting lock order, atomicity violation, UAF, invalid free, panic locations. The best match for async/concurrency review; relevant to the canonical §8.
- **RAPx** (2026-06) — UAF, memory leak.
- **Crema** (SEFM'25) — memory leak, double-free, UAF in pure unsafe Rust *and* across Rust↔C interaction. Directly relevant to an nginx-style FFI layer.
- Stale: **FFIChecker** (2022), **redpen** panic reachability (2024).

---

## 4. CI layering

**Every PR (blocking, deterministic, low noise):**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # with the lint set in §3
cargo dylint --all                                      # project invariants
opengrep scan --sarif-output=findings.sarif -f rules .   # or CodeQL for public repos
cargo audit && cargo deny check
cargo test --workspace --all-targets
```

Use an explicit **feature matrix** rather than a single `--all-features` run where features are mutually exclusive or security-relevant.

**Nightly / scheduled (non-blocking, triaged):**

```bash
cargo +nightly miri test        # unsafe modules
cargo fuzz run <target>         # per-parser campaigns
cargo mirai                     # selected crates only
```

Plus sanitizers on FFI integration tests, lockbud on concurrent crates, `cargo geiger` diff tracking, CodeQL full scan, and — if using cargo-vet — periodic exemption shrinking.

**Release gate:**

```bash
cargo auditable build --release
cargo audit bin ./target/release/<binary>
```

Plus manual sign-off on unsafe/FFI/crypto/sandbox-boundary changes.

**Differential harness (own job, not a "scanner"):** the framing/normalization equivalence tests described in the canonical §9a. This is the only oracle for PROTOCOL-LOGIC and belongs in CI as a first-class job for a proxy/WAF.

---

## 5. Verification status

**Verified directly (repository, vendor changelog, or advisory page):** Rudra archived 2026-04-02 with pinned `nightly-2021-10-21`, no workspace support, no suppression; `facebookexperimental/MIRAI` archived with development moved to `endorlabs/MIRAI`; MIRAI capability set; OpenGrep LGPL-2.1 fork of Semgrep v1.100.0, consortium backing, `--taint-intrafile` feature set, Rust support, release 1.22.0 (2026-05-19); Dylint active, Trail of Bits, dynamic-library lint model; CodeQL Rust GA in 2.23.3 (2025-10) with OWASP coverage minus A06 and the rustup/cargo/no-nightly requirement; Semgrep CE single-file limitation and Rust's absence from the top cross-file maturity tier; MirChecker/Rudra/Yuga FP figures.

**Not verified in this pass (⚠️):** SonarQube Community Build's Rust rule count and Clippy-based implementation; specific 2026 OpenGrep fixes to Rust taint propagation and AST/type-alias handling; exact current Clippy lint count (700–800 range depending on source and version); last-updated dates for lockbud/RAPx/Crema beyond the index listing.

**Evidence policy:** as in the canonical document — for every tool claim, retain the source, the date, and whether the repository was checked directly. Tool indexes go stale in a way that produces exactly the error corrected here (a live fork hidden behind an archived upstream).