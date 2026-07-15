# Rust Security Code Review — Canonical Best Practices

**Version:** July 2026, rev. 2 · Merged from three source documents (checklist draft + review guide + deep-research report with case studies)
**Scope:** general Rust security review, with extensions for codebases handling hostile input (proxies / WAF / parsers), FFI boundaries, and unsafe hotspots.

Safe Rust drastically reduces memory-corruption risk, but it does not protect against logic vulnerabilities, authorization bypass, injection, DoS, deadlocks, resource leaks, or panics. For `unsafe`, the bar is stricter: safe code must not be able to trigger Undefined Behavior through the exposed API. Real-world Rust security failures today come mostly from broken assumptions rather than memory corruption: unsafe contracts (alignment, aliasing, lifetimes), trust boundaries (deserialization, FFI, async concurrency, resource exhaustion under adversarial input), and supply-chain gaps where the production binary is not the code that was reviewed.

---

## 1. Start with a threat model

Before reading individual lines, establish:

* which data the attacker controls;
* which operations mutate state or require privileges;
* where trust boundaries lie: HTTP, IPC, files, DB, FFI, plugins;
* which properties matter: confidentiality, integrity, availability;
* what happens on panic, hang, or memory exhaustion;
* whether the process runs as root, and what it can reach: network, filesystem, secrets.

Then trace the full data path:

```text
external input
    → parsing
    → validation
    → authentication
    → authorization
    → business logic
    → side effect
```

Reviewing only the parser function or only the endpoint is usually insufficient.

**Review prioritization:** direct human attention at unsafe hotspots and trust boundaries first. Effect-based analysis (e.g. Cargo Scan) shows that potentially dangerous code is typically ~0.2–3% of lines — that is where reviewer-hours belong.

---

## 2. Audit `unsafe` as a separate pass

### 2.1 Triage: collect all potentially dangerous sites

```bash
rg '\bunsafe\b|extern "|from_raw|into_raw|transmute|zeroed|MaybeUninit|get_unchecked|static mut|asm!|no_mangle|export_name|target_feature'
```

Pay special attention to:

* `unsafe { ... }`, `unsafe fn`, `unsafe trait`;
* `unsafe impl Send` / `Sync` (each one is a full audit in itself, see §8);
* raw pointers; `transmute`, `zeroed`, `MaybeUninit`;
* `Vec::from_raw_parts`, `Box::from_raw`, `CString::from_raw`;
* manual length/capacity management;
* FFI; inline assembly; SIMD and `#[target_feature]`;
* custom allocators;
* `#[unsafe(no_mangle)]`, `export_name`, `link_section`.

### 2.2 Safety contracts

Every `unsafe` block must carry a verifiable safety contract:

```rust
// SAFETY:
// - ptr was obtained from Box::into_raw;
// - ptr is non-null;
// - the object has not been freed;
// - ptr is never used again after this call.
let value = unsafe { Box::from_raw(ptr) };
```

The comment must explain **why the preconditions hold** — a proof, not a restatement of the operation — and identify what protects those invariants against future refactoring. Public `unsafe fn` requires a `# Safety` doc section describing caller obligations. The invariant must be **locally checkable**: derivable from code within the module, not "sounds plausible."

Structural rules to demand from authors:

* `#![forbid(unsafe_code)]` in crates that don't need unsafe;
* `unsafe_op_in_unsafe_fn = "deny"` everywhere;
* unsafe encapsulated in a minimal module behind a safe API;
* minimal scope: one unsafe block = one operation, not a wrapper around a whole function.

```toml
[lints.rust]
unsafe_op_in_unsafe_fn = "deny"

[lints.clippy]
undocumented_unsafe_blocks = "deny"
missing_safety_doc = "deny"
```

For crates where unsafe must never appear:

```toml
[lints.rust]
unsafe_code = "forbid"
```

Centralize these via `[workspace.lints]` (MSRV 1.74+) so the workspace splits cleanly into **safe-only zones** (`unsafe_code = "forbid"`) and a small set of **audited unsafe boundary crates** — this makes "where can unsafe live" a reviewable, machine-enforced property rather than convention. For what good safety commentary looks like in practice, the standard library's `Vec` source is the reference exemplar: its `// SAFETY:` comments enumerate alignment, initialization, aliasing, and size assumptions explicitly.

### 2.3 Reviewer questions for every `unsafe` site

1. **Lifetime:** does the value actually live long enough? Do `transmute`/`from_raw` extend a reference's life?
2. **Aliasing:** do `&mut T` and other references to the same object coexist? Stacked/Tree Borrows conformance (checked by Miri).
3. **Alignment:** is the pointer properly aligned? Classic trap: `as_ptr()` on `[u8]` is aligned to 1; casting to `*const u64` does not make it aligned to 8.
4. **Validity:** is the bit pattern valid for the type (`bool` from 2, uninitialized memory, invalid UTF-8 in `str`)?
5. **Bounds:** do length and capacity match the allocation?
6. **Initialization:** are all read bytes and fields initialized?
7. **Ownership:** who frees the memory, and how many times? Drop ordering and double-free with `ManuallyDrop`/`MaybeUninit`.
8. **Panic safety:** if a panic can occur between invariant violation and restoration (including from callbacks, `Drop`, or allocation), is there UB or a leak during unwind?
9. **Thread safety:** are manual `Send`/`Sync` impls actually correct?
10. **Safe abstraction:** can any safe call break a hidden invariant?
11. **Pinning:** for `Pin`-based APIs (self-referential structs, futures, intrusive data structures) — are pin projections correct, is `Unpin` implemented (or auto-derived) only where structurally justified, and can safe code move a pinned value? Research (PinChecker, 2025) found unsound pinning abstractions in popular libraries; treat manual `Pin` code as an unsafe hotspot even when no `unsafe` keyword is visible.

`unsafe` does not suspend UB rules — it transfers responsibility for them to the author.

### 2.4 Verification instead of "we're confident"

* **Miri** — mandatory for crates with unsafe: runs tests through a MIR interpreter, catching UB (aliasing violations, alignment, use-after-free, uninitialized reads, data races in unsafe code). Practice: write deliberately "mean" tests targeting unsafe paths — zero lengths, odd alignments, aliasing-like usage, edge-case lifetimes — and keep hotspots Miri-clean. This is the fastest way to turn "we think it's safe" into "we have evidence." Note: Miri is a dynamic check over executed paths, not a proof of UB absence. Nightly CI job.
* **Sanitizers** (ASan/TSan/LSan/MSan) — cover the memory model of the whole process, especially mixed-language systems: FFI buffers, allocator misuse, cross-language use-after-free. Complement Miri; do not replace it.
* **Kani** — model checking for critical functions: proves absence of panics and postconditions over all inputs within stated limits. It does not model Stacked/Tree Borrows aliasing or FFI — which is exactly why Miri must run alongside it.
* **Rudra** — scanner for Rust-specific unsafe anti-patterns (panic safety, higher-order invariants), on a schedule.
* **loom** — for lock-free code and hand-rolled synchronization primitives.

---

## 3. Panic paths and DoS

A panic on attacker-controlled input is an availability vulnerability — especially for servers sharing a process, background workers, and (in FFI contexts) host processes like nginx workers.

### 3.1 Triage

```bash
rg '\.unwrap\(|\.expect\(|panic!|unreachable!|todo!|unimplemented!|assert!|assert_eq!|\[[^]]+\]'
```

Check:

* `unwrap` / `expect` on parse and I/O results — banned on paths reachable from untrusted input; `expect` allowed only with a documented unreachability proof;
* slice/string/array indexing and slicing (`[i]`, `slice[a..b]`);
* division by a potentially zero value;
* recursion with attacker-controlled depth (nested JSON/XML — serde does not limit depth by itself);
* unbounded loops and retries;
* blocking I/O without timeouts; unbounded waits on mutexes/channels;
* allocations sized by external input: `Vec::with_capacity(len_from_wire)`, `read_to_end` without a cap, `collect`, decompression without ratio/size limits (zip bombs);
* unbounded queues; spawning a task per incoming object;
* `Drop` implementations that can panic or block.

Preferred style:

```rust
let item = items
    .get(index)
    .ok_or(Error::InvalidIndex(index))?;

let size = count
    .checked_mul(element_size)
    .ok_or(Error::SizeOverflow)?;
```

### 3.2 Algorithmic DoS

* Regex over untrusted input — only linear-time engines (the `regex` crate); no backtracking engines without timeouts/limits (ReDoS).
* Hash-DoS: `std::collections::HashMap` with SipHash is fine; swapping in a "fast" hasher (FxHash, ahash without randomization) for attacker-controlled keys is a red flag.

### 3.3 Arithmetic

Do not rely on debug builds to catch overflow. Integer arithmetic may panic with overflow checks enabled or wrap in other builds; security-sensitive computations of sizes, offsets, timestamps, and counters must use `checked_*`, `saturating_*`, `wrapping_*` (with the semantics choice justified) or explicitly proven bounds. Consider `overflow-checks = true` in the release profile for security-critical crates.

Classic trap in offset/length math before indexing or `from_raw_parts`: `a + b < len` overflows; `a < len - b` panics or wraps when `b > len`.

### 3.4 Lints

```toml
[lints.clippy]
unwrap_used = "warn"
expect_used = "warn"
panic = "warn"
panic_in_result_fn = "warn"
indexing_slicing = "warn"
arithmetic_side_effects = "warn"
as_conversions = "warn"
```

Do not enable all of `clippy::restriction`: official guidance is to cherry-pick individual lints, since some are overly strict or mutually contradictory.

---

## 4. Type and size conversions

Watch for:

```rust
value as u16
length as u32
offset as usize
signed as unsigned
```

`as` silently truncates or changes sign. For data influencing memory allocation, permissions, limits, offsets, or wire formats, use checked conversion:

```rust
let length: u32 = input_length
    .try_into()
    .map_err(|_| Error::LengthOutOfRange)?;
```

Also check:

* `usize` is architecture-dependent;
* `offset + length` computations (see §3.3);
* negative-to-unsigned conversion;
* timestamp truncation;
* unit confusion: bytes vs elements vs milliseconds;
* byte order;
* inclusive/exclusive boundaries;
* integer casts at FFI boundaries (`c_int` ↔ `usize`) — checked, never `as`.

Clippy has dedicated lints for possible truncation, wrap, sign loss, and precision loss (`cast_possible_truncation`, `cast_sign_loss`, etc.).

---

## 5. External commands and file operations

Safer — arguments passed separately:

```rust
Command::new("git")
    .arg("show")
    .arg(user_supplied_revision)
    .output()?;
```

Dangerous — interpreter reintroduces injection:

```rust
Command::new("sh")
    .arg("-c")
    .arg(format!("git show {user_input}"))
    .output()?;
```

`std::process::Command::arg` generally does not pass arguments through a shell, but invoking `sh -c`, `cmd.exe`, `.bat`, or another interpreter directly brings command injection back. On Windows, `cmd.exe` and batch files need special care due to non-standard argument parsing.

For file operations, check:

* `../` and absolute paths; canonicalization before checks — naive string `starts_with` is not a path check;
* symlinks and TOCTOU (check-then-use races);
* overwriting existing files; permissions on created files; temp file handling;
* archive extraction: filenames from ZIP/TAR are attacker-controlled;
* access to special files and device paths.

---

## 6. Authorization at the side effect

Typical bug:

```text
load object → modify object → check permission
```

Required:

```text
load object → check permission → validate transition → modify object
```

Check:

* object-level authorization, not just the user's role;
* tenant/account ownership;
* deny-by-default;
* separation of authentication and authorization;
* mass assignment via struct deserialization — can service fields be set through JSON? Use `serde(deny_unknown_fields)` where unknown fields signal an attack or a parser differential;
* reuse of a stale permission check after `.await`;
* races between check and write;
* valid state transitions only;
* idempotency and replay;
* integer counters, quotas, and balances.

Good practice — distinct types for unvalidated vs validated values, so unchecked data cannot accidentally reach a sensitive operation:

```rust
struct RawTransferRequest {
    account: String,
    amount: i64,
}

struct ValidatedTransfer {
    account: AccountId,
    amount: PositiveAmount,
}
```

---

## 7. Errors, unwind, and FFI

In safe code, a panic can break a business invariant even when memory safety holds. In unsafe code, temporarily broken state must never become observable on panic; this usually requires guard objects and RAII rollback (exception safety).

The FFI boundary is the most dangerous zone: the compiler sees nothing on the other side.

Checklist:

* exact ABI and signature match — a wrong `extern` signature is UB; generate bindings (bindgen), don't hand-transcribe them; verify against the actual header, not memory;
* `#[repr(C)]` on shared structs, with static asserts on size/align (`static_assertions` or a `const` block);
* integer type sizes across the boundary;
* nullability: every pointer from C checked for null, with documented length/lifetime validity; lengths from C are untrusted — validate before `slice::from_raw_parts`;
* explicit ownership protocol: who allocates / who frees; never `free` across the boundary with mismatched allocators — memory is freed by the side that allocated it;
* strings: `CStr`/`CString`; no assumptions about NUL termination or UTF-8;
* callback lifetimes; thread affinity of the foreign API;
* **no unwind across FFI**: catch panics with `catch_unwind` (or use `extern "C-unwind"` deliberately) before leaving Rust code. A panic escaping into a C host (e.g. an nginx worker) crashes the process; a foreign exception entering through a non-unwind boundary is UB;
* host-runtime lifecycle invariants (reference counting, request lifetimes — e.g. nginx `r->main->count`) reviewed as named invariants with a test for every exit path, including early returns and error paths;
* sanitizers on integration tests exercising the FFI paths specifically.

---

## 8. Concurrency and async

Check:

* manual `unsafe impl Send` / `Sync` — `Send` and `Sync` are unsafe traits: other unsafe code is entitled to rely on their correctness. Each manual impl needs a full justification;
* lock ordering — safe Rust does not prevent deadlocks; deadlock and resource leaks are not UB and are not caught by the type system;
* a mutex guard held across `.await` — red flag; choose `tokio::sync::Mutex` vs `std::sync::Mutex` deliberately, and keep `std` mutexes out of async hot paths;
* user callbacks invoked under a lock;
* bounded vs unbounded channels;
* atomic memory ordering: `Ordering::Relaxed` in lock-free code must be justified; when in doubt, `SeqCst` plus loom tests;
* **cancellation safety**: for every future under `select!`/timeout — what happens if it's dropped mid-way? Lost data, half-written state, unclosed resources;
* partially applied state changes; check-then-act races;
* shutdown paths and message loss; re-entrant lock acquisition;
* blocking calls in async context (`std::fs`, sync channels) — executor starvation is DoS;
* manual `Pin` handling: pin projections, `Unpin` impls, self-referential futures — see §2.3 item 11.

---

## 9. Parsing and deserializing untrusted input

* Limits **before** parsing: body size, depth, element count, string lengths.
* **Parser differentials as a security invariant:** if the same data is parsed twice (edge and upstream, WAF and backend), parser equivalence must be tested, not assumed — differential fuzzing against the reference implementation.
* No `unsafe` in parsers for speed without a Miri + fuzzing harness around it; zero-copy `&[u8]` views are preferable to pointer tricks.
* Fuzzing as a standing process for every parser, run with sanitizers; corpus checked into the repo; every crash becomes a regression test. `cargo-fuzz` (libFuzzer) is the standard entry point; `afl.rs`/AFL++ or honggfuzz-rs serve as a second engine with different corpus-evolution behavior once libFuzzer plateaus. Use `cfg(fuzzing)` to strip nondeterminism (timestamps, RNG) from harnessed code paths. For public or widely reused crates, integrate with OSS-Fuzz — continuous distributed fuzzing with crash triage beats any in-house scheduled job. The rust-fuzz trophy case is a useful catalog for choosing harness targets and justifying the investment.

Priority fuzz targets:

* binary and text parsers; deserialization;
* image/archive/document formats; network packets;
* state machines;
* arithmetic over lengths and offsets;
* round-trip encode/decode;
* differential behavior vs a reference implementation.

---

## 10. Secrets and cryptography

Check that secrets do not leak into:

* `Debug` / `Display` (check the derives!);
* error chains; panic messages;
* HTTP query strings; tracing spans; metrics labels;
* serialized configuration; core dumps; temp files.

Triage:

```bash
rg 'password|passwd|secret|token|api_key|private_key|authorization|cookie'
```

Practices:

* only vetted crates: RustCrypto, `ring`, `rustls`, `aws-lc-rs`; hand-rolled cryptography is an automatic review reject — it requires a dedicated expert audit even if written entirely in safe Rust;
* secrets in memory: `zeroize` / `secrecy`;
* constant-time comparison for MACs/signatures/secrets (`subtle`), never `==`;
* RNG: `OsRng` / OS-entropy-seeded RNGs for keys and tokens; `SmallRng` or deterministic RNGs never for secrets;
* nonce/IV uniqueness — verify the source of uniqueness explicitly; no encryption without authentication (AEAD);
* certificate validation not skipped; no hardcoded keys; key rotation exists; no parameter downgrade.

---

## 11. Dependencies and supply chain

On every dependency change, review the `Cargo.lock` diff, not just `Cargo.toml`.

### 11.1 Per-dependency review

* why is it needed; is there a lighter alternative; transitive dependency count;
* enabled Cargo features (`default-features = false` where possible); git/path dependencies;
* repository and publisher; maintenance status; RustSec advisories;
* `build.rs` and proc-macro crates: both execute arbitrary code at build time on developer/CI machines — elevated trust level, audit as executable code;
* native C/C++ libraries; licenses and allowed registries; duplicate versions of the same crate;
* unsafe profile of the crate (cargo-geiger).

### 11.2 Tooling

| Tool | Purpose |
|---|---|
| `cargo audit` | known vulnerabilities via RustSec DB, yanked versions |
| `cargo deny check` | policy: advisories, licenses, sources, banned crates, duplicates |
| `cargo vet` | records manual audits of dependencies; imports audits from trusted orgs (Mozilla, Google); delta audits of version diffs |
| `cargo geiger` | map of unsafe across the full dependency tree — an attention map for auditing |
| `cargo auditable` | embeds SBOM metadata into the binary → audit the shipped artifact directly |
| `cargo tree -e features` | which dependency features are actually activated |

### 11.3 The tooling itself is in the threat model

* **Never run Cargo commands on untrusted repositories.** `cargo build`, `cargo check`, `cargo metadata` — and Cargo plugins including `cargo audit` — can trigger execution of project-controlled code (`build.rs`, proc macros, lockfile generation). Reviewing or scanning third-party code means: read-only checkout, sandboxed environment, no implicit Cargo invocations.
* **The toolchain is an attack surface.** CVE-2026-5222/5223: crafted symlinks in crate tarballs from third-party registries could overwrite the cached source of *other* crates in `~/.cargo` — the code Cargo compiles is not necessarily the code that was published. Fixed in Rust 1.96.0; keep the toolchain patched and treat third-party registries as lower-trust than crates.io.
* **build.rs is a proven exfiltration vector.** The 2023 crates.io malware postmortem documented typosquatted crates whose `build.rs` exfiltrated host metadata at build time. Typo-distance checks on new dependency names and mandatory `build.rs` review are cheap countermeasures.
* **RustSec tracks soundness issues as informational advisories** even when they are not directly exploitable vulnerabilities. Do not filter these out: "safe API, unsound internals" advisories (see §15) are exactly the class that becomes exploitable after a refactor or compiler update.

### 11.4 Practices

* `Cargo.lock` committed always (libraries too, if they have CI/benchmarks) — otherwise local, CI, and production resolve different versions and scanning is meaningless;
* vulnerability prioritization: EPSS/KEV × the crate's unsafe profile × vulnerability category — a vuln in a crate with unsafe/crypto/FFI escalates. "We don't call that path" is not a reason to defer: unsafe bugs resurface under refactors and compiler updates;
* unmaintained crates are a ticking clock: plan migration before a real CVE lands;
* publishing your own crates: Trusted Publishing (OIDC, short-lived tokens) instead of long-lived tokens in CI; audit GitHub Actions permissions, branch protection, and tag strategy — the release pipeline is a security boundary;
* delta audits (Google / cargo-vet model): on a version bump, audit the diff, but the standard is "properties are actually preserved," not "the diff doesn't look bad"; a delta audit never lowers the UB-risk level established by the baseline audit.

---

## 12. Build hardening

* Don't disable standard mitigations. Release profile: `overflow-checks` for critical crates; deliberate choice of `panic = "abort"` vs `"unwind"` (abort is simpler security-wise but breaks `catch_unwind`-based FFI shields — decide per binary);
* keep compiler environment defaults; no exotic `RUSTFLAGS` overrides (ANSSI DENV-* rules);
* reproducibility: pinned toolchain (`rust-toolchain.toml`), `--locked` in CI;
* verify that debug/test features (`cfg(test)`, feature-gated bypasses) cannot end up in production builds;
* **feature-configuration risk — "tested one configuration, shipped another":** Cargo features activate different code across normal deps, build deps, proc macros, platform targets, tests, and examples, and default tooling (tests, clippy, docs) exercises only default features unless told otherwise. Inspect resolved features with `cargo tree -e features` on key packages, and test the feature combinations you actually ship. If features are mutually exclusive, replace a single `--all-features` run with an explicit matrix of supported combinations.

---

## 13. CI pipeline and review process

### Layer 1 — automated, every PR

```bash
cargo fmt --all -- --check

cargo clippy \
  --workspace \
  --all-targets \
  --all-features \
  -- -D warnings

cargo test --workspace --all-targets --all-features

cargo audit
cargo deny check
cargo vet check          # if vet is adopted
```

`--all-targets` covers the library, binaries, examples, tests, and benches.

### Layer 2 — nightly / scheduled

```bash
cargo +nightly miri test        # unsafe modules
cargo fuzz run <target>         # ongoing campaigns per parser
```

Plus: sanitizers on integration tests, Rudra, cargo-geiger diff tracking, and — if using cargo-vet — periodically shrinking the exemptions list via `suggest`/`diff`/`certify` and importing fresh audits from trusted orgs, so "temporarily exempted" doesn't become permanent.

### Release gate

```bash
cargo auditable build --release   # embed SBOM into the binary
cargo audit bin ./target/release/<binary>   # scan the shipped artifact
```

Plus manual sign-off on any unsafe/FFI/crypto/sandbox-boundary changes since the last release.

### Layer 3 — human review

Mandatory second reviewer with unsafe expertise for: unsafe diffs, FFI changes, new dependencies, crypto, parsers of untrusted input. Kani harnesses for functions where being wrong is unacceptable.

**Routing rule:** any PR touching `unsafe`, FFI, `Cargo.toml`/`Cargo.lock`, crypto, or an untrusted-input parser automatically requires a security reviewer (CODEOWNERS).

---

## 14. Merge blockers and red flags

Do not accept a change if any of the following is present:

| Finding | Requirement |
| --- | --- |
| New `unsafe` without a safety proof | Block |
| Public `unsafe fn` without `# Safety` | Block |
| Attacker input reaches `unwrap`, indexing, or panic | Fix or prove unreachable |
| Allocation/recursion/queue without bounds | Add bounds |
| Shell command built by concatenation | Direct executable + separate args |
| Authorization performed after the side effect | Restructure the flow |
| New `build.rs` or proc macro unreviewed | Supply-chain review |
| FFI signature verified "from memory" only | Match against the actual header/API |
| Dependency feature change untested | Add a feature matrix |
| New parser without negative/fuzz tests | Add testing |

**Red flags — stop the review and talk to the author:**
`transmute`; `unsafe impl Send/Sync`; `mem::forget` outside `ManuallyDrop` patterns; `static mut`; `#[allow(...)]` without a justification comment; `as` casts in codecs; custom allocator or custom crypto; new `Ordering::Relaxed`; a guard held across `.await`; a hasher swap on attacker-controlled keys.

---

**Core principle:** safe Rust shrinks the memory-corruption surface, but security review must still verify trust boundaries, resource bounds, authorization, panic paths, the dependency chain, and the correctness of every unsafe abstraction.

---

## 15. Calibration: real-world failure modes

Each incident below maps to a section of this document. Use them as review-training material and as evidence when prioritizing reviewer time. (Advisory IDs verifiable at rustsec.org / the linked sources.)

| Incident | Failure mode | Review lesson (section) |
| --- | --- | --- |
| `flatbuffers` RUSTSEC-2019-0028 | Safe API reinterpreted arbitrary bytes as `bool` — validity violation | Validity checks in §2.3; "safe API, unsound internals" is the canonical unsafe-review target |
| `tracing` RUSTSEC-2023-0078 | Potential stack use-after-free via an unsound `mem::forget` pattern | `mem::forget` red flag (§14); lifetime/destructor edge cases (§2.3) |
| `rkyv` RUSTSEC-2026-0122 | Panic during collection cleanup → UAF/double free | Panic safety is memory safety (§2.3 item 8, §7) |
| `metacall` RUSTSEC-2026-0156 | Safe API handed Rust stack memory to C, which later freed it — bad-free | FFI ownership protocol (§7): allocator symmetry, lifetime across the boundary |
| `rustls-webpki` RUSTSEC-2026-0099 | Name-constraints logic accepted wildcard assertions it should reject | Pure security-logic bug in memory-safe code (§1, §6): soundness review ≠ security review |
| `hickory-recursor` RUSTSEC-2026-0106 | DNS cache poisoning via incorrect zone-context handling | Protocol/trust-boundary logic (§1, §9); safe Rust doesn't review your protocol for you |
| Deno RUSTSEC-2025-0138 | Permission bypass via SQLite `ATTACH DATABASE` | Authorization at the side effect (§6): capability checks must cover indirect paths |
| Deno GHSA-m4pq-fv2w-6hrw | Permission-prompt spoofing via ANSI stripping / path normalization mismatch | Normalization differentials (§5, §9): two components disagreeing on the same string is a vulnerability class |
| Wasmtime Winch GHSA-xx5w-cvp6-jv83 | Guest Wasm accessed host memory outside the sandbox (codegen backend bug) | Sandbox boundaries need dedicated review beyond language guarantees; note Wasmtime's defense-in-depth (Miri, cargo-vet, fuzzing, formal verification) still shipped this — layers reduce, not eliminate |
| crates.io malware postmortem (2023) | Typosquatted crates with exfiltrating `build.rs` | Build-time code execution is an attack surface (§11.3) |
| Cargo CVE-2026-5222/5223 | Symlinks in third-party-registry tarballs overwrote cached sources of other crates | The toolchain is in the threat model (§11.3); reviewed code ≠ compiled code |

The pattern across incidents: findings cluster at **unsafe abstraction boundaries, FFI, panic safety, feature/configuration interactions, protocol and authorization logic, and build/dependency trust** — which is exactly where this document tells reviewers to spend their time.

---

## 16. References

* The Rust Reference — [Behavior considered undefined](https://doc.rust-lang.org/reference/behavior-considered-undefined.html) · [Behavior not considered unsafe](https://doc.rust-lang.org/reference/behavior-not-considered-unsafe.html) · [The unsafe keyword](https://doc.rust-lang.org/reference/unsafe-keyword.html)
* The Rustonomicon — [Safe/Unsafe interaction](https://doc.rust-lang.org/nomicon/safe-unsafe-meaning.html) · [Exception safety](https://doc.rust-lang.org/nomicon/exception-safety.html) · [Send and Sync](https://doc.rust-lang.org/nomicon/send-and-sync.html)
* ANSSI Secure Rust Guidelines — https://anssi-fr.github.io/rust-guide/ (DENV-*/LANG-* rules, checklist)
* Rust Unsafe Code Guidelines / t-opsem (Stacked/Tree Borrows)
* Clippy — [lint index](https://rust-lang.github.io/rust-clippy/master/index.html) · [usage guidance on restriction lints](https://doc.rust-lang.org/clippy/usage.html)
* RustSec Advisory Database — https://rustsec.org/ (cargo-audit)
* cargo-vet book (Mozilla) — https://mozilla.github.io/cargo-vet/ (safe-to-run / safe-to-deploy criteria)
* Google rust-crate-audits, auditing_standards.md — https://github.com/google/rust-crate-audits (ub-risk levels, delta audits)
* Cargo Scan (arXiv 2602.06466) — effect-based dependency auditing
* Miri — https://github.com/rust-lang/miri · Kani — https://model-checking.github.io/kani/
* Rust Fuzz Book — https://rust-fuzz.github.io/book/cargo-fuzz.html
* The Cargo Book — [Build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html) · [cargo tree](https://doc.rust-lang.org/cargo/commands/cargo-tree.html) · [workspace.lints](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-lints-table)
* Chromium — [Auditing Third Party Crates](https://google.github.io/comprehensive-rust/chromium/adding-third-party-crates/reviews-and-audits.html) (concise per-crate checklist)
* Sanitizers — [rustc-dev-guide](https://rustc-dev-guide.rust-lang.org/sanitizers.html) · OSS-Fuzz [Rust integration](https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/) · [rust-fuzz trophy case](https://github.com/rust-fuzz/trophy-case)
* "Do not run any Cargo commands on untrusted projects" (Shnatsel) — and rustsec/rustsec#1342 on cargo-audit inheriting the problem
* ZhangHanDong/rust-code-review-guidelines (RCRG)
* iAnonymous3000/awesome-rust-security-guide

**Case studies / postmortems:**

* crates.io — [User Uploaded Malware postmortem](https://blog.rust-lang.org/inside-rust/2023/09/01/crates-io-malware-postmortem/) (2023)
* Cargo — [CVE-2026-5223 advisory](https://blog.rust-lang.org/2026/05/25/cve-2026-5223/) (symlink cache poisoning, fixed in 1.96.0)
* Wasmtime — [April 2026 security advisories overview](https://bytecodealliance.org/articles/wasmtime-security-advisories)
* Firefox — cargo-vet operational in mozilla-central, CI rejects failing vet checks
* Public professional audit reports as format references: Cure53 (Threema Rust crypto libs, 2022), OpenZeppelin (ink!/cargo-contract, Stylus Rust SDK)

**Academic:**

* RustBelt (Jung et al.) — formal soundness foundations for unsafe-internals abstractions
* "Understanding Memory and Thread Safety Practices and Issues in Real-World Rust" (PLDI 2020) — empirical baseline: 850 unsafe usages, 170 bugs
* "A Closer Look at the Security Risks in the Rust Ecosystem" (TOSEM 2023) — 433-vulnerability dataset
* "A Study of UB Across Foreign Function Boundaries in Rust Libraries" (arXiv 2404.11671) — FFI-crossing UB in dozens of libraries
* PinChecker (arXiv 2504.14500) — unsound safe abstractions of pinning APIs
* "Targeted Fuzzing for Unsafe Rust Code" (arXiv 2505.02464) — instrumentation focused on unsafe regions
* Miri (POPL 2026, doi 10.1145/3776690) — what Miri guarantees and what it doesn't
* Cargo Scan / "Auditing Rust Crates Effectively" (ESOP 2026, arXiv 2602.06466) — effect-based audit-surface reduction
