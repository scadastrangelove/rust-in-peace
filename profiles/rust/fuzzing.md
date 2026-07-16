# Fuzzing escalation for Rust security targets

The detector table lists cargo-fuzz as one slot. In practice, *reaching* a bug is
a staircase — cheapest rung first. A blind panic-fuzzer finds the shallow bugs in
minutes with zero harness work; you only pay for coverage-guided + sanitizer +
native-instrumentation depth once the cheap net comes back clean. This is the
escalation a target's `reattack_harness` should climb.

The methodology below is distilled from a real pre-deploy hardening campaign on a
production Rust engine that **replaces a C library and runs in-process inside a
host process** — where a scanner panic is a host-process crash. That is exactly
the FFI threat `scan-extras.txt` §7 describes, made concrete: the campaign found
and fixed one real panic and otherwise came back clean across billions of
executions. (Numbers below are illustrative of the *shape* of the effort.)

**Automating find → fuzz:** turning a graded static finding into a reproducing
harness of the right rung is [`find-to-fuzz.md`](find-to-fuzz.md) (CWE/capability
→ [`harness-templates/`](harness-templates/) → agent-bound → compile+smoke
validated). This page is the *menu* of rungs; that page is how a finding gets
dispatched to one.

## The staircase

### Stage 1 — blind panic-fuzz (stable Rust, minutes, no harness)
A ~40-line `bin` that throws mutated bytes at the target's public entry point
inside `catch_unwind` and records any input that unwinds. No nightly, no coverage
instrumentation, no sanitizer. **Highest ROI rung:** in the reference campaign a
blind run over the parser entry point (~10⁸ executions) surfaced the one real bug
in the whole effort — a char-boundary panic on malformed UTF-8 — before a single
coverage harness was written.
- Seed from **real inputs** (see *Domain-specific corpus*), mutate (bit-flip,
  truncate, extend, header/field-smash), replay.
- `catch_unwind` here is the *fuzzer's detector*, not a production shield. The
  point is to find the panic and fix it. In shipped code, `catch_unwind` is a
  net, not a fix — a caught panic is still a reported bug.

### Stage 2 — FFI ABI fuzz (guard-page + ASan) — *capability-gated*
**Only when the target has an inbound C ABI** (`capabilities.md`
`inbound_c_abi: yes` — a C ABI that C code calls *into*). On a pure-Rust target
there is no such boundary and the type system already rules out the bugs this
rung hunts, so it is skipped, not run as a borrowed step. When it does apply —
the canonical **Rust-replacing-a-C-library** case — the C ABI is its own attack
surface: wrong lengths, non-NUL-terminated buffers, double/idempotent destroy,
concurrent handle lifecycle. Drive the `extern "C"` entry points from a C harness
built with `-fsanitize=address` and a guard page *after* the buffer, so an
off-by-one read faults immediately instead of silently succeeding. (russcan today
is `inbound_c_abi: no` — Stage 2 is a deliberate skip until its libhs-compat shim
lands; see [`capabilities.md`](capabilities.md).)

### Stage 3 — coverage-guided (cargo-fuzz + AFL++)
Now spend the harness cost. `cargo-fuzz` (libFuzzer, real Rust `sancov`) over the
Rust entry point; AFL++ over the C ABI. Resume from the persisted corpus; run for
CPU-hours, not seconds.

### Stage 4 — AFL with **rustc-native** sancov (the non-obvious rung)
The trap: AFL driving a *C* harness that calls into Rust instruments only the C
edges. In the reference campaign that was **14 edges** — the Rust engine was a
black box, so "tens of millions of executions, 0 crashes" looked reassuring but
exercised almost none of the Rust. Rebuilding the Rust target with rustc-native
sancov (`-Zsanitizer`/`-C instrument-coverage` + `afl-compiler-rt`) took it to
**~16,000 edges**, path-sensitive. Only then is "0 crashes over N million execs" a
statement *about the Rust code*. **If a target is Rust-behind-C, the Stage-3
C-ABI AFL edge count is not coverage of the Rust — say so, and climb to Stage 4.**

## A different axis — fuzz the trait impl, not the bytes

The staircase above fuzzes *data*. But a large class of Rust memory-safety bugs
has **no byte input**: unsafe code that trusts a caller-supplied *trait
implementation* to behave. These are the patterns the Rudra analyzer (SOSP'21,
264 issues / 76 CVEs) named — and exactly where a one-pass static/LLM review is
weakest:

- **Higher-order invariant** — unsafe code trusts `Iterator::size_hint` /
  `ExactSizeIterator::len` / `Ord` / `Borrow` to tell the truth. A `size_hint`
  that under-reports drives an OOB `ptr::write`.
- **Panic safety** — unsafe code left in a temporarily-broken state (ownership
  duplicated by `ptr::read`, `set_len` past the initialized region) when a user
  callback (`Clone`, `Drop`, the iterator's `next`) panics → double-free /
  drop-of-uninit.
- **Send/Sync variance** — `unsafe impl Send/Sync` over a generic with no
  `T: Send/Sync` bound → cross-thread race.

You reach these by fuzzing the **impl**: supply an adversarial `Iterator` whose
`size_hint` lies, a `Clone`/`next` that panics on the Nth call, an `Ord` that is
inconsistent (parametrize the hostile behaviour with `Arbitrary`), and drive the
target's generic API — **under Miri**, the UB oracle. A `ptr::write` past the
buffer is *silent* to a plain panic-fuzzer (no panic, no crash in a `Copy`-elem
container) but Miri flags it precisely. This is the `unsafe_trait_trust` /
`unsafe_generic_soundness` capability in `capabilities.md`, and on a
soundness-heavy target it is the high-yield rung — byte-fuzzing has no surface
there.

> Validated: a ~15-line `Iterator` whose `size_hint()` returns `(0, Some(0))`
> while yielding one element, fed to `SmallVec::insert_many` at inline capacity,
> reproduced the RUSTSEC-2021-0003 class defect **in seconds** — a bug a one-pass
> blind static review had scored CLEAN. Byte-fuzzing could never reach it (no
> bytes); Miri turns the reproduction into a precise UB report.

## Domain-specific corpus (per threat model)

A fuzz corpus is only as good as its seeds, and the right seeds come from *what the
target actually parses* and *who controls it*. Do the trust-boundary analysis
first (the same one `/triage` uses), then seed each surface:

- **Seed from real, valid artifacts** the target consumes — checked-in fixtures,
  captured production inputs — so the mutator starts *inside* the structure and
  reaches deep states. Random bytes bounce off the first length check and never
  exercise the interesting code.
- **One corpus per input surface, weighted by trust.** The attacker-controlled
  surface (network/user bytes) is the live target; an operator-controlled surface
  (a compiler-emitted artifact, a signed blob, an internal-only database) is
  latent hardening — fuzz it too, but rank findings accordingly. An operator-only
  panic is a robustness bug, not a live vuln (matches `fp-rules.txt` R2).
- **Mutate structurally, not just bit-flips.** For a parsed container, smash the
  header fields, offsets, and counts specifically — that's where "integrity ≠
  bounds" bugs live (`scan-extras.txt`, deserialization section): a length/offset
  that passes a CRC but points out of bounds, a count that drives an eager
  allocation before validation.

## Cross-cutting

- **Corpus is a regression suite.** Persist it; replay every entry per-PR as a
  fast `cargo test`-speed check. A crash found once must never return.
- **Cadence.** Per-PR: blind smoke + corpus replay. Nightly: resume cargo-fuzz +
  AFL sancov from corpus (CPU-hours). Pre-release: long soak + Miri / TSan.
- **Reproducibility.** Pin the toolchain (exact nightly, LLVM, AFL++ build) in the
  target's Dockerfile / runbook; long runs in a detached session, resumed from
  `out/`.
- **`catch_unwind` is a net, not a fix** — everywhere. A caught panic is a
  reported bug, not a closed one.

## Worked example — the `russcan` target

`targets/russcan/` is a Rust literal-matching engine that replaces a C library and
loads a serialized database — the exact "Rust replacing a C library" class Stage 2
and Stage 4 are written for. Its two surfaces, their trust boundary, and their
seeds:

| Surface | Entry point | Trust boundary | Seed corpus |
|---|---|---|---|
| **DB parse** | `Database::load(&bytes)` | operator-controlled → **latent**, but the whole "crafted-DB" bug class lives here | the checked-in `.db` fixtures; mutate header fields / offsets / counts |
| **Scan** | `db.scan_block(buf, …)` | **attacker-controlled → live** | the `.corpus` files + random / edge-length buffers |

The Stage-1 blind harness over both surfaces ships in the target as the
`panic_fuzz` bin (seeded from the fixtures, structural + length mutations). It is
the cheap first net; Stage 3/4 (cargo-fuzz over `Database::load`, AFL + rustc
sancov) run from the target's Dockerfile, which already installs cargo-fuzz and a
nightly toolchain.

## Sanitizer rungs beyond ASan (the residual-named oracles)

The staircase above is horizontal — cheapest *coverage* first. There is a second,
vertical axis: **which oracle is even capable of seeing the bug**. ASan is the
default and it is blind to whole classes. When a cheaper rung comes back clean,
the finding's **residual reason** (the vocabulary in
[`find-to-fuzz.md`](find-to-fuzz.md) §5) names *which oracle to climb to* — a
clean run under the wrong oracle is not a clean finding, it is an
*uncharacterized* one. These are the rungs the rust-mizan corpus named as its
own residuals.

### MSan — uninitialized reads ASan cannot see (residual: **needs-MSan**)
ASan instruments the *allocator* — it catches out-of-bounds and use-after-free,
but a read of **validly-allocated-but-never-written** memory is, to ASan, a
perfectly legal load. That is rust-mizan **0027**: an uninitialized read that a
full ASan campaign passes clean and that only **MemorySanitizer** flags. Rebuild
the target with `-Zsanitizer=memory` on nightly, which requires `-Zbuild-std`
(the standard library must itself be MSan-instrumented or every `std` call is a
false "uninitialized" report). The `[unstable] build-std` + `RUSTFLAGS` wiring is the
[`fuzz-Cargo.msan.toml`](harness-templates/fuzz-Cargo.msan.toml) variant of the
base [`fuzz-Cargo.toml.template`](harness-templates/fuzz-Cargo.toml.template) (adds
`-Zbuild-std` + the `-Zsanitizer=memory` `RUSTFLAGS`), not a second copy of the
boilerplate.
- **GOTCHA (`--privileged` / ASLR).** MSan's shadow-memory mapping needs a
  predictable address space; under Docker's default seccomp the `personality`
  syscall that disables ASLR is blocked, and MSan aborts at startup. Run the MSan
  image `--privileged` (or at minimum `--security-opt seccomp=unconfined
  --cap-add SYS_PTRACE`). This is the single most common reason an MSan run
  "doesn't reproduce" — it never actually started.
- The dispatch key: [`index_arbitrary`](harness-templates/index_arbitrary.rs) is
  the right *harness* for a CWE-908 uninitialized read (feed the length/op
  stream — see its own header note), but its sanitizer must be swapped ASan→MSan.
  Same bytes, different oracle.

### TSan / loom — data races and Send/Sync (capability: `concurrency_async`)
libFuzzer alone will not find a data race: a race is a property of *interleaving*,
not of input bytes, so a single-threaded fuzz run over billions of executions
sees nothing. Two oracles apply, and they are complementary:
- **TSan** (`-Zsanitizer=thread`) instruments real threads and reports an actual
  observed race — good for a concrete `unsafe impl Send`/`Sync` that a driver can
  exercise with genuine cross-thread sends.
- **loom** *model-checks* the interleaving space exhaustively for a bounded thread
  count — good for a lock-free/atomic algorithm where the racy schedule is rare
  and TSan would need luck to hit it.

Drive both from the
[`threaded_driver.rs`](harness-templates/threaded_driver.rs) harness: it spawns the adversarial
cross-thread pattern (send a `!Send` `T`, concurrent handle lifecycle) that the
`concurrency_async` row in [`capabilities.md`](capabilities.md) gates. Note the
split from the *soundness* case: an unsound `unsafe impl Send/Sync` with **no**
live racing caller is proven by the compiler
([`sendsync_compileproof`](harness-templates/sendsync_compileproof.rs),
compiles ⇒ unsound) — TSan/loom are for when there **is** a caller and you want
the race itself, not just the unsound variance.

### FFI-ASan — format string / FFI-into-C (residual: **asan-on-C**)
When Rust calls *into* a C dependency (`outbound_ffi`, a `*-sys` crate) the bug
can live on the C side of the boundary — a format string reaching a C `printf`
family call (CWE-134), an OOB in the C library itself. A Rust-only ASan build
does **not** instrument that C code: the C object files were compiled by the
`*-sys` build script with their own flags, and your `RUSTFLAGS` never reach them.
The residual reason is **asan-on-C**: the fix is to rebuild the C dependency
with `CC`/`CFLAGS=-fsanitize=address` so ASan's redzones and interceptors cover
the native code too. (The full playbook is
[`ffi_asan.md`](harness-templates/ffi_asan.md).)
- This is rust-mizan **0033**: a format string into **libsqlite3-sys**, whose
  build script **breaks under `CFLAGS=-fsanitize=address`** — the amalgamation's
  configure/feature probes miscompile or the link fails when the sanitizer flag
  is injected globally. The pre-build fix: build the ASan-instrumented C
  dependency **separately and first**, pinning the sanitizer flags to that one
  crate's compile — do not let `CFLAGS` leak into the whole cargo build. A blind
  attempt to `export CFLAGS=-fsanitize=address` for the workspace reproduces
  0033's build break, not its bug.

### Grammar / dictionary — structure-gated parsers (residual: **grammar-gated**)
A deep-structure parser (magic + length + frame + checksum gates) defeats *both*
blind and coverage-guided byte fuzzing: random and mutated bytes bounce off the
first gate and never reach the vulnerable deep state. Coverage guidance does not
save you here — the edges past the gate are unreachable without a structurally
valid prefix, so the fuzzer has no gradient to climb. This is rust-mizan
**0040**: an **ID3 / synchsafe** structure-gated parser that both blind and
coverage fuzzing missed. The rung is a **grammar/dictionary** harness:
`#[derive(Arbitrary)]` over the format's AST so every generated input is
valid-by-construction and mutation happens *in the structure*, plus a libFuzzer
`-dict=` of the format's magic bytes and tag keywords. The skeleton for this is
the [`grammar_parser.rs`](harness-templates/grammar_parser.rs) template (named by
[`capabilities.md`](capabilities.md)'s `structure_gated` sub-signal). This is the same rung the
`structure_gated` sub-signal in [`capabilities.md`](capabilities.md) tells the
dispatcher to **jump straight to** after a blind pass fails, instead of burning
the whole budget on raw bytes.

> The through-line: each of these is a rung you climb **only when the residual
> reason names it** — you do not run MSan, TSan, FFI-ASan, and grammar on every
> target. The cheaper rung runs first; its clean result plus the finding's
> residual vocabulary (`needs-MSan` / `asan-on-C` / `grammar-gated` /
> `address-space-only`) is the routing signal. `address-space-only` (0040's
> sibling residual — a bug only at >4 GiB / 32-bit, [`find-to-fuzz.md`](find-to-fuzz.md)
> §5) climbs to **nothing**: it is a real defect out of fuzz scope on a 64-bit
> host, reported not chased.

## Tamm execution matrix

Each oracle is a distinct toolchain, and most need a distinct container image
(different nightly features, different privilege, an ASan-compiled C world).
The matrix below is what CI selects from — **the image is chosen per
finding-class**, from the sanitizer the dispatch table
([`find-to-fuzz.md`](find-to-fuzz.md) §1) assigned to that finding's CWE/capability.

| oracle | image | invocation | notes / privilege |
|---|---|---|---|
| **ASan** (unprivileged, cargo-fuzz default) | `russcan-fuzz:nl` | `cargo +nightly fuzz run <target> -- -rss_limit_mb=4096` | the default rung; OOB / UAF / panic. No special privilege. |
| **MSan** | `russcan-msan:nl` | `cargo +nightly fuzz run <target> -Zbuild-std --target <triple>` with `RUSTFLAGS=-Zsanitizer=memory` ([`fuzz-Cargo.msan.toml`](harness-templates/fuzz-Cargo.msan.toml)) | **`--privileged`** — MSan shadow mapping needs ASLR off; blocked by default seccomp (the `personality` syscall). Without it the run never starts. |
| **TSan / loom** | `russcan-tsan:nl` | TSan: `cargo +nightly fuzz run <t>` with `RUSTFLAGS=-Zsanitizer=thread`; loom: `RUSTFLAGS=--cfg loom cargo test` over [`threaded_driver.rs`](harness-templates/threaded_driver.rs) | `concurrency_async` only. loom is a bounded exhaustive model-check (a test run), not a fuzz run. |
| **Miri** | `mizan-miri:nl` | `cargo +nightly miri run` (or `miri test`) over [`adversarial_impl`](harness-templates/adversarial_impl.rs) | **UB oracle, no fuzz** — Stacked-Borrows / drop-of-uninit for the trait-trust & soundness classes. No sancov, no corpus. |
| **FFI-ASan** | ASan-compiled C image (per-`*-sys`, e.g. `russcan-ffi-asan:nl`) | build the C dep with `CC`/`CFLAGS=-fsanitize=address` **first**, then `cargo +nightly fuzz run` | **pre-build the broken C deps** — 0033's libsqlite3-sys breaks under a global `CFLAGS`; pin the sanitizer flags to that one crate. |
| **compile-proof** | any (`russcan-fuzz:nl` is fine) | `cargo +nightly build --bin proof` (or `cargo test`) over [`sendsync_compileproof`](harness-templates/sendsync_compileproof.rs) | **no run** — compiles ⇒ unsound. The build *is* the result; nothing to execute or reproduce. |

CI dispatches the image from the finding's sanitizer field: the
`reattack` stage reads `gates_for(cap).sanitizer` (per
[`capabilities.md`](capabilities.md)) and the CWE→oracle row in
[`find-to-fuzz.md`](find-to-fuzz.md) §1, and picks the matching image — it does
not run every image against every finding.

**"0 crashes" is only meaningful once the RIGHT oracle ran.** A clean ASan run on
an uninitialized-read finding (residual `needs-MSan`) is **uncharacterized, not
clean** — ASan is structurally blind to that bug, so its silence carries no
information. Same for a format-string finding whose C dep was never
ASan-compiled (`asan-on-C`), or a structure-gated parser blind-fuzzed without a
grammar (`grammar-gated`). The residual reason
([`find-to-fuzz.md`](find-to-fuzz.md) §5) is the gate: a run is "clean" only if
the oracle it ran under is *capable* of seeing the finding's class. Report the
residual with its reason — a no-crash under the wrong oracle is a capability gap
to close (climb the rung), never a pass.
