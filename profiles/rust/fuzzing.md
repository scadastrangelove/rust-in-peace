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

### Stage 2 — FFI ABI fuzz (guard-page + ASan)
For the canonical target class — **Rust replacing a C library** — the C ABI is its
own attack surface: wrong lengths, non-NUL-terminated buffers, double/idempotent
destroy, concurrent handle lifecycle. Drive the `extern "C"` entry points from a C
harness built with `-fsanitize=address` and a guard page *after* the buffer, so an
off-by-one read faults immediately instead of silently succeeding.

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
