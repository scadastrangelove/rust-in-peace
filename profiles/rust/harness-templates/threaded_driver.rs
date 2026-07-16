//! threaded_driver — for the `concurrency_async` capability: a data race or an
//! unsound `Send`/`Sync` variance driven by CONCURRENT threads over a shared
//! `unsafe impl Send/Sync` type or a lock-free structure. There is no byte input
//! in the classic sense — the "input" is the thread SCHEDULE and op-sequence,
//! which the fuzzer/model-checker controls.
//!
//! Oracle: **TSan** (`-Zsanitizer=thread`) for a realistic threaded run, and
//! **loom** (`#[cfg(loom)]`, exhaustive interleaving search) for a small state
//! space — loom is the surer oracle (it explores ALL interleavings of the state
//! space it is given; TSan only reports races it happens to observe). Show both;
//! run the one the state space affords. This is the concurrency rung of
//! [`find-to-fuzz.md`](../find-to-fuzz.md) §1 (CWE-362) and the `concurrency_async`
//! row of [`capabilities.md`](../capabilities.md) (TSan / loom detector, R8/R9
//! triage).
//!
//! WHY libFuzzer alone will not find it: the byte fuzzers (`byte_parser`,
//! `index_arbitrary`) drive a SINGLE thread. A race and an unsound `Send`/`Sync`
//! have no single-threaded manifestation — no bytes reach them. This is the
//! same blind spot as rust-mizan 0040 (structure-gated, both blind AND coverage
//! fuzzing bounced off it): the wrong harness shape sees nothing, and reports a
//! false CLEAN. The capability gate exists precisely so this template runs.
//!
//! fp-rules cross-ref:
//!   R8 — soundness ≠ security, both count: an unsound `unsafe impl Send`/`Sync`
//!        (no `T: Send`/`T: Sync` bound) is a real defect even if no current
//!        caller sends the type across a thread.
//!   R9 — "we don't call that path" is NOT a false positive: a race reachable
//!        only via a specific interleaving still counts; loom proves the
//!        interleaving is reachable, which is the R9 evidence.

// no_main ONLY in the fuzz (non-loom) build: libFuzzer provides the entry point.
// Under `--cfg loom` this file is built with `cargo test`, whose libtest harness
// must emit its OWN runner `main` — an unconditional `#![no_main]` suppresses it,
// so the loom test would never run (a silent false CLEAN, the exact failure this
// template exists to prevent). Gate it on `not(loom)`.
#![cfg_attr(not(loom), no_main)]

// ===========================================================================
// TSan / threaded-test path (default build; loom OFF)
// ===========================================================================
// GOTCHA (nightly + std rebuild): TSan needs the SAME nightly toolchain as
//   cargo-fuzz AND a sanitizer-instrumented std, or it under-reports:
//     RUSTFLAGS="-Zsanitizer=thread" \
//       cargo +nightly fuzz run threaded_driver \
//       -Zbuild-std --target x86_64-unknown-linux-gnu \
//       -- -rss_limit_mb=4096
//   Or, without cargo-fuzz, a plain threaded stress test (also needs -Zbuild-std):
//     RUSTFLAGS="-Zsanitizer=thread" \
//       cargo +nightly test --target x86_64-unknown-linux-gnu -- --nocapture
//   TSan is a HAPPENS-TO-OBSERVE oracle: run the schedule many times / many
//   iterations so an actual racing interleaving is scheduled. loom (below) is
//   the exhaustive complement — prefer it when the state space is small.
#[cfg(not(loom))]
mod driver {
    use libfuzzer_sys::fuzz_target;
    use arbitrary::Arbitrary;

    // N threads, each running a fuzzed op-sequence. Cap thread count and
    // op-count so the fuzzer spends its budget on interleavings, not on
    // spawning thousands of OS threads.
    #[derive(Arbitrary, Debug)]
    enum Op {
        Send(u32),        // producer: push a heap-owning element
        Recv,             // consumer: pop + drop it (the cross-thread transfer)
        Get(usize),       // read a shared slot — the racy load
    }

    #[derive(Arbitrary, Debug)]
    struct Plan {
        // per-thread op streams; the fuzzer picks how work is split, which
        // together with the OS scheduler explores interleavings.
        threads: Vec<Vec<Op>>,
    }

    fuzz_target!(|plan: Plan| {
        // L12 (critical): the SHARED, cross-thread-transferred element MUST own
        //   heap (`Box<u32>`/`String`). A torn write or a double-drop of a
        //   `Box` is an invalid-free that TSan/Miri flag precisely; the SAME
        //   race on a bare `u32`/`Copy` element is a silent value scramble no
        //   sanitizer sees — a false CLEAN. This is the concurrency form of the
        //   adversarial_impl/index_arbitrary L12 rule.
        // GOTCHA (feature/cfg gate): the racy fast-path or the `unsafe impl
        //   Send`/`Sync` frequently lives behind a feature (`--cfg threadsafe`,
        //   `--features threadsafe`/`concurrent`). Discover and ENABLE it, or
        //   the shared type is legitimately single-threaded and this proves
        //   nothing (mirrors sendsync_compileproof's gated GOTCHA).
        let shared = std::sync::Arc::new(
            TARGET_CRATE::CONTAINER::<Box<u32>>::CONSTRUCT(),
        );

        let n = (plan.threads.len()).min(8);          // OOM/scheduler cap
        let mut handles = Vec::with_capacity(n);
        for ops in plan.threads.into_iter().take(n) {
            let me = std::sync::Arc::clone(&shared);
            handles.push(std::thread::spawn(move || {
                for op in ops.into_iter().take(4096) { // OOM cap per thread
                    match op {
                        // SHARED_SEND / SHARED_RECV: the target's lock-free /
                        // unsafe-impl transfer methods (e.g. an SPSC/SPMC ring's
                        // `push`/`pop`, or a hand-off the unsafe impl claims is
                        // Send WITHOUT a `T: Send` bound). The Box crosses the
                        // thread boundary here — the cross-thread `send` of a
                        // generic `T` the impl trusts.
                        Op::Send(v) => { let _ = me.SHARED_SEND(Box::new(v)); }
                        Op::Recv    => { if let Some(b) = me.SHARED_RECV() {
                                             std::hint::black_box(*b);       // force the read/drop
                                         } }
                        // SHARED_GET: an unsynchronized read of a shared slot —
                        // the racy load TSan flags against a concurrent Send.
                        Op::Get(i)  => { let r = me.SHARED_GET(i % 64);
                                         std::hint::black_box(r); }
                    }
                }
            }));
        }
        for h in handles { let _ = h.join(); }         // join, don't detach —
        //   a leaked racing thread outlives the iteration and poisons the next.
    });
}

// ===========================================================================
// loom path (`--cfg loom`): exhaustive interleaving model-check
// ===========================================================================
// GOTCHA (where this mod lives): the fuzz `[[bin]]` is `test = false`
//   (fuzz-Cargo.toml.template), so `cargo test` will NOT pick up a `#[test]`
//   pasted into `fuzz_targets/`. Put the loom model in the TARGET CRATE's
//   `tests/loom_<name>.rs` (or a `[[test]]`), built with `--cfg loom`. Kept here
//   in one file only so the two oracles read side by side; on binding, split it
//   out — otherwise the loom half silently never runs.
// GOTCHA (loom is STABLE, not nightly): loom is a plain library model-checker —
//   it needs NO nightly toolchain and NO sanitizer/`-Zbuild-std` (that's the TSan
//   path's requirement, not loom's). Do not carry `+nightly` over from the TSan
//   invocation.
// GOTCHA (loom needs loom's primitives): loom only sees races through ITS OWN
//   `loom::sync`/`loom::sync::atomic`/`loom::thread`/`loom::cell::UnsafeCell`.
//   The target must be built against them under `#[cfg(loom)]` (the crates that
//   support loom do exactly this: `use loom::sync::Arc` in place of `std`). If
//   the shared type uses `std` atomics/locks directly, loom is blind — build it
//   with `--cfg loom` so ITS re-exports swap in, or drive a loom-mirrored copy
//   of the unsafe core. Keep the state space TINY (2 threads, ≤3 ops each):
//   loom is exhaustive over the space you give it, so op-count blows up
//   combinatorially — this is the opposite of the TSan cap, which is about OOM,
//   not search-space size.
// GOTCHA (unexpected-cfg lint): on rustc ≥1.80 a bare `--cfg loom` warns unless
//   declared. Add `[lints.rust] unexpected_cfgs = { level = "allow", check-cfg =
//   ['cfg(loom)'] }` to the crate carrying the loom test (or a `build.rs`
//   `cargo::rustc-check-cfg=cfg(loom)`), the same way loom-supporting crates do.
//
//   Run:  RUSTFLAGS="--cfg loom" cargo test --release loom_ -- --nocapture
//   (release keeps the exhaustive search tractable; loom prints the failing
//    interleaving as a replayable schedule — the R9 "this interleaving IS
//    reachable" evidence a TSan sample can't guarantee.)
#[cfg(loom)]
mod loom_model {
    // A hand-driven 2-thread model. Unlike the TSan path this is NOT
    // fuzzer-driven — loom itself enumerates every interleaving of the fixed
    // op-pair below, so a bug that needs one specific ordering is FOUND, not
    // merely sampled.
    #[test]
    fn loom_send_recv_race() {
        loom::model(|| {
            // L12 still applies: heap-owning element so a double-drop / torn
            //   transfer is a real memory error, not a silent scramble.
            let shared = loom::sync::Arc::new(
                TARGET_CRATE::CONTAINER::<Box<u32>>::CONSTRUCT(),   // loom-built target
            );

            let p = loom::sync::Arc::clone(&shared);
            let producer = loom::thread::spawn(move || {
                let _ = p.SHARED_SEND(Box::new(0xAA));              // cross-thread send of the Box
            });

            let c = loom::sync::Arc::clone(&shared);
            let consumer = loom::thread::spawn(move || {
                if let Some(b) = c.SHARED_RECV() {                 // concurrent receive/drop
                    assert_eq!(*b, 0xAA);   // loom flags a torn/duplicated Box here
                }
            });

            producer.join().unwrap();
            consumer.join().unwrap();
            // Post-condition invariant: exactly one owner of each element across
            // ALL interleavings. loom explores them exhaustively; a double-Recv
            // or a lost Send that only some orderings expose is caught.
        });
    }
}

// ---------------------------------------------------------------------------
// UPPERCASE holes the binding agent fills:
//   TARGET_CRATE   — the crate under test.
//   CONTAINER      — the shared type with the `unsafe impl Send`/`Sync` or the
//                    lock-free structure (SPSC/SPMC ring, concurrent map/stack).
//   CONSTRUCT      — its constructor (`new`, `with_capacity(64)`, …).
//   SHARED_SEND    — the producer / cross-thread hand-off method (`push`,
//                    `send`, `enqueue`) — where the `Box<T>` crosses threads.
//   SHARED_RECV    — the consumer method (`pop`, `recv`, `dequeue`).
//   SHARED_GET     — an unsynchronized shared read, if the type exposes one.
//
// The fuzz/ project boilerplate is one file — see
//   [`fuzz-Cargo.toml.template`](fuzz-Cargo.toml.template) (add `arbitrary`, and
//   `features = ["threadsafe", ...]` if the race path is feature-gated).
//
// If the finding is a PURE `Send`/`Sync` variance with no runtime race path to
//   drive (an `unsafe impl<T> Send for C<T>` you only need to PROVE unsound),
//   the compile-proof is cheaper and surer than any run — use
//   [`sendsync_compileproof.rs`](sendsync_compileproof.rs) (oracle: the
//   compiler) INSTEAD of, or alongside, this driver. This template is for the
//   race you must actually schedule (torn write, double-drop, ABA), where a
//   compile check says nothing.
