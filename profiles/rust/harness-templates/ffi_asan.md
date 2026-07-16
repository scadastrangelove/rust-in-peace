# ffi_asan — ASan across an FFI boundary into un-instrumented C

For a memory bug — classically a **format string (CWE-134)** — that lives in a
**C dependency reached through FFI**, not in the Rust. cargo-fuzz's ASan
instruments the *Rust* only; a `*-sys` crate's bundled C is compiled by its build
script as an ordinary, un-instrumented object. So the bytes flow Rust → C, the C
does the unsafe thing (`printf(user_string)`, an OOB in a C parser), and the run
comes back **clean** — ASan never watched that memory. This is not a byte-input
template; it is a **build recipe + oracle** that layers on top of
[`byte_parser.rs`](byte_parser.rs) (which supplies the `%`-directive input) so the
existing sanitizer actually covers the C.

> **rust-mizan 0033** — a format string passed into `libsqlite3-sys`. The Rust
> harness built and ran under cargo-fuzz ASan and reported nothing: the tainted
> string reached `sqlite3`'s C, which was never compiled with a sanitizer. "0
> crashes" was a coverage artifact, not a verdict — the same shape as 0040
> (structure-gated ID3/synchsafe parser both blind and coverage fuzzing bounced
> off) and 0027 (uninit read ASan is blind to, needs MSan). The bug is real; the
> *tool* was pointed at the wrong object.

Capability: [`capabilities.md`](../capabilities.md) `outbound_ffi` (Rust calls
**into** C — `extern "C" { … }` blocks, `*-sys` deps, `#[link]`). Dispatched from
the CWE-134 row of [`find-to-fuzz.md`](../find-to-fuzz.md).

## The core problem, stated once

cargo-fuzz builds the Rust crate graph with `-Zsanitizer=address`. That flag is a
**rustc** flag. It does nothing to the C that a `*-sys` build script compiles with
`cc`/`cmake`. Unless *that* C is independently compiled `-fsanitize=address`, the C
half of the address space is unwatched — reads/writes there don't trip ASan's
shadow memory, and a `%n` that corrupts a C stack frame just crashes (or worse,
doesn't) with no ASan report. Two runtimes must also **agree**: the C ASan runtime
and the Rust ASan runtime have to be the same one, or you get duplicate-runtime
aborts or shadow-scale mismatches at load.

## Recipe A — compile the C with ASan (the real fix)

Make the `*-sys` build script emit ASan-instrumented C, using the **same
clang/LLVM as the Rust nightly's ASan** so the two runtimes are one.

```sh
# Pin ONE clang that matches the nightly's LLVM (check `rustc +nightly -vV` →
# LLVM version, install the matching clang). Runtimes must agree.
export CC=clang
export CXX=clang++
export CFLAGS="-fsanitize=address -fno-omit-frame-pointer"
export CXXFLAGS="-fsanitize=address -fno-omit-frame-pointer"

cargo +nightly fuzz build FUZZ_TARGET
```

`cc-rs`-based build scripts honour `CC`/`CFLAGS`; `cmake`-based ones honour
`CXX`/`CXXFLAGS` too. When it works, the bundled C object carries ASan
instrumentation, the runtimes match, and the `%`-directive corpus from
`byte_parser.rs` now faults *inside the C* with a real ASan report. Verify it
actually took before trusting a run — see [What "clean" means](#what-clean-means-here-and-when-it-lies)
point 1 (`nm`/`readelf` for `__asan_*` resolving into the C object).

## The 0033 gotcha — this exact recipe breaks libsqlite3-sys

`CFLAGS=-fsanitize=address` did **not** just work on `libsqlite3-sys`. The build
died with:

```
error: failed to run custom build command for `libsqlite3-sys vX.Y.Z`
  ... failed to get libsqlite3-sys-17
```

The bundled-`sqlite3.c` build path (the `bundled` feature) compiles a
feature-detection probe / amalgamation step that does not survive being handed
`-fsanitize=address` through `CFLAGS` — the ASan-instrumented probe binary fails
its own link/run and the script aborts before the crate is ever built. Blanket
`CFLAGS` is the wrong layer for a `*-sys` crate that runs its own compile probes.

### Fix — pre-build the C dependency separately, then point the sys crate at it

Compile a standalone ASan `libsqlite3` **outside** the build script, then tell the
sys crate to link *that* instead of bundling its own:

```sh
# 1. Fetch the SAME sqlite version the sys crate bundles (match it — a version
#    skew changes the ABI the -sys bindgen output expects).
#    (amalgamation: sqlite3.c + sqlite3.h)

# 2. Compile it ONCE, with ASan, with the SAME clang as the Rust nightly's ASan.
#    The -D feature defines here MUST match the ones the sys crate's bindgen
#    assumed for that version — a mismatch is a silent ABI skew, not a link error.
clang -fsanitize=address -fno-omit-frame-pointer -fPIC \
      -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1 \
      -c sqlite3.c -o sqlite3.o
#    static archive …
ar rcs "$PWD/asan-sqlite/libsqlite3.a" sqlite3.o
#    … or a shared object if you prefer dynamic linking:
# clang -fsanitize=address -shared -fPIC sqlite3.c -o asan-sqlite/libsqlite3.so

# 3. Point libsqlite3-sys at the pre-built lib instead of bundling.
#    DO NOT enable `bundled` here — bundled forces the broken in-script compile.
export SQLITE3_LIB_DIR="$PWD/asan-sqlite"    # dir containing libsqlite3.a/.so
export SQLITE3_STATIC=1                       # link the .a statically (omit for .so)

# 4. Now the fuzz build compiles ONLY the Rust with ASan and links the
#    already-ASan C archive — one runtime, both halves instrumented.
export CC=clang CXX=clang++                    # still needed for the link step's runtime
cargo +nightly fuzz build FUZZ_TARGET
```

`SQLITE3_LIB_DIR` + `SQLITE3_STATIC` are `libsqlite3-sys`'s own documented link
overrides (its build script reads them when `bundled` is off) — no build-script
edit required. If a `*-sys` crate lacks such env knobs, the fallback is a
**`build.rs` link override** in the fuzz crate:
`println!("cargo:rustc-link-search=native=ASAN_DIR");
println!("cargo:rustc-link-lib=static=sqlite3");` (with `ASAN_DIR` the absolute
path to the pre-built archive) and drop the sys crate's `bundled` feature so it
does not also try to link its own copy. The rule generalizes: **any `*-sys` crate
that runs its own compile probes wants the C pre-built with ASan out-of-band and
linked in, not `CFLAGS`-injected through its build script.**

### The `--features` trap (a silent build error read as "no crash")

Feature selection is a **layering** mistake that hid the 0033 bug for a whole run.
Enabling the sqlite trace/bundled features on the **fuzz** crate —

```sh
cargo +nightly fuzz build FUZZ_TARGET --features trace,bundled   # WRONG LAYER
```

— does not do what it looks like. `--features` on `cargo fuzz` applies to the
**fuzz** package, which has no `trace`/`bundled` features; depending on cargo
version this either errors or silently no-ops, so the C is built **without** the
code path (or without ASan) you thought you enabled. The feature belongs on the
**dependency**, declared in the fuzz crate's `Cargo.toml`:

```toml
# fuzz/Cargo.toml — features go on the DEP, not passed to `cargo fuzz`.
# (boilerplate: fuzz-Cargo.toml.template)
[dependencies]
libsqlite3-sys = { version = "0.28", default-features = false, features = ["trace"] }
#   NOTE: NOT "bundled" — bundled re-triggers the broken in-script ASan compile.
#   We link the pre-built ASan archive via SQLITE3_LIB_DIR instead.
```

The failure mode is the nastiest kind: the harness builds, runs, exits `0`, and
you record "clean" — when in fact the vulnerable path was never compiled in. Treat
a `*-sys` FFI harness's **feature layering** as part of the oracle: confirm the C
symbol you are targeting is actually linked (`nm`/`objdump` the fuzz binary for
it) before trusting a clean run.

## Recipe B — fallback oracle when you *cannot* ASan-compile the C

Some C deps resist ASan entirely: no source (a prebuilt `.so`), a build system
that won't take the flag, a runtime mismatch you can't reconcile. Then you cannot
watch the memory — so make the **bug announce itself** instead. CWE-134 has a
convenient tell: hostile format directives.

Feed the C the directives that turn a format-string bug into an observable crash,
and detect the crash rather than the corruption:

- **`%n`** — writes the byte-count-so-far through a pointer argument that doesn't
  exist. Against a real `printf(user)` this writes to an attacker-influenced /
  garbage address → SIGSEGV, or on modern glibc/`_FORTIFY_SOURCE` a hard abort:
  `*** %n in writable segment detected ***` (`__fortify_fail`). Either is a
  positive signal the string reached a `printf`-family sink unfiltered.
- **`%s` × many** — dereferences successive stack slots as `char*`; several in a
  row reliably walks off into an unmapped page → SIGSEGV (a read oracle that
  doesn't need `%n`'s write).
- **`%x` × many / `%p` × many** — leak stack words; won't crash, but combined with
  a canary output check they *confirm the sink formats attacker bytes* even when it
  doesn't fault (a positive on "is this a format-string sink at all").

Wire it as the `byte_parser.rs` corpus plus a crash/abort detector — the fuzzer's
own SIGSEGV/abort catch is the oracle:

```rust
//! ffi_asan fallback — probe a suspected C format-string sink when the C can't be
//! ASan-compiled. Oracle: process crash / glibc %n-abort, NOT sanitizer shadow.
#![no_main]
use libfuzzer_sys::fuzz_target;

// PROBES: the tells that make a format-string bug crash if the sink is a
// printf-family call on unfiltered input.
const PROBES: &[&[u8]] = &[
    b"%n", b"%n%n%n%n",
    b"%s%s%s%s%s%s%s%s",
    b"%x%x%x%x%x%x%x%x%x%x%x%x",
    b"%p%p%p%p%p%p%p%p",
];

fuzz_target!(|data: &[u8]| {
    // Seed the mutator toward the tells: prepend a probe to the fuzzed bytes so
    // coverage-guided mutation keeps a live `%`-directive in the input.
    let mut s = Vec::with_capacity(data.len().min(4096) + 8);   // OOM cap
    s.extend_from_slice(PROBES[(data.first().copied().unwrap_or(0) as usize) % PROBES.len()]);
    s.extend_from_slice(&data[..data.len().min(4096)]);          // OOM cap

    // BIND: the Rust wrapper that forwards `s` (as a &str / CString) into the C
    // FFI sink. Use the PUBLIC path that reaches the printf-family call, exactly
    // as byte_parser.rs binds a parse entry.
    if let Ok(cs) = std::ffi::CString::new(s) {        // GOTCHA (NUL): CString::new
        let _ = TARGET_CRATE::FFI_SINK(&cs);           //   panics on interior 0x00 —
    }                                                  //   skipping is correct, not a mask.
    // No black_box read needed: the ORACLE is the crash/abort the C raises, which
    // libFuzzer reports as the failing input. On glibc, `%n`-abort surfaces as a
    // SIGABRT with `*** %n in writable segment detected ***` on stderr.
});
```

- **OOM:** cap any length you build from `data` (`.min(4096)`) and run with
  `-rss_limit_mb=4096` — the same discipline as every other template.
- **GOTCHA (NUL):** a `CString::new` sink panics on an interior `0x00`; skipping
  those inputs is correct (it masks nothing — the directive tells don't need NULs).
- **No L12 here — and why.** L12 (heap-owning element) is a *Rust-side* rule: it
  makes a dup/uninit/OOB-write in a Rust container visible to Miri/ASan. Recipe B
  builds no such container and does no Rust-side unsafe write — the corruption is
  entirely inside C and the oracle is the process crash, not sanitizer shadow. So
  L12 does not apply; if your FFI harness *does* stage the corrupting write on the
  Rust side, use [`index_arbitrary.rs`](index_arbitrary.rs) with its L12 element.
- **Limitation, state it in the residual:** Recipe B proves *reachability and
  sink-shape* (the string hits a `printf`-family call unfiltered) but not the full
  memory-corruption footprint an ASan build would characterize. Report it as
  "CWE-134 confirmed reachable via `%n`-abort; full ASan characterization blocked
  on C-side sanitizer build" — a `find-to-fuzz.md` §5 "no crash is a capability
  map" residual, with its reason.

## What "clean" means here (and when it lies)

Per [`find-to-fuzz.md`](../find-to-fuzz.md) §5, a clean FFI-ASan run is only
trustworthy once you've ruled out the three ways this template silently under-runs:

1. **The C wasn't ASan-compiled** (Recipe A never took; you got the un-instrumented
   bundled object) → verify with `nm`/`readelf` that `__asan_*` symbols are in the
   final fuzz binary and resolve into the C object, not just the Rust.
2. **The vulnerable path wasn't compiled in** (the `--features` layer trap) →
   confirm the target C symbol is linked before trusting the run.
3. **Wrong oracle for a sibling bug** — if the C bug is an *uninitialized* read
   rather than a format string, ASan is blind exactly as in rust-mizan 0027;
   MSan-on-C is the escalation, and it is even harder than ASan:
   - MSan reports a false positive for **any** un-instrumented code that writes a
     value MSan then reads, so *every* transitively-linked C must be MSan-built —
     pre-build them the same out-of-band way as Recipe A's archive.
   - On the Rust side MSan needs `-Zbuild-std` so `std` itself is instrumented
     (`cargo +nightly fuzz build --sanitizer memory -Zbuild-std`); without it the
     first call into an uninstrumented `std` allocation trips a false positive.
   - The sanitizer's shadow-memory mmap wants a relaxed sandbox — run the MSan
     fuzzer under `docker run --privileged` (or the equivalent seccomp/ASLR
     relaxation), the same constraint that bites ASan under gVisor.

   Note the MSan escalation as the residual reason rather than reporting "clean."

## See also

- [`byte_parser.rs`](byte_parser.rs) — supplies the `%`-directive input surface
  this recipe instruments; bind the same public FFI-reaching entry.
- [`index_arbitrary.rs`](index_arbitrary.rs) — use this instead if the corrupting
  write is staged on the *Rust* side of the boundary (carries the L12 element).
- [`find-to-fuzz.md`](../find-to-fuzz.md) — CWE-134 dispatch row and the §5
  "clean = capability map" residual protocol.
- [`capabilities.md`](../capabilities.md) — `outbound_ffi` (the gate); its find
  brief already flags `catch_unwind`-at-boundary and `from_raw_parts` on C ptr/len.
- [`fuzz-Cargo.toml.template`](fuzz-Cargo.toml.template) — the `fuzz/` boilerplate;
  put the `*-sys` dep's `features` **there**, not on `cargo fuzz --features`.
