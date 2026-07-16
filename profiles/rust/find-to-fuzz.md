# find → fuzz: turning a static finding into a reproduction

A graded static finding (a CWE + a vulnerable function/file/line) should become a
*reproducing* dynamic harness automatically. This is the pipeline's
`reattack_harness` slot, made concrete for Rust. The split that works — validated
by building 22 harnesses against the rust-mizan CVE corpus:

1. **class → template** (deterministic, code) — pick the harness skeleton + the
   right sanitizer/oracle from the finding's CWE/capability. A lookup table.
2. **template → working harness** (agent) — bind the skeleton's holes to the
   target crate's real API. This is program synthesis over unknown code; it is
   NOT table-automatable (see *Why an agent*, below).
3. **harness → validated** (deterministic, code) — `cargo fuzz build` + a short
   smoke run + replay of any known crash input. The compiler is the oracle that
   catches the agent's API mistakes; retry on failure.

The determinism lives in **dispatch and validation**, not generation. Do not
build a template engine that introspects arbitrary APIs — it loses on the long
tail an agent handles for free (private entry points, `no_std` panic handlers,
feature/cfg gates, the heap-owning-element trick).

## 1. Dispatch table — CWE / capability → template + oracle

| finding signal | template | sanitizer / oracle |
|---|---|---|
| CWE-125/787/129/193 OOB read/write/index, off-by-one; a `usize` index/len reaches an unchecked `.offset()`/`get_unchecked`/`ptr::write` | [`index_arbitrary`](harness-templates/index_arbitrary.rs) | **ASan** (cargo-fuzz default) |
| CWE-190 integer overflow feeding an allocation/index | `index_arbitrary` (feed the raw size) | **ASan** + overflow-checks (panic) |
| byte-input entry (`&[u8]`/`*const u8`/`&str`/`Read`/parser) | [`byte_parser`](harness-templates/byte_parser.rs) | **ASan** |
| CWE-416/415/908 via a caller trait impl — `size_hint`/`ExactSizeIterator::len`/`Ord`/`Borrow` feeding unsafe length; `Clone`/`Drop`/`next` panicking mid-`ptr::read`/`set_len` | [`adversarial_impl`](harness-templates/adversarial_impl.rs) | **Miri** (surest) + ASan for the heap-overflow/UAF variants |
| CWE-662 unsound `Send`/`Sync` variance | [`sendsync_compileproof`](harness-templates/sendsync_compileproof.rs) | **the compiler** (compiles ⇒ unsound) — not a fuzz run |
| CWE-908 uninitialized read (memory validly allocated) | `index_arbitrary` + [`fuzz-Cargo.msan.toml`](harness-templates/fuzz-Cargo.msan.toml) | **MSan** (`-Zsanitizer=memory -Zbuild-std`) — ASan will NOT see it |
| CWE-134 format string into a C library | `byte_parser` feeding `%`-directives | ASan **only if the C is `-fsanitize=address`-compiled** ([`ffi_asan.md`](harness-templates/ffi_asan.md)); else a `%n`/bad-ptr oracle |
| CWE-362 data race / concurrency | [`threaded_driver`](harness-templates/threaded_driver.rs) | **TSan** / loom — libFuzzer alone won't find it |
| structure-gated parser (magic/length/frame — a byte stream can't satisfy the gates) | [`grammar_parser`](harness-templates/grammar_parser.rs) | **ASan + `-dict=` grammar** (`Arbitrary` over the AST) |

The `fuzz/` project boilerplate is one file: [`fuzz-Cargo.toml.template`](harness-templates/fuzz-Cargo.toml.template).

## 2. Why an agent does the binding (not a generator)

Of 22 harnesses built against real crates, a deterministic generator would have
failed on — an agent handled all — these:
- **private vulnerable fn** → find the public wrapper that reaches it (an ID3
  parser's private `get_id3` → public `read_from_slice`).
- **`no_std` crate with its own `#[panic_handler]`** clashes with libfuzzer's
  `std` → `include!` the real source module instead of depending on the crate.
- **the bug is behind a feature/cfg** (`--features ringbuffer`, `--cfg
  threadsafe`) → the agent must discover and enable it.
- **the L12 element trick** (below) → the agent must know to pick a heap-owning
  element or the dynamic tool sees nothing.
- **non-trivial construction** — a struct with no `Default`, a FAM/`repr(C)`
  header parsed from bytes, a high-alignment element type for an alignment bug.

Give the binding agent: the finding (CWE + fn/file/line), the selected template,
and the crate. It fills the holes; the validator gates it.

## 3. Two rules the agent must not miss

- **L12 — heap-owning element.** For any duplicate/uninit/OOB-write bug, make the
  element own heap (`Box<u32>`/`String`). `Bomb(u32)` turns a double-drop /
  drop-of-uninit into a *logic* error invisible to Miri/ASan; `Bomb(Box<u32>)`
  turns it into an invalid-free the sanitizer flags. Same for OOB writes: a
  wrong integer is silent, a corrupted heap pointer is caught.
- **OOM caps.** Cap fuzzed lengths/capacities (`% 4096`) and set
  `-rss_limit_mb`, so the fuzzer spends its budget on the bug, not on a giant
  allocation. Clamp an index/param *only* where the API's own `assert!` would
  legitimately fire — otherwise you fuzz the panic, not the memory bug.

## 4. Validation protocol (deterministic, retry loop)

```
for finding:
  template   = dispatch(finding.cwe, finding.capability)
  harness    = agent.bind(template, finding, crate)     # step 2
  loop up to N:
    build = `cargo +nightly fuzz build <target> [--features ...]`
    if build fails: agent.fix(build.stderr); continue    # compiler is the oracle
    smoke = `cargo fuzz run <target> -- -max_total_time=90 -rss_limit_mb=4096`
    record: crash? (ASan/panic + file:line) | clean
    break
  if a known crash input exists: replay it, assert it reproduces
```

The build step alone catches ~all agent API errors before any fuzz time is spent.

## 5. A "no crash" is a capability map, not a failure

When a target runs clean, the *reason* is the actionable output — it names the
missing capability (validated on rust-mizan, 11/14 reproduced):
- **deep-structure byte parser** (valid magic/length/frame gates) → blind AND
  coverage-guided both miss → escalate to a **grammar/dictionary** harness
  ([`grammar_parser`](harness-templates/grammar_parser.rs): `Arbitrary` over the
  format's AST + a libFuzzer `-dict=`).
- **bug only at >4 GiB / 32-bit** → not reachable on a 64-bit host; a real defect
  but out of fuzz scope — report it, don't chase it.
- **format string in un-instrumented C** → build the C dep with ASan, or add a
  `%n`-specific check.
- **uninitialized read** → wrong sanitizer; rerun under **MSan**.

Report the residual with its reason. "0 bugs found" is a lie the reason corrects.

## Worked examples (rust-mizan)

| finding | CWE | template | result |
|---|---|---|---|
| `Slab` `Index` unchecked offset | 125 | index_arbitrary | ASan heap-overflow |
| `SmallVec::insert_many` trusts `size_hint` | 787 | adversarial_impl | Miri OOB write / Stacked-Borrows |
| `unsafe impl Sync for SPMCProducer` | 662 | sendsync_compileproof | compiles ⇒ unsound |
| ID3 `get_id3` (deep parser) | 125 | byte_parser | clean → needs grammar harness |
| compact-Vec packed len/cap | 125 | index_arbitrary | clean → >4 GiB-only, out of scope |
