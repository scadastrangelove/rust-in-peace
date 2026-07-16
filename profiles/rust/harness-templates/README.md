# Harness templates (find → fuzz)

Canonical skeletons the binding agent adapts to a target crate. Selected by the
dispatch table in [`../find-to-fuzz.md`](../find-to-fuzz.md) from a finding's
CWE/capability. Distilled from harnesses that reproduced real CVEs in the
rust-mizan corpus (11/14 memory-corruption via cargo-fuzz+ASan; 8/8 soundness via
Miri / compile-proof).

| template | for | oracle |
|---|---|---|
| [`byte_parser.rs`](byte_parser.rs) | a `&[u8]`/`&str`/`Read` parse entry | ASan |
| [`index_arbitrary.rs`](index_arbitrary.rs) | OOB via an untrusted index/len/size | ASan (MSan if uninit-read) |
| [`adversarial_impl.rs`](adversarial_impl.rs) | unsafe trusting a caller trait impl (higher-order / panic-safety) | Miri (surest) + ASan |
| [`sendsync_compileproof.rs`](sendsync_compileproof.rs) | unsound `Send`/`Sync` | the compiler (not a fuzz run) |
| [`grammar_parser.rs`](grammar_parser.rs) | structure-gated parser (magic/length/frame — 0040) | ASan + `-dict=` grammar (MSan if uninit body) |
| [`threaded_driver.rs`](threaded_driver.rs) | data race / Send-Sync variance (`concurrency_async`) | TSan / loom |
| [`fuzz-Cargo.toml.template`](fuzz-Cargo.toml.template) | the `fuzz/` project boilerplate | — |
| [`fuzz-Cargo.msan.toml`](fuzz-Cargo.msan.toml) | MSan build variant — uninitialized reads (0027) | MSan (`-Zsanitizer=memory -Zbuild-std`) |
| [`ffi_asan.md`](ffi_asan.md) | format-string / FFI into un-instrumented C (0033) | ASan-compiled C dep / `%n` oracle |

`UPPERCASE` tokens are holes the agent fills. The `// GOTCHA`/`// L12`/`// OOM`
comments are the non-obvious rules that cost real harnesses when missed — keep
them in mind, drop them from the final file.
