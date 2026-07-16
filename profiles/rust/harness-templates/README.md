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
| [`fuzz-Cargo.toml.template`](fuzz-Cargo.toml.template) | the `fuzz/` project boilerplate | — |

`UPPERCASE` tokens are holes the agent fills. The `// GOTCHA`/`// L12`/`// OOM`
comments are the non-obvious rules that cost real harnesses when missed — keep
them in mind, drop them from the final file.
