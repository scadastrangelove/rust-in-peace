# rust-canary — Rust-security pipeline demo target

A deliberately-vulnerable Rust crate (`rustcanary`) that parses a binary
"record table" format. It's the Rust analog of `targets/canary` — a self-check
that the Rust profile (find prompt + detectors + dedup) is wired correctly.

> ⚠️ `crate/src/lib.rs` announces itself as deliberately vulnerable. Like the
> C canary, `/triage` may correctly dismiss its findings as "demo code" — that's
> expected. It exists to validate the *pipeline*, not to be triaged.

## Seeded bugs (what the pipeline should find)

| id | class | where | detector |
|----|-------|-------|----------|
| BUG-1 | unchecked `unsafe` OOB read (integrity ≠ bounds) | `Table::sum_record` | Miri UB / ASAN heap-buffer-overflow |
| BUG-2 | panic on untrusted length | `parse` (records slice) | panic-slice-range → abort |
| BUG-3 | unbounded chain walk (cyclic `next`) | `Table::walk_chain` | hang-timeout |
| DECOY | **safe** — unsafe read bounded on the line above | `Table::first_byte_checked` | none (triage FALSE POSITIVE) |

The DECOY is the point of the exercise as much as the bugs: a rigorous verifier
must **reject** it (the F-018 pattern — an unchecked read whose bound is
established by a preceding validation).

## Build & poke by hand

```bash
cd crate
cargo build                       # plain build
cargo test                        # valid_input_roundtrips + BUG-2 should_panic
cargo +nightly miri test miri_bug1_oob   # observe BUG-1 as UB
```

Or via the full image (what the pipeline does):

```bash
docker build -t vuln-pipeline-rust-canary:latest targets/rust-canary
# then, inside: /work/run_detectors.sh /tmp/poc.bin
```

## Making an input the parser accepts

The format is little-endian:

```
magic     u32 = 0x52435431
checksum  u32 = additive sum of every byte AFTER this field
n_recs    u32
records   n_recs × { data_off u32, data_len u32, next u32 }
data      remaining bytes
```

The checksum is trivial to forge (that's the lesson — integrity is not a bounds
check). A record with `data_off=0, data_len=64` over a 3-byte data blob trips
BUG-1; a huge `n_recs` trips BUG-2; a record whose `next` points at itself trips
BUG-3.
