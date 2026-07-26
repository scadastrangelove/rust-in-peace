# miniz_oxide #198 — degenerate-block DoS reproducer (both variants)

A self-contained reproducer for [Frommi/miniz_oxide#198](https://github.com/Frommi/miniz_oxide/issues/198):
every DEFLATE block header forces a full Huffman-table rebuild (`init_tree`),
decoupled from output size, so a chain of minimal 0-output blocks forces
arbitrary rebuild work while the `_with_limit` output cap never engages.

It covers **both** block variants so a candidate fix can be checked by running
it, not only by reading the diff:

- `BTYPE=1` (static/fixed Huffman) — ~1.25 bytes/block. Removed by precomputing
  the fixed table (zlib's `inffixed.h` approach).
- `BTYPE=2` (dynamic Huffman) — ~11.5 bytes/block. The table is defined in the
  stream and rebuilt per block regardless, so precomputing the fixed table does
  **not** remove this variant.

Depends only on published `miniz_oxide` (see `Cargo.toml`); to check a fix, point
that dependency at the fix branch and re-run.

## Run

```bash
cargo run --release            # prints the both-variants timing table
cargo test --release           # correctness gate: both floods decode to empty
cargo test --release -- --ignored   # timing regression (see below)
```

The `--ignored` test is a wall-clock regression **designed to fail on current
`main`** (a 1M-block flood must finish under 500 ms) and pass once per-block work
is bounded — run it against `main`, then a fix branch, and watch it flip. Which
variant flips depends on the fix; the `main.rs` doc comment spells that out
(precompute → static passes, dynamic still fails; proportional fill → both pass;
opt-in rebuild budget → verify via the new `_with_limits` API instead). It is
`#[ignore]`d because wall-clock assertions are machine-dependent and don't belong
in normal CI.

`results.txt` is a captured run on the reporter's machine (published 0.9.1,
release build) for reference.
