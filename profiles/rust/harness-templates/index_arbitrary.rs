//! index_arbitrary — for OOB via an untrusted index / length / size reaching an
//! unchecked `.offset()` / `get_unchecked` / `ptr::write` / `set_len`.
//! Oracle: ASan. (If the bug is an UNINITIALIZED read of validly-allocated
//! memory — CWE-908 — ASan is blind to it; run under MSan instead.)
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
enum Op {
    Push(u32),
    Remove(usize),
    Get(usize),        // the unchecked Index/offset — the likely OOB site
    SetLen(usize),     // if the type exposes a length-forging path
}

#[derive(Arbitrary, Debug)]
struct Input {
    seed: Vec<u32>,
    ops: Vec<Op>,
}

fuzz_target!(|input: Input| {
    // L12: element owns heap so a duplicated/OOB slot is memory-corruption
    // (ASan), not a merely-wrong integer.
    let mut c = TARGET_CRATE::CONTAINER::<Box<u32>>::CONSTRUCT();
    for v in input.seed.into_iter().take(4096) {         // OOM cap
        c.FILL(Box::new(v));
    }
    for op in input.ops.into_iter().take(4096) {         // OOM cap
        match op {
            Op::Push(v)    => { if c.len() < 4096 { c.FILL(Box::new(v)); } }
            Op::Remove(i)  => { /* c.REMOVE(i) — reaches the off-by-one/OOB */ }
            Op::Get(i)     => { let r = &c[i]; std::hint::black_box(r); } // unchecked -> ASan OOB
            Op::SetLen(n)  => { /* forge the header/len past the allocation, then read all n */ }
        }
    }
    // Force reads over the whole logical length so an OOB/uninit slot is loaded.
    for x in c.iter() { std::hint::black_box(**x); }
});

// OOM: cap seed/ops and every capacity/len fed to the API; set -rss_limit_mb on
//   the run. For a pure size-overflow bug (CWE-190), feed the raw usize directly
//   and let it overflow the `size * elem` multiply; guard the harness so a valid
//   small size also runs (`checked_mul`).
// CLAMP an index ONLY where the API's own assert! legitimately fires (e.g.
//   `insert` index % (len+1)) — clamp elsewhere and you fuzz the panic, not the bug.
