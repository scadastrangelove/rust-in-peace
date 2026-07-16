//! byte_parser — for a target with a `&[u8]`/`&str`/`Read` parse entry.
//! Oracle: ASan (OOB) + overflow-checks (panic), cargo-fuzz default.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // BIND: the public byte-input entry. If the vulnerable fn is PRIVATE, find
    // the public wrapper that reaches it (e.g. a private `get_id3` reached via a
    // public `read_from_slice`). Construct any extra args cheaply (a Default /
    // hand-built metadata struct).
    let _ = TARGET_CRATE::PARSE_ENTRY(data);

    // Variant — decode `data` into the entry's real input type first, e.g.
    // let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0],c[1]])).collect();
    // and pass a pointer/slice WITHOUT a terminator so an unbounded read runs off the end.
});

// GOTCHA (no_std): if the target is `#![no_std]` with its own `#[panic_handler]`,
//   depending on it clashes with libfuzzer's std (`duplicate lang item panic_impl`).
//   Work around by `include!("../../src/<module>.rs")` of the real, unmodified
//   source into this file, plus a tiny `mod prelude` shim for its `use`s — you
//   still fuzz the exact shipped code.
// GOTCHA (NUL): if the entry does `CString::new(s)`, skip inputs containing 0x00
//   (that panics deterministically and masks the real bug).
// LIMIT: a deep-structure parser (magic + length + frame gates) resists byte
//   fuzzing — blind AND coverage-guided may both bounce off the first check.
//   Escalate to a grammar/dictionary harness (Arbitrary over the format's AST,
//   or a libFuzzer -dict=). See ../find-to-fuzz.md §5.
