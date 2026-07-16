//! grammar_parser — for a STRUCTURE-GATED byte parser: a format whose entry is
//! guarded by magic + length + frame gates a random byte stream almost never
//! satisfies (rust-mizan 0040 — an ID3v2 tag: "ID3" magic + a *synchsafe*
//! (7-bits-per-byte) size + length-prefixed frames). Blind AND coverage-guided
//! byte fuzzing both bounce off the first gate: sancov sees the `!= b"ID3"`
//! reject edge and never the parse edges behind it. The fix is to fuzz the
//! format's *AST*, not raw bytes — generate structurally-valid inputs by
//! construction, then let the mutator perturb them past the gates.
//! Oracle: ASan (OOB in the frame walk) + overflow-checks (panic). If the frame
//! walk can READ an uninitialized/short-read body slot (CWE-908), ASan is blind
//! to it — rerun under MSan (see the MSan GOTCHA below and 0027). This is the
//! grammar rung of the staircase — see ../fuzzing.md and ../find-to-fuzz.md §5.
//!
//! STRUCTURE-GATED — when the dispatcher jumps here:
//!   §9 has `untrusted_deserialization: yes` AND the evidence carries the
//!   `structure_gated` sub-signal (magic/length/frame container — see
//!   ../capabilities.md "structure_gated sub-signal"). The router first spends a
//!   cheap blind pass (Stage 1). When that comes back CLEAN, the residual is a
//!   grammar-gated surface, NOT "0 bugs": ../find-to-fuzz.md §5 says report the
//!   reason and escalate to THIS template instead of burning the rest of the
//!   budget on bytes that die at the magic check.
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

// --- The format's AST. `#[derive(Arbitrary)]` lets the fuzzer author whole,
//     well-shaped tags; `to_bytes()` serializes them into a stream the parser
//     ACCEPTS. The one thing a random byte stream never gets right — the
//     synchsafe size — we compute here, which is the entire point of the rung.
//     Adapt the field set to the real format; keep the magic + a correct
//     length encoding.

#[derive(Arbitrary, Debug)]
struct Id3Header {
    version_major: u8, // ID3v2.MAJOR (real tags: 2/3/4) — mutator explores it
    version_minor: u8,
    flags: u8, // bit7 unsync, bit6 extended-header, bit5 experimental, bit4 footer
    // NB: the tag SIZE is NOT an Arbitrary field — it is *derived* in to_bytes()
    // from the serialized frames, then synchsafe-encoded. A fuzzed size here
    // would just re-create the blind-fuzz problem (wrong length → gate reject).
}

#[derive(Arbitrary, Debug)]
struct Frame {
    id: [u8; 4],     // frame id, e.g. b"TIT2"; mutator finds the real ids via -dict
    flags: [u8; 2],  // ID3v2.3/2.4 per-frame status+format flags
    body: Vec<u8>,   // frame payload; size prefix is derived, not fuzzed
}

#[derive(Arbitrary, Debug)]
struct Id3Tag {
    header: Id3Header,
    frames: Vec<Frame>,
}

// --- synchsafe encode: 4 bytes, 7 significant bits each, high bit always 0
//     (so a 0xFF sync word can never appear inside a size). Max encodable value
//     is 2^28-1. A random stream sets the high bits ~half the time → the parser
//     rejects it as "not synchsafe" before any frame is read. Getting THIS right
//     is what carries the harness past the gate.
fn synchsafe_encode(mut n: u32) -> [u8; 4] {
    n &= 0x0FFF_FFFF; // mask to 28 bits (drops the top 4); OOM caps keep real
                      // sizes far below 2^28 so this never truncates a live length
    [
        ((n >> 21) & 0x7F) as u8,
        ((n >> 14) & 0x7F) as u8,
        ((n >> 7) & 0x7F) as u8,
        (n & 0x7F) as u8,
    ]
}

const MAGIC: &[u8; 3] = b"ID3"; // HOLE if the format differs — but keep it a real magic

impl Id3Tag {
    fn to_bytes(&self) -> Vec<u8> {
        // OOM: cap frame COUNT and each body LENGTH before serializing, and
        // never pre-size a Vec from a fuzzed number without the same cap — an
        // uncapped Vec::with_capacity(fuzzed_len) is a one-line OOM. Rely on
        // -rss_limit_mb=4096 as the backstop, not the primary guard.
        let mut frame_bytes = Vec::new();
        for f in self.frames.iter().take(64) {
            // OOM: frame-count cap
            let body: &[u8] = &f.body[..f.body.len().min(4096)]; // OOM: body-len cap
            frame_bytes.extend_from_slice(&f.id);
            // ID3v2.4 frame sizes are ALSO synchsafe; v2.3 uses a plain BE u32.
            // Match whichever the TARGET parser expects — a mismatch re-gates the
            // frame walk and you fuzz the reject path, not the body handler.
            frame_bytes.extend_from_slice(&synchsafe_encode(body.len() as u32));
            frame_bytes.extend_from_slice(&f.flags);
            frame_bytes.extend_from_slice(body);
        }

        let mut out = Vec::with_capacity(10 + frame_bytes.len()); // bounded: frame_bytes already capped
        out.extend_from_slice(MAGIC); // 3
        out.push(self.header.version_major); // +1
        out.push(self.header.version_minor); // +1
        out.push(self.header.flags); // +1
        // the tag size = byte length of everything AFTER the 10-byte header,
        // synchsafe-encoded. THIS is the gate a blind stream never satisfies.
        out.extend_from_slice(&synchsafe_encode(frame_bytes.len() as u32)); // +4 = 10
        out.extend_from_slice(&frame_bytes);
        out
    }
}

fuzz_target!(|tag: Id3Tag| {
    let bytes = tag.to_bytes();
    // BIND: the target's public byte-input parse entry. If the vulnerable fn is
    // PRIVATE (0040's `get_id3`), feed the public wrapper that reaches it
    // (`read_from_slice`) — see ../byte_parser.rs and ../find-to-fuzz.md §2.
    let _ = TARGET_CRATE::PARSE_ENTRY(&bytes);
});

// -----------------------------------------------------------------------------
// COMPANION DICTIONARY — the cheaper half of the grammar rung. Even without the
// Arbitrary AST, a libFuzzer -dict= lets the raw-byte mutator paste the magic,
// real frame ids, and version bytes as whole tokens, so it clears the gates far
// more often. Ship BOTH: the AST gets you structurally-valid tags; the dict
// tokens help the mutator recombine frame-level structure. Write `id3.dict`
// next to the fuzz target:
//
//   # id3.dict — libFuzzer dictionary for the ID3v2 structure gate
//   magic   = "ID3"
//   # version bytes seen on real tags (v2.2 / v2.3 / v2.4)
//   ver22   = "\x02\x00"
//   ver23   = "\x03\x00"
//   ver24   = "\x04\x00"
//   # common frame ids — the parse-dispatch keys behind the gate
//   tit2    = "TIT2"   # title
//   tpe1    = "TPE1"   # lead artist
//   talb    = "TALB"   # album
//   trck    = "TRCK"   # track number
//   tyer    = "TYER"   # year (v2.3)
//   comm    = "COMM"   # comment (has a lang + encoding sub-structure)
//   apic    = "APIC"   # attached picture — big body, encoding + mime + type
//   priv_   = "PRIV"   # private frame — owner id + raw binary
//   # a valid synchsafe size (each byte < 0x80) to seed the length field
//   ssz     = "\x00\x00\x02\x01"
//
//   cargo +nightly fuzz run <target> -- -dict=id3.dict -rss_limit_mb=4096
//
// Best seed corpus for BOTH: real, valid .mp3/.tag artifacts (../fuzzing.md
// "Domain-specific corpus") — the mutator starts inside the structure and the
// AST/dict push it into the unexplored frame states.
// -----------------------------------------------------------------------------

// L12 (does the format WRITE a decoded element into a container?) — if
//   PARSE_ENTRY builds a `Vec<Box<Frame>>`/`Vec<String>` etc. and the bug is an
//   OOB write / uninit slot in that build, the stored element MUST own heap so
//   the corruption is a sanitizer-visible invalid free, not a silent wrong
//   integer. (For a pure read-out-of-bounds walk over the input slice, ASan on
//   the input buffer already fires and L12 doesn't apply.) See ../find-to-fuzz.md §3.
// GOTCHA (synchsafe mismatch): if the target rejects everything, the frame-size
//   encoding is almost always wrong — v2.4 frames are synchsafe, v2.3 frames are
//   plain BE u32. Match the parser's version handling or you fuzz the reject path.
// GOTCHA (unsync flag): header flag bit7 (unsynchronisation) makes the parser
//   strip inserted 0x00 after every 0xFF before decoding. If you set it in the
//   AST you must apply the same unsync transform in to_bytes(), or the sizes no
//   longer line up. Simplest: force flags &= !0x80 in to_bytes() unless you are
//   specifically targeting the unsync decoder.
// GOTCHA (NUL / CString): if a frame body reaches `CString::new`, an interior
//   0x00 panics deterministically and masks the real bug — see ../byte_parser.rs.
// GOTCHA (MSan for uninit-read): a frame walk that trusts a size and reads a body
//   slot that was never fully initialised (a short read / a slot sized past the
//   bytes actually written) is CWE-908 — ASan is BLIND to it (0027). Rebuild the
//   target under MSan: `RUSTFLAGS="-Zsanitizer=memory" cargo +nightly fuzz run
//   <target> -Zbuild-std --target x86_64-unknown-linux-gnu`. `-Zbuild-std` is
//   MANDATORY — an un-instrumented std produces false positives that drown the
//   real one. In the gVisor pipeline the MSan run needs a privileged/relaxed
//   sandbox (`--privileged`, shadow-memory mmap), the same relaxation ASan needs;
//   don't try to reuse the default coverage container. See ../find-to-fuzz.md §5.
// OOM: caps live in to_bytes() (frame count, body len, no uncapped
//   with_capacity from a fuzzed number); pair with `-rss_limit_mb=4096`.
