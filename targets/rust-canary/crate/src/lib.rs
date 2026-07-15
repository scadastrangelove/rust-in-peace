//! rustcanary — a DELIBERATELY-VULNERABLE binary "record table" parser, used to
//! exercise the Rust-security pipeline profile. It reproduces, in miniature, the
//! real Rust bug classes found auditing a production parser:
//!
//!   BUG-1  unchecked `unsafe` offset read AFTER an integrity check
//!          (the "CRC proves bytes intact, not offsets in-bounds" trap).
//!          Detector: Miri `out-of-bounds pointer use` / ASAN heap-buffer-overflow.
//!   BUG-2  panic on an untrusted length (slice range) — availability DoS.
//!          Detector: panic-slice-range (abort under panic=abort).
//!   BUG-3  unbounded chain walk driven by an untrusted `next` index — hang.
//!          Detector: hang-timeout.
//!   DECOY  an `unsafe` read that LOOKS unchecked but is bounded by a validation
//!          on the line above — a triage FALSE POSITIVE (mirrors the real F-018).
//!
//! Format (little-endian):
//!   magic     u32  = 0x52435431 ("RCT1")
//!   checksum  u32  = additive sum of every byte AFTER this field (INTEGRITY only)
//!   n_recs    u32
//!   records   n_recs × { data_off u32, data_len u32, next u32 }   (12 B each)
//!   data      remaining bytes
//!
//! Public API (the attack surface): `parse(bytes)` then the `Table` methods.

pub const MAGIC: u32 = 0x5243_5431;
const HEADER: usize = 12; // magic + checksum + n_recs
const REC: usize = 12; // data_off + data_len + next

#[derive(Debug)]
pub enum Error {
    BadMagic,
    BadChecksum,
    Truncated,
}

pub struct Table<'a> {
    recs: &'a [u8], // n_recs * REC bytes
    n_recs: usize,
    data: &'a [u8],
}

#[inline]
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// Additive integrity checksum. NOT a bounds guarantee — the whole point of
/// BUG-1 is that passing this says nothing about whether record offsets are
/// in-bounds. Easy to forge on purpose (the lesson is integrity ≠ validation).
pub fn checksum(b: &[u8]) -> u32 {
    b.iter().fold(0u32, |a, &x| a.wrapping_add(x as u32))
}

/// Parse the container. Validates magic + integrity checksum, then frames the
/// records and data regions.
pub fn parse(bytes: &[u8]) -> Result<Table<'_>, Error> {
    if bytes.len() < HEADER {
        return Err(Error::Truncated);
    }
    if u32_at(bytes, 0) != MAGIC {
        return Err(Error::BadMagic);
    }
    // INTEGRITY check only. Proves the bytes are intact; proves NOTHING about
    // whether the internal offsets/counts below are in-bounds.
    if checksum(&bytes[8..]) != u32_at(bytes, 4) {
        return Err(Error::BadChecksum);
    }
    let n_recs = u32_at(bytes, 8) as usize;
    // BUG-2 (panic-slice-range): `n_recs` is untrusted and this slice panics
    // when the records region doesn't fit. There is NO check that
    // `HEADER + n_recs * REC <= bytes.len()`. A large n_recs → range panic.
    let recs_end = HEADER + n_recs * REC;
    let recs = &bytes[HEADER..recs_end];
    let data = &bytes[recs_end..];
    Ok(Table { recs, n_recs, data })
}

impl<'a> Table<'a> {
    pub fn n_recs(&self) -> usize {
        self.n_recs
    }

    #[inline]
    fn rec(&self, i: usize) -> (usize, usize, usize) {
        let base = i * REC;
        (
            u32_at(self.recs, base) as usize,     // data_off
            u32_at(self.recs, base + 4) as usize, // data_len
            u32_at(self.recs, base + 8) as usize, // next
        )
    }

    /// BUG-1 (unsafe OOB read). Reads `data_len` bytes at `data_off` in the data
    /// blob via an UNCHECKED raw pointer. Both fields come from the record
    /// (attacker-controlled); `parse` validated the checksum but never that
    /// `data_off + data_len <= data.len()`. A hostile offset walks off the end.
    /// Detector: Miri `out-of-bounds pointer use`; ASAN `heap-buffer-overflow`.
    pub fn sum_record(&self, i: usize) -> u64 {
        let (off, len, _) = self.rec(i);
        let p = self.data.as_ptr();
        let mut s = 0u64;
        for k in 0..len {
            // No bound on `off + k` vs `data.len()`.
            s = s.wrapping_add(unsafe { *p.add(off + k) } as u64);
        }
        s
    }

    /// BUG-3 (unbounded chain walk). Follows `next` indices until a terminator
    /// (usize::MAX). No visited-set and no step cap → a record whose `next`
    /// points at itself (or forms a cycle) loops forever. Detector: hang-timeout.
    pub fn walk_chain(&self, start: usize) -> usize {
        // `next` is stored as u32, so the terminator is u32::MAX (not usize::MAX).
        const TERMINATOR: usize = u32::MAX as usize;
        let mut i = start;
        let mut steps = 0usize;
        loop {
            let (_, _, next) = self.rec(i % self.n_recs.max(1));
            steps += 1;
            if next == TERMINATOR {
                return steps; // terminator
            }
            i = next; // cyclic `next` → never terminates (BUG-3)
        }
    }

    /// DECOY — SAFE. Looks like an unchecked `unsafe` read, but the bound IS
    /// established on the line above (`off < data.len()`), so the read is
    /// in-bounds on every path. A naive scanner flags this; a rigorous verifier
    /// must REJECT it as a false positive (this is the F-018 pattern).
    pub fn first_byte_checked(&self, i: usize) -> Option<u8> {
        let (off, len, _) = self.rec(i % self.n_recs.max(1));
        if len == 0 || off >= self.data.len() {
            return None; // bound established: off < data.len() below
        }
        // SAFETY: `off < data.len()` proven immediately above → in-bounds.
        Some(unsafe { *self.data.as_ptr().add(off) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a well-formed container with the given records + data.
    fn build(recs: &[(u32, u32, u32)], data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(recs.len() as u32).to_le_bytes());
        for &(o, l, n) in recs {
            body.extend_from_slice(&o.to_le_bytes());
            body.extend_from_slice(&l.to_le_bytes());
            body.extend_from_slice(&n.to_le_bytes());
        }
        body.extend_from_slice(data);
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&checksum(&body).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn valid_input_roundtrips() {
        let bytes = build(&[(0, 3, u32::MAX)], &[1, 2, 3]);
        let t = parse(&bytes).unwrap();
        assert_eq!(t.n_recs(), 1);
        assert_eq!(t.sum_record(0), 6); // in-bounds: off=0,len=3
        assert_eq!(t.first_byte_checked(0), Some(1));
        assert_eq!(t.walk_chain(0), 1); // next=MAX terminates
    }

    #[test]
    #[should_panic] // BUG-2: n_recs huge → records slice out of range
    fn bug2_untrusted_n_recs_panics() {
        // Hand-forge a checksum-valid header claiming 1_000_000 records.
        let mut body = Vec::new();
        body.extend_from_slice(&1_000_000u32.to_le_bytes());
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&checksum(&body).to_le_bytes());
        out.extend_from_slice(&body);
        let _ = parse(&out); // panics slicing recs
    }

    // BUG-1 (unsafe OOB) is intentionally NOT unit-tested as a panic — it is
    // Undefined Behavior; run it under Miri to observe the out-of-bounds
    // pointer use:  cargo +nightly miri test miri_bug1_oob
    #[test]
    fn miri_bug1_oob() {
        // record 0: off=0 but len=64, while data is only 3 bytes → OOB read.
        let bytes = build(&[(0, 64, u32::MAX)], &[1, 2, 3]);
        let t = parse(&bytes).unwrap();
        let _ = t.sum_record(0); // Miri: out-of-bounds pointer use
    }
}
