//! panicking_drop — for a container/collection whose unsafe internals temporarily break an
//! ownership or length invariant and then restore it, with a may-unwind call in between:
//!
//!     break the invariant  ->  call code that may unwind  ->  restore the invariant
//!                                                             ^ never runs if it unwinds
//!
//! The container's own `Drop` then observes a state its author assumed impossible. Every line of
//! the trigger is SAFE Rust; the defect is in the container. Sibling of `adversarial_impl.rs` —
//! that one drives a lying trait impl, this one drives an unwinding destructor.
//!
//! Oracle: **Miri**, and it is definitive rather than suggestive here. `cargo +nightly miri run`.
//!
//! VALIDATED 2026-07-29 against paired ground truth (thin-vec, RUSTSEC-2026-0103 / CVE-2026-6654):
//!   thin-vec 0.2.15  ->  error: Undefined Behavior: memory access failed:
//!                        alloc1209 has been freed, so this pointer is dangling   (double free)
//!   thin-vec 0.2.16  ->  both probes unwind cleanly, no UB
//! Same harness, same flags, one version apart. A harness that cannot tell the pair apart is not
//! an oracle — run yours against the patched version too, always.
#![allow(dead_code)]
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};

use CRATE::CONTAINER; // e.g. `thin_vec::ThinVec`

/// Which element unwinds. Deliberately NOT the first: the interesting states are the half-torn
/// ones, where some elements are already dropped and the length still says otherwise.
const FUSE: usize = 1;

/// The fuse fires EXACTLY ONCE, and that is not a detail — it is the difference between a working
/// oracle and a silent one. A payload that panics on EVERY drop makes the erroneous second drop
/// panic again; Rust aborts on a panic during cleanup, and `panic_in_cleanup` MASKS the memory
/// error underneath. Both facts were measured: firing every time reports only the abort, firing
/// once reports the double free itself.
static FIRED: AtomicBool = AtomicBool::new(false);

/// GOTCHA — the payload must OWN heap memory. A `Bomb(usize)` owns nothing, so dropping it twice
/// is a no-op at the memory level: Miri stays silent and the harness reports a CLEAN RUN on a
/// container that is demonstrably double-dropping. Measured on the thin-vec pair — with a bare
/// `usize` payload both versions passed. The `Box` is what makes the second drop observable.
struct Bomb(usize, Box<u64>);

impl Bomb {
    fn new(i: usize) -> Self {
        Bomb(i, Box::new(i as u64))
    }
}

impl Drop for Bomb {
    fn drop(&mut self) {
        if self.0 == FUSE && !FIRED.swap(true, Ordering::SeqCst) {
            panic!("element {} unwinds during drop (once)", self.0);
        }
    }
}

fn probe(name: &str, f: impl FnOnce()) {
    println!("--- {name} ---");
    FIRED.store(false, Ordering::SeqCst); // each probe gets its own single shot
    let unwound = catch_unwind(AssertUnwindSafe(f)).is_err();
    println!("    unwound: {unwound}");
}

fn main() {
    // One probe per API that touches the invariant. Enumerate them from the crate's `unsafe`
    // blocks: anything calling `drop_in_place`, `set_len`, `ptr::read`, `mem::forget`,
    // `ManuallyDrop::take`, or `assume_init` around a generic `T` is a candidate entry point.

    // A — TRUNCATING API: drops elements, then updates the length.
    probe("CONTAINER::clear", || {
        let mut c: CONTAINER<Bomb> = CONTAINER::from_iter((0..3).map(Bomb::new));
        c.clear();
        // `c` is still live and is dropped WHILE UNWINDING, with whatever length `clear` left.
        // Keeping it alive across the unwind is the whole point — do not drop it early.
    });

    // B — CONSUMING API: the same root cause usually has a second entry point. In thin-vec the
    // advisory named both `ThinVec::clear` and `IntoIter::drop`; only one of them was found first.
    probe("IntoIter::drop", || {
        let c: CONTAINER<Bomb> = CONTAINER::from_iter((0..3).map(Bomb::new));
        let it = c.into_iter();
        drop(it);
    });

    // C — REALLOCATING API: `insert`/`remove`/`retain`/`dedup`/`drain` shift elements around a
    // hole. Add one probe per such method the target exposes; they fail independently.
    // probe("CONTAINER::retain", || { ... });

    println!("harness completed without Miri reporting UB");
}
