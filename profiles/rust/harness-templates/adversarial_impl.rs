//! adversarial_impl — for unsafe code that TRUSTS a caller-supplied trait impl
//! (higher-order-invariant / panic-safety, the Rudra patterns). There is no byte
//! input — the "input" is the trait impl's behaviour, which the fuzzer controls.
//! Oracle: **Miri** is surest (Stacked-Borrows, drop-of-uninit); ASan catches the
//! heap-overflow / UAF variants. Run under `cargo +nightly miri run` and/or
//! `cargo fuzz run`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

// --- HIGHER-ORDER: an iterator whose size_hint()/len() LIES vs what next() yields.
struct Liar { reported: usize, remaining: usize }
impl Iterator for Liar {
    type Item = Box<u32>;                          // L12: heap element
    fn next(&mut self) -> Option<Box<u32>> {
        if self.remaining == 0 { return None; }
        self.remaining -= 1; Some(Box::new(0xAA))
    }
    fn size_hint(&self) -> (usize, Option<usize>) { (self.reported, Some(self.reported)) }
}
impl ExactSizeIterator for Liar { fn len(&self) -> usize { self.reported } }

#[derive(Arbitrary, Debug)]
struct Input { prefill: u8, index: u8, reported: u8, actual: u8 }

fuzz_target!(|input: Input| {
    let mut c = TARGET_CRATE::CONTAINER::<Box<u32>>::CONSTRUCT();
    for _ in 0..(input.prefill % 16) { c.FILL(Box::new(1)); }
    let idx = (input.index as usize) % (c.len() + 1);
    // reported (lied) may under/over-report `actual` -> the unsafe reserve/write
    // path over-/under-runs. reported=0, actual=1 at inline capacity is a common trigger.
    c.HIGHER_ORDER_METHOD(idx, Liar { reported: input.reported as usize, remaining: input.actual as usize });
    for x in c.iter() { std::hint::black_box(**x); }   // force reads across the (possibly corrupt) length
});

// --- PANIC-SAFETY variant: element = a struct owning a Box whose Clone/Drop/next
//   PANICS on the Nth call (a thread_local counter). Feed it to a Clone/insert
//   loop over unsafe MaybeUninit storage; the unwind drops uninit/double-owned
//   slots -> Miri: "reading uninitialized memory" / dangling box.
//
// L12 (critical): the element MUST own heap. `Bomb(u32)` makes the double-drop /
//   drop-of-uninit a LOGIC error invisible to Miri; `Bomb(Box<u32>)` makes it an
//   invalid free Miri flags. Verified: SmallVec::insert_many with a lying
//   size_hint is silent with a u32 element, a precise Stacked-Borrows UB with Box.
// GOTCHA: the method may be behind a feature (`--features ringbuffer`) — enable it.
