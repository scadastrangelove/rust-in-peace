//! sendsync_compileproof — for an unsound `unsafe impl Send/Sync` (variance).
//! NOT a fuzz target: unsound Send/Sync is a TYPE-SYSTEM property, proven by
//! whether an assertion COMPILES. Put this in `src/bin/proof.rs` or a `tests/`
//! file. Oracle: the compiler. Compiles => unsound PROVEN. Rejected => sound.
use std::cell::Cell;
use std::rc::Rc;
use std::sync::MutexGuard;

fn require_send<T: Send>() {}
fn require_sync<T: Sync>() {}

fn main() {
    // Instantiate the container over a NON-thread-safe element and assert the
    // marker trait. If the unsound `unsafe impl<T> Send/Sync for C<T>` (no
    // `T: Send/Sync` bound) exists, these COMPILE — that IS the bug.
    require_send::<TARGET_CRATE::CONTAINER<Rc<()>>>();      // Rc<()>   is !Send + !Sync
    require_sync::<TARGET_CRATE::CONTAINER<Rc<()>>>();
    require_sync::<TARGET_CRATE::CONTAINER<Cell<u8>>>();    // Cell<u8> is !Sync
    let _ = require_send::<MutexGuard<'static, u8>>;         // (silence unused)
}

// GOTCHA (masking): if the type has another variant/field that already requires
//   `T: Sync` (e.g. an enum `Single(&[A])`, or an inner `UnsafeCell`), a blunt
//   `C<Rc<()>>: Send` probe fails in BOTH the sound and unsound build and proves
//   nothing. Isolate the unsound impl with an element that is Sync-but-!Send
//   (`MutexGuard<'static, u8>`) or a type nameable only through that impl.
// GOTCHA (gated): the impl may exist only under a feature/cfg (`--cfg threadsafe`,
//   `--features threadsafe`). Build with it; without it the type is legitimately
//   !Send/!Sync and the proof (correctly) fails to compile.
// GOTCHA (private type): if the unsound type lives in a private module, name it
//   through the public type that embeds it by value (e.g. `Focus::Full(TreeFocus)`).
