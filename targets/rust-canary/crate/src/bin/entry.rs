// Thin driver: `entry <input_file>` → parse the bytes and exercise the public
// API on the (untrusted) table. This defines the attack surface. Built with
// AddressSanitizer + panic=abort, so a panic or an OOB read aborts before exit.
//
// A graceful `Err(...)` (bad magic / checksum / truncated) prints `reject:` and
// exits 0 — that is CORRECT handling, not a finding. The run harness treats a
// `reject:` line as clean.

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: entry <input_file>");
            std::process::exit(2);
        }
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("io error: {e}");
            std::process::exit(2);
        }
    };

    // parse() itself may panic on a hostile n_recs (BUG-2).
    let table = match rustcanary::parse(&bytes) {
        Ok(t) => t,
        Err(e) => {
            println!("reject: {e:?}"); // graceful — not a bug
            return;
        }
    };

    if table.n_recs() > 0 {
        // BUG-1: unchecked unsafe read of record 0's data span.
        let _ = table.sum_record(0);
        // DECOY: bounded unsafe read (safe).
        let _ = table.first_byte_checked(0);
        // BUG-3: chain walk from record 0 (cyclic `next` → hang).
        let _ = table.walk_chain(0);
    }
    println!("ok");
}
