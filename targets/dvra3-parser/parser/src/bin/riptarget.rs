use std::io::Read;
fn main() {
    let path = std::env::args().nth(1).expect("usage: riptarget <input-file>");
    let mut bytes = Vec::new();
    std::fs::File::open(&path).and_then(|mut f| f.read_to_end(&mut bytes)).expect("read input");
    // Untrusted public entry. A panic (OOB slice index) unwinds -> exit 101 = crash.
    // A graceful Err(...) is correct handling -> print reject:, NOT a crash.
    match dvra_parser::parse_vulnerable(&bytes) {
        Ok(d)  => println!("ok: {} record(s)", d.records.len()),
        Err(e) => println!("reject: {e:?}"),
    }
}
