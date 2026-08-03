// v2: thorough Windows path-canonicalization probe. For each payload, canonicalize the parent,
// create_dir_all the parent (as a file-receiver does), then File::create, printing every error.
// A file landing directly in `root/` (sibling of base) = escape out of base.
use std::fs;
use std::path::Path;

fn probe(label: &str, base: &Path, rel: &str) {
    let joined = base.join(rel);
    println!("--- {} rel={:?} joined={:?}", label, rel, joined);
    if let Some(parent) = joined.parent() {
        match fs::canonicalize(parent) {
            Ok(c) => println!("    canonicalize(parent)={:?}", c),
            Err(e) => println!("    canonicalize(parent) ERR={}", e.kind()),
        }
        match fs::create_dir_all(parent) {
            Ok(_) => println!("    create_dir_all(parent)=OK"),
            Err(e) => println!("    create_dir_all(parent) ERR={}", e.kind()),
        }
    }
    match fs::File::create(&joined) {
        Ok(_) => println!("    File::create=OK -> {:?}", joined),
        Err(e) => println!("    File::create ERR={}", e.kind()),
    }
}

fn main() {
    let root = std::env::temp_dir().join("winpath_v2_7c2");
    let _ = fs::remove_dir_all(&root);
    let base = root.join("base");
    fs::create_dir_all(&base).unwrap();
    println!("OS={} root={:?}", std::env::consts::OS, root);

    // trailing-space/dot component variants (all use '/' which is a separator on both OSes)
    probe("dotdot_space",  &base, ".. /esc_space.txt");
    probe("dotdot_dot",    &base, ".. ./esc_dot.txt");
    probe("plain_dotdot",  &base, "../esc_plain.txt");
    probe("double_space",  &base, ".. /.. /esc_double.txt");

    // also: does canonicalize/create of the bare parent escape?
    match fs::create_dir_all(base.join(".. /injected_dir")) {
        Ok(_) => println!("bare: create_dir_all(base/'.. '/injected_dir)=OK"),
        Err(e) => println!("bare: create_dir_all ERR={}", e.kind()),
    }

    println!("=== root listing (entries here that are NOT 'base' = ESCAPED) ===");
    for e in fs::read_dir(&root).unwrap() { println!("  {:?}", e.unwrap().file_name()); }
}
