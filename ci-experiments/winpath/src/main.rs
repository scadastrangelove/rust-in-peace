// v3 (definitive): can ANY ".. "-style name escape `base` via Rust std file ops while bypassing
// the `component == ".."` guard? Try backslash + forward separators, and the "create the leading
// dir first, then the file" sequence a receiver uses. List BOTH base/ and root/ contents.
use std::fs;
use std::path::Path;

fn guard_catches(name: &str) -> bool { name.split(|c| c=='/'||c=='\\').any(|s| s=="..") }

fn try_create(tag: &str, base: &Path, rel: &str) {
    let joined = base.join(rel);
    let r = fs::File::create(&joined);
    println!("[{}] guard_catches={} rel={:?} File::create={}",
        tag, guard_catches(rel), rel, r.map(|_|"OK".into()).unwrap_or_else(|e| format!("ERR:{}", e.kind())));
}

fn main() {
    let root = std::env::temp_dir().join("winpath_v3_a1");
    let _ = fs::remove_dir_all(&root);
    let base = root.join("base");
    fs::create_dir_all(&base).unwrap();
    println!("OS={}", std::env::consts::OS);

    // A) direct File::create with the leading dirs auto-made
    for rel in [".. \\b.txt", ".. \\.. \\b2.txt", "..\\p.txt", ".. /f.txt"] {
        if let Some(p)=base.join(rel).parent(){ let _=fs::create_dir_all(p); }
        try_create("direct", &base, rel);
    }
    // B) explicitly create the `.. ` component as a real subdirectory FIRST, then a file inside it
    let d = base.join(".. ");
    println!("B: create_dir(base/'.. ')={}", fs::create_dir(&d).map(|_|"OK".into()).unwrap_or_else(|e| format!("ERR:{}",e.kind())));
    println!("B: canonicalize(base/'.. ')={:?}", fs::canonicalize(&d).map(|c| c.file_name().map(|n| n.to_owned())).ok());
    let _ = fs::File::create(d.join("inside.txt"));

    // C) does creating a dir literally named ".. " land it inside base (verbatim) or escape?
    println!("=== base/ contents ===");   for e in fs::read_dir(&base).unwrap(){ println!("  {:?}", e.unwrap().file_name()); }
    println!("=== root/ contents (non-'base' = ESCAPED) ==="); for e in fs::read_dir(&root).unwrap(){ println!("  {:?}", e.unwrap().file_name()); }
}
