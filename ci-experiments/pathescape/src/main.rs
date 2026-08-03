// Generic Unix/macOS path-escape primitive: does base.join(name) + File::create escape `base`
// when `name` is (1) a relative "../x" or (2) an absolute path? (Standard Path::join semantics:
// absolute arg REPLACES base; ".." resolves on Unix.) Asserts via stdout markers.
use std::fs;
use std::path::Path;

fn probe(tag: &str, base: &Path, name: &str) {
    let joined = base.join(name);
    if let Some(p) = joined.parent() { let _ = fs::create_dir_all(p); }
    let r = fs::File::create(&joined);
    println!("[{}] name={:?} -> joined={:?} create={}", tag, name, joined,
        if r.is_ok() {"OK"} else {"ERR"});
}

fn main() {
    let root = std::env::temp_dir().join("pathesc_9x");
    let _ = fs::remove_dir_all(&root);
    let base = root.join("base");
    fs::create_dir_all(&base).unwrap();
    println!("OS={} root={:?}", std::env::consts::OS, root);

    probe("rel_dotdot", &base, "../CANARY_REL.txt");
    let abs = root.join("CANARY_ABS.txt");
    probe("abs_path", &base, abs.to_str().unwrap());
    let mut home_hit = false;
    if let Some(home) = std::env::var_os("HOME") {
        let ha = Path::new(&home).join("CANARY_HOME_pathesc.txt");
        probe("abs_home", &base, ha.to_str().unwrap());
        home_hit = ha.exists();
        let _ = fs::remove_file(&ha);
    }

    let rel_escaped = root.join("CANARY_REL.txt").exists();
    let abs_escaped = root.join("CANARY_ABS.txt").exists();
    println!("=== base/ contents (empty if all escaped) ===");
    for e in fs::read_dir(&base).unwrap() { println!("  {:?}", e.unwrap().file_name()); }
    println!("=== root/ contents (non-base = ESCAPED) ===");
    for e in fs::read_dir(&root).unwrap() { println!("  {:?}", e.unwrap().file_name()); }
    println!("REL_DOTDOT_ESCAPED={}", rel_escaped);
    println!("ABS_PATH_ESCAPED={}", abs_escaped);
    println!("HOME_WRITE_OUTSIDE_BASE={}", home_hit);
    println!("RESULT={}", if rel_escaped || abs_escaped || home_hit {"ESCAPE_CONFIRMED"} else {"NO_ESCAPE"});
}
