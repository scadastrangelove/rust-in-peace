// Platform path-canonicalization check: does an exact "==\"..\"" component filter miss a
// trailing-dot/space component ("..  "/".. "), and does std::fs::File::create then escape the
// base directory? (Windows Win32 path normalization strips trailing dots/spaces per component,
// turning ".. " into ".." at CreateFileW; POSIX does not.) Generic — asserts via stdout markers.
use std::fs;

// The common-but-insufficient guard: reject only a component that EXACTLY equals "..".
fn guard_catches(name: &str) -> bool {
    name.split(|c| c == '/' || c == '\\').any(|s| s == "..")
}

fn main() {
    let payload = ".. \\CANARY_ESCAPED.txt"; // dot-dot-SPACE then separator (Windows) 
    let payload_posix = ".. /CANARY_ESCAPED.txt";
    let name = if cfg!(windows) { payload } else { payload_posix };

    let caught = guard_catches(name);

    let root = std::env::temp_dir().join("winpath_canon_poc_9f3a");
    let _ = fs::remove_dir_all(&root);
    let base = root.join("base");
    fs::create_dir_all(&base).unwrap();

    // Exactly what a file-receiver does: join the peer-supplied relative name onto the base,
    // then create the file by PATH (no \\?\ verbatim prefix, no O_NOFOLLOW).
    let joined = base.join(name);
    let create_res = fs::File::create(&joined);

    // Escape target = sibling of `base` (i.e. root/CANARY_ESCAPED.txt), OUTSIDE base.
    let escaped_target = root.join("CANARY_ESCAPED.txt");
    let did_escape = escaped_target.exists();

    println!("OS={}", std::env::consts::OS);
    println!("GUARD_CATCHES_DOTDOTSPACE={}", caught);
    println!("CREATE_OK={}", create_res.is_ok());
    println!("FILE_ESCAPED_BASE={}", did_escape);
    println!(
        "RESULT={}",
        if !caught && did_escape { "CONFIRMED_TRAVERSAL" } else { "NOT_CONFIRMED" }
    );
}
